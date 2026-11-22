import Foundation
import NIOCore
import NIOPosix
import AtlasPCAVerify
import AtlasPCAMpc

/// TEST-ONLY fault injection for the networked MPC. Two layers, deliberately separate:
///  - `NetFaults.tamperFor(spec)`: a MALICIOUS SENDER rewriting its own outgoing frames at the application layer (duplicate, reorder, skipped sequence,
///    garbage, truncation, wrong round/session, oversize length, drop, silence). The bytes still travel inside valid TLS, so the receiver's framing
///    checks decide.
///  - `FaultProxy`: a NETWORK adversary on the wire (TCP middlebox): drop / delay / truncate / bit-flip / duplicate / reorder at the byte level. TLS 1.3
///    record authentication rejects tampering, so the expected outcome is an attributable-to-the-link `disconnect`, never a silently corrupted value.
public enum FrameFaultKind: String {
    case duplicate, reorder, skipSeq = "skip-seq", garbage, truncate, bitflip, wrongRound = "wrong-round", wrongSession = "wrong-session", oversize, drop
    case silentFrom = "silent-from", extraField = "extra-field", falseAccuse = "false-accuse"
}

public struct FrameFault {
    public var kind: FrameFaultKind
    /// Protocol round to attack (e.g. "mul0").
    public var round: String
    /// Restrict to one recipient; default: all recipients.
    public var to: Int?
    /// For `falseAccuse`: the (honest) party the malicious sender names in its forged abort frame.
    public var accuse: Int?
    public init(kind: FrameFaultKind, round: String, to: Int? = nil, accuse: Int? = nil) { self.kind = kind; self.round = round; self.to = to; self.accuse = accuse }
}

public enum NetFaults {
    private final class State {
        let lock = NSLock()
        var stash: [Int: [UInt8]] = [:]
        var silent = false
    }

    private static func be32(_ n: Int) -> [UInt8] { [UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] }

    public static func tamperFor(_ spec: FrameFault) -> (TamperEvent) -> [[UInt8]] {
        let st = State()
        return { ev in
            st.lock.lock(); defer { st.lock.unlock() }
            if st.silent { return [] }
            let hit = ev.frame.rd == spec.round && (spec.to == nil || spec.to == ev.to)
            if spec.kind == .reorder {
                if let held = st.stash[ev.to] {
                    st.stash[ev.to] = nil
                    return [ev.raw, held] // later frame first, then the held-back one
                }
                if hit { st.stash[ev.to] = ev.raw; return [] }
                return [ev.raw]
            }
            if !hit { return [ev.raw] }
            func enc(_ f: PCAMpc.NetWire.Frame) -> [[UInt8]] { (try? PCAMpc.NetWire.encodeFrame(f)).map { [$0] } ?? [] }
            switch spec.kind {
            case .duplicate: return [ev.raw, ev.raw]
            case .skipSeq:
                var f = ev.frame
                f.seq = .int(Int64((IV.num(ev.frame.seq) ?? 0) + 1))
                return enc(f)
            case .garbage:
                var g = [UInt8](repeating: 0x5a, count: ev.raw.count)
                g.replaceSubrange(0..<4, with: be32(ev.raw.count - 4))
                return [g]
            case .truncate: return [Array(ev.raw.prefix(max(5, ev.raw.count / 2)))]
            case .bitflip:
                var b = ev.raw
                let i = Int(Double(b.count) * 0.6)
                b[i] ^= 0x04
                return [b]
            case .wrongRound:
                var f = ev.frame
                f.rd = "zzz-" + ev.frame.rd
                return enc(f)
            case .wrongSession:
                var f = ev.frame
                f.sid = "not-this-session"
                return enc(f)
            case .oversize: return [[0x7f, 0xff, 0xff, 0xff]]
            case .drop: return []
            case .silentFrom:
                st.silent = true
                return []
            case .falseAccuse:
                var f = ev.frame
                f.ty = "abort"
                f.rd = "abort"
                f.d = .object(["kind": .string("timeout"), "blamed": .int(Int64(spec.accuse ?? 0)), "detail": .string("forged accusation")])
                return enc(f)
            case .extraField:
                // an envelope with a seventh member: splice it into the honest body and fix the length prefix
                var body = Array(ev.raw.dropFirst(4))
                guard body.last == UInt8(ascii: "}") else { return [ev.raw] }
                body.removeLast()
                body += Array(",\"x\":1}".utf8)
                return [be32(body.count) + body]
            case .reorder: return [ev.raw]
            }
        }
    }
}

// MARK: TCP fault proxy

public enum WireFaultKind: String { case none, drop, delay, truncate, bitflip, duplicate, reorder }
public enum WireDir { case c2s, s2c }

public struct WireFault {
    public var kind: WireFaultKind
    /// Which direction through the proxy: client->server or server->client.
    public var dir: WireDir
    /// The fault starts after this many bytes have passed in that direction (skips the TLS handshake).
    public var afterBytes: Int
    /// Delay in milliseconds (kind = delay).
    public var ms: Int?
    public init(kind: WireFaultKind, dir: WireDir, afterBytes: Int, ms: Int? = nil) { self.kind = kind; self.dir = dir; self.afterBytes = afterBytes; self.ms = ms }
}

/// One direction of the proxy: forwards chunks and misbehaves once, after `afterBytes` bytes.
private final class Pump {
    let fault: WireFault
    let active: Bool
    var seen = 0
    var fired = false
    var done = false
    var held: [UInt8]?
    var pending = 0
    var closeAfter = false
    weak var to: Channel?
    let onFire: (String) -> Void
    let dir: WireDir

    init(_ f: WireFault, _ dir: WireDir, _ onFire: @escaping (String) -> Void) {
        fault = f
        self.dir = dir
        active = f.kind != .none && f.dir == dir
        self.onFire = onFire
    }

    func write(_ b: [UInt8]) {
        guard let t = to, t.isActive else { return }
        var buf = t.allocator.buffer(capacity: b.count)
        buf.writeBytes(b)
        t.writeAndFlush(buf, promise: nil)
    }

    func closeTo() { to?.close(promise: nil) }

    /// Runs on the source channel's event loop.
    func chunk(_ c: [UInt8], _ loop: EventLoop) {
        let before = seen
        seen += c.count
        if !active || done || before + c.count <= fault.afterBytes {
            if active && fault.kind == .drop && fired { return } // black hole stays black
            write(c)
            return
        }
        if !fired {
            fired = true
            onFire("fault \(fault.kind.rawValue) \(dir == .c2s ? "c2s" : "s2c") after \(fault.afterBytes)B")
        }
        switch fault.kind {
        case .drop: return
        case .delay:
            pending += 1
            loop.scheduleTask(in: .milliseconds(Int64(fault.ms ?? 1000))) { [self] in
                write(c)
                pending -= 1
                if pending == 0 && closeAfter { closeTo() }
            }
        case .truncate:
            done = true
            write(Array(c.prefix(c.count / 2)))
            closeTo()
        case .bitflip:
            done = true
            var b = c
            b[b.count / 2] ^= 0x01
            write(b)
        case .duplicate:
            done = true
            write(c)
            write(c)
        case .reorder:
            if let h = held {
                done = true
                write(c)
                write(h)
                held = nil
            } else {
                held = c
            }
        case .none: write(c)
        }
    }

    /// The source ended: deliver what is held, then close the other side once delayed bytes are out.
    func ended() {
        if let h = held { write(h); held = nil }
        if pending == 0 { closeTo() } else { closeAfter = true }
    }
}

private final class PumpHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    let pump: Pump
    init(_ p: Pump) { pump = p }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var b = unwrapInboundIn(data)
        if let bytes = b.readBytes(length: b.readableBytes) { pump.chunk(bytes, context.eventLoop) }
    }
    func channelInactive(context: ChannelHandlerContext) { pump.ended(); context.fireChannelInactive() }
    func errorCaught(context: ChannelHandlerContext, error: Error) { pump.closeTo(); context.close(promise: nil) }
}

/// A transparent TCP proxy that misbehaves once, after `afterBytes` bytes, in one direction.
public final class FaultProxy: @unchecked Sendable {
    private let listenPort: Int
    private let target: (host: String, port: Int)
    private let fault: WireFault
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private var server: Channel?
    private let logLock = NSLock()
    private var logLines: [String] = []

    public init(listenPort: Int, targetHost: String, targetPort: Int, fault: WireFault) {
        self.listenPort = listenPort
        target = (targetHost, targetPort)
        self.fault = fault
    }

    public var log: [String] { logLock.lock(); defer { logLock.unlock() }; return logLines }

    private func note(_ s: String) { logLock.lock(); logLines.append(s); logLock.unlock() }

    public func listen() throws {
        let t = target, f = fault, grp = group
        server = try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [self] client in
                let up2c = Pump(f, .s2c) { self.note($0) }
                let c2up = Pump(f, .c2s) { self.note($0) }
                up2c.to = client
                client.setOption(ChannelOptions.autoRead, value: false).whenComplete { _ in }
                _ = ClientBootstrap(group: grp).channelInitializer { $0.pipeline.addHandler(PumpHandler(up2c)) }.connect(host: t.host, port: t.port).whenComplete { r in
                    switch r {
                    case .success(let up):
                        c2up.to = up
                        _ = client.setOption(ChannelOptions.autoRead, value: true)
                    case .failure: client.close(promise: nil)
                    }
                }
                return client.pipeline.addHandler(PumpHandler(c2up))
            }
            .bind(host: "127.0.0.1", port: listenPort).wait()
    }

    public func close() {
        server?.close(promise: nil)
        group.shutdownGracefully(queue: DispatchQueue.global()) { _ in }
    }
}
