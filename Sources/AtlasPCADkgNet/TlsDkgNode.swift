import Foundation
import CryptoKit
import Dispatch
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import AtlasPCAVerify

/// Reference mutual-TLS channel for the FROST DKG (SwiftNIO + NIOSSL, BoringSSL: the same stack on Apple platforms and Linux).
///
/// One TLS 1.3 connection per pair of participants, mutually authenticated by pinned certificate: each side trusts exactly the other participants' certificates (matched by
/// SHA-256 fingerprint, inside their validity window), and the peer's fingerprint maps to its participant id, so the sender identity the DKG driver sees comes from the handshake
/// and never from message content. The higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext client, a TLS 1.2 client, a second
/// connection for an already linked identity and a connection from a party that should have been dialled are all refused before any DKG byte is read. Frames are a 4-byte
/// big-endian length then the message; the length is checked against `DKG_MAX_MESSAGE_BYTES` before any allocation. Certificate issuance, rotation and revocation are the deployer's.
public struct TlsDkgPeerCert {
    public let id: Int64
    public let certPem: String
    public init(id: Int64, certPem: String) { self.id = id; self.certPem = certPem }
}

public struct TlsDkgNodeOpts {
    public var selfId: Int64
    public var sessionId: [UInt8]
    public var keyPem: String
    public var certPem: String
    /// Pinned identities of every OTHER participant (certificate only).
    public var peerCerts: [TlsDkgPeerCert]
    /// 0 = ephemeral (read `TlsDkgNode.port`).
    public var listenPort: Int
    public var listenHost: String
    public init(selfId: Int64, sessionId: [UInt8], keyPem: String, certPem: String, peerCerts: [TlsDkgPeerCert], listenPort: Int = 0, listenHost: String = "127.0.0.1") {
        self.selfId = selfId; self.sessionId = sessionId; self.keyPem = keyPem; self.certPem = certPem; self.peerCerts = peerCerts; self.listenPort = listenPort; self.listenHost = listenHost
    }
}

public struct TlsDkgAddress {
    public let id: Int64
    public let host: String
    public let port: Int
    public init(id: Int64, host: String, port: Int) { self.id = id; self.host = host; self.port = port }
}

/// Reads just enough DER to get a certificate's validity window.
enum TlsDkgDer {
    struct Bad: Error {}
    private static func read(_ b: [UInt8], _ off: Int) throws -> (tag: UInt8, start: Int, end: Int) {
        guard off + 2 <= b.count else { throw Bad() }
        var len = Int(b[off + 1]), p = off + 2
        if len & 0x80 != 0 {
            let n = len & 0x7f
            guard n >= 1, n <= 3, p + n <= b.count else { throw Bad() }
            len = 0
            for i in 0..<n { len = len << 8 | Int(b[p + i]) }
            p += n
        }
        guard p + len <= b.count else { throw Bad() }
        return (b[off], p, p + len)
    }
    private static func time(_ b: [UInt8], _ tag: UInt8) throws -> Date {
        let t = String(decoding: b, as: UTF8.self)
        let digits = tag == 0x18 ? 14 : 12
        guard t.hasSuffix("Z"), t.count == digits + 1, t.dropLast().allSatisfy({ $0.isASCII && $0.isNumber }) else { throw Bad() }
        let n = t.dropLast().compactMap { Int(String($0)) }
        func two(_ i: Int) -> Int { n[i] * 10 + n[i + 1] }
        let year = tag == 0x18 ? two(0) * 100 + two(2) : (two(0) >= 50 ? 1900 + two(0) : 2000 + two(0))
        let o = tag == 0x18 ? 4 : 2
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        guard let d = c.date(from: DateComponents(year: year, month: two(o), day: two(o + 2), hour: two(o + 4), minute: two(o + 6), second: two(o + 8))) else { throw Bad() }
        return d
    }
    static func validity(der: [UInt8]) throws -> (Date, Date) {
        let cert = try read(der, 0)
        let tbs = try read(der, cert.start)
        guard cert.tag == 0x30, tbs.tag == 0x30 else { throw Bad() }
        var off = tbs.start
        if try read(der, off).tag == 0xa0 { off = try read(der, off).end }
        for _ in 0..<3 { off = try read(der, off).end } // serial, signature, issuer
        let v = try read(der, off)
        let a = try read(der, v.start), b = try read(der, a.end)
        guard v.tag == 0x30, a.tag == 0x17 || a.tag == 0x18, b.tag == 0x17 || b.tag == 0x18 else { throw Bad() }
        return (try time(Array(der[a.start..<a.end]), a.tag), try time(Array(der[b.start..<b.end]), b.tag))
    }
}

public func startTlsDkgNode(_ opts: TlsDkgNodeOpts) throws -> TlsDkgNode { try TlsDkgNode(opts) }

public final class TlsDkgNode: @unchecked Sendable {
    typealias E = PCADkgChannelError

    /// The fingerprint a connection presented, recorded by the verification callback.
    final class PeerBox { var fp: String? }

    final class Outcome {
        private let sem = DispatchSemaphore(value: 0)
        private let l = NSLock()
        private var set = false
        private var ok = false
        func finish(_ v: Bool) { l.lock(); if set { l.unlock(); return }; set = true; ok = v; l.unlock(); sem.signal() }
        func wait(_ seconds: Double) -> Bool { sem.wait(timeout: .now() + max(0.001, seconds)) == .success && ok }
    }

    final class Link {
        let id: Int64
        let channel: Channel
        var buf: [UInt8] = []
        init(_ id: Int64, _ ch: Channel) { self.id = id; channel = ch }
    }

    public let selfId: Int64
    public private(set) var port: Int = -1
    private let opts: TlsDkgNodeOpts
    private var pinned: [String: Int64] = [:]
    private var window: [String: (Date, Date)] = [:]
    let peers: [Int64]
    private let inbox: PCADkgInbox
    private let lock = NSCondition()
    private var links: [Int64: Link] = [:]
    private var closed = false
    private var group: MultiThreadedEventLoopGroup?
    private var server: Channel?
    private var serverContext: NIOSSLContext?
    private var clientContext: NIOSSLContext?

    init(_ opts: TlsDkgNodeOpts) throws {
        self.opts = opts
        selfId = opts.selfId
        let selfFp: String
        do { selfFp = Self.fingerprint(try Self.der(opts.certPem)) } catch { throw NSError(domain: "startTlsDkgNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "this node's certificate is not a PEM certificate"]) }
        var pin: [String: Int64] = [:], win: [String: (Date, Date)] = [:]
        for p in opts.peerCerts {
            let der: [UInt8], fp: String
            do { der = try Self.der(p.certPem); fp = Self.fingerprint(der); win[fp] = try TlsDkgDer.validity(der: der) } catch {
                throw NSError(domain: "startTlsDkgNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "a peer certificate is not a PEM certificate"])
            }
            pin[fp] = p.id
        }
        let ids = opts.peerCerts.map { $0.id }
        if pin.count != ids.count || ids.contains(opts.selfId) || pin[selfFp] != nil || Set(ids).count != ids.count {
            throw NSError(domain: "startTlsDkgNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "peer certificates and ids must be distinct and none may be this node"])
        }
        pinned = pin
        window = win
        peers = ids.sorted()
        inbox = PCADkgInbox(sessionId: opts.sessionId, peers: peers)
        try listen()
    }

    static func der(_ pem: String) throws -> [UInt8] {
        let head = "-----BEGIN CERTIFICATE-----", tail = "-----END CERTIFICATE-----"
        guard let a = pem.range(of: head), let b = pem.range(of: tail, range: a.upperBound..<pem.endIndex),
              let d = Data(base64Encoded: String(pem[a.upperBound..<b.lowerBound].filter { !$0.isWhitespace })) else { throw TlsDkgDer.Bad() }
        return [UInt8](d)
    }
    static func fingerprint(_ der: [UInt8]) -> String { SHA256.hash(data: Data(der)).map { String(format: "%02x", $0) }.joined() }

    private func verifier(_ box: PeerBox) -> NIOSSLCustomVerificationCallback {
        return { [self] chain, promise in
            guard let leaf = chain.first, let der = try? leaf.toDERBytes() else { noteLinkError("peer certificate unreadable"); promise.succeed(.failed); return }
            let fp = Self.fingerprint(der)
            let now = Date()
            guard pinned[fp] != nil, let w = window[fp], now >= w.0, now <= w.1 else { noteLinkError("peer certificate \(fp) not pinned or outside its window"); promise.succeed(.failed); return }
            box.fp = fp
            promise.succeed(.certificateVerified)
        }
    }

    /// A connect failure as the underlying errors it carries (NIO's own description nests the whole target list and hides the cause behind the length cap).
    static func brief(_ e: Error) -> String {
        if let c = e as? NIOConnectionError {
            let inner = c.connectionErrors.map { "\($0.target): \($0.error)" }.joined(separator: "; ")
            return "connect failed (\(inner.isEmpty ? "no detail" : inner))"
        }
        return "\(e)"
    }

    /// Which socket options a fresh TCP socket accepts here (the failed connect names the syscall, never the option): one line, for the link-error trail.
    static func probeSocketOptions() -> String {
        #if canImport(Glibc)
        let stream = Int32(SOCK_STREAM.rawValue)
        #else
        let stream = SOCK_STREAM
        #endif
        let fd = socket(AF_INET, stream, 0)
        guard fd >= 0 else { return "probe: socket() failed (errno \(errno))" }
        // the libc close, not this type's own close()
        #if canImport(Glibc)
        defer { _ = Glibc.close(fd) }
        #else
        defer { _ = Darwin.close(fd) }
        #endif
        var one: Int32 = 1
        func tryOpt(_ name: String, _ level: Int32, _ opt: Int32) -> String {
            let r = setsockopt(fd, level, opt, &one, socklen_t(MemoryLayout<Int32>.size))
            return r == 0 ? "\(name)=ok" : "\(name)=errno \(errno)"
        }
        return "probe: " + [tryOpt("TCP_NODELAY", Int32(IPPROTO_TCP), TCP_NODELAY), tryOpt("SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR),
                            tryOpt("SO_KEEPALIVE", SOL_SOCKET, SO_KEEPALIVE)].joined(separator: " ")
    }

    private var linkError: String?
    func noteLinkError(_ m: String) { lock.lock(); linkError = String(((linkError.map { $0 + "; " } ?? "") + String(m.prefix(200))).suffix(900)); lock.unlock() }
    private func lastLinkError() -> String? { lock.lock(); defer { lock.unlock() }; return linkError }

    private func listen() throws {
        let g = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        group = g
        do {
            let cert = try NIOSSLCertificate(bytes: Array(opts.certPem.utf8), format: .pem)
            let key = try NIOSSLPrivateKey(bytes: Array(opts.keyPem.utf8), format: .pem)
            var sc = TLSConfiguration.makeServerConfiguration(certificateChain: [.certificate(cert)], privateKey: .privateKey(key))
            sc.minimumTLSVersion = .tlsv13
            sc.certificateVerification = .noHostnameVerification // the client certificate is required; the callback decides
            var cc = TLSConfiguration.makeClientConfiguration()
            cc.certificateChain = [.certificate(cert)]
            cc.privateKey = .privateKey(key)
            cc.minimumTLSVersion = .tlsv13
            cc.certificateVerification = .noHostnameVerification // pinned by certificate, not by host name
            serverContext = try NIOSSLContext(configuration: sc)
            clientContext = try NIOSSLContext(configuration: cc)
            let boot = ServerBootstrap(group: g)
                .serverChannelOption(ChannelOptions.backlog, value: 128)
                .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { [self] ch in
                    let box = PeerBox()
                    do {
                        let ssl = try NIOSSLServerHandler(context: serverContext!, customVerificationCallback: verifier(box))
                        return ch.pipeline.addHandlers([ssl, DkgLinkHandler(node: self, box: box, dialId: nil, outcome: nil)])
                    } catch { noteLinkError("inbound channel setup: \(error)"); return ch.eventLoop.makeFailedFuture(error) }
                }
            server = try boot.bind(host: opts.listenHost, port: opts.listenPort).wait()
            port = server?.localAddress?.port ?? -1
        } catch {
            shutdown()
            throw NSError(domain: "startTlsDkgNode", code: 2, userInfo: [NSLocalizedDescriptionKey: "cannot listen: \(error)"])
        }
    }

    /// Called on the event loop when a handshake is complete: only a pinned peer, that is meant to be here, once.
    func onHandshake(_ ch: Channel, _ fp: String?, _ dialId: Int64?, _ h: DkgLinkHandler) -> Bool {
        guard let fp = fp, let id = pinned[fp] else { return false }
        if let want = dialId { if id != want { return false } } else if id < selfId { return false }
        lock.lock(); defer { lock.unlock() }
        if closed || links[id] != nil { return false }
        let l = Link(id, ch)
        links[id] = l
        h.link = l
        lock.broadcast()
        return true
    }

    func onData(_ l: Link, _ chunk: [UInt8]) {
        l.buf += chunk
        while true {
            if l.buf.count < 4 { return }
            let len = (Int(l.buf[0]) << 24) | (Int(l.buf[1]) << 16) | (Int(l.buf[2]) << 8) | Int(l.buf[3])
            if len > PCAFrostDkgWire.DKG_MAX_MESSAGE_BYTES {
                inbox.fail(l.id, E("oversize", l.id, "frame of \(len) bytes exceeds the cap"))
                l.channel.close(promise: nil)
                l.buf = []
                return
            }
            if l.buf.count < 4 + len { return }
            inbox.accept(l.id, Array(l.buf[4..<(4 + len)]))
            l.buf = Array(l.buf[(4 + len)...])
        }
    }

    func onClosed(_ l: Link) {
        lock.lock()
        if links[l.id] === l { links[l.id] = nil }
        lock.unlock()
        inbox.peerGone(l.id)
    }

    private func dial(_ a: TlsDkgAddress, _ stop: @escaping () -> Bool) {
        var probed = false
        while !stop() && !isClosed {
            let out = Outcome()
            let box = PeerBox()
            let boot = ClientBootstrap(group: group!)
                .connectTimeout(.seconds(3))
                .channelInitializer { [self] ch in
                    do {
                        let ssl = try NIOSSLClientHandler(context: clientContext!, serverHostname: nil, customVerificationCallback: verifier(box))
                        return ch.pipeline.addHandlers([ssl, DkgLinkHandler(node: self, box: box, dialId: a.id, outcome: out)])
                    } catch { noteLinkError("dial \(a.id) channel setup: \(error)"); return ch.eventLoop.makeFailedFuture(error) }
                }
            do {
                let ch = try boot.connect(host: a.host, port: a.port).wait()
                if out.wait(3) { return }
                noteLinkError("dial \(a.id): no authenticated link within 3 s of connecting")
                ch.close(promise: nil)
            } catch {
                noteLinkError("dial \(a.id) at \(a.host):\(a.port): \(Self.brief(error))")
                if !probed { probed = true; noteLinkError(Self.probeSocketOptions()) }
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    private var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }

    /// Dial the lower-numbered peers, wait for the higher-numbered ones, and return the channel once every link is authenticated.
    public func connect(_ addresses: [TlsDkgAddress], connectTimeoutMs: Double = 15_000) throws -> PCADkgChannel {
        let stopLock = NSLock()
        var stop = false
        let stopped = { stopLock.lock(); defer { stopLock.unlock() }; return stop }
        for a in addresses {
            if !peers.contains(a.id) { throw E("identity", a.id, "address for a participant that is not a pinned peer") }
            if a.id < selfId { Thread.detachNewThread { [self] in dial(a, stopped) } }
        }
        let deadline = Date().addingTimeInterval(connectTimeoutMs / 1000)
        lock.lock()
        while true {
            if closed { lock.unlock(); throw E("closed", nil, "node closed while connecting") }
            let missing = peers.filter { links[$0] == nil }
            if missing.isEmpty { break }
            let left = deadline.timeIntervalSinceNow
            if !(left > 0) {
                lock.unlock()
                stopLock.lock(); stop = true; stopLock.unlock()
                close()
                throw E("timeout", missing[0], "no authenticated link to \(missing.map(String.init).joined(separator: ","))" + (lastLinkError().map { " (last link error: \($0))" } ?? ""))
            }
            _ = lock.wait(until: Date(timeIntervalSinceNow: min(left, 0.05)))
        }
        lock.unlock()
        stopLock.lock(); stop = true; stopLock.unlock()
        return DkgTlsChannel(self)
    }

    func write(_ to: Int64, _ kind: String, _ body: JSONValue) throws {
        lock.lock(); let l = links[to]; lock.unlock()
        guard let link = l, link.channel.isActive else { throw E("closed", to, "no authenticated link") }
        let frame = PCAFrostDkgWire.tlsFrameEncode(try PCAFrostDkgWire.encodeDkgMessage(opts.sessionId, kind, body, order: PCAFrostDkgWire.BODY_ORDER))
        var buf = link.channel.allocator.buffer(capacity: frame.count)
        buf.writeBytes(frame)
        do { try link.channel.writeAndFlush(buf).wait() } catch { throw E("closed", to, "write failed") }
    }

    func collect(_ kind: String, _ from: [Int64], timeoutMs: Double) throws -> [(Int64, JSONValue)] { try inbox.collect(kind, from, timeoutMs: timeoutMs) }

    private func shutdown() {
        let chans: [Channel]
        lock.lock()
        closed = true
        chans = links.values.map { $0.channel }
        let srv = server, g = group
        group = nil
        lock.broadcast()
        lock.unlock()
        for c in chans { c.close(promise: nil) }
        srv?.close(promise: nil)
        g?.shutdownGracefully(queue: DispatchQueue.global()) { _ in }
    }

    public func close() {
        inbox.close()
        shutdown()
    }
}

final class DkgTlsChannel: PCADkgChannel {
    let node: TlsDkgNode
    init(_ n: TlsDkgNode) { node = n }
    var selfId: Int64 { node.selfId }
    var peers: [Int64] { node.peers }
    func broadcast(_ kind: String, _ body: JSONValue) throws { for p in peers { try node.write(p, kind, body) } }
    func send(_ to: Int64, _ kind: String, _ body: JSONValue) throws {
        guard peers.contains(to) else { throw PCADkgChannelError("identity", to, "not a connected peer") }
        try node.write(to, kind, body)
    }
    func collect(_ kind: String, _ from: [Int64], timeoutMs: Double) throws -> [(Int64, JSONValue)] { try node.collect(kind, from, timeoutMs: timeoutMs) }
    func close() { node.close() }
}

/// The handler of one TLS connection: attaches the link once the handshake is done (or closes the connection), feeds bytes to the node.
final class DkgLinkHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    let node: TlsDkgNode
    let box: TlsDkgNode.PeerBox
    let dialId: Int64?
    let outcome: TlsDkgNode.Outcome?
    var link: TlsDkgNode.Link?
    init(node: TlsDkgNode, box: TlsDkgNode.PeerBox, dialId: Int64?, outcome: TlsDkgNode.Outcome?) { self.node = node; self.box = box; self.dialId = dialId; self.outcome = outcome }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let e = event as? TLSUserEvent, case .handshakeCompleted = e {
            let ok = node.onHandshake(context.channel, box.fp, dialId, self)
            if !ok { node.noteLinkError("handshake refused (peer fingerprint \(box.fp ?? "none"), dial \(dialId.map(String.init) ?? "inbound"))") }
            outcome?.finish(ok)
            if !ok { context.close(promise: nil) }
        }
        context.fireUserInboundEventTriggered(event)
    }
    func channelActive(context: ChannelHandlerContext) {
        // TCP_NODELAY is a latency nicety, set on the live connection and never allowed to fail it: as a bootstrap option a refused setsockopt (EACCES on the CI hosts) failed every connect
        context.channel.setOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1).whenFailure { [node = self.node] e in node.noteLinkError("TCP_NODELAY not set: \(e)") }
        node.noteLinkError("connection active (\(dialId.map { "dial \($0)" } ?? "inbound"))")
        context.fireChannelActive()
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        guard let l = link, let bytes = buf.readBytes(length: buf.readableBytes) else { return }
        node.onData(l, bytes)
    }
    func channelInactive(context: ChannelHandlerContext) {
        if let l = link { node.onClosed(l) }
        outcome?.finish(false)
        context.fireChannelInactive()
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        node.noteLinkError("\(error)")
        outcome?.finish(false)
        context.close(promise: nil)
    }
}
