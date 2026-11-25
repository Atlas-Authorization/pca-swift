import Foundation
import CryptoKit
import Dispatch
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import AtlasPCAVerify
import AtlasPCAMpc

/// Time source for the mesh's deadlines (default: a monotonic wall clock). A test injects a `ManualMeshClock` so an outcome never depends on how loaded
/// the machine is; the mesh re-reads the clock every 20 ms of real time while it waits, so advancing the clock is enough to fire a deadline.
public protocol MeshClock: AnyObject {
    /// Milliseconds on this clock's own timeline.
    func now() -> Int64
}

public final class WallMeshClock: MeshClock {
    public init() {}
    public func now() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }
}

/// A virtual clock: time moves only when the test says so.
public final class ManualMeshClock: MeshClock {
    private let lock = NSLock()
    private var t: Int64 = 0
    public init() {}
    public func now() -> Int64 { lock.lock(); defer { lock.unlock() }; return t }
    public func advance(_ ms: Int64) { lock.lock(); t += ms; lock.unlock() }
}

/// A node of the session: its address and PUBLIC certificate (the pinned trust anchor and identity).
public struct NodeAddr {
    public var id: Int
    public var host: String
    public var port: Int
    public var certPem: String
    public init(id: Int, host: String, port: Int, certPem: String) { self.id = id; self.host = host; self.port = port; self.certPem = certPem }
}

/// TEST HOOK input: a frame about to be sent and its honest encoding.
public struct TamperEvent {
    public let to: Int
    public let frame: PCAMpc.NetWire.Frame
    public let raw: [UInt8]
}

public struct LinkStats {
    public let peer: Int
    public let appBytesOut: Int64
    public let appBytesIn: Int64
    public let framesOut: Int64
    public let framesIn: Int64
}

public struct MeshConfig {
    public var selfId: Int
    /// Every node of the session, including self.
    public var nodes: [NodeAddr]
    /// Node ids this node keeps a link to (default: all others).
    public var linkTo: [Int]?
    public var keyPem: String
    public var certPem: String
    public var sessionId: String
    public var listenHost = "0.0.0.0"
    public var connectTimeoutMs: Int64 = 30_000
    public var recvTimeoutMs: Int64 = 20_000
    /// TEST HOOK: a (malicious) sender rewriting its own outgoing frames; refused unless `unsafeTestHooks`.
    public var tamper: ((TamperEvent) -> [[UInt8]])?
    /// TEST HOOK: runs on the attaching thread once the link is open and before our hello is sent, with the peer id; refused unless `unsafeTestHooks`.
    public var beforeHello: ((Int) -> Void)?
    public var unsafeTestHooks = false
    public var maxInboxFrames = 1024
    public var maxInboxBytes = 32 * 1024 * 1024
    public var clock: MeshClock?

    public init(selfId: Int, nodes: [NodeAddr], keyPem: String, certPem: String, sessionId: String) {
        self.selfId = selfId
        self.nodes = nodes
        self.keyPem = keyPem
        self.certPem = certPem
        self.sessionId = sessionId
    }
}

/// Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3 (SwiftNIO + NIOSSL).
///
/// * MUTUAL TLS with PINNED self-signed certificates (`NetCerts`): a peer is identified by the SHA-256 fingerprint of its certificate, never by
///   anything it claims; the id in its hello frame must agree with the pinned fingerprint. A custom verification callback accepts a certificate only
///   when its fingerprint is pinned and its validity window holds (no chain building, no hostnames).
/// * Strict framing and per-link sequence numbers. A malformed frame, a replayed or skipped one, a frame for the wrong round or session, or an
///   oversize length prefix aborts the whole run with a `NetAbort` naming the sender.
/// * Every receive has a timeout (no hangs); a silent peer is blamed after `recvTimeoutMs`.
/// * ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort sends an `abort` frame to every peer, then closes.
///
/// A node dials every lower-numbered link target and accepts from the higher-numbered ones. The protocol side is blocking (one thread per party); the
/// sockets are NIO event loops that hand frames over through the inbox under one condition lock.
public final class Mesh: @unchecked Sendable {
    public static let MAX_MESH_EVENTS = 64

    struct Item {
        let rd: String
        let d: JSONValue
        let size: Int
        let abort: NetAbort?
    }

    final class Link {
        let id: Int
        let splitter = PCAMpc.NetWire.FrameSplitter()
        var inbox: [Item] = []
        var channel: Channel?
        var inboxBytes = 0
        var paused = false
        var sendSeq: Int64 = 0
        var recvSeq: Int64 = 0
        var closed = false
        var helloSeen = false
        let sendLock = NSLock()
        private let statLock = NSLock()
        private var bIn: Int64 = 0, bOut: Int64 = 0, fIn: Int64 = 0, fOut: Int64 = 0
        init(_ id: Int) { self.id = id }
        func add(bytesIn: Int64 = 0, bytesOut: Int64 = 0, framesIn: Int64 = 0, framesOut: Int64 = 0) {
            statLock.lock(); bIn += bytesIn; bOut += bytesOut; fIn += framesIn; fOut += framesOut; statLock.unlock()
        }
        func stats() -> LinkStats { statLock.lock(); defer { statLock.unlock() }; return LinkStats(peer: id, appBytesOut: bOut, appBytesIn: bIn, framesOut: fOut, framesIn: fIn) }
    }

    /// The pinned fingerprint a connection presented, recorded by the verification callback.
    final class PeerBox { var fp: String? }

    public let selfId: Int
    private let cfg: MeshConfig
    private let clock: MeshClock
    var links: [Int: Link] = [:]
    private let linkOrder: [Int]
    private var pinned: [String: Int] = [:]
    private var pinWindow: [String: (Date, Date)] = [:]
    private var nodeById: [Int: NodeAddr] = [:]
    private let signKey: P256.Signing.PrivateKey
    private var peerKeys: [Int: P256.Signing.PublicKey] = [:]
    private let lock = NSCondition()
    private let eventLock = NSLock()
    private var eventList: [String] = []
    private var eventsDroppedCount = 0
    private var failure: NetAbort?
    private var finished = false
    private var closing = false
    private var deferAborts = false
    private var group: MultiThreadedEventLoopGroup?
    private var server: Channel?
    private var serverContext: NIOSSLContext?
    private var clientContext: NIOSSLContext?

    public init(_ cfg: MeshConfig) throws {
        self.cfg = cfg
        selfId = cfg.selfId
        clock = cfg.clock ?? WallMeshClock()
        if (cfg.tamper != nil || cfg.beforeHello != nil) && !cfg.unsafeTestHooks { throw NetError("mesh: the test hooks require unsafeTestHooks (test-only)") }
        do { signKey = try P256.Signing.PrivateKey(pemRepresentation: cfg.keyPem) } catch { throw NetError("mesh: bad private key") }
        let selfFp: String
        do { selfFp = try NetCerts.fingerprint(certPem: cfg.certPem) } catch { throw NetError("mesh: bad own certificate") }
        var selfSeen = false
        for n in cfg.nodes {
            guard nodeById[n.id] == nil else { throw NetError("mesh: duplicate node id \(n.id)") }
            nodeById[n.id] = n
            let fp: String
            do {
                fp = try NetCerts.fingerprint(certPem: n.certPem)
                peerKeys[n.id] = try NetCerts.publicKey(certPem: n.certPem)
                pinWindow[fp] = try NetCerts.validity(certPem: n.certPem)
            } catch { throw NetError("mesh: bad certificate for node \(n.id)") }
            if n.id == cfg.selfId {
                selfSeen = true
                guard fp == selfFp else { throw NetError("mesh: own certificate differs from the one listed for this node") }
            } else {
                guard pinned[fp] == nil, fp != selfFp else { throw NetError("mesh: two nodes share one certificate") }
                pinned[fp] = n.id
            }
        }
        guard selfSeen else { throw NetError("mesh: self not in nodes") }
        let want = cfg.linkTo ?? cfg.nodes.filter { $0.id != cfg.selfId }.map { $0.id }
        for id in want {
            guard nodeById[id] != nil, id != cfg.selfId else { throw NetError("mesh: unknown link target \(id)") }
            links[id] = Link(id)
        }
        linkOrder = links.keys.sorted()
    }

    func note(_ msg: String) {
        eventLock.lock(); defer { eventLock.unlock() }
        if eventList.count < Mesh.MAX_MESH_EVENTS { eventList.append(msg) } else { eventsDroppedCount += 1 }
    }

    public func events() -> [String] { eventLock.lock(); defer { eventLock.unlock() }; return eventList }
    public func eventsDropped() -> Int { eventLock.lock(); defer { eventLock.unlock() }; return eventsDroppedCount }
    public var sessionId: String { cfg.sessionId }
    public func failed() -> NetAbort? { lock.lock(); defer { lock.unlock() }; return failure }
    public var peers: [Int] { linkOrder }

    // MARK: connect

    /// Port the TLS server is bound to (useful when the configured port was 0); -1 before `connect`.
    public func boundPort() -> Int { server?.localAddress?.port ?? -1 }

    private func verifier(_ box: PeerBox) -> NIOSSLCustomVerificationCallback {
        return { [self] chain, promise in
            guard let leaf = chain.first, let der = try? leaf.toDERBytes() else { promise.succeed(.failed); return }
            let fp = NetCerts.fingerprint(der: der)
            let now = Date()
            guard pinned[fp] != nil, let w = pinWindow[fp], now >= w.0, now <= w.1 else { promise.succeed(.failed); return }
            box.fp = fp
            promise.succeed(.certificateVerified)
        }
    }

    private func buildContexts() throws {
        let cert = try NIOSSLCertificate(bytes: Array(cfg.certPem.utf8), format: .pem)
        let key = try NIOSSLPrivateKey(bytes: Array(cfg.keyPem.utf8), format: .pem)
        var sc = TLSConfiguration.makeServerConfiguration(certificateChain: [.certificate(cert)], privateKey: .privateKey(key))
        sc.minimumTLSVersion = .tlsv13
        sc.maximumTLSVersion = .tlsv13
        sc.certificateVerification = .noHostnameVerification // requires the client certificate; the callback decides
        var cc = TLSConfiguration.makeClientConfiguration()
        cc.certificateChain = [.certificate(cert)]
        cc.privateKey = .privateKey(key)
        cc.minimumTLSVersion = .tlsv13
        cc.maximumTLSVersion = .tlsv13
        cc.certificateVerification = .noHostnameVerification
        serverContext = try NIOSSLContext(configuration: sc)
        clientContext = try NIOSSLContext(configuration: cc)
    }

    /// Bind this node's TLS server (a configured port of 0 lets the OS choose) and return the port it really holds. Idempotent. The real port is
    /// written back to this node's own address, so a node never advertises a port it does not hold.
    public func listen() throws -> Int {
        if let s = server { return s.localAddress?.port ?? -1 }
        let me = nodeById[selfId]!
        let g = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        group = g
        do {
            try buildContexts()
            let boot = ServerBootstrap(group: g)
                .serverChannelOption(ChannelOptions.backlog, value: 128)
                .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { [self] ch in
                    let box = PeerBox()
                    do {
                        let ssl = try NIOSSLServerHandler(context: serverContext!, customVerificationCallback: verifier(box))
                        let hs: [ChannelHandler] = [ssl, LinkHandler(mesh: self, box: box, dialId: nil, outcome: nil)]
                        return ch.pipeline.addHandlers(hs)
                    } catch { return ch.eventLoop.makeFailedFuture(error) }
                }
            server = try boot.bind(host: cfg.listenHost, port: me.port).wait()
        } catch {
            closeAll()
            throw NetError("mesh: cannot listen: \(error)")
        }
        let port = server?.localAddress?.port ?? me.port
        nodeById[selfId]?.port = port
        return port
    }

    /// Record the real port a peer bound (its address was not known until it bound); call before `connect`.
    public func setPeerPort(_ id: Int, _ port: Int) throws {
        guard id != selfId, nodeById[id] != nil else { throw NetError("mesh: unknown peer \(id)") }
        nodeById[id]?.port = port
    }

    /// Listen (when not already), dial every lower-numbered link target, and wait until all links are authenticated.
    public func connect() throws {
        let deadline = clock.now() + cfg.connectTimeoutMs
        _ = try listen()
        for id in linkOrder where id < selfId { Thread.detachNewThread { [self] in dial(id, deadline) } }
        var toFail: NetAbort? = nil
        lock.lock()
        while true {
            if let f = failure { lock.unlock(); throw f }
            let missing = linkOrder.filter { !links[$0]!.helloSeen }
            if missing.isEmpty { lock.unlock(); return }
            let left = deadline - clock.now()
            if !(left > 0) { toFail = NetAbort(kind: "timeout", blamed: missing[0], reporter: selfId, detail: "connect: no authenticated link from \(missing)"); break }
            _ = lock.wait(until: Date(timeIntervalSinceNow: Double(min(left, 20)) / 1000))
        }
        lock.unlock()
        fail(toFail!, nil)
        throw toFail!
    }

    /// Reports whether one connection attempt ended in an attached link.
    final class Outcome {
        private let sem = DispatchSemaphore(value: 0)
        private let l = NSLock()
        private var set = false
        var ok = false
        func finish(_ v: Bool) { l.lock(); if set { l.unlock(); return }; set = true; ok = v; l.unlock(); sem.signal() }
        func wait(_ seconds: Double) -> Bool { sem.wait(timeout: .now() + max(0.001, seconds)) == .success && ok }
    }

    private func dial(_ id: Int, _ deadline: Int64) {
        let node = nodeById[id]!
        while failure == nil && !closing && clock.now() < deadline {
            let out = Outcome()
            let box = PeerBox()
            let boot = ClientBootstrap(group: group!)
                .connectTimeout(.seconds(3))
                .channelInitializer { [self] ch in
                    do {
                        let ssl = try NIOSSLClientHandler(context: clientContext!, serverHostname: nil, customVerificationCallback: verifier(box))
                        let hs: [ChannelHandler] = [ssl, LinkHandler(mesh: self, box: box, dialId: id, outcome: out)]
                        return ch.pipeline.addHandlers(hs)
                    } catch { return ch.eventLoop.makeFailedFuture(error) }
                }
            do {
                let ch = try boot.connect(host: node.host, port: node.port).wait()
                if out.wait(Double(max(1, deadline - clock.now())) / 1000) { return }
                ch.close(promise: nil)
            } catch {
                // a refused connect is retried, but its cause is kept: it is what "no authenticated link" would otherwise hide
                note("dial \(id) \(node.host):\(node.port): \(NetUtil.sanitize(String(describing: error), 160))")
            }
            Thread.sleep(forTimeInterval: 0.15) // retry pacing, not a decision
        }
    }

    /// Called on the event loop once the TLS handshake of a connection is complete.
    func onHandshake(_ channel: Channel, _ fp: String?, _ dialId: Int?, _ handler: LinkHandler) -> Bool {
        guard let fp = fp, let id = pinned[fp] else { note("rejected connection (certificate not pinned)"); return false }
        if let want = dialId {
            if id != want {
                fail(NetAbort(kind: "identity", blamed: want, reporter: selfId, detail: "dial: peer certificate is not the pinned identity of node \(want)"), nil)
                return false
            }
        } else if links[id] == nil || id < selfId {
            note("rejected incoming connection (peer \(id))")
            return false
        }
        return attach(id, channel, handler)
    }

    private func attach(_ id: Int, _ ch: Channel, _ handler: LinkHandler) -> Bool {
        let l = links[id]!
        // The send lock is held from publishing the link until our hello is out: a protocol thread whose connect() already returned may send
        // on this link at once, and its frame must not take seq 0 ahead of the hello ("data before hello" at the peer).
        l.sendLock.lock(); defer { l.sendLock.unlock() }
        lock.lock()
        if l.channel != nil || closing {
            lock.unlock()
            note("duplicate connection from node \(id)")
            return false
        }
        l.channel = ch
        handler.link = l
        lock.unlock()
        cfg.beforeHello?(id)
        // hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin.
        sendFrameLocked(l, "hello", "hello", .object(["id": .int(Int64(selfId))]))
        return true
    }

    // MARK: receive path

    func onData(_ l: Link, _ chunk: [UInt8]) {
        if failed() != nil { return }
        l.add(bytesIn: Int64(chunk.count))
        let bodies: [[UInt8]]
        do { bodies = try l.splitter.push(chunk) } catch {
            fail(NetAbort(kind: "oversize", blamed: l.id, reporter: selfId, detail: "length prefix above MAX_FRAME_BYTES"), nil)
            return
        }
        for b in bodies {
            guard let f = PCAMpc.NetWire.parseFrame(b), let ty = f.jGet("ty")?.jStr, let rd = f.jGet("rd")?.jStr, let sid = f.jGet("sid")?.jStr else {
                if let pv = PCAMpc.NetWire.versionMismatch(b) {
                    fail(NetAbort(kind: "version", blamed: l.id, reporter: selfId,
                                  detail: "peer \(l.id) speaks wire version \(pv), this node speaks \(PCAMpc.NetWire.WIRE_VERSION); upgrade both peers"), nil)
                } else {
                    fail(NetAbort(kind: "malformed", blamed: l.id, reporter: selfId, detail: "undecodable or ill-shaped frame"), nil)
                }
                return
            }
            if sid != cfg.sessionId {
                fail(NetAbort(kind: "wrong-session", blamed: l.id, reporter: selfId, detail: "frame from another session"), nil)
                return
            }
            let d = f.jGet("d") ?? .null
            if ty == "abort" {
                // An abort frame is only a CLAIM by the peer that sent it: we blame that peer, never the party it names.
                let relayed = d.jGet("relayed") == .bool(true)
                let claimedKind = d.jGet("kind")?.jStr.flatMap { PCAMpc.NetWire.ABORT_KINDS.contains($0) ? $0 : nil }
                let maxId = cfg.nodes.map { $0.id }.max() ?? 0
                let cb = NetUtil.int(d.jGet("blamed"))
                let claimedBlame = cb.flatMap { $0 >= 0 && $0 <= maxId ? $0 : nil }
                let detail = d.jGet("detail")?.jStr.map { NetUtil.sanitize($0, 120) } ?? ""
                let claim = NetAbort(kind: "peer-abort", blamed: relayed ? nil : l.id, reporter: selfId,
                                     detail: "peer \(l.id) \(relayed ? "relayed" : "reported") an abort (\(claimedKind ?? "unspecified"), accuses \(claimedBlame.map { String($0) } ?? "no one"), unverified) \(detail)",
                                     claimedKind: claimedKind, claimedBlame: claimedBlame,
                                     reason: relayed ? "relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence" : nil)
                lock.lock()
                let defer_ = deferAborts
                if defer_ { l.inbox.append(Item(rd: rd, d: .null, size: b.count, abort: claim)) } // order-preserving: takes effect when READ
                lock.unlock()
                if defer_ { continue }
                fail(claim, l.id)
                return
            }
            guard let seqD = IV.num(f.jGet("seq")) else { return }
            let seq = Int64(seqD)
            if seq != l.recvSeq {
                fail(NetAbort(kind: seq < l.recvSeq ? "duplicate" : "out-of-order", blamed: l.id, reporter: selfId, detail: "expected seq \(l.recvSeq), got \(seq) (round \(rd))"), nil)
                return
            }
            l.recvSeq += 1
            l.add(framesIn: 1)
            if ty == "hello" {
                let hid = NetUtil.int(d.jGet("id"))
                if l.helloSeen || hid == nil || hid! != l.id {
                    fail(NetAbort(kind: "identity", blamed: l.id, reporter: selfId, detail: "hello claims id \(hid.map { String($0) } ?? "?") on the link pinned to \(l.id)"), nil)
                    return
                }
                lock.lock(); l.helloSeen = true; lock.broadcast(); lock.unlock()
            } else {
                if !l.helloSeen {
                    fail(NetAbort(kind: "malformed", blamed: l.id, reporter: selfId, detail: "data before hello"), nil)
                    return
                }
                var flood = false
                var pause = false
                lock.lock()
                l.inbox.append(Item(rd: rd, d: d, size: b.count, abort: nil))
                l.inboxBytes += b.count
                flood = l.inbox.count > cfg.maxInboxFrames || l.inboxBytes > cfg.maxInboxBytes
                if !flood && !l.paused && (l.inbox.count > cfg.maxInboxFrames / 2 || l.inboxBytes > cfg.maxInboxBytes / 2) { l.paused = true; pause = true }
                lock.unlock()
                if pause { _ = l.channel?.setOption(ChannelOptions.autoRead, value: false) }
                if flood {
                    fail(NetAbort(kind: "flood", blamed: l.id, reporter: selfId, detail: "peer \(l.id) queued more than the inbox cap allows"), nil)
                    return
                }
            }
        }
        lock.lock(); lock.broadcast(); lock.unlock()
    }

    func onClosed(_ l: Link, _ why: String) {
        lock.lock()
        if l.closed { lock.unlock(); return }
        l.closed = true
        let quiet = finished || failure != nil || l.helloSeen
        lock.broadcast()
        lock.unlock()
        if !quiet { note("link \(l.id) closed before hello: \(why)") }
    }

    // MARK: send path

    private func sendFrame(_ l: Link, _ ty: String, _ rd: String, _ d: JSONValue) {
        l.sendLock.lock(); defer { l.sendLock.unlock() }
        sendFrameLocked(l, ty, rd, d)
    }

    /// Requires `l.sendLock`.
    private func sendFrameLocked(_ l: Link, _ ty: String, _ rd: String, _ d: JSONValue) {
        let seq = l.sendSeq
        l.sendSeq += 1
        let frame = PCAMpc.NetWire.Frame(v: .int(Int64(PCAMpc.NetWire.WIRE_VERSION)), ty: ty, sid: cfg.sessionId, seq: .int(seq), rd: rd, d: d)
        guard let raw = try? PCAMpc.NetWire.encodeFrame(frame) else {
            fail(NetAbort(kind: "local", blamed: nil, reporter: selfId, detail: "frame for round '\(rd)' exceeds MAX_FRAME_BYTES"), nil)
            return
        }
        let outs = (cfg.tamper != nil && ty != "hello") ? cfg.tamper!(TamperEvent(to: l.id, frame: frame, raw: raw)) : [raw]
        writeAll(l, outs)
        l.add(framesOut: 1)
    }

    private func writeAll(_ l: Link, _ outs: [[UInt8]]) {
        for b in outs {
            guard let ch = l.channel, ch.isActive else { continue }
            var buf = ch.allocator.buffer(capacity: b.count)
            buf.writeBytes(b)
            ch.writeAndFlush(buf, promise: nil) // a dead link surfaces as a disconnect on the read side
            l.add(bytesOut: Int64(b.count))
        }
    }

    /// Send a protocol message to one peer. Throws the mesh failure if already aborted (fail closed).
    public func send(_ to: Int, _ round: String, _ payload: JSONValue) throws {
        if let f = failed() { throw f }
        guard let l = links[to] else { throw NetError("mesh: no link to \(to)") }
        sendFrame(l, "msg", round, payload)
        if let f = failed() { throw f }
    }

    public func broadcast(_ round: String, _ payload: JSONValue, to: [Int]? = nil) throws {
        for p in to ?? linkOrder { try send(p, round, payload) }
    }

    /// ECDSA-P256/SHA-256 (DER) signature over `data` with this node's TLS identity key.
    public func sign(_ data: [UInt8]) throws -> [UInt8] { [UInt8](try signKey.signature(for: Data(data)).derRepresentation) }

    /// Verify `sig` over `data` against the PINNED certificate of node `peer`. False on any failure.
    public func verify(_ peer: Int, _ data: [UInt8], _ sig: [UInt8]) -> Bool {
        guard peer != selfId, let k = peerKeys[peer], let s = try? P256.Signing.ECDSASignature(derRepresentation: Data(sig)) else { return false }
        return k.isValidSignature(s, for: Data(data))
    }

    /// Receive the next message from `from`, which must belong to `round`. Times out; never hangs.
    public func recv(_ from: Int, _ round: String, timeoutMs: Int64? = nil) throws -> JSONValue {
        guard let l = links[from] else { throw NetError("mesh: no link to \(from)") }
        let timeout = timeoutMs ?? cfg.recvTimeoutMs
        let deadline = clock.now() + timeout
        var toFail: NetAbort? = nil
        var skip: Int? = nil
        lock.lock()
        while true {
            if let cur = failure { lock.unlock(); throw cur }
            if !l.inbox.isEmpty {
                let it = l.inbox.removeFirst()
                if let ab = it.abort { toFail = ab; skip = from; break }
                l.inboxBytes -= it.size
                if l.paused && l.inbox.count <= cfg.maxInboxFrames / 2 && l.inboxBytes <= cfg.maxInboxBytes / 2 {
                    l.paused = false
                    _ = l.channel?.setOption(ChannelOptions.autoRead, value: true)
                    lock.broadcast()
                }
                if it.rd != round {
                    toFail = NetAbort(kind: "wrong-round", blamed: from, reporter: selfId, detail: "expected round '\(round)', got '\(it.rd)'")
                    break
                }
                lock.unlock()
                return it.d
            }
            if l.closed {
                toFail = NetAbort(kind: "disconnect", blamed: from, reporter: selfId, detail: "link to \(from) closed while awaiting '\(round)'")
                break
            }
            let left = deadline - clock.now()
            if !(left > 0) {
                toFail = NetAbort(kind: "timeout", blamed: from, reporter: selfId,
                                  detail: "no '\(round)' message from \(from) within \(timeout)ms (deadline \(timeout)ms; a silent peer is blamed on this local observation only)",
                                  deadlineMs: Int(min(Int64(Int32.max), timeout)))
                break
            }
            _ = lock.wait(until: Date(timeIntervalSinceNow: Double(min(left, 20)) / 1000))
        }
        lock.unlock()
        fail(toFail!, skip)
        throw toFail!
    }

    /// While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and only takes effect when a
    /// receive from that peer reaches it (used for the blame round).
    public func setDeferAborts(_ on: Bool) { lock.lock(); deferAborts = on; lock.unlock() }

    private final class Gather {
        private let l = NSLock()
        var values: [Int: JSONValue] = [:]
        var error: Error?
        func put(_ p: Int, _ v: JSONValue) { l.lock(); values[p] = v; l.unlock() }
        func fail(_ e: Error) { l.lock(); if error == nil { error = e }; l.unlock() }
    }

    /// Receive `round` from every peer in `from` concurrently; a failure on any link throws.
    public func collect(_ round: String, from: [Int]? = nil, timeoutMs: Int64? = nil) throws -> [Int: JSONValue] {
        let ps = from ?? linkOrder
        if ps.count == 1 { return [ps[0]: try recv(ps[0], round, timeoutMs: timeoutMs)] }
        let g = Gather()
        let wg = DispatchGroup()
        for p in ps {
            wg.enter()
            Thread.detachNewThread { [self] in
                do { g.put(p, try recv(p, round, timeoutMs: timeoutMs)) } catch { g.fail(error) }
                wg.leave()
            }
        }
        wg.wait()
        if let e = g.error { throw e }
        return g.values
    }

    // MARK: failure / shutdown

    /// Poison the mesh: record the first failure, tell EVERY peer except `skipPeer` (a forwarded accusation stays a claim, so an innocent bystander is
    /// never blamed for merely closing), close all.
    public func fail(_ err: NetAbort, _ skipPeer: Int?) {
        lock.lock()
        if failure != nil { lock.unlock(); return }
        failure = err
        lock.broadcast()
        lock.unlock()
        let fwd = err.kind == "peer-abort"
        let kind = fwd ? (err.claimedKind ?? "peer-abort") : err.kind
        let blamed = fwd ? err.claimedBlame : err.blamed
        for id in linkOrder {
            let l = links[id]!
            if let s = skipPeer, s == id { continue }
            guard let ch = l.channel, ch.isActive, !l.closed else { continue }
            var d: JObject = ["kind": .string(kind), "blamed": blamed.map { JSONValue.int(Int64($0)) } ?? JSONValue.null, "detail": .string(NetUtil.sanitize(err.message, 200))]
            if fwd { d["relayed"] = .bool(true) }
            l.sendLock.lock()
            let seq = l.sendSeq
            l.sendSeq += 1
            let frame = PCAMpc.NetWire.Frame(v: .int(Int64(PCAMpc.NetWire.WIRE_VERSION)), ty: "abort", sid: cfg.sessionId, seq: .int(seq), rd: "abort", d: .object(d))
            if let raw = try? PCAMpc.NetWire.encodeFrame(frame) { writeAll(l, [raw]) }
            l.sendLock.unlock()
        }
        Thread.detachNewThread { [self] in
            Thread.sleep(forTimeInterval: 0.05)
            closeAll()
        }
    }

    /// Normal completion: flush and close. Peers that are still reading see EOF only after our data.
    public func finish() {
        lock.lock(); finished = true; lock.unlock()
        Thread.sleep(forTimeInterval: 0.1)
        closeAll()
    }

    /// Abrupt shutdown with no abort frames (a crashed node; also the way a launcher stops a straggler).
    public func kill() { closeAll() }

    private func closeAll() {
        lock.lock()
        if closing { lock.unlock(); return }
        closing = true
        let chans = links.values.compactMap { $0.channel }
        let srv = server
        let g = group
        group = nil
        lock.unlock()
        for c in chans { c.close(promise: nil) }
        srv?.close(promise: nil)
        g?.shutdownGracefully(queue: DispatchQueue.global()) { _ in }
    }

    public func stats() -> [LinkStats] { linkOrder.map { links[$0]!.stats() } }
}

/// The channel handler of one TLS connection: attaches the link once the handshake is done, feeds bytes to the mesh, reports closure.
final class LinkHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    let mesh: Mesh
    let box: Mesh.PeerBox
    let dialId: Int?
    let outcome: Mesh.Outcome?
    var link: Mesh.Link?

    init(mesh: Mesh, box: Mesh.PeerBox, dialId: Int?, outcome: Mesh.Outcome?) { self.mesh = mesh; self.box = box; self.dialId = dialId; self.outcome = outcome }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let e = event as? TLSUserEvent, case .handshakeCompleted = e {
            // TCP_NODELAY is a latency nicety set on the live connection and never allowed to fail it: as a bootstrap option a refused setsockopt (EACCES on the CI hosts) failed every connect
            context.channel.setOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1).whenFailure { [mesh = self.mesh] err in mesh.note("TCP_NODELAY not set: \(err)") }
            let ok = mesh.onHandshake(context.channel, box.fp, dialId, self)
            outcome?.finish(ok)
            if !ok { context.close(promise: nil) }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        guard let l = link, let bytes = buf.readBytes(length: buf.readableBytes) else { return }
        mesh.onData(l, bytes)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let l = link { mesh.onClosed(l, "peer ended") }
        outcome?.finish(false)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if let l = link { mesh.onClosed(l, "socket error: \(NetUtil.sanitize(String(describing: error), 120))") } else { mesh.note("tlsClientError: \(NetUtil.sanitize(String(describing: error), 120))") }
        outcome?.finish(false)
        context.close(promise: nil)
    }
}
