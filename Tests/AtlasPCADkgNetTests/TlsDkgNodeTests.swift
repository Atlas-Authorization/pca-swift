import XCTest
import Foundation
import CryptoKit
import Dispatch
import NIOCore
import NIOPosix
import NIOSSL
import AtlasPCAVerify
@testable import AtlasPCADkgNet

/// A self-signed P-256 identity generated at test time (nothing is committed): the certificate is a fixed DER template (v3, ecdsa-with-SHA256, CN only).
struct DkgTestIdentity {
    let keyPem: String
    let certPem: String

    private static func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
        if body.count < 128 { return [tag, UInt8(body.count)] + body }
        var b: [UInt8] = []
        var n = body.count
        while n > 0 { b.insert(UInt8(n & 0xff), at: 0); n >>= 8 }
        return [tag, 0x80 | UInt8(b.count)] + b + body
    }
    private static func utc(_ d: Date) -> [UInt8] {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        let p = c.dateComponents([.year, .month, .day, .hour, .minute, .second], from: d)
        return tlv(0x17, Array(String(format: "%02d%02d%02d%02d%02d%02dZ", (p.year ?? 2000) % 100, p.month ?? 1, p.day ?? 1, p.hour ?? 0, p.minute ?? 0, p.second ?? 0).utf8))
    }
    private static func pem(_ label: String, _ der: [UInt8]) -> String {
        let b = Data(der).base64EncodedString()
        var lines: [String] = []
        var i = b.startIndex
        while i < b.endIndex { let j = b.index(i, offsetBy: 64, limitedBy: b.endIndex) ?? b.endIndex; lines.append(String(b[i..<j])); i = j }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----\n"
    }

    /// `notBefore` / `notAfter` default to a window around now; a test passes a past window for an expired certificate.
    init(cn: String, notBefore: Date = Date().addingTimeInterval(-3600), notAfter: Date = Date().addingTimeInterval(3600)) throws {
        let key = P256.Signing.PrivateKey()
        var serial = (0..<8).map { _ in UInt8.random(in: 0...255) }
        serial[0] = (serial[0] & 0x7f) | 1
        let alg: [UInt8] = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
        let cnTlv: [UInt8] = Self.tlv(0x0c, Array(cn.utf8))
        let cnAttr: [UInt8] = Self.tlv(0x30, [0x06, 0x03, 0x55, 0x04, 0x03] + cnTlv)
        let name: [UInt8] = Self.tlv(0x30, Self.tlv(0x31, cnAttr))
        let validity: [UInt8] = Self.tlv(0x30, Self.utc(notBefore) + Self.utc(notAfter))
        let spki: [UInt8] = [UInt8](key.publicKey.derRepresentation)
        var tbsBody: [UInt8] = [0xa0, 0x03, 0x02, 0x01, 0x02]
        tbsBody += Self.tlv(0x02, serial)
        tbsBody += alg
        tbsBody += name
        tbsBody += validity
        tbsBody += name
        tbsBody += spki
        let tbs = Self.tlv(0x30, tbsBody)
        let sig = [UInt8](try key.signature(for: Data(tbs)).derRepresentation)
        keyPem = key.pemRepresentation
        let sigBits: [UInt8] = Self.tlv(0x03, [0x00] + sig)
        certPem = Self.pem("CERTIFICATE", Self.tlv(0x30, tbs + alg + sigBits))
    }
}

/// A blocking task on its own thread.
final class DkgAsync<T> {
    private let sem = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var outcome: Result<T, Error>?
    init(_ f: @escaping () throws -> T) {
        Thread.detachNewThread { [self] in
            let r: Result<T, Error>
            do { r = .success(try f()) } catch { r = .failure(error) }
            lock.lock(); outcome = r; lock.unlock()
            sem.signal()
        }
    }
    func get(_ seconds: Double = 60) throws -> T {
        guard sem.wait(timeout: .now() + seconds) == .success else { throw NSError(domain: "DkgTest", code: 1, userInfo: [NSLocalizedDescriptionKey: "task timed out"]) }
        lock.lock(); defer { lock.unlock() }
        return try outcome!.get()
    }
}

/// Reports when a connection ends (the server refused it) or delivers bytes.
final class EndProbe: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    let ended = DispatchSemaphore(value: 0)
    private let l = NSLock()
    private var fired = false
    private(set) var receivedBytes = 0
    private func end() { l.lock(); let f = fired; fired = true; l.unlock(); if !f { ended.signal() } }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) { var b = unwrapInboundIn(data); l.lock(); receivedBytes += b.readableBytes; l.unlock(); _ = b.readBytes(length: b.readableBytes) }
    func channelInactive(context: ChannelHandlerContext) { end(); context.fireChannelInactive() }
    func errorCaught(context: ChannelHandlerContext, error: Error) { end(); context.close(promise: nil) }
}

final class TlsDkgNodeTests: XCTestCase {
    static let sid = [UInt8](repeating: 7, count: 32)

    private func node(_ id: Int64, _ ids: [Int64], _ idents: [Int64: DkgTestIdentity], pins: [Int64: String]? = nil) throws -> TlsDkgNode {
        let me = idents[id]!
        let peers = ids.filter { $0 != id }.map { TlsDkgPeerCert(id: $0, certPem: pins?[$0] ?? idents[$0]!.certPem) }
        return try startTlsDkgNode(TlsDkgNodeOpts(selfId: id, sessionId: Self.sid, keyPem: me.keyPem, certPem: me.certPem, peerCerts: peers))
    }

    /// Open a connection to 127.0.0.1:`port` as `identity` (nil = no client certificate; `plaintext` = no TLS at all) and report whether the node ended it without a single byte.
    private func refused(port: Int, identity: DkgTestIdentity?, maxVersion: TLSVersion = .tlsv13, plaintext: Bool = false) throws -> Bool {
        let g = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? g.syncShutdownGracefully() }
        let probe = EndProbe()
        var cfg = TLSConfiguration.makeClientConfiguration()
        cfg.minimumTLSVersion = maxVersion == .tlsv13 ? .tlsv13 : .tlsv12
        cfg.maximumTLSVersion = maxVersion
        if let id = identity {
            cfg.certificateChain = [.certificate(try NIOSSLCertificate(bytes: Array(id.certPem.utf8), format: .pem))]
            cfg.privateKey = .privateKey(try NIOSSLPrivateKey(bytes: Array(id.keyPem.utf8), format: .pem))
        }
        cfg.certificateVerification = .noHostnameVerification
        let ctx = try NIOSSLContext(configuration: cfg)
        let ch = try ClientBootstrap(group: g).channelInitializer { ch in
            if plaintext { return ch.pipeline.addHandler(probe) }
            do {
                let ssl = try NIOSSLClientHandler(context: ctx, serverHostname: nil, customVerificationCallback: { _, p in p.succeed(.certificateVerified) })
                return ch.pipeline.addHandlers([ssl, probe])
            } catch { return ch.eventLoop.makeFailedFuture(error) }
        }.connect(host: "127.0.0.1", port: port).wait()
        if plaintext {
            var b = ch.allocator.buffer(capacity: 16)
            b.writeString("GET / HTTP/1.1\r\n\r\n")
            ch.writeAndFlush(b, promise: nil)
        }
        let done = probe.ended.wait(timeout: .now() + 10) == .success
        ch.close(promise: nil)
        return done && probe.receivedBytes == 0
    }

    func testThreePartyCeremonyOverMutualTls() throws {
        let ids: [Int64] = [1, 2, 3]
        var idents: [Int64: DkgTestIdentity] = [:]
        for id in ids { idents[id] = try DkgTestIdentity(cn: "p\(id)") }
        let nodes = try Dictionary(uniqueKeysWithValues: ids.map { ($0, try node($0, ids, idents)) })
        defer { for n in nodes.values { n.close() } }
        let addrs = ids.map { TlsDkgAddress(id: $0, host: "127.0.0.1", port: nodes[$0]!.port) }
        let runs = ids.map { id in
            DkgAsync<PCAFrostDkg.RunResult> {
                let ch = try nodes[id]!.connect(addrs.filter { $0.id != id }, connectTimeoutMs: 20_000)
                return try PCAFrostDkg.runDkgOverChannel(ch, t: .int(2), participants: .array(ids.map { .int($0) }), sessionId: Self.sid, timeoutMs: 20_000)
            }
        }
        // every party's outcome is read before any is thrown: a listener's timeout hides the dialler's own reason
        let outcomes = runs.map { r in Result<PCAFrostDkg.RunResult, Error> { try r.get() } }
        let failures = outcomes.enumerated().compactMap { i, o -> String? in if case .failure(let e) = o { return "party \(ids[i]): \(e)" }; return nil }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: " | "))
        let results = try outcomes.map { try $0.get() }
        for r in results {
            XCTAssertEqual(r.keyPackage.groupPublicKey, results[0].keyPackage.groupPublicKey, "the parties disagree on the group key")
            XCTAssertEqual(r.qualified, ids)
        }
    }

    func testRefusals() throws {
        // node 2 listens (only a higher-numbered party, here 3, may dial it); node 3 is the legitimate dialler
        let ids: [Int64] = [1, 2, 3]
        var idents: [Int64: DkgTestIdentity] = [:]
        for id in ids { idents[id] = try DkgTestIdentity(cn: "p\(id)") }
        let n2 = try node(2, [2, 3], idents), n3 = try node(3, [2, 3], idents)
        defer { n2.close(); n3.close() }
        let stranger = try DkgTestIdentity(cn: "stranger")
        let expired = try DkgTestIdentity(cn: "p3", notBefore: Date().addingTimeInterval(-7200), notAfter: Date().addingTimeInterval(-3600))
        XCTAssertTrue(try refused(port: n2.port, identity: stranger), "an unpinned certificate must be refused")
        XCTAssertTrue(try refused(port: n2.port, identity: nil), "a client without a certificate must be refused")
        XCTAssertTrue(try refused(port: n2.port, identity: idents[3], maxVersion: .tlsv12), "TLS 1.2 must be refused")
        XCTAssertTrue(try refused(port: n2.port, identity: nil, plaintext: true), "a plaintext client must be refused")
        XCTAssertTrue(try refused(port: n2.port, identity: idents[2]), "a connection that presents this node's own certificate (not a pinned peer) must be refused")
        XCTAssertTrue(try refused(port: n2.port, identity: expired), "a certificate outside its validity window must be refused")
        // after all of that the legitimate dial still links, and so does nothing else
        let a2 = DkgAsync<PCADkgChannel> { try n2.connect([], connectTimeoutMs: 20_000) }
        let a3 = DkgAsync<PCADkgChannel> { try n3.connect([TlsDkgAddress(id: 2, host: "127.0.0.1", port: n2.port)], connectTimeoutMs: 20_000) }
        let r2 = Result<PCADkgChannel, Error> { try a2.get() }, r3 = Result<PCADkgChannel, Error> { try a3.get() }
        if case .failure(let e) = r2 { XCTFail("listener 2: \(e)") }
        if case .failure(let e) = r3 { XCTFail("dialler 3: \(e)") }
        let c2 = try r2.get(), c3 = try r3.get()
        XCTAssertEqual(c2.peers, [3])
        XCTAssertEqual(c3.peers, [2])
        // a second connection for the already linked identity is refused
        XCTAssertTrue(try refused(port: n2.port, identity: idents[3]), "a second connection for a linked identity must be refused")
    }

    func testLowerNumberedPartyCannotDial() throws {
        // node 3 listens; party 2 holds a pinned certificate but is lower-numbered, so 3 never accepts it
        let ids: [Int64] = [2, 3]
        var idents: [Int64: DkgTestIdentity] = [:]
        for id in ids { idents[id] = try DkgTestIdentity(cn: "p\(id)") }
        let n3 = try node(3, ids, idents)
        defer { n3.close() }
        XCTAssertTrue(try refused(port: n3.port, identity: idents[2]), "a lower-numbered peer must not be accepted")
    }

    func testWrongPinNeverLinks() throws {
        let ids: [Int64] = [1, 2]
        var idents: [Int64: DkgTestIdentity] = [:]
        for id in ids { idents[id] = try DkgTestIdentity(cn: "p\(id)") }
        let foreign = try DkgTestIdentity(cn: "foreign")
        // control: with the right pins the same two identities DO link, so the refusal below is the pin's doing and not a handshake that never works
        do {
            let c1 = try node(1, ids, idents), c2 = try node(2, ids, idents)
            defer { c1.close(); c2.close() }
            let listening = DkgAsync<PCADkgChannel> { try c1.connect([TlsDkgAddress(id: 2, host: "127.0.0.1", port: c2.port)], connectTimeoutMs: 10_000) }
            let dialled = try c2.connect([TlsDkgAddress(id: 1, host: "127.0.0.1", port: c1.port)], connectTimeoutMs: 10_000)
            XCTAssertEqual(dialled.peers, [1])
            XCTAssertEqual(try listening.get().peers, [2])
        }
        let a = try node(1, ids, idents)
        let b = try node(2, ids, idents, pins: [1: foreign.certPem]) // the dialled peer shows a certificate that is not the pinned one
        defer { a.close(); b.close() }
        XCTAssertThrowsError(try b.connect([TlsDkgAddress(id: 1, host: "127.0.0.1", port: a.port)], connectTimeoutMs: 600)) {
            XCTAssertEqual(($0 as? PCADkgChannelError)?.code, "timeout")
        }
    }

    func testConfigurationRefusals() throws {
        let a = try DkgTestIdentity(cn: "a"), b = try DkgTestIdentity(cn: "b")
        func start(_ peers: [TlsDkgPeerCert]) throws -> TlsDkgNode { try startTlsDkgNode(TlsDkgNodeOpts(selfId: 1, sessionId: Self.sid, keyPem: a.keyPem, certPem: a.certPem, peerCerts: peers)) }
        XCTAssertThrowsError(try start([TlsDkgPeerCert(id: 2, certPem: b.certPem), TlsDkgPeerCert(id: 3, certPem: b.certPem)]), "one certificate pinned for two ids")
        XCTAssertThrowsError(try start([TlsDkgPeerCert(id: 1, certPem: b.certPem)]), "a peer with this node's own id")
        XCTAssertThrowsError(try start([TlsDkgPeerCert(id: 2, certPem: a.certPem)]), "this node's own certificate pinned as a peer")
        XCTAssertThrowsError(try start([TlsDkgPeerCert(id: 2, certPem: "not a pem")]))
        let n = try start([TlsDkgPeerCert(id: 2, certPem: b.certPem)])
        defer { n.close() }
        XCTAssertThrowsError(try n.connect([TlsDkgAddress(id: 9, host: "127.0.0.1", port: 1)], connectTimeoutMs: 100)) { XCTAssertEqual(($0 as? PCADkgChannelError)?.code, "identity") }
    }
}
