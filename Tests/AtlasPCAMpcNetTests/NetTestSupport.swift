import XCTest
import Foundation
import Dispatch
import NIOCore
import NIOPosix
import NIOSSL
import AtlasPCAVerify
import AtlasPCAMpc
@testable import AtlasPCAMpcNet

/// A blocking task on its own thread (the protocol side is blocking; the common pool is never used).
final class Async<T> {
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
    /// The task's value, or its error; fails the test on a timeout.
    func get(_ seconds: Double = 30) throws -> T {
        guard sem.wait(timeout: .now() + seconds) == .success else { throw NSError(domain: "NetTest", code: 1, userInfo: [NSLocalizedDescriptionKey: "task timed out"]) }
        lock.lock(); defer { lock.unlock() }
        return try outcome!.get()
    }
    var isDone: Bool { lock.lock(); defer { lock.unlock() }; return outcome != nil }
}

enum NetTestSupport {
    static let sid = "mesh-test-session"

    /// Identities from fixed seeds: nothing secret is committed, and a run is reproducible.
    static func identity(_ name: String) throws -> NetCerts.Identity { try NetCerts.generate(cn: name, seed: Array("atlas-pca-mpc-net-test/\(name)".utf8)) }

    static func ports(_ n: Int) throws -> [Int] { try NetLaunch.reservePorts(n) }

    static func cfg(_ me: Int, _ nodes: [NodeAddr], _ id: NetCerts.Identity, connectMs: Int64, recvMs: Int64) -> MeshConfig {
        var c = MeshConfig(selfId: me, nodes: nodes, keyPem: id.keyPem, certPem: id.certPem, sessionId: sid)
        c.listenHost = "127.0.0.1"
        c.connectTimeoutMs = connectMs
        c.recvTimeoutMs = recvMs
        return c
    }

    static func abort(_ e: Error?, file: StaticString = #filePath, line: UInt = #line) -> NetAbort? {
        let a = e as? NetAbort
        if a == nil { XCTFail("expected a NetAbort, got \(String(describing: e))", file: file, line: line) }
        return a
    }

    static func thrown<T>(_ f: () throws -> T) -> Error? {
        do { _ = try f(); return nil } catch { return error }
    }
}

/// A raw TLS 1.3 client speaking the frame format, standing in for a node; it presents `me` as its client certificate and trusts any server.
final class RawPeer {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var channel: Channel!

    init(me: NetCerts.Identity, port: Int) throws {
        var cc = TLSConfiguration.makeClientConfiguration()
        cc.certificateChain = [.certificate(try NIOSSLCertificate(bytes: Array(me.certPem.utf8), format: .pem))]
        cc.privateKey = .privateKey(try NIOSSLPrivateKey(bytes: Array(me.keyPem.utf8), format: .pem))
        cc.minimumTLSVersion = .tlsv13
        cc.maximumTLSVersion = .tlsv13
        cc.certificateVerification = .none
        let ctx = try NIOSSLContext(configuration: cc)
        let end = Date().addingTimeInterval(10)
        while true {
            do {
                channel = try ClientBootstrap(group: group).channelInitializer { ch in
                    do { return ch.pipeline.addHandler(try NIOSSLClientHandler(context: ctx, serverHostname: nil)) } catch { return ch.eventLoop.makeFailedFuture(error) }
                }.connect(host: "127.0.0.1", port: port).wait()
                break
            } catch {
                if Date() > end { throw error }
                Thread.sleep(forTimeInterval: 0.1)
            }
        }
    }

    func write(_ bytes: [UInt8]) {
        var b = channel.allocator.buffer(capacity: bytes.count)
        b.writeBytes(bytes)
        try? channel.writeAndFlush(b).wait()
    }

    func frame(_ ty: String, _ rd: String, _ seq: Int64, _ d: JSONValue) {
        let f = PCAMpc.NetWire.Frame(v: .int(Int64(PCAMpc.NetWire.WIRE_VERSION)), ty: ty, sid: NetTestSupport.sid, seq: .int(seq), rd: rd, d: d)
        write((try? PCAMpc.NetWire.encodeFrame(f)) ?? [])
    }

    func hello(_ claimedId: Int) { frame("hello", "hello", 0, .object(["id": .int(Int64(claimedId))])) }

    func close() {
        try? channel.close().wait()
        try? group.syncShutdownGracefully()
    }
}
