import XCTest
import Foundation
import AtlasPCAVerify
import AtlasPCAMpc
import NIOCore
import NIOPosix
@testable import AtlasPCAMpcNet

/// The mutual-TLS mesh over loopback: an honest 3-node exchange, and the refusals (wrong pin, wrong hello id, oversize, replay, wrong round, early
/// close, silent peer, unpinned client). Identities are derived from fixed seeds.
final class NetMeshTests: XCTestCase {
    typealias S = NetTestSupport

    func testHonestThreeNodeExchange() throws {
        let n = 3
        let ids = try (0..<n).map { try S.identity("node\($0)") }
        let nodes = (0..<n).map { NodeAddr(id: $0, host: "127.0.0.1", port: 0, certPem: ids[$0].certPem) }
        let meshes = try (0..<n).map { try AtlasPCAMpcNet.Mesh(S.cfg($0, nodes, ids[$0], connectMs: 20_000, recvMs: 10_000)) }
        try S.wire(meshes)
        let conn = meshes.map { m in Async { try m.connect() } }
        for c in conn { try c.get(30) }
        let runs = (0..<n).map { me in
            Async { () -> [Int: JSONValue] in
                try meshes[me].broadcast("r1", .object(["x": .int(Int64(me))]))
                return try meshes[me].collect("r1")
            }
        }
        for i in 0..<n {
            let got = try runs[i].get(30)
            XCTAssertEqual(got.count, n - 1)
            for (peer, v) in got {
                XCTAssertNotEqual(peer, i)
                XCTAssertEqual(v.jGet("x"), .int(Int64(peer)))
            }
        }
        // signatures are verifiable against the pinned certificate only
        let data = Array("statement".utf8)
        let sig = try meshes[0].sign(data)
        XCTAssertTrue(meshes[1].verify(0, data, sig))
        XCTAssertFalse(meshes[1].verify(2, data, sig))
        XCTAssertFalse(meshes[1].verify(0, Array("other".utf8), sig))
        XCTAssertFalse(meshes[0].verify(0, data, sig))
        for m in meshes { m.finish() }
    }

    /// The acceptor's protocol thread sends the moment the link is open, before the attaching thread has sent our hello. The hello must still be
    /// the first frame: the peer receives the data, not "data before hello".
    func testASendRacingTheHelloDoesNotOvertakeIt() throws {
        let ids = try (0..<2).map { try S.identity("node\($0)") }
        let nodes = (0..<2).map { NodeAddr(id: $0, host: "127.0.0.1", port: 0, certPem: ids[$0].certPem) }
        var c0 = S.cfg(0, nodes, ids[0], connectMs: 20_000, recvMs: 10_000)
        final class Box: @unchecked Sendable { var m: AtlasPCAMpcNet.Mesh? }
        let box = Box()
        c0.unsafeTestHooks = true
        c0.beforeHello = { peer in
            let m = box.m!
            if m.links[peer]!.sendLock.`try`() { // the link is sendable before the hello: send now, which would take seq 0 (the bug)
                m.links[peer]!.sendLock.unlock()
                try? m.send(peer, "r1", .string("payload"))
            } else {
                _ = Async { try m.send(peer, "r1", .string("payload")) } // parked behind the hello
            }
        }
        let meshes = [try AtlasPCAMpcNet.Mesh(c0), try AtlasPCAMpcNet.Mesh(S.cfg(1, nodes, ids[1], connectMs: 20_000, recvMs: 10_000))]
        box.m = meshes[0]
        try S.wire(meshes)
        let conn = meshes.map { m in Async { try m.connect() } }
        for c in conn { try c.get(30) }
        XCTAssertEqual(try meshes[1].recv(0, "r1"), .string("payload"))
        XCTAssertNil(meshes[1].failed())
        for m in meshes { m.finish() }
    }

    /// Bind first: the advertised port is the held port, the ports differ, and nothing probes and releases.
    func testWireAdvertisesTheBoundPorts() throws {
        let ids = try (0..<2).map { try S.identity("bind\($0)") }
        let nodes = (0..<2).map { NodeAddr(id: $0, host: "127.0.0.1", port: 0, certPem: ids[$0].certPem) }
        let meshes = try (0..<2).map { try AtlasPCAMpcNet.Mesh(S.cfg($0, nodes, ids[$0], connectMs: 1_000, recvMs: 1_000)) }
        let ports = try S.wire(meshes)
        XCTAssertTrue(ports[0] > 0 && ports[1] > 0 && ports[0] != ports[1])
        XCTAssertEqual(meshes[0].boundPort(), ports[0])
        XCTAssertEqual(try meshes[1].listen(), ports[1]) // idempotent
        let again = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? again.syncShutdownGracefully() }
        for p in ports { XCTAssertThrowsError(try ServerBootstrap(group: again).bind(host: "127.0.0.1", port: p).wait(), "a node still holds the port it advertised") }
        for m in meshes { m.kill() }
    }

    func testPinnedCertMismatchRefusesTheLink() throws {
        let real0 = try S.identity("real0"), imposter = try S.identity("imposter"), id1 = try S.identity("node1")
        // node 1 pins an imposter certificate for node 0, so the real node 0 must be refused
        let view0 = [NodeAddr(id: 0, host: "127.0.0.1", port: 0, certPem: real0.certPem), NodeAddr(id: 1, host: "127.0.0.1", port: 0, certPem: id1.certPem)]
        let view1 = [NodeAddr(id: 0, host: "127.0.0.1", port: 0, certPem: imposter.certPem), NodeAddr(id: 1, host: "127.0.0.1", port: 0, certPem: id1.certPem)]
        let m0 = try AtlasPCAMpcNet.Mesh(S.cfg(0, view0, real0, connectMs: 2_500, recvMs: 2_000))
        let m1 = try AtlasPCAMpcNet.Mesh(S.cfg(1, view1, id1, connectMs: 2_500, recvMs: 2_000))
        try S.wire([m0, m1])
        let c0 = Async { try m0.connect() }
        let c1 = Async { try m1.connect() }
        let e1 = S.thrown { try c1.get(20) }
        XCTAssertTrue(["timeout", "identity"].contains(S.abort(e1)?.kind ?? ""))
        XCTAssertNotNil(S.thrown { try c0.get(20) })
    }

    /// A dial that cannot connect must say why: the cause was once swallowed, leaving only "no authenticated link" (the mesh job's failure).
    func testARefusedDialRecordsItsCause() throws {
        let id0 = try S.identity("dead0"), id1 = try S.identity("dead1")
        // node 0 never listens: its address stays port 0, which nothing can accept on
        let nodes = [NodeAddr(id: 0, host: "127.0.0.1", port: 0, certPem: id0.certPem), NodeAddr(id: 1, host: "127.0.0.1", port: 0, certPem: id1.certPem)]
        let m1 = try AtlasPCAMpcNet.Mesh(S.cfg(1, nodes, id1, connectMs: 1_500, recvMs: 1_000))
        let e = S.thrown { try Async { try m1.connect() }.get(20) }
        XCTAssertEqual(S.abort(e)?.kind, "timeout")
        XCTAssertTrue(m1.events().contains { $0.hasPrefix("dial 0 127.0.0.1:") }, "events: \(m1.events())")
    }

    func testTamperHookNeedsExplicitOptIn() throws {
        let id0 = try S.identity("n0"), id1 = try S.identity("n1")
        let nodes = [NodeAddr(id: 0, host: "127.0.0.1", port: 1, certPem: id0.certPem), NodeAddr(id: 1, host: "127.0.0.1", port: 2, certPem: id1.certPem)]
        var c = S.cfg(0, nodes, id0, connectMs: 1000, recvMs: 1000)
        c.tamper = { ev in [ev.raw] }
        XCTAssertThrowsError(try AtlasPCAMpcNet.Mesh(c))
        // a node whose own certificate differs from the one listed for it is refused
        XCTAssertThrowsError(try AtlasPCAMpcNet.Mesh(S.cfg(0, nodes, id1, connectMs: 1000, recvMs: 1000)))
        // two nodes cannot share one certificate
        let dup = [NodeAddr(id: 0, host: "127.0.0.1", port: 1, certPem: id0.certPem), NodeAddr(id: 1, host: "127.0.0.1", port: 2, certPem: id0.certPem)]
        XCTAssertThrowsError(try AtlasPCAMpcNet.Mesh(S.cfg(0, dup, id0, connectMs: 1000, recvMs: 1000)))
    }

    // ---- refusals from a hand-driven peer (node 1 dials node 0) ----

    private struct Rig { let id0: NetCerts.Identity; let id1: NetCerts.Identity; let m0: AtlasPCAMpcNet.Mesh; let connect: Async<Void>; let port: Int }

    private func rig(connectMs: Int64, recvMs: Int64, clock: MeshClock? = nil) throws -> Rig {
        let id0 = try S.identity("n0"), id1 = try S.identity("n1")
        let nodes = [NodeAddr(id: 0, host: "127.0.0.1", port: 0, certPem: id0.certPem), NodeAddr(id: 1, host: "127.0.0.1", port: 1, certPem: id1.certPem)]
        var c = S.cfg(0, nodes, id0, connectMs: connectMs, recvMs: recvMs)
        c.clock = clock
        let m0 = try AtlasPCAMpcNet.Mesh(c)
        let p = try m0.listen() // held from here on: the raw peer dials the port the node really holds
        return Rig(id0: id0, id1: id1, m0: m0, connect: Async { try m0.connect() }, port: p)
    }

    func testHelloWithWrongPartyIdIsRefused() throws {
        let r = try rig(connectMs: 10_000, recvMs: 5_000)
        let p = try RawPeer(me: r.id1, port: r.port)
        defer { p.close() }
        p.hello(5)
        let a = S.abort(S.thrown { try r.connect.get(15) })
        XCTAssertEqual(a?.kind, "identity")
        XCTAssertEqual(a?.blamed, 1)
    }

    func testOversizeLengthPrefixIsRefused() throws {
        let r = try rig(connectMs: 10_000, recvMs: 5_000)
        let p = try RawPeer(me: r.id1, port: r.port)
        defer { p.close() }
        p.hello(1)
        try r.connect.get(15)
        let bad = PCAMpc.NetWire.MAX_FRAME_BYTES + 1
        p.write([UInt8(bad >> 24 & 0xff), UInt8(bad >> 16 & 0xff), UInt8(bad >> 8 & 0xff), UInt8(bad & 0xff)])
        let a = S.abort(S.thrown { try r.m0.recv(1, "x", timeoutMs: 5_000) })
        XCTAssertEqual(a?.kind, "oversize")
        XCTAssertEqual(a?.blamed, 1)
    }

    func testReplayedSequenceNumberIsRefused() throws {
        let r = try rig(connectMs: 10_000, recvMs: 5_000)
        let p = try RawPeer(me: r.id1, port: r.port)
        defer { p.close() }
        p.hello(1)
        try r.connect.get(15)
        p.frame("msg", "x", 1, .string("a"))
        p.frame("msg", "x", 1, .string("b"))
        // the first frame is valid and may be read before the replay is seen: the refusal is the second read at the latest
        XCTAssertEqual(S.abort(S.thrown { _ = try r.m0.recv(1, "x", timeoutMs: 5_000); _ = try r.m0.recv(1, "x", timeoutMs: 5_000) })?.kind, "duplicate")
    }

    func testSkippedSequenceNumberIsRefused() throws {
        let r = try rig(connectMs: 10_000, recvMs: 5_000)
        let p = try RawPeer(me: r.id1, port: r.port)
        defer { p.close() }
        p.hello(1)
        try r.connect.get(15)
        p.frame("msg", "x", 5, .string("a"))
        XCTAssertEqual(S.abort(S.thrown { try r.m0.recv(1, "x", timeoutMs: 5_000) })?.kind, "out-of-order")
    }

    func testWrongRoundIsRefused() throws {
        let r = try rig(connectMs: 10_000, recvMs: 5_000)
        let p = try RawPeer(me: r.id1, port: r.port)
        defer { p.close() }
        p.hello(1)
        try r.connect.get(15)
        p.frame("msg", "other", 1, .string("a"))
        let a = S.abort(S.thrown { try r.m0.recv(1, "x", timeoutMs: 5_000) })
        XCTAssertEqual(a?.kind, "wrong-round")
        XCTAssertEqual(a?.blamed, 1)
    }

    func testEarlyCloseIsADisconnect() throws {
        let r = try rig(connectMs: 10_000, recvMs: 5_000)
        let p = try RawPeer(me: r.id1, port: r.port)
        p.hello(1)
        try r.connect.get(15)
        p.close()
        let a = S.abort(S.thrown { try r.m0.recv(1, "x", timeoutMs: 5_000) })
        XCTAssertEqual(a?.kind, "disconnect")
        XCTAssertEqual(a?.blamed, 1)
    }

    func testSilentPeerIsBlamedAfterTheDeadline() throws {
        let r = try rig(connectMs: 10_000, recvMs: 5_000)
        let p = try RawPeer(me: r.id1, port: r.port)
        defer { p.close() }
        p.hello(1)
        try r.connect.get(15)
        let a = S.abort(S.thrown { try r.m0.recv(1, "x", timeoutMs: 300) })
        XCTAssertEqual(a?.kind, "timeout")
        XCTAssertEqual(a?.blamed, 1)
        XCTAssertEqual(a?.deadlineMs, 300)
    }

    func testClientWithAnUnpinnedCertificateNeverLinks() throws {
        let r = try rig(connectMs: 2_000, recvMs: 1_000)
        let stranger = try S.identity("stranger")
        if let p = try? RawPeer(me: stranger, port: r.port) {
            p.hello(1)
            defer { p.close() }
            let a = S.abort(S.thrown { try r.connect.get(15) })
            XCTAssertEqual(a?.kind, "timeout")
        } else {
            XCTAssertEqual(S.abort(S.thrown { try r.connect.get(15) })?.kind, "timeout")
        }
    }

    /// The deadline is read from the injected clock: real time passing changes nothing, advancing the virtual clock fires it.
    func testTheMeshClockIsInjectable() throws {
        let clock = ManualMeshClock()
        let r = try rig(connectMs: 10_000, recvMs: 5_000, clock: clock)
        let p = try RawPeer(me: r.id1, port: r.port)
        defer { p.close() }
        p.hello(1)
        try r.connect.get(15)
        let waiting = Async { try r.m0.recv(1, "x", timeoutMs: 1_000) }
        Thread.sleep(forTimeInterval: 0.5)
        XCTAssertFalse(waiting.isDone, "no real-time deadline: the manual clock has not moved")
        clock.advance(1_001)
        let a = S.abort(S.thrown { try waiting.get(10) })
        XCTAssertEqual(a?.kind, "timeout")
        XCTAssertEqual(a?.blamed, 1)
    }

    /// The frame-level fault kinds a malicious sender can apply are refused by the receiver (here: garbage and a wrong session).
    func testATamperedSenderIsRefusedByItsPeer() throws {
        for kind in [FrameFaultKind.garbage, .wrongSession, .skipSeq, .wrongRound] {
            let ids = try (0..<2).map { try S.identity("t\($0)") }
            let nodes = (0..<2).map { NodeAddr(id: $0, host: "127.0.0.1", port: 0, certPem: ids[$0].certPem) }
            var c1 = S.cfg(1, nodes, ids[1], connectMs: 15_000, recvMs: 5_000)
            c1.tamper = NetFaults.tamperFor(FrameFault(kind: kind, round: "r1"))
            c1.unsafeTestHooks = true
            let m0 = try AtlasPCAMpcNet.Mesh(S.cfg(0, nodes, ids[0], connectMs: 15_000, recvMs: 5_000))
            let m1 = try AtlasPCAMpcNet.Mesh(c1)
            try S.wire([m0, m1])
            let a0 = Async { try m0.connect() }, a1 = Async { try m1.connect() }
            try a0.get(30); try a1.get(30)
            try m1.send(0, "r1", .string("hello"))
            let a = S.abort(S.thrown { try m0.recv(1, "r1", timeoutMs: 5_000) })
            XCTAssertEqual(a?.blamed, 1, "\(kind)")
            m0.kill(); m1.kill()
        }
    }
}
