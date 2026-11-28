import XCTest
import Foundation
import AtlasPCAVerify
import AtlasPCAMpc
@testable import AtlasPCAMpcNet

/// The base OT over the mutual-TLS mesh (the ot-sender / ot-receiver roles), two nodes on loopback.
final class NetOtNetTests: XCTestCase {
    typealias S = NetTestSupport

    private func pair(_ kind: String, _ count: Int) throws -> (NetOtNet.Result?, NetOtNet.Result?, Error?, Error?) {
        let ids = try (0..<2).map { try S.identity("ot\($0)") }
        let nodes = (0..<2).map { NodeAddr(id: $0, host: "127.0.0.1", port: 0, certPem: ids[$0].certPem) }
        let meshes = try (0..<2).map { try AtlasPCAMpcNet.Mesh(S.cfg($0, nodes, ids[$0], connectMs: 20_000, recvMs: 10_000)) }
        try S.wire(meshes)
        let conn = meshes.map { m in Async { try m.connect() } }
        for c in conn { try c.get(30) }
        let snd = Async { try NetOtNet.runOtSender(meshes[0], peer: 1, kind: kind, count: count) }
        let rcv = Async { try NetOtNet.runOtReceiver(meshes[1], peer: 0, kind: kind, count: count) }
        var s: NetOtNet.Result?, r: NetOtNet.Result?, se: Error?, re: Error?
        do { s = try snd.get(30) } catch { se = error }
        do { r = try rcv.get(30) } catch { re = error }
        for m in meshes { m.kill() }
        return (s, r, se, re)
    }

    func testEcBaseOtOverTheMesh() throws {
        let (s, r, se, re) = try pair("ec", 16)
        XCTAssertNil(se)
        XCTAssertNil(re)
        XCTAssertEqual(s?.matched, true)
        XCTAssertEqual(r?.matched, true)
        XCTAssertEqual(s?.count, 16)
    }

#if canImport(AtlasPCALweOt)
    func testLweBaseOtOverTheMesh() throws {
        let (s, r, se, re) = try pair("lwe", 4)
        XCTAssertNil(se)
        XCTAssertNil(re)
        XCTAssertEqual(s?.kind, "lwe")
        XCTAssertEqual(s?.matched, true)
        XCTAssertEqual(r?.matched, true)
    }
#else
    func testLweKindIsRefusedWithoutTheLibrary() throws {
        let (s, r, se, re) = try pair("lwe", 2)
        XCTAssertNil(s)
        XCTAssertNil(r)
        XCTAssertEqual((se as? NetAbort)?.kind, "local")
        XCTAssertEqual((re as? NetAbort)?.kind, "local")
    }
#endif

    func testUnknownKindIsRefused() throws {
        let (s, r, se, re) = try pair("rsa", 2)
        XCTAssertNil(s)
        XCTAssertNil(r)
        XCTAssertNotNil(se)
        XCTAssertNotNil(re)
    }
}
