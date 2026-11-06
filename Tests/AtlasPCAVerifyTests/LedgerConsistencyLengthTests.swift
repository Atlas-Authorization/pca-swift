import XCTest
@testable import AtlasPCAVerify

/// A consistency-proof node (path element or the old root that starts the walk) that is not exactly 32 bytes is refused, in the
/// ledger verifier and the mesh's own copy. Without the check, old size 1 starts from the old root itself, so a 31- or 33-byte old
/// root plus a crafted new root "proved" consistency. The 32-byte control is the same construction.
final class LedgerConsistencyLengthTests: XCTestCase {
    static func b(_ x: [UInt8]) -> String { Base64URLStrict.encode(x) }
    static func node(_ l: [UInt8], _ r: [UInt8]) -> [UInt8] { Merkle.nodeHash(l, r) }
    static func proof(_ path: [UInt8]) -> JObject { ["oldSize": .int(1), "newSize": .int(2), "path": .array([.string(b(path))])] }

    func check(_ verify: (String, String, JObject) -> Bool, _ what: String) {
        let c = [UInt8](repeating: 9, count: 32)
        for len in [31, 33] {
            let bad = [UInt8](repeating: 7, count: len)
            XCTAssertFalse(verify(Self.b(bad), Self.b(Self.node(bad, c)), Self.proof(c)), "\(what): old root of \(len) bytes")
            XCTAssertFalse(verify(Self.b(c), Self.b(Self.node(c, bad)), Self.proof(bad)), "\(what): path node of \(len) bytes")
        }
        let ok = [UInt8](repeating: 7, count: 32)
        XCTAssertTrue(verify(Self.b(ok), Self.b(Self.node(ok, c)), Self.proof(c)), "\(what): 32-byte control")
        XCTAssertTrue(verify(Self.b(c), Self.b(Self.node(c, ok)), Self.proof(ok)), "\(what): 32-byte control (path)")
    }

    func testLedgerRefusesWrongLengthNodes() {
        check({ Ledger.verifyConsistency(.string($0), .string($1), .object($2)) }, "Ledger")
    }

    func testMeshRefusesWrongLengthNodes() {
        check({ Mesh.consistency($0, $1, $2) }, "Mesh")
    }
}
