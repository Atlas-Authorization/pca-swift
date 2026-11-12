import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Ledger.swift 78: the walk that strips trailing ones from the old size - 1. With old size 1 (fn = 0) a mutated condition never ends.
final class A0DeadlineLedgerTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testA1ConsistencyFromSizeOneToTwo() {
        let old = [UInt8](repeating: 7, count: 32), c = [UInt8](repeating: 9, count: 32)
        let oldRoot = Base64URLStrict.encode(old), newRoot = Base64URLStrict.encode(Merkle.nodeHash(old, c))
        let proof: JSONValue = .object(["oldSize": .int(1), "newSize": .int(2), "path": .array([.string(Base64URLStrict.encode(c))])])
        let ok: Bool? = S2Deadline.within(10, "verifyConsistency 1 -> 2") { Ledger.verifyConsistency(.string(oldRoot), .string(newRoot), proof) }
        XCTAssertEqual(ok, true, "line 78")
        let bad: Bool? = S2Deadline.within(10, "verifyConsistency 1 -> 2, wrong new root") { Ledger.verifyConsistency(.string(oldRoot), .string(oldRoot), proof) }
        XCTAssertEqual(bad, false, "line 78: a wrong new root is refused")
    }
}
