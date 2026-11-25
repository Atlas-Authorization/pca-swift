import XCTest
import Foundation
@testable import AtlasPCAVerify

/// CaveatLang.swift 498: the slot scan advances one slot per turn. A mutated step never ends once the only slot is taken.
final class A0DeadlineCaveatLangTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testMaxUsesExhaustedSlotsTerminate() {
        let got: String? = S2Deadline.within(10, "reserveMaxUses twice") {
            let c: JSONValue = .object(["type": .string("max_uses"), "id": .string("u"), "n": .int(1), "until": .int(100)])
            let b = [BoundCaveat(caveat: c, hop: 0, capHash: "h")]
            let store = MemoryStateStore()
            let first = PCA.reserveMaxUses(store: store, bound: b, now: 1)
            let second = PCA.reserveMaxUses(store: store, bound: b, now: 1)
            return "\(first.ok)|\(second.ok)|\(second.reason)"
        }
        XCTAssertEqual(got, "true|false|max_uses 'u' is exhausted", "CaveatLang.swift:498")
    }
}
