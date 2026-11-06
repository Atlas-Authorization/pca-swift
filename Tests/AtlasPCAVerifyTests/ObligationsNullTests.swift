import XCTest
import Foundation
@testable import AtlasPCAVerify

/// JSON null is not an absent list (obligations.ts:74 allows only undefined), and no signed payload carries obligations at all
/// (wire.ts: the closed key set), whatever the member's value.
final class ObligationsNullTests: XCTestCase {
    func testNullIsNotAnAbsentList() {
        XCTAssertNil(Obligations.obligationsError(nil))
        XCTAssertEqual(Obligations.obligationsError(.null), "obligations must be an array")
        let merged = Obligations.mergeObligations([.null])
        XCTAssertFalse(merged.ok)
        XCTAssertEqual(merged.reason, "obligations must be an array")
    }

    func testTheGateDeniesANullList() {
        XCTAssertEqual(Obligations.pepObligationGate(decision: "allow", answered: false, obligations: nil, supported: .array([])).decision, "allow")
        let g = Obligations.pepObligationGate(decision: "allow", answered: false, obligations: .null, supported: .array([]))
        XCTAssertEqual(g.decision, "deny")
        XCTAssertEqual(g.reason, "malformed obligations: obligations must be an array")
    }

    func testAnOutcomeOverANullListIsOverdue() {
        let o = Obligations.obligationOutcome(obligations: .null, fulfilled: .array([]), now: .int(1))
        XCTAssertEqual(o.outcome, "escalate")
    }

    func testASignedPCActnWithAnObligationsMemberIsRefused() throws {
        let p = try XCTUnwrap(AZ.signed().pcactn.asObject)
        XCTAssertNil(Wire.validate(.object(p)))
        for v: JSONValue in [.null, .array([]), .string("x")] {
            var q = p
            q["obligations"] = v
            XCTAssertEqual(Wire.validate(.object(q)), "unknown field 'obligations'")
        }
    }
}
