import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A fraud proof's asserted decision matches the recomputation only when its `r` is a number within 1e-9 of the replayed one: a NaN, missing or mistyped r never matches
/// (the comparison is the negation of "within tolerance", so NaN cannot pass). The reference had the fail-open form until its own fix.
final class FraudProofDecisionKillTests: XCTestCase {
    private static let mismatch = "proof decision does not match an independent recomputation"

    private func fixture() throws -> (claim: JSONValue, decision: JObject, snapshot: JSONValue, grant: JSONValue?) {
        var input: JSONValue?
        _ = try Base.each("ref-decide-java.json.gz", ["decide"]) { c in if input == nil { input = c.arg(0) } }
        let i = try XCTUnwrap(input)
        let rec = try PCAPolicyVm.decide(i)
        var snap = i.asObject ?? [:]
        let grant = snap[JKey("grant")]
        snap[JKey("grant")] = nil
        let decision: JObject = ["releaseGuardianShare": rec.get("releaseGuardianShare") ?? .null,
                                 "optimisticAllowed": rec.get("requiredThreshold")?.get("optimisticAllowed") ?? .null, "r": rec.get("r") ?? .null]
        let claim: JSONValue = .object(["pcactn_digest": .string("d"), "bond_ref": .string("b"), "claimed_r": .double(0)])
        return (claim, decision, .object(snap), grant)
    }

    private func reason(_ decision: JObject) throws -> String? {
        let f = try fixture()
        let proof: JSONValue = .object(["pcactn_digest": .string("d"), "bond_ref": .string("b"), "decision": .object(decision)])
        return PCAOptimisticAdjudication.verifyFraudProof(f.claim, proof, f.grant, f.snapshot).get("reason")?.asString
    }

    func testAnAssertedRThatMatchesIsNotTheMismatchRefusal() throws {
        XCTAssertNotEqual(try reason(try fixture().decision), Self.mismatch)
    }

    func testANaNMissingOrMistypedRNeverMatches() throws {
        for bad: JSONValue? in [.double(.nan), nil, .string("0.1"), .null, .bool(true)] {
            var d = try fixture().decision
            d[JKey("r")] = bad
            XCTAssertEqual(try reason(d), Self.mismatch, "r = \(String(describing: bad))")
        }
    }

    func testARThatDiffersBeyondTheToleranceNeverMatches() throws {
        var d = try fixture().decision
        d[JKey("r")] = .double((IV.num(d[JKey("r")]) ?? 0) + 0.01)
        XCTAssertEqual(try reason(d), Self.mismatch)
    }
}
