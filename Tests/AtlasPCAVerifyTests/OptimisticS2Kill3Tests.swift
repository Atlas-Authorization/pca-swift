import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Optimistic-path wire checks (packages/pca/src/optimistic.ts fraudProofWireCheck, bond-settlement.ts settlementWireCheck) and the
/// JavaScript === used by the ledger.
final class S2G3OptimisticKillTests: XCTestCase {
    typealias O = Optimistic

    func testDefaultChallengeWindowPolicy() {
        XCTAssertEqual(O.ChallengeWindowPolicy.default, O.ChallengeWindowPolicy(minWindowMs: 1000, maxWindowMs: 86_400_000, maxSkewMs: 5000))
    }

    func testAnUncanonicalBodyIsNotCanon() {
        let bad = O.signedLenient("k", O.CLAIM_DOMAIN, ["x": JSONValue.double(Double.infinity)], nil)
        XCTAssertFalse(bad.ok, "an out-of-profile number never verifies")
        XCTAssertFalse(bad.canon, "an out-of-profile number is not canonicalisable")
        let good = O.signedLenient("k", O.CLAIM_DOMAIN, ["x": JSONValue.int(1)], nil)
        XCTAssertFalse(good.ok)
        XCTAssertTrue(good.canon)
    }

    // ---- memberEq ----

    func testMemberEq() {
        let k = "k"
        let none: JObject = [:]
        XCTAssertTrue(O.memberEq(none, none, k), "both absent are equal")
        XCTAssertFalse(O.memberEq(["k": JSONValue.int(1)], none, k), "only the first present")
        XCTAssertFalse(O.memberEq(none, ["k": JSONValue.int(1)], k), "only the second present")
        XCTAssertFalse(O.memberEq(["k": JSONValue.string("a")], none, k))
        XCTAssertFalse(O.memberEq(none, ["k": JSONValue.string("a")], k))
        XCTAssertFalse(O.memberEq(["k": JSONValue.int(1)], ["k": JSONValue.string("1")], k), "a number never equals a string")
        XCTAssertTrue(O.memberEq(["k": JSONValue.int(1)], ["k": JSONValue.double(1.0)], k), "numbers compare by value")
        XCTAssertTrue(O.memberEq(["k": JSONValue.double(1e300)], ["k": JSONValue.double(1e300)], k), "a number outside the safe range still equals itself (===)")
        XCTAssertTrue(O.memberEq(["k": JSONValue.double(-0.0)], ["k": JSONValue.int(0)], k), "-0 === 0")
        XCTAssertTrue(O.memberEq(["k": JSONValue.string("a")], ["k": JSONValue.string("a")], k))
        XCTAssertFalse(O.memberEq(["k": JSONValue.string("a")], ["k": JSONValue.string("b")], k))
    }

    // ---- fraudProofWireCheck: risk-understated ----

    func fraud(r: Double, claimedR: Double?, margin: JSONValue?) -> String {
        var claim: JObject = ["pcactn_digest": JSONValue.string("d"), "bond_ref": JSONValue.string("b")]
        var proof: JObject = [
            "pcactn_digest": JSONValue.string("d"), "bond_ref": JSONValue.string("b"), "reason": JSONValue.string("x"), "kind": JSONValue.string("risk-understated"),
            "decision": JSONValue.object(["releaseGuardianShare": JSONValue.bool(true), "optimisticAllowed": JSONValue.bool(true), "r": JSONValue.double(r)]),
        ]
        if let c = claimedR {
            claim["claimed_r"] = JSONValue.double(c)
            proof["claimed_r"] = JSONValue.double(c)
        }
        if let m = margin { proof["r_margin"] = m }
        return O.fraudProofWireCheck(JSONValue.object(claim), JSONValue.object(proof))
    }

    func testDefaultMarginIsOneNanoUnit() {
        XCTAssertEqual(fraud(r: 0.5 + 5e-10, claimedR: 0.5, margin: nil), "consistency", "inside the default margin of 1e-9")
        XCTAssertEqual(fraud(r: 0.5 + 2e-9, claimedR: 0.5, margin: nil), "ok", "beyond the default margin")
    }

    func testTheMarginIsExclusive() {
        XCTAssertEqual(fraud(r: 0.5, claimedR: 0.5, margin: JSONValue.int(0)), "consistency", "r equal to claimed_r + margin does not hold")
        XCTAssertEqual(fraud(r: 0.75, claimedR: 0.5, margin: JSONValue.int(0)), "ok")
    }

    func testAbsentClaimedRNeverHolds() {
        XCTAssertEqual(fraud(r: 0.5, claimedR: nil, margin: nil), "consistency")
        XCTAssertEqual(fraud(r: 5, claimedR: nil, margin: JSONValue.int(0)), "consistency")
    }

    // ---- settlementWireCheck ----

    static var guardian: String { Base64URLStrict.encode([UInt8](repeating: 7, count: 32)) }

    func settle(_ r: JObject) -> String { O.settlementWireCheck(JSONValue.object(r), guardianPublic: Self.guardian) }

    func base(_ action: String, amount: Int64) -> JObject {
        [
            "claimId": JSONValue.string("c"), "action": JSONValue.string(action), "amount": JSONValue.int(amount), "from": JSONValue.string("a"),
            "to": JSONValue.string("T"), "at": JSONValue.int(1), "evidenceDigest": JSONValue.string(action == "slash" ? "e" : ""), "sig": JSONValue.string("x"),
        ]
    }

    func testTheSmallestPositiveAmountPassesTheShapeCheck() {
        XCTAssertEqual(settle(base("open", amount: 1)), "signature")
        XCTAssertEqual(settle(base("open", amount: 0)), "shape")
        XCTAssertEqual(settle(base("open", amount: -1)), "shape")
    }

    func slash(_ split: JObject) -> String {
        var r = base("slash", amount: 10)
        r["split"] = JSONValue.object(split)
        return settle(r)
    }

    func split(treasuryAccount: Bool, challenger: JSONValue?, reward: Int64, remainder: Int64) -> JObject {
        var s: JObject = [
            "amount": JSONValue.int(10), "challengerReward": JSONValue.int(reward), "victimCompensation": JSONValue.int(0),
            "treasuryRemainder": JSONValue.int(remainder), "victimAccount": JSONValue.string("v"),
        ]
        if treasuryAccount { s["treasuryAccount"] = JSONValue.string("T") }
        if let c = challenger { s["challengerAccount"] = c }
        return s
    }

    func testTheTreasuryAccountIsRequired() {
        XCTAssertEqual(slash(split(treasuryAccount: true, challenger: JSONValue.string("c"), reward: 10, remainder: 0)), "signature", "control")
        XCTAssertEqual(slash(split(treasuryAccount: false, challenger: JSONValue.string("c"), reward: 10, remainder: 0)), "split")
    }

    func testAnAbsentChallengerAccountIsNotAnonymous() {
        // anonymous = an explicit null: the whole bond goes to the treasury
        XCTAssertEqual(slash(split(treasuryAccount: true, challenger: JSONValue.null, reward: 0, remainder: 10)), "signature", "control: null challenger")
        XCTAssertEqual(slash(split(treasuryAccount: true, challenger: nil, reward: 0, remainder: 10)), "split", "absent challenger")
        XCTAssertEqual(slash(split(treasuryAccount: true, challenger: JSONValue.null, reward: 5, remainder: 5)), "split", "null challenger paid a reward")
    }

    // ---- Ledger.same ----

    func testLedgerSame() {
        XCTAssertTrue(Ledger.same(nil, nil), "both absent")
        XCTAssertFalse(Ledger.same(JSONValue.int(1), nil))
        XCTAssertFalse(Ledger.same(nil, JSONValue.int(1)))
        XCTAssertTrue(Ledger.same(JSONValue.int(1), JSONValue.int(1)))
        XCTAssertFalse(Ledger.same(JSONValue.int(1), JSONValue.int(2)))
        XCTAssertFalse(Ledger.same(JSONValue.double(1e300), JSONValue.double(1e300)), "a value outside the strict profile has no canonical form: never equal")
    }
}
