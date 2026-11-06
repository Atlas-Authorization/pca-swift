import XCTest
@testable import AtlasPCAVerify

/// packages/pca/src/intent-v2.ts: String(1e21) is the exponent form; `preauth_esc` defaults to 0 (631); a malformed context
/// reports no legacy polarity (520-523); the clock is `isSafeInt(now)`.
final class IntentV2K05Tests: XCTestCase {
    typealias F = V2F
    private static let VERB = "air.book", DEF = F.digest("def")
    private static let reg = Actions.coreRegistry
    private static let reviewer = F.key("reviewer")
    private static let PINS: JSONValue = .object(["keys": .array([.object(["kid": .string("rev"), "pk": .string(F.pub(reviewer)), "roles": .array([.string("reviewer")])])])])
    private static let RISK: JSONValue = .object([
        "bMax": .int(1000), "kappa": .int(1), "lambda": .int(0), "rho": .int(0), "theta1": .double(0.5), "theta2": .double(0.8),
        "weights": .object(["alpha": .int(0), "beta": .int(0), "delta": .int(0), "epsilon": .int(0), "gamma": .int(0), "zeta": .int(0)]),
    ])
    private static let p: JObject = ["aud": .string(F.AUD), "action": .object(["verb": .string(VERB), "resource": .string("r"), "params_digest": .string(IV.strictHash(.object([:]))!)])]
    private static let CLOCK = "the verifier clock is not a safe integer (fail closed)"

    /// A read verb confirmed by a pinned reviewer: no traits, so `floors` may be anything at or above the bottom.
    private func confirmedDoc(floors: Profile) -> JSONValue {
        var v: JObject = ["verb": .string(Self.VERB), "kind": .string("read"), "reversibility": .string("reversible"), "params": .object([:]), "effects": .array([.string("read")])]
        let facts = Actions.factsDigest(v)
        v["traits"] = .array([])
        v["def"] = .string(Self.DEF)
        v["floors"] = floors.json
        var a: JObject = ["def_digest": .string(Self.DEF), "traits_digest": .string(Actions.traitsDigest(Self.reg)), "facts_digest": .string(facts), "final_traits": .array([]),
                          "dismissed": .array([]), "reviewer_kid": .string("rev"), "ts": .int(1)]
        a["sig"] = .string(F.sign(Self.reviewer, Actions.reviewMessage(a)!))
        v["confirmation"] = .object(a)
        return F.signSchema(["v": .int(2), "kind": .string("pca-action-schema"), "site": .string("https://skyair.example"), "aud": .string(F.AUD), "version": .string("1"), "verbs": .array([.object(v)])])
    }

    private func grant() -> JSONValue {
        let e: JObject = ["type": .string("envelope"), "goal_commit": .string(F.digest("goal")), "predicates": .array([]), "caveats": .array([]),
                          "agent_binding": .object([:]), "risk_policy": Self.RISK]
        return F.cap(issuer: F.principal, holder: F.agent, caveats: [.object(e)])
    }

    private func run(floors: Profile = Profile(), now: Int64 = V2F.NOW) -> [String] {
        let c: JObject = ["params": .object([:]), "schema": .object(["docs": .array([confirmedDoc(floors: floors)]), "keys": F.KEYS]),
                          "policy": .object(["schema": .object(["closed_world": .bool(true)])]), "reviewers": Self.PINS]
        return IntentV2.decide(Self.p, grant: grant(), ctx: IntentV2Context(.object(c)), now: now).checks.map { $0.ok ? $0.name : "\($0.name)=\($0.reason)" }
    }

    func testExponentFormStartsExactlyAt1e21() {
        XCTAssertEqual(IntentV2.jsString(.double(1e21)), "1e+21")
        XCTAssertEqual(IntentV2.jsString(.double(-1e21)), "-1e+21")
        XCTAssertEqual(IntentV2.jsString(.double(1e20)), "100000000000000000000")
    }

    func testPreauthEscDefaultsToZero() {
        XCTAssertEqual(run(), ["schema", "traits"])
        XCTAssertEqual(run(floors: Profile(esc: 1)),
                       ["schema", "traits=escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)"])
    }

    func testAMalformedContextReportsNoLegacyPolarity() {
        let r = IntentV2.decide(Self.p, grant: grant(), ctx: IntentV2Context(.string("x")), now: V2F.NOW)
        XCTAssertFalse(r.legacy)
        XCTAssertNil(r.env)
        let why = "malformed v2 context: the v2 verifier context must be an object"
        XCTAssertEqual(r.checks.map { "\($0.name)=\($0.reason)" }, ["schema=\(why)", "intent_session=\(why)"])
    }

    func testClockBoundaries() {
        XCTAssertEqual(run(now: Canonical.MAX_SAFE), ["schema", "traits"])
        XCTAssertEqual(run(now: -Canonical.MAX_SAFE), ["schema", "traits"])
        XCTAssertEqual(run(now: Canonical.MAX_SAFE + 1).first, "schema=\(Self.CLOCK)")
        XCTAssertEqual(run(now: -Canonical.MAX_SAFE - 1).first, "schema=\(Self.CLOCK)")
    }
}
