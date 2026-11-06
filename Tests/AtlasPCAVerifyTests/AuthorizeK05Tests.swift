import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Exact statuses, reasons and wiring of `PCA.authorize`, against packages/pca/src/server/verify.ts and server/authorize.ts.
final class AuthorizeK05Tests: XCTestCase {
    private struct K05Boom: Error {}

    private final class LastThrows: PCALastStore {
        func last(key: String) throws -> Int64? { throw K05Boom() }
        func claim(key: String, counter: Int64) -> ClaimResult { ClaimResult(ok: true) }
    }

    func testConsumeOnceDefaultClaimsCounterOne() throws {
        let st = AuthorizeTests.RecordingStore()
        XCTAssertTrue(try st.consumeOnce(key: "k", retainUntil: 5, now: 1))
        XCTAssertEqual(st.seen.map { $0.1 }, [1])
    }

    func testAWorkflowGateIsOptionalByDefault() {
        XCTAssertFalse(PCA.WorkflowGate(principal: "p", rsSigner: "r").required)
    }

    func testRiskPolicyReasons() {
        XCTAssertNil(PCA.validateRiskPolicy(AZ.RISK))
        func edit(_ f: (inout JObject) -> Void) -> String? {
            var o = AZ.RISK.asObject!
            f(&o)
            return PCA.validateRiskPolicy(.object(o))
        }
        for k in ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"] {
            XCTAssertEqual(edit { $0[JKey(k)] = nil }, "risk_policy.\(k) must be finite")
        }
        XCTAssertEqual(edit { $0["theta1"] = .int(-1) }, "risk_policy requires 0 <= theta1 <= theta2")
        XCTAssertEqual(edit { $0["theta1"] = .int(1); $0["theta2"] = .double(0.5) }, "risk_policy requires 0 <= theta1 <= theta2")
        XCTAssertEqual(edit { $0["kappa"] = .int(0) }, "risk_policy.kappa must be > 0")
        for k in ["lambda", "rho", "bMax"] {
            XCTAssertEqual(edit { $0[JKey(k)] = .int(-1) }, "risk_policy lambda/rho/bMax must be >= 0")
            XCTAssertNil(edit { $0[JKey(k)] = .int(0) })
        }
    }

    func testAContextThatIsNotAnObject() {
        let bad = PCA.evaluateAgentCaveats(.array([.object(["type": .string("x")])]), context: .string("c"))
        XCTAssertFalse(bad.ok)
        XCTAssertEqual(bad.failed, ["<evaluation error>"])
        let empty = PCA.evaluateAgentCaveats(.array([]), context: .string("c"))
        XCTAssertTrue(empty.ok)
        XCTAssertEqual(empty.failed, [])
    }

    func testClassRank() {
        XCTAssertEqual(PCA.classRank(.string("irreversible")), 2)
        XCTAssertEqual(PCA.classRank(.string("nuclear")), 2)
        XCTAssertEqual(PCA.classRank(.string("reversibl\u{E9}")), 2)
        XCTAssertEqual(PCA.classRank(nil), 2)
    }

    func testDecisiveReason() {
        var c = PCA.CheckList()
        c.set("a", .fail)
        XCTAssertEqual(PCA.decisive(c, ["z", "a: x"]), "a: x")
        c.set("operation", .pass)
        XCTAssertEqual(PCA.decisive(c, ["operation: stale", "a: x"]), "a: x")
        c.set("operation", .fail)
        XCTAssertEqual(PCA.decisive(c, ["a: x", "operation: y"]), "operation: y")
        var plan = PCA.CheckList()
        plan.set("a", .fail)
        plan.set("plan_state", .fail)
        XCTAssertEqual(PCA.decisive(plan, ["a: x", "plan_state: y"]), "plan_state: y")
        plan.set("operation", .fail)
        XCTAssertEqual(PCA.decisive(plan, ["a: x", "plan_state: y", "operation: z"]), "operation: z")
        XCTAssertEqual(PCA.decisive(PCA.CheckList(), []), "denied")
    }

    func testTheArtifactSizeBoundIsInclusive() {
        let g = AZ.signed().grant
        let input = PCA.AuthorizeInput(operation: PCA.Operation(verb: "payments.send", resource: "payments/acme", params: AuthorizeTests.P50), audience: AZ.AUD,
                                       resolveGrant: { _ in g }, stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: AZ.NOW, plan: PCA.SINGLE_STEP)
        func text(_ total: Int) -> String { #"{"a":""# + String(repeating: "x", count: total - 8) + #""}"# }
        XCTAssertEqual(text(PCA.MAX_ARTIFACT_BYTES).utf8.count, PCA.MAX_ARTIFACT_BYTES)
        XCTAssertEqual(PCA.authorize(json: text(PCA.MAX_ARTIFACT_BYTES), input).reason, "malformed: grant_ref is not a string")
        XCTAssertEqual(PCA.authorize(json: text(PCA.MAX_ARTIFACT_BYTES + 1), input).reason, "undecodable PCActn: not a strict-JSON object")
    }

    func testCallbackFailuresAre403() {
        let c = AZ.run(AZ.signed()) { $0.context = { _ in throw K05Boom() } }
        XCTAssertEqual(c.status, 403)
        XCTAssertEqual(c.reason, "context: the context callback failed (fail closed)")
        let v = AZ.run(AZ.signed()) { $0.intentV2 = .provider({ _ in throw K05Boom() }) }
        XCTAssertEqual(v.status, 403)
        XCTAssertEqual(v.reason, "intent_v2: verifier state unavailable (fail closed)")
    }

    func testV2ParamsDefaultToTheOperationsAndAnExplicitOneWins() {
        let s = EscalationTests.signed()
        let null = AZ.run(s) { $0.intentV2 = .context(IntentV2Context(.object(["params": .null]))) }
        XCTAssertEqual(null.reason, "tighten: escalate: asked by tighten rule 'big'")
        let small: JSONValue = .object(["amount": .int(5), "currency": .string("usd")])
        let explicit = AZ.run(s) { $0.intentV2 = .context(IntentV2Context(.object(["params": small]))) }
        XCTAssertEqual(explicit.checks["tighten"], .pass, "\(explicit.reasons)")
    }

    func testARevocationStateSourceThatThrows() {
        let r = AZ.run(AZ.signed()) {
            $0.revocationStaleness = RevocationStalenessPolicy(maxRevocationAgeMs: 1000)
            $0.revocationState = { _, _ in throw K05Boom() }
        }
        XCTAssertEqual(r.checks["freshness"], .fail)
        XCTAssertTrue(r.reasons.contains("freshness: the revocation state source failed (fail closed)"), "\(r.reasons)")
    }

    func testOnATieTheServersClassIsTheEffectiveOne() {
        let pred: JSONValue = .object(["verb": .string("payments.send"), "resource": .string("payments/*"),
                                       "where": .array([.object(["field": .string("action.reversibility_class"), "op": .string("eq"), "value": .string("rate_limited")])])])
        let r = AZ.run(AZ.signed(declared: "costly", predicates: [pred])) { $0.context = { _ in PCA.AuthorizeContext(reversibilityClass: "rate_limited") } }
        XCTAssertEqual(r.checks["reversibility"], .pass)
        XCTAssertEqual(r.checks["policy"], .pass, "\(r.reasons)")
    }

    func testDelegationDepthIsTheChainLengthMinusOne() {
        func run(max: Int64) -> PCA.AuthorizeResult {
            let g = AZ.grant(envelope: AZ.envelope(caveats: [.object(["type": .string("delegation_depth"), "max": .int(max)])]))
            let p = AZ.proof(g, params: AuthorizeTests.P50, declared: "reversible", now: AZ.NOW, aud: AZ.AUD, extra: ["cap_chain": .array([g, g])])
            return AZ.run(AZ.Signed(grant: g, pcactn: p, params: AuthorizeTests.P50))
        }
        let why = "policy: caveat(s) not satisfied: delegation_depth"
        XCTAssertTrue(run(max: 0).reasons.contains(why), "\(run(max: 0).reasons)")
        XCTAssertFalse(run(max: 1).reasons.contains(why), "\(run(max: 1).reasons)")
    }

    func testANarrowBlockIsAlwaysJudged() {
        let r = AZ.run(AZ.signed()) { $0.k1 = K1Input(narrow: .string("x")) }
        XCTAssertEqual(r.failedChecks, ["delegated_caveats"])
        XCTAssertTrue(r.reasons.contains("delegated_caveats: delegation caveat(s) not satisfied: narrow (malformed narrow block: not an object)"), "\(r.reasons)")
    }

    func testRootK1CaveatsAreRefusedWithoutK1() {
        let r = AZ.run(AZ.signed(rootCaveats: [.object(["type": .string("sealed")])]))
        XCTAssertTrue(r.reasons.contains("policy: root caveat(s) not satisfied: sealed"), "\(r.reasons)")
    }

    func testAK1InputJudgesTheRootEvenWithoutK1Caveats() {
        // the only verdict a grant without K1 caveats can get from the K1 evaluator: its clock check
        let overSafe = Canonical.MAX_SAFE + 1
        let why = "policy: root caveat(s) not satisfied: <malformed>"
        let on = AZ.run(AZ.signed()) { $0.now = overSafe; $0.k1 = K1Input() }
        XCTAssertTrue(on.reasons.contains(why), "\(on.reasons)")
        let off = AZ.run(AZ.signed()) { $0.now = overSafe }
        XCTAssertFalse(off.reasons.contains(why), "\(off.reasons)")
    }

    private func signed(_ env: JObject) -> AZ.Signed {
        let g = AZ.grant(envelope: .object(env))
        return AZ.Signed(grant: g, pcactn: AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD), params: AuthorizeTests.P50)
    }

    func testAssuranceDegradesOnlyALegacyTighten() {
        let readsProv: JSONValue = .object(["verb": .string("payments.send"), "resource": .string("payments/*"),
                                            "where": .array([.object(["field": .string("env.prov.x"), "op": .string("eq"), "value": .string("a")])])])
        var legacyEnv = AZ.envelope(predicates: [readsProv]).asObject!
        legacyEnv["model_polarity"] = .string("legacy")
        let legacy = AZ.run(signed(legacyEnv)) { $0.isRevoked = { _, _ in true } }
        XCTAssertEqual(legacy.assurance["tighten"]?.outcome, "pass", "\(legacy.reasons)")
        XCTAssertEqual(legacy.assurance["tighten"]?.degraded, true)
        XCTAssertEqual(legacy.assurance["tighten"]?.reason, PCA.LEGACY_POLARITY_DEGRADED)

        var plainEnv = AZ.envelope().asObject!
        plainEnv["tighten"] = .array([.object(["id": .string("big"), "signal": .string("escalate"),
                                               "when": .object(["field": .string("action.params.amount"), "op": .string("gte"), "value": .int(1000)])])])
        let plain = AZ.run(signed(plainEnv)) { $0.isRevoked = { _, _ in true } }
        XCTAssertEqual(plain.assurance["tighten"]?.outcome, "pass", "\(plain.reasons)")
        XCTAssertEqual(plain.assurance["tighten"]?.degraded, false)
    }

    func testAnUnknownHistoryHeadAdmitsNoAnswer() {
        let s = EscalationTests.signed()
        let r = EscalationTests.go(s, store: LastThrows(), answer: EscalationTests.answer(s), pins: EscalationTests.pin)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "escalate")
        XCTAssertFalse(r.reasons.contains { $0.hasPrefix("escalation:") }, "\(r.reasons)")
    }

    func testNeedsModelRules() {
        XCTAssertFalse(PCA.needsModelRules(.object([:])))
        XCTAssertFalse(PCA.needsModelRules(AZ.grant(envelope: AZ.envelope())))
        XCTAssertTrue(PCA.needsModelRules(EscalationTests.signed().grant))
    }
}
