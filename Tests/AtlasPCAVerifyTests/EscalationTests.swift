import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The ternary guard end to end: a REAL signed grant whose envelope carries a `tighten` rule (rule 21) makes the core
/// verdict `escalate`; the guard surfaces it distinctly, refuses it without an answer, admits it only with a bound principal
/// answer that the replay counter spends, and never upgrades a deny. Rule 20/21 wiring into the core verifier included.
final class EscalationTests: XCTestCase {
    static let BIG: JSONValue = .object(["id": .string("big"), "signal": .string("escalate"),
                                         "when": .object(["field": .string("action.params.amount"), "op": .string("gte"), "value": .int(10)])])
    static let ZERO = Base64URLStrict.encode([UInt8](repeating: 0, count: 32))

    /// A grant whose envelope tightens: amount >= 10 asks the principal. `limit` is the predicate's amount ceiling.
    static func signed(limit: Int64 = 100, extra: JObject = [:]) -> AZ.Signed {
        let pred: JSONValue = .object(["verb": .string("payments.send"), "resource": .string("payments/*"),
                                       "where": .array([.object(["field": .string("action.params.amount"), "op": .string("lte"), "value": .int(limit)])])])
        var env = AZ.envelope(predicates: [pred]).asObject!
        env["tighten"] = .array([BIG])
        for (k, v) in extra { env[JKey(k.s)] = v }
        let g = AZ.grant(envelope: .object(env))
        return AZ.Signed(grant: g, pcactn: AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD), params: AuthorizeTests.P50)
    }

    static func answer(_ s: AZ.Signed, last: Int64? = nil, over: JObject = [:], key: V2F.K = V2F.principal) -> JSONValue {
        var body: JObject = [
            "v": .int(1), "kind": .string("pca-escalation-answer"), "principal": .string(V2F.pub(key)),
            "policy_digest": .string(PCA.escalationPolicyDigest(grant: s.grant)!), "action_digest": .string(PCA.escalationActionDigest(pcactn: s.pcactn)!),
            "history_head": .string(PCA.escalationHistoryHead(lastCounter: last)!), "decision": .string("allow"),
            "iat": .int(AZ.NOW - 1_000), "expires_at": .int(AZ.NOW + 600_000), "nonce": .string("CQkJCQkJCQkJCQkJCQkJCQ"),
        ]
        for (k, v) in over { body[k] = v }
        body["sig"] = .string(V2F.sign(key, IV.message(PCA.ESCALATION_ANSWER_DOMAIN, .object(body))!))
        return .object(body)
    }

    static func go(_ s: AZ.Signed, store: PCAStateStore = MemoryStateStore(), answer: JSONValue? = nil, pins: [PinnedSigner] = []) -> PCA.AuthorizeResult {
        AZ.run(s) {
            $0.stateStore = store
            $0.intentV2 = .context(IntentV2Context(.object([:])))
            $0.escalationAnswer = answer
            $0.escalationPrincipals = pins
        }
    }

    static var pin: [PinnedSigner] { [PinnedSigner(V2F.pub(V2F.principal))] }

    func testEscalateIsSurfacedAndRefusedWithoutAnAnswer() {
        let r = Self.go(Self.signed())
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "escalate")
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.failedChecks, ["tighten"])
        XCTAssertEqual(r.reason, "tighten: escalate: asked by tighten rule 'big'")
        XCTAssertEqual(r.escalation?.get("kind")?.asString, "pca-escalation-request")
        XCTAssertEqual(r.escalation?.get("verb")?.asString, "payments.send")
        XCTAssertEqual(r.escalation?.get("reasons")?.asArray?.count, 1)
    }

    func testAnAllowedActionHasDecisionAllowAndNoEscalation() {
        let s = AZ.signed()
        let r = AZ.run(s)
        XCTAssertTrue(r.allow)
        XCTAssertEqual(r.decision, "allow")
        XCTAssertNil(r.escalation)
    }

    func testHardFailureAnywhereIsDenyNotEscalate() {
        // amount 50 > the 20 ceiling: `policy` fails (hard) next to the escalate-class `tighten`: deny, no request
        let r = Self.go(Self.signed(limit: 20))
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "deny")
        XCTAssertNil(r.escalation)
        XCTAssertEqual(r.failedChecks, ["policy", "tighten"])
    }

    func testValidAnswerAdmitsOnceAndTheCounterSpendsIt() {
        let s = Self.signed()
        let store = MemoryStateStore()
        let a = Self.answer(s)
        let r = Self.go(s, store: store, answer: a, pins: Self.pin)
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(r.decision, "allow")
        XCTAssertEqual(r.status, 200)
        XCTAssertEqual(r.escalation?.get("answered_by")?.asString, V2F.pub(V2F.principal))
        XCTAssertEqual(r.checks["escalation"], .pass)
        XCTAssertEqual(r.checks["tighten"], .pass)
        // the same PCActn again: the counter was spent, so even a freshly bound answer is a replay
        let key = PCA.stateKey(grantId: s.grant.get("id")!.asString!, leafHolder: V2F.pub(V2F.agent))
        XCTAssertEqual(store.last(key: key), 1)
        let again = Self.go(s, store: store, answer: Self.answer(s, last: 1), pins: Self.pin)
        XCTAssertFalse(again.allow)
        XCTAssertEqual(again.checks["replay"], .fail)
        // and the old answer (bound to "no history yet") is bound to another state now
        let stale = Self.go(s, store: store, answer: a, pins: Self.pin)
        XCTAssertFalse(stale.allow)
        XCTAssertEqual(stale.decision, "escalate")
        XCTAssertTrue(stale.reasons.contains("escalation: the answer is bound to another state of the history"))
    }

    func testBadAnswersStayEscalate() {
        let s = Self.signed()
        let cases: [(String, JSONValue)] = [
            ("deny answer", Self.answer(s, over: ["decision": .string("deny")])),
            ("other policy", Self.answer(s, over: ["policy_digest": .string(Self.ZERO)])),
            ("other action", Self.answer(s, over: ["action_digest": .string(Self.ZERO)])),
            ("other history", Self.answer(s, last: 99)),
            ("expired", Self.answer(s, over: ["iat": .int(1), "expires_at": .int(2)])),
            ("future", Self.answer(s, over: ["iat": .int(AZ.NOW + 5_000), "expires_at": .int(AZ.NOW + 9_000)])),
            ("unpinned principal", Self.answer(s, key: V2F.stranger)),
            ("junk", .object(["junk": .int(1)])),
        ]
        for (name, ans) in cases {
            let r = Self.go(s, answer: ans, pins: Self.pin)
            XCTAssertFalse(r.allow, name)
            XCTAssertEqual(r.decision, "escalate", name)
            XCTAssertNotNil(r.escalation?.get("kind"), name)
        }
        // no pinned principal at all: a good answer is not even read
        XCTAssertEqual(Self.go(s, answer: Self.answer(s), pins: []).decision, "escalate")
    }

    func testTheAnswerNeverUpgradesADeny() {
        let s = Self.signed(limit: 20)
        let r = Self.go(s, answer: Self.answer(s), pins: Self.pin)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "deny")
        XCTAssertNil(r.escalation)
    }

    struct BareStore: PCAStateStore {
        let m = MemoryStateStore()
        func claim(key: String, counter: Int64) throws -> ClaimResult { m.claim(key: key, counter: counter) }
    }

    func testAStoreWithoutLastCannotAdmitAnAnswerAndIsRefusedUpFront() {
        let s = Self.signed()
        let r = Self.go(s, store: BareStore(), answer: Self.answer(s), pins: Self.pin)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.missing, ["stateStore.last (needed with escalationPrincipals)"])
        // without principals the same store is fine: escalate is simply refused
        XCTAssertEqual(Self.go(s, store: BareStore()).decision, "escalate")
    }

    func testAnswerFromAHeader() {
        let s = Self.signed()
        let a = Self.answer(s)
        let text = Canonical.canonicalize(a)
        let h = Base64URLStrict.encode(Canonical.utf8(text))
        XCTAssertEqual(PCA.escalationAnswer(fromHeader: h), a)
        XCTAssertNil(PCA.escalationAnswer(fromHeader: h + "="))
        XCTAssertNil(PCA.escalationAnswer(fromHeader: "not json"))
        XCTAssertTrue(Self.go(s, answer: PCA.escalationAnswer(fromHeader: h), pins: Self.pin).allow)
    }

    // ---- the core verdict carries every failing reason, in order, and the model rules ----

    func testVerdictReasonsAreTheFullSet() {
        let s = Self.signed()
        // wrong audience AND the escalating tighten rule: both reasons are reported, `reason` is the first
        let v = PCA.verify(pcactn: s.pcactn, grant: s.grant, now: AZ.NOW, audience: "someone-else",
                           intentV2: IntentV2Context(.object(["params": AuthorizeTests.P50])))
        XCTAssertFalse(v.allow)
        XCTAssertEqual(v.reasons.count, 2)
        XCTAssertEqual(v.reasons.first, v.reason)
        XCTAssertTrue(v.reasons[0].hasPrefix("audience: "))
        XCTAssertEqual(v.reasons[1], "tighten: escalate: asked by tighten rule 'big'")
        // one signing: Ed25519 signatures from CryptoKit are randomized, so two AZ.signed() grants are different capabilities
        let ok = AZ.signed()
        XCTAssertEqual(PCA.verify(pcactn: ok.pcactn, grant: ok.grant, now: AZ.NOW, audience: AZ.AUD).reasons, [])
    }

    func testModelPolarityTypingAndTheLegacyFlag() {
        let readsProv: JSONValue = .object(["verb": .string("payments.send"), "resource": .string("payments/*"),
                                            "where": .array([.object(["field": .string("env.prov.x"), "op": .string("eq"), "value": .string("a")])])])
        func verdict(_ extra: JObject) -> PCA.Verdict {
            var env = AZ.envelope(predicates: [readsProv]).asObject!
            for (k, v) in extra { env[JKey(k.s)] = v }
            let g = AZ.grant(envelope: .object(env))
            let p = AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD)
            return PCA.verify(pcactn: p, grant: g, now: AZ.NOW, audience: AZ.AUD)
        }
        let strict = verdict([:])
        XCTAssertEqual(strict.checks["tighten"], false)
        XCTAssertEqual(strict.reasons, ["tighten: a grant's where reads model-derived path(s) env.prov.x: a model may only tighten (move them into tighten[]) (rule 21)"])
        XCTAssertFalse(strict.legacyModelPolarity)
        let legacy = verdict(["model_polarity": .string("legacy")])
        XCTAssertEqual(legacy.checks["tighten"], true)
        XCTAssertTrue(legacy.legacyModelPolarity)
        // a verifier policy of 'strict' overrides the grant's legacy flag
        let g = AZ.grant(envelope: .object({ () -> JObject in var e = AZ.envelope(predicates: [readsProv]).asObject!; e["model_polarity"] = .string("legacy"); return e }()))
        let p = AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD)
        let ctx = IntentV2Context(.object(["policy": .object(["model_polarity": .string("strict")])]))
        let overridden = PCA.verify(pcactn: p, grant: g, now: AZ.NOW, audience: AZ.AUD, intentV2: ctx)
        XCTAssertEqual(overridden.checks["tighten"], false)
        XCTAssertFalse(overridden.legacyModelPolarity)
    }

    func testTightenNullInTheEnvelopeIsRefused() {
        let g = AZ.grant(envelope: .object({ () -> JObject in var e = AZ.envelope().asObject!; e["tighten"] = .null; return e }()))
        let p = AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD)
        let v = PCA.verify(pcactn: p, grant: g, now: AZ.NOW, audience: AZ.AUD)
        XCTAssertEqual(v.checks["tighten"], false)
        XCTAssertEqual(v.reasons, ["tighten: malformed tighten list: tighten must be an array"])
    }

    func testUnitsNeedAnActionSchemaAndAreReportedOnlyWhenPresent() {
        let g = AZ.grant(envelope: .object({ () -> JObject in
            var e = AZ.envelope().asObject!
            e["units"] = .object(["action.params.amount": .object(["kind": .string("money"), "currency": .string("USD"), "exponent": .int(2)])])
            return e
        }()))
        let p = AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD)
        let v = PCA.verify(pcactn: p, grant: g, now: AZ.NOW, audience: AZ.AUD)
        XCTAssertEqual(v.checks["units"], false)
        XCTAssertEqual(v.reasons, ["units: this verifier has no action schema configured"])
        XCTAssertNil(PCA.verify(pcactn: AZ.signed().pcactn, grant: AZ.signed().grant, now: AZ.NOW, audience: AZ.AUD).checks["units"])
    }
}
