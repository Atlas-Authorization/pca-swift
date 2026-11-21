import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Rules 20 (units), 21 (tighten-only model rule) and the ternary decision over the SHARED vectors
/// (packages/pca/conformance/decision-vectors.json): exact outcomes, never "some failure".
final class DecisionConformanceTests: XCTestCase {
    static func table(_ name: String) throws -> [JSONValue] {
        let d = try ConformanceTests.load("decision-vectors.json")
        let t = d.get("primitives")?.get(name)?.asArray ?? []
        XCTAssertFalse(t.isEmpty, "decision-vectors.json: primitives.\(name) is empty")
        return t
    }

    /// `input_text` is raw JSON text each runner parses itself (spellings such as 2.0 / 2e0 are part of the input); else `input`.
    static func inputOf(_ v: JSONValue) throws -> JSONValue? {
        if let txt = v.get("input_text")?.asString { return try StrictJSON.parseLenient(txt) }
        return v.get("input")
    }

    func testVectorFileShape() throws {
        XCTAssertEqual(try Self.table("intent_units").count, 85)
        XCTAssertEqual(try Self.table("intent_tighten").count, 73)
        XCTAssertEqual(try Self.table("decision_of").count, 25)
        XCTAssertEqual(try Self.table("decision_lattice").count, 31)
        XCTAssertEqual(try Self.table("escalation_answer").count, 85)
    }

    func testUnitsVectors() throws {
        for v in try Self.table("intent_units") {
            let n = v.get("name")?.asString ?? "?"
            let r = PCA.decideUnits(try Self.inputOf(v) ?? .null)
            XCTAssertEqual(r.ok, v.get("expect")?.get("ok") == .bool(true), "\(n): \(r.reason)")
        }
    }

    func testTightenVectors() throws {
        for v in try Self.table("intent_tighten") {
            let n = v.get("name")?.asString ?? "?"
            let r = PCA.decideTighten(try Self.inputOf(v) ?? .null)
            let e = v.get("expect")
            XCTAssertEqual(r.outcome, e?.get("outcome")?.asString, "\(n): \(r)")
            XCTAssertEqual(r.legacy, e?.get("legacy") == .bool(true), n)
            XCTAssertEqual(r.offending, (e?.get("offending")?.asArray ?? []).compactMap { $0.asString }, n)
        }
    }

    func testDecisionOfVectors() throws {
        for v in try Self.table("decision_of") {
            let n = v.get("name")?.asString ?? "?"
            let i = try Self.inputOf(v)
            var checks: [String: String] = [:]
            for (k, s) in i?.get("checks")?.asObject ?? [:] { checks[k.s] = s.asString ?? "" }
            let got = PCA.decisionOf(allow: i?.get("allow") == .bool(true), checks: checks,
                                     reasons: (i?.get("reasons")?.asArray ?? []).compactMap { $0.asString })
            XCTAssertEqual(got, v.get("expect")?.get("decision")?.asString, n)
        }
    }

    func testLatticeVectors() throws {
        for v in try Self.table("decision_lattice") {
            let n = v.get("name")?.asString ?? "?"
            let i = try Self.inputOf(v)
            let got: String
            switch String(n.prefix(3)) {
            case "mee": got = PCA.meet(i?.get("a")?.asString ?? "", i?.get("b")?.asString ?? "")
            case "pep": got = PCA.pepDecision(i?.get("decision")?.asString ?? "", answered: i?.get("answered") == .bool(true))
            default: got = PCA.tightenDecision(i?.get("decision")?.asString ?? "", signal: i?.get("signal"))
            }
            XCTAssertEqual(got, v.get("expect")?.get("decision")?.asString, n)
        }
    }

    func testEscalationAnswerVectors() throws {
        let supported = Set(PCASuites.supported)
        var ran = Set<String>()
        for v in try Self.table("escalation_answer") {
            let n = v.get("name")?.asString ?? "?"
            let i = try Self.inputOf(v)
            var pins: [PinnedSigner] = []
            for p in i?.get("principals")?.asArray ?? [] {
                if let s = p.asString { pins.append(PinnedSigner(s)) }
                else if let s = p.get("pk")?.asString { pins.append(PinnedSigner(s, pqPk: p.get("pq_pk")?.asString)) }
            }
            let b = i?.get("bind")
            // a non-integer clock is refused by the safe-integer check
            let d = IV.num(i?.get("now")) ?? .nan
            let now: Int64 = (d.isFinite && d.rounded() == d && abs(d) < 9e18) ? Int64(d) : Int64.max
            let r = PCA.verifyEscalationAnswer(i?.get("answer"), principals: pins,
                                               bind: EscalationBinding(policyDigest: b?.get("policy_digest")?.asString ?? "", actionDigest: b?.get("action_digest")?.asString ?? "",
                                                                       historyHead: b?.get("history_head")?.asString ?? ""), now: now)
            let e = v.get("expect")
            if let need = v.get("requires_suite")?.asString, !supported.contains(need) {
                // a suite this build cannot run is refused, never accepted and never mistaken for a bad signature
                XCTAssertTrue(!r.ok && r.reason.contains(IV.UNSUPPORTED_SUITE), "\(n): suite \(need) is not built: want unsupported_suite, got \(r)")
                continue
            }
            if let need = v.get("requires_suite")?.asString, e?.get("ok") == .bool(true) { ran.insert(need) }
            XCTAssertEqual(r.ok, e?.get("ok") == .bool(true), "\(n): \(r.reason)")
            if r.ok {
                XCTAssertEqual(r.principal, e?.get("principal")?.asString, n)
                XCTAssertEqual(r.decision, e?.get("decision")?.asString, n)
            } else {
                XCTAssertTrue(r.reason.contains(e?.get("reason_contains")?.asString ?? "\u{0}"), "\(n): reason '\(r.reason)' lacks '\(e?.get("reason_contains")?.asString ?? "")'")
            }
        }
        // every suite this build implements ran its positive vector (a runner that skipped them all would pass vacuously)
        for alg in supported where alg != "ed25519" && !alg.contains("less") { XCTAssertTrue(ran.contains(alg), "suite \(alg) is built but no escalation_answer vector exercised it") }
    }

    // ---- exact outcomes beyond the shared vectors ----

    func testTightenNullIsRejectedLikeTheReference() {
        // ABSENT tighten is fine; JSON null is "not an array" (the reference treats null differently from undefined)
        XCTAssertNil(PCA.tightenListError(nil))
        XCTAssertEqual(PCA.tightenListError(.null), "tighten must be an array")
        let r = PCA.decideTighten(.object(["tighten": .null]))
        XCTAssertEqual(r.outcome, "deny")
        XCTAssertEqual(r.reason, "malformed tighten list: tighten must be an array")
        // polarity null is malformed as well: only 'legacy' is a valid value
        XCTAssertEqual(PCA.decideTighten(.object(["polarity": .null])).reason, "model_polarity must be 'legacy' when present")
    }

    func testLegacyPolarityIsReportedNotSilentlyAccepted() {
        let preds: JSONValue = .array([.array([.object(["verb": .string("*"), "where": .array([.object(["field": .string("env.prov.x"), "op": .string("eq"), "value": .string("a")])])])])])
        let strict = PCA.decideTighten(.object(["predicates": preds]))
        XCTAssertEqual(strict.outcome, "deny")
        XCTAssertEqual(strict.offending, ["env.prov.x"])
        XCTAssertFalse(strict.legacy)
        let legacy = PCA.decideTighten(.object(["predicates": preds, "polarity": .string("legacy")]))
        XCTAssertEqual(legacy.outcome, "ok")
        XCTAssertTrue(legacy.legacy)
        // legacy with no offending path is not degraded
        XCTAssertFalse(PCA.decideTighten(.object(["polarity": .string("legacy")])).legacy)
    }

    func testTightenRuleReasons() {
        let when: JSONValue = .object(["field": .string("action.params.amount"), "op": .string("gte"), "value": .int(10)])
        func rule(_ id: String, _ sig: String, reason: String? = nil) -> JSONValue {
            var o: JObject = ["id": .string(id), "when": when, "signal": .string(sig)]
            if let r = reason { o["reason"] = .string(r) }
            return .object(o)
        }
        let ctx: JSONValue = .object(["action": .object(["params": .object(["amount": .int(50)])])])
        let esc = PCA.decideTighten(.object(["tighten": .array([rule("big", "escalate", reason: "large")]), "context": ctx]))
        XCTAssertEqual(esc.outcome, "escalate")
        XCTAssertEqual(esc.reason, "escalate: asked by tighten rule 'big' (large)")
        let den = PCA.decideTighten(.object(["tighten": .array([rule("big", "escalate"), rule("huge", "deny")]), "context": ctx]))
        XCTAssertEqual(den.outcome, "deny")
        XCTAssertEqual(den.reason, "denied by tighten rule 'huge'")
        // a value the rule reads is missing: unknown -> escalate
        let unk = PCA.decideTighten(.object(["tighten": .array([rule("big", "deny")]), "context": .object(["action": .object(["params": .object([:])])])]))
        XCTAssertEqual(unk.outcome, "escalate")
        XCTAssertEqual(unk.reason, "escalate: rule 'big' could not be decided (a value it reads is missing or ill-typed)")
        // duplicate ids and an over-long list are malformed
        XCTAssertEqual(PCA.tightenListError(.array([rule("a", "deny"), rule("a", "deny")])), "tighten[1].id 'a' is a duplicate")
        XCTAssertEqual(PCA.tightenListError(.array((0..<65).map { rule("r\($0)", "deny") })), "tighten has more than 64 rules")
    }

    func testMeetNeverRaisesAndUnknownIsDeny() {
        XCTAssertEqual(PCA.meet("allow", "escalate"), "escalate")
        XCTAssertEqual(PCA.meet("escalate", "allow"), "escalate")
        XCTAssertEqual(PCA.meet("deny", "allow"), "deny")
        XCTAssertEqual(PCA.meet("allow", "banana"), "deny")
        XCTAssertEqual(PCA.pepDecision("deny", answered: true), "deny")
        XCTAssertEqual(PCA.pepDecision("escalate", answered: true), "allow")
        XCTAssertEqual(PCA.pepDecision("escalate", answered: false), "escalate")
    }

    func testDecisionOfNeedsEveryFailingCheckToBeEscalateClass() {
        let r = ["provenance: intent_required: a question is required", "tighten: escalate: asked by tighten rule 'x'"]
        XCTAssertEqual(PCA.decisionOf(allow: false, checks: ["provenance": "fail", "tighten": "fail", "wire": "pass"], reasons: r), "escalate")
        // one hard failure makes it deny, and a failing check with no reason of its own is hard
        XCTAssertEqual(PCA.decisionOf(allow: false, checks: ["provenance": "fail", "chain": "fail"], reasons: r + ["chain: bad"]), "deny")
        XCTAssertEqual(PCA.decisionOf(allow: false, checks: ["provenance": "fail", "chain": "fail"], reasons: r), "deny")
        // a check with BOTH an escalate reason and a hard reason is hard
        XCTAssertEqual(PCA.decisionOf(allow: false, checks: ["provenance": "fail"], reasons: [r[0], "provenance: rejected"]), "deny")
        XCTAssertEqual(PCA.decisionOf(allow: false, checks: ["provenance": "pass"], reasons: []), "deny")
    }
}
