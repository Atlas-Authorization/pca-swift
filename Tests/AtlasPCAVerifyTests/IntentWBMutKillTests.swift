import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Second-wave mutation-kill tests for IntentWB.swift: every wire/policy limit pinned at limit and limit+1, the guard
/// fall-throughs that must refuse, and the few helper paths the pipeline tests never reach. Reuses the signed fixtures of
/// `IntentWBKillTests` (`T`).
final class IntentWBMutKillTests: XCTestCase {
    typealias F = V2F
    typealias T = IntentWBKillTests

    func rep(_ n: Int, _ c: String = "a") -> String { String(repeating: c, count: n) }

    // ---- rule 16 policy limits ----

    func testRelationalCountLimit() {
        func rel(_ n: Int) -> JSONValue {
            .array((0..<n).map { i in
                JSONValue.object(["name": .string("r\(i)"), "fn": .string("sub"), "a": .string("action.params.a"), "b": .string("action.params.b")])
            })
        }
        XCTAssertNil(IntentWB.validateWorldPolicy(.object(["relational": rel(15)])))
        XCTAssertNil(IntentWB.validateWorldPolicy(.object(["relational": rel(16)])))
        XCTAssertEqual(IntentWB.validateWorldPolicy(.object(["relational": rel(17)])), "relational must be a list of at most 16")
    }

    func testOracleKidBound() {
        func oracles(_ len: Int) -> [JSONValue] {
            [("1", T.o1), ("2", T.o2), ("3", T.o3)].map { T.oracle(rep(len - 1) + $0.0, $0.1) }
        }
        XCTAssertNil(IntentWB.validateWorldPolicy(.object(["worlds": .array([T.world(oracles: oracles(64))])])))
        XCTAssertNotNil(IntentWB.validateWorldPolicy(.object(["worlds": .array([T.world(oracles: oracles(65))])])))
    }

    func testOfferPolicyBounds() {
        let off = T.offers()["offers"]!
        func sk(_ kid: String) -> JSONValue {
            F.with(off, ["site_keys": .array([.object(["kid": .string(kid), "pk": .string(F.pub(T.siteKey))])])])
        }
        XCTAssertNil(IntentWB.validateOfferPolicy(sk(rep(64))))
        XCTAssertNotNil(IntentWB.validateOfferPolicy(sk(rep(65))))
        // both filter halves must hold scalars only
        XCTAssertNotNil(IntentWB.validateOfferPolicy(F.with(off, ["filter": .object(["query": .object(["a": .double(1.5)]), "offer": .object([:])])])))
        XCTAssertNotNil(IntentWB.validateOfferPolicy(F.with(off, ["filter": .object(["query": .object([:]), "offer": .object(["a": .array([])])])])))
        XCTAssertNotNil(IntentWB.validateOfferPolicy(F.with(off, ["filter": .object(["query": .object(["a": .double(1.5)]), "offer": .object(["b": .array([])])])])))
        XCTAssertNil(IntentWB.validateOfferPolicy(F.with(off, ["filter": .object(["query": .object(["a": .int(1)]), "offer": .object(["b": .bool(true)])])])))
    }

    // ---- wire shapes ----

    func testFactWireBounds() {
        let f = F.fact(value: .int(1), oracle: "o1", by: T.o1)
        XCTAssertTrue(IntentWB.validateFactWire(f))
        XCTAssertTrue(IntentWB.validateFactWire(F.with(f, ["subject": .string(rep(256))])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(f, ["subject": .string(rep(257))])))
        XCTAssertTrue(IntentWB.validateFactWire(F.with(f, ["oracle": .string(rep(64))])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(f, ["oracle": .string(rep(65))])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(f, ["v": .int(2)])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(f, ["kind": .string("pca-facts")])))
    }

    func testOfferSetWireBounds() {
        func ok(_ over: JObject) -> Bool { IntentWB.validateOfferSetWire(T.offerSet(over)) }
        XCTAssertTrue(ok([:]))
        func offs(_ n: Int) -> JSONValue { .array((0..<n).map { i in JSONValue.object(["offer_id": .string("o\(i)"), "price": .int(Int64(i))]) }) }
        XCTAssertTrue(ok(["offers": offs(256)]))
        XCTAssertFalse(ok(["offers": offs(257)]))
        func q(_ n: Int) -> JSONValue {
            var o: JObject = [:]
            for i in 0..<n { o[JKey("k\(i)")] = .int(Int64(i)) }
            return .object(o)
        }
        XCTAssertTrue(ok(["query": q(32)]))
        XCTAssertFalse(ok(["query": q(33)]))
        XCTAssertTrue(ok(["query": .object([JKey(rep(64)): .string("x")])]))
        XCTAssertFalse(ok(["query": .object([JKey(rep(65)): .string("x")])]))
        XCTAssertFalse(ok(["query": .object(["a": .double(1.5)])]), "a good key with a non-scalar value")
        XCTAssertFalse(ok(["query": .object(["a": .array([])])]))
        XCTAssertFalse(ok(["query": .string("x")]))
        // the header guard refuses
        XCTAssertFalse(ok(["v": .int(2)]))
        XCTAssertFalse(ok(["kind": .string("pca-offer-sets")]))
        XCTAssertFalse(ok(["session": .string("x")]))
        XCTAssertFalse(ok(["x": .int(1)]))
        XCTAssertTrue(ok(["site": .string(rep(256))]))
        XCTAssertFalse(ok(["site": .string(rep(257))]))
        // offers
        XCTAssertTrue(ok(["offers": .array([.object(["offer_id": .string(rep(128)), "price": .int(1)])])]))
        XCTAssertFalse(ok(["offers": .array([.object(["offer_id": .string(rep(129)), "price": .int(1)])])]))
        XCTAssertTrue(ok(["offers": .array([.object(["offer_id": .string("a"), "price": .int(1), JKey(rep(64)): .int(1)])])]))
        XCTAssertFalse(ok(["offers": .array([.object(["offer_id": .string("a"), "price": .int(1), JKey(rep(65)): .int(1)])])]))
        // the tail: issued_at, kid and sig each required, kid a bounded non-empty string
        XCTAssertTrue(ok(["kid": .string(rep(64))]))
        XCTAssertFalse(ok(["kid": .string(rep(65))]))
        XCTAssertFalse(ok(["kid": .string("")]))
        XCTAssertFalse(ok(["issued_at": .int(-1)]))
        XCTAssertFalse(IntentWB.validateOfferSetWire(F.with(T.offerSet(), ["sig": .int(1)])))
        XCTAssertFalse(IntentWB.validateOfferSetWire(F.with(T.offerSet(["kid": .string("")]), ["issued_at": .int(-1)])))
    }

    func testLabelsWireBounds() {
        let f = T.field("a", .int(1))
        func ok(site: String = F.AUD, kid: String = "k1", fields: JObject? = nil) -> Bool {
            IntentWB.validateLabelsWire(T.receipt(site: site, kid: kid, fields: fields ?? ["f": f]))
        }
        XCTAssertTrue(ok())
        XCTAssertTrue(ok(site: rep(256)))
        XCTAssertFalse(ok(site: rep(257)))
        XCTAssertTrue(ok(fields: [JKey(rep(256)): f]))
        XCTAssertFalse(ok(fields: [JKey(rep(257)): f]))
        XCTAssertTrue(ok(fields: ["f": T.field(rep(128), .int(1))]))
        XCTAssertFalse(ok(fields: ["f": T.field(rep(129), .int(1))]))
        XCTAssertTrue(ok(kid: rep(64)))
        XCTAssertFalse(ok(kid: rep(65)))
        XCTAssertFalse(ok(kid: ""))
        let r = T.receipt(fields: ["f": f])
        XCTAssertFalse(IntentWB.validateLabelsWire(F.with(r, ["issued_at": .int(-1)])))
        XCTAssertFalse(IntentWB.validateLabelsWire(F.with(r, ["sig": .int(1)])))
        XCTAssertFalse(IntentWB.validateLabelsWire(F.with(T.receipt(kid: "", fields: ["f": f]), ["issued_at": .int(-1)])))
    }

    func testVerdictWireAndClassifierPolicy() {
        func ok(label: String = "x", measurement: String = "m1") -> Bool {
            IntentWB.validateVerdictWire(T.verdict(T.j1, label, measurement: measurement))
        }
        XCTAssertTrue(ok())
        XCTAssertTrue(ok(label: rep(64)))
        XCTAssertFalse(ok(label: rep(65)))
        XCTAssertTrue(ok(measurement: rep(256)))
        XCTAssertFalse(ok(measurement: rep(257)))
        XCTAssertTrue(IntentWB.validateClassifierPolicy(T.clsPolicy(labels: [rep(64), "x"])))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(T.clsPolicy(labels: [rep(65), "x"])))
        let c0 = T.clsPolicy().get("classifiers")!.asArray![0]
        func pol(_ patch: JObject) -> JSONValue { .object(["classifiers": .array([F.with(c0, patch)])]) }
        XCTAssertTrue(IntentWB.validateClassifierPolicy(pol([:])))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(pol(["keys": .array([])])))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(pol(["keys": .array([.string("x")])])))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(pol(["keys": .array([.string(F.pub(T.j1)), .string(F.pub(T.j1))])])))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(pol(["k": .int(0)])), "k must be at least 1")
        XCTAssertTrue(IntentWB.validateClassifierPolicy(pol(["k": .int(1)])))
        XCTAssertTrue(IntentWB.validateClassifierPolicy(pol(["k": .int(3)])))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(pol(["k": .int(4)])))
    }

    func testFlowRuleAndProvenancePolicyBounds() {
        XCTAssertTrue(IntentWB.validateFlowRules(.object(["a": .array([.string(rep(256))])])))
        XCTAssertFalse(IntentWB.validateFlowRules(.object(["a": .array([.string(rep(257))])])))
        XCTAssertFalse(IntentWB.validateFlowRules(.object(["a": .string("x")])), "sinks must be an array")
        XCTAssertFalse(IntentWB.validateFlowRules(.object(["a": .object([:])])))
        let base = T.policy()
        XCTAssertTrue(IntentWB.validateProvenancePolicy(F.with(base, ["registry": .object([JKey(rep(256)): .string("web")])])))
        XCTAssertFalse(IntentWB.validateProvenancePolicy(F.with(base, ["registry": .object([JKey(rep(257)): .string("web")])])))
        func lk(site: String, kid: String) -> JSONValue {
            F.with(base, ["label_keys": .array([.object(["site": .string(site), "kid": .string(kid), "pk": .string(F.pub(T.labelKey))])])])
        }
        XCTAssertTrue(IntentWB.validateProvenancePolicy(lk(site: rep(256), kid: rep(64))))
        XCTAssertFalse(IntentWB.validateProvenancePolicy(lk(site: rep(257), kid: "k")))
        XCTAssertFalse(IntentWB.validateProvenancePolicy(lk(site: "s", kid: rep(65))))
    }

    // ---- helpers ----

    func testIsParamPathSegmentCount() {
        let eight = "action.params.a.b.c.d.e.f.g.h"
        XCTAssertTrue(IntentWB.isParamPath(.string("action.params.a")))
        XCTAssertTrue(IntentWB.isParamPath(.string(eight)))
        XCTAssertFalse(IntentWB.isParamPath(.string(eight + ".i")))
        XCTAssertFalse(IntentWB.isParamPath(.string("action.params.")))
        XCTAssertFalse(IntentWB.isParamPath(.string("action.params.a..b")))
    }

    func testRatioPpmOverflowEdge() {
        // a * 1e6 lands in [2^64, 2^65): the high word is 1 == b, which must be refused (not trapped)
        XCTAssertNil(IntentWB.ratioPpm(18_446_744_073_710, 1))
        XCTAssertEqual(IntentWB.ratioPpm(1, 1), 1_000_000)
    }

    func testVerifyArtifactSigGuards() {
        let f = F.fact(value: .int(1), oracle: "o1", by: T.o1)
        let pk = F.pub(T.o1)
        XCTAssertTrue(IntentWB.verifyArtifactSig(IntentWB.FACT_DOMAIN, f.asObject!, pk))
        XCTAssertFalse(IntentWB.verifyArtifactSig(IntentWB.FACT_DOMAIN, F.without(f, ["sig"]).asObject!, pk), "no signature")
        XCTAssertFalse(IntentWB.verifyArtifactSig(IntentWB.FACT_DOMAIN, F.with(f, ["sig": .int(1)]).asObject!, pk), "a non-string signature")
        let unhashable = F.with(f, ["x": .int(9_007_199_254_740_992)]).asObject!
        XCTAssertFalse(IntentWB.verifyArtifactSig(IntentWB.FACT_DOMAIN, unhashable, pk), "not strictly canonical")
    }

    func testRankDefaultsToAgent() {
        XCTAssertEqual(IntentWB.rank("trusted"), 0)
        XCTAssertEqual(IntentWB.rank("first_party"), 1)
        XCTAssertEqual(IntentWB.rank("tool"), 2)
        XCTAssertEqual(IntentWB.rank("web"), 3)
        XCTAssertEqual(IntentWB.rank("agent"), 4)
        XCTAssertEqual(IntentWB.rank("nope"), 4)
    }

    func testSetNested() {
        var root: JObject = [:]
        XCTAssertFalse(IntentWB.setNested(&root, ArraySlice<String>(), .string("x")), "an empty path sets nothing")
        XCTAssertEqual(root, [:])
        XCTAssertTrue(IntentWB.setNested(&root, ["a", "b"], .string("x")))
        XCTAssertEqual(root, ["a": .object(["b": .string("x")])])
        XCTAssertFalse(IntentWB.setNested(&root, ["a", "b"], .string("y")), "a leaf is never overwritten")
        XCTAssertEqual(root, ["a": .object(["b": .string("x")])])
        XCTAssertFalse(IntentWB.setNested(&root, ["a"], .string("y")), "a subtree is never replaced by a leaf")
        XCTAssertFalse(IntentWB.setNested(&root, ["a", "b", "c"], .string("y")), "a leaf is never descended into")
        XCTAssertEqual(root, ["a": .object(["b": .string("x")])])
        XCTAssertTrue(IntentWB.setNested(&root, ["a", "c"], .string("z")))
        XCTAssertEqual(root, ["a": .object(["b": .string("x"), "c": .string("z")])])
    }

    // ---- offer sets (decideOfferSet) ----

    func offer(_ os: JSONValue, policy: JObject = T.offers(), offerId: String = "OF-2") -> IntentWB.WorldDecision {
        let action: JSONValue = .object(["verb": .string("air.book"), "resource": .string("r"), "params": .object(["offer_id": .string(offerId)])])
        return IntentWB.decideWorld(now: F.NOW, aud: F.AUD, session: F.SESSION, action: action,
                                    committed: .object(["offer_set": .string(F.ref(IntentWB.OFFER_SET_REF_DOMAIN, "o", os))]), facts: nil, offerSet: os, policy: .object(policy))
    }

    func testOfferFilterKeyMissingOnOffer() {
        let r = offer(T.offerSet(), policy: T.offers(filter: .object(["query": .object(["from": .string("SFO")]), "offer": .object(["meal": .string("veg")])])))
        XCTAssertFalse(r.ok)
        XCTAssertTrue(r.reason.contains("does not satisfy the intent filter"), r.reason)
        XCTAssertTrue(offer(T.offerSet()).ok)
    }

    func testOfferAgeWithoutMaxAgeIsZero() {
        var pol = T.offers()["offers"]!.asObject!
        pol["max_age_ms"] = nil
        let params: JSONValue = .object(["offer_id": .string("OF-2")])
        func run(issued: Int64) -> (excess: Int64?, reason: String) {
            let os = T.offerSet(["issued_at": .int(issued)])
            return IntentWB.decideOfferSet(policy: pol, committed: .string(F.ref(IntentWB.OFFER_SET_REF_DOMAIN, "o", os)), offerSet: os, params: params,
                                           aud: F.AUD, session: F.SESSION, now: F.NOW, skewMs: 60_000)
        }
        let fresh = run(issued: F.NOW)
        XCTAssertEqual(fresh.excess, 900, fresh.reason)
        let stale = run(issued: F.NOW - 1)
        XCTAssertNil(stale.excess)
        XCTAssertEqual(stale.reason, "offers: the offer set is stale")
    }

    // ---- rule 17 ----

    func prov(_ prov: JObject, params: JSONValue, policy: JSONValue = .object(["params": .object([:])])) -> IntentWB.ProvenanceDecision {
        IntentWB.decideProvenance(aud: F.AUD, session: F.SESSION, params: params, prov: .object(prov), committedLabels: .array([]), labels: .array([]), policy: policy)
    }

    func testProvenancePathAndRefLimits() {
        func many(_ n: Int) -> (JObject, JSONValue) {
            var pr: JObject = [:], pa: JObject = [:]
            for i in 0..<n { pr[JKey("action.params.p\(i)")] = .array([.string("x")]); pa[JKey("p\(i)")] = .int(Int64(i)) }
            return (pr, .object(pa))
        }
        let (p32, a32) = many(32)
        let ok = prov(p32, params: a32)
        XCTAssertEqual(ok.outcome, "pass", ok.reason); XCTAssertEqual(ok.labels.count, 32)
        let (p33, a33) = many(33)
        let bad = prov(p33, params: a33)
        XCTAssertEqual(bad.outcome, "deny"); XCTAssertEqual(bad.reason, "provenance: 'prov' holds more than 32 paths")
        let params: JSONValue = .object(["a": .int(1)])
        func refs(_ n: Int) -> JObject { ["action.params.a": .array((0..<n).map { .string("r\($0)") })] }
        XCTAssertEqual(prov(refs(8), params: params).outcome, "pass")
        let nine = prov(refs(9), params: params)
        XCTAssertEqual(nine.outcome, "deny"); XCTAssertEqual(nine.reason, "provenance: 'prov.action.params.a' must hold 1..8 refs")
        XCTAssertEqual(prov(["action.params.a": .array([.string(rep(256))])], params: params).outcome, "pass")
        XCTAssertEqual(prov(["action.params.a": .array([.string(rep(257))])], params: params).outcome, "deny")
        XCTAssertEqual(prov(["action.params.a": .array([])], params: params).outcome, "deny")
    }

    func testProvenanceForbiddenKeyReason() {
        for n in ["constructor", "__proto__", "prototype"] {
            let d = prov([JKey("action.params.\(n)"): .array([.string("x")])], params: .object([JKey(n): .int(1)]))
            XCTAssertEqual(d.outcome, "deny", n)
            XCTAssertEqual(d.reason, "provenance: 'prov' key 'action.params.\(n)' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)", n)
        }
        // a nested key is not a top-level parameter path
        XCTAssertEqual(prov(["action.params.a.b": .array([.string("x")])], params: .object(["a": .object(["b": .int(1)])])).reason,
                       "provenance: 'prov' key 'action.params.a.b' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)")
    }

    func testLabelMismatchWhenValueIsNotCanonical() {
        let rc = T.receipt(fields: ["offer.id": T.field("commerce.offer", .string("OF-1"))])
        let ref = F.ref(IntentWB.LABELS_REF_DOMAIN, "l", rc)
        let policy = T.policy(["params": .object([:])])
        func run(_ value: JSONValue) -> IntentWB.ProvenanceDecision {
            IntentWB.decideProvenance(aud: F.AUD, session: F.SESSION, params: .object(["offer_id": value]),
                                      prov: .object(["action.params.offer_id": .array([.string("pca-labels:\(ref)#offer.id")])]),
                                      committedLabels: .array([.string(ref)]), labels: .array([rc]), policy: policy)
        }
        let good = run(.string("OF-1"))
        XCTAssertEqual(good.outcome, "pass", good.reason); XCTAssertEqual(good.labels["action.params.offer_id"], "first_party")
        // an integer outside the safe range has no strict canonical form: no digest can match, the label is agent
        let odd = run(.int(9_007_199_254_740_992))
        XCTAssertEqual(odd.outcome, "pass", odd.reason); XCTAssertEqual(odd.labels["action.params.offer_id"], "agent")
    }

    // ---- composition and primitives ----

    func testDecideOutcomeFollowsProvenance() {
        let session: JSONValue = .object(["prov": .object([:])])
        func run(_ provPolicy: JSONValue) -> IntentWB.WBResult {
            IntentWB.decide(now: F.NOW, aud: F.AUD, session: F.SESSION, action: T.ACTION, intentSession: session, artifacts: nil,
                            policy: .object(["provenance": provPolicy]))
        }
        let pass = run(.object(["params": .object([:])]))
        XCTAssertEqual(pass.outcome, "admit")
        XCTAssertEqual(pass.checks.map { "\($0.0):\($0.1)" }, ["provenance:pass"])
        XCTAssertNil(pass.reason)
        let q = run(.object(["params": .object(["action.params.offer_id": .string("material")])]))
        XCTAssertEqual(q.outcome, "question")
        XCTAssertEqual(q.checks.map { "\($0.0):\($0.1)" }, ["provenance:question"])
        XCTAssertEqual(q.reason, "provenance: a tainted value needs the principal (lazy question)")
    }

    func testPrimitivesRefuseMissingIdentity() {
        let w = PCA.intentWorldPrimitive(.object(["now": .int(F.NOW), "session": .string(F.SESSION), "action": T.ACTION, "policy": .object([:])]))
        XCTAssertFalse(w.ok); XCTAssertEqual(w.reason, "facts: malformed input")
        let w2 = PCA.intentWorldPrimitive(.object(["now": .int(F.NOW), "aud": .string(F.AUD), "action": T.ACTION, "policy": .object([:])]))
        XCTAssertFalse(w2.ok); XCTAssertEqual(w2.reason, "facts: malformed input")
        let c = PCA.intentClassifierPrimitive(.object(["action": .object([:]), "policy": .object(["classifiers": .array([])])]))
        XCTAssertFalse(c.ok); XCTAssertEqual(c.reason, "classes: malformed input")
    }

    func testReadPurposeExactPatternOnly() {
        let fields: JSONValue = .array([.object(["path": .string("x"), "class": .string("pii.contact")])])
        func rp(_ pats: [String]) -> (String, [String]) {
            let r = PCA.intentReadPurposePrimitive(.object(["fields": fields, "purpose": .string("p"), "coverage": .object(["p": .array(pats.map { .string($0) })])]))
            return (r.outcome, r.uncovered)
        }
        XCTAssertTrue(rp(["pii.contact"]) == ("allow", []))
        XCTAssertTrue(rp(["pii.*"]) == ("allow", []))
        // a pattern that is not `.*`-terminated never matches by prefix, even when it is one character longer than the class
        XCTAssertTrue(rp(["pii.contactx"]) == ("question", ["x"]))
        XCTAssertTrue(rp(["pii.contac"]) == ("question", ["x"]))
    }
}
