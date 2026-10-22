import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mutation-kill tests for Intent Layer v2 W-B (IntentWB.swift): rule 16 (facts, relational dimensions, offer sets), rule 17
/// (provenance, label receipts, flow rules), rule 18 (classifier verdicts) at every boundary, and their composition in the
/// verifier pipeline (one unit: the first failing check ends it; a provenance question fails `provenance`).
final class IntentWBKillTests: XCTestCase {
    typealias F = V2F
    static let o1 = F.key("o1"), o2 = F.key("o2"), o3 = F.key("o3"), o4 = F.key("o4")
    static let ACTION: JSONValue = .object(["verb": .string("air.book"), "resource": .string("skyair.example/bookings"),
                                            "params": .object(["offer_id": .string("OF-1"), "total": .int(77_800), "quote": .int(38_900)])])
    static func oracle(_ kid: String, _ k: V2F.K) -> JSONValue { .object(["kid": .string(kid), "pk": .string(F.pub(k))]) }
    static func world(min: Int64 = 3, faulty: Int64 = 1, oracles: [JSONValue]? = nil, freshness: Int64 = 60_000, name: String = "fare") -> JSONValue {
        .object(["name": .string(name), "subject_path": .string("action.params.offer_id"), "freshness_ms": .int(freshness), "min_oracles": .int(min),
                 "max_faulty": .int(faulty), "oracles": .array(oracles ?? [oracle("o1", o1), oracle("o2", o2), oracle("o3", o3)])])
    }
    static func facts(_ vals: [JSONValue], t: [Int64]? = nil) -> [JSONValue] {
        let ks = [("o1", o1), ("o2", o2), ("o3", o3), ("o4", o4)]
        return vals.enumerated().map { i, v in F.fact(value: v, tObs: t?[i] ?? F.NOW - 1_000, oracle: ks[i].0, by: ks[i].1) }
    }
    static func refs(_ fs: [JSONValue]) -> JSONValue { .array(fs.map { .string(F.ref(IntentWB.FACT_REF_DOMAIN, "f", $0)) }) }

    func world(_ fs: [JSONValue], policy: JObject, committed: JSONValue? = nil, offerSet: JSONValue? = nil, committedOffer: String? = nil, supplied: [JSONValue]? = nil) -> IntentWB.WorldDecision {
        var c: JObject = ["facts": committed ?? Self.refs(fs)]
        if let co = committedOffer { c["offer_set"] = .string(co) }
        return IntentWB.decideWorld(now: F.NOW, aud: F.AUD, session: F.SESSION, action: Self.ACTION, committed: .object(c), facts: .array(supplied ?? fs),
                                    offerSet: offerSet, policy: .object(policy))
    }

    // ---- rule 16 ----------------------------------------------------------------------------------------------------

    func testWorldMedianFreshnessAndSkew() {
        let p: JObject = ["worlds": .array([Self.world()])]
        XCTAssertEqual(world(Self.facts([.int(39_900), .int(39_700), .int(39_800)]), policy: p).world["fare"], .int(39_800))
        let p4: JObject = ["worlds": .array([Self.world(oracles: [Self.oracle("o1", Self.o1), Self.oracle("o2", Self.o2), Self.oracle("o3", Self.o3), Self.oracle("o4", Self.o4)])])]
        XCTAssertEqual(world(Self.facts([.int(40), .int(10), .int(30), .int(20)]), policy: p4).world["fare"], .int(20), "lower median of an even count")
        XCTAssertEqual(world(Self.facts([.string("gold"), .string("gold"), .string("gold")]), policy: p).world["fare"], .string("gold"))
        XCTAssertFalse(world(Self.facts([.string("gold"), .string("gold"), .string("silver")]), policy: p).ok)
        XCTAssertFalse(world(Self.facts([.string("gold"), .int(1), .int(2)]), policy: p).ok)
        // freshness inclusive; skew inclusive; stale / future facts are not counted (then too few)
        let n = F.NOW
        XCTAssertTrue(world(Self.facts([.int(1), .int(2), .int(3)], t: [n - 60_000, n, n]), policy: p).ok)
        XCTAssertFalse(world(Self.facts([.int(1), .int(2), .int(3)], t: [n - 60_001, n, n]), policy: p).ok)
        XCTAssertTrue(world(Self.facts([.int(1), .int(2), .int(3)], t: [n + 60_000, n, n]), policy: p).ok)
        XCTAssertFalse(world(Self.facts([.int(1), .int(2), .int(3)], t: [n + 60_001, n, n]), policy: p).ok)
        XCTAssertFalse(world(Self.facts([.int(1), .int(2), .int(3)], t: [n + 1, n, n]), policy: p.merging(["skew_ms": .int(0)]) { $1 }).ok)
        XCTAssertTrue(world(Self.facts([.int(1), .int(2), .int(3)], t: [n, n, n]), policy: p.merging(["skew_ms": .int(0)]) { $1 }).ok)
        // n >= min_oracles: with 4 pinned and 3 required, 3 fresh suffice
        XCTAssertTrue(world(Self.facts([.int(1), .int(2), .int(3)]), policy: p4.merging(["worlds": .array([Self.world(min: 3, oracles: p4["worlds"]!.asArray![0].get("oracles")!.asArray!)])]) { $1 }).ok)
        // single source
        let single = world(Self.facts([.int(5)]), policy: ["worlds": .array([Self.world(min: 1, faulty: 0)])])
        XCTAssertEqual(single.singleSource, ["fare"]); XCTAssertEqual(single.world["fare"], .int(5))
        XCTAssertEqual(world(Self.facts([.int(1), .int(2), .int(3)]), policy: p).singleSource, [])
    }

    func testWorldFactRefusals() {
        let p: JObject = ["worlds": .array([Self.world()])]
        let fs = Self.facts([.int(1), .int(2), .int(3)])
        XCTAssertTrue(world(fs, policy: p).ok)
        // uncommitted supplied facts are ignored, even when malformed
        XCTAssertTrue(world(fs, policy: p, supplied: fs + [F.fact(value: .int(9), oracle: "o9", by: F.stranger), .int(5), .object([:])]).ok)
        XCTAssertFalse(world(fs, policy: p, supplied: Array(fs.prefix(2))).ok, "a committed fact must be supplied")
        XCTAssertFalse(world(fs, policy: p, committed: .array(Self.refs(fs).asArray! + [Self.refs(fs).asArray![0]])).ok, "duplicate commitment")
        XCTAssertFalse(world(fs, policy: p, committed: .array([.string("x")])).ok)
        XCTAssertFalse(world(fs, policy: p, committed: .object([:])).ok)
        let r17 = world(fs, policy: p, committed: .array((0..<17).map { .string(F.digest("c\($0)")) }))
        XCTAssertTrue(r17.reason.contains("at most 16"), r17.reason)
        let r16 = world(fs, policy: p, committed: .array((0..<16).map { .string(F.digest("c\($0)")) }))
        XCTAssertTrue(r16.reason.contains("was not supplied"), r16.reason)
        let unpinned = F.fact(value: .int(1), oracle: "o9", by: Self.o1)
        XCTAssertFalse(world([unpinned] + fs.dropFirst(), policy: p).ok)
        let wrongKey = F.fact(value: .int(1), oracle: "o1", by: Self.o2)
        XCTAssertFalse(world([wrongKey] + fs.dropFirst(), policy: p).ok)
        let otherSubject = F.fact(subject: "OF-2", value: .int(1), oracle: "o1", by: Self.o1)
        XCTAssertFalse(world([otherSubject] + fs.dropFirst(), policy: p).ok)
        let undeclared = F.fact(name: "tier", value: .int(1), oracle: "o1", by: Self.o1)
        XCTAssertFalse(world([undeclared] + fs.dropFirst(), policy: p).ok)
        let twice = F.fact(value: .int(7), tObs: F.NOW - 2_000, oracle: "o1", by: Self.o1)
        XCTAssertFalse(world(fs + [twice], policy: p).ok, "two facts from one oracle")
        var tampered = fs[0].asObject!
        tampered["value"] = .int(99)
        XCTAssertFalse(world([.object(tampered)] + fs.dropFirst(), policy: p).ok)
        XCTAssertFalse(IntentWB.validateFactWire(F.with(fs[0], ["value": .string("")])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(fs[0], ["t_obs": .int(-1)])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(fs[0], ["name": .string("Fare")])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(fs[0], ["x": .int(1)])))
        XCTAssertTrue(IntentWB.validateFactWire(F.with(fs[0], ["value": .string(String(repeating: "a", count: 256))])))
        XCTAssertFalse(IntentWB.validateFactWire(F.with(fs[0], ["value": .string(String(repeating: "a", count: 257))])))
    }

    func testWorldPolicySanity() {
        func bad(_ p: JObject) -> Bool { IntentWB.validateWorldPolicy(.object(p)) != nil }
        XCTAssertFalse(bad(["worlds": .array([Self.world()])]))
        XCTAssertTrue(bad(["worlds": .array([Self.world(min: 2, faulty: 1)])]), "min_oracles >= 2f+1")
        XCTAssertFalse(bad(["worlds": .array([Self.world(min: 3, faulty: 1)])]))
        XCTAssertTrue(bad(["worlds": .array([Self.world(min: 4)])]), "fewer pinned oracles than min_oracles")
        XCTAssertTrue(bad(["worlds": .array([Self.world(oracles: [Self.oracle("o1", Self.o1), Self.oracle("o1", Self.o2), Self.oracle("o3", Self.o3)])])]))
        XCTAssertTrue(bad(["skew_ms": .int(-1)]))
        XCTAssertTrue(bad(["skew_ms": .null]))
        XCTAssertTrue(bad(["worlds": .array((0..<17).map { Self.world(name: "w\($0)") })]))
        XCTAssertFalse(bad(["worlds": .array((0..<16).map { Self.world(name: "w\($0)") })]))
        XCTAssertTrue(bad(["worlds": .array([Self.world(name: "Fare")])]))
        let rel = { (name: String, a: String, b: String) in JSONValue.object(["name": .string(name), "fn": .string("sub"), "a": .string(a), "b": .string(b)]) }
        XCTAssertFalse(bad(["worlds": .array([Self.world()]), "relational": .array([rel("d", "action.params.total", "env.world.fare")])]))
        XCTAssertTrue(bad(["worlds": .array([Self.world()]), "relational": .array([rel("fare", "action.params.total", "env.world.fare")])]), "duplicate name")
        XCTAssertTrue(bad(["relational": .array([rel("d", "env.world.d", "action.params.total")])]), "self reference")
        XCTAssertTrue(bad(["relational": .array([rel("d", "env.world.e", "action.params.total"), rel("e", "action.params.total", "action.params.quote")])]), "later name")
        XCTAssertTrue(bad(["relational": .array([rel("d", "action.params.__proto__", "action.params.total")])]))
        XCTAssertTrue(bad(["relational": .array([.object(["name": .string("d"), "fn": .string("mul"), "a": .string("action.params.total"), "b": .string("action.params.quote")])])]))
    }

    func testRelationalArithmetic() {
        XCTAssertEqual(IntentWB.ratioPpm(1, 3), 333_333)
        XCTAssertEqual(IntentWB.ratioPpm(2, 1), 2_000_000)
        XCTAssertEqual(IntentWB.ratioPpm(0, 5), 0)
        XCTAssertNil(IntentWB.ratioPpm(1, 0))
        XCTAssertNil(IntentWB.ratioPpm(-1, 3))
        XCTAssertNil(IntentWB.ratioPpm(1, -3))
        XCTAssertEqual(IntentWB.ratioPpm(9_007_199_254, 1), 9_007_199_254_000_000)
        XCTAssertNil(IntentWB.ratioPpm(9_007_199_255, 1))
        XCTAssertEqual(IntentWB.ratioPpm(9_007_199_254_740_991, 1_000_000), 9_007_199_254_740_991)
        XCTAssertNil(IntentWB.ratioPpm(9_007_199_254_740_991, 999_999))
        let rel = { (name: String, fn: String, a: String, b: String) in JSONValue.object(["name": .string(name), "fn": .string(fn), "a": .string(a), "b": .string(b)]) }
        let fs = Self.facts([.int(38_900), .int(38_900), .int(38_900)])
        let w = world(fs, policy: ["worlds": .array([Self.world()]),
                                   "relational": .array([rel("over", "sub", "action.params.quote", "env.world.fare"), rel("neg", "sub", "env.world.fare", "action.params.total"),
                                                         rel("ratio", "ratio_ppm", "action.params.total", "env.world.fare"), rel("chained", "sub", "env.world.ratio", "env.world.over")])])
        XCTAssertEqual(w.world["over"], .int(0)); XCTAssertEqual(w.world["neg"], .int(-38_900))
        XCTAssertEqual(w.world["ratio"], .int(2_000_000)); XCTAssertEqual(w.world["chained"], .int(2_000_000))
        XCTAssertFalse(world(fs, policy: ["worlds": .array([Self.world()]), "relational": .array([rel("r", "ratio_ppm", "action.params.total", "action.params.missing")])]).ok)
        XCTAssertFalse(world([], policy: ["relational": .array([rel("r", "ratio_ppm", "action.params.offer_id", "action.params.total")])]).ok, "a string operand")
    }

    // offer sets
    static let siteKey = F.key("offer-site")
    static func offerSet(_ over: JObject = [:]) -> JSONValue {
        var b: JObject = ["v": .int(1), "kind": .string("pca-offer-set"), "site": .string(F.AUD), "session": .string(F.SESSION), "query": .object(["from": .string("SFO")]),
                          "rank": .string("price_asc"), "complete": .bool(true),
                          "offers": .array([.object(["offer_id": .string("OF-1"), "price": .int(38_900), "cabin": .string("eco"), "stops": .int(0)]),
                                            .object(["offer_id": .string("OF-2"), "price": .int(39_800), "cabin": .string("eco"), "stops": .int(0)]),
                                            .object(["offer_id": .string("OF-3"), "price": .int(30_000), "cabin": .string("biz"), "stops": .int(0)])]),
                          "issued_at": .int(F.NOW - 1_000), "kid": .string("s1")]
        for (k, v) in over { b[k] = v }
        return F.signArtifact(IntentWB.OFFER_SET_DOMAIN, b, siteKey)
    }
    static func offers(_ over: JObject = [:], filter: JSONValue? = nil) -> JObject {
        var o: JObject = ["name": .string("excess"), "site_keys": .array([.object(["kid": .string("s1"), "pk": .string(F.pub(siteKey))])]), "max_age_ms": .int(600_000),
                          "offer_param": .string("action.params.offer_id"),
                          "filter": filter ?? .object(["query": .object(["from": .string("SFO")]), "offer": .object(["cabin": .string("eco")])])]
        for (k, v) in over { o[k] = v }
        return ["offers": .object(o)]
    }
    func offer(_ os: JSONValue, policy: JObject = IntentWBKillTests.offers(), offerId: String = "OF-2", committed: String? = nil) -> IntentWB.WorldDecision {
        let action: JSONValue = .object(["verb": .string("air.book"), "resource": .string("r"), "params": .object(["offer_id": .string(offerId)])])
        return IntentWB.decideWorld(now: F.NOW, aud: F.AUD, session: F.SESSION, action: action,
                                    committed: .object(["offer_set": .string(committed ?? F.ref(IntentWB.OFFER_SET_REF_DOMAIN, "o", os))]), facts: nil, offerSet: os, policy: .object(policy))
    }

    func testOfferSet() {
        XCTAssertEqual(offer(Self.offerSet()).world["excess"], .int(900))
        XCTAssertEqual(offer(Self.offerSet(), offerId: "OF-1").world["excess"], .int(0))
        XCTAssertFalse(offer(Self.offerSet(), offerId: "OF-3").ok, "the chosen offer fails the filter")
        XCTAssertFalse(offer(Self.offerSet(), offerId: "OF-9").ok)
        XCTAssertTrue(offer(Self.offerSet(["issued_at": .int(F.NOW - 600_000)])).ok)
        XCTAssertFalse(offer(Self.offerSet(["issued_at": .int(F.NOW - 600_001)])).ok)
        XCTAssertTrue(offer(Self.offerSet(["issued_at": .int(F.NOW + 60_000)])).ok)
        XCTAssertFalse(offer(Self.offerSet(["issued_at": .int(F.NOW + 60_001)])).ok)
        XCTAssertFalse(offer(Self.offerSet(["complete": .bool(false)])).ok)
        XCTAssertFalse(offer(Self.offerSet(["site": .string("other.example")])).ok)
        XCTAssertFalse(offer(Self.offerSet(["session": .string(F.digest("s2"))])).ok)
        XCTAssertFalse(offer(Self.offerSet(["kid": .string("s2")])).ok)
        XCTAssertFalse(offer(Self.offerSet(["query": .object(["from": .string("SFO"), "date": .string("x")])])).ok, "a narrowed search")
        XCTAssertFalse(offer(Self.offerSet(["query": .object(["from": .string("JFK")])])).ok)
        XCTAssertTrue(offer(Self.offerSet(["query": .object([:])])).ok, "a broader query covers")
        XCTAssertFalse(offer(Self.offerSet(), committed: F.digest("x")).ok)
        XCTAssertFalse(offer(Self.offerSet(), policy: Self.offers(filter: .object(["query": .object(["from": .string("SFO")]), "offer": .object(["stops": .string("0")])]))).ok,
                       "typed equality")
        XCTAssertEqual(offer(Self.offerSet(), policy: Self.offers(filter: .object(["query": .object(["from": .string("SFO")]), "offer": .object([:])]))).world["excess"], .int(9_800))
        XCTAssertFalse(offer(Self.offerSet(), policy: Self.offers(["max_age_ms": .int(-1)])).ok)
        var tampered = Self.offerSet().asObject!
        tampered["complete"] = .bool(true)
        tampered["issued_at"] = .int(F.NOW - 2)
        XCTAssertFalse(offer(.object(tampered)).ok)
        // no committed offer set / not supplied
        let action: JSONValue = .object(["verb": .string("air.book"), "resource": .string("r"), "params": .object(["offer_id": .string("OF-2")])])
        XCTAssertFalse(IntentWB.decideWorld(now: F.NOW, aud: F.AUD, session: F.SESSION, action: action, committed: .object([:]), facts: nil, offerSet: Self.offerSet(),
                                            policy: .object(Self.offers())).ok)
        XCTAssertFalse(IntentWB.decideWorld(now: F.NOW, aud: F.AUD, session: F.SESSION, action: action,
                                            committed: .object(["offer_set": .string(F.ref(IntentWB.OFFER_SET_REF_DOMAIN, "o", Self.offerSet()))]), facts: nil, offerSet: nil,
                                            policy: .object(Self.offers())).ok)
        // wire limits
        XCTAssertTrue(IntentWB.validateOfferSetWire(Self.offerSet()))
        XCTAssertFalse(IntentWB.validateOfferSetWire(Self.offerSet(["offers": .array([])])))
        XCTAssertFalse(IntentWB.validateOfferSetWire(Self.offerSet(["offers": .array([.object(["offer_id": .string("a"), "price": .int(-1)])])])))
        XCTAssertFalse(IntentWB.validateOfferSetWire(Self.offerSet(["offers": .array([.object(["offer_id": .string("a"), "price": .int(1)]), .object(["offer_id": .string("a"), "price": .int(2)])])])))
        let attrs = { (n: Int) -> JSONValue in
            var o: JObject = ["offer_id": .string("a"), "price": .int(1)]
            for i in 0..<n { o[JKey("k\(i)")] = .int(Int64(i)) }
            return .object(o)
        }
        XCTAssertTrue(IntentWB.validateOfferSetWire(Self.offerSet(["offers": .array([attrs(32)])])))
        XCTAssertFalse(IntentWB.validateOfferSetWire(Self.offerSet(["offers": .array([attrs(33)])])))
        XCTAssertFalse(IntentWB.validateOfferSetWire(Self.offerSet(["offers": .array([F.with(attrs(1), ["k0": .double(1.5)])])])))
        XCTAssertFalse(IntentWB.validateOfferSetWire(Self.offerSet(["rank": .string("price_desc")])))
    }

    // ---- rule 17 ----------------------------------------------------------------------------------------------------

    static let labelKey = F.key("labels-site"), govKey = F.key("labels-gov")
    static let PARAMS: JSONValue = .object(["offer_id": .string("OF-1"), "payment_ref": .string("pm_ana"), "note": .string("hi")])
    static func policy(_ over: JObject = [:]) -> JSONValue {
        var p: JObject = [
            "params": .object(["action.params.offer_id": .string("material"), "action.params.payment_ref": .string("critical")]),
            "registry": .object(["skyair:offer:1": .string("first_party"), "wallet:ana": .string("trusted"), "web:ad": .string("web"), "tool:fx": .string("tool")]),
            "label_keys": .array([.object(["site": .string(F.AUD), "kid": .string("k1"), "pk": .string(F.pub(labelKey))]),
                                  .object(["site": .string("gov.example"), "kid": .string("g1"), "pk": .string(F.pub(govKey))])]),
        ]
        for (k, v) in over { p[k] = v }
        return .object(p)
    }
    static func receipt(site: String = F.AUD, kid: String = "k1", by k: V2F.K = labelKey, session: String = F.SESSION, fields: JObject) -> JSONValue {
        F.signArtifact(IntentWB.LABELS_DOMAIN, ["v": .int(1), "kind": .string("pca-labels"), "site": .string(site), "session": .string(session),
                                                "response_digest": .string(F.digest("resp")), "fields": .object(fields), "issued_at": .int(F.NOW - 1_000), "kid": .string(kid)], k)
    }
    static func field(_ cls: String, _ value: JSONValue) -> JSONValue { .object(["class": .string(cls), "value_digest": .string(F.hash(value))]) }

    func prov(_ prov: JObject, policy: JSONValue = IntentWBKillTests.policy(), labels: [JSONValue] = [], committed: [String]? = nil, params: JSONValue = PARAMS) -> IntentWB.ProvenanceDecision {
        let refs = committed ?? labels.map { F.ref(IntentWB.LABELS_REF_DOMAIN, "l", $0) }
        return IntentWB.decideProvenance(aud: F.AUD, session: F.SESSION, params: params, prov: .object(prov), committedLabels: .array(refs.map { .string($0) }),
                                         labels: .array(labels), policy: policy)
    }

    func testProvenanceModes() {
        let clean: JObject = ["action.params.offer_id": .array([.string("skyair:offer:1")]), "action.params.payment_ref": .array([.string("wallet:ana")])]
        let c = prov(clean)
        XCTAssertEqual(c.outcome, "pass"); XCTAssertEqual(c.labels, ["action.params.offer_id": "first_party", "action.params.payment_ref": "trusted"])
        XCTAssertEqual(c.env, ["action": .object(["params": .object(["offer_id": .string("first_party"), "payment_ref": .string("trusted")])])])
        let web = prov(clean.merging(["action.params.offer_id": .array([.string("skyair:offer:1"), .string("web:ad")])]) { $1 })
        XCTAssertEqual(web.outcome, "question"); XCTAssertEqual(web.friction, "tap"); XCTAssertEqual(web.labels["action.params.offer_id"], "web")
        let tool = prov(clean.merging(["action.params.payment_ref": .array([.string("tool:fx")])]) { $1 })
        XCTAssertEqual(tool.outcome, "question"); XCTAssertEqual(tool.friction, "typed")
        XCTAssertEqual(prov(clean.merging(["action.params.offer_id": .array([.string("web:ad")])]) { $1 }, policy: Self.policy(["material_tainted": .string("allow")])).outcome, "pass")
        XCTAssertEqual(prov(clean.merging(["action.params.offer_id": .array([.string("web:ad")])]) { $1 }, policy: Self.policy(["material_tainted": .string("deny")])).outcome, "deny")
        XCTAssertEqual(prov(clean.merging(["action.params.offer_id": .array([.string("web:ad")])]) { $1 }, policy: Self.policy(["material_tainted": .string("question_typed")])).friction, "typed")
        XCTAssertEqual(prov(clean.merging(["action.params.payment_ref": .array([.string("tool:fx")])]) { $1 }, policy: Self.policy(["critical_tainted": .string("question")])).friction, "tap")
        XCTAssertEqual(prov(clean.merging(["action.params.payment_ref": .array([.string("tool:fx")])]) { $1 }, policy: Self.policy(["critical_tainted": .string("deny")])).outcome, "deny")
        XCTAssertEqual(prov(clean.merging(["action.params.payment_ref": .array([.string("tool:fx")])]) { $1 }, policy: Self.policy(["critical_max": .string("first_party")])).outcome, "deny")
        XCTAssertEqual(prov(clean, policy: Self.policy(["critical_max": .string("trusted")])).outcome, "pass", "critical_max inclusive")
        XCTAssertEqual(prov(clean.merging(["action.params.payment_ref": .array([.string("skyair:offer:1")])]) { $1 }, policy: Self.policy(["critical_max": .string("trusted")])).outcome, "deny")
        // unknown and prototype-named refs are agent; free parameters are not classified unless declared in prov
        for r in ["nope", "__proto__", "constructor", "toString"] {
            let d = prov(clean.merging(["action.params.offer_id": .array([.string(r)])]) { $1 })
            XCTAssertEqual(d.labels["action.params.offer_id"], "agent", r)
        }
        let declaredFree = prov(clean.merging(["action.params.note": .array([.string("web:ad")])]) { $1 })
        XCTAssertEqual(declaredFree.outcome, "pass", "a free parameter is labelled but never questioned"); XCTAssertEqual(declaredFree.labels["action.params.note"], "web")
        // a policy parameter prov does not declare gets agent
        let undeclared = prov(["action.params.payment_ref": .array([.string("wallet:ana")])])
        XCTAssertEqual(undeclared.labels["action.params.offer_id"], "agent"); XCTAssertEqual(undeclared.outcome, "question")
        XCTAssertEqual(prov(["action.params.payment_ref": .array([.string("wallet:ana")])], params: .object(["payment_ref": .string("x")])).labels["action.params.offer_id"], nil)
        XCTAssertEqual(prov(clean.merging(["action.params.total": .array([.string("wallet:ana")])]) { $1 }).outcome, "deny", "prov names a parameter the action does not carry")
        // policy and wire refusals
        XCTAssertEqual(prov(clean, policy: Self.policy(["critical_tainted": .string("allow")])).outcome, "deny")
        XCTAssertEqual(prov(clean, policy: Self.policy(["params": .object(["action.params.offer_id": .string("free")])])).outcome, "deny")
        XCTAssertEqual(prov(clean, policy: Self.policy(["registry": .object(["x": .string("toString")])])).outcome, "deny")
        XCTAssertEqual(prov(clean, committed: (0..<16).map { F.digest("l\($0)") }).outcome, "pass")
        XCTAssertEqual(prov(clean, committed: (0..<17).map { F.digest("l\($0)") }).outcome, "deny")
        XCTAssertEqual(prov(["action.params.constructor": .array([.string("x")])], params: .object(["constructor": .string("x")])).outcome, "deny")
        XCTAssertEqual(prov(["action.params.offer_id": .array((0..<9).map { .string("r\($0)") })]).outcome, "deny")
    }

    func testLabelReceiptsAndFlows() {
        let rc = Self.receipt(fields: ["offer.id": Self.field("commerce.offer", .string("OF-1"))])
        let ref = F.ref(IntentWB.LABELS_REF_DOMAIN, "l", rc)
        let pay: JObject = ["action.params.payment_ref": .array([.string("wallet:ana")])]
        func p(_ r: String, labels: [JSONValue] = [rc], policy: JSONValue = IntentWBKillTests.policy(), committed: [String]? = nil) -> IntentWB.ProvenanceDecision {
            prov(pay.merging(["action.params.offer_id": .array([.string(r)])]) { $1 }, policy: policy, labels: labels, committed: committed)
        }
        let ok = p("pca-labels:\(ref)#offer.id")
        XCTAssertEqual(ok.outcome, "pass"); XCTAssertEqual(ok.labels["action.params.offer_id"], "first_party"); XCTAssertEqual(ok.classes, ["action.params.offer_id": ["commerce.offer"]])
        let mism = Self.receipt(fields: ["offer.id": Self.field("commerce.offer", .string("OF-2"))])
        XCTAssertEqual(p("pca-labels:\(F.ref(IntentWB.LABELS_REF_DOMAIN, "l", mism))#offer.id", labels: [mism]).labels["action.params.offer_id"], "agent")
        XCTAssertEqual(p("pca-labels:\(ref)#offer.id#x").outcome, "deny", "split at the FIRST #")
        XCTAssertEqual(p("pca-labels:\(ref)#nope").outcome, "deny")
        XCTAssertEqual(p("pca-labels:\(ref)#").outcome, "deny")
        XCTAssertEqual(p("pca-labels:\(ref)").outcome, "deny")
        XCTAssertEqual(p("pca-labels:xyz#offer.id").outcome, "deny")
        XCTAssertEqual(p("pca-labels:\(ref)#offer.id", committed: []).outcome, "deny")
        XCTAssertEqual(p("pca-labels:\(ref)#offer.id", labels: [], committed: [ref]).outcome, "deny")
        let otherSession = Self.receipt(session: F.digest("s2"), fields: ["offer.id": Self.field("commerce.offer", .string("OF-1"))])
        XCTAssertEqual(p("pca-labels:\(F.ref(IntentWB.LABELS_REF_DOMAIN, "l", otherSession))#offer.id", labels: [otherSession]).outcome, "deny")
        let unpinned = Self.receipt(kid: "k9", fields: ["offer.id": Self.field("commerce.offer", .string("OF-1"))])
        XCTAssertEqual(p("pca-labels:\(F.ref(IntentWB.LABELS_REF_DOMAIN, "l", unpinned))#offer.id", labels: [unpinned]).outcome, "deny")
        // a foreign site: tool, and its class must be allowed to flow to aud
        let gov = Self.receipt(site: "gov.example", kid: "g1", by: Self.govKey, fields: ["id": Self.field("pii.contact", .string("OF-1"))])
        let gref = "pca-labels:\(F.ref(IntentWB.LABELS_REF_DOMAIN, "l", gov))#id"
        XCTAssertEqual(p(gref, labels: [gov]).outcome, "deny", "no flow rule")
        let allowed = p(gref, labels: [gov], policy: Self.policy(["flows": .object(["pii.*": .array([.string(F.AUD)])])]))
        XCTAssertEqual(allowed.outcome, "question"); XCTAssertEqual(allowed.labels["action.params.offer_id"], "tool")
        XCTAssertEqual(p(gref, labels: [gov], policy: Self.policy(["flows": .object(["*": .array([.string(F.AUD)])])])).outcome, "question")
        XCTAssertEqual(p(gref, labels: [gov], policy: Self.policy(["flows": .object(["pii.*": .array([.string("x")]), "*": .array([.string(F.AUD)])])])).outcome, "deny", "most specific pattern wins")
        XCTAssertEqual(p(gref, labels: [gov], policy: Self.policy(["flows": .object(["pii.contact": .array([.string(F.AUD)]), "pii.*": .array([])])])).outcome, "question")
        XCTAssertEqual(p(gref, labels: [gov], policy: Self.policy(["flows": .object(["pi.*": .array([.string(F.AUD)])])])).outcome, "deny", "the dot is kept: pi.* never matches pii")
        let pub = Self.receipt(site: "gov.example", kid: "g1", by: Self.govKey, fields: ["id": Self.field("public", .string("OF-1"))])
        XCTAssertEqual(p("pca-labels:\(F.ref(IntentWB.LABELS_REF_DOMAIN, "l", pub))#id", labels: [pub]).outcome, "question", "public flows anywhere")
        XCTAssertFalse(IntentWB.flowAllowed([:], "x", "a", "b"))
        XCTAssertTrue(IntentWB.flowAllowed([:], "x", "a", "a"))
        XCTAssertFalse(IntentWB.validateFlowRules(.object(["Bad": .array([])])))
        XCTAssertTrue(IntentWB.validateFlowRules(.object(["a.b.*": .array([.string("x")]), "*": .array([])])))
        XCTAssertFalse(IntentWB.validateLabelsWire(Self.receipt(fields: [:])))
        XCTAssertTrue(IntentWB.validateLabelsWire(Self.receipt(fields: Dictionary(uniqueKeysWithValues: (0..<64).map { (JKey("f\($0)"), Self.field("a", .int(1))) }))))
        XCTAssertFalse(IntentWB.validateLabelsWire(Self.receipt(fields: Dictionary(uniqueKeysWithValues: (0..<65).map { (JKey("f\($0)"), Self.field("a", .int(1))) }))))
        XCTAssertFalse(IntentWB.validateLabelsWire(Self.receipt(fields: ["f": Self.field("A", .int(1))])))
        XCTAssertFalse(IntentWB.validateLabelsWire(Self.receipt(fields: ["f": Self.field("a.", .int(1))])))
    }

    // ---- rule 18 ----------------------------------------------------------------------------------------------------

    static let j1 = F.key("j1"), j2 = F.key("j2"), j3 = F.key("j3")
    static let BODY: JSONValue = .string("We are sorry for the delay.")
    static func verdict(_ judge: V2F.K, _ label: String, content: JSONValue = BODY, session: String = F.SESSION, measurement: String = "m1", classifier: String = "tone") -> JSONValue {
        F.signArtifact(IntentWB.CLASSIFIER_DOMAIN, ["v": .int(1), "kind": .string("pca-intent-classification"), "classifier": .string(classifier), "session": .string(session),
                                                    "content_digest": .string(F.hash(content)), "label": .string(label), "measurement": .string(measurement),
                                                    "judge": .string(F.pub(judge))], judge)
    }
    static func clsPolicy(k: Int64 = 2, labels: [String] = ["neutral", "apologetic", "hostile", "other"], measurements: [String]? = ["m1"]) -> JSONValue {
        var c: JObject = ["id": .string("tone"), "param": .string("action.params.body"), "labels": .array(labels.map { .string($0) }),
                          "keys": .array([j1, j2, j3].map { .string(F.pub($0)) }), "k": .int(k)]
        if let m = measurements { c["measurements"] = .array(m.map { .string($0) }) }
        return .object(["classifiers": .array([.object(c)])])
    }
    func cls(_ vs: [JSONValue], policy: JSONValue = IntentWBKillTests.clsPolicy(), committed: [String]? = nil, supplied: [JSONValue]? = nil) -> (ok: Bool, classes: JObject, reason: String) {
        IntentWB.decideClassifiers(session: F.SESSION, params: .object(["body": Self.BODY]),
                                   committed: .array((committed ?? vs.map { F.ref(IntentWB.CLASSIFIER_REF_DOMAIN, "c", $0) }).map { .string($0) }),
                                   verdicts: .array(supplied ?? vs), policy: policy)
    }

    func testClassifierQuorum() {
        let q = cls([Self.verdict(Self.j1, "apologetic"), Self.verdict(Self.j2, "apologetic"), Self.verdict(Self.j3, "neutral")])
        XCTAssertTrue(q.ok, q.reason); XCTAssertEqual(q.classes, ["tone": .string("apologetic")])
        XCTAssertFalse(cls([Self.verdict(Self.j1, "apologetic")]).ok, "below the quorum")
        XCTAssertTrue(cls([Self.verdict(Self.j1, "apologetic")], policy: Self.clsPolicy(k: 1)).ok)
        XCTAssertFalse(cls([Self.verdict(Self.j1, "apologetic"), Self.verdict(Self.j2, "neutral")], policy: Self.clsPolicy(k: 1)).ok, "ambiguous")
        XCTAssertTrue(cls([Self.verdict(Self.j1, "a"), Self.verdict(Self.j2, "a"), Self.verdict(Self.j3, "a")], policy: Self.clsPolicy(k: 3, labels: ["a"])).ok)
        // labels named like Object.prototype members are ordinary keys of the tally
        for l in ["toString", "constructor", "__proto__", "valueOf", "hasOwnProperty"] {
            let r = cls([Self.verdict(Self.j1, l), Self.verdict(Self.j2, l)], policy: Self.clsPolicy(labels: [l, "x"]))
            XCTAssertTrue(r.ok, l); XCTAssertEqual(r.classes["tone"], .string(l), l)
        }
        XCTAssertFalse(cls([Self.verdict(Self.j1, "apologetic"), Self.verdict(Self.j1, "neutral")], policy: Self.clsPolicy(k: 1)).ok, "two verdicts from one judge")
        XCTAssertFalse(cls([Self.verdict(F.stranger, "apologetic"), Self.verdict(Self.j2, "apologetic")]).ok, "judge not allowlisted")
        XCTAssertFalse(cls([Self.verdict(Self.j1, "apologetic", session: F.digest("s2")), Self.verdict(Self.j2, "apologetic")]).ok)
        XCTAssertFalse(cls([Self.verdict(Self.j1, "apologetic", content: .string("other")), Self.verdict(Self.j2, "apologetic")]).ok)
        XCTAssertFalse(cls([Self.verdict(Self.j1, "rude"), Self.verdict(Self.j2, "apologetic")]).ok)
        XCTAssertFalse(cls([Self.verdict(Self.j1, "apologetic", measurement: "m2"), Self.verdict(Self.j2, "apologetic")]).ok)
        XCTAssertTrue(cls([Self.verdict(Self.j1, "apologetic", measurement: "m2"), Self.verdict(Self.j2, "apologetic")], policy: Self.clsPolicy(measurements: nil)).ok)
        XCTAssertFalse(cls([Self.verdict(Self.j1, "apologetic", classifier: "mood"), Self.verdict(Self.j2, "apologetic")]).ok)
        var forged = Self.verdict(Self.j1, "apologetic").asObject!
        forged["label"] = .string("neutral")
        XCTAssertFalse(cls([.object(forged), Self.verdict(Self.j2, "neutral")]).ok)
        // uncommitted verdicts are ignored; committed ones must be supplied
        let a = Self.verdict(Self.j1, "apologetic"), b = Self.verdict(Self.j2, "apologetic")
        XCTAssertTrue(cls([a, b], supplied: [a, b, Self.verdict(Self.j3, "neutral"), .int(1)]).ok)
        XCTAssertFalse(cls([a, b], supplied: [a]).ok)
        XCTAssertTrue(cls([a, b], committed: (0..<9).map { F.digest("v\($0)") }).reason.contains("at most 8"))
        XCTAssertTrue(cls([a, b], committed: (0..<8).map { F.digest("v\($0)") }).reason.contains("not supplied"))
        // policy sanity
        XCTAssertFalse(cls([a, b], policy: Self.clsPolicy(k: 0)).ok)
        XCTAssertFalse(cls([a, b], policy: Self.clsPolicy(k: 4)).ok)
        // 32 labels is well formed; the two verdicts' label must be in the set (checked before the quorum, like the reference)
        XCTAssertTrue(cls([a, b], policy: Self.clsPolicy(k: 3, labels: (0..<31).map { "l\($0)" } + ["apologetic"])).reason.contains("quorum"))
        XCTAssertTrue(cls([a, b], policy: Self.clsPolicy(labels: (0..<33).map { "l\($0)" })).reason.contains("misconfigured"))
        XCTAssertTrue(cls([a, b], policy: Self.clsPolicy(labels: ["a", "a"])).reason.contains("misconfigured"))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(.object(["classifiers": .array([Self.clsPolicy().get("classifiers")!.asArray![0], Self.clsPolicy().get("classifiers")!.asArray![0]])])))
        XCTAssertTrue(IntentWB.classifierActive(committed: nil, classifiers: Self.clsPolicy().get("classifiers")))
        XCTAssertFalse(IntentWB.classifierActive(committed: .array([]), classifiers: .array([])))
    }

    // ---- the W-B unit in the pipeline -------------------------------------------------------------------------------

    func testPipelineUnit() {
        let fs = [F.fact(value: .int(39_800), oracle: "o1", by: Self.o1), F.fact(value: .int(39_900), oracle: "o2", by: Self.o2), F.fact(value: .int(39_700), oracle: "o3", by: Self.o3)]
        let refs = Self.refs(fs)
        let p = F.build(F.G0, is: F.is0(["facts": refs]))
        let worldPolicy: JSONValue = .object(["worlds": .array([Self.world()])])
        func ctx(_ wbPolicy: JObject, artifacts: JObject = ["facts": .array(fs)]) -> JSONValue {
            F.ctx(["wb": .object(["artifacts": .object(artifacts), "policy": .object(wbPolicy)])])
        }
        let base = ["schema", "intent_session", "accumulators"]
        let ok = F.verify(p, F.G0, ctx(["world": worldPolicy]))
        XCTAssertTrue(ok.allow, ok.reason)
        XCTAssertEqual(ok.checks["facts"], true); XCTAssertNil(ok.checks["provenance"]); XCTAssertNil(ok.checks["classes"])
        let env = PCA.intentV2Env(pcactn: p, grant: F.G0, now: F.NOW, context: IntentV2Context(ctx(["world": worldPolicy])))
        XCTAssertEqual(env?.world?["fare"], .int(39_800))
        // a committed fact but no policy world: facts fails (undeclared world), the unit ends
        let provPolicy: JSONValue = .object(["params": .object(["action.params.offer_id": .string("material")])])
        let v1 = F.verify(p, F.G0, ctx(["provenance": provPolicy, "classifiers": Self.clsPolicy().get("classifiers")!]))
        XCTAssertEqual(v1.checks["facts"], false); XCTAssertNil(v1.checks["provenance"]); XCTAssertNil(v1.checks["classes"])
        // a provenance question: provenance fails with intent_required, the unit continues to classes
        let plain = F.build(F.G0, is: F.is0())
        let q = F.verify(plain, F.G0, ctx(["provenance": provPolicy]))
        XCTAssertFalse(q.allow); XCTAssertEqual(q.checks["provenance"], false); XCTAssertNil(q.checks["facts"]); XCTAssertNil(q.checks["classes"])
        XCTAssertTrue(q.reason.contains("intent_required"), q.reason)
        for c in base { XCTAssertEqual(q.checks[c], true, c) }
        let qc = F.verify(plain, F.G0, ctx(["provenance": provPolicy, "classifiers": Self.clsPolicy().get("classifiers")!]))
        XCTAssertEqual(qc.checks["provenance"], false); XCTAssertEqual(qc.checks["classes"], false, "the classifier policy is active and has no verdicts")
        // a provenance deny ends the unit
        let deny: JSONValue = .object(["params": .object(["action.params.offer_id": .string("material")]), "material_tainted": .string("deny")])
        let d = F.verify(plain, F.G0, ctx(["provenance": deny, "classifiers": Self.clsPolicy().get("classifiers")!]))
        XCTAssertEqual(d.checks["provenance"], false); XCTAssertNil(d.checks["classes"])
        // provenance passes with a trusted registry ref, and env.prov lands
        let pp = F.build(F.G0, is: F.is0(["prov": .object(["action.params.offer_id": .array([.string("skyair:offer:1")])])]))
        let passPolicy: JSONValue = .object(["params": .object(["action.params.offer_id": .string("material")]), "registry": .object(["skyair:offer:1": .string("first_party")])])
        let pv = F.verify(pp, F.G0, ctx(["provenance": passPolicy]))
        XCTAssertTrue(pv.allow, pv.reason); XCTAssertEqual(pv.checks["provenance"], true)
        // the member alone activates provenance (default policy {params: {}})
        let pm = F.verify(pp, F.G0, ctx([:]))
        XCTAssertEqual(pm.checks["provenance"], true, pm.reason)
        // nothing active: no W-B check is reported
        let none = F.verify(plain, F.G0, ctx([:], artifacts: [:]))
        XCTAssertTrue(none.allow); XCTAssertNil(none.checks["facts"]); XCTAssertNil(none.checks["provenance"]); XCTAssertNil(none.checks["classes"])
        XCTAssertEqual(Set(none.checks.keys).count, 13)
    }

    // ---- clock and activity -----------------------------------------------------------------------------------------

    func testClock() {
        let p: JObject = ["worlds": .array([Self.world()])]
        let fs = Self.facts([.int(1), .int(2), .int(3)])
        XCTAssertTrue(world(fs, policy: p).ok)
        for now: JSONValue in [.string("1800000000000"), .double(1_800_000_000_000.5), .null, .double(-0.0), .double(9_007_199_254_740_992)] {
            let input: JSONValue = .object(["now": now, "aud": .string(F.AUD), "session": .string(F.SESSION), "action": Self.ACTION,
                                            "committed": .object(["facts": Self.refs(fs)]), "facts": .array(fs), "policy": .object(p)])
            XCTAssertFalse(PCA.intentWorldPrimitive(input).ok, "\(now): no clock, every fact is stale")
            // a relational dimension needs no clock
            let rel: JSONValue = .object(["now": now, "aud": .string(F.AUD), "session": .string(F.SESSION), "action": Self.ACTION, "committed": .object([:]),
                                          "policy": .object(["relational": .array([.object(["name": .string("d"), "fn": .string("sub"), "a": .string("action.params.total"),
                                                                                            "b": .string("action.params.quote")])])])])
            let r = PCA.intentWorldPrimitive(rel)
            XCTAssertTrue(r.ok, "\(now)"); XCTAssertEqual(r.world, .object(["d": .int(38_900)]))
            let os = Self.offerSet()
            let oi: JSONValue = .object(["now": now, "aud": .string(F.AUD), "session": .string(F.SESSION),
                                         "action": .object(["verb": .string("v"), "resource": .string("r"), "params": .object(["offer_id": .string("OF-2")])]),
                                         "committed": .object(["offer_set": .string(F.ref(IntentWB.OFFER_SET_REF_DOMAIN, "o", os))]), "offer_set": os, "policy": .object(Self.offers())])
            XCTAssertFalse(PCA.intentWorldPrimitive(oi).ok, "\(now): an offer set without a clock is stale")
        }
    }

    func testActivityIsStrict() {
        func act(_ s: JObject, _ p: JObject = [:]) -> (Bool, Bool, Bool) {
            let r = PCA.intentWBActivePrimitive(.object(["intent_session": .object(s), "policy": .object(p)]))
            return (r.facts, r.provenance, r.classes)
        }
        let d: JSONValue = .string(F.digest("x"))
        XCTAssertTrue(act([:]) == (false, false, false))
        XCTAssertTrue(act(["facts": .array([d])]) == (true, false, false))
        XCTAssertTrue(act(["facts": .array([])]) == (false, false, false))
        XCTAssertTrue(act(["facts": .object(["0": d, "length": .int(1)])]) == (false, false, false))
        XCTAssertTrue(act(["offer_set": d]) == (true, false, false))
        XCTAssertTrue(act(["offer_set": .int(1)]) == (false, false, false))
        XCTAssertTrue(act([:], ["world": .object(["worlds": .array([.int(1)])])]) == (true, false, false))
        XCTAssertTrue(act([:], ["world": .object(["worlds": .string("abc")])]) == (false, false, false))
        XCTAssertTrue(act([:], ["world": .object(["relational": .object(["length": .int(2)])])]) == (false, false, false))
        XCTAssertTrue(act([:], ["world": .object(["offers": .object([:])])]) == (true, false, false))
        XCTAssertTrue(act([:], ["world": .object(["offers": .array([])])]) == (false, false, false))
        XCTAssertTrue(act(["prov": .null]) == (false, true, false))
        XCTAssertTrue(act(["labels": .array([d])]) == (false, true, false))
        XCTAssertTrue(act(["labels": .array([])]) == (false, false, false))
        XCTAssertTrue(act([:], ["provenance": .object([:])]) == (false, true, false))
        XCTAssertTrue(act([:], ["provenance": .array([])]) == (false, false, false))
        XCTAssertTrue(act([:], ["provenance": .null]) == (false, false, false))
        XCTAssertTrue(act(["classes": .array([d])]) == (false, false, true))
        XCTAssertTrue(act([:], ["classifiers": .array([.object([:])])]) == (false, false, true))
        XCTAssertTrue(act([:], ["classifiers": .object(["length": .int(1)])]) == (false, false, false))
    }

    func testPrototypeNamesAreOrdinaryKeys() {
        let names = ["constructor", "valueof", "tostring", "hasownproperty"]
        let ws = names.map { Self.world(min: 1, faulty: 0, oracles: [Self.oracle("o1", Self.o1)], name: $0) }
        let fs = names.map { F.fact(name: $0, value: .int(7), oracle: "o1", by: Self.o1) }
        let r = world(fs, policy: ["worlds": .array(ws)])
        XCTAssertTrue(r.ok, r.reason)
        for n in names { XCTAssertEqual(r.world[JKey(n)], .int(7), n) }
        let rel = world([], policy: ["relational": .array([.object(["name": .string("x"), "fn": .string("sub"), "a": .string("env.world.constructor"), "b": .string("action.params.total")])])])
        XCTAssertFalse(rel.ok, "an undeclared world named like a prototype member resolves nothing")
    }

    func testNullIsMalformedAbsentIsDefault() {
        let action = Self.ACTION
        func worldIn(_ over: JObject) -> Bool {
            var i: JObject = ["now": .int(F.NOW), "aud": .string(F.AUD), "session": .string(F.SESSION), "action": action, "policy": .object([:])]
            for (k, v) in over { i[k] = v }
            return PCA.intentWorldPrimitive(.object(i)).ok
        }
        XCTAssertTrue(worldIn([:]))
        XCTAssertFalse(worldIn(["committed": .null]))
        XCTAssertTrue(worldIn(["committed": .object([:])]))
        XCTAssertFalse(worldIn(["committed": .object(["facts": .null])]))
        XCTAssertFalse(worldIn(["committed": .object(["offer_set": .null])]))
        XCTAssertFalse(worldIn(["facts": .null]))
        XCTAssertTrue(worldIn(["facts": .array([])]))
        XCTAssertFalse(worldIn(["policy": .null]))
        XCTAssertTrue(worldIn(["policy": .object(["worlds": .array([])])]))
        for k in ["worlds", "relational", "skew_ms", "offers"] { XCTAssertFalse(worldIn(["policy": .object([JKey(k): .null])]), k) }
        XCTAssertFalse(worldIn(["action": F.with(action, ["params": .null])]))
        func provIn(_ over: JObject) -> String {
            var i: JObject = ["aud": .string(F.AUD), "session": .string(F.SESSION), "action": .object(["params": .object(["a": .int(1)])]),
                              "policy": .object(["params": .object([:])])]
            for (k, v) in over { i[k] = v }
            return PCA.intentProvenancePrimitive(.object(i)).outcome
        }
        XCTAssertEqual(provIn([:]), "pass")
        for k in ["prov", "committed_labels", "labels"] { XCTAssertEqual(provIn([JKey(k): .null]), "deny", k) }
        XCTAssertEqual(provIn(["prov": .object([:]), "committed_labels": .array([]), "labels": .array([])]), "pass")
        XCTAssertEqual(provIn(["action": .object(["params": .null])]), "deny")
        XCTAssertEqual(provIn(["action": .object([:])]), "pass")
        for k in ["registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"] {
            XCTAssertEqual(provIn(["policy": .object(["params": .object([:]), JKey(k): .null])]), "deny", k)
        }
        XCTAssertEqual(provIn(["policy": .null]), "deny")
        func clsIn(_ over: JObject) -> Bool {
            var i: JObject = ["session": .string(F.SESSION), "action": .object(["params": .object([:])]), "policy": .object(["classifiers": .array([])])]
            for (k, v) in over { i[k] = v }
            return PCA.intentClassifierPrimitive(.object(i)).ok
        }
        XCTAssertTrue(clsIn([:]))
        XCTAssertFalse(clsIn(["committed": .null]))
        XCTAssertFalse(clsIn(["verdicts": .null]))
        XCTAssertTrue(clsIn(["committed": .array([]), "verdicts": .array([])]))
        XCTAssertFalse(clsIn(["action": .object(["params": .null])]))
        XCTAssertFalse(clsIn(["policy": .object(["classifiers": .null])]))
        XCTAssertFalse(clsIn(["action": .null]))
        XCTAssertFalse(worldIn(["action": .null]))
        XCTAssertEqual(provIn(["action": .null]), "deny")
        XCTAssertFalse(cls([], policy: Self.clsPolicy(measurements: nil).asObject.map { p in
            .object(["classifiers": .array([F.with(p["classifiers"]!.asArray![0], ["measurements": .null])])])
        }!).ok)
    }

    // ---- W-B suite agility: optional alg / pq_pk / pq_sig, unsupported_suite first, PQ only under trusted-side pins --------

    static func suited(_ a: JSONValue, _ domain: String, by k: V2F.K, _ suite: JObject) -> JSONValue {
        var b = F.without(a, ["sig", "pq_sig"]).asObject!
        for (kk, v) in suite { b[kk] = v }
        return F.signArtifact(domain, b, k)
    }

    func testWBSuiteAgility() {
        let p: JObject = ["worlds": .array([Self.world()])]
        let fs = Self.facts([.int(1), .int(2), .int(3)])
        func with0(_ f: JSONValue) -> [JSONValue] { [f] + fs.dropFirst() }
        // an explicit ed25519 is signed into the body and verifies; it may not carry PQ members
        XCTAssertTrue(world(with0(Self.suited(fs[0], IntentWB.FACT_DOMAIN, by: Self.o1, ["alg": .string("ed25519")])), policy: p).ok)
        XCTAssertFalse(world(with0(Self.suited(fs[0], IntentWB.FACT_DOMAIN, by: Self.o1, ["alg": .string("ed25519"), "pq_pk": .string("AA")])), policy: p).ok)
        XCTAssertFalse(world(with0(Self.suited(fs[0], IntentWB.FACT_DOMAIN, by: Self.o1, ["pq_sig": .string("AA")])), policy: p).ok)
        // unsupported first: even an unpinned oracle reports the suite
        let unk = Self.suited(F.fact(value: .int(1), oracle: "o9", by: Self.o1), IntentWB.FACT_DOMAIN, by: Self.o1, ["alg": .string("no-such-suite"), "pq_pk": .string("AA")])
        let r = world([unk] + fs.dropFirst(), policy: p)
        XCTAssertFalse(r.ok); XCTAssertTrue(r.reason.contains("unsupported_suite"), r.reason)
        let nonString = world(with0(Self.suited(fs[0], IntentWB.FACT_DOMAIN, by: Self.o1, ["alg": .int(1)])), policy: p)
        XCTAssertFalse(nonString.ok); XCTAssertFalse(nonString.reason.contains("unsupported_suite"), nonString.reason)
        XCTAssertFalse(world(with0(Self.suited(fs[0], IntentWB.FACT_DOMAIN, by: Self.o1, ["alg": .string("ml-dsa-65"), "pq_pk": .int(1)])), policy: p).ok)
        // a PQ suite never verifies without the oracle's pinned pq_pk
        XCTAssertFalse(world(with0(Self.suited(fs[0], IntentWB.FACT_DOMAIN, by: Self.o1, ["alg": .string("ml-dsa-65"), "pq_pk": .string("AAAA")])), policy: p).ok)
        // pins: an optional non-empty string pq_pk
        XCTAssertNotNil(IntentWB.validateWorldPolicy(.object(["worlds": .array([Self.world(oracles: [F.with(Self.oracle("o1", Self.o1), ["pq_pk": .null]),
                                                                                                        Self.oracle("o2", Self.o2), Self.oracle("o3", Self.o3)])])])))
        XCTAssertNotNil(IntentWB.validateWorldPolicy(.object(["worlds": .array([Self.world(oracles: [F.with(Self.oracle("o1", Self.o1), ["pq_pk": .string("")]),
                                                                                                        Self.oracle("o2", Self.o2), Self.oracle("o3", Self.o3)])])])))
        XCTAssertNil(IntentWB.validateWorldPolicy(.object(["worlds": .array([Self.world(oracles: [F.with(Self.oracle("o1", Self.o1), ["pq_pk": .string("AAAA")]),
                                                                                                     Self.oracle("o2", Self.o2), Self.oracle("o3", Self.o3)])])])))
        // offer set
        let os = Self.suited(Self.offerSet(), IntentWB.OFFER_SET_DOMAIN, by: Self.siteKey, ["alg": .string("no-such-suite"), "pq_pk": .string("AA")])
        let ro = offer(os)
        XCTAssertFalse(ro.ok); XCTAssertTrue(ro.reason.contains("unsupported_suite"), ro.reason)
        XCTAssertTrue(offer(Self.suited(Self.offerSet(), IntentWB.OFFER_SET_DOMAIN, by: Self.siteKey, ["alg": .string("ed25519")])).ok)
        XCTAssertFalse(offer(Self.offerSet(), policy: Self.offers(["site_keys": .array([.object(["kid": .string("s1"), "pk": .string(F.pub(Self.siteKey)), "pq_pk": .null])])])).ok)
        // label receipts
        let rc = Self.suited(Self.receipt(fields: ["offer.id": Self.field("commerce.offer", .string("OF-1"))]), IntentWB.LABELS_DOMAIN, by: Self.labelKey,
                             ["alg": .string("no-such-suite"), "pq_pk": .string("AA")])
        let ref = F.ref(IntentWB.LABELS_REF_DOMAIN, "l", rc)
        let d = prov(["action.params.offer_id": .array([.string("pca-labels:\(ref)#offer.id")])], labels: [rc])
        XCTAssertEqual(d.outcome, "deny"); XCTAssertTrue(d.reason.contains("unsupported_suite"), d.reason)
        XCTAssertEqual(prov([:], policy: Self.policy(["label_keys": .array([.object(["site": .string(F.AUD), "kid": .string("k1"), "pk": .string(F.pub(Self.labelKey)),
                                                                                       "pq_pk": .null])])])).outcome, "deny")
        // classifier verdicts and the pq_keys pins
        let a = Self.suited(Self.verdict(Self.j1, "apologetic"), IntentWB.CLASSIFIER_DOMAIN, by: Self.j1, ["alg": .string("no-such-suite"), "pq_pk": .string("AA")])
        let rcl = cls([a, Self.verdict(Self.j2, "apologetic")])
        XCTAssertFalse(rcl.ok); XCTAssertTrue(rcl.reason.contains("unsupported_suite"), rcl.reason)
        func withPq(_ m: JSONValue) -> JSONValue {
            let c = Self.clsPolicy().get("classifiers")!.asArray![0]
            return .object(["classifiers": .array([F.with(c, ["pq_keys": m])])])
        }
        let two = [Self.verdict(Self.j1, "apologetic"), Self.verdict(Self.j2, "apologetic")]
        XCTAssertTrue(cls(two, policy: withPq(.object([JKey(F.pub(Self.j1)): .string("AAAA")]))).ok, "an ed25519 verdict ignores a PQ pin")
        XCTAssertFalse(cls(two, policy: withPq(.object([JKey(F.pub(F.stranger)): .string("AAAA")]))).ok, "pq_keys names a key off the allowlist")
        XCTAssertFalse(cls(two, policy: withPq(.object([JKey(F.pub(Self.j1)): .null]))).ok)
        XCTAssertFalse(cls(two, policy: withPq(.null)).ok)
        XCTAssertFalse(cls([Self.suited(two[0], IntentWB.CLASSIFIER_DOMAIN, by: Self.j1, ["alg": .string("ml-dsa-65"), "pq_pk": .string("AAAA")]), two[1]],
                           policy: withPq(.object([JKey(F.pub(Self.j1)): .string("BBBB")]))).ok, "a PQ verdict needs pq_pk equal to the pin")
        // a non-object action / params
        for bad: JSONValue in [.string("x"), .array([])] {
            XCTAssertFalse(PCA.intentWorldPrimitive(.object(["now": .int(F.NOW), "aud": .string(F.AUD), "session": .string(F.SESSION), "action": .object(["params": bad]),
                                                             "policy": .object([:])])).ok)
            XCTAssertEqual(PCA.intentProvenancePrimitive(.object(["aud": .string(F.AUD), "session": .string(F.SESSION), "action": .object(["params": bad]),
                                                                  "policy": .object(["params": .object([:])])])).outcome, "deny")
        }
    }

    // ---- closed and typed policies; read purpose ---------------------------------------------------------------------

    func testClosedPolicies() {
        func wbad(_ p: JObject) -> Bool { IntentWB.validateWorldPolicy(.object(p)) != nil }
        XCTAssertTrue(wbad(["extra": .int(1)]))
        XCTAssertTrue(wbad(["worlds": .array([F.with(Self.world(), ["note": .string("x")])])]))
        XCTAssertTrue(wbad(["worlds": .array([F.without(Self.world(), ["max_faulty"])])]))
        XCTAssertTrue(wbad(["worlds": .array([Self.world(oracles: [F.with(Self.oracle("o1", Self.o1), ["x": .int(1)]), Self.oracle("o2", Self.o2), Self.oracle("o3", Self.o3)])])]))
        XCTAssertTrue(wbad(["relational": .array([.object(["name": .string("d"), "fn": .string("sub"), "a": .string("action.params.a"), "b": .string("action.params.b"), "x": .int(1)])])]))
        XCTAssertFalse(wbad(["relational": .array([.object(["name": .string("d"), "fn": .string("sub"), "a": .string("action.params.a"), "b": .string("action.params.b")])])]))
        XCTAssertTrue(wbad(["skew_ms": .double(1.5)]))
        let off = Self.offers()["offers"]!
        XCTAssertNil(IntentWB.validateOfferPolicy(off))
        XCTAssertNotNil(IntentWB.validateOfferPolicy(F.with(off, ["x": .int(1)])))
        XCTAssertNotNil(IntentWB.validateOfferPolicy(F.with(off, ["site_keys": .array([.object(["kid": .string("s1"), "pk": .string(F.pub(Self.siteKey)), "x": .int(1)])])])))
        XCTAssertNotNil(IntentWB.validateOfferPolicy(F.with(off, ["filter": .object(["query": .object([:]), "offer": .object([:]), "x": .object([:])])])))
        XCTAssertNotNil(IntentWB.validateOfferPolicy(F.without(off, ["max_age_ms"])))
        XCTAssertTrue(IntentWB.validateProvenancePolicy(Self.policy()))
        XCTAssertFalse(IntentWB.validateProvenancePolicy(F.with(Self.policy(), ["x": .int(1)])))
        XCTAssertFalse(IntentWB.validateProvenancePolicy(F.with(Self.policy(), ["label_keys": .array([.object(["site": .string("s"), "kid": .string("k"),
                                                                                                            "pk": .string(F.pub(Self.labelKey)), "x": .int(1)])])])))
        XCTAssertFalse(IntentWB.validateProvenancePolicy(F.with(Self.policy(), ["material_tainted": .int(1)])), "an enum must be its string")
        XCTAssertTrue(IntentWB.validateClassifierPolicy(Self.clsPolicy()))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(F.with(Self.clsPolicy(), ["x": .int(1)])))
        let c0 = Self.clsPolicy().get("classifiers")!.asArray![0]
        XCTAssertFalse(IntentWB.validateClassifierPolicy(.object(["classifiers": .array([F.with(c0, ["note": .string("x")])])])))
        XCTAssertFalse(IntentWB.validateClassifierPolicy(.object(["classifiers": .array([F.without(c0, ["k"])])])))
    }

    func testReadPurpose() {
        let fields: JSONValue = .array([
            .object(["path": .string("passengers[].name"), "class": .string("pii.identity")]),
            .object(["path": .string("passengers[].email"), "class": .string("pii.contact"), "optional": .bool(true)]),
            .object(["path": .string("loyalty"), "class": .string("internal"), "optional": .bool(true)]),
            .object(["path": .string("fares"), "class": .string("public")]),
        ])
        let cov: JSONValue = .object(["booking": .array([.string("pii.identity")]), "support": .array([.string("pii.*"), .string("internal")]), "none": .array([])])
        func rp(_ purpose: String, _ over: JObject = [:]) -> (String, [String], [String]) {
            var i: JObject = ["fields": fields, "purpose": .string(purpose), "coverage": cov]
            for (k, v) in over { i[k] = v }
            let r = PCA.intentReadPurposePrimitive(.object(i))
            return (r.outcome, r.minimise, r.uncovered)
        }
        XCTAssertTrue(rp("booking") == ("allow", ["loyalty", "passengers[].email"], []))
        XCTAssertTrue(rp("support") == ("allow", [], []))
        XCTAssertTrue(rp("none") == ("question", ["loyalty", "passengers[].email"], ["passengers[].name"]))
        XCTAssertTrue(rp("none", ["on_uncovered": .string("deny")]).0 == "deny")
        XCTAssertTrue(rp("unknown").0 == "question", "an unknown purpose covers only public")
        XCTAssertTrue(rp("constructor").0 == "question", "coverage is read as an own member")
        for bad: JObject in [["on_uncovered": .null], ["on_uncovered": .string("allow")], ["fields": .null], ["purpose": .null], ["coverage": .null],
                             ["coverage": .object(["booking": .null])], ["coverage": .object(["booking": .array([.int(1)])])],
                             ["fields": .array([.object(["path": .string("x"), "class": .string("c"), "optional": .null])])],
                             ["fields": .array([.object(["path": .string("x")])])]] {
            XCTAssertTrue(rp("booking", bad) == ("deny", [], []), "\(bad)")
        }
        // UTF-8 byte order and de-duplication
        let odd: JSONValue = .array(["\u{1F600}", "\u{FFFD}", "z\u{e9}", "a", "a"].map { JSONValue.object(["path": .string($0), "class": .string("secret")]) })
        XCTAssertEqual(PCA.intentReadPurposePrimitive(.object(["fields": odd, "purpose": .string("p"), "coverage": .object(["p": .array([])])])).uncovered,
                       ["a", "z\u{e9}", "\u{FFFD}", "\u{1F600}"])
    }
}
