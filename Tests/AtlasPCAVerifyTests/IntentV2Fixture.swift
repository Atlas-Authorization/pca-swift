import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Natively built, signed Intent Layer v2 fixtures (the shapes of `packages/pca/scripts/gen-conformance-intent-v2.mjs` and
/// `gen-conformance-intent-wb.mjs`): a site-signed action schema, principal-signed session roots and session grants
/// (G_0 / D_k), signed PCActns carrying `intent` + `intent_session`, sequencer receipts and root-signed key sets,
/// revocation epochs over a sorted Merkle set, and the W-B artifacts (facts, offer sets, label receipts, verdicts).
enum V2F {
    typealias K = Curve25519.Signing.PrivateKey
    static let NOW: Int64 = 1_800_000_000_000
    static let AUD = "skyair.example"

    static func key(_ label: String) -> K { IntentTests.key("v2/" + label) }
    static func pub(_ k: K) -> String { IntentTests.pub(k) }
    static func digest(_ s: String) -> String { IntentTests.digest("v2/" + s) }
    static func sign(_ k: K, _ msg: [UInt8]) -> String { Base64URLStrict.encode(Array(try! k.signature(for: Data(msg)))) }
    static func canon(_ v: JSONValue) -> [UInt8] { Canonical.utf8(try! Canonical.canonicalizeStrict(v)) }
    static func hash(_ v: JSONValue) -> String { IV.strictHash(v)! }

    static let principal = key("principal"), agent = key("agent"), site = key("site"), seqRoot = key("seq-root"), seqKey = key("seq-key"),
               stranger = key("stranger"), revAuthority = key("revocation-authority")
    static let REF = digest("ref"), MAP0 = digest("map0"), MAP1 = digest("map1"), SESSION = digest("session")

    // ---- schema ----

    static let UNSIGNED: JObject = [
        "v": .int(1), "kind": .string("pca-action-schema"), "site": .string("https://skyair.example"), "aud": .string(AUD), "version": .string("2026-10-01"),
        "units": .object(["usd_cents": .object(["kind": .string("money"), "currency": .string("USD"), "exponent": .int(2)])]),
        "verbs": .array([
            .object([
                "verb": .string("air.book"), "kind": .string("write"),
                "params": .object([
                    "action.params.offer_id": .object(["type": .string("string"), "semantic": .string("product.ref"), "sensitivity": .string("material")]),
                    "action.params.total": .object(["type": .string("integer"), "unit": .string("usd_cents"), "min": .int(0), "max": .int(5_000_000),
                                                    "semantic": .string("money.amount"), "sensitivity": .string("critical"),
                                                    "accumulates_into": .array([.string("spend.usd_cents")])]),
                    "action.params.add_ons": .object(["type": .string("set"), "values": .array([.string("none"), .string("tripshield"), .string("seat_plus")]),
                                                      "semantic": .string("product.addon"), "sensitivity": .string("material")]),
                    "action.params.refundable": .object(["type": .string("boolean"), "semantic": .string("flag"), "sensitivity": .string("material")]),
                    "action.params.passengers": .object(["type": .string("array"), "max_items": .int(9), "max_len": .int(64), "semantic": .string("person.identity"),
                                                         "sensitivity": .string("critical"), "required": .bool(false)]),
                    "action.params.note": .object(["type": .string("string"), "semantic": .string("text.note"), "sensitivity": .string("free"),
                                                   "required": .bool(false), "max_len": .int(16)]),
                ]),
            ]),
            .object([
                "verb": .string("air.search"), "kind": .string("read"), "reversibility": .string("reversible"),
                "params": .object([
                    "action.params.from": .object(["type": .string("string"), "values": .array([.string("SFO"), .string("JFK")]), "semantic": .string("place.airport"),
                                                   "sensitivity": .string("material")]),
                    "action.params.date": .object(["type": .string("date"), "semantic": .string("schedule.date"), "sensitivity": .string("material")]),
                    "action.params.pax": .object(["type": .string("integer"), "min": .int(1), "max": .int(9), "semantic": .string("quantity"), "sensitivity": .string("material")]),
                ]),
            ]),
        ]),
    ]
    static func signSchema(_ body: JObject, kid: String = "skyair-2026", by k: K = site) -> JSONValue {
        var d = body
        d["sig"] = nil
        let sig = sign(k, Canonical.utf8(ActionSchema.DOMAIN) + canon(.object(d)))
        d["sig"] = .object(["alg": .string("ed25519"), "kid": .string(kid), "value": .string(sig)])
        return .object(d)
    }
    static let SCHEMA = signSchema(UNSIGNED)
    static let KEYS: JSONValue = .array([.object(["kid": .string("skyair-2026"), "alg": .string("ed25519"), "pk": .string(pub(site))])])
    static let SD = ActionSchema.digest(SCHEMA)!

    // ---- session roots ----

    static let TRIP: JSONValue = .object([
        "id": .string("trip_spend"), "agg": .string("sum"), "unit": .string("usd_cents"), "sel": .object(["accumulates_into": .string("spend.usd_cents")]),
        "win": .object(["kind": .string("task")]), "key": .null, "domain_max": .int(500_000), "holder": .object(["kind": .string("site_local")]),
    ])
    static let QUESTIONS: JSONValue = .object([
        "id": .string("questions"), "agg": .string("count"), "sel": .object(["event": .string("intent_required")]), "win": .object(["kind": .string("task")]),
        "key": .null, "cap": .int(6), "holder": .object(["kind": .string("wallet")]),
    ])
    static func rootBody(_ over: JObject = [:]) -> JObject {
        var b: JObject = [
            "v": .int(1), "kind": .string("pca-intent-session"), "session": .string(SESSION), "principals": .array([.object(["key": .string(pub(principal))])]),
            "intent_ref": .string(REF), "schema": .object(["aud": .string(AUD), "digest": .string(SD)]), "layers": .object(["task": .object(["map_digest": .string(MAP0)])]),
            "accumulators": .array([TRIP, QUESTIONS]), "monitors": .array([]), "question_uri": .string("https://atlas.example/q"), "expires_at": .int(NOW + 86_400_000),
        ]
        for (k, v) in over { b[k] = v }
        return b
    }
    static func signRoot(_ body: JObject, by k: K = principal) -> JSONValue {
        var b = body
        b["signer"] = .string(pub(k))
        b["sig"] = .string(sign(k, Canonical.utf8(IntentSession.SIG_DOMAIN) + canon(.object(b))))
        return .object(b)
    }
    static func root(_ over: JObject = [:]) -> (S: JSONValue, R: String) {
        let s = signRoot(rootBody(over))
        return (s, IntentSession.rootDigest(s)!)
    }
    static let BASE = root()

    // ---- grants, PCActns ----

    static func cap(issuer: K, holder: K, caveats: [JSONValue]) -> JSONValue {
        let body: JSONValue = .object(["issuer": .string(pub(issuer)), "holder": .string(pub(holder)), "caveats": .array(caveats), "parent": .null])
        let d = hash(body)
        let sig = sign(issuer, Capability.CAP_DOMAIN + Base64URLStrict.decode(d)!)
        return .object(["id": .string(d), "issuer": .string(pub(issuer)), "holder": .string(pub(holder)), "caveats": .array(caveats),
                        "body_digest": .string(d), "sig": .string(sig)])
    }
    static func goalCommitV2(session: String = SESSION, map: String, salt: String, mapForm: String? = nil) -> String {
        Intent.goalCommit(ref: "", mapDigest: map, goalSalt: salt, session: session, mapForm: mapForm)!
    }
    static func mint(seq: Int64, prev: String? = nil, map: String, salt: String, signer: K = principal, root: String = BASE.R, session: String = SESSION,
                     mapForm: String? = nil) -> JSONValue {
        var sc: JObject = ["type": .string("intent_session"), "session": .string(session), "seq": .int(seq), "root": .string(root)]
        if let p = prev { sc["prev"] = .string(p) }
        let env: JSONValue = .object(["type": .string("envelope"), "goal_commit": .string(goalCommitV2(session: session, map: map, salt: salt, mapForm: mapForm))])
        return cap(issuer: signer, holder: agent, caveats: [env, .object(sc)])
    }
    static let G0 = mint(seq: 0, map: MAP0, salt: "salt0")
    static let D1 = mint(seq: 1, prev: G0.get("id")!.asString!, map: MAP1, salt: "salt1")

    static let PARAMS: JSONValue = .object(["offer_id": .string("OF-1"), "total": .int(38_900), "add_ons": .array([.string("none")]), "refundable": .bool(false)])

    static func with(_ v: JSONValue, _ patch: JObject) -> JSONValue {
        guard case var .object(o) = v else { return v }
        for (k, x) in patch { o[k] = x }
        return .object(o)
    }
    static func without(_ v: JSONValue, _ keys: [String]) -> JSONValue {
        guard case var .object(o) = v else { return v }
        for k in keys { o[JKey(k)] = nil }
        return .object(o)
    }

    static func is0(_ over: JObject = [:]) -> JSONValue {
        var o: JObject = ["session": .string(SESSION), "root": .string(BASE.R), "seq": .int(0), "schema": .string(SD),
                          "acc": .array([.object(["id": .string("trip_spend"), "post": .int(38_900)])])]
        for (k, v) in over { o[k] = v }
        return .object(o)
    }

    /// The unsigned PCActn body (no `sig`, no `intent_session`).
    static func body(_ grant: JSONValue, map: String, salt: String, params: JSONValue = PARAMS, ref: String = REF, verb: String = "air.book") -> JObject {
        let action: JObject = ["verb": .string(verb), "resource": .string("skyair.example/bookings"), "params_digest": .string(hash(params)),
                               "reversibility_class": .string("irreversible")]
        let cond = IntentTests.digest("cond")
        let rootP = Merkle.merkleRoot([Merkle.planLeaf(.string("book"), action, cond)!])!
        return [
            "ver": .int(2), "action": .object(action), "grant_ref": grant.get("id")!, "cap_chain": .array([grant]),
            "plan": .object(["root": .string(rootP), "node_id": .string("book"), "conditions_digest": .string(cond),
                             "inclusion_proof": .object(["index": .int(0), "size": .int(1), "path": .array([])])]),
            "attestation": .object(["epoch": .int(1), "quote_digest": .string("q"), "model_id": .string("m"), "measurement": .string("x"), "operator": .string("o")]),
            "provenance": .object(["causal_hash": .string("h"), "taint_level": .int(0), "trusted_refs": .array([])]),
            "freshness": .object(["beacon_ref": .string("b"), "accumulator_witness": .string("w"), "epoch": .int(1)]),
            "counter": .int(1), "risk_claim": .object(["r": .double(0.5), "inputs": .object([:])]),
            "aud": .string(AUD), "iat": .int(NOW), "exp": .int(NOW + 600_000),
            "intent": .object(["ref": .string(ref), "map_digest": .string(map), "goal_salt": .string(salt), "fidelity_ppm": .int(1_000_000), "residual_risk_ppm": .int(0)]),
        ]
    }
    static func signP(_ b: JObject) -> JSONValue {
        var p = b
        p["sig"] = nil
        p["sig"] = .string(sign(agent, try! PCA.thresholdMessage(p)))
        return .object(p)
    }
    static func build(_ grant: JSONValue, map: String = MAP0, salt: String = "salt0", is: JSONValue?, params: JSONValue = PARAMS, ref: String = REF,
                      verb: String = "air.book") -> JSONValue {
        var b = body(grant, map: map, salt: salt, params: params, ref: ref, verb: verb)
        if let s = `is` { b["intent_session"] = s }
        return signP(b)
    }
    static let P0 = build(G0, is: is0())

    static func ctx(_ over: JObject = [:]) -> JSONValue {
        var o: JObject = [
            "params": PARAMS, "schema": .object(["docs": .array([SCHEMA]), "keys": KEYS]),
            "session": .object(["root": BASE.S, "grants": .array([])]),
            "acc": .object(["state": .object(["trip_spend": .object(["sum": .int(0)])]), "monitors": .object([:])]),
        ]
        for (k, v) in over { o[k] = v }
        return .object(o)
    }

    static func verify(_ p: JSONValue, _ g: JSONValue, _ c: JSONValue?, now: Int64 = NOW) -> PCA.Verdict {
        PCA.verify(pcactn: p, grant: g, now: now, audience: AUD, intentV2: c.flatMap(IntentV2Context.fromJSON))
    }

    // ---- sequencer receipts and key sets ----

    static func keySet(keys: [JSONValue], by k: K = seqRoot, issued: Int64 = NOW - 1_000, version: Int64 = 1) -> JSONValue {
        var b: JObject = ["v": .int(1), "kind": .string("pca-sequencer-keys"), "sequencer": .string(pub(k)), "version": .int(version), "issued_at": .int(issued),
                          "keys": .array(keys)]
        b["sig"] = .string(sign(k, Canonical.utf8(IntentAcc.SEQUENCER_KEYS_DOMAIN) + canon(.object(b))))
        return .object(b)
    }
    static func keyEntry(kid: String = "k1", key k: K = seqKey, notBefore: Int64 = 0, notAfter: Int64? = nil, alg: String? = nil) -> JSONValue {
        var e: JObject = ["kid": .string(kid), "pk": .string(pub(k)), "not_before": .int(notBefore)]
        if let na = notAfter { e["not_after"] = .int(na) }
        if let a = alg { e["alg"] = .string(a) }
        return .object(e)
    }
    static func receipt(_ over: JObject = [:], by k: K = seqKey) -> JSONValue {
        var b: JObject = [
            "v": .int(1), "kind": .string("pca-acc-receipt"), "session": .string(SESSION), "acc": .string("trip_spend"), "seq": .int(3),
            "pre": .int(10_000), "delta": .int(38_900), "post": .int(48_900), "pcactn_digest": .string(""), "aud": .string(AUD),
            "issued_at": .int(NOW - 1_000), "expires_at": .int(NOW + 60_000), "kid": .string("k1"),
            "ledger": .object(["index": .int(7), "head": .string(digest("head"))]),
        ]
        for (kk, v) in over { b[kk] = v }
        b["signer"] = .string(pub(k))
        b["sig"] = .string(sign(k, Canonical.utf8(IntentAcc.RECEIPT_DOMAIN) + canon(.object(b))))
        return .object(b)
    }

    // ---- revocation (the dedicated authority's epochs carry the full sorted revoked list) ----

    /// A session revocation source naming the dedicated authority.
    static func revocationSource(maxAgeS: Int64 = 60, key k: K = revAuthority) -> JSONValue {
        .object(["epoch_uri": .string("https://atlas.example/rev"), "max_age_s": .int(maxAgeS), "key": .string(pub(k))])
    }
    static func sortedIds(_ ids: [String]) -> [String] { Array(Set(ids)).sorted { Canonical.compareUtf8($0, $1) < 0 } }
    /// Signed epoch over the (sorted, distinct) revoked list: epoch == set_size == |list|, root == revset_root(list).
    static func epoch(_ revoked: [String], issued: Int64, notAfter: Int64? = nil, by k: K = revAuthority,
                      scope: String = IntentRevocation.sessionScope(SESSION), number: Int64? = nil, root: String? = nil) -> JSONValue {
        let ids = sortedIds(revoked)
        var b: JObject = ["instance_id": .string("ana"), "grant_ref": .string(scope), "epoch": .int(number ?? Int64(ids.count)), "set_size": .int(Int64(ids.count)),
                          "root": .string(root ?? IntentRevocation.revsetRoot(ids)!), "issued_at": .int(issued), "not_after": .int(notAfter ?? issued + 300_000)]
        let sig = sign(k, Canonical.utf8(IntentRevocation.EPOCH_DOMAIN) + canon(.object(b)))
        b["guardian"] = .string(pub(k))
        b["sig"] = .string(sig)
        return .object(b)
    }
    /// Evidence `{epoch, revoked}`.
    static func evidence(_ revoked: [String], issued: Int64, notAfter: Int64? = nil, by k: K = revAuthority,
                         scope: String = IntentRevocation.sessionScope(SESSION)) -> JSONValue {
        .object(["epoch": epoch(revoked, issued: issued, notAfter: notAfter, by: k, scope: scope), "revoked": .array(sortedIds(revoked).map { .string($0) })])
    }

    // ---- W-B artifacts ----

    static func signArtifact(_ domain: String, _ body: JObject, _ k: K) -> JSONValue {
        var b = body
        b["sig"] = .string(sign(k, Canonical.utf8(domain) + canon(.object(b))))
        return .object(b)
    }
    static func fact(name: String = "fare", subject: String = "OF-1", value: JSONValue, tObs: Int64 = NOW - 1_000, oracle: String, by k: K) -> JSONValue {
        signArtifact(IntentWB.FACT_DOMAIN, ["v": .int(1), "kind": .string("pca-fact"), "name": .string(name), "subject": .string(subject), "value": value,
                                            "t_obs": .int(tObs), "oracle": .string(oracle)], k)
    }
    static func ref(_ domain: String, _ slot: String, _ a: JSONValue) -> String { IntentWB.artifactRef(domain, slot, a)! }

    // ---- committed map (rule 19) ----

    /// A one-verb committed map for `air.book`: dims `total` (num, cuts [40000] over [0, 100000]: 3 cells) and
    /// `action.resource` (cat: exact bookings, prefix "skyair.example/", other): 9 cells, then metrics and learner (12 leaves).
    struct CommittedMap {
        var header: JSONValue
        var cells: [JSONValue]
        var metrics: JSONValue
        var learner: JSONValue
        var leaves: [(String, JSONValue)] { [("header", header)] + cells.map { ("cell", $0) } + [("metrics", metrics), ("learner", learner)] }
        var size: Int64 { Int64(leaves.count) }
        func salt(_ i: Int) -> [UInt8] { Canonical.sha256(Canonical.utf8("v2/map-salt/\(i)")) }
        var hashes: [[UInt8]] { leaves.enumerated().map { IntentMap.leafHash($0.element.0, salt($0.offset), $0.element.1)! } }
        var commit: String { IntentMap.commitOf(size, IntentMap.treeRoot(hashes[...])) }
        func path(_ idx: Int) -> [JSONValue] {
            func go(_ hs: ArraySlice<[UInt8]>, _ i: Int) -> [[UInt8]] {
                if hs.count == 1 { return [] }
                let k = IntentMap.split(hs.count)
                if i < k { return go(hs.prefix(k), i) + [IntentMap.treeRoot(hs.dropFirst(k))] }
                return go(hs.dropFirst(k), i - k) + [IntentMap.treeRoot(hs.prefix(k))]
            }
            return go(hashes[...], idx).map { .string(Base64URLStrict.encode($0)) }
        }
        func entry(_ idx: Int) -> JSONValue {
            .object(["index": .int(Int64(idx)), "salt": .string(Base64URLStrict.encode(salt(idx))), "leaf": leaves[idx].1, "path": .array(path(idx))])
        }
        /// The disclosure for the cell at flat index `flat`.
        func disclosure(flat: Int) -> JSONValue {
            .object(["size": .int(size), "header": entry(0), "cell": entry(1 + flat), "metrics": entry(Int(size) - 2)])
        }
    }
    static func committedMap(residualRiskPpm: Int64 = 5_000, granted: Set<Int> = [0, 3]) -> CommittedMap {
        let header: JSONValue = .object(["verb": .string("air.book"), "first": .int(1), "cells": .int(9), "dims": .array([
            .object(["kind": .string("num"), "path": .string("action.params.total"), "lo": .int(0), "hi": .int(100_000), "cuts": .array([.int(40_000)])]),
            .object(["kind": .string("cat"), "path": .string("action.resource"), "values": .array([
                .object(["kind": .string("exact"), "value": .string("skyair.example/bookings")]),
                .object(["kind": .string("prefix"), "value": .string("skyair.example/")]),
                .object(["kind": .string("other"), "value": .string(IntentMap.OTHER)])])]),
        ])])
        var cells: [JSONValue] = []
        for a in 0..<3 { for b in 0..<3 {
            let flat = a * 3 + b
            cells.append(.object(["verb": .string("air.book"), "cell": .array([.int(Int64(a)), .int(Int64(b))]), "p_ppm": .int(Int64(990_000 - flat)),
                                  "in_grant": .bool(granted.contains(flat))]))
        } }
        var m: JObject = [:]
        for k in IntentMap.METRIC_FIELDS { m[JKey(k)] = .int(0) }
        m["residual_risk_ppm"] = .int(residualRiskPpm)
        return CommittedMap(header: header, cells: cells, metrics: .object(m), learner: .object(["learner_digest": .string(digest("learner"))]))
    }
}
