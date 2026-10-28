import Foundation

/// Intent Layer v2 W-B (conformance rules 16-18): world facts, relational dimensions and offer sets
/// (`oracle-facts.ts`, `offer-set.ts`), per-parameter provenance with label receipts and flow rules
/// (`param-provenance.ts`, `label-receipts.ts`, the label lattice of `taint.ts`), classifier verdicts
/// (`intent-classifier.ts`), and their composition (`intent-env.ts` `decideIntentWB`). Every artifact is a closed-member
/// JSON object signed with strict Ed25519 under a key from the VERIFIER's pins over `utf8(domain) || strictCanonical(artifact
/// without sig)`; its reference is `base64url(sha256(strictCanonical({d: <ref domain>, <slot>: artifact})))`.
enum IntentWB {
    static let FACT_DOMAIN = "atlas-pca/fact/v1\u{0}"
    static let FACT_REF_DOMAIN = "atlas-pca/fact-ref/v1"
    static let OFFER_SET_DOMAIN = "atlas-pca/offer-set/v1\u{0}"
    static let OFFER_SET_REF_DOMAIN = "atlas-pca/offer-set-ref/v1"
    static let LABELS_DOMAIN = "atlas-pca/labels/v1\u{0}"
    static let LABELS_REF_DOMAIN = "atlas-pca/labels-ref/v1"
    static let CLASSIFIER_DOMAIN = "atlas-pca/intent-classifier/v1\u{0}"
    static let CLASSIFIER_REF_DOMAIN = "atlas-pca/intent-classifier-ref/v1"
    static let MAX_COMMITTED_FACTS = 16
    static let MAX_WORLDS = 16
    static let MAX_RELATIONAL = 16
    static let DEFAULT_SKEW_MS: Int64 = 60_000
    static let MAX_OFFERS = 256
    static let MAX_OFFER_ATTRS = 32
    static let MAX_QUERY_KEYS = 32
    static let MAX_LABEL_FIELDS = 64
    static let MAX_PROV_PATHS = 32
    static let MAX_PROV_REFS = 8
    static let MAX_COMMITTED_LABELS = 16
    static let MAX_COMMITTED_CLASSES = 8
    static let MAX_CLASSIFIER_LABELS = 32
    static let LABEL_REF_PREFIX = "pca-labels:"
    static let TAINT_LEVELS = ["trusted", "first_party", "tool", "web", "agent"]
    static let TAINTED_RANK = 2

    // ---- shared artifact plumbing (intent-artifacts.ts) ----

    static func closedMembers(_ o: JObject, _ required: [String], _ optional: [String] = []) -> Bool {
        o.keys.allSatisfy { k in required.contains { JKey($0) == k } || optional.contains { JKey($0) == k } }
            && required.allSatisfy { o[JKey($0)] != nil }
    }

    /// `closedMembers(o, required, optional, where)`: nil when `o` has exactly the `required` members plus any of `optional`,
    /// else the reference's reason (an unknown member first, then a missing one).
    static func closedMembersError(_ o: JObject, _ required: [String], _ optional: [String] = [], _ wher: String) -> String? {
        for k in o.keys.map({ $0.s }).sorted(by: IV.utf8Less) where !(required.contains { IV.same($0, k) } || optional.contains { IV.same($0, k) }) {
            return "unknown member '\(wher).\(k)'"
        }
        for r in required where o[JKey(r)] == nil { return "missing member '\(wher).\(r)'" }
        return nil
    }

    /// ECMAScript `String(v)` of a possibly absent value (`undefined` when absent).
    static func jsOpt(_ v: JSONValue?) -> String { v.map { IntentV2.jsString($0) } ?? "undefined" }

    /// The optional suite members every W-B artifact may carry (`alg` and `pq_pk` are signed, `pq_sig` is not).
    static let SUITE_MEMBERS = ["alg", "pq_pk", "pq_sig"]

    /// The bytes an artifact signature covers: utf8(domain) || strictCanonical(artifact without `sig` / `pq_sig`).
    static func artifactMessage(_ domain: String, _ a: JObject) -> [UInt8]? {
        var body = a
        body["sig"] = nil
        body["pq_sig"] = nil
        return IV.message(domain, .object(body))
    }

    /// Suite capability and shape of an artifact's suite members (nil = usable): a non-string `alg`, `pq_pk` or `pq_sig`
    /// is malformed; an `alg` the suite dispatch does not resolve is `unsupported_suite`; an ed25519 artifact carries neither
    /// `pq_pk` nor `pq_sig`.
    static func artifactSuiteError(_ a: JObject) -> String? {
        if let e = IV.suiteError(a["alg"]) { return e }
        for k in ["pq_pk", "pq_sig"] { if let x = a[JKey(k)], x.asString == nil { return "\(k) must be a string" } }
        if IV.sigAlg(a["alg"]) == "ed25519" && (a["pq_pk"] != nil || a["pq_sig"] != nil) { return "an ed25519 artifact must not carry pq_pk / pq_sig" }
        return nil
    }

    /// A pin's optional `pq_pk`: absent, or a non-empty string (JSON null is malformed).
    static func pinPqOk(_ v: JSONValue?) -> Bool { v == nil || (v!.asString.map { !$0.isEmpty } ?? false) }

    /// Verify an artifact's signature under a PINNED signer (`artifactSuiteError` already passed), through the suite
    /// dispatch: Ed25519 under `pk`; a PQ or hybrid suite only when the artifact's `pq_pk` equals the pinned `pqPin`.
    static func verifyArtifactSig(_ domain: String, _ a: JObject, _ pk: String, pqPin: String? = nil) -> Bool {
        guard a["sig"]?.asString != nil, let msg = artifactMessage(domain, a) else { return false }
        return IV.verifyPinned(alg: a["alg"], identity: pk, artifactPqPk: a["pq_pk"], msg: msg, sig: a["sig"], pqSig: a["pq_sig"], pin: pqPin) == .valid
    }

    static func artifactRef(_ domain: String, _ slot: String, _ a: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(domain), JKey(slot): a]))
    }

    /// `resolveParamPath(params, path)`: `action.params.<a>.<b>…`, own members of plain objects, usable segments only.
    static func resolveParamPath(_ params: JSONValue?, _ path: String) -> JSONValue? {
        guard IV.startsWith(path, "action.params.") else { return nil }
        var cur = params
        for s in IV.split(IV.dropPrefix(path, 14), ".") {
            guard IV.isPathSegment(s), case let .object(o)? = cur, let x = o[JKey(s)] else { return nil }
            cur = x
        }
        return cur
    }

    /// `isParamPath`: `action.params.*` with 1..8 usable segments.
    static func isParamPath(_ v: JSONValue?) -> Bool {
        guard let p = v?.asString, IV.startsWith(p, "action.params.") else { return false }
        let segs = IV.split(IV.dropPrefix(p, 14), ".")
        return segs.count >= 1 && segs.count <= 8 && segs.allSatisfy(IV.isPathSegment)
    }

    /// An optional list member: ABSENT = []; an array; anything else (JSON null included) is malformed (nil: fail closed).
    static func list(_ v: JSONValue?) -> [JSONValue]? {
        switch v {
        case nil: return []
        case let .array(a)?: return a
        default: return nil
        }
    }

    /// A non-empty ARRAY (strict: an object with a `length` member is not one).
    static func nonEmptyArray(_ v: JSONValue?) -> Bool {
        if case let .array(a)? = v { return !a.isEmpty }
        return false
    }

    // ---- rule 16: facts, relational dimensions, offer sets ----

    static func validateFactWire(_ fv: JSONValue) -> Bool {
        guard case let .object(f) = fv, closedMembers(f, ["v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"], SUITE_MEMBERS) else { return false }
        guard IV.num(f["v"]) == 1, IV.same(f["kind"]?.asString, "pca-fact") else { return false }
        guard let n = f["name"]?.asString, IV.isName(n), IV.bounded(f["subject"], 256) != nil else { return false }
        if IV.int(f["value"]) == nil && IV.bounded(f["value"], 256) == nil { return false }
        guard IV.nonNeg(f["t_obs"]) != nil, IV.bounded(f["oracle"], 64) != nil, f["sig"]?.asString != nil else { return false }
        return true
    }

    /// floor(a * 10^6 / b) exactly (128-bit), nil when b <= 0, a < 0 or the result is not a safe integer.
    static func ratioPpm(_ a: Int64, _ b: Int64) -> Int64? {
        if !(b > 0) || a < 0 { return nil }
        let (hi, lo) = UInt64(a).multipliedFullWidth(by: 1_000_000)
        if hi >= UInt64(b) { return nil }
        let (q, _) = UInt64(b).dividingFullWidth((hi, lo))
        return q <= UInt64(Canonical.MAX_SAFE) ? Int64(q) : nil
    }

    static func validateOfferPolicy(_ pv: JSONValue) -> String? {
        guard case let .object(p) = pv else { return "offers policy must be an object" }
        if let e = closedMembersError(p, ["name", "site_keys", "max_age_ms", "offer_param", "filter"], [], "offers") { return e }
        if p["name"]?.asString == nil { return "offers policy needs a name" }
        guard case let .array(sk)? = p["site_keys"], !sk.isEmpty else { return "offers policy needs at least one pinned site key" }
        var kids = Set<JKey>()
        for k in sk {
            guard case let .object(ko) = k, closedMembers(ko, ["kid", "pk"], ["pq_pk"]), let kid = IV.bounded(ko["kid"], 64), IV.digest(ko["pk"]) != nil, pinPqOk(ko["pq_pk"]),
                  kids.insert(JKey(kid)).inserted else {
                return "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk"
            }
        }
        if IV.nonNeg(p["max_age_ms"]) == nil { return "offers policy: max_age_ms must be a non-negative safe integer" }
        guard let op = p["offer_param"]?.asString, IV.startsWith(op, "action.params.") else { return "offers policy: offer_param must be an action.params.* path" }
        guard case let .object(f)? = p["filter"], closedMembers(f, ["query", "offer"]), case let .object(q)? = f["query"], case let .object(o)? = f["offer"] else {
            return "offers policy: filter must be exactly {query: {}, offer: {}}"
        }
        if !(q.values.allSatisfy { IV.isScalar($0) } && o.values.allSatisfy { IV.isScalar($0) }) { return "offers policy: filter values must be scalars" }
        return nil
    }

    static func validateWorldPolicy(_ pv: JSONValue) -> String? {
        guard case let .object(p) = pv else { return "world policy must be an object" }
        if let e = closedMembersError(p, [], ["skew_ms", "worlds", "relational", "offers"], "policy") { return e }
        if let s = p["skew_ms"], IV.nonNeg(s) == nil { return "skew_ms must be a non-negative safe integer" }
        var names = Set<JKey>()
        func claim(_ n: JSONValue?) -> String? {
            guard let s = n?.asString, IV.isName(s) else { return "dimension name '\(jsOpt(n))' must match ^[a-z][a-z0-9_]{0,63}$" }
            if !names.insert(JKey(s)).inserted { return "duplicate dimension name '\(s)'" }
            return nil
        }
        guard let worlds = list(p["worlds"]) else { return "worlds must be a list of at most \(MAX_WORLDS)" }
        if worlds.count > MAX_WORLDS { return "worlds must be a list of at most \(MAX_WORLDS)" }
        for wv in worlds {
            guard case let .object(w) = wv else { return "world entry must be an object" }
            if let e = closedMembersError(w, ["name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty"], [], "world") { return e }
            if let e = claim(w["name"]) { return e }
            let wn = w["name"]!.asString!
            guard let sp = w["subject_path"]?.asString, IV.startsWith(sp, "action.") else { return "world '\(wn)': subject_path must be rooted at action." }
            guard IV.nonNeg(w["freshness_ms"]) != nil else { return "world '\(wn)': freshness_ms must be a non-negative safe integer" }
            guard let mf = IV.nonNeg(w["max_faulty"]) else { return "world '\(wn)': max_faulty must be a non-negative safe integer" }
            guard let mo = IV.int(w["min_oracles"]), Double(mo) >= 2 * Double(mf) + 1 else { return "world '\(wn)': min_oracles must be a safe integer >= 2*max_faulty+1" }
            guard case let .array(os)? = w["oracles"], Double(os.count) >= Double(mo) else { return "world '\(wn)': fewer pinned oracles than min_oracles" }
            var kids = Set<JKey>()
            for o in os {
                guard case let .object(oo) = o, closedMembers(oo, ["kid", "pk"], ["pq_pk"]), let kid = IV.bounded(oo["kid"], 64), IV.digest(oo["pk"]) != nil, pinPqOk(oo["pq_pk"]), kids.insert(JKey(kid)).inserted else {
                    return "world '\(wn)': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
                }
            }
        }
        guard let rel = list(p["relational"]) else { return "relational must be a list of at most \(MAX_RELATIONAL)" }
        if rel.count > MAX_RELATIONAL { return "relational must be a list of at most \(MAX_RELATIONAL)" }
        for rv in rel {
            guard case let .object(r) = rv else { return "relational entry must be an object" }
            if let e = closedMembersError(r, ["name", "fn", "a", "b"], [], "relational") { return e }
            if let e = claim(r["name"]) { return e }
            let own = r["name"]!.asString!
            guard let fn = r["fn"]?.asString, fn == "sub" || fn == "ratio_ppm" else { return "relational '\(own)': fn must be \"sub\" or \"ratio_ppm\"" }
            for op in [r["a"], r["b"]] {
                var ok = isParamPath(op)
                if !ok, let s = op?.asString, IV.startsWith(s, "env.world.") {
                    let n = IV.dropPrefix(s, 10)
                    ok = names.contains(JKey(n)) && !IV.same(n, own)
                }
                if !ok { return "relational '\(own)': operand '\(jsOpt(op))' must be an action.params path or an earlier env.world dimension" }
            }
        }
        if let ov = p["offers"] {
            if let e = validateOfferPolicy(ov) ?? claim(ov.get("name")) { return e }
        }
        return nil
    }

    /// ACTIVITY of rule 16: `committed.facts` a non-empty array, `committed.offer_set` a string, `policy.worlds` /
    /// `policy.relational` a non-empty array, or `policy.offers` a plain object.
    static func worldActive(committed: JSONValue?, policy: JSONValue?) -> Bool {
        if nonEmptyArray(committed?.get("facts")) { return true }
        if case .string? = committed?.get("offer_set") { return true }
        return nonEmptyArray(policy?.get("worlds")) || nonEmptyArray(policy?.get("relational")) || (policy?.get("offers")?.isObject ?? false)
    }

    /// ACTIVITY of rule 17: `prov` present (any value), `labels` a non-empty array, or the policy a plain object.
    static func provenanceActive(prov: JSONValue?, labels: JSONValue?, policy: JSONValue?) -> Bool {
        prov != nil || nonEmptyArray(labels) || (policy?.isObject ?? false)
    }

    static func validateOfferSetWire(_ ov: JSONValue) -> Bool { offerSetWireError(ov) == nil }

    /// `validateOfferSetWire`: nil = well-formed, else the reference's reason.
    static func offerSetWireError(_ ov: JSONValue) -> String? {
        guard case let .object(o) = ov else { return "offer set must be an object" }
        if let e = closedMembersError(o, ["v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig"], SUITE_MEMBERS, "offer_set") { return e }
        if IV.num(o["v"]) != 1 || !IV.same(o["kind"]?.asString, "pca-offer-set") { return "offer set must be {v: 1, kind: \"pca-offer-set\"}" }
        if IV.bounded(o["site"], 256) == nil { return "'offer_set.site' must be a non-empty string (<= 256 bytes)" }
        if IV.digest(o["session"]) == nil { return "'offer_set.session' must be canonical base64url (32 bytes)" }
        guard case let .object(q)? = o["query"], q.count <= MAX_QUERY_KEYS else { return "'offer_set.query' must be an object with <= \(MAX_QUERY_KEYS) keys" }
        for k in q.keys.map({ $0.s }).sorted(by: IV.utf8Less) where IV.bounded(.string(k), 64) == nil || !IV.isScalar(q[JKey(k)]!) { return "'offer_set.query.\(k)' must be a scalar" }
        if !IV.same(o["rank"]?.asString, "price_asc") { return "'offer_set.rank' must be \"price_asc\"" }
        guard case .bool? = o["complete"] else { return "'offer_set.complete' must be a boolean" }
        guard case let .array(offers)? = o["offers"], !offers.isEmpty, offers.count <= MAX_OFFERS else { return "'offer_set.offers' must hold 1..\(MAX_OFFERS) offers" }
        var ids = Set<JKey>()
        for (i, of) in offers.enumerated() {
            guard case let .object(x) = of else { return "offer \(i) must be an object" }
            guard let id = IV.bounded(x["offer_id"], 128) else { return "offer \(i): 'offer_id' must be a non-empty string (<= 128 bytes)" }
            if !ids.insert(JKey(id)).inserted { return "offer \(i): duplicate offer_id" }
            if IV.nonNeg(x["price"]) == nil { return "offer \(i): 'price' must be a non-negative safe integer" }
            let attrs = x.filter { $0.key != "offer_id" && $0.key != "price" }
            if attrs.count > MAX_OFFER_ATTRS { return "offer \(i): more than \(MAX_OFFER_ATTRS) attributes" }
            for k in attrs.keys.map({ $0.s }).sorted(by: IV.utf8Less) where IV.bounded(.string(k), 64) == nil || !IV.isScalar(attrs[JKey(k)]!) { return "offer \(i): attribute '\(k)' must be a scalar" }
        }
        if IV.nonNeg(o["issued_at"]) == nil { return "'offer_set.issued_at' must be a non-negative safe integer" }
        if IV.bounded(o["kid"], 64) == nil { return "'offer_set.kid' must be a non-empty string (<= 64 bytes)" }
        if o["sig"]?.asString == nil { return "'offer_set.sig' must be a string" }
        return nil
    }

    static func offerMatches(_ offer: JObject, _ f: JObject) -> Bool {
        f.allSatisfy { k, v in offer[k].map { IV.scalarEq($0, v) } ?? false }
    }

    /// `decideOfferSet`: the excess of the chosen offer over the cheapest offer satisfying the filter, or the refusal reason.
    static func decideOfferSet(policy: JObject, committed: JSONValue?, offerSet: JSONValue?, params: JSONValue, aud: String, session: String,
                               now nowClock: Int64?, skewMs: Double) -> (excess: Int64?, reason: String) {
        func no(_ r: String) -> (Int64?, String) { (nil, "offers: \(r)") }
        guard let c = committed?.asString else { return no("the PCActn commits no offer set but the policy requires one") }
        guard let ov = offerSet else { return no("the committed offer set was not supplied") }
        if let w = offerSetWireError(ov) { return no(w) }
        guard case let .object(os) = ov else { return no("malformed offer set") }
        guard let ref = artifactRef(OFFER_SET_REF_DOMAIN, "o", ov) else { return no("the offer set is not strictly canonical") }
        if !IV.same(ref, c) { return no("the supplied offer set does not match the committed reference") }
        if let se = artifactSuiteError(os) { return no("signature suite: \(se)") }
        guard let key = policy["site_keys"]?.asArray?.first(where: { IV.same($0.get("kid")?.asString, os["kid"]?.asString) }),
              let pk = key.get("pk")?.asString else { return no("signing key '\(os["kid"]?.asString ?? "")' is not pinned") }
        if !verifyArtifactSig(OFFER_SET_DOMAIN, os, pk, pqPin: key.get("pq_pk")?.asString) { return no("bad site signature") }
        guard IV.same(os["site"]?.asString, aud) else { return no("the offer set was issued for another audience") }
        guard IV.same(os["session"]?.asString, session), let issued = IV.num(os["issued_at"]) else { return no("the offer set is bound to another session") }
        guard let nowI = nowClock else { return no("no usable clock (now must be a safe integer): the offer set counts as stale") }
        let now = Double(nowI)
        if issued > now + skewMs { return no("the offer set is issued in the future") }
        if now - issued > (IV.num(policy["max_age_ms"]) ?? 0) { return no("the offer set is stale") }
        guard case .bool(true)? = os["complete"] else { return no("the offer set is not declared complete") }
        guard case let .object(query)? = os["query"], case let .object(filter)? = policy["filter"], case let .object(fq)? = filter["query"],
              case let .object(fo)? = filter["offer"] else { return no("malformed filter") }
        if !query.allSatisfy({ k, v in fq[k].map { IV.scalarEq($0, v) } ?? false }) { return no("the search was narrowed beyond the intent filter (coverage)") }
        guard let op = policy["offer_param"]?.asString, case let .string(id)? = resolveParamPath(params, op) else { return no("the action names no offer id at the declared parameter") }
        let offers = (os["offers"]?.asArray ?? []).compactMap { $0.asObject }
        guard let chosen = offers.first(where: { IV.same($0["offer_id"]?.asString, id) }) else { return no("the chosen offer is not in the signed offer set") }
        guard offerMatches(chosen, fo), let cp = IV.nonNeg(chosen["price"]) else { return no("the chosen offer does not satisfy the intent filter") }
        var mn = cp
        for x in offers where offerMatches(x, fo) { if let p = IV.nonNeg(x["price"]), p < mn { mn = p } }
        return (cp - mn, "")
    }

    struct WorldDecision {
        var ok: Bool
        var world: JObject = [:]
        var singleSource: [String] = []
        var reason = ""
    }

    /// `decideIntentWorld` (rule 16). First failure wins.
    /// `now`: the clock, a safe integer; nil (any other value) makes every fact and every offer set stale.
    static func decideWorld(now: Int64?, aud: String, session: String, action: JSONValue, committed: JSONValue?, facts: JSONValue?,
                            offerSet: JSONValue?, policy policyIn: JSONValue?) -> WorldDecision {
        func fail(_ r: String) -> WorldDecision { WorldDecision(ok: false, reason: "facts: \(r)") }
        let policyV = policyIn ?? .object([:]) // absent = {}; a JSON null policy is malformed (validateWorldPolicy refuses it)
        if let e = validateWorldPolicy(policyV) { return fail("policy misconfigured (fail closed): \(e)") }
        guard case let .object(policy) = policyV else { return fail("policy misconfigured") }
        let skew = Double(IV.nonNeg(policy["skew_ms"]) ?? DEFAULT_SKEW_MS)
        guard action.isObject else { return fail("action must be an object") }
        if let p = action.get("params"), !p.isObject { return fail("action.params must be an object") }
        if let c = committed, !c.isObject { return fail("committed must be an object") }
        guard let cf = list(committed?.get("facts")) else { return fail("committed facts must be a list of at most \(MAX_COMMITTED_FACTS) digests") }
        if cf.count > MAX_COMMITTED_FACTS { return fail("committed facts must be a list of at most \(MAX_COMMITTED_FACTS) digests") }
        var seen = Set<JKey>()
        var committedFacts: [String] = []
        for d in cf {
            guard let s = IV.digest(d) else { return fail("a committed fact digest is not canonical base64url (32 bytes)") }
            if !seen.insert(JKey(s)).inserted { return fail("duplicate committed fact digest") }
            committedFacts.append(s)
        }
        let committedOffer = committed?.get("offer_set")
        if let co = committedOffer, IV.digest(co) == nil { return fail("the committed offer_set is not canonical base64url (32 bytes)") }
        guard let supplied = list(facts) else { return fail("facts must be an array") }
        if let o = offerSet, !o.isObject { return fail("offer_set must be an object") }
        var byRef: [JKey: JObject] = [:]
        for f in supplied where validateFactWire(f) {
            if let r = artifactRef(FACT_REF_DOMAIN, "f", f) { byRef[JKey(r)] = f.asObject! }
        }
        let worlds = (policy["worlds"]?.asArray ?? []).compactMap { $0.asObject }
        var accepted: [JObject] = []
        var pairs = Set<JKey>()
        for d in committedFacts {
            guard let fact = byRef[JKey(d)] else { return fail("a committed fact was not supplied (or is malformed)") }
            if let se = artifactSuiteError(fact) { return fail("fact signature suite: \(se)") }
            let fname = fact["name"]!.asString!
            guard let w = worlds.first(where: { IV.same($0["name"]?.asString, fname) }) else { return fail("fact for undeclared world '\(fname)'") }
            let oracle = fact["oracle"]!.asString!
            guard let pin = w["oracles"]?.asArray?.first(where: { IV.same($0.get("kid")?.asString, oracle) }), let pk = pin.get("pk")?.asString else {
                return fail("oracle '\(oracle)' is not pinned for world '\(fname)'")
            }
            if !verifyArtifactSig(FACT_DOMAIN, fact, pk, pqPin: pin.get("pq_pk")?.asString) { return fail("bad oracle signature on a '\(fname)' fact") }
            let sp = w["subject_path"]!.asString!
            let subject: String?
            if IV.same(sp, "action.resource") { subject = action.get("resource")?.asString }
            else if IV.same(sp, "action.verb") { subject = action.get("verb")?.asString }
            else { subject = resolveParamPath(action.get("params") ?? .object([:]), sp)?.asString }
            guard let sub = subject, IV.same(fact["subject"]?.asString, sub) else { return fail("a '\(fname)' fact names another subject") }
            if !pairs.insert(JKey(fname + "\u{0}" + oracle)).inserted { return fail("two facts from oracle '\(oracle)' for world '\(fname)'") }
            accepted.append(fact)
        }
        var out = WorldDecision(ok: true)
        for w in worlds {
            let name = w["name"]!.asString!
            let freshness = IV.num(w["freshness_ms"])!
            let fresh = now.map { n in
                accepted.filter { f in
                    guard IV.same(f["name"]?.asString, name), let t = IV.num(f["t_obs"]) else { return false }
                    return t <= Double(n) + skew && Double(n) - t <= freshness
                }
            } ?? []
            let minOracles = IV.num(w["min_oracles"])!
            if Double(fresh.count) < minOracles { return fail("world '\(name)' has \(fresh.count) fresh fact(s), needs \(Int64(minOracles))") }
            let nums = fresh.compactMap { IV.int($0["value"]) }
            if nums.count == fresh.count {
                let s = nums.sorted()
                out.world[JKey(name)] = .int(s[(s.count - 1) / 2])
            } else if nums.isEmpty {
                let v = fresh[0]["value"]!.asString!
                if fresh.contains(where: { !IV.same($0["value"]?.asString, v) }) { return fail("world '\(name)': string facts disagree") }
                out.world[JKey(name)] = .string(v)
            } else {
                return fail("world '\(name)': facts mix integer and string values")
            }
            if minOracles == 1 { out.singleSource.append(name) }
        }
        func operand(_ path: String) -> Int64? {
            if IV.startsWith(path, "env.world.") { return IV.int(out.world[JKey(IV.dropPrefix(path, 10))]) }
            return IV.int(resolveParamPath(action.get("params") ?? .object([:]), path))
        }
        for rv in policy["relational"]?.asArray ?? [] {
            let name = rv.get("name")!.asString!
            guard let a = operand(rv.get("a")?.asString ?? ""), let b = operand(rv.get("b")?.asString ?? "") else {
                return fail("relational '\(name)': an operand is missing or not a safe integer")
            }
            let v: Int64?
            if IV.same(rv.get("fn")?.asString, "sub") {
                let d = Double(a) - Double(b)
                v = IV.isSafeDouble(d) ? Int64(d) : nil
            } else {
                v = ratioPpm(a, b)
            }
            guard let r = v else { return fail("relational '\(name)': result undefined or outside the safe integer range") }
            out.world[JKey(name)] = .int(r)
        }
        if case let .object(op)? = policy["offers"] {
            let od = decideOfferSet(policy: op, committed: committedOffer, offerSet: offerSet, params: action.get("params") ?? .object([:]),
                                    aud: aud, session: session, now: now, skewMs: skew)
            guard let excess = od.excess else { return fail(od.reason) }
            out.world[JKey(op["name"]!.asString!)] = .int(excess)
        }
        return out
    }

    // ---- rule 17: provenance, label receipts, flow rules ----

    static func rank(_ level: String) -> Int { TAINT_LEVELS.firstIndex(of: level) ?? 4 }
    static func isTaintLevel(_ v: JSONValue?) -> Bool { v?.asString.map { s in TAINT_LEVELS.contains { IV.same($0, s) } } ?? false }

    static func validateLabelsWire(_ lv: JSONValue) -> Bool {
        guard case let .object(l) = lv, closedMembers(l, ["v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"], SUITE_MEMBERS),
              IV.num(l["v"]) == 1, IV.same(l["kind"]?.asString, "pca-labels"), IV.bounded(l["site"], 256) != nil, IV.digest(l["session"]) != nil,
              IV.digest(l["response_digest"]) != nil, case let .object(fields)? = l["fields"], !fields.isEmpty, fields.count <= MAX_LABEL_FIELDS else { return false }
        for (k, f) in fields {
            guard IV.bounded(.string(k.s), 256) != nil, case let .object(fo) = f, closedMembers(fo, ["class", "value_digest"]),
                  let cls = fo["class"]?.asString, IV.u16(cls) <= 128, IV.isDataClass(cls), IV.digest(fo["value_digest"]) != nil else { return false }
        }
        return IV.nonNeg(l["issued_at"]) != nil && IV.bounded(l["kid"], 64) != nil && l["sig"]?.asString != nil
    }

    static func validateFlowRules(_ rv: JSONValue) -> Bool { flowRulesError(rv) == nil }

    /// `validateFlowRules`: nil = well-formed, else the reference's reason.
    static func flowRulesError(_ rv: JSONValue) -> String? {
        guard case let .object(r) = rv else { return "flows must be an object" }
        for p in r.keys.map({ $0.s }).sorted(by: IV.utf8Less) {
            let base = p == "*" ? "x" : (IV.endsWith(p, ".*") ? IV.text((p.unicodeScalars.dropLast(2))) : p)
            if !IV.isDataClass(base) { return "flow pattern '\(p)' is not a class, a 'prefix.*' or '*'" }
            guard case let .array(ss)? = r[JKey(p)], ss.allSatisfy({ IV.bounded($0, 256) != nil }) else { return "flow pattern '\(p)' needs a list of audiences" }
        }
        return nil
    }

    /// `flowAllowed(rules, cls, origin, aud)`: same origin or `public`; else the most specific matching pattern lists `aud`.
    static func flowAllowed(_ rules: JObject, _ cls: String, _ origin: String, _ aud: String) -> Bool {
        if IV.same(aud, origin) || IV.same(cls, "public") { return true }
        var pattern: String?
        if rules[JKey(cls)] != nil {
            pattern = cls
        } else {
            var best: String?
            for p in rules.keys.map({ $0.s }) where IV.endsWith(p, ".*") {
                let prefix = IV.text((p.unicodeScalars.dropLast()))
                if IV.startsWith(cls, prefix) && (best == nil || IV.u16(p) > IV.u16(best!)) { best = p }
            }
            pattern = best ?? (rules["*"] != nil ? "*" : nil)
        }
        guard let p = pattern, case let .array(sinks)? = rules[JKey(p)] else { return false }
        return sinks.contains { IV.same($0.asString, aud) }
    }

    static let MODES = ["allow", "question", "question_typed", "deny"]

    static func validateProvenancePolicy(_ pv: JSONValue) -> Bool { provenancePolicyError(pv) == nil }

    /// `validateProvenancePolicy`: nil = well-formed, else the reference's reason.
    static func provenancePolicyError(_ pv: JSONValue) -> String? {
        guard case let .object(p) = pv, case let .object(params)? = p["params"] else { return "provenance policy needs a params map" }
        if let e = closedMembersError(p, ["params"], ["registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"], "policy") { return e }
        for k in params.keys.map({ $0.s }).sorted(by: IV.utf8Less) {
            if !isParamPath(.string(k)) { return "policy param '\(k)' is not an action.params path" }
            guard let sv = params[JKey(k)]?.asString, sv == "material" || sv == "critical" else { return "policy param '\(k)': sensitivity must be material or critical" }
        }
        if let rv = p["registry"] {
            guard case let .object(reg) = rv else { return "registry must be an object" }
            for k in reg.keys.map({ $0.s }).sorted(by: IV.utf8Less) where IV.bounded(.string(k), 256) == nil || !isTaintLevel(reg[JKey(k)]) { return "registry entry '\(k)' must map to a taint level" }
        }
        if let lk = p["label_keys"] {
            guard case let .array(keys) = lk else { return "label_keys must be a list" }
            for k in keys {
                guard case let .object(ko) = k, closedMembers(ko, ["site", "kid", "pk"], ["pq_pk"]), IV.bounded(ko["site"], 256) != nil, IV.bounded(ko["kid"], 64) != nil, IV.digest(ko["pk"]) != nil,
                      pinPqOk(ko["pq_pk"]) else { return "every label key needs site, kid, a 32-byte pk and an optional string pq_pk" }
            }
        }
        if let c = p["critical_max"], !isTaintLevel(c) { return "critical_max must be a taint level" }
        if let m = p["material_tainted"], !(m.asString.map { IV.contains(MODES, $0) } ?? false) { return "material_tainted must be allow | question | question_typed | deny" }
        if let m = p["critical_tainted"], !(m.asString.map { $0 != "allow" && IV.contains(MODES, $0) } ?? false) { return "critical_tainted must be question | question_typed | deny" }
        if let f = p["flows"], let e = flowRulesError(f) { return e }
        return nil
    }

    /// `validateProvWire`: nil = well-formed, else the reference's reason.
    static func provWireError(_ provV: JSONValue) -> String? {
        guard case let .object(prov) = provV else { return "'prov' must be an object" }
        if prov.count > MAX_PROV_PATHS { return "'prov' holds more than \(MAX_PROV_PATHS) paths" }
        for k in prov.keys.map({ $0.s }).sorted(by: IV.utf8Less) {
            guard IV.isTopParamPath(k), !IV.FORBIDDEN_SEGMENTS.contains(IV.dropPrefix(k, 14)) else {
                return "'prov' key '\(k)' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)"
            }
            guard case let .array(rs)? = prov[JKey(k)], !rs.isEmpty, rs.count <= MAX_PROV_REFS else { return "'prov.\(k)' must hold 1..\(MAX_PROV_REFS) refs" }
            if !rs.allSatisfy({ IV.bounded($0, 256) != nil }) { return "'prov.\(k)' refs must be non-empty strings (<= 256 bytes)" }
        }
        return nil
    }

    struct ProvenanceDecision {
        var outcome: String // pass | question | deny
        var friction: String?
        var labels: [String: String] = [:]
        var classes: [String: [String]] = [:]
        var env: JObject = [:]
        var reason = ""
    }

    /// `setNested(root, path, value)`: false when the path collides with an existing leaf or subtree.
    static func setNested(_ root: inout JObject, _ segs: ArraySlice<String>, _ value: JSONValue) -> Bool {
        guard let first = segs.first else { return false }
        let k = JKey(first)
        if segs.count == 1 {
            if root[k] != nil { return false }
            root[k] = value
            return true
        }
        var child: JObject
        switch root[k] {
        case nil: child = [:]
        case let .object(o)?: child = o
        default: return false
        }
        let ok = setNested(&child, segs.dropFirst(), value)
        if ok { root[k] = .object(child) }
        return ok
    }

    /// `decideParamProvenance` (rule 17). First failure wins.
    static func decideProvenance(aud: String, session: String, params paramsIn: JSONValue?, prov provIn: JSONValue?, committedLabels: JSONValue?,
                                 labels labelsIn: JSONValue?, policy policyV: JSONValue) -> ProvenanceDecision {
        var d = ProvenanceDecision(outcome: "pass")
        func deny(_ r: String) -> ProvenanceDecision { var x = d; x.outcome = "deny"; x.reason = "provenance: \(r)"; x.env = [:]; return x }
        if let e = provenancePolicyError(policyV) { return deny("policy misconfigured (fail closed): \(e)") }
        guard case let .object(policy) = policyV, case let .object(pparams)? = policy["params"] else { return deny("policy misconfigured") }
        let provV = provIn ?? .object([:]) // absent = {}; JSON null is malformed
        if let e = provWireError(provV) { return deny(e) }
        guard case let .object(prov) = provV else { return deny("'prov' must be an object") }
        guard let cl = list(committedLabels) else { return deny("committed labels must be a list of at most \(MAX_COMMITTED_LABELS) digests") }
        if cl.count > MAX_COMMITTED_LABELS { return deny("committed labels must be a list of at most \(MAX_COMMITTED_LABELS) digests") }
        var committed = Set<JKey>()
        for x in cl {
            guard let s = IV.digest(x), committed.insert(JKey(s)).inserted else { return deny("committed labels must be distinct canonical 32-byte digests") }
        }
        if let pi = paramsIn, !pi.isObject { return deny("action.params must be an object") }
        let params: JSONValue = paramsIn ?? .object([:])
        guard let suppliedLabels = list(labelsIn) else { return deny("labels must be an array") }
        let paths = prov.keys.map { $0.s }.sorted(by: IV.utf8Less)
        for p in paths where resolveParamPath(params, p) == nil { return deny("prov names '\(p)', a parameter the action does not carry") }
        for a in paths { for b in paths where !IV.same(a, b) && IV.startsWith(b, a + ".") { return deny("prov paths '\(a)' and '\(b)' overlap") } }
        var receipts: [JKey: JObject] = [:]
        for r in suppliedLabels where validateLabelsWire(r) {
            if let ref = artifactRef(LABELS_REF_DOMAIN, "l", r) { receipts[JKey(ref)] = r.asObject! }
        }
        let registry = policy["registry"]?.asObject ?? [:]
        let labelKeys = policy["label_keys"]?.asArray ?? []
        var origins: [String: [(cls: String, origin: String)]] = [:]
        for p in paths {
            let value = resolveParamPath(params, p)!
            var maxRank = -1
            for refV in prov[JKey(p)]!.asArray! {
                let ref = refV.asString!
                if !IV.startsWith(ref, LABEL_REF_PREFIX) {
                    let lvl = registry[JKey(ref)].flatMap { isTaintLevel($0) ? $0.asString : nil } ?? "agent"
                    maxRank = max(maxRank, rank(lvl))
                    continue
                }
                let rest = Array(IV.dropPrefix(ref, LABEL_REF_PREFIX.unicodeScalars.count).unicodeScalars)
                guard let hash = rest.firstIndex(of: "#") else { return deny("malformed label ref on '\(p)'") }
                let receiptD = IV.text((rest[..<hash]))
                let field = IV.text((rest[(hash + 1)...]))
                guard IV.digest(.string(receiptD)) != nil, !field.isEmpty else { return deny("malformed label ref on '\(p)'") }
                if !committed.contains(JKey(receiptD)) { return deny("label ref on '\(p)' names a receipt the PCActn does not commit") }
                guard let receipt = receipts[JKey(receiptD)] else { return deny("label receipt for '\(p)' was not supplied") }
                let site = receipt["site"]!.asString!
                if let se = artifactSuiteError(receipt) { return deny("label receipt for '\(p)': signature suite: \(se)") }
                guard let key = labelKeys.first(where: { IV.same($0.get("site")?.asString, site) && IV.same($0.get("kid")?.asString, receipt["kid"]?.asString) }),
                      let pk = key.get("pk")?.asString else { return deny("label receipt for '\(p)': no pinned label key for site '\(site)' kid '\(receipt["kid"]?.asString ?? "")'") }
                if !verifyArtifactSig(LABELS_DOMAIN, receipt, pk, pqPin: key.get("pq_pk")?.asString) { return deny("label receipt for '\(p)': bad label receipt signature") }
                if !IV.same(receipt["session"]?.asString, session) { return deny("label receipt for '\(p)' is bound to another session") }
                guard let f = receipt["fields"]?.asObject?[JKey(field)] else { return deny("label receipt for '\(p)' has no field '\(field)'") }
                let match = IV.strictHash(value).map { IV.same($0, f.get("value_digest")?.asString) } ?? false
                maxRank = max(maxRank, rank(match ? (IV.same(site, aud) ? "first_party" : "tool") : "agent"))
                origins[p, default: []].append((f.get("class")!.asString!, site))
            }
            d.labels[p] = TAINT_LEVELS[maxRank < 0 ? 4 : maxRank]
        }
        for p in pparams.keys.map({ $0.s }).sorted(by: IV.utf8Less) where d.labels[p] == nil {
            if resolveParamPath(params, p) != nil { d.labels[p] = "agent" }
        }
        let flows = policy["flows"]?.asObject ?? [:]
        for p in origins.keys.sorted(by: IV.utf8Less) {
            var uniq: [String] = []
            for o in origins[p]! where !IV.contains(uniq, o.cls) { uniq.append(o.cls) }
            d.classes[p] = uniq.sorted(by: IV.utf8Less)
            for o in origins[p]! where !flowAllowed(flows, o.cls, o.origin, aud) {
                return deny("flow: class '\(o.cls)' from '\(o.origin)' may not reach '\(aud)' (parameter '\(p)')")
            }
        }
        let capRank = rank(policy["critical_max"]?.asString ?? "agent")
        func sens(_ p: String) -> String? { pparams[JKey(p)]?.asString }
        let labelPaths = d.labels.keys.sorted(by: IV.utf8Less)
        for p in labelPaths where sens(p) == "critical" && rank(d.labels[p]!) > capRank {
            return deny("critical parameter '\(p)' has provenance '\(d.labels[p]!)', above the policy maximum '\(jsOpt(policy["critical_max"]))'")
        }
        var question = false, typed = false
        for p in labelPaths {
            guard let s = sens(p), rank(d.labels[p]!) >= TAINTED_RANK else { continue }
            let mode = s == "critical" ? (policy["critical_tainted"]?.asString ?? "question_typed") : (policy["material_tainted"]?.asString ?? "question")
            if mode == "deny" { return deny("tainted \(s) parameter '\(p)' (provenance '\(d.labels[p]!)') is denied by policy") }
            if mode == "question" || mode == "question_typed" { question = true }
            if mode == "question_typed" { typed = true }
        }
        var env: JObject = [:]
        for p in labelPaths {
            if !setNested(&env, IV.split(p, ".")[...], .string(d.labels[p]!)) { return deny("provenance paths overlap at '\(p)'") }
        }
        d.env = env
        if question {
            d.outcome = "question"
            d.friction = typed ? "typed" : "tap"
            d.reason = "provenance: a tainted value needs the principal (lazy question)"
        }
        return d
    }

    // ---- rule 18: classifier verdicts ----

    static func validateVerdictWire(_ vv: JSONValue) -> Bool {
        guard case let .object(v) = vv, closedMembers(v, ["v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"], SUITE_MEMBERS),
              IV.num(v["v"]) == 1, IV.same(v["kind"]?.asString, "pca-intent-classification"), let c = v["classifier"]?.asString, IV.isName(c),
              IV.digest(v["session"]) != nil, IV.digest(v["content_digest"]) != nil, IV.bounded(v["label"], 64) != nil,
              IV.bounded(v["measurement"], 256) != nil, IV.digest(v["judge"]) != nil, v["sig"]?.asString != nil else { return false }
        return true
    }

    static func validateClassifierPolicy(_ pv: JSONValue) -> Bool { classifierPolicyError(pv) == nil }

    /// `validateClassifierPolicy`: nil = well-formed, else the reference's reason.
    static func classifierPolicyError(_ pv: JSONValue) -> String? {
        guard case let .object(p) = pv, case let .array(cs)? = p["classifiers"] else { return "classifier policy needs a classifiers list" }
        if let e = closedMembersError(p, ["classifiers"], [], "policy") { return e }
        var ids = Set<JKey>()
        for cv in cs {
            guard case let .object(c) = cv, closedMembers(c, ["id", "param", "labels", "keys", "k"], ["measurements", "pq_keys"]) else {
                return "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}"
            }
            guard let id = c["id"]?.asString, IV.isName(id), ids.insert(JKey(id)).inserted else { return "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$" }
            if !isParamPath(c["param"]) { return "classifier '\(id)': param must be an action.params path" }
            guard case let .array(ls)? = c["labels"], !ls.isEmpty, ls.count <= MAX_CLASSIFIER_LABELS else { return "classifier '\(id)': labels must hold 1..\(MAX_CLASSIFIER_LABELS) strings" }
            if !(ls.allSatisfy({ IV.bounded($0, 64) != nil }) && IV.distinct(ls.compactMap { $0.asString })) { return "classifier '\(id)': labels must be distinct non-empty strings" }
            guard case let .array(ks)? = c["keys"], !ks.isEmpty, ks.allSatisfy({ IV.digest($0) != nil }), IV.distinct(ks.compactMap { $0.asString }) else { return "classifier '\(id)': keys must be distinct 32-byte keys" }
            guard let k = IV.int(c["k"]), k >= 1, k <= Int64(ks.count) else { return "classifier '\(id)': k must be an integer in [1, \(ks.count)]" }
            if let m = c["measurements"] {
                guard case let .array(ms) = m, ms.allSatisfy({ $0.asString != nil }) else { return "classifier '\(id)': measurements must be a list of strings" }
            }
            // PQ keys pinned per allowlisted key (judge key -> pq_pk)
            if let pk = c["pq_keys"] {
                guard case let .object(pm) = pk, pm.allSatisfy({ k, v in ks.contains { IV.same($0.asString, k.s) } && (v.asString.map { !$0.isEmpty } ?? false) }) else { return "classifier '\(id)': pq_keys must map allowlisted keys to PQ keys" }
            }
        }
        return nil
    }

    /// ACTIVITY of rule 18: `committed` or `policy.classifiers` a non-empty array.
    static func classifierActive(committed: JSONValue?, classifiers: JSONValue?) -> Bool {
        nonEmptyArray(committed) || nonEmptyArray(classifiers)
    }

    /// `decideClassifierDimensions` (rule 18): (ok, classes, reason).
    static func decideClassifiers(session: String?, params paramsIn: JSONValue?, committed committedIn: JSONValue?, verdicts: JSONValue?,
                                  policy: JSONValue) -> (ok: Bool, classes: JObject, reason: String) {
        func fail(_ r: String) -> (Bool, JObject, String) { (false, [:], "classes: \(r)") }
        if let e = classifierPolicyError(policy) { return fail("policy misconfigured (fail closed): \(e)") }
        let cls = (policy.get("classifiers")?.asArray ?? []).compactMap { $0.asObject }
        guard let cl = list(committedIn) else { return fail("committed verdicts must be a list of at most \(MAX_COMMITTED_CLASSES) digests") }
        if cl.count > MAX_COMMITTED_CLASSES { return fail("committed verdicts must be a list of at most \(MAX_COMMITTED_CLASSES) digests") }
        var seen = Set<JKey>()
        var committed: [String] = []
        for d in cl {
            guard let s = IV.digest(d), seen.insert(JKey(s)).inserted else { return fail("committed verdicts must be distinct canonical 32-byte digests") }
            committed.append(s)
        }
        guard let supplied = list(verdicts) else { return fail("verdicts must be an array") }
        var byRef: [JKey: JObject] = [:]
        for v in supplied where validateVerdictWire(v) {
            if let r = artifactRef(CLASSIFIER_REF_DOMAIN, "c", v) { byRef[JKey(r)] = v.asObject! }
        }
        if let pi = paramsIn, !pi.isObject { return fail("action.params must be an object") }
        let params: JSONValue = paramsIn ?? .object([:])
        var votes: [JKey: [JKey: Int]] = [:]
        var pairs = Set<JKey>()
        for d in committed {
            guard let v = byRef[JKey(d)] else { return fail("a committed verdict was not supplied (or is malformed)") }
            if let se = artifactSuiteError(v) { return fail("verdict signature suite: \(se)") }
            let cid = v["classifier"]!.asString!
            guard let c = cls.first(where: { IV.same($0["id"]?.asString, cid) }) else { return fail("verdict for undeclared classifier '\(cid)'") }
            let judge = v["judge"]!.asString!
            if !(c["keys"]?.asArray ?? []).contains(where: { IV.same($0.asString, judge) }) { return fail("classifier '\(cid)': judge key is not on the allowlist") }
            if !verifyArtifactSig(CLASSIFIER_DOMAIN, v, judge, pqPin: c["pq_keys"]?.asObject?[JKey(judge)]?.asString) { return fail("classifier '\(cid)': bad verdict signature") }
            if !IV.same(v["session"]?.asString, session) { return fail("classifier '\(cid)': verdict bound to another session") }
            guard let content = resolveParamPath(params, c["param"]!.asString!) else { return fail("classifier '\(cid)': the action carries no '\(c["param"]!.asString!)'") }
            if let ce = IV.strictCanonError(content) { return fail("evaluation error (fail closed): \(ce)") }
            guard let cd = IV.strictHash(content) else { return fail("evaluation error (fail closed): content is not strictly canonical") }
            if !IV.same(cd, v["content_digest"]?.asString) { return fail("classifier '\(cid)': verdict is about other content") }
            let label = v["label"]!.asString!
            if !(c["labels"]?.asArray ?? []).contains(where: { IV.same($0.asString, label) }) { return fail("classifier '\(cid)': label '\(label)' is not in its label set") }
            if let ms = c["measurements"]?.asArray, !ms.contains(where: { IV.same($0.asString, v["measurement"]?.asString) }) {
                return fail("classifier '\(cid)': measurement is not pinned")
            }
            if !pairs.insert(JKey(cid + "\u{0}" + judge)).inserted { return fail("classifier '\(cid)': two verdicts from one judge") }
            votes[JKey(cid), default: [:]][JKey(label), default: 0] += 1
        }
        var classes: JObject = [:]
        for c in cls {
            let id = c["id"]!.asString!
            let k = IV.int(c["k"])!
            let t = votes[JKey(id)] ?? [:]
            let winners = (c["labels"]?.asArray ?? []).compactMap { $0.asString }.filter { Int64(t[JKey($0)] ?? 0) >= k }
            if winners.isEmpty { return fail("classifier '\(id)': no label reaches the quorum \(k)") }
            if winners.count > 1 { return fail("classifier '\(id)': ambiguous, \(winners.count) labels reach the quorum") }
            classes[JKey(id)] = .string(winners[0])
        }
        return (true, classes, "")
    }

    // ---- composition (intent-env.ts decideIntentWB) ----

    struct WBResult {
        var outcome = "admit" // admit | question | deny
        var checks: [(String, String)] = [] // (facts|provenance|classes, pass|question|fail) in order
        var world: JObject?
        var prov: JObject?
        var cls: JObject?
        var singleSource: [String] = [] // worlds decided by ONE oracle (rule 21: env.world.<name> is then model-derived)
        var reason: String?
    }

    /// `now`: the clock (nil when it is not a safe integer: facts and offer sets are then stale).
    static func decide(now: Int64?, aud: String, session: String, action: JSONValue, intentSession: JSONValue, artifacts: JSONValue?, policy: JSONValue?) -> WBResult {
        var out = WBResult()
        // `intentWBContextError`: artifacts {facts?, labels?, verdicts?, offer_set?} and policy {world?, provenance?,
        // classifiers?} are closed; a malformed W-B context fails `facts`, the first check of the unit
        if let a = artifacts?.asObject, let e = closedMembersError(a, [], ["facts", "labels", "verdicts", "offer_set"], "artifacts") {
            out.outcome = "deny"; out.checks = [("facts", "fail")]; out.reason = "facts: the W-B context is malformed: \(e)"
            return out
        }
        if let p = policy?.asObject, let e = closedMembersError(p, [], ["world", "provenance", "classifiers"], "policy") {
            out.outcome = "deny"; out.checks = [("facts", "fail")]; out.reason = "facts: the W-B context is malformed: \(e)"
            return out
        }
        let s = intentSession
        let worldPolicy = policy?.get("world") ?? .object([:])
        let committed: JSONValue = .object(["facts": s.get("facts"), "offer_set": s.get("offer_set")].compactMapValues { $0 })
        if worldActive(committed: committed, policy: worldPolicy) {
            let w = decideWorld(now: now, aud: aud, session: session, action: action, committed: committed, facts: artifacts?.get("facts"),
                                offerSet: artifacts?.get("offer_set"), policy: worldPolicy)
            if !w.ok { out.outcome = "deny"; out.checks = [("facts", "fail")]; out.reason = w.reason; return out }
            out.checks.append(("facts", "pass"))
            out.world = w.world
            out.singleSource = w.singleSource
        }
        let provPolicy = policy?.get("provenance")
        if provenanceActive(prov: s.get("prov"), labels: s.get("labels"), policy: provPolicy) {
            let p = decideProvenance(aud: aud, session: session, params: action.get("params"), prov: s.get("prov"), committedLabels: s.get("labels"),
                                     labels: artifacts?.get("labels"), policy: provPolicy ?? .object(["params": .object([:])]))
            if p.outcome == "deny" { out.outcome = "deny"; out.checks.append(("provenance", "fail")); out.reason = p.reason; return out }
            out.checks.append(("provenance", p.outcome == "question" ? "question" : "pass"))
            out.prov = p.env
            if p.outcome == "question" { out.outcome = "question"; out.reason = p.reason }
        }
        let classifiers = policy?.get("classifiers") ?? .array([])
        if classifierActive(committed: s.get("classes"), classifiers: classifiers) {
            let c = decideClassifiers(session: session, params: action.get("params"), committed: s.get("classes"), verdicts: artifacts?.get("verdicts"),
                                      policy: .object(["classifiers": classifiers]))
            if !c.ok { out.outcome = "deny"; out.checks.append(("classes", "fail")); out.reason = c.reason; return out }
            out.checks.append(("classes", "pass"))
            out.cls = c.classes
        }
        return out
    }
}

extension PCA {
    /// Rule 16 on its own (`primitives.intent_world`): `{now, aud, session, action, committed, facts?, offer_set?, policy}`.
    public static func intentWorldPrimitive(_ input: JSONValue) -> (ok: Bool, world: JSONValue?, singleSource: [String]?, reason: String) {
        let i = IV.normalized(input)
        guard let aud = i.get("aud")?.asString, let session = i.get("session")?.asString else { return (false, nil, nil, "facts: malformed input") }
        let d = IntentWB.decideWorld(now: IV.int(i.get("now")), aud: aud, session: session, action: i.get("action") ?? .null, committed: i.get("committed"),
                                     facts: i.get("facts"), offerSet: i.get("offer_set"), policy: i.get("policy"))
        return d.ok ? (true, .object(d.world), d.singleSource, "") : (false, nil, nil, d.reason)
    }

    /// Rule 17 on its own (`primitives.intent_provenance`): `{aud, session, action: {params}, prov?, committed_labels?, labels?, policy}`
    /// -> outcome (`pass` / `question` / `deny`), and unless deny the labels, the classes and (question) the friction.
    public static func intentProvenancePrimitive(_ input: JSONValue)
        -> (outcome: String, labels: [String: String], classes: [String: [String]], friction: String?, reason: String) {
        let i = IV.normalized(input)
        guard let aud = i.get("aud")?.asString, let session = i.get("session")?.asString else { return ("deny", [:], [:], nil, "provenance: malformed input") }
        guard i.get("action")?.isObject == true else { return ("deny", [:], [:], nil, "provenance: action must be an object") }
        let d = IntentWB.decideProvenance(aud: aud, session: session, params: i.get("action")?.get("params"), prov: i.get("prov"),
                                          committedLabels: i.get("committed_labels"), labels: i.get("labels"), policy: i.get("policy") ?? .null)
        return (d.outcome, d.labels, d.classes, d.friction, d.reason)
    }

    /// Activity on its own (`primitives.intent_wb_active`): `{intent_session, policy: {world?, provenance?, classifiers?}}`
    /// -> which of `facts` / `provenance` / `classes` a verifier reports.
    public static func intentWBActivePrimitive(_ input: JSONValue) -> (facts: Bool, provenance: Bool, classes: Bool) {
        let i = IV.normalized(input)
        let s = i.get("intent_session")
        let p = i.get("policy")
        var committed: JObject = [:]
        if let f = s?.get("facts") { committed["facts"] = f }
        if let o = s?.get("offer_set") { committed["offer_set"] = o }
        let world = p?.get("world")
        return (IntentWB.worldActive(committed: .object(committed), policy: world ?? .object([:])),
                IntentWB.provenanceActive(prov: s?.get("prov"), labels: s?.get("labels"), policy: p?.get("provenance")),
                IntentWB.classifierActive(committed: s?.get("classes"), classifiers: p?.get("classifiers")))
    }

    /// Rule 18 on its own (`primitives.intent_classifier`): `{session, action: {params}, committed?, verdicts?, policy}`.
    public static func intentClassifierPrimitive(_ input: JSONValue) -> (ok: Bool, classes: JSONValue?, reason: String) {
        let i = IV.normalized(input)
        let session = i.get("session")?.asString
        guard i.get("action")?.isObject == true else { return (false, nil, "classes: action must be an object") }
        let d = IntentWB.decideClassifiers(session: session, params: i.get("action")?.get("params"), committed: i.get("committed"),
                                           verdicts: i.get("verdicts"), policy: i.get("policy") ?? .null)
        // a non-string session is malformed input: refused, with the reference's reason when a check fails first
        if session == nil && d.ok { return (false, nil, "classes: malformed input") }
        return d.ok ? (true, .object(d.classes), "") : (false, nil, d.reason)
    }

    /// Read purpose (`primitives.intent_read_purpose`, `decideReadPurpose`): `{fields: [{path, class, optional?}], purpose,
    /// coverage: {purpose: [pattern]}, on_uncovered?}`. Optional uncovered fields are minimised, required uncovered ones make
    /// the read `on_uncovered` (`question` by default, or `deny`); `public` is always covered; `coverage[purpose]` is an own
    /// member (patterns: a class, `p.*`, `*`). Both lists are de-duplicated and sorted in UTF-8 byte order. Malformed input
    /// (JSON null included) is `deny` with empty lists.
    public static func intentReadPurposePrimitive(_ input: JSONValue) -> (outcome: String, minimise: [String], uncovered: [String]) {
        let malformed = ("deny", [String](), [String]())
        let i = IV.normalized(input)
        guard case let .array(fields)? = i.get("fields"), let purpose = i.get("purpose")?.asString, case let .object(coverage)? = i.get("coverage") else { return malformed }
        var onUncovered = "question"
        if let ou = i.get("on_uncovered") {
            guard let o = ou.asString, o == "question" || o == "deny" else { return malformed }
            onUncovered = o
        }
        for pats in coverage.values {
            guard case let .array(a) = pats, a.allSatisfy({ $0.asString != nil }) else { return malformed }
        }
        let patterns = (coverage[JKey(purpose)]?.asArray ?? []).compactMap { $0.asString }
        func covered(_ cls: String) -> Bool {
            IV.same(cls, "public") || patterns.contains { p in
                IV.same(p, "*") || IV.same(p, cls) || (IV.endsWith(p, ".*") && IV.startsWith(cls, IV.text(p.unicodeScalars.dropLast())))
            }
        }
        var minimise: [String] = [], uncovered: [String] = []
        for f in fields {
            guard case let .object(fo) = f, let path = fo["path"]?.asString, let cls = fo["class"]?.asString else { return malformed }
            var optional = false
            if let o = fo["optional"] {
                guard case let .bool(b) = o else { return malformed }
                optional = b
            }
            if covered(cls) { continue }
            if optional { if !IV.contains(minimise, path) { minimise.append(path) } } else if !IV.contains(uncovered, path) { uncovered.append(path) }
        }
        return (uncovered.isEmpty ? "allow" : onUncovered, minimise.sorted(by: IV.utf8Less), uncovered.sorted(by: IV.utf8Less))
    }
}
