import Foundation

/// Trajectory state at the verifier (Intent Layer v2 V2/V3; conformance rule 15). Mirrors `packages/pca/src/intent-acc.ts`:
/// accumulator and monitor declarations, selection, val(ω), the host-injected pre-state and its combination, sequencer
/// reservation receipts (`pca-acc-receipt` v1) resolved through the sequencer's root-signed key set (`pca-sequencer-keys`
/// v1), the reservation digest and the receipt arithmetic.
enum IntentAcc {
    static let AGGS = ["sum", "count", "distinct", "max"]
    static let MONITOR_KINDS = ["requires_prior", "precedes", "never", "always", "responds_within"]
    static let MAX_SESSION_ACCUMULATORS = 16
    static let MAX_SESSION_MONITORS = 16
    static let MAX_MONITOR_WITHIN: Int64 = 64
    static let RECEIPT_DOMAIN = "atlas-pca/acc-receipt/v1\u{0}"
    static let RECEIPT_REF_DOMAIN = "atlas-pca/acc-receipt-ref/v1"
    static let RESERVE_DOMAIN = "atlas-pca/acc-reserve/v1"
    static let SEQUENCER_KEYS_DOMAIN = "atlas-pca/sequencer-keys/v1\u{0}"
    static let RECEIPT_SKEW_MS = 60_000.0
    /// A receipt lives at most 15 min: `issued_at <= expires_at <= issued_at + MAX_RECEIPT_LIFETIME_MS`.
    static let MAX_RECEIPT_LIFETIME_MS: Int64 = 900_000
    /// Default bounds (policy `acc.max_receipt_age_s` / `acc.max_keyset_age_s`): 15 min and 1 h.
    static let DEFAULT_MAX_RECEIPT_AGE_MS = 900_000.0
    static let DEFAULT_MAX_KEYSET_AGE_MS = 3_600_000.0

    static let SEQUENCER_KEYS_REF_DOMAIN = "atlas-pca/sequencer-keys-ref/v1"

    /// A key set's content address: base64url(sha256(strictCanonical({"d": "atlas-pca/sequencer-keys-ref/v1", "k": set}))).
    static func keySetDigest(_ ks: JSONValue) -> String? { IV.strictHash(.object(["d": .string(SEQUENCER_KEYS_REF_DOMAIN), "k": ks])) }

    /// The newest key set a verifier has accepted for one sequencer root (`acc.keyset_versions[root]`).
    struct TrackedKeySet { let version: Int64; let digest: String }

    /// `acc.keyset_versions[root]` is exactly `{version, digest}`: version a safe integer >= 1, digest canonical base64url (32 bytes).
    static func trackedKeySetError(_ v: JSONValue) -> String? {
        guard case let .object(o) = v else { return "a tracked key set must be an object {version, digest}" }
        for k in o.keys where k.s != "version" && k.s != "digest" { return "a tracked key set has the unknown member '\(k.s)'" }
        guard let ver = IV.int(o["version"]), ver >= 1 else { return "a tracked key set version must be a safe integer >= 1" }
        if IV.digest(o["digest"]) == nil { return "a tracked key set digest must be canonical base64url (32 bytes)" }
        return nil
    }
    static func trackedKeySet(_ v: JSONValue?) -> TrackedKeySet? {
        guard let x = v, trackedKeySetError(x) == nil else { return nil }
        return TrackedKeySet(version: IV.int(x.get("version"))!, digest: x.get("digest")!.asString!)
    }

    /// Freshness bounds of receipt verification: receipt age, key-set age, and the tracked key set of the holder's root.
    struct Freshness {
        var maxReceiptAgeMs = DEFAULT_MAX_RECEIPT_AGE_MS
        var maxKeySetAgeMs = DEFAULT_MAX_KEYSET_AGE_MS
        var tracked: TrackedKeySet?
    }
    static let RECEIPT_KEYS = ["v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid",
                               "ledger", "signer", "alg", "pq_pk", "sig", "pq_sig"]

    private static func has(_ list: [String], _ k: JKey) -> Bool { list.contains { JKey($0) == k } }
    private static func isIn(_ list: [String], _ v: JSONValue?) -> Bool { v?.asString.map { IV.contains(list, $0) } ?? false }
    private static func exactKeys(_ o: JObject, _ keys: [String]) -> Bool { o.count == keys.count && keys.allSatisfy { o[JKey($0)] != nil } }

    /// `^[A-Za-z0-9_.:-]{1,64}$`
    static func isKid(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        return (1...64).contains(u.count) && u.allSatisfy {
            ($0.value >= 0x30 && $0.value <= 0x39) || ($0.value >= 0x41 && $0.value <= 0x5A) || ($0.value >= 0x61 && $0.value <= 0x7A)
                || $0 == "_" || $0 == "." || $0 == ":" || $0 == "-"
        }
    }

    static func accumulatorDeclError(_ av: JSONValue) -> String? {
        guard case let .object(a) = av else { return "accumulator must be an object" }
        for k in a.keys where !has(["id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder"], k) {
            return "accumulator: unknown member '\(k.s)'"
        }
        guard let id = a["id"]?.asString, IV.isId(id), !IV.isReserved(id) else {
            return "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
        }
        let at = "accumulator '\(id)'"
        if !isIn(AGGS, a["agg"]) { return "\(at): unknown agg" }
        let agg = a["agg"]!.asString!
        if let v = a["val"], !(v.asString.map(IV.isTopParamPath) ?? false) { return "\(at): val must be action.params.<name>" }
        if let u = a["unit"], !(u.asString.map { IV.u16($0) <= 64 && IV.isUnitId($0) } ?? false) { return "\(at): unit must be a unit id" }
        guard case let .object(sel)? = a["sel"] else { return "\(at): sel must be an object" }
        for k in sel.keys where !has(["verbs", "accumulates_into", "event"], k) { return "\(at): sel has unknown member '\(k.s)'" }
        if let vv = sel["verbs"] {
            guard case let .array(vs) = vv, !vs.isEmpty, vs.count <= 64, vs.allSatisfy({ ($0.asString.map { !$0.isEmpty }) ?? false }) else {
                return "\(at): sel.verbs must be 1..64 verb names"
            }
        }
        if let ai = sel["accumulates_into"], !(ai.asString.map(IV.isUnitId) ?? false) { return "\(at): sel.accumulates_into must be a unit id" }
        if let e = sel["event"], !isIn(["intent_required", "question", "clarification"], e) { return "\(at): unknown sel.event" }
        let actionSel = sel["verbs"] != nil || sel["accumulates_into"] != nil
        if actionSel == (sel["event"] != nil) { return "\(at): sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind" }
        guard case let .object(w)? = a["win"] else { return "\(at): win must be an object" }
        switch w["kind"]?.asString {
        case "task"?:
            if w.count != 1 { return "\(at): win {kind: task} has no other member" }
        case "sliding"?:
            if !exactKeys(w, ["kind", "ms"]) || !((IV.int(w["ms"]) ?? 0) > 0) { return "\(at): win sliding needs a positive ms" }
        case "period"?:
            if !exactKeys(w, ["kind", "ms", "t0"]) || !((IV.int(w["ms"]) ?? 0) > 0) || IV.nonNeg(w["t0"]) == nil {
                return "\(at): win period needs a positive ms and t0 >= 0"
            }
        default:
            return "\(at): unknown win kind"
        }
        if a["key"]?.isNull != true, !(a["key"]?.asString.map(IV.isTopParamPath) ?? false) { return "\(at): key must be null or action.params.<name>" }
        if let d = a["domain_max"], IV.nonNeg(d) == nil { return "\(at): domain_max must be a non-negative safe integer" }
        if let c = a["cap"], IV.nonNeg(c) == nil { return "\(at): cap must be a non-negative safe integer" }
        guard case let .object(h)? = a["holder"] else { return "\(at): holder must be an object" }
        let hk = h["kind"]?.asString ?? ""
        switch hk {
        case "site_local", "wallet":
            if h.count != 1 { return "\(at): holder \(hk) has no other member" }
        case "sequenced":
            for k in h.keys where !has(["kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri"], k) { return "\(at): holder sequenced has unknown member '\(k.s)'" }
            guard let uri = h["uri"]?.asString, !uri.isEmpty else { return "\(at): holder sequenced needs a uri" }
            if IV.digest(h["root"]) == nil { return "\(at): holder.root is not canonical base64url (32 bytes)" }
            if let se = IV.suiteError(h["root_alg"]) { return "\(at): holder.root_alg: \(se)" }
            if let rp = h["root_pq_pk"], !(rp.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "\(at): holder.root_pq_pk is not canonical base64url" }
            if let ku = h["keys_uri"], !(ku.asString.map { !$0.isEmpty } ?? false) { return "\(at): holder.keys_uri must be a non-empty string" }
        default:
            return "\(at): unknown holder kind"
        }
        let wallet = hk == "wallet"
        if wallet != (sel["event"] != nil) { return "\(at): wallet events are wallet-held and only wallet events are" }
        if !wallet {
            if agg != "count" && a["val"] == nil && sel["accumulates_into"] == nil { return "\(at): \(agg) needs val (or sel.accumulates_into for a sum)" }
            if agg != "sum" && agg != "count" && a["val"] == nil { return "\(at): \(agg) needs val" }
            if agg == "count" && a["val"] != nil { return "\(at): count takes no val" }
        }
        return nil
    }

    private static func predicateShapeOk(_ p: JSONValue?) -> Bool {
        guard case let .object(o)? = p else { return false }
        switch o["verb"] {
        case .string?: return true
        case let .array(a)?: return !a.isEmpty && a.allSatisfy { $0.asString != nil }
        default: return false
        }
    }

    static func monitorDeclError(_ mv: JSONValue) -> String? {
        guard case let .object(m) = mv else { return "monitor must be an object" }
        for k in m.keys where !has(["id", "kind", "p", "q", "status", "within"], k) { return "monitor: unknown member '\(k.s)'" }
        guard let id = m["id"]?.asString, IV.isId(id), !IV.isReserved(id) else {
            return "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
        }
        let at = "monitor '\(id)'"
        if !isIn(MONITOR_KINDS, m["kind"]) { return "\(at): unknown kind" }
        let kind = m["kind"]!.asString!
        if !predicateShapeOk(m["p"]) { return "\(at): p must be a predicate" }
        let needsQ = kind == "requires_prior" || kind == "precedes" || kind == "responds_within"
        if needsQ != (m["q"] != nil) { return "\(at): q is required exactly for requires_prior / precedes / responds_within" }
        if m["q"] != nil && !predicateShapeOk(m["q"]) { return "\(at): q must be a predicate" }
        if let s = m["status"], !isIn(["admitted", "committed"], s) { return "\(at): status must be admitted or committed" }
        if (kind == "responds_within") != (m["within"] != nil) { return "\(at): within is required exactly for responds_within" }
        if let w = m["within"], !((IV.int(w).map { $0 >= 1 && $0 <= MAX_MONITOR_WITHIN }) ?? false) { return "\(at): within must be an integer in 1..\(MAX_MONITOR_WITHIN)" }
        return nil
    }

    /// The state set Q of a monitor.
    static func monitorStates(_ m: JSONValue) -> [String] {
        switch m.get("kind")?.asString {
        case "requires_prior"?, "precedes"?: return ["unmet", "met"]
        case "never"?: return ["clean", "seen"]
        case "always"?: return ["ok", "broken"]
        case "responds_within"?:
            let w = IV.int(m.get("within")) ?? 0
            return ["idle"] + (w > 0 ? (1...w).map { "pending:\($0)" } : []) + ["missed"]
        default: return []
        }
    }

    // ---- selection, values, combination ----

    /// `accumulationParams(v, unit)`: the integer params of a verb entry whose `accumulates_into` lists `unit` (UTF-8 order).
    static func accumulationParams(_ v: JObject, _ unit: String) -> [String] {
        guard case let .object(ps)? = v["params"] else { return [] }
        return ps.keys.sorted().filter { k in
            guard case let .object(d)? = ps[k], IV.same(d["type"]?.asString, "integer") else { return false }
            guard case let .array(ai)? = d["accumulates_into"] else { return false }
            return ai.contains { IV.same($0.asString, unit) }
        }.map { $0.s }
    }

    /// `accSelects`: ω ∈ sel (action selectors only).
    static func selects(_ a: JObject, _ verb: String, _ schema: JSONValue?) -> Bool {
        guard case let .object(sel)? = a["sel"] else { return false }
        if sel["event"] != nil { return false }
        if case let .array(vs)? = sel["verbs"], vs.contains(where: { IV.same($0.asString, verb) }) { return true }
        if let unit = sel["accumulates_into"]?.asString, let s = schema {
            guard let v = ActionSchema.verb(s, verb) else { return false }
            return !accumulationParams(v, unit).isEmpty
        }
        return false
    }

    /// `distinctKey`: the strict canonical JSON text of a string or a safe integer (not -0).
    static func distinctKey(_ x: JSONValue?) -> String? {
        guard let x = x else { return nil }
        if case .string = x { return IV.strictCanon(x) }
        if let i = IV.int(x) { return String(i) }
        return nil
    }

    /// val(ω) for a selected action: (val, distinct key) or nil.
    static func valueOf(_ a: JObject, _ verb: String, _ params: JObject, _ schema: JSONValue?) -> (val: Double, key: String?)? {
        valueOfChecked(a, verb, params, schema).value
    }

    /// `accValueOf`: val(ω) for a selected action, or the reference's reason.
    static func valueOfChecked(_ a: JObject, _ verb: String, _ params: JObject, _ schema: JSONValue?) -> (value: (val: Double, key: String?)?, reason: String) {
        func read(_ path: String) -> JSONValue? { params[JKey(IV.dropPrefix(path, 14))] }
        let agg = a["agg"]?.asString ?? ""
        if agg == "count" { return ((1, nil), "") }
        let valPath = a["val"]?.asString
        if agg == "distinct" {
            guard let vp = valPath, let k = distinctKey(read(vp)) else { return (nil, "\(IntentWB.jsOpt(a["val"])) must be a string or a safe integer") }
            return ((1, k), "")
        }
        if let vp = valPath {
            guard let x = IV.nonNeg(read(vp)) else { return (nil, "\(vp) must be a non-negative safe integer") }
            return ((Double(x), nil), "")
        }
        guard let s = schema, let v = ActionSchema.verb(s, verb), let unit = a["sel"]?.get("accumulates_into")?.asString else {
            return (nil, "no schema entry for '\(verb)' to read accumulates_into")
        }
        var sum = 0.0
        for p in accumulationParams(v, unit) {
            guard let x = read(p) else { continue }
            guard let n = IV.nonNeg(x) else { return (nil, "\(p) must be a non-negative safe integer") }
            sum += Double(n)
            if !IV.isSafeDouble(sum) { return (nil, "accumulated value exceeds 2^53-1") }
        }
        return ((sum, nil), "")
    }

    static func preKey(_ agg: String) -> String { agg == "sum" ? "sum" : agg == "count" ? "count" : agg == "max" ? "max" : "values" }

    /// `preStateError`: nil when the injected pre-state is exactly `{sum}` / `{count}` / `{max}` (a non-negative safe
    /// integer) or `{values}` (distinct strings).
    static func preStateError(_ agg: String, _ s: JSONValue) -> String? {
        guard case let .object(o) = s else { return "pre-state must be an object" }
        let want = preKey(agg)
        if !(o.count == 1 && o[JKey(want)] != nil) { return "pre-state of a \(agg) accumulator is {\(want)}" }
        if want == "values" {
            guard case let .array(vs)? = o["values"] else { return "pre-state values must be strings" }
            let ss = vs.compactMap { $0.asString }
            if ss.count != vs.count { return "pre-state values must be strings" }
            if !IV.distinct(ss) { return "pre-state values must be distinct" }
            return nil
        }
        return IV.nonNeg(o[JKey(want)]) == nil ? "pre-state \(want) must be a non-negative safe integer" : nil
    }

    /// The post-action value from a well-formed pre-state; nil when it leaves the safe-integer range.
    static func combine(_ agg: String, _ pre: JSONValue, _ val: Double, _ key: String?) -> Double? {
        let post: Double
        switch agg {
        case "sum": post = Double(IV.nonNeg(pre.get("sum")) ?? 0) + val
        case "count": post = Double(IV.nonNeg(pre.get("count")) ?? 0) + 1
        case "max": post = max(Double(IV.nonNeg(pre.get("max")) ?? 0), val)
        default:
            let vs = (pre.get("values")?.asArray ?? []).compactMap { $0.asString }
            post = Double(vs.count) + (key.map { IV.contains(vs, $0) } == true ? 0 : 1)
        }
        return IV.isSafeDouble(post) ? post : nil
    }

    static func preValue(_ agg: String, _ pre: JSONValue) -> Double {
        switch agg {
        case "sum": return Double(IV.nonNeg(pre.get("sum")) ?? 0)
        case "count": return Double(IV.nonNeg(pre.get("count")) ?? 0)
        case "max": return Double(IV.nonNeg(pre.get("max")) ?? 0)
        default: return Double(pre.get("values")?.asArray?.count ?? 0)
        }
    }

    // ---- reservation receipts ----

    /// `pcactnReservationDigest(p)`: base64url(sha256(strictCanonical({d, b: p without sig, pq_sig, threshold, intent_session}))).
    static func reservationDigest(_ p: JObject) -> String? {
        var b = p
        for k in ["sig", "pq_sig", "threshold", "intent_session"] { b[JKey(k)] = nil }
        return IV.strictHash(.object(["d": .string(RESERVE_DOMAIN), "b": .object(b)]))
    }

    static func receiptShapeError(_ rv: JSONValue) -> String? {
        guard case let .object(r) = rv else { return "receipt is not an object" }
        for k in r.keys where !has(RECEIPT_KEYS, k) { return "receipt: unknown member '\(k.s)'" }
        if IV.num(r["v"]) != 1 || !IV.same(r["kind"]?.asString, "pca-acc-receipt") { return "not a pca-acc-receipt v1" }
        if IV.digest(r["session"]) == nil { return "receipt.session is not canonical base64url (32 bytes)" }
        if !(r["acc"]?.asString.map(IV.isId) ?? false) { return "receipt.acc is not an accumulator id" }
        if !((IV.int(r["seq"]) ?? 0) >= 1) { return "receipt.seq must be a safe integer >= 1" }
        if IV.nonNeg(r["pre"]) == nil || IV.nonNeg(r["delta"]) == nil || IV.nonNeg(r["post"]) == nil {
            return "receipt pre / delta / post must be non-negative safe integers"
        }
        if IV.digest(r["pcactn_digest"]) == nil { return "receipt.pcactn_digest is not canonical base64url (32 bytes)" }
        if !(r["aud"]?.asString.map { !$0.isEmpty } ?? false) { return "receipt.aud must be a non-empty string" }
        guard let ia = IV.nonNeg(r["issued_at"]), let ea = IV.nonNeg(r["expires_at"]) else { return "receipt.issued_at / expires_at must be non-negative safe integers" }
        if !(ea >= ia && ea - ia <= MAX_RECEIPT_LIFETIME_MS) { return "receipt.expires_at must be within \(MAX_RECEIPT_LIFETIME_MS) ms after issued_at" }
        if !(r["kid"]?.asString.map(isKid) ?? false) { return "receipt.kid must match [A-Za-z0-9_.:-]{1,64}" }
        guard case let .object(l)? = r["ledger"], exactKeys(l, ["head", "index"]), IV.nonNeg(l["index"]) != nil, IV.digest(l["head"]) != nil else {
            return "receipt.ledger must be {index, head}"
        }
        if IV.digest(r["signer"]) == nil { return "receipt.signer is not canonical base64url (32 bytes)" }
        if let se = IV.suiteError(r["alg"]) { return "receipt.alg: \(se)" }
        let suite = IV.sigAlg(r["alg"])!
        if suite == "ed25519" && (r["pq_pk"] != nil || r["pq_sig"] != nil) { return "an ed25519 receipt must not carry pq_pk / pq_sig" }
        if r["sig"]?.asString == nil { return "receipt.sig must be a string" }
        return nil
    }

    static func receiptBody(_ r: JObject) -> JObject {
        var out: JObject = [:]
        for k in ["v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid", "signer"] {
            out[JKey(k)] = r[JKey(k)]
        }
        out["ledger"] = .object(["index": r["ledger"]?.get("index") ?? .null, "head": r["ledger"]?.get("head") ?? .null])
        return out
    }

    /// `verifyAccReceiptSignature(r, expectedSigner, pin)`.
    static func verifyReceiptSignature(_ rv: JSONValue, expectedSigner: String, pin: String?) -> IV.SuiteVerdict {
        guard receiptShapeError(rv) == nil, case let .object(r) = rv, let signer = r["signer"]?.asString, IV.same(signer, expectedSigner),
              let bound = IV.bindSuite(receiptBody(r), alg: r["alg"], pqPk: r["pq_pk"]),
              let msg = IV.message(RECEIPT_DOMAIN, .object(bound)) else { return .invalid }
        return IV.verifyPinned(alg: r["alg"], identity: signer, artifactPqPk: r["pq_pk"], msg: msg, sig: r["sig"], pqSig: r["pq_sig"], pin: pin)
    }

    /// `accReceiptDigest(r)` = base64url(sha256(strictCanonical({d, r}))).
    static func receiptDigest(_ r: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(RECEIPT_REF_DOMAIN), "r": r]))
    }

    // ---- the sequencer's root-signed key set ----

    static func keySetShapeError(_ kv: JSONValue) -> String? {
        guard case let .object(k) = kv else { return "key set is not an object" }
        for x in k.keys where !has(["v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig"], x) { return "key set: unknown member '\(x.s)'" }
        if IV.num(k["v"]) != 1 || !IV.same(k["kind"]?.asString, "pca-sequencer-keys") { return "not a pca-sequencer-keys v1" }
        if IV.digest(k["sequencer"]) == nil { return "sequencer is not canonical base64url (32 bytes)" }
        if !((IV.nonNeg(k["version"]) ?? 0) >= 1) { return "version must be a safe integer >= 1" }
        if IV.nonNeg(k["issued_at"]) == nil { return "issued_at must be a non-negative safe integer" }
        guard case let .array(keys)? = k["keys"], !keys.isEmpty, keys.count <= 256 else { return "keys must be 1..256 entries" }
        var kids = Set<JKey>()
        for ev in keys {
            guard case let .object(e) = ev, e.keys.allSatisfy({ has(["kid", "pk", "alg", "pq_pk", "not_before", "not_after"], $0) }) else {
                return "keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}"
            }
            guard let kid = e["kid"]?.asString, isKid(kid), kids.insert(JKey(kid)).inserted else { return "key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct" }
            if IV.digest(e["pk"]) == nil { return "key pk is not canonical base64url (32 bytes)" }
            if let se = IV.suiteError(e["alg"]) { return "key alg: \(se)" }
            if let pk = e["pq_pk"], !(pk.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "key pq_pk is not canonical base64url" }
            guard let nb = IV.nonNeg(e["not_before"]) else { return "key validity must be 0 <= not_before <= not_after" }
            if e["not_after"] != nil, !((IV.nonNeg(e["not_after"]).map { $0 >= nb }) ?? false) { return "key validity must be 0 <= not_before <= not_after" }
        }
        if let se = IV.suiteError(k["alg"]) { return "alg: \(se)" }
        let suite = IV.sigAlg(k["alg"])!
        if suite == "ed25519" && (k["pq_pk"] != nil || k["pq_sig"] != nil) { return "an ed25519 key set must not carry pq_pk / pq_sig" }
        if k["sig"]?.asString == nil { return "sig must be a string" }
        return nil
    }

    /// `verifySequencerKeySet(k, root, rootPqPk)`: shape, `sequencer == root`, signature under the root (PQ pinned by `rootPqPk`).
    static func verifyKeySet(_ kv: JSONValue, root: String, rootPqPk: JSONValue?) -> IV.SuiteVerdict {
        if let e = keySetShapeError(kv) { return e.contains(IV.UNSUPPORTED_SUITE) ? .unsupported : .invalid }
        guard case let .object(k) = kv, IV.same(k["sequencer"]?.asString, root) else { return .invalid }
        let body: JObject = ["v": k["v"]!, "kind": k["kind"]!, "sequencer": k["sequencer"]!, "version": k["version"]!, "issued_at": k["issued_at"]!, "keys": k["keys"]!]
        guard let bound = IV.bindSuite(body, alg: k["alg"], pqPk: k["pq_pk"]), let msg = IV.message(SEQUENCER_KEYS_DOMAIN, .object(bound)) else { return .invalid }
        let pin = rootPqPk.map { $0.asString ?? "" }
        return IV.verifyPinned(alg: k["alg"], identity: root, artifactPqPk: k["pq_pk"], msg: msg, sig: k["sig"], pqSig: k["pq_sig"], pin: pin)
    }

    /// `verifyReceiptAgainstHolder(r, holder, keySets, now)` (rule 15, sequenced): some presented key set verifies under
    /// `holder.root` and lists `receipt.kid` with `pk == receipt.signer`, valid at `issued_at`, with the receipt's suite;
    /// `issued_at <= now + 60000`; the receipt verifies under that entry (PQ pinned by the entry).
    static func verifyAgainstHolder(_ rv: JSONValue, holder: JObject, keySets: JSONValue?, now: Double, fresh: Freshness = Freshness()) -> IV.SuiteVerdict {
        if !IV.isSafeDouble(now) || !(IV.isSafeDouble(fresh.maxReceiptAgeMs) && fresh.maxReceiptAgeMs >= 0)
            || !(IV.isSafeDouble(fresh.maxKeySetAgeMs) && fresh.maxKeySetAgeMs >= 0) { return .invalid }
        let sets: [JSONValue]
        switch keySets {
        case nil: sets = []
        case let .array(a)?: sets = a
        default: return .invalid // not a list: fail closed
        }
        if let e = receiptShapeError(rv) { return e.contains(IV.UNSUPPORTED_SUITE) ? .unsupported : .invalid }
        guard case let .object(r) = rv, let issued = IV.num(r["issued_at"]), let root = holder["root"]?.asString else { return .invalid }
        // receipt freshness: issued at most 60 s in the future, at most maxReceiptAgeMs old
        if !(issued <= now + RECEIPT_SKEW_MS) || !(now - issued <= fresh.maxReceiptAgeMs) { return .invalid }
        var unsupported = false
        for k in sets {
            switch verifyKeySet(k, root: root, rootPqPk: holder["root_pq_pk"]) {
            case .valid: break
            case .unsupported: unsupported = true; continue
            case .invalid: continue
            }
            // the tracked {version, digest}: an older set is a rollback, ANOTHER set under the same version an equivocation (skip)
            if let t = fresh.tracked {
                let v = IV.nonNeg(k.get("version")) ?? 0
                if v < t.version || (v == t.version && !IV.same(keySetDigest(k), t.digest)) { continue }
            }
            guard let ksIssued = IV.num(k.get("issued_at")), ksIssued <= now + RECEIPT_SKEW_MS, now - ksIssued <= fresh.maxKeySetAgeMs else { continue }
            guard let e = k.get("keys")?.asArray?.first(where: { IV.same($0.get("kid")?.asString, r["kid"]?.asString) })?.asObject else { continue }
            guard let pk = e["pk"]?.asString, IV.same(pk, r["signer"]?.asString) else { continue }
            if issued < (IV.num(e["not_before"]) ?? .infinity) { continue }
            // a retired key stops verifying once retired: issued_at <= not_after AND now - 60 s <= not_after
            if let na = e["not_after"] {
                let n = IV.num(na) ?? -.infinity
                if issued > n || n < now - RECEIPT_SKEW_MS { continue }
            }
            if IV.sigAlg(e["alg"]) != IV.sigAlg(r["alg"]) { continue }
            let pin = e["pq_pk"].map { $0.asString ?? "" }
            switch verifyReceiptSignature(rv, expectedSigner: pk, pin: pin) {
            case .valid: return .valid
            case .unsupported: unsupported = true
            case .invalid: break
            }
        }
        return unsupported ? .unsupported : .invalid
    }

    /// `receiptArithmeticOk(a, r, val)`.
    static func receiptArithmeticOk(_ agg: String, _ r: JSONValue, _ val: Double) -> Bool {
        guard let pre = IV.num(r.get("pre")), let delta = IV.num(r.get("delta")), let post = IV.num(r.get("post")) else { return false }
        switch agg {
        case "sum": return delta == val && post == pre + delta
        case "count": return delta == 1 && post == pre + 1
        case "max": return delta == val && post == max(pre, delta)
        default: return (delta == 0 || delta == 1) && post == pre + delta
        }
    }
}
