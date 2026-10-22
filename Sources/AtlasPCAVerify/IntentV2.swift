import Foundation

/// The Intent Layer v2 verifier state + policy (`IntentV2Context` of `packages/pca/src/intent-v2.ts`), held as the JSON
/// object the reference reads: `{policy?: {session?: {require?, max_revocation_age_s?}, schema?: {closed_world?}}, params?,
/// schema?: {docs, keys}, session?: {root?, grants?, revocation?: {epoch, proofs}}, layers?: {org?, site?, std?},
/// wb?: {artifacts?: {facts?, offer_set?, labels?, verdicts?}, policy?: {world?, provenance?, classifiers?}},
/// acc?: {state?, monitors?, receipts?, last_seq?, sequencer_keys?}}`. Everything in it is VERIFIER state.
public struct IntentV2Context {
    public let value: JSONValue
    public init(_ value: JSONValue) { self.value = IV.normalized(value) }

    /// From the PRESENT member `context.intent_v2` (pass nothing when it is absent). A value that is not a JSON object
    /// (JSON null included) is a MALFORMED context, never "no context": every v2 check that would be reported fails with
    /// "malformed v2 context: the v2 verifier context must be an object", as in the reference. (It used to be nil, which a
    /// caller turned into no context: v2 enforcement silently off on a misconfigured verifier.) Never nil now.
    public static func fromJSON(_ v: JSONValue) -> IntentV2Context? { IntentV2Context(v) }

    /// Parse raw JSON text with the lenient loader (any JSON number form) and apply `fromJSON`.
    public static func fromJSONText(_ text: String) -> IntentV2Context? {
        guard let v = try? StrictJSON.parseLenient(text), v.isObject else { return nil }
        return fromJSON(v)
    }
}

/// The verifier-computed predicate environment of the admitting root: `canon` (schema passed), `acc` / `mon`
/// (accumulators passed), `world` / `prov` / `class` (W-B passed). A host REPLACES any member of these names it supplies.
public struct IntentV2Env {
    public var canon: JObject?
    public var acc: JObject?
    public var mon: JObject?
    public var world: JObject?
    public var prov: JObject?
    public var cls: JObject?

    public var json: JSONValue {
        var o: JObject = [:]
        if let x = canon { o["canon"] = .object(x) }
        if let x = acc { o["acc"] = .object(x) }
        if let x = mon { o["mon"] = .object(x) }
        if let x = world { o["world"] = .object(x) }
        if let x = prov { o["prov"] = .object(x) }
        if let x = cls { o["class"] = .object(x) }
        return .object(o)
    }
}

enum IntentV2 {
    struct Check { let name: String; let ok: Bool; let reason: String }

    /// ECMAScript String(p.action?.<k>), as the reference builds the action: absent => "undefined".
    static func actionString(_ p: JObject, _ k: String) -> String {
        guard let a = p["action"], case let .object(o) = a, let v = o[JKey(k)] else { return "undefined" }
        return jsString(v)
    }

    /// ECMAScript String(v) of a JSON value.
    static func jsString(_ v: JSONValue) -> String {
        switch v {
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case let .int(i): return String(i)
        case let .double(d): return d == 0 ? "0" : Canonical.numberString(d)
        case let .string(s): return s
        case let .array(a): return a.map { if case .null = $0 { return "" } else { return jsString($0) } }.joined(separator: ",")
        case .object: return "[object Object]"
        }
    }

    /// Result of one step: nil = pass, else the failure reason (first failing step wins).
    typealias Step = String?

    static func optObj(_ v: JSONValue?) -> Bool { v == nil || v!.isObject }
    static func isBool(_ v: JSONValue) -> Bool { if case .bool = v { return true }; return false }
    static func optArr(_ v: JSONValue?) -> Bool { v == nil || v!.isArray }

    /// `intentV2ContextError`: ABSENT members mean empty / default; a member PRESENT with null (or of the wrong JSON type)
    /// is malformed. Covers the members passed through to the `layers` and W-B checks too.
    static func contextError(_ ctx: JSONValue?) -> String? {
        guard let c = ctx else { return nil }
        guard case let .object(o) = c else { return "the v2 verifier context must be an object" }
        let pol = o["policy"]
        if !optObj(pol) { return "policy must be an object" }
        if case let .object(po)? = pol {
            // closed member sets; every flag a JSON boolean and every number a non-negative safe integer when present
            for k in po.keys where !["session", "schema", "acc", "map"].contains(k.s) { return "policy: unknown member '\(k.s)'" }
            if let pa = po["acc"] {
                guard case let .object(o) = pa else { return "policy.acc must be an object" }
                for k in o.keys where k.s != "max_receipt_age_s" && k.s != "max_keyset_age_s" { return "policy.acc: unknown member '\(k.s)'" }
                for k in ["max_receipt_age_s", "max_keyset_age_s"] { if let v = o[JKey(k)], !IV.isSafeNonNeg(v) { return "policy.acc.\(k) must be a non-negative safe integer" } }
            }
            if let pm = po["map"] {
                guard case let .object(o) = pm else { return "policy.map must be an object" }
                for k in o.keys where k.s != "require" && k.s != "max_residual_risk_ppm" { return "policy.map: unknown member '\(k.s)'" }
                if let r = o["require"], !isBool(r) { return "policy.map.require must be a boolean" }
                if let e = o["max_residual_risk_ppm"], !IV.isSafeNonNeg(e) { return "policy.map.max_residual_risk_ppm must be a non-negative safe integer" }
            }
            if let ps = po["session"] {
                guard case let .object(o) = ps else { return "policy.session must be an object" }
                for k in o.keys where k.s != "require" && k.s != "max_revocation_age_s" { return "policy.session: unknown member '\(k.s)'" }
                if let r = o["require"], !isBool(r) { return "policy.session.require must be a boolean" }
                if let m = o["max_revocation_age_s"], !IV.isSafeNonNeg(m) { return "policy.session.max_revocation_age_s must be a non-negative safe integer" }
            }
            if let pc = po["schema"] {
                guard case let .object(o) = pc else { return "policy.schema must be an object" }
                for k in o.keys where k.s != "closed_world" { return "policy.schema: unknown member '\(k.s)'" }
                if let c = o["closed_world"], !isBool(c) { return "policy.schema.closed_world must be a boolean" }
            }
        }
        if !optObj(o["params"]) { return "params must be an object" }
        for k in ["schema", "session", "acc"] where !optObj(o[JKey(k)]) { return "\(k) must be an object" }
        if let L = o["layers"] {
            guard case let .object(lo) = L else { return "layers must be an object" }
            for (k, v) in lo {
                if !["org", "site", "std"].contains(k.s) { return "layers: unknown member '\(k.s)'" }
                guard case let .object(lo) = v, case .array? = lo["predicates"] else { return "layers.\(k.s) must be {predicates: [...]}" }
            }
        }
        if let m = o["map"] {
            guard case let .object(mo) = m else { return "map must be an object" }
            for k in mo.keys where k.s != "disclosure" { return "map: unknown member '\(k.s)'" }
        }
        if let wb = o["wb"] {
            guard wb.isObject else { return "wb must be an object" }
            let a = wb.get("artifacts")
            if !optObj(a) { return "wb.artifacts must be an object" }
            for k in ["facts", "labels", "verdicts"] where !optArr(a?.get(k)) { return "wb.artifacts.\(k) must be an array" }
            if !optObj(a?.get("offer_set")) { return "wb.artifacts.offer_set must be an object" }
            let p = wb.get("policy")
            if !optObj(p) { return "wb.policy must be an object" }
            if !optObj(p?.get("world")) || !optObj(p?.get("provenance")) { return "wb.policy.world / provenance must be objects" }
            if !optArr(p?.get("classifiers")) { return "wb.policy.classifiers must be an array" }
        }
        return nil
    }

    static func schemaCtxError(_ ctx: JSONValue?) -> String? {
        guard let sc = ctx?.get("schema") else { return nil }
        guard sc.isObject, case .array? = sc.get("docs"), case .array? = sc.get("keys") else { return "the schema context must be {docs: [...], keys: [...]}" }
        return nil
    }
    static func sessionCtxError(_ ctx: JSONValue?) -> String? {
        guard let se = ctx?.get("session") else { return nil }
        guard se.isObject else { return "the session context must be an object" }
        if !optArr(se.get("grants")) { return "the session grants must be an array" }
        if !optObj(se.get("revocation")) { return "the session revocation evidence must be an object" }
        if !optObj(se.get("revocation_last")) { return "the tracked last revocation epoch must be an object" }
        if let pp = se.get("pq_pins") {
            guard let m = pp.asObject, m.values.allSatisfy({ $0.asString != nil }) else { return "the session pq_pins must be an object of strings" }
        }
        return nil
    }
    static func accCtxError(_ ctx: JSONValue?) -> String? {
        guard let a = ctx?.get("acc") else { return nil }
        guard a.isObject else { return "the accumulator context must be an object" }
        for k in ["state", "monitors", "last_seq", "keyset_versions"] where !optObj(a.get(k)) { return "acc.\(k) must be an object" }
        if case let .object(kv)? = a.get("keyset_versions") {
            for v in kv.values { if let e = IntentAcc.trackedKeySetError(v) { return "acc.keyset_versions: \(e)" } }
        }
        for k in ["receipts", "sequencer_keys"] where !optArr(a.get(k)) { return "acc.\(k) must be an array" }
        if case let .object(ls)? = a.get("last_seq"), !ls.values.allSatisfy({ IV.isSafeNonNeg($0) }) { return "acc.last_seq values must be non-negative safe integers" }
        return nil
    }

    /// Rule 14 (`schema`). On success also the matched schema document.
    static func schemaStep(_ p: JObject, _ ctx: JSONValue?) -> (Step, JSONValue?) {
        let isv = p["intent_session"]
        if let ce = schemaCtxError(ctx) { return (ce, nil) }
        guard case let .array(docs)? = ctx?.get("schema")?.get("docs"), !docs.isEmpty else { return ("this verifier has no action schema configured", nil) }
        let doc: JSONValue
        if let iss = isv?.get("schema")?.asString {
            guard let d = docs.first(where: { ActionSchema.digest($0).map { IV.same($0, iss) } ?? false }) else {
                return ("intent_session.schema names no schema this verifier accepts", nil)
            }
            doc = d
        } else {
            doc = docs[0]
        }
        let v = ActionSchema.verify(doc, keys: ctx?.get("schema")?.get("keys"))
        if !v.ok { return ("schema does not verify: \(v.reason)", nil) }
        if !IV.same(doc.get("aud")?.asString, p["aud"]?.asString) { return ("schema aud does not match the PCActn aud", nil) }
        guard let params = ctx?.get("params"), params.isObject else { return ("no plaintext params to check against the schema (closed world needs them)", nil) }
        guard let pd = IV.strictHash(params), IV.same(pd, p["action"]?.get("params_digest")?.asString) else {
            return ("params do not hash to action.params_digest", nil)
        }
        let c = ActionSchema.conform(doc, verb: actionString(p, "verb"), params: params)
        if !c.ok { return ("schema_violation: \(c.code): \(c.reason)", nil) }
        return (nil, doc)
    }

    /// The bound, verified session root (rules 13 and 15).
    static func boundRoot(_ p: JObject, _ ctx: JSONValue?, _ now: Double) -> (Step, JObject?) {
        let iss = p["intent_session"]!
        guard let S = ctx?.get("session")?.get("root") else { return ("no session root for this session", nil) }
        // a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals
        let v = IntentSession.verifyRoot(S, pqPins: ctx?.get("session")?.get("pq_pins"))
        if !v.ok { return ("session root: \(v.reason)", nil) }
        guard let d = IntentSession.rootDigest(S), IV.same(d, iss.get("root")?.asString) else {
            return ("intent_session.root is not the digest of the session root", nil)
        }
        if !IV.same(S.get("session")?.asString, iss.get("session")?.asString) { return ("the session root names another session", nil) }
        guard let exp = IV.num(S.get("expires_at")), now < exp else { return ("the session root has expired", nil) }
        return (nil, S.asObject)
    }

    /// Rule 13 (`intent_session`).
    static func sessionStep(_ p: JObject, _ grant: JSONValue, _ ctx: JSONValue?, _ now: Double) -> Step {
        let maxAgeV = ctx?.get("policy")?.get("session")?.get("max_revocation_age_s")
        if let m = maxAgeV, IV.nonNeg(m) == nil {
            return "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)"
        }
        guard let iss = p["intent_session"] else { return "this verifier requires an intent_session but the PCActn carries none" }
        if let ce = sessionCtxError(ctx) { return ce }
        guard let intent = p["intent"] else { return "an intent_session needs the envelope.intent binding" }
        let (e, Sopt) = boundRoot(p, ctx, now)
        if let e = e { return e }
        let S = Sopt!
        let session = iss.get("session")!.asString!
        let rootD = iss.get("root")!.asString!
        let seq = IV.nonNeg(iss.get("seq"))!
        if !IV.same(S["intent_ref"]?.asString, intent.get("ref")?.asString) { return "intent.ref is not the session statement" }
        if !IV.same(S["schema"]?.get("digest")?.asString, iss.get("schema")?.asString) { return "intent_session.schema is not the session schema" }
        if !IV.same(S["schema"]?.get("aud")?.asString, p["aud"]?.asString) { return "the session schema is for another audience" }
        if seq == 0 && !IV.same(intent.get("map_digest")?.asString, S["layers"]?.get("task")?.get("map_digest")?.asString) {
            return "a seq-0 action must use the session task map"
        }
        let gc = IntentSession.grantCaveat(grant)
        if let ge = IntentSession.caveatError(gc) { return "admitting root: \(ge)" }
        if !IV.same(gc!.get("session")?.asString, session) || !IV.same(gc!.get("root")?.asString, rootD) || IV.num(gc!.get("seq")) != Double(seq) {
            return "the admitting root is bound to another session, root or seq"
        }
        let principals = (S["principals"]?.asArray ?? []).compactMap { $0.get("key")?.asString }
        if !(grant.get("issuer")?.asString.map { IV.contains(principals, $0) } ?? false) { return "the admitting root is not signed by a session principal" }
        let prior: [JSONValue]
        switch ctx?.get("session")?.get("grants") {
        case nil: prior = []
        case let .array(a)?: prior = a
        default: return "the verifier does not hold the \(seq) earlier grants of this session"
        }
        if Int64(prior.count) < seq { return "the verifier does not hold the \(seq) earlier grants of this session" }
        let n = Int(seq)
        for i in 0..<n {
            let g = prior[i]
            guard g.isObject, g.get("id")?.asString != nil, g.get("issuer")?.asString != nil else { return "session grant \(i) is not a capability" }
            if let se = IV.suiteError(g.get("alg")) { return "session grant \(i): \(se)" }
            let c = IntentSession.grantCaveat(g)
            if IntentSession.caveatError(c) != nil || !IV.same(c!.get("session")?.asString, session) || !IV.same(c!.get("root")?.asString, rootD)
                || IV.num(c!.get("seq")) != Double(i) {
                return "session grant \(i) does not belong to this session at seq \(i)"
            }
            if !(g.get("issuer")?.asString.map { IV.contains(principals, $0) } ?? false) { return "session grant \(i) is not signed by a session principal" }
            if i > 0 && !IV.strictEq(c!.get("prev"), prior[i - 1].get("id")) { return "session grant \(i) does not chain to grant \(i - 1)" }
        }
        if seq > 0 && !IV.strictEq(gc!.get("prev"), prior[n - 1].get("id")) { return "the admitting root does not chain to grant \(n - 1)" }
        let rev = S["revocation"]
        if rev != nil || maxAgeV != nil {
            var ages: [Double] = []
            if let a = IV.num(rev?.get("max_age_s")) { ages.append(a) }
            if let a = IV.num(maxAgeV) { ages.append(a) }
            let maxAgeMs = (ages.min() ?? .infinity) * 1000
            guard let r = rev, let authority = r.get("key")?.asString else {
                return "revocation: the policy requires a revocation epoch but the session root names no revocation authority"
            }
            var ids = [IntentRevocation.sessionId(session), IntentRevocation.mapId(intent.get("map_digest")?.asString ?? "")]
            for g in prior[0..<n] {
                guard let gid = g.get("id")?.asString else { return "revocation: a held grant has no id" }
                ids.append(IntentRevocation.deltaId(gid))
            }
            guard let aid = grant.get("id")?.asString else { return "revocation: the admitting root has no id" }
            ids.append(IntentRevocation.deltaId(aid))
            if case let .object(std)? = S["layers"]?.get("std") {
                ids.append(IntentRevocation.profileId(std["profile"]?.asString ?? "", IV.int(std["version"]) ?? 0))
            }
            // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
            var pins: [String: String] = [:]
            if let pq = r.get("pq_pk")?.asString { pins[authority] = pq }
            let (ok, why) = IntentRevocation.check(ctx?.get("session")?.get("revocation"), session: session, authority: authority, ids: ids, now: now,
                                                   maxAgeMs: maxAgeMs, pqPins: pins, last: ctx?.get("session")?.get("revocation_last"))
            if !ok { return "revocation: \(why)" }
        }
        return nil
    }

    /// Rule 15 (`accumulators`). On success the `acc` / `mon` env.
    static func accStep(_ p: JObject, _ ctx: JSONValue?, _ now: Double) -> (Step, JObject, JObject) {
        let iss = p["intent_session"]!
        let (e, Sopt) = boundRoot(p, ctx, now)
        if let e = e { return (e, [:], [:]) }
        let S = Sopt!
        if let ce = accCtxError(ctx) ?? schemaCtxError(ctx) { return (ce, [:], [:]) }
        let verb = actionString(p, "verb")
        let accs = (S["accumulators"]?.asArray ?? []).compactMap { $0.asObject }
        let claims = (iss.get("acc")?.asArray ?? []).compactMap { $0.asObject }
        for c in claims {
            let cid = c["id"]!.asString!
            guard let a = accs.first(where: { IV.same($0["id"]?.asString, cid) }) else { return ("claim '\(cid)' names no accumulator of the session", [:], [:]) }
            if a["holder"]?.get("kind")?.asString == "wallet" { return ("accumulator '\(cid)' is wallet-held and cannot be claimed at a site", [:], [:]) }
        }
        let issSchema = iss.get("schema")?.asString ?? ""
        let docs: [JSONValue]
        switch ctx?.get("schema")?.get("docs") {
        case nil: docs = []
        case let .array(d)?: docs = d
        default: return ("accumulators error (fail closed): schema docs is not a list", [:], [:])
        }
        let schemaDoc = docs.first { ActionSchema.digest($0).map { IV.same($0, issSchema) } ?? false }
        let params = ctx?.get("params")
        var envAcc: JObject = [:], envMon: JObject = [:]
        let accCtx = ctx?.get("acc")
        let state = accCtx?.get("state")?.asObject ?? [:]
        for a in accs {
            let id = a["id"]!.asString!
            let agg = a["agg"]!.asString!
            let hk = a["holder"]?.get("kind")?.asString ?? ""
            if hk == "wallet" { continue }
            if a["sel"]?.get("accumulates_into") != nil && schemaDoc == nil {
                return ("accumulator '\(id)' selects by accumulates_into but the session schema is not available", [:], [:])
            }
            let selected = IntentAcc.selects(a, verb, schemaDoc)
            let claim = claims.first { IV.same($0["id"]?.asString, id) }
            let pre = state[JKey(id)]
            if !selected {
                if claim != nil { return ("claim '\(id)' for an accumulator this action does not feed", [:], [:]) }
                if hk == "site_local", let pr = pre {
                    if let pe = IntentAcc.preStateError(agg, pr) { return ("accumulator '\(id)': \(pe)", [:], [:]) }
                    envAcc[JKey(id)] = .object(["post": .int(Int64(IntentAcc.preValue(agg, pr)))])
                }
                continue
            }
            guard let cl = claim else { return ("no claim for accumulator '\(id)' that this action feeds", [:], [:]) }
            guard case let .object(po)? = params else { return ("no plaintext params to compute accumulator values", [:], [:]) }
            if let key = a["key"]?.asString {
                let name = IV.dropPrefix(key, 14)
                if po[JKey(name)] == nil { return ("accumulator '\(id)': the key parameter \(key) is missing", [:], [:]) }
                let kd = schemaDoc.flatMap { ActionSchema.verb($0, verb) }?["params"]?.get(key)
                guard let sem = kd?.get("semantic")?.asString, !IV.startsWith(sem, "text.") else {
                    return ("accumulator '\(id)': the key must be a schema-declared identity (not free text)", [:], [:])
                }
            }
            let vr = IntentAcc.valueOfChecked(a, verb, po, schemaDoc)
            guard let v = vr.value else { return ("accumulator '\(id)': \(vr.reason)", [:], [:]) }
            let post: Double
            if hk == "site_local" {
                if cl["receipt"] != nil { return ("accumulator '\(id)' is site-local: a receipt is not accepted", [:], [:]) }
                guard let pr = pre else { return ("no state for site-local accumulator '\(id)'", [:], [:]) }
                if let pe = IntentAcc.preStateError(agg, pr) { return ("accumulator '\(id)': \(pe)", [:], [:]) }
                guard let x = IntentAcc.combine(agg, pr, v.val, v.key) else { return ("accumulator '\(id)' overflows 2^53-1", [:], [:]) }
                post = x
            } else {
                guard let rd = cl["receipt"]?.asString else { return ("accumulator '\(id)' is sequenced: the claim needs a reservation receipt", [:], [:]) }
                let receipts: [JSONValue]
                switch ctx?.get("acc")?.get("receipts") {
                case nil: receipts = []
                case let .array(r)?: receipts = r
                default: return ("accumulators error (fail closed): receipts is not a list", [:], [:])
                }
                guard let rc = receipts.first(where: { IntentAcc.receiptDigest($0).map { IV.same($0, rd) } ?? false }) else {
                    return ("the reservation receipt for '\(id)' was not presented", [:], [:])
                }
                // freshness: policy acc (absent = the defaults) and the tracked key-set version for the holder's root
                let pa = ctx?.get("policy")?.get("acc")
                let tracked = a["holder"]?.get("root")?.asString.flatMap { IntentAcc.trackedKeySet(ctx?.get("acc")?.get("keyset_versions")?.asObject?[JKey($0)]) }
                let fresh = IntentAcc.Freshness(maxReceiptAgeMs: IV.nonNeg(pa?.get("max_receipt_age_s")).map { Double($0) * 1000 } ?? IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS,
                                                maxKeySetAgeMs: IV.nonNeg(pa?.get("max_keyset_age_s")).map { Double($0) * 1000 } ?? IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS,
                                                tracked: tracked)
                switch IntentAcc.verifyAgainstHolder(rc, holder: a["holder"]?.asObject ?? [:], keySets: ctx?.get("acc")?.get("sequencer_keys"), now: now, fresh: fresh) {
                case .valid: break
                case .unsupported: return ("accumulator '\(id)': \(IV.UNSUPPORTED_SUITE)", [:], [:])
                case .invalid: return ("the reservation receipt for '\(id)' is not signed by a key the session sequencer's root-signed key set lists for its issue time", [:], [:])
                }
                if !IV.same(rc.get("session")?.asString, iss.get("session")?.asString) || !IV.same(rc.get("acc")?.asString, id)
                    || !IV.same(rc.get("aud")?.asString, p["aud"]?.asString) {
                    return ("the reservation receipt for '\(id)' is for another session, accumulator or audience", [:], [:])
                }
                guard let rsv = IntentAcc.reservationDigest(p), IV.same(rc.get("pcactn_digest")?.asString, rsv) else {
                    return ("the reservation receipt for '\(id)' is for another action", [:], [:])
                }
                if !(now <= (IV.num(rc.get("expires_at")) ?? -.infinity)) { return ("the reservation receipt for '\(id)' has expired", [:], [:]) }
                // the last accepted seq for this id (an own member; a present value must be a safe integer)
                if let last = ctx?.get("acc")?.get("last_seq")?.asObject?[JKey(id)] {
                    guard let l = IV.int(last), let seq = IV.int(rc.get("seq")), seq > l else {
                        return ("the reservation receipt for '\(id)' replays seq \(IntentWB.jsOpt(rc.get("seq"))) (last accepted \(IntentWB.jsOpt(last)))", [:], [:])
                    }
                }
                if !IntentAcc.receiptArithmeticOk(agg, rc, v.val) { return ("the reservation receipt for '\(id)' does not add up", [:], [:]) }
                post = IV.num(rc.get("post"))!
            }
            if let dm = IV.num(a["domain_max"]), post > dm { return ("accumulator '\(id)' post \(Int64(post)) is outside its domain (max \(IntentWB.jsOpt(a["domain_max"])))", [:], [:]) }
            if IV.num(cl["post"]) != post { return ("claimed post \(IntentWB.jsOpt(cl["post"])) for '\(id)' differs from the verifier's \(Int64(post))", [:], [:]) }
            envAcc[JKey(id)] = .object(["post": .int(Int64(post))])
        }
        let mons = ctx?.get("acc")?.get("monitors")?.asObject ?? [:]
        for mv in S["monitors"]?.asArray ?? [] {
            let mid = mv.get("id")!.asString!
            guard let st = mons[JKey(mid)]?.asString, IntentAcc.monitorStates(mv).contains(where: { IV.same($0, st) }) else {
                return ("no valid state for monitor '\(mid)'", [:], [:])
            }
            envMon[JKey(mid)] = .object(["state": .string(st)])
        }
        return (nil, envAcc, envMon)
    }

    /// Rule 19 (`map`, V15 Z0): after `accumulators`, independent of the earlier checks, before W-B.
    static func mapStep(_ p: JObject, _ ctx: JSONValue?) -> Step {
        if !IV.same(p["intent_session"]?.get("map_form")?.asString, IntentMap.FORM_COMMIT) {
            return "this verifier requires a committed map (intent_session.map_form \"commit\")"
        }
        guard let intent = p["intent"] else { return "a committed map needs the envelope.intent binding" }
        guard let disclosure = ctx?.get("map")?.get("disclosure") else { return "no disclosure of the committed map was presented" }
        let r = IntentMap.decide(mapCommit: intent.get("map_digest"), action: p["action"], params: ctx?.get("params"), disclosure: disclosure,
                                 maxResidualRiskPpm: IV.nonNeg(ctx?.get("policy")?.get("map")?.get("max_residual_risk_ppm")))
        return r.ok ? nil : r.reason
    }

    /// `decideIntentV2`: the v2 checks in order, each reported only under its condition; never traps.
    static func decide(_ p: JObject, grant: JSONValue, ctx ctxIn: IntentV2Context?, now nowI: Int64) -> (checks: [Check], env: IntentV2Env?) {
        let ctx = ctxIn?.value
        let now = Double(nowI)
        var checks: [Check] = []
        var env: IntentV2Env?
        func run(_ name: String, _ s: Step) { checks.append(Check(name: name, ok: s == nil, reason: s ?? "")) }
        let present = p["intent_session"] != nil
        if let ce = contextError(ctx) {
            // a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
            let committed = present && IV.same(p["intent_session"]?.get("map_form")?.asString, IntentMap.FORM_COMMIT)
            for name in ["schema", "intent_session"] + (present ? ["accumulators"] : []) + (committed ? ["map"] : []) { run(name, "malformed v2 context: \(ce)") }
            return (checks, nil)
        }
        // the verifier clock: a safe integer, else every v2 check run here fails closed
        let clockOk = IV.isSafeDouble(now) && nowI >= -Canonical.MAX_SAFE && nowI <= Canonical.MAX_SAFE
        func step(_ s: @autoclosure () -> Step) -> Step { clockOk ? s() : "the verifier clock is not a safe integer (fail closed)" }
        let pol = ctx?.get("policy")
        if present || pol?.get("schema")?.get("closed_world") == .bool(true) {
            let (s, doc) = clockOk ? schemaStep(p, ctx) : ("the verifier clock is not a safe integer (fail closed)", nil)
            if s == nil, let d = doc, case let .object(params)? = ctx?.get("params") {
                env = IntentV2Env(canon: ActionSchema.canonProjection(d, verb: actionString(p, "verb"), params: params))
            }
            run("schema", s)
        }
        if present || pol?.get("session")?.get("require") == .bool(true) {
            run("intent_session", step(sessionStep(p, grant, ctx, now)))
        }
        // rule 19: `map` is reported iff the PCActn commits its map or the policy requires a committed map
        let mapActive = IV.same(p["intent_session"]?.get("map_form")?.asString, IntentMap.FORM_COMMIT) || pol?.get("map")?.get("require") == .bool(true)
        let params: JSONValue = (ctx?.get("params")?.isObject ?? false) ? ctx!.get("params")! : .object([:])
        let action: JSONValue = .object(["verb": .string(actionString(p, "verb")), "resource": .string(actionString(p, "resource")),
                                         "params": params])
        if present, let layers = ctx?.get("layers") {
            var envObj: JObject = [:]
            if let c = env?.canon { envObj["canon"] = .object(c) }
            let pctx: JSONValue = .object(["action": action, "env": .object(envObj)])
            var failed: String? = clockOk ? nil : "the verifier clock is not a safe integer (fail closed)"
            for k in ["org", "site", "std"] where failed == nil {
                guard let layer = layers.get(k) else { continue }
                // a layer is EXACTLY {predicates: [...]}: anything else fails as that ceiling
                guard case let .object(lo) = layer, lo.count == 1, case .array? = lo["predicates"] else {
                    failed = "layers: the \(k) ceiling is malformed (null or not {predicates: [...]})"
                    break
                }
                if !Predicates.evaluate(layer.get("predicates"), pctx) {
                    failed = "layers: the action is outside the \(k) ceiling (a ceiling is never a question)"
                    break
                }
            }
            run("layers", failed)
        }
        if present {
            let (s, acc, mon) = clockOk ? accStep(p, ctx, now) : ("the verifier clock is not a safe integer (fail closed)", [:], [:])
            if s == nil {
                var e = env ?? IntentV2Env()
                e.acc = acc
                e.mon = mon
                env = e
            }
            run("accumulators", s)
            if mapActive { run("map", step(mapStep(p, ctx))) }
            let wb = IntentWB.decide(now: clockOk ? nowI : nil, aud: p["aud"]?.asString ?? "", session: p["intent_session"]!.get("session")?.asString ?? "",
                                     action: action, intentSession: p["intent_session"]!, artifacts: ctx?.get("wb")?.get("artifacts"), policy: ctx?.get("wb")?.get("policy"))
            for (name, status) in wb.checks {
                if status == "pass" { run(name, nil) }
                else { run(name, status == "question" ? "intent_required: \(wb.reason ?? "a question is required")" : (wb.reason ?? "rejected")) }
            }
            if wb.outcome != "deny" {
                var e = env ?? IntentV2Env()
                if let w = wb.world { e.world = w }
                if let pr = wb.prov { e.prov = pr }
                if let c = wb.cls { e.cls = c }
                env = e
            }
        } else if mapActive {
            run("map", step(mapStep(p, ctx)))
        }
        return (checks, env)
    }
}

extension PCA {
    /// The verifier-computed Intent Layer v2 predicate environment (`env.canon` / `env.acc` / `env.mon` / `env.world` /
    /// `env.prov` / `env.class`) for a wire-valid PCActn under `grant`, as the admitting root's predicates read it. nil when
    /// no member was computed.
    public static func intentV2Env(pcactn: JSONValue, grant: JSONValue, now: Int64, context: IntentV2Context) -> IntentV2Env? {
        guard Wire.validate(pcactn) == nil, let p = pcactn.asObject else { return nil }
        return IntentV2.decide(p, grant: grant, ctx: context, now: now).env
    }
}
