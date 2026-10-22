import Foundation

/// Intent sessions (Intent Layer v2 V3; conformance rule 13). Mirrors `packages/pca/src/intent-session.ts` and
/// `intent-session-caveat.ts`: the closed wire of the signed PCActn member `intent_session`, the grant caveat
/// `{type: "intent_session", session, seq, root, prev?}`, and the principal-signed session root S.
enum IntentSession {
    static let KIND = "pca-intent-session"
    static let SIG_DOMAIN = "atlas-pca/intent-session/v1\u{0}"
    static let REF_DOMAIN = "atlas-pca/intent-session-ref/v1"
    static let CAVEAT = "intent_session"
    static let MAX_SEQ: Int64 = 2_147_483_647
    static let MAX_ACC = 16
    static let MAX_FACTS = 16
    static let MAX_PROV_PATHS = 32
    static let MAX_PROV_REFS = 8
    static let MAX_CLASSES = 8
    static let MAX_LABELS = 16
    static let MAX_STRING_BYTES = 256
    static let MAX_PRINCIPALS = 16
    static let FIELDS = ["session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form"]
    static let ROOT_KEYS = ["v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri",
                            "revocation", "flows", "expires_at", "signer", "alg", "pq_pk", "sig", "pq_sig"]
    static let GOAL_V2_PREFIX = "pca-intent:v2:"
    /// Rule 19: the goal over a COMMITTED map (`intent_session.map_form` "commit").
    static let GOAL_V2C_PREFIX = "pca-intent:v2c:"

    private static func has(_ list: [String], _ k: JKey) -> Bool { list.contains { JKey($0) == k } }

    private static func digestList(_ v: JSONValue, _ name: String, _ max: Int) -> String? {
        guard case let .array(a) = v, a.count <= max else { return "'intent_session.\(name)' must be an array of at most \(max) digests" }
        for x in a where IV.digest(x) == nil { return "'intent_session.\(name)' entries must be canonical base64url (32 bytes)" }
        if !IV.distinct(a.compactMap { $0.asString }) { return "'intent_session.\(name)' entries must be distinct" }
        return nil
    }

    /// `validateIntentSessionWire` (part of the terminal `wire` check). nil = well-formed.
    static func validateWire(_ v: JSONValue) -> String? {
        guard case let .object(o) = v else { return "'intent_session' must be an object" }
        for k in o.keys where !has(FIELDS, k) { return "unknown field 'intent_session.\(k.s)'" }
        for k in ["session", "root", "seq", "schema"] where o[JKey(k)] == nil { return "missing field 'intent_session.\(k)'" }
        for k in ["session", "root", "schema"] where IV.digest(o[JKey(k)]) == nil { return "'intent_session.\(k)' is not canonical base64url (32 bytes)" }
        guard let seq = IV.nonNeg(o["seq"]), seq <= MAX_SEQ else { return "'intent_session.seq' must be a safe integer in [0, 2147483647]" }
        if let av = o["acc"] {
            guard case let .array(acc) = av, acc.count <= MAX_ACC else { return "'intent_session.acc' must be an array of at most \(MAX_ACC) entries" }
            var ids = Set<JKey>()
            for (i, x) in acc.enumerated() {
                guard case let .object(a) = x else { return "'intent_session.acc[\(i)]' must be an object" }
                for k in a.keys where !has(["id", "post", "receipt"], k) { return "unknown field 'intent_session.acc[\(i)].\(k.s)'" }
                guard let id = a["id"]?.asString, IV.isId(id) else { return "'intent_session.acc[\(i)].id' must match [A-Za-z0-9_]{1,64}" }
                if !ids.insert(JKey(id)).inserted { return "'intent_session.acc' ids must be distinct" }
                if IV.nonNeg(a["post"]) == nil { return "'intent_session.acc[\(i)].post' must be a non-negative safe integer" }
                if let r = a["receipt"], IV.digest(r) == nil { return "'intent_session.acc[\(i)].receipt' is not canonical base64url (32 bytes)" }
            }
        }
        if let f = o["facts"], let e = digestList(f, "facts", MAX_FACTS) { return e }
        if let os = o["offer_set"], IV.digest(os) == nil { return "'intent_session.offer_set' is not canonical base64url (32 bytes)" }
        if let pv = o["prov"] {
            guard case let .object(prov) = pv, prov.count <= MAX_PROV_PATHS else {
                return "'intent_session.prov' must be an object of at most \(MAX_PROV_PATHS) entries"
            }
            for (path, refs) in prov.sorted(by: { $0.key < $1.key }) {
                if !IV.isTopParamPath(path.s) { return "'intent_session.prov' key '\(path.s)' is not action.params.<name>" }
                guard case let .array(rs) = refs, !rs.isEmpty, rs.count <= MAX_PROV_REFS,
                      rs.allSatisfy({ r in r.asString.map { !$0.isEmpty && !Canonical.hasLoneSurrogate($0) && IV.u8($0) <= MAX_STRING_BYTES } ?? false }) else {
                    return "'intent_session.prov.\(path.s)' must be 1..\(MAX_PROV_REFS) non-empty strings of at most \(MAX_STRING_BYTES) UTF-8 bytes"
                }
            }
        }
        if let c = o["classes"], let e = digestList(c, "classes", MAX_CLASSES) { return e }
        if let l = o["labels"], let e = digestList(l, "labels", MAX_LABELS) { return e }
        // rule 19: the only map form is "commit" (any other value, null included, fails wire)
        if let mf = o["map_form"], !IV.same(mf.asString, IntentMap.FORM_COMMIT) { return "'intent_session.map_form' must be \"commit\" when present" }
        return nil
    }

    /// `intentSessionCaveatError`: exactly {type, session, seq, root, prev?}, prev present iff seq > 0. nil = well-formed.
    static func caveatError(_ c: JSONValue?) -> String? {
        guard case let .object(o)? = c, IV.same(o["type"]?.asString, CAVEAT) else { return "not an intent_session caveat" }
        for k in o.keys where !has(["type", "session", "seq", "root", "prev"], k) { return "intent_session caveat: unknown member '\(k.s)'" }
        if IV.digest(o["session"]) == nil || IV.digest(o["root"]) == nil {
            return "intent_session caveat: session and root must be canonical base64url (32 bytes)"
        }
        guard let seq = IV.nonNeg(o["seq"]), seq <= MAX_SEQ else { return "intent_session caveat: seq must be a safe integer in [0, 2147483647]" }
        if (seq == 0) != (o["prev"] == nil) { return "intent_session caveat: prev is present exactly when seq > 0" }
        if let p = o["prev"], IV.digest(p) == nil { return "intent_session caveat: prev must be canonical base64url (32 bytes)" }
        return nil
    }

    /// `grantSessionCaveat(grant)`: the FIRST caveat of the grant that is an object with `type == "intent_session"`.
    static func grantCaveat(_ grant: JSONValue?) -> JSONValue? {
        guard case let .array(cs)? = grant?.get("caveats") else { return nil }
        return cs.first { c in c.isObject && IV.same(c.get("type")?.asString, CAVEAT) }
    }

    // ---- the session root S ----

    /// `suiteError` for the root's SHAPE: a registered suite (`PCASuites.registered`, the TS registry) passes even when this
    /// OS cannot run it, so `verifyRoot`'s verifier-pin checks (no crypto) run before availability, in the reference's
    /// order; `verifyRoot` refuses an unavailable signer suite with `unsupported_suite` after the pins.
    static func suiteKnownError(_ alg: JSONValue?) -> String? {
        guard let a = alg else { return nil }
        guard let s = a.asString else { return "alg must be a string" }
        return PCASuites.registered.contains { IV.same($0, s) } ? nil : "\(IV.UNSUPPORTED_SUITE): '\(s)'"
    }

    static func shapeError(_ sv: JSONValue) -> String? {
        guard case let .object(s) = sv else { return "session root is not an object" }
        for k in s.keys where !has(ROOT_KEYS, k) { return "session root: unknown member '\(k.s)'" }
        if IV.num(s["v"]) != 1 || !IV.same(s["kind"]?.asString, KIND) { return "not a pca-intent-session v1" }
        if IV.digest(s["session"]) == nil || IV.digest(s["intent_ref"]) == nil { return "session and intent_ref must be canonical base64url (32 bytes)" }
        guard case let .array(ps)? = s["principals"], !ps.isEmpty, ps.count <= MAX_PRINCIPALS else { return "principals must be 1..\(MAX_PRINCIPALS) keys" }
        var keys = Set<JKey>()
        for p in ps {
            guard case let .object(po) = p, po.keys.allSatisfy({ has(["key", "alg", "pq_pk"], $0) }), let key = IV.digest(po["key"]) else {
                return "principals entries are {key, alg?, pq_pk?} with a 32-byte key"
            }
            if let se = suiteKnownError(po["alg"]) { return "principal alg: \(se)" }
            if let pk = po["pq_pk"], !(pk.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "principal pq_pk is not canonical base64url" }
            if !keys.insert(JKey(key)).inserted { return "principal keys must be distinct" }
        }
        guard case let .object(sch)? = s["schema"], sch.count == 2, let aud = sch["aud"]?.asString, !aud.isEmpty, IV.digest(sch["digest"]) != nil else {
            return "schema must be {aud, digest}"
        }
        guard case let .object(L)? = s["layers"] else { return "layers must be an object" }
        for k in L.keys where !has(["org", "std", "task"], k) { return "layers: unknown member '\(k.s)'" }
        guard case let .object(task)? = L["task"], task.count == 1, IV.digest(task["map_digest"]) != nil else { return "layers.task must be {map_digest}" }
        // absent = no such layer; null is malformed
        if let org = L["org"] {
            guard case let .object(oo) = org, IV.digest(oo["digest"]) != nil else { return "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)" }
        }
        if let std = L["std"] {
            guard case let .object(d) = std, d.count == 3, let prof = d["profile"]?.asString, !prof.isEmpty, IV.u8(prof) <= 128,
                  let ver = IV.int(d["version"]), ver >= 1, IV.digest(d["digest"]) != nil else {
                return "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)"
            }
        }
        guard case let .array(accs)? = s["accumulators"], accs.count <= IntentAcc.MAX_SESSION_ACCUMULATORS else {
            return "accumulators must be an array of at most \(IntentAcc.MAX_SESSION_ACCUMULATORS)"
        }
        var ids = Set<JKey>()
        for a in accs {
            if let e = IntentAcc.accumulatorDeclError(a) { return e }
            if !ids.insert(JKey(a.get("id")!.asString!)).inserted { return "accumulator and monitor ids must be distinct" }
        }
        guard case let .array(mons)? = s["monitors"], mons.count <= IntentAcc.MAX_SESSION_MONITORS else {
            return "monitors must be an array of at most \(IntentAcc.MAX_SESSION_MONITORS)"
        }
        var mids = Set<JKey>()
        for m in mons {
            if let e = IntentAcc.monitorDeclError(m) { return e }
            if !mids.insert(JKey(m.get("id")!.asString!)).inserted { return "monitor ids must be distinct" }
        }
        guard let q = s["question_uri"]?.asString, !q.isEmpty, IV.u8(q) <= 2048 else { return "question_uri must be a non-empty string" }
        if let rv = s["revocation"] {
            guard case let .object(r) = rv, r.keys.allSatisfy({ has(["epoch_uri", "max_age_s", "key", "pq_pk"], $0) }) else {
                return "revocation must be {epoch_uri, max_age_s, key, pq_pk?}"
            }
            guard let eu = r["epoch_uri"]?.asString, !eu.isEmpty else { return "revocation.epoch_uri must be a non-empty string" }
            if IV.nonNeg(r["max_age_s"]) == nil { return "revocation.max_age_s must be a non-negative safe integer" }
            // the DEDICATED revocation authority: required, never a session principal
            guard let key = IV.digest(r["key"]) else { return "revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)" }
            if keys.contains(JKey(key)) { return "revocation.key must not be a session principal (a dedicated revocation authority)" }
            if let pq = r["pq_pk"], !(pq.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "revocation.pq_pk must be canonical base64url" }
        }
        if let f = s["flows"], !f.isObject { return "flows must be an object" }
        if IV.nonNeg(s["expires_at"]) == nil { return "expires_at must be a non-negative safe integer (epoch ms)" }
        guard let signer = IV.digest(s["signer"]) else { return "signer must be canonical base64url (32 bytes)" }
        if !keys.contains(JKey(signer)) { return "signer is not one of the session principals" }
        if let se = suiteKnownError(s["alg"]) { return "alg: \(se)" }
        let suite = IV.sigAlg(s["alg"])!
        if suite == "ed25519" && (s["pq_pk"] != nil || s["pq_sig"] != nil) { return "an ed25519 session root must not carry pq_pk / pq_sig" }
        if s["sig"]?.asString == nil { return "sig must be a string" }
        if let ce = IV.strictCanonError(.object(body(s))) { return "malformed session root: \(ce)" }
        return nil
    }

    /// `sessionRootBody`: the signed members (without signer and suite fields).
    static func body(_ s: JObject) -> JObject {
        var out: JObject = [:]
        for k in ["v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "revocation", "flows", "expires_at"] {
            if let x = s[JKey(k)] { out[JKey(k)] = x }
        }
        return out
    }

    /// `verifySessionRoot(S, {pqPins})`: shape, signer listed, suite signature. R3-01 (fail closed): a non-ed25519 root
    /// verifies only under the VERIFIER's pin for its signer (`pqPins` = context `session.pq_pins`, an object whose member
    /// for the signer is a string), never under the root's own `principals[].pq_pk`; the signer's own entry, when it
    /// declares a `pq_pk`, must agree. An ed25519 root never consults the pins.
    static func verifyRoot(_ sv: JSONValue, pqPins: JSONValue? = nil) -> (ok: Bool, reason: String) {
        if let e = shapeError(sv) { return (false, e) }
        guard case let .object(s) = sv, let signer = s["signer"]?.asString else { return (false, "malformed session root") }
        let principal = s["principals"]?.asArray?.first { IV.same($0.get("key")?.asString, signer) }
        var pin: String? = nil
        if let a = IV.sigAlg(s["alg"]), !IV.same(a, "ed25519") {  // a registered name (shapeError); every non-ed25519 suite has a PQ key
            guard let p = pqPins?.get(signer)?.asString else {
                return (false, "session root suite '\(a)' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it")
            }
            guard let apk = s["pq_pk"]?.asString, apk == p else { return (false, "session root pq_pk does not match the verifier's pin for the signer") }
            if let e = principal?.get("pq_pk"), e.asString != apk { return (false, "session root pq_pk does not match the signer's principals entry") }
            pin = p
        }
        if let se = IV.suiteError(s["alg"]) { return (false, "alg: \(se)") }  // availability on this OS, AFTER the pins (the reference's order)
        var b = body(s)
        b["signer"] = .string(signer)
        guard let bound = IV.bindSuite(b, alg: s["alg"], pqPk: s["pq_pk"]), let msg = IV.message(SIG_DOMAIN, .object(bound)) else {
            return (false, "malformed session root")
        }
        switch IV.verifyPinned(alg: s["alg"], identity: signer, artifactPqPk: s["pq_pk"], msg: msg, sig: s["sig"], pqSig: s["pq_sig"], pin: pin) {
        case .valid: break
        case .unsupported: return (false, IV.UNSUPPORTED_SUITE)
        case .invalid: return (false, "session root signature invalid")
        }
        return (true, "")
    }

    /// `sessionRootDigest(S)` = base64url(sha256(strictCanonical({d, s: S}))).
    static func rootDigest(_ s: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(REF_DOMAIN), "s": s]))
    }
}
