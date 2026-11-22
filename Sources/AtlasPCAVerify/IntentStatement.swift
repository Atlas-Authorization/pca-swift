import Foundation

/// The signed intent statement (`packages/pca/src/intent.ts`): its content address, its shape and its signature check, and the
/// action digest a just-in-time consent is bound to (`intent-required.ts`). The suite fields (`alg`, `pq_pk`) are signed, the
/// signatures are not, and the reference names the CONTENT (`intentRef` ignores the suite fields and the signatures).
public enum PCAIntentStatement {
    static let SIG_DOMAIN = "atlas-pca/intent/v1\u{0}"
    static let REF_DOMAIN = "atlas-pca/intent-ref/v1"
    static let ACTION_DOMAIN = "atlas-pca/intent-action/v1"
    static let SOURCE_KINDS = ["conversation", "ticket", "document", "form", "other"]
    static let BODY_KEYS = ["v", "principal", "text", "slots", "sources", "created_at", "nonce"]

    /// `statementBody`: the signed content members that are present (a JSON round trip drops the absent ones).
    static func body(_ s: JObject) -> JObject {
        var out: JObject = [:]
        for k in BODY_KEYS { if let x = s[JKey(k)] { out[JKey(k)] = JSLoose.plain(x) } }
        return out
    }

    /// Content address of an intent statement: `base64url(sha256(strictCanonical({d, s: body})))`. Throws where the reference throws.
    public static func ref(_ s: JSONValue?) throws -> String {
        guard let o = s?.asObject else { throw JSError("canonicalize: not an intent statement") }
        guard let h = IV.strictHash(.object(["d": .string(REF_DOMAIN), "s": .object(body(o))])) else { throw JSError("canonicalize: value out of profile") }
        return h
    }

    /// `statementShapeError`: nil = well-formed.
    static func shapeError(_ sv: JSONValue?) -> String? {
        guard case let .object(s)? = sv else { return "intent statement is not an object" }
        if !JSLoose.isOne(s["v"]) { return "unsupported intent statement version" }
        guard let p = s["principal"]?.asString, Base64URLStrict.decode(p, length: 32) != nil else { return "principal is not canonical base64url (32 bytes)" }
        guard let text = s["text"]?.asString, !text.isEmpty else { return "text must be a non-empty string" }
        guard case .object? = s["slots"] else { return "slots must be an object" }
        guard case let .array(sources)? = s["sources"] else { return "sources must be an array" }
        for (i, src) in sources.enumerated() {
            guard case let .object(so) = src, let k = so["kind"]?.asString, SOURCE_KINDS.contains(where: { IV.same($0, k) }) else { return "sources[\(i)] has an unknown kind" }
            if let u = so["uri"], u.asString == nil { return "sources[\(i)].uri must be a string" }
            guard let d = so["digest"]?.asString, Base64URLStrict.decode(d, length: 32) != nil else { return "sources[\(i)].digest is not canonical base64url (32 bytes)" }
        }
        guard IV.nonNeg(s["created_at"]) != nil else { return "created_at must be a non-negative safe integer (epoch ms)" }
        guard let n = s["nonce"]?.asString, !n.isEmpty else { return "nonce must be a non-empty string" }
        return nil
    }

    /// Verify a signed statement (shape, signer, suite signature; no post-quantum pin is supplied, so a post-quantum suite is
    /// refused). Never throws: (ok, reason).
    public static func verify(_ sv: JSONValue?) -> (ok: Bool, reason: String) {
        if let bad = shapeError(sv) { return (false, bad) }
        guard case let .object(st)? = sv, let principal = st["principal"]?.asString else { return (false, "intent statement is not an object") }
        // suite fields must be consistent: an unknown alg is refused; an Ed25519 statement carries no pq_pk / pq_sig
        guard let alg = IV.sigAlg(st["alg"]), PQ.resolve(alg) != nil else { return (false, "unknown signature suite") }
        if IV.same(alg, "ed25519") && (st["pq_pk"] != nil || st["pq_sig"] != nil) { return (false, "an ed25519 artifact must not carry pq_pk / pq_sig") }
        guard let bound = IV.bindSuite(body(st), alg: st["alg"], pqPk: st["pq_pk"]) else { return (false, "malformed intent statement: missing pq_pk") }
        if let e = IV.strictCanonError(.object(bound)) { return (false, "malformed intent statement: \(e)") }
        guard let msg = IV.message(SIG_DOMAIN, .object(bound)) else { return (false, "malformed intent statement: canonicalize failed") }
        return IV.verifyPinned(alg: st["alg"], identity: principal, artifactPqPk: st["pq_pk"], msg: msg, sig: st["sig"], pqSig: st["pq_sig"], pin: nil) == .valid
            ? (true, "") : (false, "bad signature")
    }

    /// `intentActionDigest(action)`: `H({d, action: {verb, resource, params_digest, reversibility_class}})` over the PCActn's signed action.
    public static func actionDigest(_ action: JSONValue?) throws -> String {
        var a: JObject = [:]
        for k in ["verb", "resource", "params_digest", "reversibility_class"] { if let x = JSLoose.get(action, k) { a[JKey(k)] = x } }
        guard let h = IV.strictHash(.object(["d": .string(ACTION_DOMAIN), "action": .object(a)])) else { throw JSError("canonicalize: undefined member") }
        return h
    }
}

extension PCA {
    /// The action digest a JIT consent is bound to (`intentActionDigest`).
    public static func intentActionDigest(_ action: JSONValue?) throws -> String { try PCAIntentStatement.actionDigest(action) }
}

// MARK: signing, the full verdict and the goal string

extension PCAIntentStatement {
    public static let INTENT_GOAL_PREFIX = "pca-intent:v1:"

    /// Sign a statement as its principal with the principal's Ed25519 seed (the principal defaults to the key's identity; it must match
    /// when given).
    public static func signIntent(_ s: JSONValue?, _ principalSeed: [UInt8]) throws -> JSONValue {
        return try signIntent(s, PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: principalSeed)))
    }

    /// Sign under any registry suite (ML-DSA, hybrid, ...): `alg` and `pq_pk` are signed into the statement.
    public static func signIntent(_ s: JSONValue?, _ suiteKey: PCASuiteKey) throws -> JSONValue {
        guard let ed = suiteKey.ed else { throw JSError("signIntentStatement: signer needs an Ed25519 identity key") }
        guard var withP = s?.asObject else { throw JSError("canonicalize: not an intent statement") }
        let principal = ed.id
        if let p = withP[JKey("principal")], !IV.same(p.asString, principal) { throw JSError("signIntentStatement: principal key mismatch") }
        withP[JKey("principal")] = .string(principal)
        let b = body(withP)
        if let bad = shapeError(.object(b)) { throw JSError("signIntentStatement: \(bad)") }
        let signed = try PCAIntentKit.signSuite(b, suiteKey) { (bound: JObject) throws -> [UInt8] in
            return try PCAIntentKit.message(SIG_DOMAIN, .object(bound))
        }
        return .object(signed)
    }

    private static func verdict(_ reason: String?) -> JSONValue {
        guard let r = reason else { return .object(["ok": .bool(true)]) }
        return .object(["ok": .bool(false), "reason": .string(r)])
    }

    /// `{ok: true}` or `{ok: false, reason}`. `pqPins` maps a principal to the post-quantum key the verifier pins for it. Never throws.
    public static func verifyIntent(_ so: JSONValue?, _ expectedSigner: String? = nil, _ pqPins: JObject? = nil) -> JSONValue {
        if let bad = shapeError(so) { return verdict(bad) }
        guard case let .object(st)? = so, let principal = st[JKey("principal")]?.asString else { return verdict("intent statement is not an object") }
        if let e = expectedSigner, !IV.same(e, principal) { return verdict("principal mismatch") }
        let algPresent = st[JKey("alg")] != nil
        guard let suite = PCAIntentKit.suiteName(st[JKey("alg")], algPresent) else { return verdict("unknown signature suite") }
        let pqPkPresent = st[JKey("pq_pk")] != nil
        if IV.same(suite, "ed25519") && (pqPkPresent || st[JKey("pq_sig")] != nil) { return verdict("an ed25519 artifact must not carry pq_pk / pq_sig") }
        let bound = PCAIntentKit.bindSuiteFields(body(st), st[JKey("alg")], algPresent, st[JKey("pq_pk")], pqPkPresent)
        if let e = IV.strictCanonError(.object(bound)) { return verdict("malformed intent statement: \(e)") }
        guard let msg = try? PCAIntentKit.message(SIG_DOMAIN, .object(bound)) else { return verdict("malformed intent statement: canonicalize failed") }
        if !PCAIntentKit.verifyPinnedSuite(st[JKey("alg")], algPresent, principal, st[JKey("pq_pk")], msg, st[JKey("sig")], st[JKey("pq_sig")], pqPins) {
            return verdict("bad signature")
        }
        return verdict(nil)
    }

    /// The goal string that binds a grant to an intent statement (and optionally an Intent Map).
    public static func intentGoal(_ ref: String, _ mapDigest: String? = nil) -> String {
        if let m = mapDigest, !m.isEmpty { return INTENT_GOAL_PREFIX + ref + ":" + m }
        return INTENT_GOAL_PREFIX + ref
    }

    /// Parse an intent goal string: `{intentRef, mapDigest?}`, or nil when it is not one.
    public static func parseIntentGoal(_ goal: JSONValue?) -> JSONValue? {
        guard let g = goal?.asString, IV.startsWith(g, INTENT_GOAL_PREFIX) else { return nil }
        let parts = IV.split(IV.dropPrefix(g, IV.u8(INTENT_GOAL_PREFIX)), ":")
        let ref = parts[0]
        let map: String? = parts.count > 1 ? parts[1] : nil
        if ref.isEmpty || parts.count > 2 { return nil }
        var r: JObject = ["intentRef": .string(ref)]
        if let m = map, !m.isEmpty { r["mapDigest"] = .string(m) }
        return .object(r)
    }
}
