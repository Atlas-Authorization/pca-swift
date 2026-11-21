import Foundation

/// A signed runtime observation against an Intent Map: y = 0 says the outcome should NOT have been allowed (a divergence), y = 1
/// confirms it. Signed by whoever observed it (Ed25519; a PQ-suite artifact verifies only under a PQ key the verifier pins).
public enum PCAIntentObservation {
    public static let INTENT_OBS_SIG_DOMAIN = "atlas-pca/intent-obs/v1\u{0}"
    public static let INTENT_OBSERVATION_SOURCES: [String] = ["runtime", "witness", "elicitation", "import"]
    static let BODY_KEYS: [String] = ["v", "map_digest", "verb", "values", "y", "source", "observed_at", "pcactn_digest", "signer"]

    static func obsBody(_ o: JObject) -> JObject {
        var b: JObject = [:]
        for k in BODY_KEYS { if let x = o[JKey(k)] { b[JKey(k)] = x } }
        if case let .object(n) = IV.normalized(JSONValue.object(b)) { return n }
        return b
    }

    private static func isNum(_ o: JSONValue?, _ v: Double) -> Bool {
        guard let d = IV.num(o) else { return false }
        return d == v
    }

    private static func b32(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString else { return false }
        return Base64URLStrict.decode(s, length: 32) != nil
    }

    /// The first shape problem of an observation, or nil.
    static func obsShapeError(_ oo: JSONValue?) -> String? {
        guard let o = oo?.asObject, isNum(o[JKey("v")], 1.0) else { return "not an intent observation v1" }
        if !b32(o[JKey("map_digest")]) { return "map_digest is not canonical base64url (32 bytes)" }
        guard let verb = o[JKey("verb")]?.asString, !verb.isEmpty else { return "verb must be a non-empty string" }
        _ = verb
        var ok: Bool = false
        if let values = o[JKey("values")]?.asObject {
            ok = true
            for (_, x) in values {
                if x.asString != nil { continue }
                if let d = IV.num(x), d.isFinite { continue }
                ok = false
            }
        }
        if !ok { return "values must map paths to numbers or strings" }
        if !isNum(o[JKey("y")], 0.0) && !isNum(o[JKey("y")], 1.0) { return "y must be 0 or 1" }
        guard let source = o[JKey("source")]?.asString, INTENT_OBSERVATION_SOURCES.contains(where: { IV.same($0, source) }) else { return "unknown observation source" }
        guard let at = IV.int(o[JKey("observed_at")]), at >= 0 else { return "observed_at must be a non-negative safe integer" }
        _ = at
        if o[JKey("pcactn_digest")] != nil && !b32(o[JKey("pcactn_digest")]) { return "pcactn_digest is not canonical base64url (32 bytes)" }
        if !b32(o[JKey("signer")]) { return "signer is not canonical base64url (32 bytes)" }
        return nil
    }

    /// Sign an observation ({map_digest, verb, values, y, source, observed_at, pcactn_digest?}) as the holder of an Ed25519 seed.
    public static func signIntentObservation(_ o: JObject, _ signerSeed: [UInt8]) throws -> JSONValue {
        return try signIntentObservation(o, PCASuiteKey.ed25519(try PCAEdKey(seed: signerSeed)))
    }

    /// Sign under any registry suite (ML-DSA, hybrid, ...): alg and pq_pk are signed into the observation.
    public static func signIntentObservation(_ o: JObject, _ key: PCASuiteKey) throws -> JSONValue {
        guard let ed = key.ed else { throw JSError("signIntentObservation: signer needs an Ed25519 identity key") }
        var inp: JObject = o
        inp[JKey("v")] = JSONValue.int(1)
        inp[JKey("signer")] = JSONValue.string(ed.id)
        let body: JObject = obsBody(inp)
        if let bad = obsShapeError(JSONValue.object(body)) { throw JSError("signIntentObservation: \(bad)") }
        let signed: JObject = try PCAIntentKit.signSuite(body, key) { (b: JObject) throws -> [UInt8] in
            return try PCAIntentKit.message(INTENT_OBS_SIG_DOMAIN, JSONValue.object(b))
        }
        return JSONValue.object(signed)
    }

    private static func verdict(_ reason: String?) -> JSONValue {
        var r: JObject = [:]
        r[JKey("ok")] = JSONValue.bool(reason == nil)
        if let x = reason { r[JKey("reason")] = JSONValue.string(x) }
        return JSONValue.object(r)
    }

    /// {ok: true} or {ok: false, reason}. Never throws.
    public static func verifyIntentObservation(_ oo: JSONValue?, _ expectedSigner: String? = nil, _ pqPins: JObject? = nil) -> JSONValue {
        if let bad = obsShapeError(oo) { return verdict(bad) }
        guard let ob = oo?.asObject, let signer = ob[JKey("signer")]?.asString else { return verdict("not an intent observation v1") }
        if let e = expectedSigner, !IV.same(e, signer) { return verdict("signer mismatch") }
        let algPresent: Bool = ob[JKey("alg")] != nil
        guard let suite = PCAIntentKit.suiteName(ob[JKey("alg")], algPresent) else { return verdict("unknown signature suite") }
        if suite == "ed25519" && (ob[JKey("pq_pk")] != nil || ob[JKey("pq_sig")] != nil) { return verdict("an ed25519 artifact must not carry pq_pk / pq_sig") }
        let body: JObject = PCAIntentKit.bindSuiteFields(obsBody(ob), ob[JKey("alg")], algPresent, ob[JKey("pq_pk")], ob[JKey("pq_pk")] != nil)
        guard let msg = IV.message(INTENT_OBS_SIG_DOMAIN, JSONValue.object(body)) else { return verdict("malformed intent observation: canonicalize failed") }
        if !PCAIntentKit.verifyPinnedSuite(ob[JKey("alg")], algPresent, signer, ob[JKey("pq_pk")], msg, ob[JKey("sig")], ob[JKey("pq_sig")], pqPins) { return verdict("bad signature") }
        return verdict(nil)
    }
}
