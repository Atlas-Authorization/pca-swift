import Foundation

/// Suite and number helpers of the intent artifacts, shared by the intent package (wrappers over the module's value rules).
public enum PCAIntentKit {
    private static func effective(_ alg: JSONValue?, _ algPresent: Bool) -> JSONValue? {
        return algPresent ? (alg ?? JSONValue.null) : nil
    }

    /// The suite an `alg` resolves to ("ed25519" when absent), or nil when this SDK does not implement it.
    public static func suiteName(_ alg: JSONValue?, _ algPresent: Bool) -> String? {
        guard let a = IV.sigAlg(effective(alg, algPresent)) else { return nil }
        return PQ.resolve(a) == nil ? nil : a
    }

    public static func verifyPinnedSuite(_ alg: JSONValue?, _ algPresent: Bool, _ identity: String?, _ artifactPqPk: JSONValue?, _ msg: [UInt8],
                                         _ sig: JSONValue?, _ pqSig: JSONValue?, _ pqPins: JObject?) -> Bool {
        guard let name = suiteName(alg, algPresent), let id = identity else { return false }
        if name == "ed25519" { return verifyEd(JSONValue.string(id), msg, sig) }
        var pin: String? = nil
        if let p = pqPins?[JKey(id)]?.asString { pin = p }
        return IV.verifyPinned(alg: effective(alg, algPresent), identity: id, artifactPqPk: artifactPqPk, msg: msg, sig: sig, pqSig: pqSig, pin: pin) == IV.SuiteVerdict.valid
    }

    public static func bindSuiteFields(_ base: JObject, _ alg: JSONValue?, _ algPresent: Bool, _ pqPk: JSONValue?, _ pqPresent: Bool) -> JObject {
        guard let name = suiteName(alg, algPresent), name != "ed25519" else { return base }
        var out: JObject = base
        out[JKey("alg")] = JSONValue.string(name)
        if pqPresent { out[JKey("pq_pk")] = pqPk ?? JSONValue.null }
        return out
    }

    /// `Number.isSafeInteger(v) && !Object.is(v, -0)` for a JSON number.
    public static func isInt(_ v: JSONValue?) -> Bool { return IV.int(v) != nil }

    /// The binary64 value of a JSON number, else nil.
    public static func num(_ v: JSONValue?) -> Double? { return IV.num(v) }

    /// `utf8(domain) || strictCanonical(body)`; throws where the reference's canonicalizer throws.
    public static func message(_ domain: String, _ body: JSONValue) throws -> [UInt8] {
        guard let m = IV.message(domain, body) else { throw JSError("canonicalize: value out of profile") }
        return m
    }

    /// Strict Ed25519 under a b64u key; a malformed key or signature is a failed signature.
    public static func verifyEd(_ pub: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        guard let p = pub?.asString else { return false }
        return IV.verifyEd(p, msg, sig)
    }

    /// Sign `body` under the key's suite: the message is `msg(bound)` where a non-ed25519 suite binds `alg` and `pq_pk` into the signed
    /// body; the result is the body plus `sig` (and `alg`, `pq_pk`, `pq_sig` when the suite has them). The key must carry an Ed25519
    /// identity (the artifact's principal).
    public static func signSuite(_ body: JObject, _ key: PCASuiteKey, _ msg: (JObject) throws -> [UInt8]) throws -> JObject {
        if key.ed == nil { throw JSError("signer needs an Ed25519 identity key") }
        var bound: JObject = body
        if key.alg != "ed25519" {
            bound[JKey("alg")] = JSONValue.string(key.alg)
            bound[JKey("pq_pk")] = key.pqPk.map { JSONValue.string($0) } ?? JSONValue.null
        }
        let sg = try key.sign(try msg(bound))
        var out: JObject = bound
        out[JKey("sig")] = JSONValue.string(sg.sig)
        if let q = sg.pqSig { out[JKey("pq_sig")] = JSONValue.string(q) }
        return out
    }
}
