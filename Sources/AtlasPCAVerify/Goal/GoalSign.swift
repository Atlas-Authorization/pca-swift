import Foundation

/// The one signer of the goal-to-decision flow: approvals, test sets, policy pins and precedents are artifacts signed with the
/// suite-agile artifact signer under a per-kind domain, over strict canonical bytes.
public enum PCAGoalSign {
    /// Domain separation: an artifact of one kind never verifies as another kind.
    public static func goalDomain(_ kind: String) -> String { return "atlas-pca/goal/" + kind + "/v1\u{0}" }

    /// The pinned public identity (b64u Ed25519) of a signing key.
    public static func signerId(_ key: PCAEdKey) -> String { return key.id }

    /// The pinned public identity of a 32-byte Ed25519 seed.
    public static func signerId(_ seed: [UInt8]) throws -> String { return try PCAEdKey(seed: seed).id }

    /// Sign a flat artifact body (it must already carry its signer identity member). Throws on a non-canonical body.
    public static func signGoalArtifact(_ kind: String, _ body: JSONValue, _ signer: PCASuiteKey) throws -> JSONValue {
        return JSONValue.object(try PCAIssue.signArtifact(domain: goalDomain(kind), body: body, signer: signer))
    }

    public static func signGoalArtifact(_ kind: String, _ body: JSONValue, _ seed: [UInt8]) throws -> JSONValue {
        return try signGoalArtifact(kind, body, PCASuiteKey.ed25519(try PCAEdKey(seed: seed)))
    }

    /// The `pk` of a pin: a b64u key string, or the `pk` member of a pin object.
    private static func pinPk(_ p: JSONValue) -> String? {
        if let s = p.asString { return s }
        return GV.get(p, "pk")?.asString
    }

    /// Verify a signed artifact against the caller's PINNED signers (each a b64u key string or an object {pk, pq_pk}): the pin whose
    /// `pk` equals the artifact's own `signerField` member must verify. Total: false on anything malformed.
    public static func verifyGoalArtifact(_ kind: String, _ artifact: JSONValue?, _ signerField: String, _ pins: [JSONValue]) -> Bool {
        guard let a = artifact?.asObject else { return false }
        if IntentWB.artifactSuiteError(a) != nil { return false }
        guard let who = a[JKey(signerField)]?.asString else { return false }
        for p in pins {
            guard let pk = pinPk(p), IV.same(who, pk) else { continue }
            return verifyArtifactSig(goalDomain(kind), a, p)
        }
        return false
    }

    /// The artifact's signature under a PINNED signer (a b64u key string or an object {pk, pq_pk?}); the caller has checked the
    /// suite members. Ed25519 under `pk`; any other suite only when the artifact's `pq_pk` equals the pin's. Total.
    public static func verifyArtifactSig(_ domain: String, _ a: JObject, _ pin: JSONValue?) -> Bool {
        guard let p = pin, let pk = pinPk(p), a[JKey("sig")]?.asString != nil else { return false }
        var pinPq: String? = nil
        if p.isObject, let q = GV.get(p, "pq_pk")?.asString { pinPq = q }
        return IntentWB.verifyArtifactSig(domain, a, pk, pqPin: pinPq)
    }

    /// The same with the pins as one parsed value (anything but an array verifies nothing).
    public static func verifyGoalArtifact(_ kind: String, _ artifact: JSONValue?, _ signerField: String, _ pins: JSONValue?) -> Bool {
        guard let ps = pins?.asArray else { return false }
        return verifyGoalArtifact(kind, artifact, signerField, ps)
    }

    public static func verifyArtifactSig(_ domain: String, _ a: JSONValue, _ pin: JSONValue?) -> Bool {
        guard let o = a.asObject else { return false }
        return verifyArtifactSig(domain, o, pin)
    }

    /// A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents.
    public static func signPayload(_ kind: String, _ payload: JSONValue, _ key: PCAEdKey, _ suite: PCASuiteKey) throws -> JSONValue {
        return try signGoalArtifact(kind, GV.obj([("v", JSONValue.int(1)), ("kind", JSONValue.string(kind)), ("signer", JSONValue.string(key.id)), ("payload", payload)]), suite)
    }

    public static func signPayload(_ kind: String, _ payload: JSONValue, _ seed: [UInt8]) throws -> JSONValue {
        let key = try PCAEdKey(seed: seed)
        return try signPayload(kind, payload, key, PCASuiteKey.ed25519(key))
    }

    public static func verifyPayload(_ s: JSONValue?, _ kind: String, _ pins: [JSONValue]) -> Bool {
        guard let o = s, o.isObject, GV.safeInt(GV.get(o, "v")) == 1, let k = GV.get(o, "kind")?.asString, IV.same(k, kind) else { return false }
        return verifyGoalArtifact(kind, o, "signer", pins)
    }

    public static func verifyPayload(_ s: JSONValue?, _ kind: String, _ pins: JSONValue?) -> Bool {
        guard let ps = pins?.asArray else { return false }
        return verifyPayload(s, kind, ps)
    }
}
