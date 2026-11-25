import Foundation

/// The signing half of action pins: single evolution records, the registry's key entry, the principal's re-approval of a widening step, the pin constants and
/// the reason-bearing counterparts of the registry-signature checks.
extension Actions {
    /// What a grant does with an unpinned (new) action: refuse it or escalate to the principal.
    public static let ACTION_PIN_ON_NEW = ["deny", "escalate"]
    /// The highest escalation tier a rule can name.
    public static let MAX_ESC_TIER: Int64 = 3

    /// Signs one evolution record as the registry (any suite the core supports); an invalid unsigned record throws and is never signed.
    public static func signEvolutionRecord(_ record: JSONValue, kid: String, key: PCASuiteKey) throws -> JSONValue {
        guard let r = try ActionEvolve.signEvolution([record], kid: kid, key: key).first else { throw PCAProducerError("signEvolutionRecord") }
        return r
    }

    /// The discovery key entry `{kid, alg, pk, pq_pk?}` a verifier pins for the registry signer.
    public static func registryKeyOf(kid: String, key: PCASuiteKey) throws -> JSONValue { try PCASigners.actionSchemaKeyOf(kid: kid, site: key) }

    /// The principal's approval of one evolution step for one grant: `{v, kind, grant, verb, diff, sig: {alg: "ed25519", value}}`, bound to the grant id and
    /// the record's diff digest; `record` may be signed or unsigned. Ed25519 only (the grant principal's key).
    public static func signReapproval(grantId: String, record: JSONValue, principal: PCAEdKey) throws -> JSONValue {
        guard let diff = evolutionDiffDigest(record) else { throw PCAProducerError("canonicalize: unsupported type undefined") }
        let body: JSONValue = .object(["v": .int(1), "kind": .string(REAPPROVAL_KIND), "grant": .string(grantId), "verb": record.get("verb") ?? .null, "diff": .string(diff)])
        guard let msg = IV.message(REAPPROVAL_DOMAIN, body) else { throw PCAProducerError("the re-approval is outside the strict JSON profile") }
        var o = body.asObject ?? [:]
        o["sig"] = .object(["alg": .string("ed25519"), "value": .string(Base64URLStrict.encode(try principal.sign(msg)))])
        return .object(o)
    }

    /// Why a registry-signed body does not verify under `domain` against the pinned keys (the suite comes from the KEY entry), or nil when it does. Never throws.
    public static func registrySigError(_ domain: String, _ body: JSONValue, _ sig: JSONValue, _ keys: JSONValue?) -> String? {
        guard case let .array(ks)? = keys else { return "the registry keys must be an array" }
        var key: JObject?
        for k in ks {
            guard case let .object(o) = k, let kid = o["kid"], !kid.isNull else { continue }
            switch (kid, sig.get("kid")) {
            case let (.string(a), .string(b)?) where IV.same(a, b): key = o
            case let (.int(a), .int(b)?) where a == b: key = o
            default: break
            }
            if key != nil { break }
        }
        guard let k = key else { return "no registry key with kid '\(JS.toString(sig.get("kid")))'" }
        if let pq = k["pq_pk"], pq.asString == nil { return "the registry key pq_pk must be a string" }
        guard let pk = k["pk"]?.asString, Base64URLStrict.isValid(pk, length: 32) else { return "registry key pk is not canonical base64url (32 bytes)" }
        guard let ka = IV.sigAlg(k["alg"]), PQ.resolve(ka) != nil, ka == IV.sigAlg(sig.get("alg")) else { return "sig.alg does not match the pinned key suite" }
        guard let msg = IV.message(domain, body) else { return "verification error: canonicalize: value out of profile" }
        let ok = IV.verifyPinned(alg: .string(ka), identity: pk, artifactPqPk: k["pq_pk"], msg: msg, sig: sig.get("value"), pqSig: sig.get("pq_value"), pin: k["pq_pk"].map { $0.asString ?? "" }) == .valid
        return ok ? nil : "signature invalid"
    }

    /// Why an evolution record is not well-formed and registry-signed (the shape first, then the signature), or nil.
    public static func evolutionRecordSigError(_ rec: JSONValue?, _ keys: JSONValue?) -> String? {
        if let bad = evolutionRecordError(rec) { return bad }
        guard case var .object(r)? = rec else { return "malformed record" }
        let sig = r["sig"] ?? .null
        r["sig"] = nil
        return registrySigError(EVOLUTION_DOMAIN, .object(r), sig, keys)
    }
}
