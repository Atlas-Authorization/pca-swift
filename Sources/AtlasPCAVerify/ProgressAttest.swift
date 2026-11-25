import Foundation

/// Proof of progress, signed state attestations: a state source signs that a transition `(action, prior state) -> state` is what it observed, and a
/// verifier built over the trusted source keys and the attestations accepts a step only when the source is trusted, an attestation covers exactly that
/// transition, the step's evidence digest is the hash of that attestation, and the signature verifies (ed25519, ml-dsa-65 or hybrid, pins enforced). The
/// legacy opt-out `allowUnboundPq` is not supported: such an attestation is refused.
extension PCAProgress {
    /// The signed message: the domain, a NUL, then the strict canonical bytes of the suite-bound body `{source, goal_commitment, action_digest,
    /// prior_digest, state_digest}` (`alg` and `pq_pk` enter the body for a post-quantum suite).
    static func stateAttestationMessage(_ a: JSONValue, alg: JSONValue?, algPresent: Bool, pqPk: JSONValue?, pqPresent: Bool) throws -> [UInt8] {
        var body = JObject()
        for k in ["source", "goal_commitment", "action_digest", "prior_digest", "state_digest"] {
            guard let v = a.get(k) else { throw err("canonicalize: unsupported type undefined") }
            body[JKey(k)] = v
        }
        return try PCAIntentKit.message(STATE_ATTESTATION_DOMAIN, .object(PCAIntentKit.bindSuiteFields(body, alg, algPresent, pqPk, pqPresent)))
    }

    /// True iff `att` verifies under the trusted Ed25519 identity (and the pinned post-quantum key for a PQ suite); never throws.
    /// `pin`: `{pqPins?}` (the issuer identity to PQ public key map).
    public static func verifyStateAttestation(_ att: JSONValue?, _ trustedPublicKey: JSONValue?, _ pin: JSONValue? = nil) -> Bool {
        guard let a = att, a.isObject, case let .string(sig)? = a.get("sig"), a.get("source")?.asString != nil,
              case let .string(key)? = trustedPublicKey, !key.isEmpty else { return false }
        let algPresent = a.get("alg") != nil, pqPresent = a.get("pq_pk") != nil
        guard let msg = try? stateAttestationMessage(a, alg: a.get("alg"), algPresent: algPresent, pqPk: a.get("pq_pk"), pqPresent: pqPresent) else { return false }
        return PCAIntentKit.verifyPinnedSuite(a.get("alg"), algPresent, key, a.get("pq_pk"), msg, .string(sig), a.get("pq_sig"), pin?.get("pqPins")?.asObject)
    }

    private static func attestationKey(_ action: String, _ prior: String, _ state: String) -> [UInt16] { Array("\(action)\u{0}\(prior)\u{0}\(state)".utf16) }

    /// The attestation hook over `{trustedKeys, pqPins?, attestations}`: index the attestations by `action NUL prior NUL state` (a later duplicate
    /// replaces an earlier one); a step passes iff its source has a trusted key, an attestation of the same source covers the transition, the step's
    /// evidence digest is the strict hash of `{t: "pca-evidence", e: attestation}`, and the signature verifies. Never throws.
    public static func attestedStateVerifier(_ opts: JSONValue) -> (JSONValue) -> Bool {
        var byKey: [[UInt16]: JSONValue] = [:]
        for att in opts.get("attestations")?.asArray ?? [] {
            if let a = att.get("action_digest")?.asString, let p = att.get("prior_digest")?.asString, let s = att.get("state_digest")?.asString { byKey[attestationKey(a, p, s)] = att }
        }
        return { step in
            guard let src = step.get("state_source")?.asString, case let .string(pub)? = opts.get("trustedKeys")?.get(src), !pub.isEmpty,
                  let a = step.get("action_digest")?.asString, let b = step.get("before_digest")?.asString, let c = step.get("after_digest")?.asString,
                  let att = byKey[attestationKey(a, b, c)], att.get("source")?.asString.map({ $0.utf16.elementsEqual(src.utf16) }) == true,
                  let h = try? hashStrict(.object(["t": .string("pca-evidence"), "e": att])), let ev = step.get("evidence_digest")?.asString,
                  h.utf16.elementsEqual(ev.utf16) else { return false }
            return verifyStateAttestation(att, .string(pub), opts)
        }
    }
}
