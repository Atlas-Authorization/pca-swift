import Foundation

/// B4 — post-quantum crypto-agility, mirroring `pq.ts`. An additive, backward-compatible `alg` slot for the
/// PCActn leaf signature: absent `alg` (or `"ed25519"`) is byte-identical to the classical wire. Suites:
///  - `ed25519`                   classical 64-byte Ed25519 `sig`;
///  - `ml-dsa-65`                 pure PQ: `sig` is an ML-DSA-65 signature verified under `pq_pk`;
///  - `hybrid-ed25519-ml-dsa-65`  BOTH `sig` (Ed25519 under the holder) AND `pq_sig` (ML-DSA under `pq_pk`),
///                                over the same canonical message — both must verify (fail-closed).
///
/// `alg` and `pq_pk` are SIGNED (part of the canonical body); `sig` and `pq_sig` are the signatures and are
/// excluded from the signed body (like `sig`/`threshold`).
enum PQ {
    static let ML_DSA_65_PUBLIC_KEY_BYTES = 1952
    static let ML_DSA_65_SIGNATURE_BYTES = 3309
    static let ED25519_SIGNATURE_BYTES = 64

    enum Alg: String { case ed25519, mlDsa65 = "ml-dsa-65", hybrid = "hybrid-ed25519-ml-dsa-65" }

    struct Suite {
        let alg: Alg
        let sigBytes: Int
        let needsPqPk: Bool
        let needsPqSig: Bool
    }

    static let suites: [String: Suite] = [
        "ed25519": Suite(alg: .ed25519, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: false, needsPqSig: false),
        "ml-dsa-65": Suite(alg: .mlDsa65, sigBytes: ML_DSA_65_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: false),
        "hybrid-ed25519-ml-dsa-65": Suite(alg: .hybrid, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true),
    ]

    /// Resolve the suite: `nil` (field absent) → ed25519; a known name → that suite; anything else → nil (fail-closed).
    static func resolve(_ alg: String?) -> Suite? {
        guard let alg = alg else { return suites["ed25519"] }
        return suites[alg]
    }

    /// Validate the signature-carrying fields (`alg`, `sig`, `pq_pk`, `pq_sig`) per suite (wire.ts seam).
    /// Returns nil when well-formed, else a reason. Strict + fail-closed.
    static func validateSignatureWire(_ p: [String: JSONValue]) -> String? {
        if let a = p["alg"], a.asString == nil { return "'alg' must be a string" }
        guard let suite = resolve(p["alg"]?.asString) else {
            return "unknown signature alg '\(p["alg"]?.asString ?? "")'"
        }
        guard let sig = p["sig"]?.asString, Base64URLStrict.isValid(sig, length: suite.sigBytes) else {
            return "'sig' is not canonical base64url (\(suite.sigBytes) bytes) for alg '\(suite.alg.rawValue)'"
        }
        if suite.needsPqPk {
            guard let pk = p["pq_pk"]?.asString, Base64URLStrict.isValid(pk, length: ML_DSA_65_PUBLIC_KEY_BYTES) else {
                return "'pq_pk' is not canonical base64url (\(ML_DSA_65_PUBLIC_KEY_BYTES) bytes)"
            }
        } else if p["pq_pk"] != nil {
            return "'pq_pk' must be absent for alg '\(suite.alg.rawValue)'"
        }
        if suite.needsPqSig {
            guard let sg = p["pq_sig"]?.asString, Base64URLStrict.isValid(sg, length: ML_DSA_65_SIGNATURE_BYTES) else {
                return "'pq_sig' is not canonical base64url (\(ML_DSA_65_SIGNATURE_BYTES) bytes)"
            }
        } else if p["pq_sig"] != nil {
            return "'pq_sig' must be absent for alg '\(suite.alg.rawValue)'"
        }
        return nil
    }

    /// Verify the leaf signature under the PCActn's suite. FAIL-CLOSED: unknown alg / missing / invalid → false.
    static func verifyLeaf(alg: String?, holder: String, pqPublicKey: String?, message: [UInt8],
                           sig: String?, pqSig: String?) -> Bool {
        guard let suite = resolve(alg), let sig = sig else { return false }
        switch suite.alg {
        case .ed25519:
            return Ed25519Strict.verifyB64u(holder, message, sig)
        case .mlDsa65:
            guard let pk = pqPublicKey else { return false }
            return MLDSA.verifyB64u(pk, message, sig)
        case .hybrid:
            guard let pk = pqPublicKey, let pqSig = pqSig else { return false }
            return Ed25519Strict.verifyB64u(holder, message, sig) && MLDSA.verifyB64u(pk, message, pqSig)
        }
    }
}
