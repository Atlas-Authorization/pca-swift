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
    static func validateSignatureWire(_ p: JObject) -> String? {
        validateSuiteFields(p, checkPqPk: true)
    }

    /// 0.4.1: a threshold share's `alg`/`sig`/`pq_sig` per suite, exactly like the leaf (absent `alg` == ed25519: a 64-byte
    /// `sig` and no `pq_sig`), EXCEPT `pq_pk`: on a share it is an optional echo judged by `Threshold.verifyShare` against the
    /// signer set, so the wire does not look at it. Mirrors `validateShareSignatureWire` in pq.ts.
    static func validateShareSignatureWire(_ s: JObject) -> String? {
        validateSuiteFields(s, checkPqPk: false)
    }

    private static func validateSuiteFields(_ p: JObject, checkPqPk: Bool) -> String? {
        if let a = p["alg"], a.asString == nil { return "'alg' must be a string" }
        guard let suite = resolve(p["alg"]?.asString) else {
            return "unknown signature alg '\(p["alg"]?.asString ?? "")'"
        }
        guard let sig = p["sig"]?.asString, Base64URLStrict.isValid(sig, length: suite.sigBytes) else {
            return "'sig' is not canonical base64url (\(suite.sigBytes) bytes) for alg '\(suite.alg.rawValue)'"
        }
        if !checkPqPk {
            // share: `pq_pk` is an optional echo, judged by Threshold.verifyShare against the signer set
        } else if suite.needsPqPk {
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

    /// Verify a signature under the ARTIFACT'S OWN `pq_pk` (CALLER-VOUCHED). Only for surfaces whose key is authorised
    /// elsewhere (threshold shares, the `pq_artifact` conformance primitives): it proves nothing about who issued the
    /// artifact. The capability chain and the PCActn leaf never call it; they go through `verifySuite` with a
    /// `PinnedPQ` from `resolvePqKey`.
    static func verifyLeaf(alg: String?, holder: String, pqPublicKey: String?, message: [UInt8],
                           sig: String?, pqSig: String?) -> Bool {
        verifySuite(alg: alg, holder: holder,
                    pq: resolvePqKey(identity: nil, artifactPk: pqPublicKey, trustedPk: pqPublicKey),
                    message: message, sig: sig, pqSig: pqSig)
    }

    /// The key-authorised seam. The PQ half verifies ONLY under `pq` (a `PinnedPQ`, minted solely by `resolvePqKey`),
    /// never under a `pq_pk` read off the artifact. FAIL-CLOSED: unknown alg / missing key / invalid -> false.
    static func verifySuite(alg: String?, holder: String, pq: PinnedPQ?, message: [UInt8],
                            sig: String?, pqSig: String?) -> Bool {
        guard let suite = resolve(alg), let sig = sig else { return false }
        switch suite.alg {
        case .ed25519:
            return Ed25519Strict.verifyB64u(holder, message, sig)
        case .mlDsa65:
            guard let pq = pq else { return false }
            return MLDSA.verifyB64u(pq.key, message, sig)
        case .hybrid:
            guard let pq = pq, let pqSig = pqSig else { return false }
            return Ed25519Strict.verifyB64u(holder, message, sig) && MLDSA.verifyB64u(pq.key, message, pqSig)
        }
    }

    /// THE choke point (R3-01), mirroring `resolvePqVerifyKey` in packages/pca/src/pq.ts. Returns the key to verify under,
    /// or nil (REFUSE) when no verifier-side authority vouches for the artifact's `pq_pk`:
    ///  1. `trustedPk`: a key the verifier itself holds (the stored grant). Used as is.
    ///  2. `pqPins[identity]` (own entry only): the artifact key MUST equal the pin; a differing pin is a refusal.
    ///  3. `holderPq`: the artifact key must hash to the signer's committed `holder_pq` (F-2).
    /// Natives have no allowUnboundPq: an artifact's own key is never enough.
    static func resolvePqKey(identity: String?, artifactPk: String?, holderPq: String? = nil,
                             pqPins: [String: String]? = nil, trustedPk: String? = nil) -> PinnedPQ? {
        if let t = trustedPk, !t.isEmpty { return PinnedPQ(key: t, source: "trusted") }
        guard let pk = artifactPk, !pk.isEmpty else { return nil }
        if let pins = pqPins, let id = identity, let pin = pins[id] {
            return pin == pk ? PinnedPQ(key: pk, source: "pin") : nil
        }
        if let hp = holderPq, Capability.holderPqCommitment(pk) == hp { return PinnedPQ(key: pk, source: "holder-commitment") }
        return nil
    }
}

/// An opaque PQ verification key (R3-01 choke point). The initialiser is `fileprivate`: the only producer is
/// `PQ.resolvePqKey` in this file, so `PQ.verifySuite` cannot be reached with a `pq_pk` read off the artifact being verified.
struct PinnedPQ {
    let key: String
    let source: String
    fileprivate init(key: String, source: String) { self.key = key; self.source = source }
}
