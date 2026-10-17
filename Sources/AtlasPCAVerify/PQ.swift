import Foundation

/// The suite-capability manifest (packages/pca/conformance/SUITES.md), public: the closed TS registry, the registered
/// suites this verifier can verify on THIS OS, and the reason token of the rest.
public enum PCASuites {
    /// The closed TS suite registry (`SIG_SUITES` in pq.ts), in registry order.
    public static let registered: [String] = [
        "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
        "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
        "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "fn-dsa-1024", "less-cat1", "hybrid-ed25519-less-cat1",
    ]
    /// The registered suites this verifier implements on this OS (registry order). ML-DSA needs macOS / iOS 26.
    public static var supported: [String] { registered.filter { PQ.resolve($0) != nil } }
    /// The reason token of a registered suite this verifier does not verify (full reason `unsupported_suite: <alg>`).
    public static let unsupportedSuiteReason = "unsupported_suite"
}

/// B4 — post-quantum crypto-agility, mirroring `pq.ts`. An additive, backward-compatible `alg` slot for the
/// PCActn leaf signature: absent `alg` (or `"ed25519"`) is byte-identical to the classical wire.
///
/// Suite capability: every registered suite CryptoKit provides (pure mode, EMPTY context), on macOS / iOS 26+:
///  - `ml-dsa-65` / `ml-dsa-87`                pure PQ: `sig` is the ML-DSA signature under the resolved `pq_pk`;
///  - `hybrid-ed25519-ml-dsa-65` / `-87`       `sig` (Ed25519 under the holder, checked FIRST) AND `pq_sig` (ML-DSA)
///                                             over the same canonical message — both must verify (fail-closed);
///  - `hybrid-nested-ed25519-ml-dsa-65`        SUF-CMA: the ML-DSA half signs message ‖ the Ed25519 signature bytes.
/// CryptoKit has no SLH-DSA, FN-DSA or LESS and the package takes no third-party crypto, so `slh-dsa-*`, `fn-dsa-*`,
/// `less-cat1` and their hybrids (and the ML-DSA suites on an older OS) are refused with the distinct reason
/// `unsupported_suite: <alg>`; an unregistered alg keeps `unknown signature alg`.
///
/// `alg` and `pq_pk` are SIGNED (part of the canonical body); `sig` and `pq_sig` are the signatures and are
/// excluded from the signed body (like `sig`/`threshold`).
enum PQ {
    static let ML_DSA_65_PUBLIC_KEY_BYTES = 1952
    static let ML_DSA_65_SIGNATURE_BYTES = 3309
    static let ED25519_SIGNATURE_BYTES = 64

    enum Alg: String {
        case ed25519
        case mlDsa65 = "ml-dsa-65"
        case hybrid = "hybrid-ed25519-ml-dsa-65"
        case hybridNested = "hybrid-nested-ed25519-ml-dsa-65"
        case mlDsa87 = "ml-dsa-87"
        case hybrid87 = "hybrid-ed25519-ml-dsa-87"
    }

    struct Suite {
        let alg: Alg
        let sigBytes: Int
        let needsPqPk: Bool
        let needsPqSig: Bool
        /// The ML-DSA level of the PQ half (nil for ed25519).
        let pq: MLDSA.Level?
        /// SUF-CMA nested hybrid: the PQ half signs message ‖ the Ed25519 signature bytes.
        let nested: Bool
    }

    static let suites: [String: Suite] = [
        "ed25519": Suite(alg: .ed25519, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: false, needsPqSig: false, pq: nil, nested: false),
        "ml-dsa-65": Suite(alg: .mlDsa65, sigBytes: ML_DSA_65_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: false, pq: .mlDsa65, nested: false),
        "hybrid-ed25519-ml-dsa-65": Suite(alg: .hybrid, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: .mlDsa65, nested: false),
        "hybrid-nested-ed25519-ml-dsa-65": Suite(alg: .hybridNested, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: .mlDsa65, nested: true),
        "ml-dsa-87": Suite(alg: .mlDsa87, sigBytes: MLDSA.lens(.mlDsa87).sig, needsPqPk: true, needsPqSig: false, pq: .mlDsa87, nested: false),
        "hybrid-ed25519-ml-dsa-87": Suite(alg: .hybrid87, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: .mlDsa87, nested: false),
    ]

    /// Resolve the suite: `nil` (field absent) → ed25519; a name this verifier implements AND can run on this OS → that
    /// suite; anything else → nil (fail-closed; `refusal` names it).
    static func resolve(_ alg: String?) -> Suite? {
        guard let alg = alg else { return suites["ed25519"] }
        guard let s = suites[alg] else { return nil }
        return s.pq == nil || MLDSA.available ? s : nil
    }

    /// The refusal of an `alg` `resolve` rejects: `unsupported_suite: <alg>` for a registered suite, else unknown.
    static func refusal(_ alg: String?) -> String {
        if let a = alg, PCASuites.registered.contains(a) { return "\(PCASuites.unsupportedSuiteReason): \(a)" }
        return "unknown signature alg '\(alg ?? "")'"
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
        guard let suite = resolve(p["alg"]?.asString) else { return refusal(p["alg"]?.asString) }
        let pqLens = suite.pq.map(MLDSA.lens) ?? (pk: 0, sig: 0)
        guard let sig = p["sig"]?.asString, Base64URLStrict.isValid(sig, length: suite.sigBytes) else {
            return "'sig' is not canonical base64url (\(suite.sigBytes) bytes) for alg '\(suite.alg.rawValue)'"
        }
        if !checkPqPk {
            // share: `pq_pk` is an optional echo, judged by Threshold.verifyShare against the signer set
        } else if suite.needsPqPk {
            guard let pk = p["pq_pk"]?.asString, Base64URLStrict.isValid(pk, length: pqLens.pk) else {
                return "'pq_pk' is not canonical base64url (\(pqLens.pk) bytes)"
            }
        } else if p["pq_pk"] != nil {
            return "'pq_pk' must be absent for alg '\(suite.alg.rawValue)'"
        }
        if suite.needsPqSig {
            guard let sg = p["pq_sig"]?.asString, Base64URLStrict.isValid(sg, length: pqLens.sig) else {
                return "'pq_sig' is not canonical base64url (\(pqLens.sig) bytes)"
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
        guard let level = suite.pq else { return Ed25519Strict.verifyB64u(holder, message, sig) }
        guard let pq = pq else { return false }
        if !suite.needsPqSig { return MLDSA.verifyB64u(level, pq.key, message, sig) } // pure PQ: `sig` is the PQ signature
        // hybrid: the cheap Ed25519 half first (R6-API-04), then the PQ `pq_sig` (nested: over message ‖ Ed25519 sig bytes)
        guard let pqSig = pqSig, Ed25519Strict.verifyB64u(holder, message, sig) else { return false }
        if suite.nested {
            guard let edSig = Base64URLStrict.decode(sig, length: ED25519_SIGNATURE_BYTES) else { return false }
            return MLDSA.verifyB64u(level, pq.key, message + edSig, pqSig)
        }
        return MLDSA.verifyB64u(level, pq.key, message, pqSig)
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
