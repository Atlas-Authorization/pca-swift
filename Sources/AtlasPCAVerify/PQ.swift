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
    /// The registered suites this verifier implements on this OS (registry order). ML-DSA is on every platform (CryptoKit on macOS / iOS 26, the vendored CMLDSA target elsewhere).
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
/// CryptoKit has no SLH-DSA, FN-DSA or LESS and the package takes no third-party crypto, so `slh-dsa-*` (verified through `PCASlhDsaHook`, which the
/// opt-in AtlasPCAOpenSSL product registers on libcrypto 3.5+), `less-cat1` and their hybrids (and the ML-DSA suites on an older OS) are refused with the distinct reason
/// `unsupported_suite: <alg>`; an unregistered alg keeps `unknown signature alg`.
///
/// `less-cat1` / `hybrid-ed25519-less-cat1` are registered suites verified through `PCALessHook` (the AtlasPCALess product registers the patched
/// reference C into it; nothing registers itself). The LESS signature is variable-length (1,153..1,329 bytes in steps of 16); without a backend the
/// suites resolve to nil like the SLH-DSA ones. This SDK cannot SIGN with them.
///
/// `fn-dsa-512` / `fn-dsa-1024` are registered pure PQ suites verified through `PCAFnDsaHook` (the AtlasPCAFnDsa product registers a
/// backend into it; nothing registers itself). With no backend they resolve to nil: refused `unsupported_suite`, never accepted.
///
/// `alg` and `pq_pk` are SIGNED (part of the canonical body); `sig` and `pq_sig` are the signatures and are
/// excluded from the signed body (like `sig`/`threshold`).
public enum PQ {
    static let ML_DSA_65_PUBLIC_KEY_BYTES = 1952
    public static let ML_DSA_65_SIGNATURE_BYTES = 3309
    static let ED25519_SIGNATURE_BYTES = 64

    enum Alg: String {
        case ed25519
        case mlDsa65 = "ml-dsa-65"
        case hybrid = "hybrid-ed25519-ml-dsa-65"
        case hybridNested = "hybrid-nested-ed25519-ml-dsa-65"
        case mlDsa87 = "ml-dsa-87"
        case hybrid87 = "hybrid-ed25519-ml-dsa-87"
        case fnDsa512 = "fn-dsa-512"
        case fnDsa1024 = "fn-dsa-1024"
        case lessCat1 = "less-cat1"
        case hybridLess = "hybrid-ed25519-less-cat1"
        case slh128f = "slh-dsa-sha2-128f"
        case hybridSlh128f = "hybrid-ed25519-slh-dsa-sha2-128f"
        case slh256s = "slh-dsa-sha2-256s"
        case hybridSlh256s = "hybrid-ed25519-slh-dsa-sha2-256s"
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
        /// The FN-DSA variant of a pure FN-DSA suite (verified through `PCAFnDsaHook`); nil otherwise.
        var fnDsa: String? = nil
        /// A LESS (code-based) suite, verified through `PCALessHook`; its signature is variable-length (`sigBytes` / `pqSigBytes` is the maximum).
        var lessCat1: Bool = false
        /// The SLH-DSA parameter set of an SLH-DSA suite (`slh-dsa-sha2-128f` / `slh-dsa-sha2-256s`, pure or hybrid), verified through `PCASlhDsaHook`; nil otherwise.
        var slh: String? = nil
        var pqPkBytes: Int {
            if lessCat1 { return PCALessHook.pkBytes }
            if let v = slh { return PCASlhDsaHook.pkBytes[v]! }
            return fnDsa.map { PCAFnDsaHook.pkBytes[$0]! } ?? pq.map { MLDSA.lens($0).pk } ?? 0
        }
        var pqSigBytes: Int {
            if lessCat1 { return needsPqSig ? PCALessHook.sigMax : 0 }
            if let v = slh { return needsPqSig ? PCASlhDsaHook.sigBytes[v]! : 0 }
            return pq.map { MLDSA.lens($0).sig } ?? 0
        }
        /// False for a backend-verified suite (FN-DSA, LESS, SLH-DSA) whose backend is not registered: such a suite is refused, never accepted.
        var backendReady: Bool {
            if fnDsa != nil { return PCAFnDsaHook.isRegistered }
            if lessCat1 { return PCALessHook.isRegistered }
            if slh != nil { return PCASlhDsaHook.isRegistered }
            return true
        }
    }

    static let suites: [String: Suite] = [
        "ed25519": Suite(alg: .ed25519, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: false, needsPqSig: false, pq: nil, nested: false),
        "ml-dsa-65": Suite(alg: .mlDsa65, sigBytes: ML_DSA_65_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: false, pq: .mlDsa65, nested: false),
        "hybrid-ed25519-ml-dsa-65": Suite(alg: .hybrid, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: .mlDsa65, nested: false),
        "hybrid-nested-ed25519-ml-dsa-65": Suite(alg: .hybridNested, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: .mlDsa65, nested: true),
        "ml-dsa-87": Suite(alg: .mlDsa87, sigBytes: MLDSA.lens(.mlDsa87).sig, needsPqPk: true, needsPqSig: false, pq: .mlDsa87, nested: false),
        "hybrid-ed25519-ml-dsa-87": Suite(alg: .hybrid87, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: .mlDsa87, nested: false),
        "fn-dsa-512": Suite(alg: .fnDsa512, sigBytes: PCAFnDsaHook.sigBytes["fn-dsa-512"]!, needsPqPk: true, needsPqSig: false, pq: nil, nested: false, fnDsa: "fn-dsa-512"),
        "fn-dsa-1024": Suite(alg: .fnDsa1024, sigBytes: PCAFnDsaHook.sigBytes["fn-dsa-1024"]!, needsPqPk: true, needsPqSig: false, pq: nil, nested: false, fnDsa: "fn-dsa-1024"),
        "less-cat1": Suite(alg: .lessCat1, sigBytes: PCALessHook.sigMax, needsPqPk: true, needsPqSig: false, pq: nil, nested: false, lessCat1: true),
        "hybrid-ed25519-less-cat1": Suite(alg: .hybridLess, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: nil, nested: false, lessCat1: true),
        "slh-dsa-sha2-128f": Suite(alg: .slh128f, sigBytes: PCASlhDsaHook.sigBytes["SLH-DSA-SHA2-128f"]!, needsPqPk: true, needsPqSig: false, pq: nil, nested: false, slh: "SLH-DSA-SHA2-128f"),
        "hybrid-ed25519-slh-dsa-sha2-128f": Suite(alg: .hybridSlh128f, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: nil, nested: false, slh: "SLH-DSA-SHA2-128f"),
        "slh-dsa-sha2-256s": Suite(alg: .slh256s, sigBytes: PCASlhDsaHook.sigBytes["SLH-DSA-SHA2-256s"]!, needsPqPk: true, needsPqSig: false, pq: nil, nested: false, slh: "SLH-DSA-SHA2-256s"),
        "hybrid-ed25519-slh-dsa-sha2-256s": Suite(alg: .hybridSlh256s, sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, needsPqSig: true, pq: nil, nested: false, slh: "SLH-DSA-SHA2-256s"),
    ]

    /// Resolve the suite: `nil` (field absent) → ed25519; a name this verifier implements AND can run on this OS → that
    /// suite; anything else → nil (fail-closed; `refusal` names it).
    static func resolve(_ alg: String?) -> Suite? {
        guard let alg = alg else { return suites["ed25519"] }
        guard let s = suites[alg] else { return nil }
        if s.fnDsa != nil { return PCAFnDsaHook.isRegistered ? s : nil } // no backend: refused, never accepted
        if s.lessCat1 { return PCALessHook.isRegistered ? s : nil }
        if s.slh != nil { return PCASlhDsaHook.isRegistered ? s : nil }
        return s.pq == nil || MLDSA.available ? s : nil
    }

    /// The refusal of an `alg` `resolve` rejects: `unsupported_suite: <alg>` for a registered suite, else unknown.
    static func refusal(_ alg: String?) -> String {
        if let a = alg, PCASuites.registered.contains(a) { return "\(PCASuites.unsupportedSuiteReason): \(a)" }
        return "unknown signature alg '\(alg ?? "")'"
    }

    /// Validate the signature-carrying fields (`alg`, `sig`, `pq_pk`, `pq_sig`) per suite (wire.ts seam).
    /// Returns nil when well-formed, else a reason. Strict + fail-closed.
    public static func validateSignatureWire(_ p: JObject) -> String? {
        validateSuiteFields(p, checkPqPk: true)
    }

    /// 0.4.1: a threshold share's `alg`/`sig`/`pq_sig` per suite, exactly like the leaf (absent `alg` == ed25519: a 64-byte
    /// `sig` and no `pq_sig`), EXCEPT `pq_pk`: on a share it is an optional echo judged by `Threshold.verifyShare` against the
    /// signer set, so the wire does not look at it. Mirrors `validateShareSignatureWire` in pq.ts.
    public static func validateShareSignatureWire(_ s: JObject) -> String? {
        validateSuiteFields(s, checkPqPk: false)
    }

    private static func validateSuiteFields(_ p: JObject, checkPqPk: Bool) -> String? {
        if let a = p["alg"], a.asString == nil { return "'alg' must be a string" }
        guard let suite = resolve(p["alg"]?.asString) else { return refusal(p["alg"]?.asString) }
        let pqLens = (pk: suite.pqPkBytes, sig: suite.pqSigBytes)
        let sigVar = suite.lessCat1 && !suite.needsPqSig, pqSigVar = suite.lessCat1 && suite.needsPqSig
        guard let sig = p["sig"]?.asString, sigVar ? PCALessHook.sigWireOK(sig) : Base64URLStrict.isValid(sig, length: suite.sigBytes) else {
            return "'sig' is not canonical base64url (\(sigVar ? "\(PCALessHook.sigMin)..\(suite.sigBytes)" : "\(suite.sigBytes)") bytes) for alg '\(suite.alg.rawValue)'"
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
            guard let sg = p["pq_sig"]?.asString, pqSigVar ? PCALessHook.sigWireOK(sg) : Base64URLStrict.isValid(sg, length: pqLens.sig) else {
                return "'pq_sig' is not canonical base64url (\(pqSigVar ? "\(PCALessHook.sigMin)..\(pqLens.sig)" : "\(pqLens.sig)") bytes) for alg '\(suite.alg.rawValue)'"
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
        if let v = suite.fnDsa { // pure PQ: `sig` is the FN-DSA signature under the pinned `pq_pk`; lengths first, then the backend
            guard let pq = pq, let pk = Base64URLStrict.decode(pq.key, length: suite.pqPkBytes),
                  let sg = Base64URLStrict.decode(sig, length: suite.sigBytes) else { return false }
            return PCAFnDsaHook.verify(v, vk: pk, msg: message, sig: sg)
        }
        if suite.lessCat1 { // LESS: lengths first (the key exactly, the signature in its variable-length set), then the backend; a hybrid checks Ed25519 FIRST
            guard let pq = pq, let pk = Base64URLStrict.decode(pq.key, length: suite.pqPkBytes) else { return false }
            if !suite.needsPqSig {
                guard let sg = Base64URLStrict.decode(sig), PCALessHook.sigLenOK(sg.count) else { return false }
                return PCALessHook.verify(vk: pk, msg: message, sig: sg)
            }
            guard let pqSig = pqSig, Ed25519Strict.verifyB64u(holder, message, sig),
                  let sg = Base64URLStrict.decode(pqSig), PCALessHook.sigLenOK(sg.count) else { return false }
            return PCALessHook.verify(vk: pk, msg: message, sig: sg)
        }
        if let fam = suite.slh { // SLH-DSA (pure, empty context): the key and signature lengths exactly, then the backend; a hybrid checks Ed25519 FIRST
            guard let pq = pq, let pk = Base64URLStrict.decode(pq.key, length: suite.pqPkBytes) else { return false }
            if !suite.needsPqSig {
                guard let sg = Base64URLStrict.decode(sig, length: suite.sigBytes) else { return false }
                return PCASlhDsaHook.verify(fam, vk: pk, msg: message, sig: sg)
            }
            guard let pqSig = pqSig, Ed25519Strict.verifyB64u(holder, message, sig),
                  let sg = Base64URLStrict.decode(pqSig, length: suite.pqSigBytes) else { return false }
            return PCASlhDsaHook.verify(fam, vk: pk, msg: message, sig: sg)
        }
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

/// The registry the core owns for LESS (code-based, NIST additional-signature round-2 candidate, not a standard; the core takes no native dependency).
/// `AtlasPCALess` calls `register` explicitly; nothing registers at import. A backend that throws or answers anything but true is a deny; with no
/// backend the two LESS suites resolve to nil (refused `unsupported_suite`, never accepted). Signing is a separate registration (`registerSigner`):
/// a verify-only backend can never sign.
public enum PCALessHook {
    public static let pkBytes = 97_484, sigMin = 1_153, sigMax = 1_329, sigStep = 16
    private static let lock = NSLock()
    private static var backend: ((_ vk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool)?
    public static func register(_ verify: @escaping (_ vk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool) { lock.lock(); backend = verify; lock.unlock() }
    /// Clears the verify backend AND the signer.
    public static func unregister() { lock.lock(); backend = nil; signer = nil; lock.unlock() }
    public static var isRegistered: Bool { lock.lock(); defer { lock.unlock() }; return backend != nil }

    /// The signing half of a backend: key generation from a seed (at least 32 bytes) and signing with an optional seed (nil: the backend draws 32
    /// fresh CSPRNG bytes; the same seed gives the same signature, for conformance replays).
    public struct Signer {
        public let keygen: (_ seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8])
        public let sign: (_ sk: [UInt8], _ msg: [UInt8], _ seed: [UInt8]?) throws -> [UInt8]
        public init(keygen: @escaping (_ seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8]),
                    sign: @escaping (_ sk: [UInt8], _ msg: [UInt8], _ seed: [UInt8]?) throws -> [UInt8]) {
            self.keygen = keygen; self.sign = sign
        }
    }
    private static var signer: Signer?
    public static func registerSigner(_ s: Signer) { lock.lock(); signer = s; lock.unlock() }
    public static var isSignerRegistered: Bool { lock.lock(); defer { lock.unlock() }; return signer != nil }
    static var currentSigner: Signer? { lock.lock(); defer { lock.unlock() }; return signer }
    /// A length a LESS cat-1 signature can have: 1,153..1,329 bytes in steps of 16.
    public static func sigLenOK(_ n: Int) -> Bool { n >= sigMin && n <= sigMax && (sigMax - n) % sigStep == 0 }
    /// A canonical base64url value that decodes to a LESS signature length.
    static func sigWireOK(_ s: String) -> Bool { Base64URLStrict.decode(s).map { sigLenOK($0.count) } ?? false }
    static func verify(vk: [UInt8], msg: [UInt8], sig: [UInt8]) -> Bool {
        lock.lock(); let b = backend; lock.unlock()
        guard let b = b, vk.count == pkBytes, sigLenOK(sig.count) else { return false }
        return (try? b(vk, msg, sig)) == true
    }
}

/// LESS key material for the agent-side signer: the verifying key, the secret key and an optional sign seed (at least 32 bytes; nil: 32 fresh CSPRNG
/// bytes per signature, which is what real signing does; a fixed seed makes signatures reproducible for conformance replays).
public struct PCALessKey {
    public let vk: [UInt8]
    public let sk: [UInt8]
    public let signSeed: [UInt8]?
    public init(vk: [UInt8], sk: [UInt8], signSeed: [UInt8]? = nil) { self.vk = vk; self.sk = sk; self.signSeed = signSeed }

    /// Key pair from a keygen seed (at least 32 bytes) through the registered signer. Without one: the typed `unsupported_suite` refusal.
    public static func fromSeed(seed: [UInt8], signSeed: [UInt8]? = nil) throws -> PCALessKey {
        guard let s = PCALessHook.currentSigner else { throw PCAProducerError(PQ.refusal("less-cat1")) }
        guard seed.count >= 32, signSeed == nil || signSeed!.count >= 32 else { throw PCAProducerError("a LESS seed is at least 32 bytes") }
        let kp = try s.keygen(seed)
        return PCALessKey(vk: kp.vk, sk: kp.sk, signSeed: signSeed)
    }
    public var pkB64u: String { Base64URLStrict.encode(vk) }
}

/// The registry the core owns for SLH-DSA (FIPS 205, SHA2 parameter sets 128f and 256s, pure mode, EMPTY context; the core takes no native
/// dependency). `AtlasPCAOpenSSL` (`PCAOpenSSL.registerSlhDsa()`, libcrypto 3.5+) registers a backend explicitly; nothing registers at import. A backend
/// that throws or answers anything but true is a deny; with no backend the four SLH-DSA suites resolve to nil (refused `unsupported_suite`, never
/// accepted). Signing is a separate registration (`registerSigner`): a verify-only backend can never sign.
public enum PCASlhDsaHook {
    /// The parameter sets, by their FIPS 205 names.
    public static let families = ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-256s"]
    public static let pkBytes = ["SLH-DSA-SHA2-128f": 32, "SLH-DSA-SHA2-256s": 64]
    public static let skBytes = ["SLH-DSA-SHA2-128f": 64, "SLH-DSA-SHA2-256s": 128]
    public static let sigBytes = ["SLH-DSA-SHA2-128f": 17_088, "SLH-DSA-SHA2-256s": 29_792]
    /// The key-generation seed: SK.seed || SK.prf || PK.seed (3n bytes).
    public static let seedBytes = ["SLH-DSA-SHA2-128f": 48, "SLH-DSA-SHA2-256s": 96]
    /// The suite name of a parameter set (pure).
    public static func suiteName(_ family: String) -> String? {
        family == "SLH-DSA-SHA2-128f" ? "slh-dsa-sha2-128f" : family == "SLH-DSA-SHA2-256s" ? "slh-dsa-sha2-256s" : nil
    }
    /// The parameter set a pure SLH-DSA suite name stands for.
    public static func family(ofSuite alg: String) -> String? {
        alg == "slh-dsa-sha2-128f" ? "SLH-DSA-SHA2-128f" : alg == "slh-dsa-sha2-256s" ? "SLH-DSA-SHA2-256s" : nil
    }

    private static let lock = NSLock()
    private static var backend: ((_ family: String, _ vk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool)?
    public static func register(_ verify: @escaping (_ family: String, _ vk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool) {
        lock.lock(); backend = verify; lock.unlock()
    }
    /// Clears the verify backend AND the signer: back to "no backend", where every SLH-DSA suite is refused.
    public static func unregister() { lock.lock(); backend = nil; signer = nil; lock.unlock() }
    public static var isRegistered: Bool { lock.lock(); defer { lock.unlock() }; return backend != nil }

    /// The signing half of a backend: key generation from a 3n-byte seed and (deterministic, FIPS 205 section 10.2.1 with opt_rand = PK.seed) signing
    /// under the raw secret key.
    public struct Signer {
        public let keygen: (_ family: String, _ seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8])
        public let sign: (_ family: String, _ sk: [UInt8], _ msg: [UInt8]) throws -> [UInt8]
        public init(keygen: @escaping (_ family: String, _ seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8]),
                    sign: @escaping (_ family: String, _ sk: [UInt8], _ msg: [UInt8]) throws -> [UInt8]) {
            self.keygen = keygen; self.sign = sign
        }
    }
    private static var signer: Signer?
    public static func registerSigner(_ s: Signer) { lock.lock(); signer = s; lock.unlock() }
    public static var isSignerRegistered: Bool { lock.lock(); defer { lock.unlock() }; return signer != nil }
    static var currentSigner: Signer? { lock.lock(); defer { lock.unlock() }; return signer }
    static func verify(_ family: String, vk: [UInt8], msg: [UInt8], sig: [UInt8]) -> Bool {
        lock.lock(); let b = backend; lock.unlock()
        guard let b = b, vk.count == pkBytes[family], sig.count == sigBytes[family] else { return false }
        return (try? b(family, vk, msg, sig)) == true
    }
}

/// SLH-DSA key material for the agent-side signer: the parameter set, the verifying key and the raw secret key (4n bytes).
public struct PCASlhDsaKey {
    public let family: String
    public let vk: [UInt8]
    public let sk: [UInt8]
    public init(family: String, vk: [UInt8], sk: [UInt8]) { self.family = family; self.vk = vk; self.sk = sk }

    /// Key pair from a 3n-byte seed (48 for 128f, 96 for 256s) through the registered signer. Without one: the typed `unsupported_suite` refusal.
    public static func fromSeed(_ family: String, seed: [UInt8]) throws -> PCASlhDsaKey {
        guard PCASlhDsaHook.pkBytes[family] != nil, let s = PCASlhDsaHook.currentSigner else {
            throw PCAProducerError(PQ.refusal(PCASlhDsaHook.suiteName(family) ?? family))
        }
        guard seed.count == PCASlhDsaHook.seedBytes[family] else { throw PCAProducerError("an \(family) seed is \(PCASlhDsaHook.seedBytes[family]!) bytes") }
        let kp = try s.keygen(family, seed)
        return PCASlhDsaKey(family: family, vk: kp.vk, sk: kp.sk)
    }
    public var pkB64u: String { Base64URLStrict.encode(vk) }
}

/// An opaque PQ verification key (R3-01 choke point). The initialiser is `fileprivate`: the only producer is
/// `PQ.resolvePqKey` in this file, so `PQ.verifySuite` cannot be reached with a `pq_pk` read off the artifact being verified.
struct PinnedPQ {
    let key: String
    let source: String
    fileprivate init(key: String, source: String) { self.key = key; self.source = source }
}

/// The registry the core owns for FN-DSA (the core takes no native dependency). `AtlasPCAFnDsa` calls `register` explicitly; nothing registers at
/// import. A backend that throws or answers anything but true is a deny.
public enum PCAFnDsaHook {
    public static let pkBytes = ["fn-dsa-512": 897, "fn-dsa-1024": 1793]
    public static let sigBytes = ["fn-dsa-512": 666, "fn-dsa-1024": 1280]
    private static let lock = NSLock()
    private static var backend: ((_ variant: String, _ vk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool)?
    public static func register(_ verify: @escaping (_ variant: String, _ vk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool) {
        lock.lock(); backend = verify; lock.unlock()
    }
    /// Clears the verify backend AND the signer: back to "no backend", where every FN-DSA suite is refused.
    public static func unregister() { lock.lock(); backend = nil; signer = nil; lock.unlock() }

    /// The signing half of a backend: key generation from a 32-byte seed and signing with an optional 32-byte sign seed (nil: the backend draws
    /// 32 fresh CSPRNG bytes). Registered separately from `register` so a verify-only backend can never sign.
    public struct Signer {
        public let keygen: (_ variant: String, _ seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8])
        public let sign: (_ variant: String, _ sk: [UInt8], _ msg: [UInt8], _ seed: [UInt8]?) throws -> [UInt8]
        public init(keygen: @escaping (_ variant: String, _ seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8]),
                    sign: @escaping (_ variant: String, _ sk: [UInt8], _ msg: [UInt8], _ seed: [UInt8]?) throws -> [UInt8]) {
            self.keygen = keygen; self.sign = sign
        }
    }
    private static var signer: Signer?
    public static func registerSigner(_ s: Signer) { lock.lock(); signer = s; lock.unlock() }
    public static var isSignerRegistered: Bool { lock.lock(); defer { lock.unlock() }; return signer != nil }
    static var currentSigner: Signer? { lock.lock(); defer { lock.unlock() }; return signer }
    public static var isRegistered: Bool { lock.lock(); defer { lock.unlock() }; return backend != nil }
    static func verify(_ variant: String, vk: [UInt8], msg: [UInt8], sig: [UInt8]) -> Bool {
        lock.lock(); let b = backend; lock.unlock()
        guard let b = b, vk.count == pkBytes[variant], sig.count == sigBytes[variant] else { return false }
        return (try? b(variant, vk, msg, sig)) == true
    }
}

/// FN-DSA key material for the agent-side signer: the verifying key, the secret key and an optional 32-byte sign seed (nil: 32 fresh CSPRNG bytes per
/// signature, which is what real signing does; a fixed seed makes signatures reproducible for conformance replays).
public struct PCAFnDsaKey {
    public let variant: String
    public let vk: [UInt8]
    public let sk: [UInt8]
    public let signSeed: [UInt8]?
    public init(variant: String, vk: [UInt8], sk: [UInt8], signSeed: [UInt8]? = nil) {
        self.variant = variant; self.vk = vk; self.sk = sk; self.signSeed = signSeed
    }

    /// Key pair from a 32-byte keygen seed through the registered signer. Without one: the typed `unsupported_suite` refusal.
    public static func fromSeed(_ variant: String, seed: [UInt8], signSeed: [UInt8]? = nil) throws -> PCAFnDsaKey {
        guard PCAFnDsaHook.pkBytes[variant] != nil, let s = PCAFnDsaHook.currentSigner else { throw PCAProducerError(PQ.refusal(variant)) }
        guard seed.count == 32, signSeed == nil || signSeed!.count == 32 else { throw PCAProducerError("an FN-DSA seed is 32 bytes") }
        let kp = try s.keygen(variant, seed)
        return PCAFnDsaKey(variant: variant, vk: kp.vk, sk: kp.sk, signSeed: signSeed)
    }
    public var pkB64u: String { Base64URLStrict.encode(vk) }
}
