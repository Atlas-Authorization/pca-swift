import Foundation
import CryptoKit

/// The public post-quantum surface of `pq.ts`: size constants, deterministic key generation, raw and base64url verification, public-key encoders, the
/// well-formed-key guard and the LAMPS composite (ML-DSA-65 + Ed25519) signature. ML-DSA signs through CryptoKit (macOS / iOS 26), SLH-DSA / FN-DSA / LESS
/// through their registered backends (`PCASlhDsaHook`, `PCAFnDsaHook`, `PCALessHook`); without one the operation is the typed `unsupported_suite` refusal
/// (signing) or false (verifying), never an acceptance.
public enum PCAPq {
    public static let ED25519_SIGNATURE_BYTES = 64
    public static let ML_DSA_65_PUBLIC_KEY_BYTES = 1952, ML_DSA_65_SIGNATURE_BYTES = 3309, ML_DSA_65_SEED_BYTES = 32
    public static let ML_DSA_87_PUBLIC_KEY_BYTES = 2592, ML_DSA_87_SIGNATURE_BYTES = 4627, ML_DSA_87_SEED_BYTES = 32
    public static let SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES = 32, SLH_DSA_SHA2_128F_SECRET_KEY_BYTES = 64
    public static let SLH_DSA_SHA2_128F_SIGNATURE_BYTES = 17088, SLH_DSA_SHA2_128F_SEED_BYTES = 48
    public static let SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES = 64, SLH_DSA_SHA2_256S_SECRET_KEY_BYTES = 128
    public static let SLH_DSA_SHA2_256S_SIGNATURE_BYTES = 29792, SLH_DSA_SHA2_256S_SEED_BYTES = 96
    public static let FN_DSA_512_PUBLIC_KEY_BYTES = 897, FN_DSA_512_SECRET_KEY_BYTES = 1345, FN_DSA_512_SIGNATURE_BYTES = 666
    public static let FN_DSA_1024_PUBLIC_KEY_BYTES = 1793, FN_DSA_1024_SECRET_KEY_BYTES = 2369, FN_DSA_1024_SIGNATURE_BYTES = 1280
    public static let FN_DSA_SEED_BYTES = 32
    public static let LESS_CAT1_PUBLIC_KEY_BYTES = 97484, LESS_CAT1_SECRET_KEY_BYTES = 32
    public static let LESS_CAT1_SIGNATURE_MAX_BYTES = 1329, LESS_CAT1_SIGNATURE_MIN_BYTES = 1153, LESS_CAT1_SIGNATURE_STEP_BYTES = 16
    public static let LESS_SEED_BYTES = 32
    public static let DEFAULT_SIG_ALG = "ed25519"

    /// True when `x` is one of the registered signature suite names (a closed registry; a lookalike is not one).
    public static func isKnownSigAlg(_ x: JSONValue?) -> Bool {
        guard let s = x?.asString else { return false }
        return PCASuites.registered.contains(where: { IV.same($0, s) })
    }

    /// The suite a signature `alg` selects (absent: ed25519), or nil for a name this verifier does not run (fail closed).
    public static func resolveSigAlg(_ alg: String?) -> String? {
        guard let a = alg else { return DEFAULT_SIG_ALG }
        return PQ.resolve(a) != nil ? a : nil
    }

    // ---- ML-DSA ----

    public static func mlDsa65Keygen(_ seed: [UInt8]) throws -> PCAPQKey { try PCAPQKey.fromSeed(.mlDsa65, seed: seed) }
    public static func mlDsa87Keygen(_ seed: [UInt8]) throws -> PCAPQKey { try PCAPQKey.fromSeed(.mlDsa87, seed: seed) }
    public static func mlDsa65Sign(_ key: PCAPQKey, _ msg: [UInt8]) throws -> [UInt8] { try key.signFn(msg) }
    public static func mlDsa87Sign(_ key: PCAPQKey, _ msg: [UInt8]) throws -> [UInt8] { try key.signFn(msg) }
    public static func mlDsa65Verify(_ publicKey: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        publicKey.count == ML_DSA_65_PUBLIC_KEY_BYTES && sig.count == ML_DSA_65_SIGNATURE_BYTES && MLDSA.verify(.mlDsa65, publicKey: publicKey, message: msg, signature: sig)
    }
    public static func mlDsa87Verify(_ publicKey: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        publicKey.count == ML_DSA_87_PUBLIC_KEY_BYTES && sig.count == ML_DSA_87_SIGNATURE_BYTES && MLDSA.verify(.mlDsa87, publicKey: publicKey, message: msg, signature: sig)
    }
    public static func mlDsa65VerifyB64u(_ publicKey: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        guard let p = publicKey?.asString, let s = sig?.asString else { return false }
        return MLDSA.verifyB64u(.mlDsa65, p, msg, s)
    }
    public static func mlDsa87VerifyB64u(_ publicKey: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        guard let p = publicKey?.asString, let s = sig?.asString else { return false }
        return MLDSA.verifyB64u(.mlDsa87, p, msg, s)
    }

    // ---- SLH-DSA (backend through PCASlhDsaHook) ----

    public static func slhDsa128fKeygen(_ seed: [UInt8]) throws -> PCASlhDsaKey { try PCASlhDsaKey.fromSeed("SLH-DSA-SHA2-128f", seed: seed) }
    public static func slhDsa256sKeygen(_ seed: [UInt8]) throws -> PCASlhDsaKey { try PCASlhDsaKey.fromSeed("SLH-DSA-SHA2-256s", seed: seed) }

    private static func slhSign(_ key: PCASlhDsaKey, _ msg: [UInt8]) throws -> [UInt8] {
        guard let s = PCASlhDsaHook.currentSigner, PCASlhDsaHook.isRegistered else { throw PCAProducerError(PQ.refusal(PCASlhDsaHook.suiteName(key.family) ?? key.family)) }
        return try s.sign(key.family, key.sk, msg)
    }
    public static func slhDsa128fSign(_ key: PCASlhDsaKey, _ msg: [UInt8]) throws -> [UInt8] { try slhSign(key, msg) }
    public static func slhDsa256sSign(_ key: PCASlhDsaKey, _ msg: [UInt8]) throws -> [UInt8] { try slhSign(key, msg) }
    public static func slhDsa128fVerify(_ publicKey: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool { PCASlhDsaHook.verify("SLH-DSA-SHA2-128f", vk: publicKey, msg: msg, sig: sig) }
    public static func slhDsa256sVerify(_ publicKey: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool { PCASlhDsaHook.verify("SLH-DSA-SHA2-256s", vk: publicKey, msg: msg, sig: sig) }

    private static func b64uVerify(_ pk: JSONValue?, _ sig: JSONValue?, _ pkLen: Int, _ sigLen: Int, _ f: ([UInt8], [UInt8]) -> Bool) -> Bool {
        guard let p = pk?.asString, let s = sig?.asString, let pb = Base64URLStrict.decode(p, length: pkLen), let sb = Base64URLStrict.decode(s, length: sigLen) else { return false }
        return f(pb, sb)
    }
    public static func slhDsa128fVerifyB64u(_ publicKey: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        b64uVerify(publicKey, sig, SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_128F_SIGNATURE_BYTES) { slhDsa128fVerify($0, msg, $1) }
    }
    public static func slhDsa256sVerifyB64u(_ publicKey: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        b64uVerify(publicKey, sig, SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_256S_SIGNATURE_BYTES) { slhDsa256sVerify($0, msg, $1) }
    }

    // ---- FN-DSA (backend through PCAFnDsaHook) ----

    public static func fnDsa512Keygen(_ seed: [UInt8]) throws -> PCAFnDsaKey { try PCAFnDsaKey.fromSeed("fn-dsa-512", seed: seed) }
    public static func fnDsa1024Keygen(_ seed: [UInt8]) throws -> PCAFnDsaKey { try PCAFnDsaKey.fromSeed("fn-dsa-1024", seed: seed) }
    private static func fnSign(_ key: PCAFnDsaKey, _ msg: [UInt8]) throws -> [UInt8] {
        guard let s = PCAFnDsaHook.currentSigner, PCAFnDsaHook.isRegistered else { throw PCAProducerError(PQ.refusal(key.variant)) }
        return try s.sign(key.variant, key.sk, msg, key.signSeed)
    }
    public static func fnDsa512Sign(_ key: PCAFnDsaKey, _ msg: [UInt8]) throws -> [UInt8] { try fnSign(key, msg) }
    public static func fnDsa1024Sign(_ key: PCAFnDsaKey, _ msg: [UInt8]) throws -> [UInt8] { try fnSign(key, msg) }
    public static func fnDsa512Verify(_ publicKey: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool { PCAFnDsaHook.verify("fn-dsa-512", vk: publicKey, msg: msg, sig: sig) }
    public static func fnDsa1024Verify(_ publicKey: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool { PCAFnDsaHook.verify("fn-dsa-1024", vk: publicKey, msg: msg, sig: sig) }
    public static func fnDsa512VerifyB64u(_ publicKey: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        b64uVerify(publicKey, sig, FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_512_SIGNATURE_BYTES) { fnDsa512Verify($0, msg, $1) }
    }
    public static func fnDsa1024VerifyB64u(_ publicKey: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        b64uVerify(publicKey, sig, FN_DSA_1024_PUBLIC_KEY_BYTES, FN_DSA_1024_SIGNATURE_BYTES) { fnDsa1024Verify($0, msg, $1) }
    }

    // ---- LESS (backend through PCALessHook) ----

    public static func lessCat1VerifyB64u(_ publicKey: JSONValue?, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        guard let p = publicKey?.asString, let s = sig?.asString, let pb = Base64URLStrict.decode(p, length: LESS_CAT1_PUBLIC_KEY_BYTES),
              let sb = Base64URLStrict.decode(s), PCALessHook.sigLenOK(sb.count) else { return false }
        return PCALessHook.verify(vk: pb, msg: msg, sig: sb)
    }
    /// Whether a LESS verify backend is registered (else every LESS suite fails closed).
    public static func isLessBackendActive() -> Bool { PCALessHook.isRegistered }
    public static func lessBackendStatus() -> (available: Bool, reason: String?) {
        PCALessHook.isRegistered ? (true, nil) : (false, "no LESS backend registered (AtlasPCALess)")
    }

    // ---- public-key encoders and guards ----

    private static func encodeKey(_ pk: [UInt8], _ len: Int, _ what: String) throws -> String {
        guard pk.count == len else { throw PCAProducerError("\(what) public key must be \(len) bytes") }
        return Base64URLStrict.encode(pk)
    }
    public static func encodeMlDsaPublicKey(_ pk: [UInt8]) throws -> String { try encodeKey(pk, ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA-65") }
    public static func encodeMlDsa87PublicKey(_ pk: [UInt8]) throws -> String { try encodeKey(pk, ML_DSA_87_PUBLIC_KEY_BYTES, "ML-DSA-87") }
    public static func encodeSlhDsaPublicKey(_ pk: [UInt8]) throws -> String { try encodeKey(pk, SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, "SLH-DSA-SHA2-128f") }
    public static func encodeSlhDsa256sPublicKey(_ pk: [UInt8]) throws -> String { try encodeKey(pk, SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, "SLH-DSA-SHA2-256s") }
    public static func encodeLessPublicKey(_ pk: [UInt8]) throws -> String { try encodeKey(pk, LESS_CAT1_PUBLIC_KEY_BYTES, "LESS cat-1") }
    /// FN-DSA public key of either degree (897 or 1793 bytes).
    public static func encodeFnDsaPublicKey(_ pk: [UInt8]) throws -> String {
        guard pk.count == FN_DSA_512_PUBLIC_KEY_BYTES || pk.count == FN_DSA_1024_PUBLIC_KEY_BYTES else { throw PCAProducerError("FN-DSA public key must be 897 or 1793 bytes") }
        return Base64URLStrict.encode(pk)
    }

    static let publicKeyLengths: Set<Int> = [ML_DSA_65_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES,
                                             FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_1024_PUBLIC_KEY_BYTES, LESS_CAT1_PUBLIC_KEY_BYTES]

    /// True when `pq` is canonical base64url of a byte string with the public-key length of a registered PQ suite.
    public static func isWellFormedPqPublicKey(_ pq: JSONValue?) -> Bool {
        guard let s = pq?.asString, let b = Base64URLStrict.decode(s) else { return false }
        return publicKeyLengths.contains(b.count)
    }

    // ---- LAMPS composite: ML-DSA-65 + Ed25519 (draft-ietf-lamps-pq-composite-sigs) ----

    public static let COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025"
    public static let COMPOSITE_LABEL = "COMPSIG-MLDSA65-Ed25519-SHA512"
    public static let COMPOSITE_SIGNATURE_BYTES = ML_DSA_65_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES

    /// `M' = Prefix || Label || len(ctx) || ctx || SHA-512(message)`; throws when `ctx` exceeds 255 bytes.
    public static func compositeRepresentative(_ message: [UInt8], ctx: [UInt8] = []) throws -> [UInt8] {
        guard ctx.count <= 255 else { throw PCAProducerError("compositeRepresentative: ctx exceeds 255 bytes") }
        return Array(COMPOSITE_PREFIX.utf8) + Array(COMPOSITE_LABEL.utf8) + [UInt8(ctx.count)] + ctx + Array(SHA512.hash(data: Data(message)))
    }

    /// `mldsaSig || tradSig` over the composite representative; both halves sign the same `M'`.
    public static func compositeSign(ed25519: PCAEdKey, mlDsa: PCAPQKey, message: [UInt8], ctx: [UInt8] = []) throws -> [UInt8] {
        guard mlDsa.level == .mlDsa65 else { throw PCAProducerError("compositeSign: an ML-DSA-65 key is required") }
        let m = try compositeRepresentative(message, ctx: ctx)
        return try mlDsa.signFn(m) + ed25519.sign(m)
    }

    /// Fail closed: a wrong total length, an over-long `ctx`, or either half failing returns false. Never throws.
    public static func compositeVerify(ed25519Pub: [UInt8], mlDsaPub: [UInt8], message: [UInt8], signature: [UInt8], ctx: [UInt8] = []) -> Bool {
        guard signature.count == COMPOSITE_SIGNATURE_BYTES, let m = try? compositeRepresentative(message, ctx: ctx) else { return false }
        let mldsaSig = Array(signature[..<ML_DSA_65_SIGNATURE_BYTES]), tradSig = Array(signature[ML_DSA_65_SIGNATURE_BYTES...])
        let mlOk = mlDsa65Verify(mlDsaPub, m, mldsaSig)
        let edOk = Ed25519Strict.verify(publicKey: ed25519Pub, message: m, signature: tradSig)
        return mlOk && edOk
    }
}
