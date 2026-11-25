import Foundation
import CryptoKit
import Clibsodium
import CMLDSA // the vendored ML-DSA code signs where CryptoKit has no ML-DSA

/// A failure of the producer side (a signer never emits a weaker or inconsistent artifact: it throws instead).
public struct PCAProducerError: Error, CustomStringConvertible {
    public let message: String
    public var description: String { message }
    init(_ m: String) { message = m }
}

/// RFC 8032 deterministic Ed25519 signing on every platform. Apple's CryptoKit hedges Ed25519 (a fresh random nonce mixed into every
/// signature), so there the signature comes from libsodium (constant time, deterministic); Swift Crypto on Linux already signs deterministically.
enum PCAEd25519 {
    static func sign(seed: [UInt8], _ message: [UInt8]) throws -> [UInt8] {
        #if os(Linux)
        return Array(try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed)).signature(for: Data(message)))
        #else
        guard seed.count == 32, sodium_init() >= 0 else { throw PCAProducerError("an Ed25519 seed is 32 bytes") }
        var pk = [UInt8](repeating: 0, count: 32), sk = [UInt8](repeating: 0, count: 64)
        guard crypto_sign_seed_keypair(&pk, &sk, seed) == 0 else { throw PCAProducerError("an Ed25519 seed is 32 bytes") }
        var sig = [UInt8](repeating: 0, count: 64)
        guard crypto_sign_detached(&sig, nil, message, UInt64(message.count), sk) == 0 else { throw PCAProducerError("Ed25519 signing failed") }
        return sig
        #endif
    }
}

/// An Ed25519 key: the 32-byte seed (RFC 8032 private key) and public key. Signatures are RFC 8032 deterministic on every platform.
public struct PCAEdKey {
    public let seed: [UInt8]
    public let pub: [UInt8]
    private let signFn: ([UInt8]) throws -> [UInt8]

    public init(seed: [UInt8]) throws {
        guard seed.count == 32, let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed)) else { throw PCAProducerError("an Ed25519 seed is 32 bytes") }
        self.seed = seed
        self.pub = Array(k.publicKey.rawRepresentation)
        self.signFn = { try PCAEd25519.sign(seed: seed, $0) }
    }

    /// Test seam: the platform key with its signatures taken from `signer` (the byte-for-byte vector replay injects RFC 8032
    /// deterministic signing where the platform hedges). The public key is still the platform's.
    init(seed: [UInt8], signer: @escaping ([UInt8]) throws -> [UInt8]) throws {
        let k = try PCAEdKey(seed: seed)
        self.seed = k.seed
        self.pub = k.pub
        self.signFn = signer
    }

    public static func generate() throws -> PCAEdKey {
        var s = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { s[i] = UInt8.random(in: 0...255) }
        return try PCAEdKey(seed: s)
    }

    /// The b64u public key: the key id used as `issuer` / `holder` on the wire.
    public var id: String { Base64URLStrict.encode(pub) }

    public func sign(_ msg: [UInt8]) throws -> [UInt8] { try signFn(msg) }
}

/// The ML-DSA levels (FIPS 204) this SDK can sign with.
public enum PCAMLDSALevel { case mlDsa65, mlDsa87 }

/// A post-quantum key pair. ML-DSA signs through CryptoKit's `MLDSA65` / `MLDSA87`, which exist only on macOS / iOS / tvOS / watchOS /
/// visionOS 26 and later: on an older system `generate` / `fromSeed` throw `unsupported_suite` (the same refusal the verifier gives),
/// and nothing else is affected. SLH-DSA signs through the opt-in AtlasPCAOpenSSL backend (`PCASlhDsaKey`); without one it is refused as `unsupported_suite`.
public struct PCAPQKey {
    public let level: PCAMLDSALevel
    public let pk: [UInt8]
    let signFn: ([UInt8]) throws -> [UInt8]
    public var pkB64u: String { Base64URLStrict.encode(pk) }

    static func unsupported(_ what: String) -> PCAProducerError { PCAProducerError("\(PCASuites.unsupportedSuiteReason): \(what)") }

    /// True iff this platform can SIGN ML-DSA: always (CryptoKit on the 26.0 systems, the vendored CMLDSA target elsewhere), unless the test seam is on.
    /// Producers check this, never `MLDSA.available`.
    public static var signingAvailable: Bool { !signingDisabledForTests }

    /// Test seam: makes this platform report no ML-DSA signing, so the refusal paths run on a platform that can sign.
    static var signingDisabledForTests = false

    /// A new random key.
    public static func generate(_ level: PCAMLDSALevel) throws -> PCAPQKey { try make(level, seed: nil) }

    /// A reproducible key from the 32-byte FIPS 204 seed (xi): the same seed always gives the same key pair.
    public static func fromSeed(_ level: PCAMLDSALevel, seed: [UInt8]) throws -> PCAPQKey {
        guard seed.count == 32 else { throw PCAProducerError("an ML-DSA seed is 32 bytes") }
        return try make(level, seed: seed)
    }

    private static func make(_ level: PCAMLDSALevel, seed: [UInt8]?) throws -> PCAPQKey {
        guard signingAvailable else { throw unsupported(level == .mlDsa65 ? "ml-dsa-65" : "ml-dsa-87") }
        #if canImport(CryptoKit)
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            switch level {
            case .mlDsa65:
                let k = try seed.map { try MLDSA65.PrivateKey(seedRepresentation: Data($0), publicKey: nil) } ?? MLDSA65.PrivateKey()
                return PCAPQKey(level: level, pk: Array(k.publicKey.rawRepresentation), signFn: { Array(try k.signature(for: Data($0))) })
            case .mlDsa87:
                let k = try seed.map { try MLDSA87.PrivateKey(seedRepresentation: Data($0), publicKey: nil) } ?? MLDSA87.PrivateKey()
                return PCAPQKey(level: level, pk: Array(k.publicKey.rawRepresentation), signFn: { Array(try k.signature(for: Data($0))) })
            }
        }
        #endif
        // CryptoKit has no ML-DSA on this OS (or this is Linux): the vendored CMLDSA target keys and signs
        let lvl: MLDSA.Level = level == .mlDsa65 ? .mlDsa65 : .mlDsa87
        guard let (pk, secret) = MLDSA.vendoredKeyPair(lvl, seed: seed) else { throw unsupported("ml-dsa") }
        return PCAPQKey(level: level, pk: pk, signFn: { msg in
            guard let sig = MLDSA.vendoredSign(lvl, secretKey: secret, message: msg) else { throw PCAPQKey.unsupported("ml-dsa") }
            return sig
        })
    }
}

/// The key material one signature suite needs. `ed25519` needs the Ed25519 key; a hybrid both; a pure ML-DSA suite the PQ key.
/// Fails closed on a missing or mismatched key and on a suite this SDK cannot sign.
public struct PCASuiteKey {
    public let alg: String
    public let ed: PCAEdKey?
    public let pq: PCAPQKey?
    let suite: PQ.Suite
    /// The FN-DSA key of a pure FN-DSA suite (nil otherwise).
    let fn: PCAFnDsaKey?
    /// The LESS key of a LESS suite (nil otherwise).
    let less: PCALessKey?
    /// The SLH-DSA key of an SLH-DSA suite (nil otherwise).
    let slh: PCASlhDsaKey?

    /// A LESS suite (`less-cat1`, or `hybrid-ed25519-less-cat1` with an Ed25519 key). Refused as `unsupported_suite` unless a LESS backend that can
    /// SIGN is registered (`AtlasPCALess`), and when the key does not match the suite's sizes. LESS is a NIST additional-signature round-2 candidate.
    public init(alg: String, ed: PCAEdKey?, less key: PCALessKey) throws {
        guard let s = PQ.suites[alg], s.lessCat1, PCALessHook.isRegistered, PCALessHook.isSignerRegistered else { throw PCAProducerError(PQ.refusal(alg)) }
        guard key.vk.count == s.pqPkBytes, !key.sk.isEmpty, key.signSeed == nil || key.signSeed!.count >= 32 else {
            throw PCAProducerError("'\(alg)' needs a matching LESS key")
        }
        if s.needsPqSig && ed == nil { throw PCAProducerError("'\(alg)' requires an Ed25519 key") }
        self.alg = alg; self.ed = s.needsPqSig ? ed : nil; self.pq = nil; self.suite = s; self.fn = nil; self.less = key; self.slh = nil
    }

    /// An SLH-DSA suite (`slh-dsa-sha2-128f` / `-256s`, or `hybrid-ed25519-` + either with an Ed25519 key). Refused as `unsupported_suite` unless an SLH-DSA
    /// backend that can SIGN is registered (`PCAOpenSSL.registerSlhDsa()`), and when the key does not match the suite's parameter set and sizes.
    public init(alg: String, ed: PCAEdKey?, slhDsa key: PCASlhDsaKey) throws {
        guard let s = PQ.suites[alg], let fam = s.slh, PCASlhDsaHook.isRegistered, PCASlhDsaHook.isSignerRegistered else { throw PCAProducerError(PQ.refusal(alg)) }
        guard key.family == fam, key.vk.count == s.pqPkBytes, key.sk.count == PCASlhDsaHook.skBytes[fam] else { throw PCAProducerError("'\(alg)' needs a matching SLH-DSA key") }
        if s.needsPqSig && ed == nil { throw PCAProducerError("'\(alg)' requires an Ed25519 key") }
        self.alg = alg; self.ed = s.needsPqSig ? ed : nil; self.pq = nil; self.suite = s; self.fn = nil; self.less = nil; self.slh = key
    }

    /// A pure FN-DSA suite (`fn-dsa-512` / `fn-dsa-1024`). Refused as `unsupported_suite` unless an FN-DSA backend that can SIGN is registered
    /// (`AtlasPCAFnDsa`), and when the key does not match the suite's variant and sizes.
    public init(alg: String, fnDsa key: PCAFnDsaKey) throws {
        guard let s = PQ.suites[alg], s.fnDsa == alg, PCAFnDsaHook.isRegistered, PCAFnDsaHook.isSignerRegistered else { throw PCAProducerError(PQ.refusal(alg)) }
        guard key.variant == alg, key.vk.count == s.pqPkBytes, !key.sk.isEmpty, key.signSeed == nil || key.signSeed!.count == 32 else {
            throw PCAProducerError("'\(alg)' needs a matching FN-DSA key")
        }
        self.alg = alg; self.ed = nil; self.pq = nil; self.suite = s; self.fn = key; self.less = nil; self.slh = nil
    }

    public init(alg: String, ed: PCAEdKey?, pq: PCAPQKey? = nil) throws {
        guard let s = PQ.suites[alg] else { throw PCAProducerError(PQ.refusal(alg)) }
        if s.fnDsa != nil { throw PCAProducerError(PQ.refusal(alg)) } // an FN-DSA suite needs `init(alg:fnDsa:)` (key bundle + registered signer)
        if s.lessCat1 { throw PCAProducerError(PQ.refusal(alg)) } // a LESS suite needs `init(alg:ed:less:)` (key bundle + registered signer)
        if s.slh != nil { throw PCAProducerError(PQ.refusal(alg)) } // an SLH-DSA suite needs `init(alg:ed:slhDsa:)` (key bundle + registered signer)
        if s.pq != nil && !PCAPQKey.signingAvailable { throw PCAProducerError(PQ.refusal(alg)) }
        if (s.pq == nil || s.needsPqSig) && ed == nil { throw PCAProducerError("'\(alg)' requires an Ed25519 key") }
        if let lv = s.pq {
            guard let pq = pq else { throw PCAProducerError("'\(alg)' requires an ML-DSA key") }
            if (lv == .mlDsa65) != (pq.level == .mlDsa65) { throw PCAProducerError("'\(alg)' needs a different ML-DSA level") }
        }
        self.alg = alg; self.ed = ed; self.pq = pq; self.suite = s; self.fn = nil; self.less = nil; self.slh = nil
    }

    public static func ed25519(_ ed: PCAEdKey) -> PCASuiteKey { try! PCASuiteKey(alg: "ed25519", ed: ed) }

    /// The PQ public key bound into the signed body (`pq_pk`); nil for ed25519.
    public var pqPk: String? { suite.needsPqPk ? (fn?.pkB64u ?? less?.pkB64u ?? slh?.pkB64u ?? pq?.pkB64u) : nil }
    /// The Ed25519 identity (key id); nil for a pure PQ suite.
    public var id: String? { ed?.id }

    /// The suite signature of `msg` (the reference's `signWithSuite`): `sig` is the primary signature (Ed25519, or the PQ one in a pure PQ
    /// suite), `pqSig` the PQ half of a hybrid (over `msg`, or `msg || sig` in the nested hybrid). Both base64url.
    public func sign(_ msg: [UInt8]) throws -> (sig: String, pqSig: String?) {
        if let k = fn { // pure PQ: `sig` is the FN-DSA signature; the signer is re-checked at sign time and the length must be exact (fail closed)
            guard let s = PCAFnDsaHook.currentSigner, PCAFnDsaHook.isRegistered else { throw PCAProducerError(PQ.refusal(alg)) }
            let sig = try s.sign(k.variant, k.sk, msg, k.signSeed)
            guard sig.count == suite.sigBytes else { throw PCAProducerError("'\(alg)' signer returned a signature of the wrong length") }
            return (Base64URLStrict.encode(sig), nil)
        }
        if let k = slh { // SLH-DSA: the signer is re-checked at sign time, the length must be exact, and the signature must verify (fail closed)
            guard let s = PCASlhDsaHook.currentSigner, PCASlhDsaHook.isRegistered else { throw PCAProducerError(PQ.refusal(alg)) }
            let sig = try s.sign(k.family, k.sk, msg)
            guard sig.count == PCASlhDsaHook.sigBytes[k.family], PCASlhDsaHook.verify(k.family, vk: k.vk, msg: msg, sig: sig) else {
                throw PCAProducerError("'\(alg)' signer returned a signature that does not verify")
            }
            if !suite.needsPqSig { return (Base64URLStrict.encode(sig), nil) }
            return (Base64URLStrict.encode(try ed!.sign(msg)), Base64URLStrict.encode(sig))
        }
        if let k = less { // LESS: the signer is re-checked at sign time, the length must be one the parameter set produces, and the signature must verify (fail closed)
            guard let s = PCALessHook.currentSigner, PCALessHook.isRegistered else { throw PCAProducerError(PQ.refusal(alg)) }
            let sig = try s.sign(k.sk, msg, k.signSeed)
            guard PCALessHook.sigLenOK(sig.count), PCALessHook.verify(vk: k.vk, msg: msg, sig: sig) else {
                throw PCAProducerError("'\(alg)' signer returned a signature that does not verify")
            }
            if !suite.needsPqSig { return (Base64URLStrict.encode(sig), nil) }
            return (Base64URLStrict.encode(try ed!.sign(msg)), Base64URLStrict.encode(sig))
        }
        if suite.pq == nil { return (Base64URLStrict.encode(try ed!.sign(msg)), nil) }
        if !suite.needsPqSig { return (Base64URLStrict.encode(try pq!.signFn(msg)), nil) }
        let edSig = try ed!.sign(msg)
        let pqSig = try pq!.signFn(suite.nested ? msg + edSig : msg)
        return (Base64URLStrict.encode(edSig), Base64URLStrict.encode(pqSig))
    }
}
