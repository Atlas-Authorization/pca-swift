import Foundation
import CryptoKit

/// A failure of the producer side (a signer never emits a weaker or inconsistent artifact: it throws instead).
public struct PCAProducerError: Error, CustomStringConvertible {
    public let message: String
    public var description: String { message }
    init(_ m: String) { message = m }
}

/// An Ed25519 key: the 32-byte seed (RFC 8032 private key) and public key. Apple's CryptoKit hedges Ed25519 (a fresh random
/// nonce mixed into every signature), so on Apple platforms two signatures of the same message differ; both are valid RFC 8032
/// signatures and every verifier accepts them. Swift Crypto on Linux signs deterministically.
public struct PCAEdKey {
    public let seed: [UInt8]
    public let pub: [UInt8]
    private let signFn: ([UInt8]) throws -> [UInt8]

    public init(seed: [UInt8]) throws {
        guard seed.count == 32, let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed)) else { throw PCAProducerError("an Ed25519 seed is 32 bytes") }
        self.seed = seed
        self.pub = Array(k.publicKey.rawRepresentation)
        self.signFn = { Array(try k.signature(for: Data($0))) }
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
/// and nothing else is affected. SLH-DSA is not implemented by this SDK's verifier either, so it is refused as `unsupported_suite`.
public struct PCAPQKey {
    public let level: PCAMLDSALevel
    public let pk: [UInt8]
    let signFn: ([UInt8]) throws -> [UInt8]
    public var pkB64u: String { Base64URLStrict.encode(pk) }

    static func unsupported(_ what: String) -> PCAProducerError { PCAProducerError("\(PCASuites.unsupportedSuiteReason): \(what)") }

    /// True iff this platform can SIGN ML-DSA (CryptoKit on the 26.0 systems). Verification can be available where signing is not
    /// (a Linux build verifies through liboqs), so producers check this, never `MLDSA.available`.
    public static var signingAvailable: Bool {
        #if canImport(CryptoKit)
        return MLDSA.available
        #else
        return false
        #endif
    }

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
        throw unsupported("ml-dsa")
    }
}

/// The key material one signature suite needs. `ed25519` needs the Ed25519 key; a hybrid both; a pure ML-DSA suite the PQ key.
/// Fails closed on a missing or mismatched key and on a suite this SDK cannot sign.
public struct PCASuiteKey {
    public let alg: String
    public let ed: PCAEdKey?
    public let pq: PCAPQKey?
    let suite: PQ.Suite

    public init(alg: String, ed: PCAEdKey?, pq: PCAPQKey? = nil) throws {
        guard let s = PQ.suites[alg] else { throw PCAProducerError(PQ.refusal(alg)) }
        if s.pq != nil && !PCAPQKey.signingAvailable { throw PCAProducerError(PQ.refusal(alg)) }
        if (s.pq == nil || s.needsPqSig) && ed == nil { throw PCAProducerError("'\(alg)' requires an Ed25519 key") }
        if let lv = s.pq {
            guard let pq = pq else { throw PCAProducerError("'\(alg)' requires an ML-DSA key") }
            if (lv == .mlDsa65) != (pq.level == .mlDsa65) { throw PCAProducerError("'\(alg)' needs a different ML-DSA level") }
        }
        self.alg = alg; self.ed = ed; self.pq = pq; self.suite = s
    }

    public static func ed25519(_ ed: PCAEdKey) -> PCASuiteKey { try! PCASuiteKey(alg: "ed25519", ed: ed) }

    /// The PQ public key bound into the signed body (`pq_pk`); nil for ed25519.
    public var pqPk: String? { suite.needsPqPk ? pq?.pkB64u : nil }
    /// The Ed25519 identity (key id); nil for a pure PQ suite.
    public var id: String? { ed?.id }

    /// `sig` is the primary signature, `pqSig` the PQ half of a hybrid.
    func sign(_ msg: [UInt8]) throws -> (sig: String, pqSig: String?) {
        if suite.pq == nil { return (Base64URLStrict.encode(try ed!.sign(msg)), nil) }
        if !suite.needsPqSig { return (Base64URLStrict.encode(try pq!.signFn(msg)), nil) }
        let edSig = try ed!.sign(msg)
        let pqSig = try pq!.signFn(suite.nested ? msg + edSig : msg)
        return (Base64URLStrict.encode(edSig), Base64URLStrict.encode(pqSig))
    }
}
