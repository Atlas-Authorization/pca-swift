import AtlasPCAVerify
import Foundation

/// An FN-DSA refusal or a missing backend. Nothing is returned on a refusal.
public enum FnDsaError: Error, Equatable {
    /// No backend is installed (the default), or the library behind it is absent.
    case backendMissing(String)
    /// A malformed input or a backend that misbehaved.
    case invalid(String)
}

/// One FN-DSA signature suite: how many bytes each half of the wire framing carries.
public struct FnDsaSuite: Equatable {
    public let alg: String, variant: String
    public let hasEd25519: Bool
    public let sigBytes: Int
    public let needsPqPk: Bool
    public let pqPkBytes: Int
    public let needsPqSig: Bool
    public let pqSigBytes: Int
    public let fnSigBytes: Int
}

/// The pluggable primitive. `verify` is required; `sign` is nil for a verify-only backend. A backend that throws propagates.
public struct FalconBackend {
    public var verify: (_ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool
    public var sign: ((_ sk: [UInt8], _ msg: [UInt8]) throws -> [UInt8])?
    public init(verify: @escaping (_ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool,
                sign: ((_ sk: [UInt8], _ msg: [UInt8]) throws -> [UInt8])? = nil) {
        self.verify = verify
        self.sign = sign
    }
}

/// FN-DSA (Falcon) suite registry, wire framing and the Ed25519 + FN-DSA hybrid leaf composition (the reference is @atlasauth/pca-fndsa).
///
/// This file carries no Falcon arithmetic: the primitive is a backend (`setBackend`), so the framing, lengths and hybrid fail-closed rules are
/// testable without one and verification refuses until one is installed. The real primitive is `FnDsaNative.backend()` (Pornin's fn-dsa 0.4.0
/// behind libfndsa). FIPS 206 is not final, so that is a draft best guess pinned in lockstep with the TypeScript reference, and it interoperates
/// with it byte for byte. A round-3 Falcon (liboqs, BouncyCastle, circl) is a different scheme with the same signature lengths and is NOT interoperable.
public enum FnDsa {
    public static let pk512 = 897, sig512 = 666, pk1024 = 1793, sig1024 = 1280
    static let pkBytes = ["fn-dsa-512": pk512, "fn-dsa-1024": pk1024]
    static let sigBytes = ["fn-dsa-512": sig512, "fn-dsa-1024": sig1024]

    private static func suite(_ alg: String, _ variant: String, _ hybrid: Bool) -> FnDsaSuite {
        let pk = pkBytes[variant]!, sig = sigBytes[variant]!
        return FnDsaSuite(alg: alg, variant: variant, hasEd25519: hybrid, sigBytes: hybrid ? 64 : sig, needsPqPk: true, pqPkBytes: pk,
                          needsPqSig: hybrid, pqSigBytes: hybrid ? sig : 0, fnSigBytes: sig)
    }

    public static let suites: [String: FnDsaSuite] = [
        "fn-dsa-512": suite("fn-dsa-512", "fn-dsa-512", false),
        "fn-dsa-1024": suite("fn-dsa-1024", "fn-dsa-1024", false),
        "hybrid-ed25519-fn-dsa-512": suite("hybrid-ed25519-fn-dsa-512", "fn-dsa-512", true),
        "hybrid-ed25519-fn-dsa-1024": suite("hybrid-ed25519-fn-dsa-1024", "fn-dsa-1024", true),
    ]

    public static func resolveAlg(_ alg: String?) -> FnDsaSuite? { alg.flatMap { suites[$0] } }
    public static func isKnownAlg(_ alg: String?) -> Bool { resolveAlg(alg) != nil }
    public static func isVariant(_ v: String?) -> Bool { v.map { pkBytes[$0] != nil } ?? false }

    // ---- backend seam

    private static let lock = NSLock()
    private static var current: FalconBackend = defaultBackend
    static let noBackendMessage = "no FN-DSA backend registered: supply one via FnDsa.setBackend() (for example FnDsaNative.backend())"
    private static var defaultBackend: FalconBackend {
        FalconBackend(verify: { _, _, _ in throw FnDsaError.backendMissing(noBackendMessage) },
                      sign: { _, _ in throw FnDsaError.backendMissing(noBackendMessage) })
    }

    public static func setBackend(_ b: FalconBackend) { lock.lock(); current = b; lock.unlock() }
    public static func resetBackend() { setBackend(defaultBackend) }
    public static var backend: FalconBackend { lock.lock(); defer { lock.unlock() }; return current }

    /// Signs `msg` with the installed backend; the signature must be the variant's padded length.
    public static func sign(_ variant: String, sk: [UInt8], msg: [UInt8]) throws -> [UInt8] {
        guard let want = sigBytes[variant] else { throw FnDsaError.invalid("fndsaSign: unknown FN-DSA variant \(variant)") }
        guard !sk.isEmpty else { throw FnDsaError.invalid("fndsaSign: secret key must be a non-empty byte string") }
        guard let signer = backend.sign else { throw FnDsaError.invalid("fndsaSign: FN-DSA backend is verify-only (no sign())") }
        let sig = try signer(sk, msg)
        guard sig.count == want else { throw FnDsaError.invalid("fndsaSign: FN-DSA backend returned a bad signature; expected padded \(want) bytes for '\(variant)'") }
        return sig
    }

    /// False for any length violation (before the backend is consulted); a backend that throws propagates.
    public static func verify(_ variant: String, pk: [UInt8], msg: [UInt8], sig: [UInt8]) throws -> Bool {
        guard let wantPk = pkBytes[variant], pk.count == wantPk, sig.count == sigBytes[variant]! else { return false }
        return try backend.verify(pk, msg, sig)
    }

    // ---- hybrid leaf composition

    static let leafDomain = Array("atlas-pca/fn-dsa/leaf/v1".utf8) + [0]

    /// leafMessage(leaf) || domain || alg || 0x00 || the base64url FN-DSA public key text (alg and key are bound).
    public static func leafMessage(_ leaf: JSONValue, alg: String, pqPkB64u: String) throws -> [UInt8] {
        var m = try PCAWire.leafMessage(leaf)
        m += leafDomain
        m += Array(alg.utf8)
        m.append(0)
        m += Array(pqPkB64u.utf8)
        return m
    }

    public struct Signed: Equatable {
        public let sig: String, alg: String, pqPk: String
        public let pqSig: String?
    }

    /// Test seam: builds the Ed25519 key of a hybrid suite (the byte-for-byte replay injects RFC 8032 deterministic signing where the platform hedges).
    static var edKeyFactory: ([UInt8]) throws -> PCAEdKey = { try PCAEdKey(seed: $0) }

    /// Hybrid suites also need the 32-byte Ed25519 leaf-holder seed.
    public static func signPca(alg: String, leaf: JSONValue, pk: [UInt8], sk: [UInt8], edSecret: [UInt8]? = nil) throws -> Signed {
        guard let s = resolveAlg(alg) else { throw FnDsaError.invalid("signPcaWithFndsa: unknown FN-DSA alg \(alg)") }
        guard pk.count == s.pqPkBytes else { throw FnDsaError.invalid("signPcaWithFndsa: '\(s.alg)' requires a \(s.pqPkBytes)-byte FN-DSA public key") }
        guard !sk.isEmpty else { throw FnDsaError.invalid("signPcaWithFndsa: '\(s.alg)' requires FN-DSA secret-key material") }
        let pqPk = PCAWire.b64uEncode(pk)
        let msg = try leafMessage(leaf, alg: s.alg, pqPkB64u: pqPk)
        let fnSig = try sign(s.variant, sk: sk, msg: msg)
        if !s.hasEd25519 { return Signed(sig: PCAWire.b64uEncode(fnSig), alg: s.alg, pqPk: pqPk, pqSig: nil) }
        guard let ed = edSecret else { throw FnDsaError.invalid("signPcaWithFndsa: '\(s.alg)' requires edSecret (Ed25519 leaf-holder secret key)") }
        return Signed(sig: PCAWire.b64uEncode(try edKeyFactory(ed).sign(msg)), alg: s.alg, pqPk: pqPk, pqSig: PCAWire.b64uEncode(fnSig))
    }

    private static func strict(_ s: String?, _ n: Int) -> [UInt8]? { s.flatMap { PCAWire.b64uDecode($0) }.flatMap { $0.count == n ? $0 : nil } }

    /// Fails closed. A hybrid needs BOTH the Ed25519 half and the FN-DSA half; every length and encoding check runs before the backend.
    public static func verifyPca(alg: String?, leaf: JSONValue, holder: String? = nil, pqPk: String? = nil, sig: String? = nil, pqSig: String? = nil) throws -> Bool {
        guard let s = resolveAlg(alg), let pqPk = pqPk, let pk = strict(pqPk, s.pqPkBytes) else { return false }
        let msg = try leafMessage(leaf, alg: s.alg, pqPkB64u: pqPk)
        if !s.hasEd25519 {
            guard let fnSig = strict(sig, s.sigBytes) else { return false }
            return try verify(s.variant, pk: pk, msg: msg, sig: fnSig)
        }
        guard let holder = holder, let sig = sig, strict(sig, s.sigBytes) != nil else { return false }
        let edOk = PCAWire.ed25519Verify(publicKeyB64u: holder, message: msg, signatureB64u: sig)
        guard let fnSig = strict(pqSig, s.pqSigBytes) else { return false }
        let pqOk = try verify(s.variant, pk: pk, msg: msg, sig: fnSig)
        return edOk && pqOk
    }

    // ---- deterministic mock backend: TEST ONLY (anyone can forge its signatures; never register it in production)

    static let mockSkTag = Array("atlas-pca/fn-dsa/mock-sk/v1".utf8) + [0]

    public static func hashKat(_ seed: [UInt8], _ outLen: Int) throws -> [UInt8] {
        guard outLen >= 0 else { throw FnDsaError.invalid("Invalid typed array length: \(outLen)") }
        var out: [UInt8] = []
        var counter: UInt32 = 0
        while out.count < outLen {
            out += PCAWire.sha256(seed + [UInt8(counter >> 24), UInt8((counter >> 16) & 255), UInt8((counter >> 8) & 255), UInt8(counter & 255)])
            counter += 1
        }
        return Array(out.prefix(outLen))
    }

    private static func mockSig(_ pk: [UInt8], _ msg: [UInt8]) -> [UInt8]? {
        guard let n = pk.count == pk512 ? sig512 : pk.count == pk1024 ? sig1024 : nil else { return nil }
        return try? hashKat(Array("fn-dsa/mock-sig/v1".utf8) + [0] + pk + msg, n)
    }

    /// The mock key pair of a variant; the seed is text (`variant/seed`) or raw bytes (`variant/` then the bytes).
    public static func mockKeypair(_ variant: String, seed: String = "default") throws -> (pk: [UInt8], sk: [UInt8]) {
        try mockKeypair(variant, seedBytes: Array("\(variant)/\(seed)".utf8))
    }

    public static func mockKeypair(_ variant: String, seed: [UInt8]) throws -> (pk: [UInt8], sk: [UInt8]) {
        try mockKeypair(variant, seedBytes: Array((variant + "/").utf8) + seed)
    }

    private static func mockKeypair(_ variant: String, seedBytes: [UInt8]) throws -> (pk: [UInt8], sk: [UInt8]) {
        guard let n = pkBytes[variant] else { throw FnDsaError.invalid("mockKeypair: unknown FN-DSA variant \(variant)") }
        let pk = try hashKat(seedBytes, n)
        return (pk, mockSkTag + pk)
    }

    /// TEST ONLY: installs a hash-derived backend (explicit known-answer vectors, keyed by public key and message, take precedence).
    @discardableResult
    public static func registerTestBackend(vectors: [(pk: [UInt8], msg: [UInt8], sig: [UInt8])] = []) -> FalconBackend {
        var table: [String: [UInt8]] = [:]
        for v in vectors { table[PCAWire.b64uEncode(v.pk) + "|" + PCAWire.b64uEncode(v.msg)] = v.sig }
        let b = FalconBackend(
            verify: { pk, msg, sig in
                guard let expected = table[PCAWire.b64uEncode(pk) + "|" + PCAWire.b64uEncode(msg)] ?? mockSig(pk, msg) else { return false }
                return sig == expected
            },
            sign: { sk, msg in
                guard sk.count > mockSkTag.count, Array(sk.prefix(mockSkTag.count)) == mockSkTag else {
                    throw FnDsaError.invalid("mock FN-DSA backend: secret key was not minted by mockKeypair()")
                }
                let pk = Array(sk.dropFirst(mockSkTag.count))
                if let known = table[PCAWire.b64uEncode(pk) + "|" + PCAWire.b64uEncode(msg)] { return known }
                guard let d = mockSig(pk, msg) else { throw FnDsaError.invalid("mock FN-DSA backend: public key length matches no FN-DSA variant") }
                return d
            })
        setBackend(b)
        return b
    }
}
