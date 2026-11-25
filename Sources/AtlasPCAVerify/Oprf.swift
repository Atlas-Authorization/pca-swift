import Foundation
import CryptoKit
import Clibsodium

/// RFC 9497 Oblivious Pseudorandom Functions on the ristretto255-SHA512 ciphersuite (OPRF 0x00, VOPRF 0x01, POPRF 0x02) and the private
/// revocation / private rate-limit layer of the reference (@atlasauth/pca-oprf). The group arithmetic is libsodium's ristretto255 through
/// RatchetGroup (never re-derived here); only the RFC 9380 expand_message_xmd(SHA-512) expander and the protocol framing are written out.
/// The base OPRF / VOPRF entry points accept those two modes only (the reference silently takes the VOPRF path for any other mode string).
public enum PCAOprf {
    public static let elementBytes = 32
    public static let scalarBytes = 32
    public static let outputBytes = 64
    public static let suiteId = "ristretto255-SHA512"
    static let maxFramed = 0xffff

    public enum Mode: String {
        case oprf, voprf, poprf
        var byte: UInt8 { self == .oprf ? 0 : (self == .voprf ? 1 : 2) }
    }

    public struct KeyPair { public let secretKey: [UInt8]; public let publicKey: [UInt8] }
    public struct BlindResult { public let blind: [UInt8]; public let blindedElement: [UInt8] }
    public struct PoprfBlindResult { public let blind: [UInt8]; public let blindedElement: [UInt8]; public let tweakedKey: [UInt8] }
    public struct EvaluateResult {
        public let evaluatedElement: [UInt8]
        public let proof: [UInt8]?
        public init(evaluatedElement: [UInt8], proof: [UInt8]? = nil) { self.evaluatedElement = evaluatedElement; self.proof = proof }
    }

    typealias G = RatchetGroup
    private static let ready: Bool = sodium_init() >= 0

    // MARK: encodings

    static func i2osp(_ n: Int, _ len: Int) throws -> [UInt8] {
        guard n >= 0, len >= 1, len <= 8, n < (1 << (8 * len)) else { throw JSError("I2OSP: value does not fit in \(len) bytes") }
        return (0..<len).map { UInt8(truncatingIfNeeded: n >> (8 * (len - 1 - $0))) }
    }

    public static func contextString(_ mode: Mode) -> [UInt8] { Array("OPRFV1-".utf8) + [mode.byte] + Array(("-" + suiteId).utf8) }

    static func sha512(_ b: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: Data(b))) }

    /// expand_message_xmd(SHA-512) for a 64-byte output (one block), RFC 9380 section 5.3.1.
    static func expand64(_ msg: [UInt8], _ dst: [UInt8]) throws -> [UInt8] {
        guard dst.count <= 255 else { throw JSError("expand_message_xmd: DST too long") }
        let dstPrime = dst + [UInt8(dst.count)]
        let b0 = sha512([UInt8](repeating: 0, count: 128) + msg + [0, 64, 0] + dstPrime)
        return sha512(b0 + [1] + dstPrime)
    }

    public static func serializeScalar(_ s: PCABigInt) -> [UInt8] { G.scalar(s) }

    public static func deserializeScalar(_ b: [UInt8]) throws -> [UInt8] {
        guard b.count == scalarBytes else { throw JSError("DeserializeScalar: expected 32 bytes, got \(b.count)") }
        guard BigUInt(bytesLE: b) < Ed25519Strict.L else { throw JSError("DeserializeScalar: non-canonical scalar (value >= group order)") }
        return b
    }

    /// A canonical, non-identity ristretto255 element (the identity and every non-canonical encoding are refused).
    public static func deserializeElement(_ b: [UInt8]) throws -> [UInt8] {
        _ = ready
        guard b.count == elementBytes, b[31] & 0x80 == 0, b != G.zero, crypto_core_ristretto255_is_valid_point(b) == 1 else {  // RFC 9496: bit 255 clear
            throw JSError("DeserializeElement: not a valid ristretto255 element")
        }
        return b
    }

    // MARK: group helpers

    public static func hashToGroup(_ input: [UInt8], _ mode: Mode) throws -> [UInt8] {
        try G.hashToCurve(try expand64(input, Array("HashToGroup-".utf8) + contextString(mode)))
    }

    private static func hashToScalar(_ input: [UInt8], dst: [UInt8]) throws -> [UInt8] {
        _ = ready
        var r = G.zero
        crypto_core_ristretto255_scalar_reduce(&r, try expand64(input, dst))
        return r
    }

    private static func hashToScalar(_ input: [UInt8], _ mode: Mode) throws -> [UInt8] {
        try hashToScalar(input, dst: Array("HashToScalar-".utf8) + contextString(mode))
    }

    /// k * p for a scalar in [1, L): a zero scalar is refused like the reference's constant-time multiply.
    private static func smul(_ p: [UInt8], _ k: [UInt8]) throws -> [UInt8] {
        guard k != G.zero else { throw JSError("invalid scalar: expected 1 <= sc < curve.n") }
        return try G.mul(p, k)
    }

    private static func scalarBaseMult(_ k: [UInt8]) throws -> [UInt8] { try smul(G.G, k) }

    private static func invert(_ s: [UInt8]) throws -> [UInt8] {
        _ = ready
        var r = G.zero
        guard crypto_core_ristretto255_scalar_invert(&r, s) == 0 else { throw JSError("scalarInvert: inverse of zero") }
        return r
    }

    private static func framed(_ b: [UInt8]) throws -> [UInt8] {
        guard b.count <= maxFramed else { throw JSError("\(b.count) bytes exceeds the \(maxFramed)-byte limit") }
        return b
    }

    // MARK: keys

    public static func deriveKeyPair(seed: [UInt8], info: [UInt8], mode: Mode) throws -> KeyPair {
        guard seed.count == scalarBytes else { throw JSError("DeriveKeyPair: seed must be exactly 32 bytes") }
        let dst = Array("DeriveKeyPair".utf8) + contextString(mode)
        let input = seed + (try i2osp(info.count, 2)) + info
        for counter in 0...255 {
            let sk = try hashToScalar(input + [UInt8(counter)], dst: dst)
            if sk != G.zero { return KeyPair(secretKey: sk, publicKey: try scalarBaseMult(sk)) }
        }
        throw JSError("DeriveKeyPair: failed to derive a non-zero key after 256 attempts")
    }

    public static func randomKeyPair() throws -> KeyPair {
        let sk = G.randScalar()
        return KeyPair(secretKey: sk, publicKey: try scalarBaseMult(sk))
    }

    public static func publicKeyFor(_ secretKey: [UInt8]) throws -> [UInt8] { try scalarBaseMult(try deserializeScalar(secretKey)) }

    // MARK: DLEQ proof

    private static func compositesSeed(_ b: [UInt8], _ mode: Mode) throws -> [UInt8] {
        let seedDst = Array("Seed-".utf8) + contextString(mode)
        return sha512(try i2osp(b.count, 2) + b + (try i2osp(seedDst.count, 2)) + seedDst)
    }

    private static func coefficient(_ seed: [UInt8], _ index: Int, _ c: [UInt8], _ d: [UInt8], _ mode: Mode) throws -> [UInt8] {
        var t = try i2osp(seed.count, 2) + seed + (try i2osp(index, 2))
        t += try i2osp(c.count, 2) + c + (try i2osp(d.count, 2)) + d + Array("Composite".utf8)
        return try hashToScalar(t, mode)
    }

    /// (M, Z) of the verifier path (single pair).
    private static func composites(_ b: [UInt8], _ c: [UInt8], _ d: [UInt8], _ mode: Mode) throws -> (m: [UInt8], z: [UInt8]) {
        let di = try coefficient(try compositesSeed(b, mode), 0, c, d, mode)
        return (try G.mul(c, di), try G.mul(d, di))
    }

    private static func challenge(_ pts: [[UInt8]], _ mode: Mode) throws -> [UInt8] {
        var t: [UInt8] = []
        for p in pts { t += try i2osp(p.count, 2) + p }
        return try hashToScalar(t + Array("Challenge".utf8), mode)
    }

    private static func generateProof(k: [UInt8], a: [UInt8], b: [UInt8], c: [UInt8], d: [UInt8], mode: Mode, fixed: [UInt8]?) throws -> [UInt8] {
        let di = try coefficient(try compositesSeed(b, mode), 0, c, d, mode)
        let m = try G.mul(c, di)
        let z = try G.mul(m, k)
        let r = try fixed.map { try deserializeScalar($0) } ?? G.randScalar()
        let t2 = try smul(a, r), t3 = try smul(m, r)
        let cc = try challenge([b, m, z, t2, t3], mode)
        return cc + G.scalarSub(r, G.scalarMul(cc, k))
    }

    /// True iff the DLEQ relation holds; a non-canonical challenge / response scalar throws (like the reference).
    private static func verifyProof(a: [UInt8], b: [UInt8], c: [UInt8], d: [UInt8], proof: [UInt8], mode: Mode) throws -> Bool {
        guard proof.count == 2 * scalarBytes else { return false }
        let cc = try deserializeScalar(Array(proof[0..<32])), s = try deserializeScalar(Array(proof[32...]))
        let (m, z) = try composites(b, c, d, mode)
        let t2 = try G.add(try G.mul(a, s), try G.mul(b, cc))
        let t3 = try G.add(try G.mul(m, s), try G.mul(z, cc))
        return try challenge([b, m, z, t2, t3], mode) == cc
    }

    // MARK: finalize hashes

    private static func finalizeHash(_ input: [UInt8], _ issued: [UInt8]) throws -> [UInt8] {
        sha512(try i2osp(input.count, 2) + input + (try i2osp(issued.count, 2)) + issued + Array("Finalize".utf8))
    }

    private static func finalizeHashPoprf(_ input: [UInt8], _ info: [UInt8], _ issued: [UInt8]) throws -> [UInt8] {
        sha512(try i2osp(input.count, 2) + input + (try i2osp(info.count, 2)) + info + (try i2osp(issued.count, 2)) + issued + Array("Finalize".utf8))
    }

    // MARK: OPRF / VOPRF

    private static func baseMode(_ m: Mode) throws {
        guard m != .poprf else { throw JSError("this entry point takes oprf or voprf (use the Poprf functions for poprf)") }
    }

    /// `fixedBlind` pins the blind (vectors only).
    public static func blind(input: [UInt8], mode: Mode = .oprf, fixedBlind: [UInt8]? = nil) throws -> BlindResult {
        _ = try framed(input)
        let r = try fixedBlind.map { try deserializeScalar($0) } ?? G.randScalar()
        let e = try hashToGroup(input, mode)
        guard e != G.zero else { throw JSError("Blind: input maps to identity") }
        return BlindResult(blind: r, blindedElement: try smul(e, r))
    }

    public static func blindEvaluate(secretKey: [UInt8], blindedElement: [UInt8], mode: Mode = .oprf, publicKey: [UInt8]? = nil,
                                     fixedProofRandomness: [UInt8]? = nil) throws -> EvaluateResult {
        try baseMode(mode)
        let sk = try deserializeScalar(secretKey)
        let r = try deserializeElement(blindedElement)
        let evaluated = try smul(r, sk)
        if mode == .oprf { return EvaluateResult(evaluatedElement: evaluated) }
        let pk = try publicKey.map { try deserializeElement($0) } ?? scalarBaseMult(sk)
        let proof = try generateProof(k: sk, a: G.G, b: pk, c: r, d: evaluated, mode: .voprf, fixed: fixedProofRandomness)
        return EvaluateResult(evaluatedElement: evaluated, proof: proof)
    }

    public static func finalize(input: [UInt8], blind: [UInt8], evaluatedElement: [UInt8], mode: Mode = .oprf, proof: [UInt8]? = nil,
                                publicKey: [UInt8]? = nil, blindedElement: [UInt8]? = nil) throws -> [UInt8] {
        try baseMode(mode)
        _ = try framed(input)
        let r = try deserializeScalar(blind)
        let evaluated = try deserializeElement(evaluatedElement)
        if mode == .voprf {
            guard let proof = proof, let publicKey = publicKey, let blindedElement = blindedElement else {
                throw JSError("Finalize(voprf): proof, publicKey and blindedElement are required")
            }
            let pk = try deserializeElement(publicKey), blinded = try deserializeElement(blindedElement)
            guard try verifyProof(a: G.G, b: pk, c: blinded, d: evaluated, proof: proof, mode: .voprf) else {
                throw JSError("Finalize(voprf): DLEQ proof verification failed")
            }
        }
        return try finalizeHash(input, try smul(evaluated, try invert(r)))
    }

    public static func evaluate(secretKey: [UInt8], input: [UInt8], mode: Mode = .oprf) throws -> [UInt8] {
        try baseMode(mode)
        _ = try framed(input)
        let sk = try deserializeScalar(secretKey)
        let e = try hashToGroup(input, mode)
        guard e != G.zero else { throw JSError("Evaluate: input maps to identity") }
        return try finalizeHash(input, try smul(e, sk))
    }

    // MARK: POPRF

    private static func infoScalar(_ info: [UInt8]) throws -> [UInt8] {
        _ = try framed(info)
        return try hashToScalar(Array("Info".utf8) + (try i2osp(info.count, 2)) + info, .poprf)
    }

    public static func blindPoprf(input: [UInt8], info: [UInt8], publicKey: [UInt8], fixedBlind: [UInt8]? = nil) throws -> PoprfBlindResult {
        _ = try framed(input)
        let m = try infoScalar(info)
        let tweaked = try G.add(try scalarBaseMult(m), try deserializeElement(publicKey))
        guard tweaked != G.zero else { throw JSError("Blind(poprf): tweaked key is identity") }
        let b = try blind(input: input, mode: .poprf, fixedBlind: fixedBlind)
        return PoprfBlindResult(blind: b.blind, blindedElement: b.blindedElement, tweakedKey: tweaked)
    }

    public static func blindEvaluatePoprf(secretKey: [UInt8], blindedElement: [UInt8], info: [UInt8], fixedProofRandomness: [UInt8]? = nil) throws -> EvaluateResult {
        let sk = try deserializeScalar(secretKey)
        let t = G.scalarAdd(sk, try infoScalar(info))
        guard t != G.zero else { throw JSError("BlindEvaluate(poprf): inverse of zero (bad info/key)") }
        let blinded = try deserializeElement(blindedElement)
        let evaluated = try smul(blinded, try invert(t))
        let proof = try generateProof(k: t, a: G.G, b: try scalarBaseMult(t), c: evaluated, d: blinded, mode: .poprf, fixed: fixedProofRandomness)
        return EvaluateResult(evaluatedElement: evaluated, proof: proof)
    }

    public static func finalizePoprf(input: [UInt8], blind: [UInt8], evaluatedElement: [UInt8], info: [UInt8], proof: [UInt8],
                                     blindedElement: [UInt8], tweakedKey: [UInt8]) throws -> [UInt8] {
        _ = try framed(input); _ = try framed(info)
        let r = try deserializeScalar(blind)
        let evaluated = try deserializeElement(evaluatedElement)
        let blinded = try deserializeElement(blindedElement)
        let tweaked = try deserializeElement(tweakedKey)
        guard try verifyProof(a: G.G, b: tweaked, c: evaluated, d: blinded, proof: proof, mode: .poprf) else {
            throw JSError("Finalize(poprf): DLEQ proof verification failed")
        }
        return try finalizeHashPoprf(input, info, try smul(evaluated, try invert(r)))
    }

    public static func evaluatePoprf(secretKey: [UInt8], input: [UInt8], info: [UInt8]) throws -> [UInt8] {
        _ = try framed(input)
        let sk = try deserializeScalar(secretKey)
        let t = G.scalarAdd(sk, try infoScalar(info))
        guard t != G.zero else { throw JSError("Evaluate(poprf): inverse of zero (bad info/key)") }
        let e = try hashToGroup(input, .poprf)
        guard e != G.zero else { throw JSError("Evaluate(poprf): input maps to identity") }
        return try finalizeHashPoprf(input, info, try smul(e, try invert(t)))
    }

    // MARK: utilities

    public static func toHex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    public static func bytesEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in a.indices { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}
