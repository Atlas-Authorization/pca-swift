import Foundation
import CryptoKit

/// RFC 8032 (section 5.1.6) deterministic Ed25519 signing over the verifier's own field and point arithmetic.
/// Apple's CryptoKit hedges Ed25519, so the byte-for-byte producer-vector replay (`PCAProducerVectors`, its tests and the conformance
/// driver) injects this signer on Apple platforms, for the vector files' fixed test seeds only;
/// everything else the producers emit (canonical JSON, digests, chains, plan roots, headers) is still the SDK's own code.
/// Variable time: never use it for a real key. Pinned by RFC 8032 test vector 1 and the `ed25519_sign` vectors.
enum Ed25519Deterministic {
    typealias T = Ed25519Torsion
    static let L = Ed25519Strict.L
    static let B: T.Pt = T.decode([0x58] + [UInt8](repeating: 0x66, count: 31))!

    static func mul(_ k: BigUInt, _ p: T.Pt) -> T.Pt {
        var r = T.identity
        var i = k.bitLength - 1
        while i >= 0 {
            r = T.add(r, r)
            if k.bit(i) == 1 { r = T.add(r, p) }
            i -= 1
        }
        return r
    }

    static func encode(_ p: T.Pt) -> [UInt8] {
        let zi = T.finv(p.z)
        let x = T.fmul(p.x, zi), y = T.fmul(p.y, zi)
        var out = (0..<32).map { i in UInt8(truncatingIfNeeded: y[i >> 3] >> UInt64((i & 7) * 8)) }
        out[31] |= UInt8(truncatingIfNeeded: x.a0 & 1) << 7
        return out
    }

    static func modL(_ x: BigUInt) -> BigUInt {
        var r = BigUInt(0)
        var i = x.bitLength - 1
        while i >= 0 {
            r = r << 1
            if x.bit(i) == 1 { r = r + BigUInt(1) }
            if !(r < L) { r = r - L }
            i -= 1
        }
        return r
    }

    static func bytes32(_ x: BigUInt) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0..<256 where x.bit(i) == 1 { out[i >> 3] |= UInt8(1) << UInt8(i & 7) }
        return out
    }

    static func sha512(_ b: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: Data(b))) }

    static func publicKey(seed: [UInt8]) -> [UInt8] { encode(mul(scalar(seed), B)) }

    static func scalar(_ seed: [UInt8]) -> BigUInt {
        var a = Array(sha512(seed)[0..<32])
        a[0] &= 248; a[31] &= 127; a[31] |= 64
        return BigUInt(bytesLE: a)
    }

    static func sign(seed: [UInt8], _ msg: [UInt8]) -> [UInt8] {
        let h = sha512(seed)
        let a = scalar(seed)
        let A = encode(mul(a, B))
        let r = modL(BigUInt(bytesLE: sha512(Array(h[32..<64]) + msg)))
        let R = encode(mul(r, B))
        let k = modL(BigUInt(bytesLE: sha512(R + A + msg)))
        return R + bytes32(modL(r + k * a))
    }

    /// A producer key whose signatures are deterministic: the platform key where it already is (Linux), else this signer.
    static func key(seed: [UInt8]) throws -> PCAEdKey {
        #if os(Linux)
        return try PCAEdKey(seed: seed)
        #else
        return try PCAEdKey(seed: seed, signer: { sign(seed: seed, $0) })
        #endif
    }
}
