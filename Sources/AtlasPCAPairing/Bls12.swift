import Foundation
import CBlst
import CryptoKit

/// BLS12-381 helpers over supranational blst (C), shared by the pairing packages: scalars mod r, G1 / G2 points with the
/// strict canonical decoders, hash-to-curve, and RFC 9380 expand_message_xmd. No field, curve or pairing arithmetic is
/// implemented here: every operation is a blst call.
public struct PairingError: Error, CustomStringConvertible {
    public let message: String
    public init(_ m: String) { message = m }
    public var description: String { message }
}

/// The prime order r of the BLS12-381 groups, big-endian.
public let blsOrderBE: [UInt8] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01]

/// Runs `f` on a stable pointer to `a` (a one-byte dummy for an empty array, so blst never receives NULL).
@inline(__always)
func withBytes<R>(_ a: [UInt8], _ f: (UnsafePointer<UInt8>) -> R) -> R {
    if a.isEmpty { var z: UInt8 = 0; return withUnsafePointer(to: &z) { f($0) } }
    return a.withUnsafeBufferPointer { f($0.baseAddress!) }
}

/// A scalar mod r (blst's Fr). Arithmetic is blst's; the byte form is 32 bytes big-endian.
public struct Fr {
    var v = blst_fr()

    public init() {}

    /// Any-length big-endian bytes reduced mod r.
    public init(reducing be: [UInt8]) {
        if be.isEmpty { return }
        var s = blst_scalar()
        withBytes(be) { _ = blst_scalar_from_be_bytes(&s, $0, be.count) }
        blst_fr_from_scalar(&v, &s)
    }

    /// Exactly 32 big-endian bytes encoding a value in [0, r); nil otherwise.
    public init?(canonical b: [UInt8]) {
        guard b.count == 32 else { return nil }
        var s = blst_scalar()
        withBytes(b) { blst_scalar_from_bendian(&s, $0) }
        guard blst_scalar_fr_check(&s) else { return nil }
        blst_fr_from_scalar(&v, &s)
    }

    public init(_ u: UInt64) {
        let limbs: [UInt64] = [u, 0, 0, 0]
        limbs.withUnsafeBufferPointer { blst_fr_from_uint64(&v, $0.baseAddress!) }
    }

    public var bytes: [UInt8] {
        var s = blst_scalar()
        var fr = v
        blst_scalar_from_fr(&s, &fr)
        var out = [UInt8](repeating: 0, count: 32)
        blst_bendian_from_scalar(&out, &s)
        return out
    }

    public var isZero: Bool { !bytes.contains(where: { $0 != 0 }) }

    var scalar: blst_scalar {
        var s = blst_scalar()
        var fr = v
        blst_scalar_from_fr(&s, &fr)
        return s
    }

    public static func + (a: Fr, b: Fr) -> Fr { var r = Fr(), x = a.v, y = b.v; blst_fr_add(&r.v, &x, &y); return r }
    public static func - (a: Fr, b: Fr) -> Fr { var r = Fr(), x = a.v, y = b.v; blst_fr_sub(&r.v, &x, &y); return r }
    public static func * (a: Fr, b: Fr) -> Fr { var r = Fr(), x = a.v, y = b.v; blst_fr_mul(&r.v, &x, &y); return r }
    public static prefix func - (a: Fr) -> Fr { var r = Fr(), x = a.v; blst_fr_cneg(&r.v, &x, true); return r }

    /// The multiplicative inverse; throws on zero.
    public func inverse() throws -> Fr {
        if isZero { throw PairingError("inverse of zero") }
        var r = Fr(), x = v
        blst_fr_inverse(&r.v, &x)
        return r
    }
}

extension Fr: Equatable {
    public static func == (a: Fr, b: Fr) -> Bool { a.bytes == b.bytes }
}

/// A point of G1 (48-byte compressed form).
public struct G1 {
    var p = blst_p1()
    public init() {}

    public static var generator: G1 { var g = G1(); g.p = blst_p1_generator().pointee; return g }

    /// Strict compressed decoding: 48 bytes, compression flag, canonical, on the curve, in the prime-order subgroup.
    /// The identity decodes (check `isIdentity` separately).
    public init?(compressed b: [UInt8]) {
        guard b.count == 48, b[0] & 0x80 != 0 else { return nil }
        var a = blst_p1_affine()
        guard withBytes(b, { blst_p1_uncompress(&a, $0) }) == BLST_SUCCESS else { return nil }
        guard blst_p1_affine_on_curve(&a), blst_p1_affine_in_g1(&a) else { return nil }
        var back = [UInt8](repeating: 0, count: 48)
        blst_p1_affine_compress(&back, &a)
        guard back == b else { return nil }
        blst_p1_from_affine(&p, &a)
    }

    public var isIdentity: Bool { var x = p; return blst_p1_is_inf(&x) }
    public var compressed: [UInt8] { var out = [UInt8](repeating: 0, count: 48), x = p; blst_p1_compress(&out, &x); return out }
    var affine: blst_p1_affine { var a = blst_p1_affine(), x = p; blst_p1_to_affine(&a, &x); return a }

    public static func + (a: G1, b: G1) -> G1 { var r = G1(), x = a.p, y = b.p; blst_p1_add_or_double(&r.p, &x, &y); return r }
    public static prefix func - (a: G1) -> G1 { var r = a; blst_p1_cneg(&r.p, true); return r }
    public static func - (a: G1, b: G1) -> G1 { a + (-b) }

    /// s * P; the identity when s is zero.
    public static func * (s: Fr, a: G1) -> G1 {
        if s.isZero { return G1() }
        var r = G1(), x = a.p, sc = s.scalar
        withUnsafeBytes(of: &sc) { blst_p1_mult(&r.p, &x, $0.bindMemory(to: UInt8.self).baseAddress!, 255) }
        return r
    }

    public static func == (a: G1, b: G1) -> Bool { var x = a.p, y = b.p; return blst_p1_is_equal(&x, &y) }

    /// RFC 9380 hash_to_curve (random-oracle, SSWU) into G1.
    public static func hash(_ msg: [UInt8], dst: [UInt8]) -> G1 {
        var r = G1()
        withBytes(msg) { m in withBytes(dst) { d in blst_hash_to_g1(&r.p, m, msg.count, d, dst.count, nil, 0) } }
        return r
    }
}

/// A point of G2 (96-byte compressed form).
public struct G2 {
    var p = blst_p2()
    public init() {}

    public static var generator: G2 { var g = G2(); g.p = blst_p2_generator().pointee; return g }

    public init?(compressed b: [UInt8]) {
        guard b.count == 96, b[0] & 0x80 != 0 else { return nil }
        var a = blst_p2_affine()
        guard withBytes(b, { blst_p2_uncompress(&a, $0) }) == BLST_SUCCESS else { return nil }
        guard blst_p2_affine_on_curve(&a), blst_p2_affine_in_g2(&a) else { return nil }
        var back = [UInt8](repeating: 0, count: 96)
        blst_p2_affine_compress(&back, &a)
        guard back == b else { return nil }
        blst_p2_from_affine(&p, &a)
    }

    public var isIdentity: Bool { var x = p; return blst_p2_is_inf(&x) }
    public var compressed: [UInt8] { var out = [UInt8](repeating: 0, count: 96), x = p; blst_p2_compress(&out, &x); return out }
    var affine: blst_p2_affine { var a = blst_p2_affine(), x = p; blst_p2_to_affine(&a, &x); return a }

    public static func + (a: G2, b: G2) -> G2 { var r = G2(), x = a.p, y = b.p; blst_p2_add_or_double(&r.p, &x, &y); return r }
    public static prefix func - (a: G2) -> G2 { var r = a; blst_p2_cneg(&r.p, true); return r }
    public static func - (a: G2, b: G2) -> G2 { a + (-b) }

    public static func * (s: Fr, a: G2) -> G2 {
        if s.isZero { return G2() }
        var r = G2(), x = a.p, sc = s.scalar
        withUnsafeBytes(of: &sc) { blst_p2_mult(&r.p, &x, $0.bindMemory(to: UInt8.self).baseAddress!, 255) }
        return r
    }

    public static func == (a: G2, b: G2) -> Bool { var x = a.p, y = b.p; return blst_p2_is_equal(&x, &y) }

    public static func hash(_ msg: [UInt8], dst: [UInt8]) -> G2 {
        var r = G2()
        withBytes(msg) { m in withBytes(dst) { d in blst_hash_to_g2(&r.p, m, msg.count, d, dst.count, nil, 0) } }
        return r
    }
}

public enum Bls12 {
    /// prod_i e(P_i, Q_i) == 1, with one final exponentiation. A pair containing the identity is refused (false).
    public static func pairingProductIsOne(_ pairs: [(G1, G2)]) -> Bool {
        if pairs.isEmpty { return false }
        var acc = blst_fp12_one().pointee
        for (p, q) in pairs {
            if p.isIdentity || q.isIdentity { return false }
            var pa = p.affine, qa = q.affine, ml = blst_fp12(), t = blst_fp12()
            blst_miller_loop(&ml, &qa, &pa)
            blst_fp12_mul(&t, &acc, &ml)
            acc = t
        }
        var fe = blst_fp12()
        blst_final_exp(&fe, &acc)
        return blst_fp12_is_one(&fe)
    }

    /// e(a, x) == e(b, y).
    public static func pairingEq(_ a: G1, _ x: G2, _ b: G1, _ y: G2) -> Bool { pairingProductIsOne([(a, x), (-b, y)]) }

    /// expand_message_xmd with SHA-256 (RFC 9380 5.3.1); the DST must be at most 255 octets.
    public static func expandMessageXmd(_ msg: [UInt8], _ dst: [UInt8], _ len: Int) throws -> [UInt8] {
        let ell = (len + 31) / 32
        if len < 0 || ell > 255 || len > 65535 || dst.count > 255 { throw PairingError("expand_message_xmd: invalid length or DST") }
        let dstPrime = dst + [UInt8(dst.count)]
        var h = SHA256()
        h.update(data: Data(count: 64)); h.update(data: Data(msg))
        h.update(data: Data([UInt8(len >> 8), UInt8(len & 0xff), 0])); h.update(data: Data(dstPrime))
        let b0 = Array(h.finalize())
        var h1 = SHA256()
        h1.update(data: Data(b0)); h1.update(data: Data([1])); h1.update(data: Data(dstPrime))
        var bi = Array(h1.finalize())
        var out = Array(bi.prefix(min(32, len)))
        if ell >= 2 {
            for i in 2...ell {
                var hi = SHA256()
                hi.update(data: Data((0..<32).map { b0[$0] ^ bi[$0] })); hi.update(data: Data([UInt8(i)])); hi.update(data: Data(dstPrime))
                bi = Array(hi.finalize())
                out += bi.prefix(min(32, len - (i - 1) * 32))
            }
        }
        return out
    }
}
