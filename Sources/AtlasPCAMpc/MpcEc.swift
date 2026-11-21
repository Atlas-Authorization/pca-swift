import Foundation
import CryptoKit
import Clibsodium
import enum AtlasPCAVerify.PCAFrost

/// The Ed25519 group of the base oblivious transfer (twisted Edwards, q = 2^255 - 19), used in its prime-order subgroup (order L). The group law (add,
/// subtract, scalar multiplication, subgroup test) and every scalar operation are libsodium's constant-time Ed25519 core, called on the compressed
/// encoding; nothing of it is written out here. What remains is the PUBLIC coordinate codec (affine normalisation, RFC 8032 x-recovery) and the on-curve
/// predicate in a small fixed-width field type, which touch no secret. Every point received across the OT trust boundary is validated (on curve,
/// non-identity, [L]P = O).
extension PCAMpc {
    /// A point failed on-curve / subgroup / identity validation (or the group law refused it).
    public struct PointValidationError: Error, CustomStringConvertible {
        public let description: String
        init(_ m: String) { description = m }
    }

    /// Decimal integers of any width on little-endian 64-bit limbs.
    enum Dec {
        /// (negative, magnitude limbs) of a decimal integer; nil when `s` is not one or does not fit `maxLimbs` limbs.
        static func parse(_ s: String, maxLimbs: Int) -> (neg: Bool, mag: [UInt64])? {
            var u = Array(s.utf8)
            var neg = false
            if let f = u.first, f == UInt8(ascii: "-") || f == UInt8(ascii: "+") { neg = f == UInt8(ascii: "-"); u.removeFirst() }
            guard !u.isEmpty else { return nil }
            var mag = [UInt64](repeating: 0, count: maxLimbs)
            for c in u {
                guard c >= 48 && c <= 57 else { return nil }
                var carry = UInt64(c - 48)
                for i in 0..<maxLimbs {
                    let p = mag[i].multipliedFullWidth(by: 10)
                    let (lo, o) = p.low.addingReportingOverflow(carry)
                    mag[i] = lo
                    carry = p.high &+ (o ? 1 : 0)
                }
                if carry != 0 { return nil }
            }
            return (neg, mag)
        }

        static func string(_ mag: [UInt64]) -> String {
            var m = mag
            while let l = m.last, l == 0 { m.removeLast() }
            if m.isEmpty { return "0" }
            let base: UInt64 = 10_000_000_000_000_000_000
            var chunks: [UInt64] = []
            while !m.isEmpty {
                var rem: UInt64 = 0
                for i in stride(from: m.count - 1, through: 0, by: -1) {
                    let (q, r) = base.dividingFullWidth((rem, m[i]))
                    m[i] = q
                    rem = r
                }
                chunks.append(rem)
                while let l = m.last, l == 0 { m.removeLast() }
            }
            var s = String(chunks[chunks.count - 1])
            for c in chunks.dropLast().reversed() { let t = String(c); s += String(repeating: "0", count: 19 - t.count) + t }
            return s
        }

        static func bytesLE(_ mag: [UInt64], _ len: Int) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: len)
            for i in 0..<len { let li = i / 8; if li < mag.count { out[i] = UInt8((mag[li] >> UInt64(8 * (i % 8))) & 0xff) } }
            return out
        }

        static func limbs(_ b: [UInt8]) -> [UInt64] {
            var out = [UInt64](repeating: 0, count: (b.count + 7) / 8)
            for (i, x) in b.enumerated() { out[i / 8] |= UInt64(x) << UInt64(8 * (i % 8)) }
            return out
        }
    }

    // MARK: libsodium scalars (32-byte little endian, canonical mod L)

    typealias Scalar = [UInt8]

    enum Sodium {
        private static let ready: Bool = sodium_init() >= 0
        static func ensure() { precondition(ready, "libsodium failed to initialise") }

        static let L: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]
        static let zero = [UInt8](repeating: 0, count: 32)
        static let one: Scalar = [1] + [UInt8](repeating: 0, count: 31)

        static func isZero(_ s: [UInt8]) -> Bool { s.allSatisfy { $0 == 0 } }
        /// s >= L (both 32-byte little endian).
        static func geL(_ s: [UInt8]) -> Bool {
            for i in stride(from: 31, through: 0, by: -1) where s[i] != L[i] { return s[i] > L[i] }
            return true
        }
        static func reduce(_ wide: [UInt8]) -> Scalar {
            ensure()
            var w = wide + [UInt8](repeating: 0, count: max(0, 64 - wide.count))
            var out = [UInt8](repeating: 0, count: 32)
            crypto_core_ed25519_scalar_reduce(&out, &w)
            return out
        }
        static func add(_ a: Scalar, _ b: Scalar) -> Scalar { ensure(); var z = [UInt8](repeating: 0, count: 32); crypto_core_ed25519_scalar_add(&z, a, b); return z }
        static func mul(_ a: Scalar, _ b: Scalar) -> Scalar { ensure(); var z = [UInt8](repeating: 0, count: 32); crypto_core_ed25519_scalar_mul(&z, a, b); return z }
        static func neg(_ a: Scalar) -> Scalar { ensure(); var z = [UInt8](repeating: 0, count: 32); crypto_core_ed25519_scalar_negate(&z, a); return z }

        /// A decimal integer (any sign, up to 512 bits) reduced mod L; nil when it is not one.
        static func scalar(decimal s: String) -> Scalar? {
            guard let p = Dec.parse(s, maxLimbs: 8) else { return nil }
            let r = reduce(Dec.bytesLE(p.mag, 64))
            return p.neg ? neg(r) : r
        }
        static func decimal(_ s: Scalar) -> String { Dec.string(Dec.limbs(s)) }
    }

    // MARK: F_q, q = 2^255 - 19 (public coordinates only)

    struct Fe: Equatable {
        var w: [UInt64]
        static let q: [UInt64] = [0xFFFF_FFFF_FFFF_FFED, ~0, ~0, 0x7FFF_FFFF_FFFF_FFFF]
        static let zero = Fe(w: [0, 0, 0, 0])
        static let one = Fe(w: [1, 0, 0, 0])

        init(w: [UInt64]) { self.w = w }
        init(_ v: UInt64) { w = [v, 0, 0, 0] }

        private static func geq(_ a: [UInt64], _ b: [UInt64]) -> Bool {
            for i in stride(from: 3, through: 0, by: -1) where a[i] != b[i] { return a[i] > b[i] }
            return true
        }
        private static func subRaw(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
            var out = [UInt64](repeating: 0, count: 4)
            var borrow: UInt64 = 0
            for i in 0..<4 {
                let (d1, o1) = a[i].subtractingReportingOverflow(b[i])
                let (d2, o2) = d1.subtractingReportingOverflow(borrow)
                out[i] = d2
                borrow = (o1 ? 1 : 0) + (o2 ? 1 : 0)
            }
            return out
        }
        private static func reduceFinal(_ x: [UInt64]) -> Fe {
            var r = x
            while geq(r, q) { r = subRaw(r, q) }
            return Fe(w: r)
        }

        /// 8 limbs (a value below 2^512) folded into the field: 2^256 = 38.
        static func fold(_ t: [UInt64]) -> Fe {
            var r = [UInt64](repeating: 0, count: 5)
            var carry: UInt64 = 0
            for i in 0..<4 {
                let p = t[4 + i].multipliedFullWidth(by: 38)
                let (s1, c1) = t[i].addingReportingOverflow(p.low)
                let (s2, c2) = s1.addingReportingOverflow(carry)
                r[i] = s2
                carry = p.high &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            r[4] = carry
            var out = [r[0], r[1], r[2], r[3]]
            var c = r[4] &* 38
            for i in 0..<4 {
                let (s, o) = out[i].addingReportingOverflow(c)
                out[i] = s
                c = o ? 1 : 0
                if c == 0 { break }
            }
            if c != 0 { // wrapped past 2^256: the low limbs are tiny now, adding 38 cannot carry again
                c = 38
                for i in 0..<4 {
                    let (s, o) = out[i].addingReportingOverflow(c)
                    out[i] = s
                    c = o ? 1 : 0
                    if c == 0 { break }
                }
            }
            return reduceFinal(out)
        }

        static func + (a: Fe, b: Fe) -> Fe {
            var out = [UInt64](repeating: 0, count: 4)
            var carry: UInt64 = 0
            for i in 0..<4 {
                let (s1, o1) = a.w[i].addingReportingOverflow(b.w[i])
                let (s2, o2) = s1.addingReportingOverflow(carry)
                out[i] = s2
                carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
            }
            return reduceFinal(out)
        }
        static func - (a: Fe, b: Fe) -> Fe {
            if geq(a.w, b.w) { return Fe(w: subRaw(a.w, b.w)) }
            return Fe(w: subRaw(q, subRaw(b.w, a.w)))
        }
        var negated: Fe { isZero ? self : Fe(w: Fe.subRaw(Fe.q, w)) }
        var isZero: Bool { w.allSatisfy { $0 == 0 } }
        var isOdd: Bool { w[0] & 1 == 1 }

        static func * (a: Fe, b: Fe) -> Fe {
            var t = [UInt64](repeating: 0, count: 8)
            for i in 0..<4 {
                var carry: UInt64 = 0
                for j in 0..<4 {
                    let p = a.w[i].multipliedFullWidth(by: b.w[j])
                    let (s1, c1) = p.low.addingReportingOverflow(t[i + j])
                    let (s2, c2) = s1.addingReportingOverflow(carry)
                    t[i + j] = s2
                    carry = p.high &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
                }
                t[i + 4] = carry
            }
            return fold(t)
        }

        func pow(_ e: [UInt64]) -> Fe {
            var r = Fe.one
            for i in stride(from: 255, through: 0, by: -1) {
                r = r * r
                if (e[i / 64] >> UInt64(i % 64)) & 1 == 1 { r = r * self }
            }
            return r
        }
        /// a^(q-2); the inverse of 0 is 0.
        var inverse: Fe { pow([0xFFFF_FFFF_FFFF_FFEB, ~0, ~0, 0x7FFF_FFFF_FFFF_FFFF]) }

        init(bytes32 b: [UInt8]) { w = Dec.limbs(b) }
        var bytes32: [UInt8] { Dec.bytesLE(w, 32) }

        /// A decimal integer (any sign) reduced into the field; nil when it is not one or exceeds 512 bits.
        init?(decimal s: String) {
            guard let p = Dec.parse(s, maxLimbs: 8) else { return nil }
            let f = Fe.fold(p.mag)
            self = p.neg ? f.negated : f
        }
        var decimal: String { Dec.string(w) }
    }

    // MARK: Ed25519

    enum Ec {
        static let Lbytes = Sodium.L

        /// A curve point in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, T = XY/Z.
        struct Point {
            var X: Fe, Y: Fe, Z: Fe, T: Fe
            init(_ X: Fe, _ Y: Fe, _ Z: Fe, _ T: Fe) { self.X = X; self.Y = Y; self.Z = Z; self.T = T }
        }

        static let identity = Point(.zero, .one, .one, .zero)
        static let D: Fe = Fe(121665).negated * Fe(121666).inverse
        static let SQRT_M1: Fe = Fe(2).pow([0xFFFF_FFFF_FFFF_FFFB, ~0, ~0, 0x1FFF_FFFF_FFFF_FFFF])
        static let base: Point = fromAffine(Fe(decimal: "15112221349535400772501151409588531511454012693041857206046113283949847762202")!,
                                            Fe(decimal: "46316835694926478169428394003475163141307993866256225615783033603165251855960")!)

        static func fromAffine(_ x: Fe, _ y: Fe) -> Point { Point(x, y, .one, x * y) }

        static func toAffine(_ p: Point) -> (x: Fe, y: Fe) {
            let zi = p.Z.inverse
            return (p.X * zi, p.Y * zi)
        }

        static func equal(_ a: Point, _ b: Point) -> Bool { a.X * b.Z == b.X * a.Z && a.Y * b.Z == b.Y * a.Z }
        static func isIdentity(_ p: Point) -> Bool { equal(p, identity) }

        /// Canonical 64-byte affine encoding x || y (little-endian field elements), the OT key-derivation input.
        static func encodePoint(_ p: Point) -> [UInt8] { let a = toAffine(p); return a.x.bytes32 + a.y.bytes32 }

        /// Canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255).
        static func compressPoint(_ p: Point) -> [UInt8] {
            let a = toAffine(p)
            var out = a.y.bytes32
            out[31] = out[31] | (a.x.isOdd ? 0x80 : 0)
            return out
        }

        /// RFC 8032 5.1.3 x-recovery of a canonical compressed encoding.
        static func decompressPoint(_ bytes: [UInt8]) throws -> Point {
            guard bytes.count == 32 else { throw PointValidationError("decompressPoint: expected 32 bytes") }
            let sign = (bytes[31] >> 7) & 1
            var yb = bytes
            yb[31] &= 0x7f
            let y = Fe(bytes32: yb)
            guard !Fe.geqQ(y) else { throw PointValidationError("decompressPoint: non-canonical y (>= q)") }
            let y2 = y * y
            let u = y2 - .one
            let v = D * y2 + .one
            let v3 = v * v * v
            let v7 = v3 * v3 * v
            var x = u * v3 * (u * v7).pow([0xFFFF_FFFF_FFFF_FFFD, ~0, ~0, 0x0FFF_FFFF_FFFF_FFFF])
            let vx2 = v * (x * x)
            if vx2 == u {
                // x is correct as-is
            } else if vx2 == u.negated {
                x = x * SQRT_M1
            } else {
                throw PointValidationError("decompressPoint: not on curve")
            }
            if x.isZero && sign == 1 { throw PointValidationError("decompressPoint: non-canonical sign") }
            if (x.isOdd ? 1 : 0) != Int(sign) { x = x.negated }
            return fromAffine(x, y)
        }

        /// Whether the extended coordinates lie on the curve (projectively, no inversion).
        static func isOnCurve(_ p: Point) -> Bool {
            if p.Z.isZero { return false }
            if p.T * p.Z != p.X * p.Y { return false }
            let X2 = p.X * p.X, Y2 = p.Y * p.Y, Z2 = p.Z * p.Z
            return (Y2 - X2) * Z2 == Z2 * Z2 + D * X2 * Y2
        }

        /// The cofactor check [L]P = O (true for the identity too).
        static func hasPrimeOrder(_ p: Point) -> Bool {
            if !isOnCurve(p) { return false }
            if isIdentity(p) { return true }
            Sodium.ensure()
            // the group law decides (canonical, small order, L*P = identity): libsodium 1.0.20 and older accept a mixed-order point through is_valid_point
            let b = compressPoint(p)
            return (try? PCAFrost.decodeSafePoint(b)) != nil && crypto_core_ed25519_is_valid_point(b) == 1
        }
        static func isInSubgroup(_ p: Point) -> Bool { isOnCurve(p) && !isIdentity(p) && hasPrimeOrder(p) }

        static func assertInSubgroup(_ p: Point, _ label: String = "point") throws {
            if !isOnCurve(p) { throw PointValidationError("\(label): not on curve") }
            if isIdentity(p) { throw PointValidationError("\(label): identity element (forbidden here)") }
            if !hasPrimeOrder(p) { throw PointValidationError("\(label): not in the prime-order subgroup (small-order/cofactor)") }
        }

        private static func binary(_ sub: Bool, _ a: Point, _ b: Point) throws -> Point {
            Sodium.ensure()
            var r = [UInt8](repeating: 0, count: 32)
            let ca = compressPoint(a), cb = compressPoint(b)
            let rc = sub ? crypto_core_ed25519_sub(&r, ca, cb) : crypto_core_ed25519_add(&r, ca, cb)
            guard rc == 0 else { throw PointValidationError("point is not on the curve") }
            return try decompressPoint(r)
        }
        static func add(_ a: Point, _ b: Point) throws -> Point { try binary(false, a, b) }
        static func sub(_ a: Point, _ b: Point) throws -> Point { try binary(true, a, b) }
        static func neg(_ p: Point) throws -> Point { try sub(identity, p) }
        static func dbl(_ p: Point) throws -> Point { try add(p, p) }

        /// [k]P, k canonical mod L (k = 0 or P = identity is the identity). P must lie in the prime-order subgroup (libsodium refuses torsion).
        static func mul(_ k: Scalar, _ p: Point) throws -> Point {
            if Sodium.isZero(k) || isIdentity(p) { return identity }
            Sodium.ensure()
            var r = [UInt8](repeating: 0, count: 32)
            guard crypto_scalarmult_ed25519_noclamp(&r, k, compressPoint(p)) == 0 else {
                throw PointValidationError("scalar multiplication refused: point not in the prime-order subgroup")
            }
            return try decompressPoint(r)
        }

        static func mulBase(_ k: Scalar) throws -> Point {
            if Sodium.isZero(k) { return identity }
            Sodium.ensure()
            var r = [UInt8](repeating: 0, count: 32)
            guard crypto_scalarmult_ed25519_base_noclamp(&r, k) == 0 else { throw MpcError("ed25519 base multiplication failed") }
            return try decompressPoint(r)
        }

        // MARK: Schnorr proof of knowledge

        /// Fiat-Shamir Schnorr proof of knowledge of y with S = y*B: commitment U = r*B and z = r + e*y.
        struct SchnorrProof { var U: Point; var z: Scalar }

        static let TAG_SCHNORR = Array("atlas-pca-mpc/schnorr-dlog".utf8)

        private static func schnorrChallenge(_ S: Point, _ U: Point, _ ctx: [UInt8]) -> Scalar {
            let d = MpcHash.sha512([TAG_SCHNORR, MpcHash.u32(Int64(ctx.count)), ctx, encodePoint(base), encodePoint(S), encodePoint(U)])
            return Sodium.reduce(Array(d.reversed())) // the digest is read as a big-endian integer
        }

        static func schnorrProve(_ y: Scalar, _ S: Point, _ rnd: () throws -> Scalar, _ ctx: [UInt8]) throws -> SchnorrProof {
            guard !ctx.isEmpty else { throw MpcError("schnorrProve: a non-empty session binding is required") }
            let r = try rnd()
            guard !Sodium.isZero(r) else { throw MpcError("schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof") }
            let U = try mulBase(r)
            let e = schnorrChallenge(S, U, ctx)
            return SchnorrProof(U: U, z: Sodium.add(r, Sodium.mul(e, y)))
        }

        static func schnorrVerify(_ S: Point, _ proof: SchnorrProof, _ ctx: [UInt8]) -> Bool {
            if ctx.isEmpty { return false }
            if proof.z.count != 32 || Sodium.geL(proof.z) { return false }
            if !isInSubgroup(proof.U) { return false }
            let e = schnorrChallenge(S, proof.U, ctx)
            do {
                return equal(try mulBase(proof.z), try add(proof.U, try mul(e, S)))
            } catch { return false }
        }
    }

    // MARK: hashing and the OT randomness source

    enum MpcHash {
        static func sha256(_ parts: [[UInt8]]) -> [UInt8] { var h = SHA256(); for p in parts { h.update(data: p) }; return Array(h.finalize()) }
        static func sha512(_ parts: [[UInt8]]) -> [UInt8] { var h = SHA512(); for p in parts { h.update(data: p) }; return Array(h.finalize()) }
        static func u32(_ x: Int64) -> [UInt8] { [UInt8((x >> 24) & 0xff), UInt8((x >> 16) & 0xff), UInt8((x >> 8) & 0xff), UInt8(x & 0xff)] }
        static func xor(_ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
            guard a.count == b.count else { throw MpcError("XOR length mismatch") }
            return zip(a, b).map { $0 ^ $1 }
        }
        static func ctEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
            guard a.count == b.count else { return false }
            var d: UInt8 = 0
            for i in a.indices { d |= a[i] ^ b[i] }
            return d == 0
        }
    }

    /// A source of scalars and seeds for OT needs: the CSPRNG (default) or a seeded SplitMix64 stream (reproducible tests only).
    public final class OtRandom {
        private let next64: () -> UInt64
        init(next64: @escaping () -> UInt64) { self.next64 = next64 }

        public static func secure() -> OtRandom { OtRandom(next64: { UInt64.random(in: 0...UInt64.max) }) }
        public static func splitMix(seed: UInt64) -> OtRandom {
            var g = Field.Rng(seed: seed)
            return OtRandom(next64: { g.nextU64() })
        }

        /// A scalar in [1, L): four 64-bit draws read big-endian, reduced mod L, retried on zero.
        func scalar() throws -> Scalar {
            for _ in 0..<8 {
                let u0 = next64(), u1 = next64(), u2 = next64(), u3 = next64()
                let s = Sodium.reduce(Dec.bytesLE([u3, u2, u1, u0], 64))
                if !Sodium.isZero(s) { return s }
            }
            throw MpcError("otRandom: entropy stream returned zero scalars repeatedly (RNG failure)")
        }

        public func bytes(_ n: Int) -> [UInt8] {
            var out: [UInt8] = []
            out.reserveCapacity(n)
            while out.count < n {
                var v = next64()
                for _ in 0..<8 where out.count < n { out.append(UInt8(v & 0xff)); v >>= 8 }
            }
            return out
        }
    }
}

extension PCAMpc.Fe {
    /// y >= q (a non-canonical field encoding).
    static func geqQ(_ y: PCAMpc.Fe) -> Bool {
        for i in stride(from: 3, through: 0, by: -1) where y.w[i] != q[i] { return y.w[i] > q[i] }
        return true
    }
}
