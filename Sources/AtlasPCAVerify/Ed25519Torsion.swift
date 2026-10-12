import Foundation

/// Exact prime-order-subgroup test for edwards25519 points (`[L]·P == O`), the check `keys.ts` makes through
/// `isTorsionFree()`. CryptoKit's cofactorless verification accepts a MIXED-ORDER public key `A + T` (T of order 8)
/// whenever the signature hash k ≡ 0 (mod 8), so the public key MUST be proven torsion-free here. Results are cached
/// per encoding (a verifier sees the same few keys over and over). R needs no separate subgroup test: with a
/// torsion-free A and S < L, CryptoKit's (cofactorless) equation only accepts R = [S]B − [k]A, which is torsion-free
/// (the conformance corpus has mixed-order-R vectors that pin this).
///
/// Field arithmetic is a small fixed-width (4 x UInt64) implementation mod p = 2^255 - 19, with no heap allocation.
enum Ed25519Torsion {
    struct Fe: Equatable {
        var a0: UInt64, a1: UInt64, a2: UInt64, a3: UInt64
        init(_ a0: UInt64, _ a1: UInt64 = 0, _ a2: UInt64 = 0, _ a3: UInt64 = 0) { self.a0 = a0; self.a1 = a1; self.a2 = a2; self.a3 = a3 }
        subscript(i: Int) -> UInt64 {
            get { switch i { case 0: return a0; case 1: return a1; case 2: return a2; default: return a3 } }
            set { switch i { case 0: a0 = newValue; case 1: a1 = newValue; case 2: a2 = newValue; default: a3 = newValue } }
        }
        var isZero: Bool { a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0 }
    }

    static let P = Fe(0xFFFF_FFFF_FFFF_FFED, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF)
    static let zero = Fe(0)
    static let one = Fe(1)

    static func geP(_ x: Fe) -> Bool {
        var i = 3
        while i >= 0 { if x[i] != P[i] { return x[i] > P[i] }; i -= 1 }
        return true
    }
    static func subP(_ x: Fe) -> Fe {
        var r = x, borrow: UInt64 = 0
        for i in 0..<4 {
            let (s1, o1) = r[i].subtractingReportingOverflow(P[i])
            let (s2, o2) = s1.subtractingReportingOverflow(borrow)
            r[i] = s2; borrow = (o1 || o2) ? 1 : 0
        }
        return r
    }
    /// Fold a value in [0, 2^256) to the canonical representative in [0, p).
    static func canon(_ x: Fe) -> Fe {
        var r = x
        while geP(r) { r = subP(r) }
        return r
    }
    static func addCarry(_ x: Fe, _ y: Fe) -> (Fe, UInt64) {
        var r = x, c: UInt64 = 0
        for i in 0..<4 {
            let (s1, o1) = x[i].addingReportingOverflow(y[i])
            let (s2, o2) = s1.addingReportingOverflow(c)
            r[i] = s2; c = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        return (r, c)
    }
    static func fadd(_ x: Fe, _ y: Fe) -> Fe {
        var (r, c) = addCarry(x, y)
        while c != 0 { (r, c) = addCarry(r, Fe(c &* 38)) }   // 2^256 = 38 (mod p)
        return canon(r)
    }
    static func negSub(_ x: Fe) -> Fe {          // p - x for canonical x != 0
        var r = P, borrow: UInt64 = 0
        for i in 0..<4 {
            let (s1, o1) = P[i].subtractingReportingOverflow(x[i])
            let (s2, o2) = s1.subtractingReportingOverflow(borrow)
            r[i] = s2; borrow = (o1 || o2) ? 1 : 0
        }
        return r
    }
    static func fsub(_ x: Fe, _ y: Fe) -> Fe { fadd(x, y.isZero ? y : negSub(y)) }
    static func fmul(_ x: Fe, _ y: Fe) -> Fe {
        var r = [UInt64](repeating: 0, count: 8)
        r.withUnsafeMutableBufferPointer { r in
            for i in 0..<4 {
                var carry: UInt64 = 0
                for j in 0..<4 {
                    let (hi, lo) = x[i].multipliedFullWidth(by: y[j])
                    let (s1, o1) = lo.addingReportingOverflow(r[i + j])
                    let (s2, o2) = s1.addingReportingOverflow(carry)
                    r[i + j] = s2
                    carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
                }
                r[i + 4] = carry
            }
        }
        return reduceWide(r)
    }
    /// Reduce a 512-bit little-endian value (8 limbs) mod p: fold the high 256 bits (2^256 = 38 mod p), then canonicalise.
    static func reduceWide(_ r: [UInt64]) -> Fe {
        var t = Fe(r[0], r[1], r[2], r[3]), c: UInt64 = 0
        for j in 0..<4 {
            let (hi, lo) = r[4 + j].multipliedFullWidth(by: 38)
            let (s1, o1) = lo.addingReportingOverflow(t[j])
            let (s2, o2) = s1.addingReportingOverflow(c)
            t[j] = s2
            c = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
        }
        var cc = c
        while cc != 0 { let (n, k) = addCarry(t, Fe(cc &* 38)); t = n; cc = k }
        return canon(t)
    }
    private static func fpow(_ base: Fe, _ e: Fe) -> Fe {
        var r = one
        var i = 255
        while i >= 0 {
            r = fmul(r, r)
            if (e[i >> 6] >> UInt64(i & 63)) & 1 == 1 { r = fmul(r, base) }
            i -= 1
        }
        return r
    }
    private static let pMinus2 = Fe(0xFFFF_FFFF_FFFF_FFEB, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF)
    private static let pMinus5Div8 = Fe(0xFFFF_FFFF_FFFF_FFFD, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x0FFF_FFFF_FFFF_FFFF)
    private static let pMinus1Div4 = Fe(0xFFFF_FFFF_FFFF_FFFB, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x1FFF_FFFF_FFFF_FFFF)
    private static func finv(_ x: Fe) -> Fe { fpow(x, pMinus2) }
    private static let d: Fe = fmul(negSub(Fe(121665)), finv(Fe(121666)))
    private static let d2: Fe = fadd(d, d)
    private static let sqrtM1: Fe = fpow(Fe(2), pMinus1Div4)

    private struct Pt { var x: Fe, y: Fe, z: Fe, t: Fe }
    private static let identity = Pt(x: zero, y: one, z: one, t: zero)

    private static func add(_ a: Pt, _ b: Pt) -> Pt {
        let A = fmul(fsub(a.y, a.x), fsub(b.y, b.x))
        let B = fmul(fadd(a.y, a.x), fadd(b.y, b.x))
        let C = fmul(fmul(a.t, d2), b.t)
        let D = fmul(fadd(a.z, a.z), b.z)
        let E = fsub(B, A), F = fsub(D, C), G = fadd(D, C), H = fadd(B, A)
        return Pt(x: fmul(E, F), y: fmul(G, H), z: fmul(F, G), t: fmul(E, H))
    }

    /// Canonical decode: nil if y >= p, off-curve, or x == 0 with the sign bit set.
    private static func decode(_ enc: [UInt8]) -> Pt? {
        guard enc.count == 32 else { return nil }
        var limbs = [UInt64](repeating: 0, count: 4)
        for i in 0..<32 { limbs[i >> 3] |= UInt64(enc[i]) << UInt64((i & 7) * 8) }
        let sign = Int(limbs[3] >> 63)
        limbs[3] &= 0x7FFF_FFFF_FFFF_FFFF
        let y = Fe(limbs[0], limbs[1], limbs[2], limbs[3])
        if geP(y) { return nil }
        let y2 = fmul(y, y)
        let u = fsub(y2, one)
        let v = fadd(fmul(d, y2), one)
        let v3 = fmul(fmul(v, v), v)
        let v7 = fmul(fmul(v3, v3), v)
        var x = fmul(fmul(u, v3), fpow(fmul(u, v7), pMinus5Div8))
        let vx2 = fmul(v, fmul(x, x))
        if vx2 != u {
            if vx2 != fsub(zero, u) { return nil }
            x = fmul(x, sqrtM1)
        }
        if x.isZero && sign == 1 { return nil }
        if Int(x.a0 & 1) != sign { x = fsub(zero, x) }
        return Pt(x: x, y: y, z: one, t: fmul(x, y))
    }

    private static func isIdentity(_ q: Pt) -> Bool { q.x.isZero && q.y == q.z }

    private static let cacheLock = NSLock()
    nonisolated(unsafe) private static var cache: [[UInt8]: Bool] = [:]

    /// True iff `enc` is a canonical on-curve point of the prime-order subgroup (`[L]P == O`) other than the identity.
    static func isPrimeOrder(_ enc: [UInt8]) -> Bool {
        cacheLock.lock()
        if let hit = cache[enc] { cacheLock.unlock(); return hit }
        cacheLock.unlock()
        var ok = false
        if let pt = decode(enc), !isIdentity(pt) {
            var r = identity
            let L = Ed25519Strict.L
            var i = L.bitLength - 1
            while i >= 0 {
                r = add(r, r)
                if L.bit(i) == 1 { r = add(r, pt) }
                i -= 1
            }
            ok = isIdentity(r)
        }
        cacheLock.lock()
        if cache.count > 8192 { cache.removeAll() }
        cache[enc] = ok
        cacheLock.unlock()
        return ok
    }
}
