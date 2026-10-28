import Foundation

// ECDSA verification over NIST P-224 (secp224r1). swift-crypto / CryptoKit have no P-224, but the reference verifiers hand
// every certificate / CRL / OCSP signature to OpenSSL, which accepts it, so a P-224 issuer key must verify here too.
// shortcut: variable-time schoolbook Montgomery arithmetic, fine for public-key verification only (no secret is involved).

/// Arithmetic modulo an odd prime on fixed-width little-endian 32-bit limbs; elements are kept in Montgomery form.
struct MontField {
    let k: Int
    let n: [UInt32]
    let nPrime: UInt32
    var r2: [UInt32]
    var one: [UInt32]

    init(_ mod: [UInt32]) {
        k = mod.count
        n = mod
        var inv = mod[0]
        for _ in 0..<5 { inv = inv &* (2 &- mod[0] &* inv) }
        nPrime = 0 &- inv
        r2 = [UInt32](repeating: 0, count: mod.count)
        one = r2
        var x = [UInt32](repeating: 0, count: mod.count)
        x[0] = 1
        for _ in 0..<(64 * mod.count) { x = doubleMod(x) } // R^2 mod n by repeated doubling of 1
        r2 = x
        var plain = [UInt32](repeating: 0, count: mod.count)
        plain[0] = 1
        one = mul(plain, r2)
    }

    func geq(_ a: [UInt32]) -> Bool {
        var i = k - 1
        while i >= 0 {
            if a[i] != n[i] { return a[i] > n[i] }
            i -= 1
        }
        return true
    }

    func subRaw(_ a: inout [UInt32], _ b: [UInt32]) -> Bool {
        var borrow: Int64 = 0
        for i in 0..<k {
            let d = Int64(a[i]) - Int64(b[i]) - borrow
            a[i] = UInt32(truncatingIfNeeded: d)
            borrow = d < 0 ? 1 : 0
        }
        return borrow != 0
    }

    private func doubleMod(_ a: [UInt32]) -> [UInt32] { add(a, a) }

    func add(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var r = [UInt32](repeating: 0, count: k)
        var carry: UInt64 = 0
        for i in 0..<k {
            let s = UInt64(a[i]) + UInt64(b[i]) + carry
            r[i] = UInt32(truncatingIfNeeded: s)
            carry = s >> 32
        }
        if carry != 0 || geq(r) { _ = subRaw(&r, n) }
        return r
    }

    func sub(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var r = a
        if subRaw(&r, b) {
            var carry: UInt64 = 0
            for i in 0..<k {
                let s = UInt64(r[i]) + UInt64(n[i]) + carry
                r[i] = UInt32(truncatingIfNeeded: s)
                carry = s >> 32
            }
        }
        return r
    }

    func mul(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var t = [UInt32](repeating: 0, count: k + 2)
        for i in 0..<k {
            var carry: UInt64 = 0
            let ai = UInt64(a[i])
            for j in 0..<k {
                let cur = UInt64(t[j]) + ai * UInt64(b[j]) + carry
                t[j] = UInt32(truncatingIfNeeded: cur)
                carry = cur >> 32
            }
            let c2 = UInt64(t[k]) + carry
            t[k] = UInt32(truncatingIfNeeded: c2)
            t[k + 1] = UInt32(truncatingIfNeeded: c2 >> 32)
            let m = UInt64(t[0] &* nPrime)
            carry = (UInt64(t[0]) + m * UInt64(n[0])) >> 32
            if k > 1 {
                for j in 1..<k {
                    let cur = UInt64(t[j]) + m * UInt64(n[j]) + carry
                    t[j - 1] = UInt32(truncatingIfNeeded: cur)
                    carry = cur >> 32
                }
            }
            let c3 = UInt64(t[k]) + carry
            t[k - 1] = UInt32(truncatingIfNeeded: c3)
            t[k] = t[k + 1] &+ UInt32(truncatingIfNeeded: c3 >> 32)
        }
        var r = Array(t[0..<k])
        if t[k] != 0 || geq(r) { _ = subRaw(&r, n) }
        return r
    }

    func sqr(_ a: [UInt32]) -> [UInt32] { mul(a, a) }
    func toMont(_ a: [UInt32]) -> [UInt32] { mul(a, r2) }
    func fromMont(_ a: [UInt32]) -> [UInt32] {
        var plain = [UInt32](repeating: 0, count: k)
        plain[0] = 1
        return mul(a, plain)
    }
    func isZero(_ a: [UInt32]) -> Bool { !a.contains { $0 != 0 } }

    /// a^(n-2) for a prime modulus (a in Montgomery form; zero maps to zero).
    func inv(_ a: [UInt32]) -> [UInt32] {
        var e = n
        var borrow: UInt64 = 2 // n - 2 across limbs (the field prime's low limb is 1, so the borrow ripples)
        for i in 0..<k {
            let d = Int64(e[i]) - Int64(borrow)
            e[i] = UInt32(truncatingIfNeeded: d)
            borrow = d < 0 ? 1 : 0
        }
        var acc = one
        var bit = 32 * k - 1
        while bit >= 0 {
            acc = sqr(acc)
            if (e[bit / 32] >> UInt32(bit % 32)) & 1 == 1 { acc = mul(acc, a) }
            bit -= 1
        }
        return acc
    }
}

enum P224 {
    static func limbs(_ be: [UInt8]) -> [UInt32] {
        var l = [UInt32](repeating: 0, count: 7)
        for (i, x) in be.reversed().enumerated() where i < 28 { l[i / 4] |= UInt32(x) << UInt32(8 * (i % 4)) }
        return l
    }
    static func hexLimbs(_ s: String) -> [UInt32] { limbs(ACrypto.unhex(s)!) }

    static let F = MontField(hexLimbs("ffffffffffffffffffffffffffffffff000000000000000000000001"))
    static let N = MontField(hexLimbs("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d"))
    static let b = F.toMont(hexLimbs("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"))
    static let gx = F.toMont(hexLimbs("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"))
    static let gy = F.toMont(hexLimbs("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"))

    typealias JP = (x: [UInt32], y: [UInt32], z: [UInt32])
    static var inf: JP { (F.one, F.one, [UInt32](repeating: 0, count: 7)) }
    static func isInf(_ p: JP) -> Bool { F.isZero(p.z) }

    static func lt(_ a: [UInt32], _ m: [UInt32]) -> Bool {
        var i = 6
        while i >= 0 {
            if a[i] != m[i] { return a[i] < m[i] }
            i -= 1
        }
        return false
    }

    static func dbl(_ p: JP) -> JP {
        if isInf(p) || F.isZero(p.y) { return inf }
        let delta = F.sqr(p.z), gamma = F.sqr(p.y), beta = F.mul(p.x, gamma)
        let alpha = F.mul(F.sub(p.x, delta), F.add(p.x, delta))
        let alpha3 = F.add(alpha, F.add(alpha, alpha))
        let beta2 = F.add(beta, beta), beta4 = F.add(beta2, beta2), beta8 = F.add(beta4, beta4)
        let x3 = F.sub(F.sqr(alpha3), beta8)
        let z3 = F.sub(F.sub(F.sqr(F.add(p.y, p.z)), gamma), delta)
        let g2 = F.add(F.sqr(gamma), F.sqr(gamma)), g4 = F.add(g2, g2), g8 = F.add(g4, g4) // 8*gamma^2
        let y3 = F.sub(F.mul(alpha3, F.sub(beta4, x3)), g8)
        return (x3, y3, z3)
    }

    static func add(_ p: JP, _ q: JP) -> JP {
        if isInf(p) { return q }
        if isInf(q) { return p }
        let z1z1 = F.sqr(p.z), z2z2 = F.sqr(q.z)
        let u1 = F.mul(p.x, z2z2), u2 = F.mul(q.x, z1z1)
        let s1 = F.mul(F.mul(p.y, q.z), z2z2), s2 = F.mul(F.mul(q.y, p.z), z1z1)
        let h = F.sub(u2, u1), r0 = F.sub(s2, s1)
        if F.isZero(h) { return F.isZero(r0) ? dbl(p) : inf }
        let i = F.sqr(F.add(h, h)), j = F.mul(h, i), r = F.add(r0, r0), v = F.mul(u1, i)
        let x3 = F.sub(F.sub(F.sqr(r), j), F.add(v, v))
        let sj = F.mul(s1, j)
        let y3 = F.sub(F.mul(r, F.sub(v, x3)), F.add(sj, sj))
        let z3 = F.mul(F.sub(F.sub(F.sqr(F.add(p.z, q.z)), z1z1), z2z2), h)
        return (x3, y3, z3)
    }

    /// The uncompressed SEC1 point as Montgomery affine coordinates; nil unless it is 04||x||y on the curve with x, y < p.
    static func decode(_ point: [UInt8]) -> (x: [UInt32], y: [UInt32])? {
        guard point.count == 57, point[0] == 0x04 else { return nil }
        let xr = limbs(Array(point[1..<29])), yr = limbs(Array(point[29..<57]))
        guard lt(xr, F.n), lt(yr, F.n) else { return nil }
        let x = F.toMont(xr), y = F.toMont(yr)
        let x3 = F.mul(F.sqr(x), x)
        let rhs = F.add(F.sub(x3, F.add(x, F.add(x, x))), b)
        return F.sqr(y) == rhs ? (x, y) : nil
    }

    static func pointValid(_ point: [UInt8]) -> Bool { decode(point) != nil }

    /// r and s from raw r||s (56 bytes) or a strict ASN.1 DER SEQUENCE of two minimal positive INTEGERs; nil otherwise.
    static func parseSig(raw: [UInt8]?, der: [UInt8]?) -> (r: [UInt32], s: [UInt32])? {
        if let r = raw {
            guard r.count == 56 else { return nil }
            return (limbs(Array(r[0..<28])), limbs(Array(r[28..<56])))
        }
        guard let d = der, d.count >= 8, d[0] == 0x30, Int(d[1]) == d.count - 2, d[1] < 0x80 else { return nil }
        var off = 2
        func int() -> [UInt32]? {
            guard off + 2 <= d.count, d[off] == 0x02 else { return nil }
            let len = Int(d[off + 1])
            guard len >= 1, len < 0x80, off + 2 + len <= d.count else { return nil }
            var v = Array(d[(off + 2)..<(off + 2 + len)])
            off += 2 + len
            if v[0] & 0x80 != 0 { return nil } // negative
            if v.count > 1 && v[0] == 0 {
                if v[1] & 0x80 == 0 { return nil } // non-minimal
                v.removeFirst()
            }
            return v.count <= 28 ? limbs(v) : nil
        }
        guard let r = int(), let s = int(), off == d.count else { return nil }
        return (r, s)
    }

    static func verify(point: [UInt8], hash: AHash, message: [UInt8], raw: [UInt8]?, der: [UInt8]?) -> Bool {
        guard let q = decode(point), let sig = parseSig(raw: raw, der: der) else { return false }
        guard !N.isZero(sig.r), !N.isZero(sig.s), lt(sig.r, N.n), lt(sig.s, N.n) else { return false }
        var e = limbs(Array(hash.digest(message).prefix(28)))
        if !lt(e, N.n) { _ = N.subRaw(&e, N.n) }
        let w = N.inv(N.toMont(sig.s))
        let u1 = N.fromMont(N.mul(N.toMont(e), w))
        let u2 = N.fromMont(N.mul(N.toMont(sig.r), w))
        let g: JP = (gx, gy, F.one), qj: JP = (q.x, q.y, F.one)
        let gq = add(g, qj)
        var acc = inf
        var bit = 223
        while bit >= 0 {
            acc = dbl(acc)
            let b1 = (u1[bit / 32] >> UInt32(bit % 32)) & 1 == 1
            let b2 = (u2[bit / 32] >> UInt32(bit % 32)) & 1 == 1
            if b1 && b2 { acc = add(acc, gq) } else if b1 { acc = add(acc, g) } else if b2 { acc = add(acc, qj) }
            bit -= 1
        }
        if isInf(acc) { return false }
        let zi = F.inv(acc.z)
        var xr = F.fromMont(F.mul(acc.x, F.sqr(zi)))
        if !lt(xr, N.n) { _ = N.subRaw(&xr, N.n) } // p - n < n, so one subtraction reduces
        return xr == sig.r
    }
}
