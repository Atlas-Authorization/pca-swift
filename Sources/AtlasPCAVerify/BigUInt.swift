import Foundation

/// A minimal arbitrary-precision unsigned integer, enough for edwards25519 field (mod `p = 2^255-19`)
/// and scalar (`L`) arithmetic used by the strict RFC 8032 checks. Little-endian `UInt32` limbs,
/// normalized so the most-significant limb is never zero (value 0 == empty limb array).
///
/// Deliberately simple and total: no performance tuning beyond the specialised `mod p` folding in
/// `Ed25519Strict`. It is exercised only by the conformance suite (a few hundred verifications).
struct BigUInt: Comparable, Equatable {
    /// Little-endian base-2^32 limbs; no trailing zero limbs.
    private(set) var limbs: [UInt32]

    init() { limbs = [] }

    init(_ v: UInt64) {
        var out: [UInt32] = []
        var x = v
        while x != 0 { out.append(UInt32(x & 0xffff_ffff)); x >>= 32 }
        limbs = out
    }

    private init(normalizing l: [UInt32]) {
        var l = l
        while l.last == 0 { l.removeLast() }
        limbs = l
    }

    /// Little-endian bytes (least-significant byte first).
    init(bytesLE bytes: [UInt8]) {
        var l = [UInt32](repeating: 0, count: (bytes.count + 3) / 4)
        for (i, b) in bytes.enumerated() {
            l[i >> 2] |= UInt32(b) << UInt32((i & 3) * 8)
        }
        self.init(normalizing: l)
    }

    /// Base-10 string (unsigned). Used only for the two fixed curve constants.
    init(decimal s: String) {
        var acc = BigUInt(0)
        let ten = BigUInt(10)
        for ch in s.unicodeScalars {
            let d = UInt64(ch.value) - 48
            precondition(d <= 9, "BigUInt(decimal:) non-digit")
            acc = acc * ten + BigUInt(d)
        }
        self = acc
    }

    var isZero: Bool { limbs.isEmpty }
    var isEven: Bool { limbs.isEmpty || (limbs[0] & 1) == 0 }

    /// Number of significant bits (0 for zero).
    var bitLength: Int {
        guard let top = limbs.last else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    /// Bit `i` (0 == least significant).
    func bit(_ i: Int) -> Int {
        let limb = i >> 5
        if limb >= limbs.count { return 0 }
        return Int((limbs[limb] >> UInt32(i & 31)) & 1)
    }

    static func == (a: BigUInt, b: BigUInt) -> Bool { a.limbs == b.limbs }

    static func < (a: BigUInt, b: BigUInt) -> Bool {
        if a.limbs.count != b.limbs.count { return a.limbs.count < b.limbs.count }
        var i = a.limbs.count - 1
        while i >= 0 {
            if a.limbs[i] != b.limbs[i] { return a.limbs[i] < b.limbs[i] }
            i -= 1
        }
        return false
    }

    static func + (a: BigUInt, b: BigUInt) -> BigUInt {
        let n = max(a.limbs.count, b.limbs.count)
        var out = [UInt32](); out.reserveCapacity(n + 1)
        var carry: UInt64 = 0
        for i in 0..<n {
            let av = i < a.limbs.count ? UInt64(a.limbs[i]) : 0
            let bv = i < b.limbs.count ? UInt64(b.limbs[i]) : 0
            let s = av + bv + carry
            out.append(UInt32(s & 0xffff_ffff))
            carry = s >> 32
        }
        if carry != 0 { out.append(UInt32(carry)) }
        return BigUInt(normalizing: out)
    }

    /// `a - b`, requires `a >= b`.
    static func - (a: BigUInt, b: BigUInt) -> BigUInt {
        precondition(!(a < b), "BigUInt subtraction underflow")
        var out = [UInt32](); out.reserveCapacity(a.limbs.count)
        var borrow: Int64 = 0
        for i in 0..<a.limbs.count {
            let av = Int64(a.limbs[i])
            let bv = i < b.limbs.count ? Int64(b.limbs[i]) : 0
            var s = av - bv - borrow
            if s < 0 { s += 0x1_0000_0000; borrow = 1 } else { borrow = 0 }
            out.append(UInt32(s))
        }
        return BigUInt(normalizing: out)
    }

    static func * (a: BigUInt, b: BigUInt) -> BigUInt {
        if a.isZero || b.isZero { return BigUInt() }
        var out = [UInt64](repeating: 0, count: a.limbs.count + b.limbs.count)
        for i in 0..<a.limbs.count {
            var carry: UInt64 = 0
            let ai = UInt64(a.limbs[i])
            for j in 0..<b.limbs.count {
                let cur = out[i + j] + ai * UInt64(b.limbs[j]) + carry
                out[i + j] = cur & 0xffff_ffff
                carry = cur >> 32
            }
            out[i + b.limbs.count] += carry
        }
        return BigUInt(normalizing: out.map { UInt32($0 & 0xffff_ffff) })
    }

    static func << (a: BigUInt, bits: Int) -> BigUInt {
        if a.isZero || bits == 0 { return a }
        let limbShift = bits >> 5
        let bitShift = UInt32(bits & 31)
        var out = [UInt32](repeating: 0, count: a.limbs.count + limbShift + 1)
        for i in 0..<a.limbs.count {
            let v = UInt64(a.limbs[i]) << UInt64(bitShift)
            out[i + limbShift] |= UInt32(v & 0xffff_ffff)
            out[i + limbShift + 1] |= UInt32(v >> 32)
        }
        return BigUInt(normalizing: out)
    }

    static func >> (a: BigUInt, bits: Int) -> BigUInt {
        if a.isZero || bits == 0 { return a }
        let limbShift = bits >> 5
        if limbShift >= a.limbs.count { return BigUInt() }
        let bitShift = UInt32(bits & 31)
        var out = [UInt32](repeating: 0, count: a.limbs.count - limbShift)
        for i in 0..<out.count {
            var v = UInt64(a.limbs[i + limbShift]) >> UInt64(bitShift)
            if bitShift != 0 && (i + limbShift + 1) < a.limbs.count {
                v |= UInt64(a.limbs[i + limbShift + 1]) << UInt64(32 - bitShift)
            }
            out[i] = UInt32(v & 0xffff_ffff)
        }
        return BigUInt(normalizing: out)
    }

    /// Low `n` bits (value mod 2^n).
    func maskBits(_ n: Int) -> BigUInt {
        let limbCount = (n + 31) >> 5
        if limbCount >= limbs.count { return self }
        var out = Array(limbs[0..<limbCount])
        let rem = n & 31
        if rem != 0 { out[limbCount - 1] &= (UInt32(1) << UInt32(rem)) - 1 }
        return BigUInt(normalizing: out)
    }
}
