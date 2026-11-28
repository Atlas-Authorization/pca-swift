import Foundation

/// Deterministic math (the rule the reference states): fixed point with 96 fractional bits, truncating division, and one final
/// round-to-nearest-even conversion to a double followed by an exact power-of-two scaling. No libm.

extension BigUInt {
    static func >> (a: BigUInt, bits: Int) -> BigUInt {
        let ls = bits >> 5
        if a.isZero || bits == 0 { return a }
        if ls >= a.limbs.count { return BigUInt() }
        let bs = UInt32(bits & 31)
        var out = [UInt32](repeating: 0, count: a.limbs.count - ls)
        for i in 0..<out.count {
            let lo = a.limbs[i + ls] >> bs
            let hi: UInt32 = (bs > 0 && i + ls + 1 < a.limbs.count) ? (a.limbs[i + ls + 1] << (32 - bs)) : 0
            out[i] = lo | hi
        }
        return BigUInt(normalizing: out)
    }

    /// Quotient and remainder (Knuth algorithm D over 32-bit limbs); the divisor must not be zero.
    func divMod(_ d: BigUInt) -> (q: BigUInt, r: BigUInt) {
        precondition(!d.isZero, "BigUInt division by zero")
        if self < d { return (BigUInt(), self) }
        if d.limbs.count == 1 {
            let dv = UInt64(d.limbs[0])
            var q = [UInt32](repeating: 0, count: limbs.count)
            var rem: UInt64 = 0
            var i = limbs.count - 1
            while i >= 0 {
                let cur = (rem << 32) | UInt64(limbs[i])
                q[i] = UInt32(cur / dv)
                rem = cur % dv
                i -= 1
            }
            return (BigUInt(normalizing: q), BigUInt(rem))
        }
        let s = d.limbs[d.limbs.count - 1].leadingZeroBitCount
        let v = (d << s).limbs
        var u = (self << s).limbs
        while u.count < limbs.count + 1 { u.append(0) }
        let n = v.count
        let m = limbs.count - n
        var q = [UInt32](repeating: 0, count: m + 1)
        let base: UInt64 = 1 << 32
        let vTop = UInt64(v[n - 1]), vNext = UInt64(v[n - 2])
        var j = m
        while j >= 0 {
            let num = (UInt64(u[j + n]) << 32) | UInt64(u[j + n - 1])
            var qhat = num / vTop
            var rhat = num % vTop
            while qhat >= base || qhat * vNext > ((rhat << 32) | UInt64(u[j + n - 2])) {
                qhat -= 1
                rhat += vTop
                if rhat >= base { break }
            }
            var borrow: Int64 = 0
            var carry: UInt64 = 0
            for i in 0..<n {
                let p = qhat * UInt64(v[i]) + carry
                carry = p >> 32
                let t = Int64(u[i + j]) - borrow - Int64(p & 0xffff_ffff)
                u[i + j] = UInt32(truncatingIfNeeded: t)
                borrow = t < 0 ? 1 : 0
            }
            let t = Int64(u[j + n]) - borrow - Int64(carry)
            u[j + n] = UInt32(truncatingIfNeeded: t)
            if t < 0 {
                qhat -= 1
                var c: UInt64 = 0
                for i in 0..<n {
                    let sum = UInt64(u[i + j]) + UInt64(v[i]) + c
                    u[i + j] = UInt32(truncatingIfNeeded: sum)
                    c = sum >> 32
                }
                u[j + n] = UInt32(truncatingIfNeeded: UInt64(u[j + n]) + c)
            }
            q[j] = UInt32(truncatingIfNeeded: qhat)
            j -= 1
        }
        return (BigUInt(normalizing: q), BigUInt(normalizing: Array(u[0..<n])) >> s)
    }

    static func / (a: BigUInt, b: BigUInt) -> BigUInt { a.divMod(b).q }

    func power(_ e: Int) -> BigUInt {
        var result = BigUInt(1), b = self, k = e
        while k > 0 {
            if k & 1 == 1 { result = result * b }
            k >>= 1
            if k > 0 { b = b * b }
        }
        return result
    }

    /// The nearest double, ties to even (an overflow is +Infinity).
    func toDouble() -> Double {
        let len = bitLength
        if len == 0 { return 0 }
        func low64(_ x: BigUInt) -> UInt64 { UInt64(x.limbs[0]) | (x.limbs.count > 1 ? UInt64(x.limbs[1]) << 32 : 0) }
        if len <= 64 { return Double(low64(self)) }
        let sh = len - 64
        let top = self >> sh
        var t = low64(top)
        if (top << sh) != self { t |= 1 } // sticky: the bits below the top 64 only decide a tie
        return Double(sign: .plus, exponent: sh, significand: Double(t))
    }
}

/// A sign and magnitude integer, enough for the fixed-point series.
struct DetInt {
    var neg: Bool
    var mag: BigUInt
    init(_ mag: BigUInt, neg: Bool = false) { self.mag = mag; self.neg = neg && !mag.isZero }
    var isZero: Bool { mag.isZero }

    static func + (a: DetInt, b: DetInt) -> DetInt {
        if a.neg == b.neg { return DetInt(a.mag + b.mag, neg: a.neg) }
        if a.mag < b.mag { return DetInt(b.mag - a.mag, neg: b.neg) }
        return DetInt(a.mag - b.mag, neg: a.neg)
    }
    static prefix func - (a: DetInt) -> DetInt { DetInt(a.mag, neg: !a.neg) }
    static func - (a: DetInt, b: DetInt) -> DetInt { a + (-b) }
    static func * (a: DetInt, b: DetInt) -> DetInt { DetInt(a.mag * b.mag, neg: a.neg != b.neg) }
    /// Division truncating toward zero.
    static func / (a: DetInt, b: DetInt) -> DetInt { DetInt(a.mag.divMod(b.mag).q, neg: a.neg != b.neg) }
    func toDouble() -> Double { neg ? -mag.toDouble() : mag.toDouble() }
    static func int(_ v: Int) -> DetInt { DetInt(BigUInt(UInt64(v.magnitude)), neg: v < 0) }
}

public enum DetMath {
    private static let FRAC = 96
    private static let ONE = BigUInt(1) << 96
    private static let TWO96 = Double(sign: .plus, exponent: 96, significand: 1)

    /// 2 * atanh(num / den) in fixed point (num, den >= 0).
    private static func atanh2(_ num: BigUInt, _ den: BigUInt) -> BigUInt {
        let z = (num << FRAC) / den
        let z2 = (z * z) >> FRAC
        var term = z
        var sum = BigUInt()
        var i: UInt64 = 1
        while !term.isZero {
            sum = sum + term / BigUInt(i)
            term = (term * z2) >> FRAC
            i += 2
        }
        return sum + sum
    }

    private static let LN2: BigUInt = atanh2(BigUInt(1), BigUInt(3))

    /// ln x * 2^96 for a positive finite double.
    private static func lnFixed(_ x: Double) -> DetInt {
        var y = x
        var scale = 0
        if y < Double.leastNormalMagnitude { y *= Double(sign: .plus, exponent: 64, significand: 1); scale = 64 }
        let bits = y.bitPattern
        let e = Int((bits >> 52) & 0x7ff) - 1023 - scale
        let mant = (bits & ((1 << 52) - 1)) | (1 << 52)
        let one52 = BigUInt(1) << 52
        let m = BigUInt(mant)
        return DetInt.int(e) * DetInt(LN2) + DetInt(atanh2(m - one52, m + one52))
    }

    public static func detLn(_ x: Double) -> Double {
        if x == 0 { return -Double.infinity } // as Math.log: +0 and -0 give -Infinity
        if !(x > 0) { return Double.nan }
        if x == Double.infinity { return x }
        if x == 1 { return 0 }
        return lnFixed(x).toDouble() / TWO96
    }

    public static func detLog2(_ x: Double) -> Double {
        if x == 0 { return -Double.infinity } // as Math.log: +0 and -0 give -Infinity
        if !(x > 0) { return Double.nan }
        if x == Double.infinity { return x }
        if x == 1 { return 0 }
        let l = lnFixed(x)
        let fixed = DetInt(l.mag << FRAC, neg: l.neg) / DetInt(LN2)
        return fixed.toDouble() / TWO96
    }

    private static func floorDiv(_ a: DetInt, _ b: DetInt) -> DetInt {
        let qr = a.mag.divMod(b.mag)
        let q = DetInt(qr.q, neg: a.neg != b.neg)
        if !qr.r.isZero && a.neg != b.neg { return q - DetInt.int(1) }
        return q
    }

    public static func detExp(_ x: Double) -> Double {
        if x.isNaN { return x }
        if x > 709.782712893384 { return Double.infinity }
        if x < -745.2 { return 0 }
        if x == 0 { return 1 }
        let bits = abs(x).bitPattern
        let be = Int((bits >> 52) & 0x7ff)
        let frac = bits & ((1 << 52) - 1)
        let m = BigUInt(be == 0 ? frac : (frac | (1 << 52)))
        let sh = (be == 0 ? 1 : be) - 1075 + FRAC
        let xmag = sh >= 0 ? (m << sh) : (m >> (-sh))
        let bigX = DetInt(xmag, neg: x < 0)
        let ln2 = DetInt(LN2)
        let k = floorDiv(bigX + DetInt(LN2 >> 1), ln2)
        let kInt = Int(k.mag.toDouble()) * (k.neg ? -1 : 1)
        let r = bigX - DetInt.int(kInt) * ln2
        let one = DetInt(ONE)
        var term = one
        var sum = one
        var n: UInt64 = 1
        while !term.isZero {
            term = ((term * r) / one) / DetInt(BigUInt(n))
            sum = sum + term
            n += 1
        }
        let e = kInt - 96
        let half = e / 2 // truncating, as Math.trunc
        func p2(_ k: Int) -> Double { Double(sign: .plus, exponent: k, significand: 1) }
        return sum.toDouble() * p2(half) * p2(e - half)
    }

    /// b^n for an integer n >= 0: 1 multiplied by b, n times in sequence.
    public static func detPowInt(_ b: Double, _ n: Int) -> Double {
        var r = 1.0
        var i = 0
        while i < n { r = r * b; i += 1 }
        return r
    }
}
