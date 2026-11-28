import Foundation
import BigInt

/// The arbitrary-precision type the VDF code works in, named so a test that also sees another module's `BigUInt` can refer to this one.
public typealias PCAVdfBigUInt = BigUInt

/// Fixed-width Montgomery arithmetic for an ODD modulus (CIOS: multiply and reduce in one pass over preallocated limbs, `multipliedFullWidth`, no per-operation
/// allocation in the hot loops). The VDF, Miller-Rabin and Lucas paths run in Montgomery form and cross to `BigUInt` only at the edges (parsing and output).
/// `BigUInt` multiplication plus a long division per step was the cost that made one corpus slice take more than 25 minutes.
/// Assumes 64-bit words (`BigUInt.Word` is 64 bits on every platform this package builds for).
final class PCAMont {
    let k: Int
    let n: [UInt64]
    let one: [UInt64]   // R mod n
    let r2: [UInt64]    // R^2 mod n
    let nprime: UInt64  // -n^-1 mod 2^64
    private let t: UnsafeMutablePointer<UInt64> // k + 2 scratch limbs
    private let np: UnsafeMutablePointer<UInt64>

    /// nil unless `modulus` is odd and > 1.
    init?(_ modulus: BigUInt) {
        guard modulus > 1, modulus[bitAt: 0] else { return nil }
        let k = (modulus.bitWidth + 63) / 64
        self.k = k
        var limbs = [UInt64](repeating: 0, count: k)
        var i = 0
        for w in modulus.words { limbs[i] = UInt64(w); i += 1 }
        n = limbs
        let n0 = limbs[0]
        var inv = n0 // n0 * n0 = 1 (mod 8): 3 correct bits, doubled five times
        for _ in 0..<5 { inv = inv &* (2 &- n0 &* inv) }
        nprime = 0 &- inv
        func pad(_ x: BigUInt) -> [UInt64] {
            var a = [UInt64](repeating: 0, count: k)
            var j = 0
            for w in x.words { a[j] = UInt64(w); j += 1 }
            return a
        }
        one = pad((BigUInt(1) << (64 * k)) % modulus)
        r2 = pad((BigUInt(1) << (128 * k)) % modulus)
        t = UnsafeMutablePointer<UInt64>.allocate(capacity: k + 2)
        np = UnsafeMutablePointer<UInt64>.allocate(capacity: k)
        for j in 0..<k { np[j] = limbs[j] }
    }

    deinit {
        t.deallocate()
        np.deallocate()
    }

    // MARK: core (pointers; `out` may alias `a` or `b`)

    /// out = a * b * R^-1 mod n, for a, b < n.
    private func core(_ a: UnsafePointer<UInt64>, _ b: UnsafePointer<UInt64>, _ out: UnsafeMutablePointer<UInt64>) {
        let k = self.k
        for j in 0..<(k + 2) { t[j] = 0 }
        for i in 0..<k {
            let bi = b[i]
            var carry: UInt64 = 0
            for j in 0..<k {
                let (hi, lo) = a[j].multipliedFullWidth(by: bi)
                let (s1, c1) = lo.addingReportingOverflow(t[j])
                let (s2, c2) = s1.addingReportingOverflow(carry)
                t[j] = s2
                carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            let (top, ct) = t[k].addingReportingOverflow(carry)
            t[k] = top
            t[k + 1] = ct ? 1 : 0
            let m = t[0] &* nprime
            let (h0, l0) = m.multipliedFullWidth(by: np[0])
            let (_, cz) = l0.addingReportingOverflow(t[0])
            carry = h0 &+ (cz ? 1 : 0)
            if k > 1 {
                for j in 1..<k {
                    let (hi, lo) = m.multipliedFullWidth(by: np[j])
                    let (s1, c1) = lo.addingReportingOverflow(t[j])
                    let (s2, c2) = s1.addingReportingOverflow(carry)
                    t[j - 1] = s2
                    carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
                }
            }
            let (s3, c3) = t[k].addingReportingOverflow(carry)
            t[k - 1] = s3
            t[k] = t[k + 1] &+ (c3 ? 1 : 0)
        }
        finish(out)
    }

    /// out = t[0...k] (a value below 2n) reduced into [0, n).
    private func finish(_ out: UnsafeMutablePointer<UInt64>) {
        var sub = t[k] != 0
        if !sub {
            sub = true // equal to n reduces to zero
            var i = k - 1
            while i >= 0 {
                if t[i] != np[i] { sub = t[i] > np[i]; break }
                i -= 1
            }
        }
        if sub {
            var borrow: UInt64 = 0
            for j in 0..<k {
                let (d1, b1) = t[j].subtractingReportingOverflow(np[j])
                let (d2, b2) = d1.subtractingReportingOverflow(borrow)
                out[j] = d2
                borrow = (b1 || b2) ? 1 : 0
            }
        } else {
            for j in 0..<k { out[j] = t[j] }
        }
    }

    // MARK: array API

    func mulInto(_ a: [UInt64], _ b: [UInt64], _ out: inout [UInt64]) {
        a.withUnsafeBufferPointer { ap in
            b.withUnsafeBufferPointer { bp in
                out.withUnsafeMutableBufferPointer { op in core(ap.baseAddress!, bp.baseAddress!, op.baseAddress!) }
            }
        }
    }

    func mul(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var out = [UInt64](repeating: 0, count: k)
        mulInto(a, b, &out)
        return out
    }

    func add(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var carry: UInt64 = 0
        for j in 0..<k {
            let (s1, c1) = a[j].addingReportingOverflow(b[j])
            let (s2, c2) = s1.addingReportingOverflow(carry)
            t[j] = s2
            carry = (c1 || c2) ? 1 : 0
        }
        t[k] = carry
        var out = [UInt64](repeating: 0, count: k)
        out.withUnsafeMutableBufferPointer { finish($0.baseAddress!) }
        return out
    }

    func sub(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var borrow: UInt64 = 0
        var out = [UInt64](repeating: 0, count: k)
        for j in 0..<k {
            let (d1, b1) = a[j].subtractingReportingOverflow(b[j])
            let (d2, b2) = d1.subtractingReportingOverflow(borrow)
            out[j] = d2
            borrow = (b1 || b2) ? 1 : 0
        }
        if borrow != 0 { // went below zero: add n back
            var carry: UInt64 = 0
            for j in 0..<k {
                let (s1, c1) = out[j].addingReportingOverflow(n[j])
                let (s2, c2) = s1.addingReportingOverflow(carry)
                out[j] = s2
                carry = (c1 || c2) ? 1 : 0
            }
        }
        return out
    }

    /// x / 2 mod n (n is odd): the value itself when even, else (x + n) / 2.
    func half(_ x: [UInt64]) -> [UInt64] {
        var carry: UInt64 = 0
        let odd = x[0] & 1 == 1
        for j in 0..<k {
            if odd {
                let (s1, c1) = x[j].addingReportingOverflow(n[j])
                let (s2, c2) = s1.addingReportingOverflow(carry)
                t[j] = s2
                carry = (c1 || c2) ? 1 : 0
            } else {
                t[j] = x[j]
            }
        }
        t[k] = carry
        var out = [UInt64](repeating: 0, count: k)
        for j in 0..<k { out[j] = (t[j] >> 1) | (t[j + 1] << 63) }
        return out
    }

    func isZero(_ a: [UInt64]) -> Bool { !a.contains { $0 != 0 } }

    /// x mod n in Montgomery form.
    func toMont(_ x: BigUInt) -> [UInt64] {
        let r = x % BigUInt(words: n.map { UInt($0) })
        var a = [UInt64](repeating: 0, count: k)
        var i = 0
        for w in r.words { a[i] = UInt64(w); i += 1 }
        return mul(a, r2)
    }

    func fromMont(_ a: [UInt64]) -> BigUInt {
        var unit = [UInt64](repeating: 0, count: k)
        unit[0] = 1
        return BigUInt(words: mul(a, unit).map { UInt($0) })
    }

    /// base^exp, all in Montgomery form (4-bit windows over a 16-entry table; squarings in place).
    func pow(_ base: [UInt64], _ exp: BigUInt) -> [UInt64] {
        if exp.isZero { return one }
        var table = [one, base]
        for i in 2..<16 { table.append(mul(table[i - 1], base)) }
        let bits = exp.bitWidth
        var acc = one, tmp = [UInt64](repeating: 0, count: k)
        var started = false
        var i = ((bits + 3) / 4) * 4 - 4
        while i >= 0 {
            var w = 0
            for b in 0..<4 where i + b < bits && exp[bitAt: i + b] { w |= 1 << b }
            if started {
                for _ in 0..<4 { mulInto(acc, acc, &tmp); swap(&acc, &tmp) }
            }
            if w != 0 {
                mulInto(acc, table[w], &tmp); swap(&acc, &tmp)
                started = true
            }
            i -= 4
        }
        return acc
    }

    /// x^(2^steps), all in Montgomery form.
    func squarings(_ x: [UInt64], _ steps: Int) -> [UInt64] {
        var y = x, tmp = [UInt64](repeating: 0, count: k)
        var s = 0
        while s < steps { mulInto(y, y, &tmp); swap(&y, &tmp); s += 1 }
        return y
    }
}
