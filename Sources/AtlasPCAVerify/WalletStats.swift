import Foundation

/// Small numerics for the wallet's noise estimates: log-gamma (Lanczos), the regularized incomplete beta function (modified Lentz),
/// its quantile by bisection and the binary entropy. Floats follow the reference operation by operation; `log`, `exp`, `sin` and
/// `log2` come from the platform libm, so the last bit can differ from the reference's fdlibm on a rare input.
public enum WalletStats {
    static let LANCZOS: [Double] = [676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
                                    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7]

    public static func lnGamma(_ x: Double) -> Double {
        if x < 0.5 { return FdLibm.log(Double.pi / FdLibm.sin(Double.pi * x)) - lnGamma(1 - x) }
        let z = x - 1
        var a = 0.99999999999980993
        let t = z + 7.5
        for i in 0..<LANCZOS.count { a += LANCZOS[i] / (z + Double(i) + 1) }
        return 0.5 * FdLibm.log(2 * Double.pi) + (z + 0.5) * FdLibm.log(t) - t + FdLibm.log(a)
    }

    /// The continued fraction of I_x(a, b) (a zero denominator is replaced by 1e-300, never divided by).
    public static func betacf(_ a: Double, _ b: Double, _ x: Double) -> Double {
        let tiny = 1e-300
        let qab = a + b, qap = a + 1, qam = a - 1
        var c = 1.0
        var d = 1 - (qab * x) / qap
        if abs(d) < tiny { d = tiny }
        d = 1 / d
        var h = d
        var m = 1.0
        while m <= 300 {
            let m2 = 2 * m
            var aa = (m * (b - m) * x) / ((qam + m2) * (a + m2))
            d = 1 + aa * d
            if abs(d) < tiny { d = tiny }
            c = 1 + aa / c
            if abs(c) < tiny { c = tiny }
            d = 1 / d
            h *= d * c
            aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2))
            d = 1 + aa * d
            if abs(d) < tiny { d = tiny }
            c = 1 + aa / c
            if abs(c) < tiny { c = tiny }
            d = 1 / d
            let del = d * c
            h *= del
            if abs(del - 1) < 1e-15 { break }
            m += 1
        }
        return h
    }

    /// Regularized incomplete beta I_x(a, b), a, b > 0, x in [0, 1].
    public static func betaInc(_ x: Double, _ a: Double, _ b: Double) throws -> Double {
        if !(a > 0 && b > 0) { throw JSError("betaInc: a and b must be > 0") }
        if x <= 0 { return 0 }
        if x >= 1 { return 1 }
        let lbt = lnGamma(a + b) - lnGamma(a) - lnGamma(b) + a * FdLibm.log(x) + b * FdLibm.log(1 - x)
        let bt = FdLibm.exp(lbt)
        if x < (a + 1) / (a + b + 2) { return (bt * betacf(a, b, x)) / a }
        return 1 - (bt * betacf(b, a, 1 - x)) / b
    }

    /// The q-quantile of Beta(a, b) by bisection (200 steps).
    /// The upper bound q such that the Beta(a, b) posterior puts mass delta above it, for positive integer a and b, exactly: I_x(a, b) = P[Bin(a + b - 1, x) >= a],
    /// so it is the Clopper-Pearson inversion with k = a - 1 successes in n = a + b - 1 trials.
    public static func betaUpperExact(_ delta: Double, _ a: Double, _ b: Double) throws -> Double {
        guard a.isFinite, b.isFinite, a == a.rounded(.towardZero), b == b.rounded(.towardZero), a >= 1, b >= 1 else { throw JSError("betaUpperExact: a and b must be positive integers") }
        return try PCAIntentStats.clopperPearsonUpper(a - 1, a + b - 1, delta)
    }

    public static func betaQuantile(_ q: Double, _ a: Double, _ b: Double) throws -> Double {
        if !(q >= 0 && q <= 1) { throw JSError("betaQuantile: q must be in [0, 1]") }
        if q == 0 { return 0 }
        if q == 1 { return 1 }
        var lo = 0.0, hi = 1.0
        for _ in 0..<200 {
            let mid = (lo + hi) / 2
            if try betaInc(mid, a, b) < q { lo = mid } else { hi = mid }
        }
        return hi
    }

    /// Binary entropy in bits.
    static func binEnt(_ p: Double) -> Double {
        if p <= 0 || p >= 1 { return 0 }
        return -(p * FdLibm.log2(p) + (1 - p) * FdLibm.log2(1 - p))
    }
}
