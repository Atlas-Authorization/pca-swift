import Foundation

/// Exact Clopper-Pearson upper bounds (integer arithmetic on the 2^-52 grid), the floating-point binomial CDF used for starting
/// guesses, Hoeffding half-widths and Wilson intervals (reference: @atlasauth/pca-intent clopper.ts). This is the one
/// implementation: the wallet's `WalletOmegaMath` forwards here.
public enum PCAIntentStats {
    public static let CP_GRID_BITS: Int = 52
    public static let CP_TOLERANCE: Double = 1.0 / 17592186044416.0 // 2^-44
    static let TOL_UNITS: Int64 = 256 // 2^(52-44)
    static let GRID: Int64 = Int64(1) << 52

    /// The exact binary fraction num / 2^exp of a double in (0, 1).
    struct Dyadic {
        var num: BigUInt
        var exp: Int
        init(_ num: BigUInt, _ exp: Int) { self.num = num; self.exp = exp }
    }

    /// A bound on the 2^-52 grid with its certified bracket (units of 2^-52).
    public struct CPCertificate {
        public var upper: Double
        public var upperUnits: Int64
        public var lowerUnits: Int64
    }

    public struct Wilson {
        public var p: Double
        public var lo: Double
        public var hi: Double
    }

    static let GRID_BITS = 52
    static let A = BigUInt(1) << 52

    public static func logFactorials(_ n: Int) -> [Double] {
        var lf = [Double](repeating: 0, count: n + 1)
        if n >= 1 { for i in 1...n { lf[i] = lf[i - 1] + FdLibm.log(Double(i)) } }
        return lf
    }

    static func power(_ base: BigUInt, _ e: Int) -> BigUInt {
        var r = BigUInt(1)
        for _ in 0..<e { r = r * base }
        return r
    }

    static func floatGuess(_ k: Int, _ n: Int, _ alpha: Double) -> Double {
        let lf = logFactorials(n)
        var lo = Double(k) / Double(n)
        var hi = 1.0
        var it = 0
        while it < 200 && hi - lo > 1e-13 {
            let mid = (lo + hi) / 2
            if binomialCdf(k, n, mid, lf) > alpha { lo = mid } else { hi = mid }
            it += 1
        }
        return hi
    }

    /// P(X <= k), X ~ Binomial(n, p), in floating point (guesses and diagnostics only).
    public static func binomialCdf(_ k: Int, _ n: Int, _ p: Double, _ lf0: [Double]? = nil) -> Double {
        if k >= n { return 1.0 }
        if k < 0 { return 0.0 }
        if p <= 0 { return 1.0 }
        if p >= 1 { return 0.0 }
        let lf: [Double] = lf0 ?? logFactorials(n)
        let lp: Double = FdLibm.log(p)
        let lq: Double = log1p(-p)
        var s: Double = 0
        for i in 0...k { s += FdLibm.exp(lf[n] - lf[i] - lf[n - i] + Double(i) * lp + Double(n - i) * lq) }
        return min(1, s)
    }

    static func doubleToDyadic(_ x: Double) throws -> Dyadic {
        if !(x > 0 && x < 1) { throw JSError("doubleToDyadic: need 0 < x < 1") }
        var e: Int = 0
        var y: Double = x
        while y != y.rounded(.toNearestOrEven) {
            y *= 2
            e += 1
            if e > 1100 { throw JSError("doubleToDyadic: not reached") }
        }
        return Dyadic(BigUInt(UInt64(y)), e)
    }

    /// N with cdfRec(a / 2^52, n, k) = N / 2^(52 n), by the recursion of the definition.
    static func cdfRecNumerator(_ n: Int, _ k: Int, _ a: BigUInt) throws -> BigUInt {
        if !(a < (A + BigUInt(1))) { throw JSError("cdfRecNumerator: a must be in [0, 2^52]") }
        if min(k, n) < 0 { throw JSError("cdfRecNumerator: bad k") }
        let b = A - a
        let kk = min(k, n)
        var row = [BigUInt](repeating: BigUInt(1), count: kk + 1)
        var pw = BigUInt(1)
        for m in 0..<n {
            var nxt = [BigUInt](repeating: BigUInt(), count: kk + 1)
            let pwNext = pw * A
            for j in 0...kk {
                if j >= m + 1 { nxt[j] = pwNext } else {
                    let left = j == 0 ? BigUInt() : row[j - 1]
                    nxt[j] = a * left + b * row[j]
                }
            }
            row = nxt
            pw = pwNext
        }
        return row[kk]
    }

    /// Exactly decides alpha < cdfRec(a / 2^52, n, k).
    static func cdfExceeds(_ n: Int, _ k: Int, _ a: BigUInt, _ alpha: Dyadic) throws -> Bool {
        let big: BigUInt = try cdfRecNumerator(n, k, a)
        let lhs: BigUInt = big << alpha.exp
        let rhs: BigUInt = alpha.num * power(A, n)
        return rhs < lhs
    }

    private static func clamp(_ a: Int64) -> Int64 { a < 0 ? 0 : (a > GRID ? GRID : a) }

    private static func isInt(_ d: Double) -> Bool { d.isFinite && d == d.rounded(.toNearestOrEven) }

    /// Certifies a bracket of at most TOL_UNITS around the flip point of the antitone `exceeds`.
    public static func certifyBracket(_ start: Int64, _ exceeds: (Int64) throws -> Bool) throws -> (hi: Int64, lo: Int64) {
        var hi: Int64 = start
        var step: Int64 = TOL_UNITS
        while try exceeds(hi) { hi = clamp(hi + step); step *= 2 }
        var lo: Int64 = clamp(hi - TOL_UNITS)
        step = TOL_UNITS
        while lo > 0 {
            if try exceeds(lo) { break }
            hi = lo
            lo = clamp(lo - step)
            step *= 2
        }
        if lo == 0 {
            let z: Bool = try exceeds(0)
            if !z { throw JSError("clopperPearsonUpper: unreachable (cdfRec(0) = 1)") }
        }
        while hi - lo > TOL_UNITS {
            let mid: Int64 = (lo + hi) >> 1
            if try exceeds(mid) { lo = mid } else { hi = mid }
        }
        return (hi, lo)
    }

    public static func clopperPearsonCertified(_ kD: Double, _ nD: Double, _ alpha: Double) throws -> CPCertificate {
        if !(isInt(kD) && isInt(nD) && kD >= 0 && nD >= 0 && kD <= nD && nD <= 9007199254740991) { throw JSError("clopperPearsonUpper: need integers 0 <= k <= n") }
        if !(alpha > 0 && alpha < 1) { throw JSError("clopperPearsonUpper: alpha must be in (0, 1)") }
        let k: Int = Int(kD)
        let n: Int = Int(nD)
        if n == 0 || k == n { return CPCertificate(upper: 1.0, upperUnits: GRID, lowerUnits: GRID) }
        let al: Dyadic = try doubleToDyadic(alpha)
        let aPowN: BigUInt = power(A, n)
        let guess: Double = floatGuess(k, n, alpha)
        let start: Int64 = clamp(Int64((guess * 4503599627370496.0).rounded(.up)) + TOL_UNITS)
        let br = try certifyBracket(start) { (a: Int64) -> Bool in
            let lhs: BigUInt = try cdfRecNumerator(n, k, BigUInt(UInt64(a))) << al.exp
            return aPowN * al.num < lhs
        }
        return CPCertificate(upper: Double(br.hi) / 4503599627370496.0, upperUnits: br.hi, lowerUnits: br.lo)
    }

    public static func clopperPearsonUpper(_ k: Double, _ n: Double, _ alpha: Double) throws -> Double {
        return try clopperPearsonCertified(k, n, alpha).upper
    }

    public static func hoeffdingHalfWidth(_ range: Double, _ samples: Double, _ deltaPrime: Double = 0.05) -> Double {
        return range * (FdLibm.log(2 / deltaPrime) / (2 * samples)).squareRoot()
    }

    public static func wilsonInterval(_ k: Double, _ n: Double, _ z: Double = 1.959963984540054) -> Wilson {
        if !(n > 0) { return Wilson(p: Double.nan, lo: 0.0, hi: 1.0) }
        let p: Double = k / n
        let z2: Double = z * z
        let den: Double = 1 + z2 / n
        let centre: Double = (p + z2 / (2 * n)) / den
        let half: Double = (z * ((p * (1 - p)) / n + z2 / (4 * n * n)).squareRoot()) / den
        return Wilson(p: p, lo: max(0.0, centre - half), hi: min(1.0, centre + half))
    }
}
