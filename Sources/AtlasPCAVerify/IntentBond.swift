import Foundation

/// Bond sizing for optimistic claims: max(floor, curve(k, exposure)) on the micro grid, linear by default, optionally convex.
public enum PCAIntentBond {
    public static let MICROS_PER_UNIT: Double = 1000000.0
    static let MAX_SAFE_MICROS: Double = 1e15

    public struct Tier {
        public var upTo: Double
        public var marginalK: Double
        public init(_ upTo: Double, _ marginalK: Double) { self.upTo = upTo; self.marginalK = marginalK }
    }

    /// The sizing and per-depositor cap policy; curveKind is nil/linear, power (gamma) or piecewise (tiers).
    public struct BondPolicy {
        public var floor: Double = 1.0
        public var k: Double = 1.0
        public var maxOpenClaims: Double = 100.0
        public var maxOpenAmount: Double = Double.infinity
        public var curveKind: String? = nil
        public var gamma: Double = Double.nan
        public var tiers: [Tier]? = nil
        public var tiersIsArray: Bool = true

        public init() {}

        public static func fromJson(_ o: JSONValue?) throws -> BondPolicy {
            guard let m = o?.asObject else { throw JSError("bond policy: not an object") }
            var p = BondPolicy()
            p.floor = num(m[JKey("floor")]); p.k = num(m[JKey("k")]); p.maxOpenClaims = num(m[JKey("maxOpenClaims")])
            if let mo = m[JKey("maxOpenAmount")], !mo.isNull { p.maxOpenAmount = num(mo) } else { p.maxOpenAmount = Double.infinity }
            if let cv = m[JKey("curve")], !cv.isNull {
                guard let c = cv.asObject else { throw JSError("bond policy: curve is not an object") }
                if let kv = c[JKey("kind")], !kv.isNull {
                    guard let ks = kv.asString else { throw JSError("bond policy: curve kind is not a string") }
                    p.curveKind = ks
                }
                if let g = c[JKey("gamma")] { p.gamma = num(g) }
                if let tv = c[JKey("tiers")] {
                    if let arr = tv.asArray {
                        var ts: [Tier] = []
                        for t in arr {
                            guard let to = t.asObject else { throw JSError("bond policy: tier is not an object") }
                            ts.append(Tier(num(to[JKey("upTo")]), num(to[JKey("marginalK")])))
                        }
                        p.tiers = ts
                    } else { p.tiersIsArray = false }
                }
            }
            return p
        }
    }

    private static func num(_ o: JSONValue?) -> Double { return IV.num(o) ?? Double.nan }

    private static func fin(_ x: Double) -> Bool { return x.isFinite }

    public static let DEFAULT_BOND_POLICY = BondPolicy()

    /// Round an amount up onto the micro grid (a micro amount round-trips exactly; amounts too large for it are unchanged).
    public static func quantizeUp(_ x: Double) -> Double {
        if !fin(x) || x <= 0 { return x }
        let scaled: Double = x * MICROS_PER_UNIT
        if scaled > MAX_SAFE_MICROS { return x }
        let r: Double = WJ.jsRound(scaled)
        let m: Double = (r / MICROS_PER_UNIT == x || abs(scaled - r) <= 1e-3) ? r : scaled.rounded(.up)
        return m / MICROS_PER_UNIT
    }

    /// e^gamma for gamma a multiple of 1/8 up to 64, from exactly rounded multiplications and square roots only (no pow, no FMA).
    private static func powEighths(_ e: Double, _ gamma: Double) throws -> Double {
        let n = gamma * 8
        if !(n == n.rounded(.towardZero) && gamma <= 64) { throw JSError("bondAmount: power curve gamma must be a multiple of 1/8 and at most 64") }
        var r = 1.0
        for _ in 0..<Int(n / 8) { r = r * e }
        let f = Int(n) % 8
        let s1 = e.squareRoot(), s2 = s1.squareRoot(), s3 = s2.squareRoot()
        if f & 4 != 0 { r = r * s1 }
        if f & 2 != 0 { r = r * s2 }
        if f & 1 != 0 { r = r * s3 }
        return r
    }

    private static func curveComponent(_ p: BondPolicy, _ e: Double) throws -> Double {
        let kind: String? = p.curveKind
        if kind == nil || kind! == "linear" { return p.k * e }
        if kind! == "power" {
            if !(fin(p.gamma) && p.gamma >= 1) { throw JSError("bondAmount: power curve requires finite gamma >= 1") }
            return p.k * (try powEighths(e, p.gamma))
        }
        guard p.tiersIsArray, let tiers = p.tiers, !tiers.isEmpty else { throw JSError("bondAmount: piecewise curve requires at least one tier") }
        var acc: Double = 0.0
        var prevUpTo: Double = 0.0
        var prevMarginal: Double = 0.0
        for t in tiers {
            if !(fin(t.upTo) && t.upTo > prevUpTo) && t.upTo != Double.infinity { throw JSError("bondAmount: piecewise tier `upTo` must be strictly increasing") }
            if !(fin(t.marginalK) && t.marginalK >= 0) { throw JSError("bondAmount: piecewise `marginalK` must be a finite number >= 0") }
            if !(t.marginalK >= prevMarginal) { throw JSError("bondAmount: piecewise marginal rates must be non-decreasing (convex)") }
            let width: Double = min(e, t.upTo) - prevUpTo
            if width > 0 { acc += width * t.marginalK }
            prevUpTo = t.upTo
            prevMarginal = t.marginalK
            if e <= t.upTo { break }
        }
        if e > prevUpTo { acc += (e - prevUpTo) * prevMarginal }
        return p.k * acc
    }

    /// The bond for an exposure; a non-finite or non-positive exposure gives the floor.
    public static func bondAmount(_ policy: BondPolicy, _ exposure: Double) throws -> Double {
        let e: Double = (fin(exposure) && exposure > 0) ? exposure : 0.0
        let c: Double = try curveComponent(policy, e)
        // Math.max: NaN wins
        let m: Double = (policy.floor.isNaN || c.isNaN) ? Double.nan : (policy.floor > c ? policy.floor : c)
        return quantizeUp(m)
    }
}
