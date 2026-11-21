import Foundation

/// The separable harm model of an outcome space: a weight per verb and per dimension value.
public protocol PCAIntentHarmModel {
    func verb(_ vs: PCAIntentOmega.VerbSpace) -> Double
    func dim(_ d: PCAIntentOmega.Dim, _ x: JSONValue?) -> Double
    /// Optional closed form of the mean of `dim` over an integer interval; nil when absent.
    func dimMean(_ d: PCAIntentOmega.NumDim, _ lo: Double, _ hi: Double) -> Double?
}

extension PCAIntentHarmModel {
    public func dimMean(_ d: PCAIntentOmega.NumDim, _ lo: Double, _ hi: Double) -> Double? { nil }
}

/// The outcome space (a typed, finite cell grid per verb): numeric dimensions partitioned by cuts, categorical dimensions with an OTHER
/// cell; the product workload measure and the separable harm model. Numbers are binary64 throughout.
public enum PCAIntentOmega {
    public typealias HarmModel = PCAIntentHarmModel

    /// The categorical "any other value" sentinel.
    public static let OTHER = "\u{22A5}"
    public static let EXACT_SPAN = 4096
    public static let HARM_QUADRATURE_PIECES = 1024
    private static let EULER_GAMMA = 0.5772156649015329

    public struct CatValue {
        public let kind: String
        public let value: String
        public init(_ kind: String, _ value: String) { self.kind = kind; self.value = value }
    }

    public struct NumCell {
        public let lo: Double
        public let hi: Double
        public init(_ lo: Double, _ hi: Double) { self.lo = lo; self.hi = hi }
    }

    /// A dimension of a verb space: numeric (`kind == "num"`) or categorical (`"cat"`).
    public class Dim {
        public let kind: String
        public let path: String
        init(_ kind: String, _ path: String) { self.kind = kind; self.path = path }
    }

    public final class NumDim: Dim {
        public let lo: Double
        public let hi: Double
        public let cuts: [Double]
        public let dist: String
        var cells: [NumCell]?
        var total: Double?
        public init(_ path: String, _ lo: Double, _ hi: Double, _ cuts: [Double], _ dist: String) {
            self.lo = lo; self.hi = hi; self.cuts = cuts; self.dist = dist
            super.init("num", path)
        }
    }

    public final class CatDim: Dim {
        public let values: [CatValue]
        public init(_ path: String, _ values: [CatValue]) {
            self.values = values
            super.init("cat", path)
        }
    }

    public final class VerbSpace {
        public let verb: String
        public let reversibility: String
        public var weight: Double
        public let dims: [Dim]
        public init(_ verb: String, _ reversibility: String, _ weight: Double, _ dims: [Dim]) {
            self.verb = verb; self.reversibility = reversibility; self.weight = weight; self.dims = dims
        }
    }

    public final class Omega {
        public let verbs: [VerbSpace]
        public let approximate: [String]
        public init(_ verbs: [VerbSpace], _ approximate: [String]) { self.verbs = verbs; self.approximate = approximate }
    }

    /// A concrete outcome: the verb and one value (a number or a string) per dimension path.
    public struct Outcome {
        public var verb: String
        public var values: JObject
        public init(_ verb: String, _ values: JObject) { self.verb = verb; self.values = values }
    }

    public struct Stats {
        public let mass: Double
        public let harm: Double
        public init(_ mass: Double, _ harm: Double) { self.mass = mass; self.harm = harm }
    }

    public struct Sample {
        public let vs: VerbSpace
        public let o: Outcome
    }

    // ---- JavaScript number helpers ----

    /// `Math.max` / `Math.min` (NaN wins; -0 < +0).
    static func jmax(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return .nan }
        if a == 0 && b == 0 { return a.sign == .minus ? b : a }
        return a > b ? a : b
    }

    static func jmin(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return .nan }
        if a == 0 && b == 0 { return a.sign == .minus ? a : b }
        return a < b ? a : b
    }

    /// A binary64 as a JSON number (an integral safe value is written as an integer).
    static func jn(_ d: Double) -> JSONValue {
        (d.isFinite && d == d.rounded() && abs(d) <= 9007199254740991.0) ? .int(Int64(d)) : .double(d)
    }

    /// Kotlin `Double.toInt()` (saturating, NaN is 0).
    static func toInt(_ d: Double) -> Int {
        if d.isNaN { return 0 }
        if d >= 2147483647.0 { return 2147483647 }
        if d <= -2147483648.0 { return -2147483648 }
        return Int(d)
    }

    /// `Math.round`.
    static func jround(_ x: Double) -> Double {
        if x.isNaN || x.isInfinite { return x }
        let f = x.rounded(.down)
        return x - f >= 0.5 ? f + 1 : f
    }

    // ---- JSON <-> typed ----

    public static func dbl(_ o: JSONValue?) throws -> Double {
        guard let d = IV.num(o) else { throw JSError("not a number") }
        return d
    }

    public static func obj(_ o: JSONValue?) throws -> JObject {
        guard let m = o?.asObject else { throw JSError("not an object") }
        return m
    }

    public static func arr(_ o: JSONValue?) throws -> [JSONValue] {
        guard let a = o?.asArray else { throw JSError("not an array") }
        return a
    }

    public static func isNumber(_ o: JSONValue?) -> Bool { IV.num(o) != nil }

    /// A required string member (a cast failure in the reference).
    static func str(_ o: JSONValue?) throws -> String {
        guard let s = o?.asString else { throw JSError("not a string") }
        return s
    }

    public static func dimFromJson(_ o: JSONValue?) throws -> Dim {
        let m = try obj(o)
        let path = try str(m[JKey("path")])
        if IV.same(m[JKey("kind")]?.asString, "num") {
            let cs = try arr(m[JKey("cuts")])
            var cuts: [Double] = []
            for c in cs { cuts.append(try dbl(c)) }
            return NumDim(path, try dbl(m[JKey("lo")]), try dbl(m[JKey("hi")]), cuts, try str(m[JKey("dist")]))
        }
        var vs: [CatValue] = []
        for x in try arr(m[JKey("values")]) {
            let xm = try obj(x)
            vs.append(CatValue(try str(xm[JKey("kind")]), try str(xm[JKey("value")])))
        }
        return CatDim(path, vs)
    }

    public static func catValueJson(_ v: CatValue) -> JSONValue {
        .object([JKey("kind"): .string(v.kind), JKey("value"): .string(v.value)])
    }

    public static func dimToJson(_ d: Dim) -> JSONValue {
        var m = JObject()
        m[JKey("kind")] = .string(d.kind)
        m[JKey("path")] = .string(d.path)
        if let n = d as? NumDim {
            m[JKey("lo")] = jn(n.lo)
            m[JKey("hi")] = jn(n.hi)
            m[JKey("cuts")] = .array(n.cuts.map { jn($0) })
            m[JKey("dist")] = .string(n.dist)
        } else if let c = d as? CatDim {
            m[JKey("values")] = .array(c.values.map { catValueJson($0) })
        }
        return .object(m)
    }

    public static func verbSpaceFromJson(_ o: JSONValue?) throws -> VerbSpace {
        let m = try obj(o)
        var dims: [Dim] = []
        for d in try arr(m[JKey("dims")]) { dims.append(try dimFromJson(d)) }
        return VerbSpace(try str(m[JKey("verb")]), try str(m[JKey("reversibility")]), try dbl(m[JKey("weight")]), dims)
    }

    public static func verbSpaceToJson(_ vs: VerbSpace) -> JSONValue {
        var m = JObject()
        m[JKey("verb")] = .string(vs.verb)
        m[JKey("reversibility")] = .string(vs.reversibility)
        m[JKey("weight")] = jn(vs.weight)
        m[JKey("dims")] = .array(vs.dims.map { dimToJson($0) })
        return .object(m)
    }

    public static func omegaFromJson(_ o: JSONValue?) throws -> Omega {
        let m = try obj(o)
        var vs: [VerbSpace] = []
        for v in try arr(m[JKey("verbs")]) { vs.append(try verbSpaceFromJson(v)) }
        var ap: [String] = []
        if let a = m[JKey("approximate")]?.asArray { for x in a { ap.append(try str(x)) } }
        return Omega(vs, ap)
    }

    public static func omegaToJson(_ om: Omega) -> JSONValue {
        var m = JObject()
        m[JKey("v")] = .int(1)
        m[JKey("verbs")] = .array(om.verbs.map { verbSpaceToJson($0) })
        m[JKey("approximate")] = .array(om.approximate.map { .string($0) })
        return .object(m)
    }

    public static func outcomeFromJson(_ o: JSONValue?) throws -> Outcome {
        let m = try obj(o)
        var vals = JObject()
        for (k, v) in try obj(m[JKey("values")]) {
            if let d = IV.num(v) { vals[k] = .double(d) } else { vals[k] = v }
        }
        return Outcome(try str(m[JKey("verb")]), vals)
    }

    public static func outcomeToJson(_ o: Outcome) -> JSONValue {
        var vals = JObject()
        for (k, v) in o.values {
            if let d = IV.num(v) { vals[k] = jn(d) } else { vals[k] = v }
        }
        return .object([JKey("verb"): .string(o.verb), JKey("values"): .object(vals)])
    }

    // ---- cells ----

    public static func numCells(_ d: NumDim) -> [NumCell] {
        if let c = d.cells { return c }
        var out: [NumCell] = []
        var cur = d.lo
        for c in d.cuts {
            if c < d.lo || c > d.hi { continue }
            if cur <= c - 1 { out.append(NumCell(cur, c - 1)) }
            out.append(NumCell(c, c))
            cur = c + 1
        }
        if cur <= d.hi { out.append(NumCell(cur, d.hi)) }
        d.cells = out
        return out
    }

    public static func cellCount(_ d: Dim) -> Int {
        if let n = d as? NumDim { return numCells(n).count }
        return (d as? CatDim)?.values.count ?? 0
    }

    public static func verbCellCount(_ vs: VerbSpace) -> Double {
        var n = 1.0
        for d in vs.dims { n *= Double(cellCount(d)) }
        return n
    }

    public static func decodeCell(_ vs: VerbSpace, _ flat0: Double) -> [Int] {
        var flat = flat0
        var idx = [Int](repeating: 0, count: vs.dims.count)
        var i = vs.dims.count - 1
        while i >= 0 {
            let n = Double(cellCount(vs.dims[i]))
            idx[i] = toInt(fmod(flat, n))
            flat = (flat / n).rounded(.down)
            i -= 1
        }
        return idx
    }

    public static func encodeCell(_ vs: VerbSpace, _ idx: [Int]) -> Double {
        var flat = 0.0
        for i in 0..<vs.dims.count { flat = flat * Double(cellCount(vs.dims[i])) + Double(idx[i]) }
        return flat
    }

    /// Which cell a concrete string falls in (exact, then longest prefix, then OTHER).
    public static func catCellOf(_ d: CatDim, _ s: String) -> Int {
        var best = -1
        var bestLen = -1
        for i in 0..<d.values.count {
            let v = d.values[i]
            if v.kind == "exact" && IV.same(v.value, s) { return i }
            if v.kind == "prefix" && IV.startsWith(s, v.value) && v.value.utf16.count > bestLen {
                best = i
                bestLen = v.value.utf16.count
            }
        }
        if best >= 0 { return best }
        for i in 0..<d.values.count where d.values[i].kind == "other" { return i }
        return -1
    }

    /// The cell a value falls in, or -1 outside the dimension's domain or type.
    public static func cellOfValue(_ d: Dim, _ x: JSONValue?) -> Int {
        if let n = d as? NumDim {
            guard let v = IV.num(x), v.isFinite else { return -1 }
            let cells = numCells(n)
            for i in 0..<cells.count where v >= cells[i].lo && v <= cells[i].hi { return i }
            return -1
        }
        guard let s = x?.asString, let c = d as? CatDim else { return -1 }
        return catCellOf(c, s)
    }

    /// Per-dimension cell indices of an outcome, or nil when a value lies outside the space.
    public static func cellOf(_ vs: VerbSpace, _ o: Outcome) -> [Int]? {
        var idx = [Int](repeating: 0, count: vs.dims.count)
        for k in 0..<idx.count {
            let d = vs.dims[k]
            let i = cellOfValue(d, o.values[JKey(d.path)])
            if i < 0 { return nil }
            idx[k] = i
        }
        return idx
    }

    public static func catRep(_ d: CatDim, _ i: Int) -> String {
        let v = d.values[i]
        if v.kind == "exact" { return v.value }
        let base = v.kind == "prefix" ? v.value + "x" : "other"
        for k in 0..<64 {
            let s = base + (k == 0 ? "" : String(k))
            if catCellOf(d, s) == i { return s }
        }
        return base
    }

    /// The question point of a numeric cell (a boundary witness).
    public static func numRep(_ d: NumDim, _ i: Int) -> Double {
        let c = numCells(d)[i]
        return i > 0 ? c.lo : c.hi
    }

    public static func repValue(_ d: Dim, _ i: Int) -> JSONValue {
        if let n = d as? NumDim { return .double(numRep(n, i)) }
        return .string(catRep(d as! CatDim, i))
    }

    public static func cellRep(_ vs: VerbSpace, _ idx: [Int]) -> Outcome {
        var values = JObject()
        for i in 0..<vs.dims.count { values[JKey(vs.dims[i].path)] = repValue(vs.dims[i], idx[i]) }
        return Outcome(vs.verb, values)
    }

    // ---- workload and harm ----

    private static func logUniform(_ d: NumDim) -> Bool { d.dist == "loguniform" && d.lo >= 0 }

    static func pointWeight(_ d: NumDim, _ x: Double) -> Double { logUniform(d) ? 1 / (x + 1) : 1.0 }

    /// `/(^|\.)amount$/` on the path.
    static func linearAmount(_ d: Dim) -> Bool {
        guard d is NumDim else { return false }
        return IV.same(d.path, "amount") || IV.endsWith(d.path, ".amount")
    }

    private struct DefaultHarm: PCAIntentHarmModel {
        func verb(_ vs: PCAIntentOmega.VerbSpace) -> Double {
            vs.reversibility == "irreversible" ? 10.0 : (vs.reversibility == "rate_limited" ? 3.0 : 1.0)
        }

        func dim(_ d: PCAIntentOmega.Dim, _ x: JSONValue?) -> Double {
            if PCAIntentOmega.linearAmount(d), let v = IV.num(x) { return 1 + PCAIntentOmega.jmax(0.0, v) / 100 }
            return 1.0
        }

        func dimMean(_ d: PCAIntentOmega.NumDim, _ lo: Double, _ hi: Double) -> Double? {
            if PCAIntentOmega.linearAmount(d) {
                return 1 + PCAIntentOmega.jmax(0.0, PCAIntentOmega.intervalMeanX(d, PCAIntentOmega.jmax(lo, 0.0), hi, lo)) / 100
            }
            return 1.0
        }
    }

    /// Irreversible 10, rate-limited 3, reversible 1; amounts scale as 1 + x/100.
    public static let DEFAULT_HARM: PCAIntentHarmModel = DefaultHarm()

    public static func harmMax(_ omega: Omega, _ harm: PCAIntentHarmModel = DEFAULT_HARM) -> Double {
        var m = 0.0
        for vs in omega.verbs {
            var f = harm.verb(vs)
            for d in vs.dims {
                if let n = d as? NumDim {
                    f *= jmax(harm.dim(d, .double(n.lo)), harm.dim(d, .double(n.hi)))
                } else if let c = d as? CatDim {
                    var mx = -Double.infinity
                    for i in 0..<c.values.count { mx = jmax(mx, harm.dim(d, .string(catRep(c, i)))) }
                    f *= mx
                }
            }
            m = jmax(m, f)
        }
        return m
    }

    static func harmonic(_ n: Double) -> Double {
        if n <= 0 { return 0.0 }
        if n <= Double(EXACT_SPAN) {
            var s = 0.0
            var k = n
            while k >= 1 {
                s += 1 / k
                k -= 1
            }
            return s
        }
        let n2 = n * n
        return FdLibm.log(n) + EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2)
    }

    /// The sum of the point weight over the integers a..b (0 for an empty interval).
    public static func intervalWeight(_ d: NumDim, _ a: Double, _ b: Double) -> Double {
        if b < a { return 0.0 }
        if !logUniform(d) { return b - a + 1 }
        if b - a + 1 <= Double(EXACT_SPAN) {
            var s = 0.0
            var x = b
            while x >= a {
                s += 1 / (x + 1)
                x -= 1
            }
            return s
        }
        return harmonic(b + 1) - harmonic(a)
    }

    static func intervalFirstMoment(_ d: NumDim, _ a: Double, _ b: Double) -> Double {
        if b < a { return 0.0 }
        if !logUniform(d) { return ((a + b) * (b - a + 1)) / 2 }
        return b - a + 1 - intervalWeight(d, a, b)
    }

    static func intervalMeanX(_ d: NumDim, _ a: Double, _ b: Double, _ cellLo: Double) -> Double {
        let whole = intervalWeight(d, cellLo, b)
        return whole > 0 ? intervalFirstMoment(d, a, b) / whole : 0.0
    }

    private static func intervalHarm(_ d: NumDim, _ a: Double, _ b: Double, _ harm: PCAIntentHarmModel) -> Double {
        if let mean = harm.dimMean(d, a, b) { return mean }
        let n = b - a + 1
        let wTot = intervalWeight(d, a, b)
        if !(wTot > 0) { return harm.dim(d, .double(a)) }
        if n <= Double(EXACT_SPAN) {
            var s = 0.0
            var x = a
            while x <= b {
                s += pointWeight(d, x) * harm.dim(d, .double(x))
                x += 1
            }
            return s / wTot
        }
        var s = 0.0
        let pieces = Double(HARM_QUADRATURE_PIECES)
        for i in 0..<HARM_QUADRATURE_PIECES {
            let pa = a + ((Double(i) * n) / pieces).rounded(.down)
            let pb = a + ((Double(i + 1) * n) / pieces).rounded(.down) - 1
            if pb < pa { continue }
            let w = intervalWeight(d, pa, pb)
            s += w * harm.dim(d, .double(jround((pa + pb) / 2)))
        }
        return s / wTot
    }

    private static func dimTotal(_ d: NumDim) -> Double {
        let t = d.total ?? intervalWeight(d, d.lo, d.hi)
        d.total = t
        return t
    }

    public static func dimCellStats(_ d: Dim, _ i: Int, _ harm: PCAIntentHarmModel = DEFAULT_HARM) -> Stats {
        if let c = d as? CatDim { return Stats(1.0 / Double(c.values.count), harm.dim(c, .string(catRep(c, i)))) }
        let n = d as! NumDim
        let c = numCells(n)[i]
        let wm = intervalWeight(n, c.lo, c.hi)
        return Stats(wm / dimTotal(n), wm > 0 ? intervalHarm(n, c.lo, c.hi, harm) : harm.dim(n, .double(c.lo)))
    }

    private static func quantileValue(_ d: NumDim, _ target: Double) -> Double {
        var acc = 0.0
        let cells = numCells(d)
        for ci in 0..<cells.count {
            let c = cells[ci]
            let w = intervalWeight(d, c.lo, c.hi)
            if target < acc + w || ci == cells.count - 1 {
                var r = target - acc
                if c.hi - c.lo + 1 <= Double(EXACT_SPAN) {
                    var x = c.lo
                    while x < c.hi {
                        r -= pointWeight(d, x)
                        if r < 0 { return x }
                        x += 1
                    }
                    return c.hi
                }
                if !logUniform(d) { return jmin(c.hi, c.lo + r.rounded(.down)) }
                let x = ((c.lo + 1) * FdLibm.exp(r) - 1).rounded(.down)
                return jmax(c.lo, jmin(c.hi, x))
            }
            acc += w
        }
        return d.hi
    }

    public static func cellStats(_ vs: VerbSpace, _ idx: [Int], _ harm: PCAIntentHarmModel = DEFAULT_HARM) -> Stats {
        var mass = vs.weight
        var h = harm.verb(vs)
        for k in 0..<vs.dims.count {
            let s = dimCellStats(vs.dims[k], idx[k], harm)
            mass *= s.mass
            h *= s.harm
        }
        return Stats(mass, h)
    }

    public static func harmOf(_ vs: VerbSpace, _ o: Outcome, _ harm: PCAIntentHarmModel = DEFAULT_HARM) -> Double {
        var h = harm.verb(vs)
        for d in vs.dims { h *= harm.dim(d, o.values[JKey(d.path)]) }
        return h
    }

    /// mulberry32, so every Monte Carlo number is reproducible.
    public static func rng(_ seed: Double) -> () -> Double {
        var lng: Int64 = 0
        if seed.isNaN { lng = 0 }
        else if seed >= 9.223372036854775807e18 { lng = Int64.max }
        else if seed <= -9.223372036854775808e18 { lng = Int64.min }
        else { lng = Int64(seed) }
        var a = Int32(truncatingIfNeeded: lng)
        return {
            a = a &+ 0x6d2b79f5
            var t: Int32 = a
            let s15: Int32 = Int32(bitPattern: UInt32(bitPattern: t) >> 15)
            t = (t ^ s15) &* (t | 1)
            let s7: Int32 = Int32(bitPattern: UInt32(bitPattern: t) >> 7)
            t = t ^ (t &+ ((t ^ s7) &* (t | 61)))
            let s14: Int32 = Int32(bitPattern: UInt32(bitPattern: t) >> 14)
            let r: UInt32 = UInt32(bitPattern: t ^ s14)
            return Double(r) / 4294967296.0
        }
    }

    /// Draw an outcome from the workload.
    public static func sampleOutcome(_ omega: Omega, _ rand: () -> Double) -> Sample {
        var u = rand()
        var vs = omega.verbs[omega.verbs.count - 1]
        for v in omega.verbs {
            if u < v.weight {
                vs = v
                break
            }
            u -= v.weight
        }
        var values = JObject()
        for d in vs.dims {
            if let c = d as? CatDim {
                let k = toInt((rand() * Double(c.values.count)).rounded(.down))
                values[JKey(d.path)] = .string(catRep(c, min(c.values.count - 1, k)))
                continue
            }
            let n = d as! NumDim
            values[JKey(d.path)] = .double(quantileValue(n, rand() * dimTotal(n)))
        }
        return Sample(vs: vs, o: Outcome(vs.verb, values))
    }

    public static func verbSpace(_ omega: Omega, _ verb: String?) -> VerbSpace? {
        guard let v = verb else { return nil }
        return omega.verbs.first { IV.same($0.verb, v) }
    }

    /// `Double.compare` order (-0 before 0, NaN last).
    static func sortedNums(_ xs: [Double]) -> [Double] {
        xs.sorted { a, b in
            if a.isNaN { return false }
            if b.isNaN { return true }
            if a == 0 && b == 0 { return a.sign == .minus && b.sign == .plus }
            return a < b
        }
    }
}
