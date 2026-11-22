import Foundation

/// JavaScript value helpers shared by the wallet modules (numbers are binary64, strings compare by code point).
enum WJ {
    static func i(_ n: Int) -> JSONValue { .int(Int64(n)) }
    static func d(_ x: Double) -> JSONValue { .double(x) }
    static func s(_ x: String) -> JSONValue { .string(x) }
    static func arr(_ xs: [Int]) -> JSONValue { .array(xs.map { .int(Int64($0)) }) }
    static func obj(_ pairs: [(String, JSONValue)]) -> JSONValue {
        var o = JObject()
        for (k, v) in pairs { o[JKey(k)] = v }
        return .object(o)
    }

    /// `typeof v === 'number'`.
    static func isNumber(_ v: JSONValue?) -> Bool { IV.num(v) != nil }
    /// `Number.isFinite(v)` on a number value.
    static func isFiniteNumber(_ v: JSONValue?) -> Bool { IV.num(v).map { $0.isFinite } ?? false }
    /// A finite integer-valued number (accepts -0).
    static func isIntegral(_ v: JSONValue?) -> Bool { IV.num(v).map { $0.isFinite && $0.rounded(.towardZero) == $0 } ?? false }
    /// `Number.isSafeInteger` (accepts -0).
    static func isSafeInt(_ v: JSONValue?) -> Bool { IV.safe(v) != nil }
    /// The wire `isInt`: a safe integer that is not -0.
    static func isInt(_ v: JSONValue?) -> Bool { IV.int(v) != nil }
    static func negZero(_ v: JSONValue?) -> Bool { IV.num(v).map { IV.isNegZero($0) } ?? false }
    static func numEq(_ v: JSONValue?, _ n: Double) -> Bool { IV.num(v) == n }
    /// `v === s` for a string.
    static func isStr(_ v: JSONValue?, _ s: String) -> Bool { IV.same(v?.asString, s) }

    /// `JSON.parse(JSON.stringify(v))`: -0 becomes 0, an integral float an integer.
    static func plain(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .double(x):
            if x.isFinite, x.rounded(.towardZero) == x, abs(x) < 9.2e18 { return .int(Int64(x)) }
            return v
        case let .array(a): return .array(a.map(plain))
        case let .object(o): return .object(o.mapValues(plain))
        default: return v
        }
    }

    /// `hashCanonical(v)` (strict canonical form); throws where the reference throws.
    static func hash(_ v: JSONValue) throws -> String {
        guard let h = IV.strictHash(v) else { throw JSError("canonicalize: value is outside the strict JSON profile") }
        return h
    }

    /// `utf8(domain) || canonicalBytesStrict(body)`.
    static func message(_ domain: String, _ v: JSONValue) throws -> [UInt8] {
        guard let m = IV.message(domain, v) else { throw JSError("canonicalize: value is outside the strict JSON profile") }
        return m
    }

    /// `Object.entries(v)`: objects in canonical key order (a parsed object has no insertion order), arrays and strings by index;
    /// null / undefined throw.
    static func entries(_ v: JSONValue?) throws -> [(String, JSONValue)] {
        switch v {
        case let .object(o)?:
            let idx = o.keys.compactMap { k in JS.indexKey(k.s).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
            let rest = o.keys.filter { JS.indexKey($0.s) == nil }.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }
            return (idx + rest).map { ($0.s, o[$0]!) }
        case let .array(a)?: return a.enumerated().map { (String($0.offset), $0.element) }
        case let .string(s)?: return s.unicodeScalars.enumerated().map { (String($0.offset), .string(String($0.element))) }
        case nil, .null?: throw JSError("Cannot convert undefined or null to object")
        default: return []
        }
    }

    /// UTF-16 code-unit order (the default JS sort).
    static func u16Less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    /// `s.slice(start, end)` in UTF-16 code units.
    static func u16slice(_ s: String, _ start: Int, _ end: Int? = nil) -> String {
        let u = Array(s.utf16)
        let e = min(end ?? u.count, u.count)
        let b = max(0, start)
        return b >= e ? "" : String(decoding: u[b..<e], as: UTF16.self)
    }

    /// `Math.round`.
    static func jsRound(_ x: Double) -> Double {
        let f = x.rounded(.down)
        return x - f >= 0.5 ? f + 1 : f
    }
}

/// One dimension of a verb's outcome space (the wallet's own, private port of the reference's Omega).
public struct WalletDim {
    var kind: String
    var path: String
    var lo = 0
    var hi = 0
    var cuts: [Int] = []
    var dist: String?
    var values: [(kind: String, value: String)] = []

    var isNum: Bool { kind == "num" }
    var logUniform: Bool { dist == "loguniform" && lo >= 0 }
}

extension WalletDim {
    /// The typed outcome-space dimension this view stands for (PCAIntentOmega is the one implementation of the cell arithmetic).
    var numCore: PCAIntentOmega.NumDim { PCAIntentOmega.NumDim(path, Double(lo), Double(hi), cuts.map { Double($0) }, dist ?? "") }
    var catCore: PCAIntentOmega.CatDim { PCAIntentOmega.CatDim(path, values.map { PCAIntentOmega.CatValue($0.kind, $0.value) }) }
}

public struct WalletVerb {
    var verb: String
    var reversibility: String
    var weight: Double
    var dims: [WalletDim]
}

public struct WalletOmega {
    var verbs: [WalletVerb]

    func verb(_ name: String) -> WalletVerb? { verbs.first { IV.same($0.verb, name) } }

    /// Reads an outcome space; throws on anything malformed (the corpus and every caller pass a well-formed space).
    public init(_ v: JSONValue?) throws {
        guard let o = v?.asObject, let vs = o["verbs"]?.asArray else { throw JSError("omega: not an outcome space") }
        var out: [WalletVerb] = []
        for x in vs {
            guard let vo = x.asObject, let name = vo["verb"]?.asString, let w = IV.num(vo["weight"]), let ds = vo["dims"]?.asArray else { throw JSError("omega: bad verb") }
            var dims: [WalletDim] = []
            for dv in ds {
                guard let d = dv.asObject, let kind = d["kind"]?.asString, let path = d["path"]?.asString else { throw JSError("omega: bad dim") }
                var dim = WalletDim(kind: kind, path: path)
                if kind == "num" {
                    guard let lo = IV.int(d["lo"]), let hi = IV.int(d["hi"]), let cuts = d["cuts"]?.asArray else { throw JSError("omega: bad numeric dim") }
                    dim.lo = Int(lo); dim.hi = Int(hi)
                    dim.cuts = try cuts.map { guard let c = IV.int($0) else { throw JSError("omega: bad cut") }; return Int(c) }
                    dim.dist = d["dist"]?.asString
                } else {
                    guard let vals = d["values"]?.asArray else { throw JSError("omega: bad categorical dim") }
                    dim.values = try vals.map {
                        guard let k = $0.get("kind")?.asString, let s = $0.get("value")?.asString else { throw JSError("omega: bad value") }
                        return (k, s)
                    }
                }
                dims.append(dim)
            }
            out.append(WalletVerb(verb: name, reversibility: vo["reversibility"]?.asString ?? "", weight: w, dims: dims))
        }
        verbs = out
    }
}

/// The wallet's outcome-space arithmetic, the separable harm model and the exact Clopper-Pearson bound. Floats follow the reference
/// operation by operation (IEEE-754 doubles).
enum WalletOmegaMath {
    static let OTHER = "\u{22A5}"
    static let EXACT_SPAN = 4096
    static let EULER_GAMMA = 0.5772156649015329

    // ---- cells ----

    static func numCells(_ d: WalletDim) -> [(lo: Int, hi: Int)] {
        PCAIntentOmega.numCells(d.numCore).map { (Int($0.lo), Int($0.hi)) }
    }

    static func cellCount(_ d: WalletDim) -> Int { d.isNum ? numCells(d).count : d.values.count }

    static func verbCellCount(_ vs: WalletVerb) -> Int { vs.dims.reduce(1) { $0 * cellCount($1) } }

    static func decodeCell(_ vs: WalletVerb, _ flat: Int) -> [Int] {
        var idx = [Int](repeating: 0, count: vs.dims.count)
        var f = flat
        var i = vs.dims.count - 1
        while i >= 0 {
            let n = cellCount(vs.dims[i])
            idx[i] = f % n
            f /= n
            i -= 1
        }
        return idx
    }

    static func catCellOf(_ d: WalletDim, _ s: String) -> Int { PCAIntentOmega.catCellOf(d.catCore, s) }

    static func cellOfValue(_ d: WalletDim, _ x: JSONValue?) -> Int {
        if d.isNum {
            guard let n = IV.num(x), n.isFinite else { return -1 }
            for (i, c) in numCells(d).enumerated() where n >= Double(c.lo) && n <= Double(c.hi) { return i }
            return -1
        }
        guard let s = x?.asString else { return -1 }
        return catCellOf(d, s)
    }

    /// The cell of an outcome `{verb, values}`, or nil outside the space.
    static func cellOf(_ vs: WalletVerb, values: JSONValue?) -> [Int]? {
        var idx: [Int] = []
        for d in vs.dims {
            let i = cellOfValue(d, values?.asObject?[JKey(d.path)])
            if i < 0 { return nil }
            idx.append(i)
        }
        return idx
    }

    static func catRep(_ d: WalletDim, _ i: Int) -> String { PCAIntentOmega.catRep(d.catCore, i) }

    static func numRep(_ d: WalletDim, _ i: Int) -> Int {
        let c = numCells(d)[i]
        return i > 0 ? c.lo : c.hi
    }

    static func repValue(_ d: WalletDim, _ i: Int) -> JSONValue { d.isNum ? WJ.i(numRep(d, i)) : .string(catRep(d, i)) }

    static func cellRep(_ vs: WalletVerb, _ idx: [Int]) -> JSONValue {
        var values = JObject()
        for (i, d) in vs.dims.enumerated() { values[JKey(d.path)] = repValue(d, idx[i]) }
        return WJ.obj([("verb", .string(vs.verb)), ("values", .object(values))])
    }

    static func labelOf(_ path: String) -> String {
        if IV.same(path, "action.resource") { return "resource" }
        let last = path.unicodeScalars.split(separator: ".", omittingEmptySubsequences: false).last.map { IV.text($0) } ?? path
        return last.replacingOccurrences(of: "_", with: " ")
    }

    // ---- workload and harm ----

    static func harmonic(_ n: Int) -> Double { PCAIntentOmega.harmonic(Double(n)) }

    static func intervalWeight(_ d: WalletDim, _ a: Int, _ b: Int) -> Double { PCAIntentOmega.intervalWeight(d.numCore, Double(a), Double(b)) }

    static func firstMoment(_ d: WalletDim, _ a: Int, _ b: Int) -> Double { PCAIntentOmega.intervalFirstMoment(d.numCore, Double(a), Double(b)) }

    static func intervalMeanX(_ d: WalletDim, _ a: Int, _ b: Int, _ cellLo: Int) -> Double {
        PCAIntentOmega.intervalMeanX(d.numCore, Double(a), Double(b), Double(cellLo))
    }

    /// `(^|\.)amount$` on a numeric dimension.
    static func linearAmount(_ d: WalletDim) -> Bool { PCAIntentOmega.linearAmount(d.isNum ? d.numCore : d.catCore) }

    /// h_v, g_d (at a concrete value; nil for a categorical representative) and the closed-form mean over an interval.
    struct HarmModel {
        var verb: (WalletVerb) -> Double
        var dim: (WalletDim, Double?) -> Double
        var dimMean: ((WalletDim, Int, Int) -> Double)?
    }

    static let DEFAULT_HARM = HarmModel(
        verb: { vs in vs.reversibility == "irreversible" ? 10 : vs.reversibility == "rate_limited" ? 3 : 1 },
        dim: { d, x in
            if linearAmount(d), let x = x { return 1 + max(0, x) / 100 }
            return 1
        },
        dimMean: { d, lo, hi in linearAmount(d) ? 1 + max(0, intervalMeanX(d, max(lo, 0), hi, lo)) / 100 : 1 })

    static func pointWeight(_ d: WalletDim, _ x: Int) -> Double { PCAIntentOmega.pointWeight(d.numCore, Double(x)) }

    static func intervalHarm(_ d: WalletDim, _ a: Int, _ b: Int, _ harm: HarmModel) -> Double {
        if let m = harm.dimMean { return m(d, a, b) }
        let n = b - a + 1
        let wTot = intervalWeight(d, a, b)
        if !(wTot > 0) { return harm.dim(d, Double(a)) }
        if n <= EXACT_SPAN {
            var s = 0.0
            for x in a...b { s += pointWeight(d, x) * harm.dim(d, Double(x)) }
            return s / wTot
        }
        var s = 0.0
        for i in 0..<1024 {
            let pa = a + (i * n) / 1024
            let pb = a + ((i + 1) * n) / 1024 - 1
            if pb < pa { continue }
            let w = intervalWeight(d, pa, pb)
            s += w * harm.dim(d, (Double(pa + pb) / 2 + 0.5).rounded(.down))
        }
        return s / wTot
    }

    static func dimCellStats(_ d: WalletDim, _ i: Int, _ harm: HarmModel) -> (mass: Double, harm: Double) {
        if !d.isNum { return (1 / Double(d.values.count), harm.dim(d, nil)) }
        let c = numCells(d)[i]
        let wm = intervalWeight(d, c.lo, c.hi)
        let total = intervalWeight(d, d.lo, d.hi)
        return (wm / total, wm > 0 ? intervalHarm(d, c.lo, c.hi, harm) : harm.dim(d, Double(c.lo)))
    }

    /// Exact mu(cell) and E[h | cell] of a whole cell (product measure, separable harm).
    static func cellStats(_ vs: WalletVerb, _ idx: [Int], _ harm: HarmModel = DEFAULT_HARM) -> (mass: Double, harm: Double) {
        var mass = vs.weight
        var h = harm.verb(vs)
        for (k, d) in vs.dims.enumerated() {
            let s = dimCellStats(d, idx[k], harm)
            mass *= s.mass
            h *= s.harm
        }
        return (mass, h)
    }

    // ---- exact Clopper-Pearson upper bound: PCAIntentStats is the one implementation ----

    static let GRID_BITS = PCAIntentStats.GRID_BITS
    static let A = PCAIntentStats.A
    static let TOL_UNITS = PCAIntentStats.TOL_UNITS

    static func logFactorials(_ n: Int) -> [Double] { PCAIntentStats.logFactorials(n) }
    static func binomialCdf(_ k: Int, _ n: Int, _ p: Double, _ lf: [Double]) -> Double { PCAIntentStats.binomialCdf(k, n, p, lf) }
    static func power(_ base: BigUInt, _ e: Int) -> BigUInt { PCAIntentStats.power(base, e) }

    /// One-sided Clopper-Pearson upper bound after k successes in n, rounded outward on the 2^-52 grid (exact integer arithmetic).
    static func clopperPearsonUpper(_ kv: JSONValue?, _ nv: JSONValue?, _ alphaV: JSONValue?) throws -> Double {
        guard let kd = IV.num(kv), let nd = IV.num(nv), let alpha = IV.num(alphaV) else {
            if IV.num(alphaV) == nil, IV.num(kv) != nil, IV.num(nv) != nil { throw JSError("clopperPearsonUpper: alpha must be in (0, 1)") }
            throw JSError("clopperPearsonUpper: need integers 0 <= k <= n")
        }
        return try PCAIntentStats.clopperPearsonUpper(kd, nd, alpha)
    }
}
