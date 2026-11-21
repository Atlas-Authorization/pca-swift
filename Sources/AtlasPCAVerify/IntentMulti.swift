import Foundation

/// The joint-grant rules of multi-principal intent (unanimity, quorum(k), weighted with a threshold, plus vetoers), the exact joint
/// acceptance probability, and the common refinement of several outcome spaces. A rule is a JSON tree {kind, vetoers?, k?, weights?,
/// threshold?}; an outcome space is the JSON object `{v, verbs, approximate}` an Intent Map carries (see `PCAIntentMap.omegaFromJSON`).
public enum PCAIntentMulti {
    /// A rule in normal form: integer weights, an integer threshold, per-principal veto flags.
    public struct NormalRule {
        public var weights: [Double]
        public var threshold: Double
        public var veto: [Bool]

        public init(weights: [Double], threshold: Double, veto: [Bool]) {
            self.weights = weights
            self.threshold = threshold
            self.veto = veto
        }

        public func toJson() -> JSONValue {
            return .object([
                "weights": .array(weights.map { PCAIntentMulti.n($0) }),
                "threshold": PCAIntentMulti.n(threshold),
                "veto": .array(veto.map { JSONValue.bool($0) }),
            ])
        }

        public static func fromJson(_ o: JSONValue?) throws -> NormalRule {
            guard let m = o?.asObject, let w = m[JKey("weights")]?.asArray, let v = m[JKey("veto")]?.asArray else { throw JSError("pca-intent: not a normal rule") }
            var ws: [Double] = []
            for x in w {
                guard let d = IV.num(x) else { throw JSError("pca-intent: not a number") }
                ws.append(d)
            }
            guard let t = IV.num(m[JKey("threshold")]) else { throw JSError("pca-intent: not a number") }
            var vs: [Bool] = []
            for x in v {
                guard case let .bool(b) = x else { throw JSError("pca-intent: not a boolean") }
                vs.append(b)
            }
            return NormalRule(weights: ws, threshold: t, veto: vs)
        }
    }

    static func n(_ x: Double) -> JSONValue { return WJ.plain(.double(x)) }

    private static func isInteger(_ o: JSONValue?) -> Bool {
        guard let d = IV.num(o) else { return false }
        return d.isFinite && d == d.rounded(.toNearestOrEven)
    }

    /// `normalizeRule`: throws on an unknown vetoer, a bad quorum k, a missing or non-integer weight, or a bad threshold.
    public static func normalizeRule(_ rule: JSONValue?, _ refs: [String]) throws -> NormalRule {
        var vetoers: [String] = []
        if let vr = rule?.get("vetoers")?.asArray {
            for v in vr {
                let s = JS.toString(v)
                if !IV.contains(vetoers, s) { vetoers.append(s) }
            }
        }
        for v in vetoers where !IV.contains(refs, v) { throw JSError("aggregateIntentMaps: vetoer \(v) is not one of the maps") }
        let veto: [Bool] = refs.map { IV.contains(vetoers, $0) }
        let ones: [Double] = refs.map { _ in 1.0 }
        let kind = rule?.get("kind")?.asString
        if let k = kind, IV.same(k, "unanimity") { return NormalRule(weights: ones, threshold: Double(refs.count), veto: veto) }
        if let k = kind, IV.same(k, "quorum") {
            let kv = rule?.get("k")
            guard isInteger(kv), let kd = IV.num(kv), kd >= 1, kd <= Double(refs.count) else {
                throw JSError("aggregateIntentMaps: quorum k must be an integer in [1, \(refs.count)]")
            }
            return NormalRule(weights: ones, threshold: kd, veto: veto)
        }
        guard let wm = rule?.get("weights")?.asObject else { throw JSError("Cannot read properties of undefined") }
        var weights: [Double] = []
        for r in refs {
            let w = wm[JKey(r)]
            guard isInteger(w), let wd = IV.num(w), wd >= 0 else { throw JSError("aggregateIntentMaps: every principal needs a non-negative integer weight") }
            weights.append(wd)
        }
        var total = 0.0
        for w in weights { total += w }
        let t = rule?.get("threshold")
        guard isInteger(t), let td = IV.num(t), td >= 1, td <= total else {
            throw JSError("aggregateIntentMaps: threshold must be an integer in [1, \(JS.number(total))]")
        }
        return NormalRule(weights: weights, threshold: td, veto: veto)
    }

    /// Principals that bound the joint grant: explicit vetoers plus implicit ones (threshold > W - w_i).
    public static func effectiveVetoers(_ rule: JSONValue?, _ refs: [String]) throws -> [String] {
        let nr = try normalizeRule(rule, refs)
        var total = 0.0
        for w in nr.weights { total += w }
        var out: [String] = []
        for i in 0..<refs.count where nr.veto[i] || nr.threshold > total - nr.weights[i] { out.append(refs[i]) }
        return out
    }

    /// Does the rule admit, given which principals admit (vetoers must; the admitting weight must reach the threshold)?
    public static func ruleAdmits(_ nr: NormalRule, _ ins: [Bool]) -> Bool {
        var s = 0.0
        for i in 0..<ins.count {
            if nr.veto[i] && !ins[i] { return false }
            if ins[i] { s += nr.weights[i] }
        }
        return s >= nr.threshold
    }

    /// P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the capped admitting weight.
    public static func jointAcceptance(_ nr: NormalRule, _ ps: [Double]) -> Double {
        let t = Int(nr.threshold)
        var dist = [Double](repeating: 0, count: t + 1)
        dist[0] = 1.0
        for i in 0..<ps.count {
            var next = [Double](repeating: 0, count: t + 1)
            let w = nr.weights[i]
            let p = ps[i]
            for s in 0...t {
                let m = dist[s]
                if m == 0.0 { continue }
                let to = Int(min(Double(t), Double(s) + w))
                next[to] = next[to] + m * p
                if !nr.veto[i] { next[s] = next[s] + m * (1 - p) }
            }
            dist = next
        }
        return dist[t]
    }

    // MARK: common refinement

    static let SEV = ["reversible", "rate_limited", "irreversible"]

    static func sevIndex(_ s: String) -> Int { return SEV.firstIndex(where: { IV.same($0, s) }) ?? -1 }

    private static func cmp16(_ a: String, _ b: String) -> Bool { return WJ.u16Less(a, b) }

    private static func sortedUnique(_ xs: [String]) -> [String] {
        var seen = Set<JKey>()
        var out: [String] = []
        for x in xs where !seen.contains(JKey(x)) {
            seen.insert(JKey(x))
            out.append(x)
        }
        return out.sorted(by: cmp16)
    }

    private static func mergeDim(_ a: WalletDim, _ b: WalletDim) throws -> WalletDim {
        if a.kind != b.kind { throw JSError("commonRefinement: \(a.path) is numeric in one Omega and categorical in another") }
        if a.isNum {
            if a.lo != b.lo || a.hi != b.hi {
                throw JSError("commonRefinement: \(a.path) has different domains ([\(a.lo), \(a.hi)] vs [\(b.lo), \(b.hi)])")
            }
            var cuts = Set<Int>()
            for c in a.cuts { cuts.insert(c) }
            for c in b.cuts { cuts.insert(c) }
            var out = a
            out.cuts = cuts.sorted()
            return out
        }
        var ex: [String] = []
        var pre: [String] = []
        for v in a.values + b.values {
            if v.kind == "exact" { ex.append(v.value) } else if v.kind == "prefix" { pre.append(v.value) }
        }
        var values: [(kind: String, value: String)] = []
        for v in sortedUnique(ex) { values.append((kind: "exact", value: v)) }
        for v in sortedUnique(pre) { values.append((kind: "prefix", value: v)) }
        values.append((kind: "other", value: WalletOmegaMath.OTHER))
        var out = WalletDim(kind: "cat", path: a.path)
        out.values = values
        return out
    }

    /// The outcome-space JSON of a verb list (the shape `omegaToJson` writes).
    static func dimJSON(_ d: WalletDim) throws -> JSONValue {
        if d.isNum {
            guard let dist = d.dist else { throw JSError("pca-intent: a numeric dimension needs a dist") }
            return .object(["kind": .string("num"), "path": .string(d.path), "lo": .int(Int64(d.lo)), "hi": .int(Int64(d.hi)),
                            "cuts": .array(d.cuts.map { JSONValue.int(Int64($0)) }), "dist": .string(dist)])
        }
        return .object(["kind": .string("cat"), "path": .string(d.path),
                        "values": .array(d.values.map { JSONValue.object(["kind": .string($0.kind), "value": .string($0.value)]) })])
    }

    /// The union of the spaces' verbs, dimensions, cuts and named values (every input cell is a union of result cells). Returns the
    /// outcome-space JSON `{v: 1, verbs, approximate}`.
    public static func commonRefinement(_ omegas: [JSONValue]) throws -> JSONValue {
        var revs: [JKey: String] = [:]
        var dimsByVerb: [JKey: [WalletDim]] = [:]
        var order: [String] = []
        var approx: [String] = []
        for ov in omegas {
            let o = try WalletOmega(ov)
            if let ap = ov.get("approximate")?.asArray {
                for a in ap { if let s = a.asString { approx.append(s) } }
            }
            for vs in o.verbs {
                let key = JKey(vs.verb)
                guard var cur = dimsByVerb[key] else {
                    revs[key] = vs.reversibility
                    dimsByVerb[key] = vs.dims
                    order.append(vs.verb)
                    continue
                }
                if sevIndex(vs.reversibility) > sevIndex(revs[key] ?? "") { revs[key] = vs.reversibility }
                for d in vs.dims {
                    if let i = cur.firstIndex(where: { IV.same($0.path, d.path) }) { cur[i] = try mergeDim(cur[i], d) } else { cur.append(d) }
                }
                dimsByVerb[key] = cur
            }
        }
        let names = sortedUnique(order)
        var verbs: [JSONValue] = []
        for v in names {
            let dims0 = dimsByVerb[JKey(v)] ?? []
            // stable by path in UTF-16 order
            let idx = Array(0..<dims0.count).sorted { (x: Int, y: Int) -> Bool in
                let a = dims0[x].path, b = dims0[y].path
                if cmp16(a, b) { return true }
                if cmp16(b, a) { return false }
                return x < y
            }
            var dimJ: [JSONValue] = []
            for i in idx { dimJ.append(try dimJSON(dims0[i])) }
            verbs.append(.object(["verb": .string(v), "reversibility": .string(revs[JKey(v)] ?? ""),
                                  "weight": n(1.0 / Double(names.count)), "dims": .array(dimJ)]))
        }
        return .object(["v": .int(1), "verbs": .array(verbs), "approximate": .array(sortedUnique(approx).map { JSONValue.string($0) })])
    }
}
