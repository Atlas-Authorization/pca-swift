import Foundation

/// Classifier error folded into the residual risk: a confusion matrix estimated on a labelled calibration set with per-entry
/// Clopper-Pearson upper bounds (union bound), the risk in true coordinates (exact decomposition), the label-sound bound, the
/// classifier-aware residual risk of a learner over the augmented space, and the cells a maximum-error gate sends to just-in-time consent.
/// Calibrations and specs are JSON trees; the learner is the wallet-space `PCAIntentLearner`.
public enum PCAIntentClassifierKit {
    private static func obj(_ o: JSONValue?) throws -> JObject { try PCAIntentOmega.obj(o) }
    private static func arr(_ o: JSONValue?) throws -> [JSONValue] { try PCAIntentOmega.arr(o) }
    private static func dbl(_ o: JSONValue?) throws -> Double { try PCAIntentOmega.dbl(o) }
    private static func str(_ o: JSONValue?) throws -> String { try PCAIntentOmega.str(o) }
    private static func jn(_ d: Double) -> JSONValue { PCAIntentOmega.jn(d) }
    private static func row(_ r: [Double]) -> JSONValue { .array(r.map { jn($0) }) }

    /// Calibrate a classifier on labelled examples ({truth, predicted}); labels outside the set are refused. `deltaGamma` defaults to 0.05.
    public static func calibrateConfusion(_ samples: [JSONValue], _ labels: [JSONValue], _ deltaGamma: Double?) throws -> JSONValue {
        let delta = deltaGamma ?? 0.05
        var names: [String] = []
        for l in labels { names.append(try str(l)) }
        var seen = Set<JKey>()
        var uniq: [String] = []
        for x in names where seen.insert(JKey(x)).inserted { uniq.append(x) }
        let labs = uniq.sorted { IV.utf8Less($0, $1) }
        if labs.isEmpty { throw JSError("calibrateConfusion: empty label set") }
        if !(delta > 0 && delta < 1) { throw JSError("calibrateConfusion: delta must be in (0, 1)") }
        let n = labs.count
        var counts = [[Double]](repeating: [Double](repeating: 0, count: n), count: n)
        for so in samples {
            let s = try obj(so)
            var t = -1
            var p = -1
            if let x = s[JKey("truth")]?.asString { t = labs.firstIndex { IV.same($0, x) } ?? -1 }
            if let x = s[JKey("predicted")]?.asString { p = labs.firstIndex { IV.same($0, x) } ?? -1 }
            if t < 0 || p < 0 {
                throw JSError("calibrateConfusion: label outside L (\(JS.toString(s[JKey("truth")])) / \(JS.toString(s[JKey("predicted")])))")
            }
            counts[t][p] = counts[t][p] + 1
        }
        let alpha = delta / (Double(n) * Double(n))
        var cs: [JSONValue] = []
        var gs: [JSONValue] = []
        var bs: [JSONValue] = []
        for r in counts {
            var total = 0.0
            for c in r { total += c }
            var g = [Double](repeating: 0, count: n)
            var b = [Double](repeating: 0, count: n)
            for i in 0..<n {
                g[i] = total != 0.0 ? r[i] / total : 0.0
                b[i] = try PCAIntentStats.clopperPearsonUpper(r[i], total, alpha)
            }
            cs.append(row(r))
            gs.append(row(g))
            bs.append(row(b))
        }
        var out = JObject()
        out[JKey("labels")] = .array(labs.map { JSONValue.string($0) })
        out[JKey("counts")] = .array(cs)
        out[JKey("gamma")] = .array(gs)
        out[JKey("gammaBar")] = .array(bs)
        out[JKey("delta_ppm")] = jn(WJ.jsRound(delta * 1_000_000))
        return .object(out)
    }

    /// The calibration's content address (labels, counts, delta).
    public static func confusionDigest(_ c: JSONValue?) throws -> String {
        var body = JObject()
        body[JKey("d")] = .string("atlas-pca/intent-classifier-calibration/v1")
        body[JKey("labels")] = c?.get("labels") ?? JSONValue.null
        body[JKey("counts")] = c?.get("counts") ?? JSONValue.null
        body[JKey("delta_ppm")] = c?.get("delta_ppm") ?? JSONValue.null
        return try WJ.hash(WJ.plain(.object(body)))
    }

    /// The published error rate shown on cards: the maximum over true labels of the upper bound of any other label, capped at 1.
    public static func publishedErrorRate(_ c: JSONValue?) throws -> Double {
        var worst = 0.0
        let gb = try arr(c?.get("gammaBar"))
        for t in 0..<gb.count {
            var s = 0.0
            let r = try arr(gb[t])
            for p in 0..<r.count where p != t { s = s + (try dbl(r[p])) }
            let e = PCAIntentOmega.jmin(1.0, s)
            if e > worst { worst = e }
        }
        return worst
    }

    /// `x.toFixed(1)` for a non-negative finite x (an exact tie rounds up, as BigDecimal HALF_UP does).
    private static func fixed1(_ x: Double) throws -> String {
        guard x.isFinite, x >= 0, x < 1e15 else { throw JSError("not a finite non-negative number") }
        let f = x.rounded(.down)
        let frac = x - f
        if frac == 0.25 || frac == 0.75 {
            let n = Int64(f) * 10 + (frac == 0.25 ? 3 : 8)
            return "\(n / 10).\(n % 10)"
        }
        return String(format: "%.1f", x)
    }

    /// The fixed card note for a classifier dimension.
    public static func classifierCardNote(_ id: String, _ c: JSONValue?) throws -> String {
        let pct = try fixed1(try publishedErrorRate(c) * 100)
        return "\"\(id)\" is decided by an attested classifier, not by a person. Published error rate: up to \(pct)%."
    }

    // ---- risk on explicit arrays ----

    private static func mat(_ o: JSONValue?) throws -> [[Double]] {
        var out: [[Double]] = []
        for r in try arr(o) {
            var rr: [Double] = []
            for x in try arr(r) { rr.append(try dbl(x)) }
            out.append(rr)
        }
        return out
    }

    private static func bmat(_ o: JSONValue?) throws -> [[Bool]] {
        var out: [[Bool]] = []
        for r in try arr(o) { out.append(try arr(r).map { $0 == JSONValue.bool(true) }) }
        return out
    }

    private static func at(_ m: [[Double]], _ i: Int, _ j: Int) throws -> Double {
        guard i >= 0, i < m.count, j >= 0, j < m[i].count else { throw JSError("index out of bounds") }
        return m[i][j]
    }

    private static func gammaOfSet(_ g: [[Double]], _ a: [Int], _ t: Int) throws -> Double {
        var s = 0.0
        for p in a { s = s + (try at(g, p, t)) }
        return PCAIntentOmega.jmin(1.0, s)
    }

    private static func members(_ inG: [Bool]) -> [Int] {
        var out: [Int] = []
        for i in 0..<inG.count where inG[i] { out.append(i) }
        return out
    }

    /// R_kappa(G) over explicit arrays {mu, a, h, inG, g}: sum of mu (1 - a) h Gamma(A_G(x) | l), the set mass capped at 1.
    public static func classifierRisk(_ arrays: JSONValue?) throws -> Double {
        let mu = try mat(arrays?.get("mu"))
        let a = try mat(arrays?.get("a"))
        let h = try mat(arrays?.get("h"))
        let g = try mat(arrays?.get("g"))
        let inG = try bmat(arrays?.get("inG"))
        var r = 0.0
        for x in 0..<mu.count {
            guard x < inG.count else { throw JSError("index out of bounds") }
            let set = members(inG[x])
            for t in 0..<mu[x].count {
                r += mu[x][t] * (1 - (try at(a, x, t))) * (try at(h, x, t)) * (try gammaOfSet(g, set, t))
            }
        }
        return r
    }

    /// True iff a(x, l) = 1 for every (x, l) in G.
    public static func labelSound(_ arrays: JSONValue?) throws -> Bool {
        let a = try mat(arrays?.get("a"))
        let inG = try bmat(arrays?.get("inG"))
        for x in 0..<inG.count {
            for p in 0..<inG[x].count where inG[x][p] {
                if try at(a, x, p) != 1.0 { return false }
            }
        }
        return true
    }

    /// The bound for a label-sound grant: hMax times the mass of unacceptable cells weighted by the set error.
    public static func labelSoundBound(_ arrays: JSONValue?, _ hMax: Double) throws -> Double {
        let mu = try mat(arrays?.get("mu"))
        let a = try mat(arrays?.get("a"))
        let g = try mat(arrays?.get("g"))
        let inG = try bmat(arrays?.get("inG"))
        var s = 0.0
        for x in 0..<mu.count {
            guard x < inG.count else { throw JSError("index out of bounds") }
            let set = members(inG[x])
            for t in 0..<mu[x].count {
                if try at(a, x, t) == 0.0 { s += mu[x][t] * (try gammaOfSet(g, set, t)) }
            }
        }
        return hMax * s
    }

    // ---- risk from a learner over the augmented space ----

    private struct Member {
        let cell: [Int]
        let p: Double
        let mass: Double
        let harm: Double
        let inGrant: Bool
    }

    /// The cells of one group in first-seen order: (categorical index, member).
    private struct Groups {
        let dim: WalletDim
        let verb: WalletVerb
        var groups: [[(key: Int, mem: Member)]]
    }

    private static func groupsOf(_ l: PCAIntentLearner, _ spec: JObject) throws -> Groups {
        let verb = try str(spec[JKey("verb")])
        let path = try str(spec[JKey("path")])
        guard let vs = l.omega.verb(verb) else { throw JSError("classifier: no verb \(verb) in \u{03A9}") }
        guard let k = vs.dims.firstIndex(where: { IV.same($0.path, path) }), !vs.dims[k].isNum else {
            throw JSError("classifier: \(verb) has no categorical dimension \(path)")
        }
        var order: [String] = []
        var groups: [String: [(key: Int, mem: Member)]] = [:]
        for c in l.cells() {
            if !IV.same(c.verb, verb) { continue }
            var key = ""
            for i in 0..<c.cell.count where i != k { key += String(c.cell[i]) + "," }
            if groups[key] == nil { order.append(key); groups[key] = [] }
            let mem = Member(cell: c.cell, p: c.p, mass: c.mass, harm: c.harm, inGrant: c.inGrant)
            var list = groups[key] ?? []
            if let pos = list.firstIndex(where: { $0.key == c.cell[k] }) { list[pos] = (c.cell[k], mem) } else { list.append((c.cell[k], mem)) }
            groups[key] = list
        }
        return Groups(dim: vs.dims[k], verb: vs, groups: order.map { groups[$0] ?? [] })
    }

    private static func gbar(_ spec: JObject, _ dim: WalletDim, _ pred: Int, _ truth: Int) throws -> Double {
        let pv = dim.values[pred]
        let tv = dim.values[truth]
        if pv.kind != "exact" { return 0.0 }
        let cal = try obj(spec[JKey("cal")])
        let labels = try arr(cal[JKey("labels")])
        guard let pi = labels.firstIndex(where: { IV.same($0.asString, pv.value) }) else { return 0.0 }
        var ti = -1
        if tv.kind == "exact" { ti = labels.firstIndex(where: { IV.same($0.asString, tv.value) }) ?? -1 }
        if ti < 0 { return 1.0 }
        let rows = try arr(cal[JKey("gammaBar")])
        guard ti < rows.count else { throw JSError("index out of bounds") }
        let r = try arr(rows[ti])
        guard pi < r.count else { throw JSError("index out of bounds") }
        return try dbl(r[pi])
    }

    private static func admitted(_ g: [(key: Int, mem: Member)]) -> [Int] {
        return g.filter { $0.mem.inGrant }.map { $0.key }
    }

    private static func setError(_ spec: JObject, _ dim: WalletDim, _ a: [Int], _ t: Int) throws -> Double {
        var s = 0.0
        for p in a { s = s + (try gbar(spec, dim, p, t)) }
        return PCAIntentOmega.jmin(1.0, s)
    }

    /// R-hat of the learner's grant with classifier error folded in: {total, perVerb}. `specs`: [{verb, path, cal}].
    public static func classifierAwareResidualRisk(_ l: PCAIntentLearner, _ specs: [JSONValue]) throws -> JSONValue {
        var order: [String] = []
        var perVerb: [JKey: Double] = [:]
        var specOf: [JKey: Bool] = [:]
        for s in specs {
            let sv: String = try str(try obj(s)[JKey("verb")])
            specOf[JKey(sv)] = true
        }
        for c in l.cells() {
            if specOf[JKey(c.verb)] != nil { continue }
            let prev = perVerb[JKey(c.verb)] ?? 0.0
            if perVerb[JKey(c.verb)] == nil { order.append(c.verb) }
            perVerb[JKey(c.verb)] = c.inGrant ? prev + c.mass * (1 - c.p) * c.harm : prev
        }
        for so in specs {
            let spec = try obj(so)
            let gr = try groupsOf(l, spec)
            var r = 0.0
            for g in gr.groups {
                let a = admitted(g)
                for e in g { r += e.mem.mass * (1 - e.mem.p) * e.mem.harm * (try setError(spec, gr.dim, a, e.key)) }
            }
            let v = try str(spec[JKey("verb")])
            if perVerb[JKey(v)] == nil { order.append(v) }
            perVerb[JKey(v)] = r
        }
        var total = 0.0
        var pv = JObject()
        for k in order {
            let v = perVerb[JKey(k)] ?? 0.0
            total += v
            pv[JKey(k)] = jn(v)
        }
        return .object([JKey("total"): jn(total), JKey("perVerb"): .object(pv)])
    }

    /// The maximum-error gate: cells admitted on a classifier label that go to just-in-time consent, as [{verb, cell, flat}] sorted by flat index.
    public static func classifierJitCells(_ l: PCAIntentLearner, _ spec: JSONValue?, _ gammaMax: Double) throws -> [JSONValue] {
        let sp = try obj(spec)
        let gr = try groupsOf(l, sp)
        var out: [(flat: Double, v: JSONValue)] = []
        for g in gr.groups {
            let a = admitted(g)
            if a.isEmpty { continue }
            var worst = 0.0
            for e in g {
                if e.mem.inGrant || gr.dim.values[e.key].kind != "exact" { continue }
                worst = PCAIntentOmega.jmax(worst, try setError(sp, gr.dim, a, e.key))
            }
            if worst > gammaMax {
                for p in a {
                    guard let cell = g.first(where: { $0.key == p })?.mem.cell else { throw JSError("missing cell") }
                    let flat = Double(PCAIntentLearner.encode(gr.verb, cell))
                    var o = JObject()
                    o[JKey("verb")] = sp[JKey("verb")] ?? JSONValue.null
                    o[JKey("cell")] = WJ.arr(cell)
                    o[JKey("flat")] = jn(flat)
                    out.append((flat, JSONValue.object(o)))
                }
            }
        }
        let ordered = out.enumerated().sorted { a, b in
            if a.element.flat != b.element.flat { return a.element.flat < b.element.flat }
            return a.offset < b.offset
        }
        return ordered.map { $0.element.v }
    }
}
