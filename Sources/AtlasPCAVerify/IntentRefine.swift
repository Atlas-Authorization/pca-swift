import Foundation

/// Cut refinement and partial answers: a "partly" answer refines the outcome space (inserts cuts, names values or adds a dimension),
/// replays every earlier observation as a value-space region over the refined space, and records one observation per new sub-cell of
/// the questioned cell. Outcome spaces, regions and observations are the learner's JSON forms; cut points are integers (a fractional
/// cut in a new dimension is refused, the learner's outcome space has integer cells).
public enum PCAIntentRefine {
    /// One refinement of a verb's space: numeric cuts, categorical values / prefixes, or a whole new dimension.
    public struct Refinement {
        public var verb: String
        public var path: String
        public var cuts: [Double]?
        public var values: [String]?
        public var prefixes: [String]?
        public var newDim: WalletDim?

        public init(verb: String, path: String) {
            self.verb = verb
            self.path = path
        }

        public static func fromJson(_ o: JSONValue?) throws -> Refinement {
            let m = try IntentTree.obj(o)
            var r = Refinement(verb: try IntentTree.str(m["verb"]), path: try IntentTree.str(m["path"]))
            if let c = IntentTree.present(m["cuts"]) { r.cuts = try PCAIntentRefine.doubles(c) }
            if let v = IntentTree.present(m["values"]) { r.values = try PCAIntentRefine.strings(v) }
            if let p = IntentTree.present(m["prefixes"]) { r.prefixes = try PCAIntentRefine.strings(p) }
            if let d = IntentTree.present(m["newDim"]) { r.newDim = try PCAIntentRefine.dimFromJson(d) }
            return r
        }
    }

    static func doubles(_ o: JSONValue?) throws -> [Double] { try IntentTree.arr(o).map { try IntentTree.dbl($0) } }

    static func strings(_ o: JSONValue?) throws -> [String] { try IntentTree.arr(o).map { try IntentTree.str($0) } }

    // ---- the outcome space as JSON ----

    private static func integer(_ d: Double, _ what: String) throws -> Int {
        guard d.isFinite, d == d.rounded(.towardZero), abs(d) <= IV.MAX_SAFE else { throw JSError("refine: \(what) must be an integer") }
        return Int(d)
    }

    static func dimFromJson(_ o: JSONValue?) throws -> WalletDim {
        let m = try IntentTree.obj(o)
        let path = try IntentTree.str(m["path"])
        if let k = m["kind"]?.asString, IV.same(k, "num") {
            var d = WalletDim(kind: "num", path: path)
            d.cuts = try IntentTree.arr(m["cuts"]).map { try integer(try IntentTree.dbl($0), "a cut") }
            d.lo = try integer(try IntentTree.dbl(m["lo"]), "lo")
            d.hi = try integer(try IntentTree.dbl(m["hi"]), "hi")
            d.dist = try IntentTree.str(m["dist"])
            return d
        }
        var d = WalletDim(kind: "cat", path: path)
        for x in try IntentTree.arr(m["values"]) {
            let xo = try IntentTree.obj(x)
            d.values.append((kind: try IntentTree.str(xo["kind"]), value: try IntentTree.str(xo["value"])))
        }
        return d
    }

    static func dimToJson(_ d: WalletDim) -> JSONValue {
        if d.isNum {
            var o: JObject = ["kind": .string("num"), "path": .string(d.path), "lo": WJ.i(d.lo), "hi": WJ.i(d.hi), "cuts": WJ.arr(d.cuts)]
            if let dist = d.dist { o["dist"] = .string(dist) }
            return .object(o)
        }
        return .object(["kind": .string("cat"), "path": .string(d.path), "values": .array(d.values.map { catValueJson($0) })])
    }

    static func catValueJson(_ v: (kind: String, value: String)) -> JSONValue { .object(["kind": .string(v.kind), "value": .string(v.value)]) }

    /// {v: 1, verbs, approximate}: the outcome space in its JSON form.
    public static func omegaToJson(_ verbs: [WalletVerb], _ approximate: [String]) -> JSONValue {
        let vs: [JSONValue] = verbs.map { v in
            .object(["verb": .string(v.verb), "reversibility": .string(v.reversibility), "weight": IntentTree.jsonNumber(v.weight),
                     "dims": .array(v.dims.map { dimToJson($0) })])
        }
        return .object(["v": .int(1), "verbs": .array(vs), "approximate": .array(approximate.map { .string($0) })])
    }

    /// The learner's outcome space as JSON.
    public static func omegaJson(_ l: PCAIntentLearner) -> JSONValue { omegaToJson(l.omega.verbs, l.omegaApprox ?? []) }

    private static func approximateOf(_ omega: JSONValue?) throws -> [String] {
        guard let a = omega?.get("approximate")?.asArray else { return [] }
        return try a.map { try IntentTree.str($0) }
    }

    // ---- refining the space ----

    private static func sortedCat(_ values: [(kind: String, value: String)]) -> [(kind: String, value: String)] {
        func uniqSorted(_ kind: String) -> [String] {
            var seen = Set<JKey>()
            var out: [String] = []
            for v in values where IV.same(v.kind, kind) && seen.insert(JKey(v.value)).inserted { out.append(v.value) }
            return out.sorted { WJ.u16Less($0, $1) }
        }
        var out: [(kind: String, value: String)] = []
        for s in uniqSorted("exact") { out.append((kind: "exact", value: s)) }
        for s in uniqSorted("prefix") { out.append((kind: "prefix", value: s)) }
        out.append((kind: "other", value: WalletOmegaMath.OTHER))
        return out
    }

    private static func cutsOf(_ xs: [Int], _ lo: Int, _ hi: Int) -> [Int] {
        Array(Set(xs.filter { $0 >= lo && $0 <= hi })).sorted()
    }

    /// The verbs of an outcome space with one verb's dimension refined (the input is untouched).
    static func refineVerbs(_ omega: WalletOmega, _ r: Refinement) throws -> [WalletVerb] {
        guard let srcIndex = omega.verbs.firstIndex(where: { IV.same($0.verb, r.verb) }) else {
            throw JSError("refineOmega: no verb \(r.verb) in Omega")
        }
        var dims = omega.verbs[srcIndex].dims
        let i = dims.firstIndex(where: { IV.same($0.path, r.path) })
        if let nd = r.newDim {
            guard i == nil else { throw JSError("refineOmega: \(r.path) is already a dimension of \(r.verb)") }
            guard IV.same(nd.path, r.path) else { throw JSError("refineOmega: newDim.path must equal path") }
            var d = nd
            if d.isNum { d.cuts = cutsOf(d.cuts, d.lo, d.hi) } else { d.values = sortedCat(d.values) }
            dims.append(d)
            // a stable sort by path in UTF-16 code unit order
            dims = dims.enumerated().sorted { a, b in
                WJ.u16Less(a.element.path, b.element.path) || (!WJ.u16Less(b.element.path, a.element.path) && a.offset < b.offset)
            }.map { $0.element }
        } else {
            guard let at = i else { throw JSError("refineOmega: \(r.verb) has no dimension \(r.path) (pass newDim to add it)") }
            var d = dims[at]
            if d.isNum {
                if !(r.values ?? []).isEmpty || !(r.prefixes ?? []).isEmpty { throw JSError("refineOmega: \(r.path) is numeric") }
                var all = d.cuts
                for c in r.cuts ?? [] where c == c.rounded(.down) && c.isFinite && abs(c) <= IV.MAX_SAFE { all.append(Int(c)) }
                d.cuts = cutsOf(all, d.lo, d.hi)
            } else {
                if !(r.cuts ?? []).isEmpty { throw JSError("refineOmega: \(r.path) is categorical") }
                var all = d.values
                for s in r.values ?? [] { all.append((kind: "exact", value: s)) }
                for s in r.prefixes ?? [] { all.append((kind: "prefix", value: s)) }
                let sorted = sortedCat(all)
                if sorted.count > 20 { throw JSError("refineOmega: \(r.path) would have more than 20 values") }
                d.values = sorted
            }
            dims[at] = d
        }
        var verbs = omega.verbs
        verbs[srcIndex] = WalletVerb(verb: omega.verbs[srcIndex].verb, reversibility: omega.verbs[srcIndex].reversibility, weight: omega.verbs[srcIndex].weight, dims: dims)
        return verbs
    }

    /// The outcome space with one verb's dimension refined, as JSON (the input is untouched).
    public static func refineOmega(_ omega: JSONValue, _ r: Refinement) throws -> JSONValue {
        let w = try WalletOmega(omega)
        return omegaToJson(try refineVerbs(w, r), try approximateOf(omega))
    }

    // ---- regions as JSON ----

    /// The value-space region of one cell.
    static func regionOfCell(_ vs: WalletVerb, _ idx: [Int]) throws -> JSONValue {
        guard idx.count >= vs.dims.count else { throw JSError("regionOfCell: the cell has fewer indices than the verb has dimensions") }
        var dims = JObject()
        for (k, d) in vs.dims.enumerated() {
            let n = WalletOmegaMath.cellCount(d)
            guard idx[k] >= 0 && idx[k] < n else { throw JSError("regionOfCell: cell index out of range") }
            if d.isNum {
                let c = WalletOmegaMath.numCells(d)[idx[k]]
                dims[JKey(d.path)] = .object(["kind": .string("num"), "lo": WJ.i(c.lo), "hi": WJ.i(c.hi)])
            } else {
                dims[JKey(d.path)] = .object(["kind": .string("cat"), "values": .array(d.values.map { catValueJson($0) }), "cells": WJ.arr([idx[k]])])
            }
        }
        return .object(["verb": .string(vs.verb), "dims": .object(dims)])
    }

    /// One restricted part of a region: a numeric range or the listed cells of a categorical dimension.
    enum Part {
        case range(Double, Double)
        case cells([Int])
    }

    private static func restrictRegion(_ r: JSONValue, _ d: WalletDim, _ part: Part) throws -> JSONValue {
        var o = try IntentTree.obj(r)
        var dims = try IntentTree.obj(o["dims"])
        switch part {
        case let .range(lo, hi) where d.isNum:
            dims[JKey(d.path)] = .object(["kind": .string("num"), "lo": IntentTree.jsonNumber(lo), "hi": IntentTree.jsonNumber(hi)])
        case let .cells(cs) where !d.isNum:
            dims[JKey(d.path)] = .object(["kind": .string("cat"), "values": .array(d.values.map { catValueJson($0) }), "cells": WJ.arr(cs)])
        default:
            throw JSError("restrictRegion: part does not match the kind of \(d.path)")
        }
        o["dims"] = .object(dims)
        return .object(o)
    }

    /// The value-space region an observation was about, in the space it was recorded in.
    public static func regionOfObservation(_ omega: WalletOmega, _ o: PCAIntentLearner.Observation) throws -> JSONValue {
        if let r = o.region { return r }
        for v in omega.verbs where IV.same(v.verb, o.verb) { return try regionOfCell(v, o.cell) }
        throw JSError("regionOfObservation: no verb \(o.verb)")
    }

    /// May rewrite the region of an earlier observation (used when a dimension is added).
    public typealias Rescope = (PCAIntentLearner.Observation, JSONValue) throws -> JSONValue

    public static func refineLearner(_ l: PCAIntentLearner, _ r: Refinement, _ rescope: Rescope?) throws -> PCAIntentLearner {
        let verbs = try refineVerbs(l.omega, r)
        guard let params = l.mapParams else {
            throw JSError("pca-intent: build the learner with createLearner() so its parameters are serialisable")
        }
        let next = try PCAIntentMap.createLearner(omega: omegaToJson(verbs, l.omegaApprox ?? []), options: params)
        for o in l.observations {
            var region = try regionOfObservation(l.omega, o)
            if let f = rescope { region = try f(o, region) }
            guard let vs = verbs.first(where: { IV.same($0.verb, o.verb) }) else { throw JSError("refineLearner: no verb \(o.verb)") }
            var values = o.values.asObject ?? JObject()
            for d in vs.dims where values[JKey(d.path)] == nil { values[JKey(d.path)] = WalletOmegaMath.repValue(d, 0) }
            let oc: JSONValue = .object(["verb": .string(o.verb), "values": .object(values)])
            try next.observe(oc, y: o.y, source: o.source, region: region)
        }
        return next
    }

    // ---- partial answers ----

    private static func toInt(_ d: Double) -> Int {
        if d.isNaN { return 0 }
        return Int(max(-2147483648.0, min(2147483647.0, d.rounded(.towardZero))))
    }

    /// One labelled part of a partial answer: a numeric range, a set of exact values, or "every other value".
    public struct PartialPart {
        public var lo: Double?
        public var hi: Double?
        public var values: [String]?
        public var isRange: Bool
        public var isValues: Bool
        public var y: Int

        public static func fromJson(_ o: JSONValue?) throws -> PartialPart {
            let m = try IntentTree.obj(o)
            let y = PCAIntentRefine.toInt(try IntentTree.dbl(m["y"]))
            func numOrNull(_ v: JSONValue?) throws -> Double? {
                guard let x = IntentTree.present(v) else { return nil }
                return try IntentTree.dbl(x)
            }
            if m[JKey("lo")] != nil {
                return PartialPart(lo: try numOrNull(m["lo"]), hi: try numOrNull(m["hi"]), values: nil, isRange: true, isValues: false, y: y)
            }
            if m[JKey("values")] != nil {
                return PartialPart(lo: nil, hi: nil, values: try PCAIntentRefine.strings(m["values"]), isRange: false, isValues: true, y: y)
            }
            return PartialPart(lo: nil, hi: nil, values: nil, isRange: false, isValues: false, y: y)
        }
    }

    /// "Partly": the refinement the answer implies and the label of every part.
    public struct PartialAnswer {
        public var path: String?
        public var cuts: [Double]?
        public var values: [String]?
        public var newDim: WalletDim?
        public var parts: [PartialPart] = []

        public init() {}

        public static func fromJson(_ o: JSONValue?) throws -> PartialAnswer {
            let m = try IntentTree.obj(o)
            var a = PartialAnswer()
            if let p = IntentTree.present(m["path"]) { a.path = try IntentTree.str(p) }
            if let c = IntentTree.present(m["cuts"]) { a.cuts = try PCAIntentRefine.doubles(c) }
            if let v = IntentTree.present(m["values"]) { a.values = try PCAIntentRefine.strings(v) }
            if let d = IntentTree.present(m["newDim"]) { a.newDim = try PCAIntentRefine.dimFromJson(d) }
            for p in try IntentTree.arr(m["parts"]) { a.parts.append(try PartialPart.fromJson(p)) }
            return a
        }
    }

    private static func partLabel(_ d: WalletDim, _ j: Int, _ parts: [PartialPart]) -> Int? {
        let x = WalletOmegaMath.repValue(d, j)
        for p in parts {
            if p.isRange {
                if !d.isNum { continue }
                let c = WalletOmegaMath.numCells(d)[j]
                if let lo = p.lo, let hi = p.hi, Double(c.lo) >= lo, Double(c.hi) <= hi { return p.y }
            } else if p.isValues {
                if !d.isNum && IV.same(d.values[j].kind, "exact"), let vs = p.values, IV.contains(vs, JS.toString(x)) { return p.y }
            } else if !d.isNum && !IV.same(d.values[j].kind, "exact") { return p.y }
        }
        return nil
    }

    private static func subCells(_ d: WalletDim, _ region: JSONValue) throws -> [Int] {
        let n = WalletOmegaMath.cellCount(d)
        let rd = try PCAIntentRegion.parse(region.get("dims")?.asObject?[JKey(d.path)])
        var out: [Int] = []
        for j in 0..<n {
            guard let r = rd else { out.append(j); continue }
            if d.isNum && r.isNum {
                let c = WalletOmegaMath.numCells(d)[j]
                if Double(c.lo) >= r.lo && Double(c.hi) <= r.hi { out.append(j) }
            } else if !d.isNum && !r.isNum {
                var ref = WalletDim(kind: "cat", path: d.path)
                ref.values = r.values
                let cell = WalletOmegaMath.catCellOf(ref, WalletOmegaMath.catRep(d, j))
                if r.cells.contains(cell) { out.append(j) }
            }
        }
        return out
    }

    public struct PartialResult {
        public let learner: PCAIntentLearner
        public let added: [PCAIntentLearner.Observation]
    }

    /// Apply a partial answer to question q: a NEW learner over the refined space and the observations the answer added.
    public static func answerPartial(_ l: PCAIntentLearner, _ q: PCAIntentLearner.Question, _ a: PartialAnswer) throws -> PartialResult {
        guard let oldVs = l.omega.verbs.first(where: { IV.same($0.verb, q.verb) }) else { throw JSError("answerPartial: no verb \(q.verb)") }
        let qRegion = try regionOfCell(oldVs, q.cell)
        guard let path = a.path else { throw JSError("answerPartial: the answer names no path") }
        var r = Refinement(verb: q.verb, path: path)
        r.cuts = a.cuts
        r.values = a.values
        r.newDim = a.newDim
        let refinedVerbs = try refineVerbs(l.omega, r)
        guard let nvs = refinedVerbs.first(where: { IV.same($0.verb, q.verb) }), let dd = nvs.dims.first(where: { IV.same($0.path, path) }) else {
            throw JSError("answerPartial: the refined space lost the dimension")
        }
        var rescope: Rescope?
        if a.newDim != nil {
            var yesCells: [Int] = []
            for j in 0..<WalletOmegaMath.cellCount(dd) where partLabel(dd, j, a.parts) == 1 { yesCells.append(j) }
            let yes = yesCells
            rescope = { o, region in
                if !IV.same(o.verb, q.verb) || o.y != 1 { return region }
                if !dd.isNum { return try restrictRegion(region, dd, .cells(yes)) }
                if yes.isEmpty { return try restrictRegion(region, dd, .range(Double(dd.hi) + 1, Double(dd.hi) + 1)) }
                let cells = WalletOmegaMath.numCells(dd)
                return try restrictRegion(region, dd, .range(Double(cells[yes[0]].lo), Double(cells[yes[yes.count - 1]].hi)))
            }
        }
        let next = try refineLearner(l, r, rescope)
        var added: [PCAIntentLearner.Observation] = []
        for j in try subCells(dd, qRegion) {
            guard let y = partLabel(dd, j, a.parts) else { continue }
            let region: JSONValue
            if dd.isNum {
                let c = WalletOmegaMath.numCells(dd)[j]
                region = try restrictRegion(qRegion, dd, .range(Double(c.lo), Double(c.hi)))
            } else {
                region = try restrictRegion(qRegion, dd, .cells([j]))
            }
            var values = q.outcome.get("values")?.asObject ?? JObject()
            values[JKey(dd.path)] = WalletOmegaMath.repValue(dd, j)
            for x in nvs.dims where values[JKey(x.path)] == nil { values[JKey(x.path)] = WalletOmegaMath.repValue(x, 0) }
            let oc: JSONValue = .object(["verb": .string(q.verb), "values": .object(values)])
            if let ob = try next.observe(oc, y: y, source: "elicitation", region: region) { added.append(ob) }
        }
        return PartialResult(learner: next, added: added)
    }

    // ---- adaptive elicitation ----

    /// An adaptive answer is 0, 1 or a partial answer.
    public enum Answer {
        case label(Int)
        case partial(PartialAnswer)
    }

    public struct AdaptiveElicitResult {
        public let stop: String
        public let questions: Int
        public let auditQuestions: Int
        public let seedQuestions: Int
        public let asked: [PCAIntentLearner.Question]
        public let learner: PCAIntentLearner
        public let refinements: Int
    }

    /// Elicitation that accepts yes, no and partly; after maxRefinements (default 8) partial answers further ones count as "no".
    public static func elicitAdaptive(_ learner: PCAIntentLearner, _ answer: @escaping (PCAIntentLearner.Question, PCAIntentLearner) throws -> Answer,
                                      _ o: PCAIntentLearner.ElicitOptions, _ maxRefinements: Int? = nil) throws -> AdaptiveElicitResult {
        var cur = learner
        var asked: [PCAIntentLearner.Question] = []
        var refinements = 0
        let maxRef = maxRefinements ?? 8

        func ask(_ q: PCAIntentLearner.Question) throws {
            let a = try answer(q, cur)
            asked.append(q)
            switch a {
            case let .partial(pa):
                if refinements < maxRef {
                    cur = try answerPartial(cur, q, pa).learner
                    refinements += 1
                } else {
                    try cur.observe(q.outcome, y: 0, source: "elicitation", region: nil)
                }
            case let .label(y):
                try cur.observe(q.outcome, y: y, source: "elicitation", region: nil)
            }
        }

        var seedQuestions = 0
        for s in o.seed {
            if !(Double(asked.count) < o.maxQuestions) { break }
            guard let vs = cur.omega.verbs.first(where: { IV.same($0.verb, s.verb) }), s.cell.count == vs.dims.count else { continue }
            var values = JObject()
            for (k, d) in vs.dims.enumerated() {
                guard s.cell[k] >= 0 && s.cell[k] < WalletOmegaMath.cellCount(d) else { throw JSError("pca-intent: seed cell out of range") }
                values[JKey(d.path)] = WalletOmegaMath.repValue(d, s.cell[k])
            }
            let outcome: JSONValue = .object(["verb": .string(s.verb), "values": .object(values)])
            let p = cur.acceptance(outcome)
            if p <= 1e-9 || p >= 1 - 1e-9 || cur.isVetoed(outcome) { continue }
            try ask(PCAIntentLearner.Question(verb: s.verb, cell: s.cell, outcome: outcome, p: p, score: 0.0))
            seedQuestions += 1
        }
        var stop: String?
        while stop == nil {
            let m = cur.metrics()
            if m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden { stop = "converged" }
            else if !(Double(asked.count) < o.maxQuestions) { stop = "budget" }
            else if let q = cur.nextQuestion() { try ask(q) }
            else { stop = "no-disagreement" }
        }
        var auditQuestions = 0
        if o.audit {
            while true {
                let pending = cur.unconfirmedGrantCells()
                var mass = 0.0
                for x in pending { mass += x.weight }
                if pending.isEmpty || mass <= o.epsRisk { break }
                if !(Double(asked.count) < o.maxQuestions) { stop = "budget"; break }
                let top = pending[0]
                guard let vs = cur.omega.verbs.first(where: { IV.same($0.verb, top.verb) }) else { throw JSError("pca-intent: no such verb") }
                let outcome = WalletOmegaMath.cellRep(vs, top.cell)
                try ask(PCAIntentLearner.Question(verb: top.verb, cell: top.cell, outcome: outcome, p: cur.acceptance(outcome), score: top.weight))
                auditQuestions += 1
            }
        }
        return AdaptiveElicitResult(stop: stop ?? "budget", questions: asked.count, auditQuestions: auditQuestions, seedQuestions: seedQuestions,
                                    asked: asked, learner: cur, refinements: refinements)
    }
}
