import Foundation

/// Elicitation as learning (reference: @atlasauth/pca-intent learner.ts, region.ts, policy.ts): the exact Bayesian posterior over the
/// per-verb hypothesis class (boxes, unions of boxes, decision lists), the next question, the audit round, the conservative grant as
/// predicates, and the admission oracle of a policy. The outcome space reuses the wallet's cell arithmetic (WalletOmegaMath). Doubles
/// follow the reference operation by operation; log2 / exp / pow come from the platform libm (the reference's fdlibm may round a
/// transcendental differently in the last bit).
public enum PCAIntentRegion {
    struct Dim {
        var isNum: Bool
        var lo = 0.0, hi = 0.0
        var values: [(kind: String, value: String)] = []
        var cells: [Int] = []
    }

    static func parse(_ v: JSONValue?) throws -> Dim? {
        guard let v = v, !v.isNull else { return nil }
        guard let o = v.asObject, let kind = o["kind"]?.asString else { throw JSError("region: bad dimension") }
        if kind == "num" {
            guard let lo = IV.num(o["lo"]), let hi = IV.num(o["hi"]) else { throw JSError("region: bad numeric range") }
            return Dim(isNum: true, lo: lo, hi: hi)
        }
        guard kind == "cat", let vals = o["values"]?.asArray, let cells = o["cells"]?.asArray else { throw JSError("region: bad categorical dimension") }
        var d = Dim(isNum: false)
        d.values = try vals.map {
            guard let k = $0.get("kind")?.asString, let s = $0.get("value")?.asString else { throw JSError("region: bad value") }
            return (k, s)
        }
        d.cells = try cells.map { guard let i = IV.int($0) else { throw JSError("region: bad cell") }; return Int(i) }
        return d
    }

    /// The cells of dimension `d` covered by the region dimension: 'inner' (wholly inside) for a yes, 'outer' (meeting it) for a no.
    static func dimCellsIn(_ d: WalletDim, _ rd: Dim?, inner: Bool) throws -> [Int] {
        let n = WalletOmegaMath.cellCount(d)
        let all = Array(0..<n)
        guard let rd = rd else { return all }
        if d.isNum {
            guard rd.isNum else { throw JSError("region: \(d.path) is numeric in the outcome space but categorical in the region") }
            let cells = WalletOmegaMath.numCells(d)
            return all.filter { i in
                let c = cells[i]
                return inner ? Double(c.lo) >= rd.lo && Double(c.hi) <= rd.hi : Double(c.hi) >= rd.lo && Double(c.lo) <= rd.hi
            }
        }
        guard !rd.isNum else { throw JSError("region: \(d.path) is categorical in the outcome space but numeric in the region") }
        var ref = WalletDim(kind: "cat", path: d.path)
        ref.values = rd.values
        let inSet = Set(rd.cells)
        return all.filter { inSet.contains(WalletOmegaMath.catCellOf(ref, WalletOmegaMath.catRep(d, $0))) }
    }

    /// Flat cell indices of the verb space covered by the region (row-major, last dimension fastest). A region that restricts a
    /// dimension the verb space lacks is refused (dropping the restriction would widen a narrow yes).
    static func cells(_ vs: WalletVerb, _ r: JSONValue, inner: Bool) throws -> [Int] {
        guard let o = r.asObject, let verb = o["verb"]?.asString, IV.same(verb, vs.verb), let dims = o["dims"]?.asObject else {
            throw JSError("region: verb does not match or no dimensions")
        }
        for k in dims.keys where !vs.dims.contains(where: { IV.same($0.path, k.s) }) { throw JSError("region: restricts \(k.s), which the outcome space has no dimension for") }
        var per: [[Int]] = []
        for d in vs.dims { per.append(try dimCellsIn(d, try parse(dims[JKey(d.path)]), inner: inner)) }
        if per.contains(where: { $0.isEmpty }) { return [] }
        var acc: [Int] = [0]
        for (k, cells) in per.enumerated() {
            let size = WalletOmegaMath.cellCount(vs.dims[k])
            var next: [Int] = []
            for f in acc { for c in cells { next.append(f * size + c) } }
            acc = next
        }
        return acc
    }
}

/// An admission oracle for a policy ({predicates, caveats}): the static caveat gate (satisfiability, reversibility cap) then the real
/// predicate evaluator. Policies with vetoes, tighten rules or meets are refused (the learner never builds one).
public struct PCAIntentAdmitter {
    let predicates: JSONValue
    let sat: Bool
    let revCap: Int?
    static let revOrder = ["reversible", "rate_limited", "irreversible"]

    private static func finite(_ v: JSONValue?) -> Double? { IV.num(v).flatMap { $0.isFinite ? $0 : nil } }

    /// Static satisfiability of the caveat set (analyzeCaveats): the cap is the strictest reversibility_max.
    static func analyze(_ caveats: [JSONValue]) -> (sat: Bool, revCap: Int?) {
        var notBefore = -Double.infinity, expires = Double.infinity
        var cap: Int?
        for cv in caveats {
            guard let o = cv.asObject, let type = o["type"]?.asString else { return (false, nil) }
            switch type {
            case "expires": guard let at = finite(o["at"]) else { return (false, nil) }; expires = min(expires, at)
            case "not_before": guard let at = finite(o["at"]) else { return (false, nil) }; notBefore = max(notBefore, at)
            case "rate":
                guard let m = finite(o["max"]), let per = finite(o["per_secs"]), per > 0, m >= 1 else { return (false, nil) }
            case "max_blast_radius", "delegation_depth":
                guard let m = finite(o["max"]), m >= 0 else { return (false, nil) }
            case "reversibility_max":
                guard let c = o["class"].map({ IntentV2.jsString($0) }), let i = revOrder.firstIndex(where: { IV.same($0, c) }) else { return (false, nil) }
                cap = cap.map { min($0, i) } ?? i
            case "budget_alloc": guard let l = finite(o["limit"]), l >= 0 else { return (false, nil) }
            default: return (false, nil)
            }
        }
        if notBefore != -Double.infinity && expires != Double.infinity && notBefore >= expires { return (false, nil) }
        return (true, cap)
    }

    public init(_ policy: JSONValue?) throws {
        let o = policy?.asObject
        for k in ["vetoes", "tighten", "meet"] {
            if let a = o?[JKey(k)]?.asArray, !a.isEmpty { throw JSError("admitter: \(k) are not supported by this port") }
        }
        predicates = .array(o?[JKey("predicates")]?.asArray ?? [])
        let a = PCAIntentAdmitter.analyze(o?[JKey("caveats")]?.asArray ?? [])
        sat = a.sat
        revCap = a.revCap
    }

    private static func setPath(_ root: inout JObject, _ segs: ArraySlice<String>, _ value: JSONValue) {
        guard let k = segs.first else { return }
        if segs.count == 1 { root[JKey(k)] = value; return }
        var child = root[JKey(k)]?.asObject ?? JObject()
        setPath(&child, segs.dropFirst(), value)
        root[JKey(k)] = .object(child)
    }

    /// The outcome as the evaluator's action context ({action, subject, env}).
    static func context(_ vs: WalletVerb, _ outcome: JSONValue) -> JSONValue {
        var params = JObject(), env = JObject(), subject = JObject()
        var resource = "resource:any"
        for (key, value) in outcome.get("values")?.asObject ?? [:] {
            let segs = key.s.unicodeScalars.split(separator: ".", omittingEmptySubsequences: false).map { IV.text($0) }
            if IV.same(key.s, "action.resource") { resource = IntentV2.jsString(value) }
            else if segs.count > 2 && segs[0] == "action" && segs[1] == "params" { setPath(&params, segs.dropFirst(2), value) }
            else if segs.count > 1 && segs[0] == "env" { setPath(&env, segs.dropFirst(1), value) }
            else if segs.count > 1 && segs[0] == "subject" { setPath(&subject, segs.dropFirst(1), value) }
        }
        let action: JObject = ["verb": .string(vs.verb), "resource": .string(resource), "params": .object(params), "reversibility_class": .string(vs.reversibility)]
        return .object(["action": .object(action), "subject": .object(subject), "env": .object(env)])
    }

    public func admits(_ vs: WalletVerb, _ outcome: JSONValue) -> Bool {
        guard sat else { return false }
        if let cap = revCap {
            guard let i = Self.revOrder.firstIndex(where: { IV.same($0, vs.reversibility) }), i <= cap else { return false }
        }
        return Predicates.evaluate(predicates, Self.context(vs, outcome))
    }
}

public final class PCAIntentLearner {
    typealias LM = WalletOmegaMath

    // MARK: options

    public enum HypothesisClass {
        case box
        /// k, decay: the raw option values (validated when a verb model is built, like the reference).
        case union(k: Double, decay: Double?)
        case decisionList(maxRules: Double, decay: Double?, conditions: String?)
    }

    public struct Anchor { public var policy: JSONValue; public var lambda: Double }

    public struct Options {
        public var eta: Double?
        public var etaPos: Double?, etaNeg: Double?
        public var tau: Double?
        public var nullMass: Double?
        public var nullMassFn: ((WalletVerb) -> Double)?
        public var anchor: Anchor?
        public var anchors: [Anchor] = []
        public var maxHypotheses: Double = 400_000
        public var maxEnumeration: Double = 4_000_000
        public var strategy: String?
        public var hypothesisClass: HypothesisClass = .box
        public var agnosticSlack: Double?
        public var monotone: (paths: [String], offMass: Double?)?
        public var priorMix: (beta: Double, weight: (WalletVerb, (Int) -> Bool) throws -> Double)?

        public init() {}

        private static func number(_ o: JObject, _ k: String) -> Double? {
            guard let v = o[JKey(k)], !v.isNull else { return nil }
            return IV.num(v) ?? .nan // present but not a number: NaN fails every range check
        }

        private static func anchorOf(_ v: JSONValue) -> Anchor {
            Anchor(policy: v.get("policy") ?? .null, lambda: IV.num(v.get("lambda")) ?? .nan)
        }

        /// The data members of the option object (a closure member such as nullMassFn / priorMix.weight is set by the caller).
        public init(json: JSONValue?) throws {
            guard let o = json?.asObject else { return }
            eta = Self.number(o, "eta"); etaPos = Self.number(o, "etaPos"); etaNeg = Self.number(o, "etaNeg"); tau = Self.number(o, "tau")
            nullMass = Self.number(o, "nullMass"); agnosticSlack = Self.number(o, "agnosticSlack")
            if let m = Self.number(o, "maxHypotheses") { maxHypotheses = m }
            if let m = Self.number(o, "maxEnumeration") { maxEnumeration = m }
            if let s = o[JKey("strategy")], !s.isNull {
                guard let t = s.asString, t == "disagreement" || t == "risk" else { throw JSError("pca-intent: unknown strategy") }
                strategy = t
            }
            if let a = o[JKey("anchor")], !a.isNull { anchor = Self.anchorOf(a) }
            if let a = o[JKey("anchors")]?.asArray { anchors = a.map(Self.anchorOf) }
            if let h = o[JKey("hypothesisClass")], !h.isNull {
                guard let ho = h.asObject, let kind = ho["kind"]?.asString else { throw JSError("pca-intent: bad hypothesis class") }
                let decay = Self.number(ho, "decay")
                switch kind {
                case "box": hypothesisClass = .box
                case "union": hypothesisClass = .union(k: Self.number(ho, "k") ?? .nan, decay: decay)
                case "decision-list":
                    let c = ho[JKey("conditions")]
                    hypothesisClass = .decisionList(maxRules: Self.number(ho, "maxRules") ?? .nan, decay: decay, conditions: c?.isNull == false ? (c?.asString ?? "?") : nil)
                default: throw JSError("pca-intent: unknown hypothesis class")
                }
            }
            if let m = o[JKey("monotone")], !m.isNull {
                guard let paths = m.get("paths")?.asArray else { throw JSError("pca-intent: monotone.paths must be a list") }
                monotone = (try paths.map { guard let s = $0.asString else { throw JSError("pca-intent: monotone path") }; return s }, Self.number(m.asObject ?? [:], "offMass"))
            }
        }
    }

    public struct Observation {
        public var verb: String
        public var values: JSONValue
        public var cell: [Int]
        public var y: Int
        public var source: String
        public var region: JSONValue?
        public var conflict = false

        public var json: JSONValue {
            var o: JObject = ["verb": .string(verb), "values": values, "cell": .array(cell.map { .int(Int64($0)) }), "y": .int(Int64(y)), "source": .string(source)]
            if let r = region { o["region"] = r }
            if conflict { o["conflict"] = .bool(true) }
            return .object(o)
        }
    }

    public struct Question {
        public var verb: String
        public var cell: [Int]
        public var outcome: JSONValue
        public var p: Double
        public var score: Double

        public var json: JSONValue {
            .object(["verb": .string(verb), "cell": .array(cell.map { .int(Int64($0)) }), "outcome": outcome, "p": .double(p), "score": .double(score)])
        }
    }

    public struct Metrics {
        public var residualRisk = 0.0, burden = 0.0, uncertainty = 0.0, entropyBits = 0.0
        public var log2VersionSpace: Double?
        public var disagreementMass = 0.0, meanHarm = 0.0
        public var questions = 0, conflicts = 0

        public var json: JSONValue {
            .object(["residualRisk": .double(residualRisk), "burden": .double(burden), "uncertainty": .double(uncertainty), "entropyBits": .double(entropyBits),
                     "log2VersionSpace": log2VersionSpace.map { .double($0) } ?? .null, "disagreementMass": .double(disagreementMass),
                     "meanHarm": .double(meanHarm), "questions": .int(Int64(questions)), "conflicts": .int(Int64(conflicts))])
        }
    }

    // MARK: hypothesis enumeration

    final class VerbModel {
        let vs: WalletVerb
        var nChoice: [Int] = []
        var contains: [[UInt8]] = []
        var nCellsD: [Int] = []
        var nh = 0
        var choice: [Int32] = []
        var member: [UInt8]?
        var complexity: [Int]?
        var prior: [Double] = []
        var w: [Double] = []
        var err: [Int] = []
        var nCells = 0
        var cellIdx: [Int32] = []
        var mass: [Double] = []
        var harm: [Double] = []
        var p: [Double] = []
        var veto: [UInt8] = []
        var seen: [UInt8] = []
        var dirty = true
        init(_ vs: WalletVerb) { self.vs = vs }
    }

    static func isInteger(_ d: Double) -> Bool { d.isFinite && d.rounded(.towardZero) == d }

    public static func binEnt(_ p: Double) -> Double {
        if p <= 0 || p >= 1 { return 0 }
        return -(p * FdLibm.log2(p) + (1 - p) * FdLibm.log2(1 - p))
    }

    static func buildBoxTables(_ vs: WalletVerb, _ nCellsD: [Int]) throws -> (contains: [[UInt8]], nChoice: [Int]) {
        var contains: [[UInt8]] = [], nChoice: [Int] = []
        for (k, d) in vs.dims.enumerated() {
            let n = nCellsD[k]
            if d.isNum {
                var ch: [(Int, Int)] = []
                for i in 0..<n { for j in i..<n { ch.append((i, j)) } }
                var t = [UInt8](repeating: 0, count: ch.count * n)
                for (c, r) in ch.enumerated() { for x in r.0...r.1 { t[c * n + x] = 1 } }
                contains.append(t); nChoice.append(ch.count)
            } else {
                if n > 20 { throw JSError("pca-intent: categorical dimension \(d.path) has \(n) values (max 20 for exact enumeration)") }
                let m = (1 << n) - 1
                var t = [UInt8](repeating: 0, count: m * n)
                if m >= 1 { for mask in 1...m { for x in 0..<n where mask & (1 << x) != 0 { t[(mask - 1) * n + x] = 1 } } }
                contains.append(t); nChoice.append(m)
            }
        }
        return (contains, nChoice)
    }

    /// The product of the per-dimension choice counts; nil on overflow (certainly above every cap).
    static func product(_ xs: [Int]) -> Int? {
        var p = 1
        for x in xs { let (r, o) = p.multipliedReportingOverflow(by: x); if o { return nil }; p = r }
        return p
    }

    static func boxMasks(_ m: VerbModel, cap: Double) throws -> [[UInt8]] {
        let D = m.vs.dims.count
        guard let boxes = product(m.nChoice), Double(boxes) <= cap else { throw JSError("pca-intent: boxes for \(m.vs.verb) exceed the enumeration cap; coarsen the cuts") }
        var out: [[UInt8]] = []
        var cur = [Int](repeating: 0, count: D)
        for _ in 0..<boxes {
            var mask = [UInt8](repeating: 0, count: m.nCells)
            for c in 0..<m.nCells {
                var inside = true
                var d = 0
                while d < D && inside {
                    if m.contains[d][cur[d] * m.nCellsD[d] + Int(m.cellIdx[c * D + d])] == 0 { inside = false }
                    d += 1
                }
                if inside { mask[c] = 1 }
            }
            out.append(mask)
            var d = D - 1
            while d >= 0 {
                cur[d] += 1
                if cur[d] < m.nChoice[d] { break }
                cur[d] = 0
                d -= 1
            }
        }
        return out
    }

    /// Unions of at most k boxes, deduplicated by cell set; complexity = fewest boxes.
    static func enumerateUnions(_ boxes: [[UInt8]], k: Int, cap: Double, verb: String) throws -> (sets: [[UInt8]], complexity: [Int]) {
        var seen = Set<[UInt8]>()
        var sets: [[UInt8]] = [], complexity: [Int] = [], frontier: [[UInt8]] = []
        for b in boxes {
            if seen.contains(b) { continue }
            seen.insert(b); sets.append(b); complexity.append(1); frontier.append(b)
        }
        var work = 0.0
        if k >= 2 {
            for level in 2...k {
                var next: [[UInt8]] = []
                for s in frontier {
                    for b in boxes {
                        work += 1
                        if !(work <= cap) { throw JSError("pca-intent: the union-of-\(k)-boxes class for \(verb) exceeds the enumeration cap; coarsen the cuts or lower k") }
                        var u = s
                        for i in 0..<u.count { u[i] |= b[i] }
                        if seen.contains(u) { continue }
                        seen.insert(u); sets.append(u); complexity.append(level); next.append(u)
                    }
                }
                frontier = next
            }
        }
        return (sets, complexity)
    }

    static func dedup(_ masks: [[UInt8]]) -> [[UInt8]] {
        var seen = Set<[UInt8]>()
        return masks.filter { seen.insert($0).inserted }
    }

    static func atomicTests(_ m: VerbModel) -> [[UInt8]] {
        let D = m.vs.dims.count
        var tests: [[UInt8]] = []
        func add(_ k: Int, _ pred: (Int) -> Bool) {
            var mask = [UInt8](repeating: 0, count: m.nCells)
            var any = false, all = true
            for c in 0..<m.nCells {
                if pred(Int(m.cellIdx[c * D + k])) { mask[c] = 1; any = true } else { all = false }
            }
            if any && !all { tests.append(mask) }
        }
        for (k, d) in m.vs.dims.enumerated() {
            let n = m.nCellsD[k]
            if d.isNum {
                if n >= 2 { for i in 0..<(n - 1) { add(k) { $0 <= i } } }
                if n >= 2 { for i in 1..<n { add(k) { $0 >= i } } }
                if n > 2 { for i in 1..<(n - 1) { add(k) { $0 == i } } }
            } else { for i in 0..<n { add(k) { $0 == i } } }
        }
        return dedup(tests)
    }

    static func enumerateDecisionLists(_ tests: [[UInt8]], nCells: Int, L: Int, cap: Double, verb: String) throws -> (sets: [[UInt8]], complexity: [Int]) {
        var seen = Set<[UInt8]>()
        var sets: [[UInt8]] = [], complexity: [Int] = []
        func emit(_ acc: [UInt8], _ decided: [UInt8], _ rules: Int) {
            for def in [UInt8(0), UInt8(1)] {
                var s = [UInt8](repeating: 0, count: nCells)
                var any = false
                for c in 0..<nCells {
                    s[c] = decided[c] != 0 ? acc[c] : def
                    if s[c] != 0 { any = true }
                }
                if !any || seen.contains(s) { continue }
                seen.insert(s); sets.append(s); complexity.append(max(1, rules))
            }
        }
        var frontier: [(decided: [UInt8], acc: [UInt8])] = [([UInt8](repeating: 0, count: nCells), [UInt8](repeating: 0, count: nCells))]
        emit(frontier[0].acc, frontier[0].decided, 0)
        var work = 0.0
        for depth in 1...L {
            var order: [(decided: [UInt8], acc: [UInt8])] = []
            var states = Set<[UInt8]>()
            for st in frontier {
                for t in tests {
                    for label in [UInt8(0), UInt8(1)] {
                        work += 1
                        if !(work <= cap) { throw JSError("pca-intent: the decision-list class (<= \(L) rules) for \(verb) exceeds the enumeration cap") }
                        var decided = [UInt8](repeating: 0, count: nCells), acc = [UInt8](repeating: 0, count: nCells)
                        var fresh = false
                        for c in 0..<nCells {
                            if st.decided[c] != 0 { decided[c] = 1; acc[c] = st.acc[c] }
                            else if t[c] != 0 { decided[c] = 1; acc[c] = label; fresh = true }
                        }
                        if !fresh { continue }
                        if states.insert(decided + acc).inserted { order.append((decided, acc)) }
                    }
                }
            }
            frontier = order
            for st in frontier { emit(st.acc, st.decided, depth) }
        }
        return (sets, complexity)
    }

    static func buildVerbModel(_ vs: WalletVerb, _ opts: Options, _ harm: WalletOmegaMath.HarmModel) throws -> VerbModel {
        let m = VerbModel(vs)
        let D = vs.dims.count
        m.nCellsD = vs.dims.map { LM.cellCount($0) }
        let t = try buildBoxTables(vs, m.nCellsD)
        m.contains = t.contains; m.nChoice = t.nChoice
        m.nCells = LM.verbCellCount(vs)
        m.cellIdx = [Int32](repeating: 0, count: m.nCells * D)
        m.mass = [Double](repeating: 0, count: m.nCells)
        m.harm = [Double](repeating: 0, count: m.nCells)
        for c in 0..<m.nCells {
            let idx = LM.decodeCell(vs, c)
            for d in 0..<D { m.cellIdx[c * D + d] = Int32(idx[d]) }
            let s = LM.cellStats(vs, idx, harm)
            m.mass[c] = s.mass; m.harm[c] = s.harm
        }
        switch opts.hypothesisClass {
        case .box:
            guard let boxes = product(m.nChoice), Double(boxes) + 1 <= opts.maxHypotheses else {
                throw JSError("pca-intent: |Theta_\(vs.verb)| exceeds maxHypotheses \(opts.maxHypotheses); coarsen the cuts")
            }
            m.nh = boxes + 1
            m.choice = [Int32](repeating: 0, count: max(1, boxes * D))
            var cur = [Int](repeating: 0, count: D)
            for h in 0..<boxes {
                for d in 0..<D { m.choice[h * D + d] = Int32(cur[d]) }
                var d = D - 1
                while d >= 0 {
                    cur[d] += 1
                    if cur[d] < m.nChoice[d] { break }
                    cur[d] = 0
                    d -= 1
                }
            }
        case let .union(k, _):
            guard isInteger(k), k >= 1 else { throw JSError("pca-intent: union class needs an integer k >= 1") }
            let boxes = try boxMasks(m, cap: opts.maxEnumeration)
            let r = try enumerateUnions(boxes, k: Int(k), cap: opts.maxEnumeration, verb: vs.verb)
            try install(m, r.sets, r.complexity, opts)
        case let .decisionList(maxRules, _, conditions):
            guard isInteger(maxRules), maxRules >= 1 else { throw JSError("pca-intent: decision-list class needs an integer maxRules >= 1") }
            let cond = conditions ?? "box"
            guard cond == "box" || cond == "atomic" else { throw JSError("pca-intent: decision-list conditions must be 'box' or 'atomic'") }
            let tests = cond == "atomic" ? atomicTests(m) : dedup(try boxMasks(m, cap: opts.maxEnumeration))
            let r = try enumerateDecisionLists(tests, nCells: m.nCells, L: Int(maxRules), cap: opts.maxEnumeration, verb: vs.verb)
            try install(m, r.sets, r.complexity, opts)
        }
        m.prior = [Double](repeating: 0, count: m.nh)
        m.w = [Double](repeating: 0, count: m.nh)
        m.err = [Int](repeating: 0, count: m.nh)
        m.p = [Double](repeating: 0, count: m.nCells)
        m.veto = [UInt8](repeating: 0, count: m.nCells)
        m.seen = [UInt8](repeating: 0, count: m.nCells)
        return m
    }

    private static func install(_ m: VerbModel, _ sets: [[UInt8]], _ cx: [Int], _ opts: Options) throws {
        guard Double(sets.count) + 1 <= opts.maxHypotheses else { throw JSError("pca-intent: |Theta_\(m.vs.verb)| exceeds maxHypotheses \(opts.maxHypotheses); coarsen the cuts") }
        m.nh = sets.count + 1
        var member = [UInt8](repeating: 0, count: m.nh * m.nCells)
        var complexity = [Int](repeating: 0, count: m.nh)
        for (i, s) in sets.enumerated() {
            for c in 0..<m.nCells { member[(i + 1) * m.nCells + c] = s[c] }
            complexity[i + 1] = cx[i]
        }
        m.member = member
        m.complexity = complexity
    }

    static func holds(_ m: VerbModel, _ h: Int, _ c: Int) -> Bool {
        if let mem = m.member { return mem[h * m.nCells + c] == 1 }
        let D = m.vs.dims.count
        let base = (h - 1) * D
        for d in 0..<D where m.contains[d][Int(m.choice[base + d]) * m.nCellsD[d] + Int(m.cellIdx[c * D + d])] == 0 { return false }
        return true
    }

    /// The non-empty hypotheses of a class as cell masks (index 0, the empty set, omitted) with their Occam complexity.
    public static func hypothesisCellSets(_ vsJSON: JSONValue?, _ hc: HypothesisClass = .box, maxHypotheses: Double? = nil, maxEnumeration: Double? = nil) throws -> (sets: [[UInt8]], complexity: [Int]) {
        let vs = try verbSpace(vsJSON)
        var o = Options()
        o.hypothesisClass = hc
        if let a = maxHypotheses { o.maxHypotheses = a }
        if let a = maxEnumeration { o.maxEnumeration = a }
        let m = try buildVerbModel(vs, o, LM.DEFAULT_HARM)
        var sets: [[UInt8]] = [], cx: [Int] = []
        if m.nh > 1 {
            for h in 1..<m.nh {
                sets.append((0..<m.nCells).map { holds(m, h, $0) ? 1 : 0 })
                cx.append(m.complexity?[h] ?? 1)
            }
        }
        return (sets, cx)
    }

    /// The canonical class name stored in an Intent Map.
    public static func hypothesisClassName(_ hc: HypothesisClass) -> String {
        switch hc {
        case .box: return "per-verb-box/v1"
        case .union: return "per-verb-union/v1"
        case let .decisionList(_, _, c): return (c ?? "box") == "atomic" ? "per-verb-decision-list/v1" : "per-verb-decision-list/v2"
        }
    }

    static func verbSpace(_ v: JSONValue?) throws -> WalletVerb {
        let o = try WalletOmega(.object(["verbs": .array(v.map { [$0] } ?? [])]))
        guard let vs = o.verbs.first else { throw JSError("pca-intent: bad verb space") }
        return vs
    }

    // MARK: the learner

    public let omega: WalletOmega
    /// The outcome space as it was given (JSON): `typedOmega()` reads it as the typed `PCAIntentOmega.Omega`.
    public let omegaSource: JSONValue?
    /// The outcome space's `approximate` list (nil when the source object had none; an Intent Map needs it).
    public let omegaApprox: [String]?
    public let eta: Double
    public let etaPos: Double, etaNeg: Double
    let noisy: Bool
    public let tau: Double
    let risk: Bool
    /// 'disagreement' or 'risk'.
    public let strategy: String
    /// The map-form parameters this learner was built with (set by PCAIntentMap.createLearner; nil for a plain learner).
    public var mapParams: JSONValue?
    let harm: WalletOmegaMath.HarmModel = LM.DEFAULT_HARM
    public let hypothesisClass: HypothesisClass
    let agnosticSlack: Int?
    public private(set) var observations: [Observation] = []
    var models: [VerbModel] = []
    let opts: Options

    /// A learner over the typed outcome space (the reference's `createLearner(omega, options)`). The typed `PCAIntentOmega` is the one implementation of the cell
    /// arithmetic; the learner itself still runs on the `WalletOmega` view of the same space (see the lane's parity notes).
    public convenience init(typed omega: PCAIntentOmega.Omega, options: Options = Options()) throws {
        try self.init(omega: PCAIntentOmega.omegaToJson(omega), options: options)
    }

    /// This learner's outcome space as the typed `PCAIntentOmega.Omega`.
    public func typedOmega() throws -> PCAIntentOmega.Omega { try PCAIntentOmega.omegaFromJson(omegaSource) }

    public init(omega json: JSONValue?, options: Options = Options()) throws {
        omega = try WalletOmega(json)
        omegaSource = json
        omegaApprox = json?.get("approximate")?.asArray?.compactMap { $0.asString }
        opts = options
        eta = options.eta ?? 0
        guard eta >= 0 && eta < 0.5 else { throw JSError("pca-intent: eta must be in [0, 0.5)") }
        etaPos = options.etaPos ?? eta
        etaNeg = options.etaNeg ?? eta
        guard etaPos >= 0 && etaPos < 0.5 && etaNeg >= 0 && etaNeg < 0.5 else { throw JSError("pca-intent: etaPos and etaNeg must be in [0, 0.5)") }
        noisy = etaPos != 0 || etaNeg != 0
        tau = options.tau ?? (noisy ? 0.95 : 1)
        risk = options.strategy == "risk"
        strategy = options.strategy ?? "disagreement"
        hypothesisClass = options.hypothesisClass
        if let s = options.agnosticSlack {
            guard Self.isInteger(s), s >= 0 else { throw JSError("pca-intent: agnosticSlack must be a non-negative integer") }
            guard !noisy else { throw JSError("pca-intent: agnostic selection replaces the noise model; use eta = 0") }
            agnosticSlack = Int(s)
        } else { agnosticSlack = nil }
        models = try omega.verbs.map { try Self.buildVerbModel($0, options, harm) }
        try initPrior()
    }

    private func decay() -> Double? {
        switch hypothesisClass {
        case .box: return 1
        case let .union(_, d): return d ?? 0.25
        case let .decisionList(_, d, _): return d ?? 0.25
        }
    }

    private static func normalize(_ w: inout [Double]) {
        var s = 0.0
        for x in w { s += x }
        if s > 0 { for i in w.indices { w[i] = w[i] / s } }
    }

    private func initPrior() throws {
        var anchors = (opts.anchor.map { [$0] } ?? []) + opts.anchors
        anchors = anchors.filter { $0.lambda > 0 }
        let admitters = try anchors.map { (adm: try PCAIntentAdmitter($0.policy), lambda: $0.lambda) }
        guard let dec = decay(), dec > 0 && dec <= 1 else { throw JSError("pca-intent: decay must be in (0, 1]") }
        for m in models {
            let nm = opts.nullMassFn?(m.vs) ?? opts.nullMass ?? 0.2
            guard nm >= 0 && nm <= 1 else { throw JSError("pca-intent: nullMass must be in [0, 1]") }
            m.w[0] = nm
            var z = 0.0
            if m.nh > 1 {
                for h in 1..<m.nh {
                    let raw = m.complexity.map { pow(dec, Double($0[h] - 1)) } ?? 1
                    m.w[h] = raw
                    z += raw
                }
                for h in 1..<m.nh { m.w[h] = ((1 - nm) * m.w[h]) / (z != 0 ? z : 1) }
            }
            if let mono = opts.monotone { try applyMonotone(m, mono.paths, mono.offMass) }
            if !admitters.isEmpty {
                var tot = 0.0
                for c in 0..<m.nCells { tot += m.mass[c] }
                let accs: [[UInt8]] = admitters.map { a in
                    (0..<m.nCells).map { c in a.adm.admits(m.vs, LM.cellRep(m.vs, LM.decodeCell(m.vs, c))) ? 1 : 0 }
                }
                for h in 0..<m.nh {
                    var mix = 0.0
                    for (i, acc) in accs.enumerated() {
                        var dist = 0.0
                        for c in 0..<m.nCells {
                            let inH: UInt8 = h == 0 ? 0 : (Self.holds(m, h, c) ? 1 : 0)
                            if inH != acc[c] { dist += m.mass[c] }
                        }
                        mix += FdLibm.exp((-admitters[i].lambda * dist) / (tot != 0 ? tot : 1))
                    }
                    m.w[h] = m.w[h] * (mix / Double(accs.count))
                }
            }
            Self.normalize(&m.w)
            if let pm = opts.priorMix { try mixPrior(m, pm.beta, pm.weight) }
            m.prior = m.w
            m.dirty = true
        }
    }

    private func applyMonotone(_ m: VerbModel, _ paths: [String], _ offMass: Double?) throws {
        let off = offMass ?? 0
        guard off >= 0 && off <= 1 else { throw JSError("pca-intent: monotone.offMass must be in [0, 1]") }
        let D = m.vs.dims.count
        let ks = m.vs.dims.enumerated().compactMap { (k, d) in d.isNum && paths.contains(where: { IV.same($0, d.path) }) ? k : nil }
        if ks.isEmpty { return }
        let stride = ks.map { k in m.nCellsD[(k + 1)...].reduce(1, *) }
        if m.nh <= 1 { return }
        for h in 1..<m.nh {
            var isMono = true
            var c = 0
            while c < m.nCells && isMono {
                if Self.holds(m, h, c) {
                    for i in ks.indices where Int(m.cellIdx[c * D + ks[i]]) > 0 && !Self.holds(m, h, c - stride[i]) { isMono = false; break }
                }
                c += 1
            }
            if !isMono { m.w[h] = m.w[h] * off }
        }
    }

    private func mixPrior(_ m: VerbModel, _ beta: Double, _ weight: (WalletVerb, (Int) -> Bool) throws -> Double) throws {
        guard beta >= 0 && beta < 1 else { throw JSError("pca-intent: priorMix.beta must be in [0, 1)") }
        var pop = [Double](repeating: 0, count: m.nh)
        var z = 0.0
        for h in 0..<m.nh {
            let x = try weight(m.vs) { c in h != 0 && c >= 0 && c < m.nCells && Self.holds(m, h, c) }
            guard x.isFinite && x >= 0 else { throw JSError("pca-intent: priorMix.weight must be finite and >= 0") }
            pop[h] = x
            z += x
        }
        if !(z > 0) { return }
        for h in 0..<m.nh { m.w[h] = (1 - beta) * m.w[h] + (beta * pop[h]) / z }
    }

    private func inGrant(_ m: VerbModel, _ c: Int) -> Bool { m.veto[c] == 0 && m.p[c] >= tau - 1e-12 }

    private func model(_ verb: String) -> VerbModel? { models.first { IV.same($0.vs.verb, verb) } }

    private func refresh(_ m: VerbModel) {
        if !m.dirty { return }
        for c in 0..<m.nCells { m.p[c] = 0 }
        // certainty is decided combinatorially: p = 1 iff every live hypothesis contains the cell, p = 0 iff none does
        var anyIn = [Bool](repeating: false, count: m.nCells), anyOut = [Bool](repeating: false, count: m.nCells)
        var live = false
        for h in 0..<m.nh {
            let w = m.w[h]
            if w == 0 { continue }
            live = true
            for c in 0..<m.nCells {
                if h > 0 && Self.holds(m, h, c) { m.p[c] += w; anyIn[c] = true } else { anyOut[c] = true }
            }
        }
        for c in 0..<m.nCells { m.p[c] = !live || !anyIn[c] ? 0 : (!anyOut[c] ? 1 : min(1, max(0, m.p[c]))) }
        m.dirty = false
    }

    static func flat(_ m: VerbModel, _ idx: [Int]) -> Int {
        var f = 0
        for d in 0..<idx.count { f = f * m.nCellsD[d] + idx[d] }
        return f
    }

    /// p_n(outcome) (0 outside the outcome space: the conservative reading).
    public func acceptance(_ o: JSONValue) -> Double {
        guard let m = model(o.get("verb")?.asString ?? "\u{0}"), let idx = LM.cellOf(m.vs, values: o.get("values")) else { return 0 }
        refresh(m)
        return m.p[Self.flat(m, idx)]
    }

    public func admitsOutcome(_ o: JSONValue) -> Bool {
        guard let m = model(o.get("verb")?.asString ?? "\u{0}"), let idx = LM.cellOf(m.vs, values: o.get("values")) else { return false }
        refresh(m)
        return inGrant(m, Self.flat(m, idx))
    }

    public func isVetoed(_ o: JSONValue) -> Bool {
        guard let m = model(o.get("verb")?.asString ?? "\u{0}"), let idx = LM.cellOf(m.vs, values: o.get("values")) else { return false }
        return m.veto[Self.flat(m, idx)] == 1
    }

    public func vetoedCells() -> [String] {
        var out: [String] = []
        for m in models { for c in 0..<m.nCells where m.veto[c] != 0 { out.append("\(m.vs.verb)|\(c)") } }
        return out
    }

    static func holdsAll(_ m: VerbModel, _ h: Int, _ cells: [Int]) -> Bool {
        if h == 0 { return false }
        for c in cells where !holds(m, h, c) { return false }
        return true
    }

    /// Records the answer y (0 or 1) to "should this outcome (or every outcome of the region) be allowed?" and updates the posterior.
    /// Returns nil when the outcome is outside the outcome space or the region covers no cell.
    @discardableResult
    public func observe(_ o: JSONValue, y: Int, source: String = "elicitation", region: JSONValue? = nil) throws -> Observation? {
        guard y == 0 || y == 1 else { throw JSError("pca-intent: an answer is 0 or 1") }
        guard let verb = o.get("verb")?.asString, let m = model(verb), let idx = LM.cellOf(m.vs, values: o.get("values")) else { return nil }
        let cells = try region.map { try PCAIntentRegion.cells(m.vs, $0, inner: y == 1) } ?? [Self.flat(m, idx)]
        if cells.isEmpty { return nil }
        refresh(m)
        var obs = Observation(verb: verb, values: o.get("values") ?? .object([:]), cell: idx, y: y, source: source, region: region)
        var regionP = 0.0
        if m.nh > 1 { for h in 1..<m.nh where m.w[h] > 0 && Self.holdsAll(m, h, cells) { regionP += m.w[h] } }
        let contradictsAll = y == 0 ? regionP >= 1 - 1e-12 : regionP <= 1e-12
        if source == "runtime" && y == 0 { for c in cells { m.veto[c] = 1 } }
        for c in cells { m.seen[c] = 1 }
        if let slack = agnosticSlack {
            for h in 0..<m.nh where (Self.holdsAll(m, h, cells) ? 1 : 0) != y { m.err[h] += 1 }
            var minErr = Int.max
            for h in 0..<m.nh where m.prior[h] > 0 { minErr = min(minErr, m.err[h]) }
            for h in 0..<m.nh { m.w[h] = minErr == Int.max || m.err[h] <= minErr + slack ? m.prior[h] : 0 }
            Self.normalize(&m.w)
            if contradictsAll {
                obs.conflict = true
                if y == 0 { for c in cells { m.veto[c] = 1 } }
            }
        } else {
            let prev: [Double]? = etaPos == 0 || etaNeg == 0 ? m.w : nil
            func lik(_ inH: Int) -> Double { inH == 1 ? (y == 1 ? 1 - etaNeg : etaNeg) : (y == 1 ? etaPos : 1 - etaPos) }
            var sum = 0.0
            for h in 0..<m.nh {
                m.w[h] = m.w[h] * lik(Self.holdsAll(m, h, cells) ? 1 : 0)
                sum += m.w[h]
            }
            if sum == 0, let p = prev {
                m.w = p
                obs.conflict = true
                if y == 0 { for c in cells { m.veto[c] = 1 } }
            } else { Self.normalize(&m.w) }
        }
        m.dirty = true
        observations.append(obs)
        return obs
    }

    public struct CellView {
        public var verb: String, cell: [Int], p: Double, mass: Double, harm: Double, inGrant: Bool, vetoed: Bool
        public var json: JSONValue {
            .object(["verb": .string(verb), "cell": .array(cell.map { .int(Int64($0)) }), "p": .double(p), "mass": .double(mass), "harm": .double(harm),
                     "inGrant": .bool(inGrant), "vetoed": .bool(vetoed)])
        }
    }

    public func cells() -> [CellView] {
        var out: [CellView] = []
        for m in models {
            refresh(m)
            for c in 0..<m.nCells {
                out.append(CellView(verb: m.vs.verb, cell: LM.decodeCell(m.vs, c), p: m.p[c], mass: m.mass[c], harm: m.harm[c], inGrant: inGrant(m, c), vetoed: m.veto[c] == 1))
            }
        }
        return out
    }

    public func metrics() -> Metrics {
        var R = 0.0, B = 0.0, U = 0.0, H = 0.0, vs = 0.0, dis = 0.0, meanHarm = 0.0
        for m in models {
            refresh(m)
            for c in 0..<m.nCells {
                let p = m.p[c], mu = m.mass[c]
                meanHarm += mu * m.harm[c]
                if inGrant(m, c) { R += mu * (1 - p) * m.harm[c] } else { B += mu * p }
                U += mu * min(p, 1 - p)
                if p > 1e-12 && p < 1 - 1e-12 { dis += mu }
            }
            var alive = 0
            for h in 0..<m.nh {
                let w = m.w[h]
                if w > 0 { alive += 1; H -= w * FdLibm.log2(w) }
            }
            vs += FdLibm.log2(Double(max(1, alive)))
        }
        var r = Metrics()
        r.residualRisk = R; r.burden = B; r.uncertainty = U; r.entropyBits = H
        r.log2VersionSpace = noisy ? nil : vs
        r.disagreementMass = dis; r.meanHarm = meanHarm
        r.questions = observations.filter { $0.source == "elicitation" }.count
        r.conflicts = observations.filter { $0.conflict }.count
        return r
    }

    /// The next question: argmax expected information (x mu*h for the risk strategy); nil when nothing is uncertain.
    public func nextQuestion() -> Question? {
        var best: Question?
        let hPos = Self.binEnt(etaPos), hNeg = Self.binEnt(etaNeg)
        for m in models {
            refresh(m)
            for c in 0..<m.nCells {
                if m.veto[c] != 0 { continue }
                let p = m.p[c]
                if p <= 1e-9 || p >= 1 - 1e-9 { continue }
                let pe = p * (1 - etaNeg) + (1 - p) * etaPos
                var score = Self.binEnt(pe) - (etaPos == etaNeg ? hPos : p * hNeg + (1 - p) * hPos)
                if risk { score *= m.mass[c] * m.harm[c] }
                if score <= 1e-15 { continue }
                if best == nil || score > best!.score + 1e-12 {
                    let cell = LM.decodeCell(m.vs, c)
                    best = Question(verb: m.vs.verb, cell: cell, outcome: LM.cellRep(m.vs, cell), p: p, score: score)
                }
            }
        }
        return best
    }

    /// Grant cells inferred (via the hull of other answers) but never directly observed, most consequential first.
    public func unconfirmedGrantCells() -> [(verb: String, cell: [Int], weight: Double)] {
        var out: [(verb: String, cell: [Int], weight: Double)] = []
        for m in models {
            refresh(m)
            for c in 0..<m.nCells where m.seen[c] == 0 && inGrant(m, c) { out.append((m.vs.verb, LM.decodeCell(m.vs, c), m.mass[c] * m.harm[c])) }
        }
        // a stable sort by descending weight (the reference's Array#sort is stable)
        return out.enumerated().sorted { $0.element.weight != $1.element.weight ? $0.element.weight > $1.element.weight : $0.offset < $1.offset }.map { $0.element }
    }

    /// The conservative grant as a policy: allow only the cells with p_n >= tau that are not vetoed.
    public func synthesize() -> JSONValue {
        var predicates: [JSONValue] = []
        let order = ["reversible", "rate_limited", "irreversible"]
        var worst = -1
        for m in models {
            refresh(m)
            var allowed = [UInt8](repeating: 0, count: m.nCells)
            var any = false
            for c in 0..<m.nCells where inGrant(m, c) { allowed[c] = 1; any = true }
            if !any { continue }
            worst = max(worst, order.firstIndex(where: { IV.same($0, m.vs.reversibility) }) ?? -1)
            predicates += Self.boxesToPredicates(m.vs, allowed)
        }
        let caveats: [JSONValue] = worst >= 0 ? [.object(["type": .string("reversibility_max"), "class": .string(order[worst])])] : []
        return .object(["predicates": .array(predicates), "caveats": .array(caveats)])
    }

    /// Replays observations onto a fresh learner.
    public static func replay(omega: JSONValue?, options: Options, observations: [Observation]) throws -> PCAIntentLearner {
        let l = try PCAIntentLearner(omega: omega, options: options)
        for o in observations { try l.observe(.object(["verb": .string(o.verb), "values": o.values]), y: o.y, source: o.source, region: o.region) }
        return l
    }

    // MARK: synthesis: allowed cells -> boxes -> predicates

    struct Box {
        var lo: [Int], hi: [Int]       // numeric dimensions (unused for categorical)
        var sets: [[Int]]              // categorical value sets, in insertion order (a JS Set iterates in insertion order)
    }

    static func boxCells(_ vs: WalletVerb, _ box: Box) -> [[Int]] {
        var acc: [[Int]] = [[]]
        for (k, d) in vs.dims.enumerated() {
            let vals: [Int] = d.isNum ? Array(box.lo[k]...max(box.lo[k], box.hi[k])) : box.sets[k].sorted()
            let count = d.isNum ? max(0, box.hi[k] - box.lo[k] + 1) : vals.count
            let use = Array(vals.prefix(count))
            acc = acc.flatMap { pre in use.map { pre + [$0] } }
        }
        return acc
    }

    static func encode(_ vs: WalletVerb, _ idx: [Int]) -> Int {
        var f = 0
        for (i, d) in vs.dims.enumerated() { f = f * LM.cellCount(d) + idx[i] }
        return f
    }

    static func cond(_ field: String, _ op: String, _ value: JSONValue) -> JSONValue { .object(["field": .string(field), "op": .string(op), "value": value]) }

    static func catCondition(_ d: WalletDim, _ S: [Int]) -> JSONValue? {
        if S.count == d.values.count { return nil }
        let exacts = d.values.filter { $0.kind == "exact" }.map { $0.value }
        let prefixes = d.values.filter { $0.kind == "prefix" }.map { $0.value }
        var alts: [JSONValue] = []
        let allowedExacts = S.map { d.values[$0] }.filter { $0.kind == "exact" }.map { $0.value }
        if allowedExacts.count == 1 { alts.append(cond(d.path, "eq", .string(allowedExacts[0]))) }
        else if allowedExacts.count > 1 { alts.append(cond(d.path, "in", .array(allowedExacts.map { .string($0) }))) }
        for i in S.sorted() {
            let v = d.values[i]
            if v.kind == "exact" { continue }
            var parts: [JSONValue] = []
            if v.kind == "prefix" {
                parts.append(cond(d.path, "prefix", .string(v.value)))
                let under = exacts.filter { IV.startsWith($0, v.value) }
                if !under.isEmpty { parts.append(cond(d.path, "nin", .array(under.map { .string($0) }))) }
                for q in prefixes where !IV.same(q, v.value) && IV.startsWith(q, v.value) {
                    parts.append(.object(["not": cond(d.path, "prefix", .string(q))]))
                }
            } else {
                if !exacts.isEmpty { parts.append(cond(d.path, "nin", .array(exacts.map { .string($0) }))) }
                for q in prefixes { parts.append(.object(["not": cond(d.path, "prefix", .string(q))])) }
            }
            if parts.count == 1 { alts.append(parts[0]) } else if parts.count > 1 { alts.append(.object(["all_of": .array(parts)])) }
        }
        if alts.isEmpty { return nil }
        return alts.count == 1 ? alts[0] : .object(["any_of": .array(alts)])
    }

    static func boxToPredicate(_ vs: WalletVerb, _ box: Box) -> JSONValue {
        var where_: [JSONValue] = []
        for (k, d) in vs.dims.enumerated() {
            if d.isNum {
                let cells = LM.numCells(d)
                where_.append(cond(d.path, "gte", .int(Int64(cells[box.lo[k]].lo))))
                where_.append(cond(d.path, "lte", .int(Int64(cells[box.hi[k]].hi))))
            } else if let c = catCondition(d, box.sets[k]) { where_.append(c) }
        }
        var o: JObject = ["verb": .string(vs.verb), "resource": .string("*")]
        if !where_.isEmpty { o["where"] = .array(where_) }
        return .object(o)
    }

    /// Covers the allowed cell set exactly with greedily grown maximal boxes; one predicate per box.
    public static func boxesToPredicates(_ vs: WalletVerb, _ allowed: [UInt8]) -> [JSONValue] {
        var covered = [Bool](repeating: false, count: allowed.count)
        var out: [JSONValue] = []
        func ok(_ i: Int) -> Bool { i >= 0 && i < allowed.count && allowed[i] == 1 }
        func all(_ b: Box) -> Bool { boxCells(vs, b).allSatisfy { ok(encode(vs, $0)) } }
        for c in 0..<allowed.count {
            if allowed[c] == 0 || covered[c] { continue }
            let idx = LM.decodeCell(vs, c)
            var box = Box(lo: idx, hi: idx, sets: idx.map { [$0] })
            for (k, d) in vs.dims.enumerated() {
                if d.isNum {
                    let n = LM.cellCount(d)
                    while box.hi[k] + 1 < n {
                        box.hi[k] += 1
                        if !all(box) { box.hi[k] -= 1; break }
                    }
                    while box.lo[k] > 0 {
                        box.lo[k] -= 1
                        if !all(box) { box.lo[k] += 1; break }
                    }
                } else {
                    for v in 0..<d.values.count {
                        if box.sets[k].contains(v) { continue }
                        box.sets[k].append(v)
                        if !all(box) { box.sets[k].removeLast() }
                    }
                }
            }
            for bi in boxCells(vs, box) { let e = encode(vs, bi); if e >= 0 && e < covered.count { covered[e] = true } }
            out.append(boxToPredicate(vs, box))
        }
        return out
    }

    // MARK: elicitation loop

    public struct ElicitOptions {
        public var epsRisk: Double, epsBurden: Double, maxQuestions: Double
        public var audit = false
        public var seed: [(verb: String, cell: [Int])] = []
        public init(epsRisk: Double, epsBurden: Double, maxQuestions: Double) { self.epsRisk = epsRisk; self.epsBurden = epsBurden; self.maxQuestions = maxQuestions }
    }

    public struct ElicitResult {
        public var stop: String
        public var questions: Int, auditQuestions: Int, seedQuestions: Int
        public var asked: [Question]
    }

    func seedQuestion(_ s: (verb: String, cell: [Int])) throws -> Question? {
        guard let vs = omega.verbs.first(where: { IV.same($0.verb, s.verb) }), s.cell.count == vs.dims.count else { return nil }
        for (k, d) in vs.dims.enumerated() where s.cell[k] < 0 || s.cell[k] >= LM.cellCount(d) { throw JSError("pca-intent: seed cell out of range") }
        let outcome = LM.cellRep(vs, s.cell)
        let p = acceptance(outcome)
        if p <= 1e-9 || p >= 1 - 1e-9 || isVetoed(outcome) { return nil }
        return Question(verb: s.verb, cell: s.cell, outcome: outcome, p: p, score: 0)
    }

    public func elicit(_ answer: (Question) -> Int, _ o: ElicitOptions) throws -> ElicitResult {
        var asked: [Question] = []
        var seedQuestions = 0
        for s in o.seed {
            if !(Double(asked.count) < o.maxQuestions) { break }
            let m = metrics()
            if m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden { break }
            guard let q = try seedQuestion(s) else { continue }
            try observe(q.outcome, y: answer(q), source: "elicitation")
            asked.append(q)
            seedQuestions += 1
        }
        var stop: String?
        while stop == nil {
            let m = metrics()
            if m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden { stop = "converged" }
            else if !(Double(asked.count) < o.maxQuestions) { stop = "budget" }
            else if let q = nextQuestion() {
                try observe(q.outcome, y: answer(q), source: "elicitation")
                asked.append(q)
            } else { stop = "no-disagreement" }
        }
        let a = try auditRound(answer, o, &asked)
        if a.exhausted { stop = "budget" }
        return ElicitResult(stop: stop!, questions: asked.count, auditQuestions: a.asked, seedQuestions: seedQuestions, asked: asked)
    }

    /// The audit round: asks about unconfirmed grant cells until their total weight is within epsRisk (or the budget ends).
    public func auditRound(_ answer: (Question) -> Int, _ o: ElicitOptions, _ asked: inout [Question]) throws -> (asked: Int, exhausted: Bool) {
        var n = 0
        if !o.audit { return (0, false) }
        while true {
            let pending = unconfirmedGrantCells()
            var mass = 0.0
            for x in pending { mass += x.weight }
            if pending.isEmpty || mass <= o.epsRisk { return (n, false) }
            if !(Double(asked.count) < o.maxQuestions) { return (n, true) }
            let top = pending[0]
            guard let vs = omega.verbs.first(where: { IV.same($0.verb, top.verb) }) else { throw JSError("pca-intent: no such verb") }
            let rep = LM.cellRep(vs, top.cell)
            let q = Question(verb: top.verb, cell: top.cell, outcome: rep, p: acceptance(rep), score: top.weight)
            try observe(q.outcome, y: answer(q), source: "elicitation")
            asked.append(q)
            n += 1
        }
    }
}
