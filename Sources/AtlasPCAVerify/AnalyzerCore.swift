import Foundation

/// Static analyzability of authority (the policy analyzer): a SOUND, BOUNDED decision procedure over PCA's predicate / caveat policy.
/// It enumerates a finite, distinguishing set of representative actions built from the literals, thresholds, prefixes, verbs and
/// resource matchers in the policies, and evaluates the real predicate evaluator at each, so reachability, vacuity, totality,
/// subsumption, disjointness and equivalence are exact for the decided fragment; anything outside it (a `re:` resource, a cross-field
/// `ref`, a grid over the bound) fails safe and is marked `approximate`.
///
/// Policies, actions and results are plain JSON trees (`JSONValue`); a missing member is `nil` (JavaScript `undefined`), `.null` is
/// `null`. A reference TypeError (a property read of null / undefined, a call on a non-function) is a thrown `JSError`.
public enum PCAAnalyzer {
    public typealias V = JSONValue

    static let REVERSIBILITY_ORDER = ["reversible", "rate_limited", "irreversible"]
    /// A sentinel string guaranteed not to equal, be a prefix of, or be prefixed by any policy literal.
    static let FRESH_STRING = "\u{0}atlas-analyzer::fresh-unmatched\u{0}"
    static let FRESH_VERB = "\u{0}atlas-analyzer::fresh-verb\u{0}"
    static let FRESH_RESOURCE = "\u{0}atlas-analyzer::fresh-resource\u{0}"
    /// Default cap on the representative grid size (product of all dimensions).
    public static let DEFAULT_MAX_COMBINATIONS = 200_000.0

    // ---- JS value helpers ----

    /// `x.k` for a possibly absent x: never throws, nil for anything without that member.
    static func mem(_ x: V?, _ k: String) -> V? { JSLoose.get(x, k) }
    /// `x.k` where x must not be null / undefined (a TypeError otherwise).
    static func rd(_ x: V?, _ k: String) throws -> V? { try JSLoose.rd(x, k) }
    /// `typeof v === 'number' && Number.isFinite(v)`.
    static func fin(_ v: V?) -> Double? {
        guard let d = IV.num(v), d.isFinite else { return nil }
        return d
    }
    /// A number as JSON: an integral value in the safe range as an integer, else a binary64 (an infinity stays one).
    static func num(_ d: Double) -> V { d == d.rounded() && abs(d) <= Double(Canonical.MAX_SAFE) ? .int(Int64(d)) : .double(d) }
    static func strs(_ xs: [String]) -> V { .array(xs.map { .string($0) }) }
    /// `x !== null && typeof x === 'object' && !Array.isArray(x)`.
    static func isObjRec(_ x: V?) -> Bool { x?.isObject ?? false }
    /// `'k' in x` for a plain object.
    static func inObj(_ x: V?, _ k: String) -> Bool { x?.asObject?[JKey(k)] != nil }
    /// A list member that must be an array to count (`Array.isArray(x) ? x : []`).
    static func arr(_ x: V?) -> [V] { x?.asArray ?? [] }
    static func same(_ a: V?, _ b: V?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?): return x == y
        default: return false
        }
    }
    /// `[...new Set(xs)]` over strings, first-seen order.
    static func uniq(_ xs: [String]) -> [String] { PCADataflow.distinct(xs) }
    static func obj(_ pairs: [(String, V?)]) -> V {
        var o: JObject = [:]
        for (k, v) in pairs { if let v = v { o[JKey(k)] = v } }
        return .object(o)
    }

    /// A reference-side refusal (a TypeError).
    static func fail(_ m: String) -> JSError { JSError(m) }

    /// The `isGroupCondition` test: an object with all_of / any_of / not.
    static func isGroup(_ c: V?) -> Bool { isObjRec(c) && (inObj(c, "all_of") || inObj(c, "any_of") || inObj(c, "not")) }
    /// The `isLeafCondition` test: a non-group object whose `field` is a string.
    static func isLeaf(_ c: V?) -> Bool { isObjRec(c) && !isGroup(c) && mem(c, "field")?.asString != nil }

    // ---- caveats (static satisfiability of the envelope caveat set) ----

    public struct CaveatAnalysis {
        public var sat: Bool
        public var reason: String?
        /// Strictest `reversibility_max` cap as an index into REVERSIBILITY_ORDER.
        public var revCap: Int?
        public init(sat: Bool, reason: String? = nil, revCap: Int? = nil) { self.sat = sat; self.reason = reason; self.revCap = revCap }
        public var json: V {
            var o: [(String, V?)] = [("sat", .bool(sat)), ("reason", reason.map { .string($0) })]
            if let c = revCap { o.append(("revCap", .int(Int64(c)))) }
            return obj(o)
        }
    }

    public static func analyzeCaveats(_ caveats: V?) -> CaveatAnalysis {
        guard case let .array(list)? = caveats else { return CaveatAnalysis(sat: false, reason: "caveats are not an array", revCap: nil) }
        var notBeforeMax = -Double.infinity, expiresMin = Double.infinity
        var revCap: Int?
        func unsat(_ r: String) -> CaveatAnalysis { CaveatAnalysis(sat: false, reason: r, revCap: nil) }
        for cv in list {
            guard case let .object(o) = cv, let type = o["type"]?.asString else { return unsat("malformed caveat (not an object with a string type)") }
            switch type {
            case "expires":
                guard let at = fin(o["at"]) else { return unsat("expires.at is not a finite number") }
                expiresMin = min(expiresMin, at)
            case "not_before":
                guard let at = fin(o["at"]) else { return unsat("not_before.at is not a finite number") }
                notBeforeMax = max(notBeforeMax, at)
            case "rate":
                guard let mx = fin(o["max"]), let per = fin(o["per_secs"]), per > 0 else { return unsat("rate caveat requires finite max and per_secs > 0") }
                if mx < 1 { return unsat("rate.max \(JS.number(mx)) < 1 forbids every action") }
            case "max_blast_radius":
                guard let mx = fin(o["max"]) else { return unsat("max_blast_radius.max is not a finite number") }
                if mx < 0 { return unsat("max_blast_radius.max < 0 forbids every action") }
            case "reversibility_max":
                let cls = JS.toString(o["class"])
                guard let idx = REVERSIBILITY_ORDER.firstIndex(where: { IV.same($0, cls) }) else { return unsat("reversibility_max.class '\(cls)' is unknown") }
                revCap = revCap.map { min($0, idx) } ?? idx
            case "delegation_depth":
                guard let mx = fin(o["max"]) else { return unsat("delegation_depth.max is not a finite number") }
                if mx < 0 { return unsat("delegation_depth.max < 0 forbids every action") }
            case "budget_alloc":
                guard let lim = fin(o["limit"]), lim >= 0 else { return unsat("budget_alloc.limit must be a finite number >= 0") }
            default:
                return unsat("unknown caveat type '\(type)' (fail closed)")
            }
        }
        if notBeforeMax != -.infinity && expiresMin != .infinity && notBeforeMax >= expiresMin {
            return unsat("not_before (\(JS.number(notBeforeMax))) >= expires (\(JS.number(expiresMin))): the validity window is empty")
        }
        return CaveatAnalysis(sat: true, reason: nil, revCap: revCap)
    }

    // ---- constitution vetoes ----

    /// The stateless invariants of a constitution in analyzable form; `unmodeled` lists those the enumeration cannot model.
    public static func vetoesFromConstitution(_ c: JSONValue?) throws -> JSONValue {
        var vetoes: [V] = [], unmodeled: [V] = []
        let invs = mem(c, "invariants")
        for inv in arr(invs) {
            let id = try rd(inv, "id"), kind = try rd(inv, "kind")
            switch kind?.asString {
            case "never": vetoes.append(obj([("id", id), ("kind", .string("deny")), ("when", try rd(inv, "when"))]))
            case "never_unless": vetoes.append(obj([("id", id), ("kind", .string("deny")), ("when", try rd(inv, "when")), ("unless", try rd(inv, "unless"))]))
            case "require_approval_over":
                vetoes.append(obj([("id", id), ("kind", .string("approval")), ("when", try rd(inv, "when")),
                                   ("over", obj([("path", try rd(inv, "amount")), ("threshold", try rd(inv, "threshold"))])), ("unless", try rd(inv, "approved"))]))
            case "cap", "rate":
                unmodeled.append(obj([("id", id), ("kind", kind), ("reason", .string("windowed total: bounded by maxExposure, not by a per-action veto"))]))
            default:
                unmodeled.append(obj([("id", id), ("kind", kind), ("reason", .string("needs action history"))]))
            }
        }
        return obj([("vetoes", .array(vetoes)), ("unmodeled", .array(unmodeled))])
    }

    // ---- the interval + finite-set engine for one field ----

    public struct Interval {
        public var lo: Double, loInc: Bool, hi: Double, hiInc: Bool
        public init(lo: Double, loInc: Bool, hi: Double, hiInc: Bool) { self.lo = lo; self.loInc = loInc; self.hi = hi; self.hiInc = hiInc }
        public static let full = Interval(lo: -.infinity, loInc: false, hi: .infinity, hiInc: false)
        public var json: V { .object(["lo": .double(lo), "loInclusive": .bool(loInc), "hi": .double(hi), "hiInclusive": .bool(hiInc)]) }
    }

    public static func tightenInterval(_ iv: Interval, _ op: V?, _ value: V?) -> Interval {
        guard let v = fin(value) else { return iv }
        var n = iv
        switch op?.asString {
        case "eq":
            if v > n.lo || (v == n.lo && !n.loInc) { n.lo = v; n.loInc = true }
            if v < n.hi || (v == n.hi && !n.hiInc) { n.hi = v; n.hiInc = true }
        case "gte": if v > n.lo { n.lo = v; n.loInc = true }
        case "gt": if v > n.lo || (v == n.lo && n.loInc) { n.lo = v; n.loInc = false }
        case "lte": if v < n.hi { n.hi = v; n.hiInc = true }
        case "lt": if v < n.hi || (v == n.hi && n.hiInc) { n.hi = v; n.hiInc = false }
        default: break
        }
        return n
    }

    public static func intervalEmpty(_ iv: Interval) -> Bool {
        if iv.lo > iv.hi { return true }
        if iv.lo == iv.hi { return !(iv.loInc && iv.hiInc) }
        return false
    }

    /// Whether the numeric subset of a `where` conjunction is satisfiable (one interval per field).
    public static func numericConjunctionSatisfiable(_ conditions: [JSONValue]) -> Bool {
        var byField: [(String, Interval)] = []
        for c in conditions where isLeaf(c) && mem(c, "ref") == nil {
            let f = mem(c, "field")!.asString!
            if let i = byField.firstIndex(where: { IV.same($0.0, f) }) { byField[i].1 = tightenInterval(byField[i].1, mem(c, "op"), mem(c, "value")) }
            else { byField.append((f, tightenInterval(.full, mem(c, "op"), mem(c, "value")))) }
        }
        return !byField.contains { intervalEmpty($0.1) }
    }

    /// `typeof x + ':' + JSON.stringify(x)`, the de-duplication key of mixed-type probe values.
    static func valueKey(_ x: V) -> String {
        if case let .string(s) = x, IV.same(s, FRESH_STRING) { return "s:__fresh__" }
        let t: String
        switch x {
        case .int, .double: t = "number"
        case .string: t = "string"
        case .bool: t = "boolean"
        default: t = "object"
        }
        return t + ":" + JS.stringify(x)
    }

    static func numericCellReps(_ thresholds: [Double]) -> [Double] {
        var seen = Set<Double>(), s: [Double] = []
        for t in thresholds where t.isFinite && seen.insert(t == 0 ? 0 : t).inserted { s.append(t) }
        s.sort()
        guard let first = s.first, let last = s.last else { return [] }
        var out = [first - 1]
        for i in s.indices {
            out.append(s[i])
            if i + 1 < s.count { out.append((s[i] + s[i + 1]) / 2) }
        }
        out.append(last + 1)
        return out
    }

    /// The representative probe values of one field from the conjunction of `where` conditions on it (the caller adds `absent`).
    static func fieldProbes(_ conditions: [V]) -> [V] {
        var literals: [V] = [], thresholds: [Double] = [], prefixes: [String] = []
        for c in conditions where isLeaf(c) && mem(c, "ref") == nil {
            let v = mem(c, "value") ?? .null // a missing value is not in the corpus: read as null
            switch mem(c, "op")?.asString {
            case "eq", "ne":
                literals.append(v)
                if let d = fin(v) { thresholds.append(d) }
            case "in", "nin":
                if case let .array(xs) = v { for x in xs { literals.append(x); if let d = fin(x) { thresholds.append(d) } } }
            case "lt", "lte", "gt", "gte":
                if let d = fin(v) { thresholds.append(d) }
            case let op? where op == "prefix" || op == "like" || op == "matches" || op == "is_a":
                if case let .string(s) = v { literals.append(v); if op == "prefix" { prefixes.append(s) } }
            case "member_of":
                if case .string = v { literals.append(v) }
                else if case let .array(xs) = v { for x in xs where x.asString != nil { literals.append(x) } }
            default: break
            }
        }
        var out: [V] = [], seen = Set<JKey>()
        func add(_ x: V) { if seen.insert(JKey(valueKey(x))).inserted { out.append(x) } }
        for l in literals { add(l) }
        for n in numericCellReps(thresholds) { add(num(n)) }
        for p in prefixes { add(.string(p)); add(.string(p + "x")) }
        add(.string(FRESH_STRING))
        return out
    }

    // ---- policies -> models ----

    public final class Model {
        public var predicates: [V] = [], caveats: [V] = [], vetoes: [V] = [], tighten: [V] = []
        /// Policies that must also admit (a delegation chain: the ancestors); their static gates are folded into caveatSat / revCap.
        public var meets: [Model] = []
        public var caveatSat = false
        public var caveatReason: String?
        public var revCap: Int?
        /// Non-empty when the policy uses features the analyzer cannot decide exactly.
        public var undecidable: [String] = []
        public init() {}

        public var json: V {
            obj([("predicates", .array(predicates)), ("caveats", .array(caveats)), ("vetoes", .array(vetoes)), ("tighten", .array(tighten)),
                 ("meets", .array(meets.map { $0.json })), ("caveatSat", .bool(caveatSat)), ("caveatReason", caveatReason.map { .string($0) }),
                 ("revCap", revCap.map { .int(Int64($0)) }), ("undecidable", strs(undecidable))])
        }
    }

    /// A value that is not a policy is an empty policy (the verifier admits nothing under it).
    static func normalizePolicy(_ p: V?) -> (predicates: [V], caveats: [V], vetoes: [V], tighten: [V]) {
        guard let p = p, p.isObject else { return ([], [], [], []) }
        return (arr(mem(p, "predicates")), arr(mem(p, "caveats")), arr(mem(p, "vetoes")), arr(mem(p, "tighten")))
    }

    /// The predicates whose literals shape the representative grid: the permits plus every veto and tighten trigger.
    public static func probeSet(_ m: Model) throws -> [V] {
        var out = m.predicates
        for v in m.vetoes {
            out.append(try rd(v, "when") ?? .null)
            let unless = mem(v, "unless")
            if JS.truthy(mem(unless, "length")) { out.append(.object(["verb": .string("*"), "where": unless ?? .null])) }
            if let over = mem(v, "over"), JS.truthy(over) {
                out.append(.object(["verb": .string("*"), "where": .array([obj([("field", mem(over, "path")), ("op", .string("gt")), ("value", mem(over, "threshold"))])])]))
            }
        }
        for t in m.tighten { out.append(.object(["verb": .string("*"), "where": .array([try rd(t, "when") ?? .null])])) }
        for x in m.meets { out += try probeSet(x) }
        return out
    }

    static func conditionUndecidable(_ c: V?, _ reasons: inout [String]) {
        guard isObjRec(c) else { return }
        func add(_ r: String) { if !reasons.contains(where: { IV.same($0, r) }) { reasons.append(r) } }
        if isGroup(c) {
            if inObj(c, "all_of"), let a = mem(c, "all_of")?.asArray { for x in a { conditionUndecidable(x, &reasons) } }
            else if inObj(c, "any_of"), let a = mem(c, "any_of")?.asArray { for x in a { conditionUndecidable(x, &reasons) } }
            else if inObj(c, "not") { conditionUndecidable(mem(c, "not"), &reasons) }
            return
        }
        guard isLeaf(c) else { return }
        if mem(c, "ref") != nil { add("cross-field `ref` condition \u{2014} the relation between two fields is not resolved") }
        if IV.same(mem(c, "field")?.asString, "action.params") { add("condition on the whole `action.params` object is not enumerated precisely") }
        let op = mem(c, "op")?.asString
        if let o = op, ["lt", "lte", "gt", "gte"].contains(o), fin(mem(c, "value")) == nil {
            add("`\(o)` against a non-numeric operand \u{2014} string ordering is not enumerated exactly")
        }
        if let o = op, ["like", "matches", "is_a", "member_of"].contains(o) { add("`\(o)` condition \u{2014} matched by over-approximation, not enumerated exactly") }
    }

    static func detectUndecidable(_ predicates: [V]) -> [String] {
        var reasons: [String] = []
        for p in predicates where p.isObject || p.isArray {
            if let r = mem(p, "resource")?.asString, IV.startsWith(r, "re:") {
                let m = "re: regex resource matcher \u{2014} resource dimension cannot be soundly enumerated"
                if !reasons.contains(where: { IV.same($0, m) }) { reasons.append(m) }
            }
            if let w = mem(p, "where")?.asArray { for c in w { conditionUndecidable(c, &reasons) } }
        }
        return reasons
    }

    public static func toModel(_ p: V?) throws -> Model {
        let n = normalizePolicy(p)
        let ca = analyzeCaveats(.array(n.caveats))
        var meets: [Model] = []
        if let p = p, p.isObject, let ms = mem(p, "meet")?.asArray { meets = try ms.map { try toModel($0) } }
        let m = Model()
        m.predicates = n.predicates; m.caveats = n.caveats; m.vetoes = n.vetoes; m.tighten = n.tighten; m.meets = meets
        m.caveatSat = ca.sat && meets.allSatisfy { $0.caveatSat }
        m.caveatReason = ca.sat ? meets.first(where: { !$0.caveatSat })?.caveatReason : ca.reason
        m.revCap = ([ca.revCap] + meets.map { $0.revCap }).compactMap { $0 }.min()
        m.undecidable = uniq(detectUndecidable(try probeSet(m)) + meets.flatMap { $0.undecidable })
        return m
    }

    // ---- probe collection ----

    /// One probe value of a field: a concrete value, or "not set".
    public enum Cell { case absent, value(V) }

    public struct Probes {
        public var verbs: [V?]
        public var resources: [V?]
        /// A nil entry is "no reversibility dimension" (no policy sets a `reversibility_max`).
        public var revClasses: [V?]
        public var fields: [(path: String, values: [Cell])]
        public init(verbs: [V?], resources: [V?], revClasses: [V?], fields: [(path: String, values: [Cell])]) { self.verbs = verbs; self.resources = resources; self.revClasses = revClasses; self.fields = fields }
        public var json: V {
            obj([("verbs", .array(verbs.map { $0 ?? .null })), ("resources", .array(resources.map { $0 ?? .null })), ("revClasses", .array(revClasses.map { $0 ?? .null })),
                 ("fields", .array(fields.map { f in
                     .object(["path": .string(f.path), "values": .array(f.values.map { c in
                         switch c { case .absent: return .object(["$absent": .bool(true)]); case let .value(v): return v }
                     })])
                 }))])
        }
    }

    public struct ProbeInputs {
        public var predicateSets: [[V]]
        public var extraVerbs: [String] = []
        public var extraResources: [String] = []
        public var extraFieldConditions: [(path: String, cond: V)] = []
        /// Vary the reversibility class over all three classes (needed when any policy caps reversibility).
        public var varyReversibility: Bool
        public init(predicateSets: [[V]], extraVerbs: [String] = [], extraResources: [String] = [], extraFieldConditions: [(path: String, cond: V)] = [], varyReversibility: Bool) {
            self.predicateSets = predicateSets; self.extraVerbs = extraVerbs; self.extraResources = extraResources; self.extraFieldConditions = extraFieldConditions; self.varyReversibility = varyReversibility
        }
    }

    public static func collectProbes(_ inputs: ProbeInputs) throws -> Probes {
        var verbLiterals = uniq(inputs.extraVerbs)
        var resourceLiterals: [String] = []
        var fieldConds: [(path: String, conds: [V])] = []
        func addUniq(_ list: inout [String], _ s: String) { if !list.contains(where: { IV.same($0, s) }) { list.append(s) } }
        func classifyResource(_ r: V?) throws {
            guard let r = r else { return }
            guard case let .string(s) = r else { throw fail("r.startsWith is not a function") }
            if IV.same(s, "*") || IV.startsWith(s, "re:") { return }
            if IV.endsWith(s, "*") {
                let body = IV.text(Array(s.unicodeScalars.dropLast()))
                addUniq(&resourceLiterals, body); addUniq(&resourceLiterals, body + "x")
                return
            }
            addUniq(&resourceLiterals, s)
        }
        func handle(_ c: V?) throws {
            guard isObjRec(c) else { return }
            if isGroup(c) {
                if inObj(c, "all_of"), let a = mem(c, "all_of")?.asArray { for x in a { try handle(x) } }
                else if inObj(c, "any_of"), let a = mem(c, "any_of")?.asArray { for x in a { try handle(x) } }
                else if inObj(c, "not") { try handle(mem(c, "not")) }
                return
            }
            guard isLeaf(c) else { return }
            let field = mem(c, "field")!.asString!, op = mem(c, "op")?.asString, v = mem(c, "value")
            if IV.same(field, "action.verb") {
                if let o = op, ["eq", "ne", "prefix", "like", "is_a"].contains(o) { if let s = v?.asString { addUniq(&verbLiterals, s) } }
                else if op == "in" || op == "nin", let a = v?.asArray { for x in a { if let s = x.asString { addUniq(&verbLiterals, s) } } }
                return
            }
            if IV.same(field, "action.resource") {
                if op == "prefix", let s = v?.asString { try classifyResource(.string(s + "*")) }
                else if v?.asString != nil { try classifyResource(v) }
                else if let a = v?.asArray { for x in a where x.asString != nil { try classifyResource(x) } }
                return
            }
            if let i = fieldConds.firstIndex(where: { IV.same($0.path, field) }) { fieldConds[i].conds.append(c!) } else { fieldConds.append((field, [c!])) }
        }
        for list in inputs.predicateSets {
            for p in list {
                guard p.isObject || p.isArray else { continue }
                if let v = mem(p, "verb")?.asString { if !IV.same(v, "*") { addUniq(&verbLiterals, v) } }
                else if let a = mem(p, "verb")?.asArray { for x in a { if let s = x.asString, !IV.same(s, "*") { addUniq(&verbLiterals, s) } } }
                try classifyResource(mem(p, "resource"))
                if let w = mem(p, "where")?.asArray { for c in w { try handle(c) } }
            }
        }
        for r in inputs.extraResources { try classifyResource(.string(r)) }
        for ec in inputs.extraFieldConditions {
            var o = ec.cond.asObject ?? [:]
            o["field"] = .string(ec.path)
            try handle(.object(o))
        }
        let fields: [(path: String, values: [Cell])] = fieldConds.map { f in (f.path, fieldProbes(f.conds).map { Cell.value($0) } + [Cell.absent]) }
        return Probes(verbs: (verbLiterals + [FRESH_VERB]).map { V.string($0) }, resources: (resourceLiterals + [FRESH_RESOURCE]).map { V.string($0) },
                      revClasses: inputs.varyReversibility ? REVERSIBILITY_ORDER.map { Optional(V.string($0)) } : [nil], fields: fields)
    }

    static func productSize(_ pr: Probes) -> Double {
        var n = Double(pr.verbs.count) * Double(pr.resources.count) * Double(pr.revClasses.count)
        for f in pr.fields { n *= Double(f.values.count) }
        return n
    }

    // ---- representatives ----

    public struct Rep {
        public var verb: V?
        public var resource: V?
        public var revClass: V?
        /// Field path -> value in insertion order, absent fields excluded.
        public var assignments: [(path: String, value: V)]
        public init(verb: V?, resource: V?, revClass: V?, assignments: [(path: String, value: V)]) { self.verb = verb; self.resource = resource; self.revClass = revClass; self.assignments = assignments }
        public var assignmentsJson: V {
            var o: JObject = [:]
            for a in assignments { o[JKey(a.path)] = a.value }
            return .object(o)
        }
    }

    /// Walks the representative grid (verb, resource, reversibility, then each field in turn) until `body` returns true.
    @discardableResult
    static func eachRep(_ pr: Probes, _ body: (Rep) throws -> Bool) rethrows -> Bool {
        func fields(_ i: Int, _ acc: inout [(path: String, value: V)], _ yield: ([(path: String, value: V)]) throws -> Bool) rethrows -> Bool {
            if i == pr.fields.count { return try yield(acc) }
            let f = pr.fields[i]
            for c in f.values {
                switch c {
                case .absent: acc.removeAll { IV.same($0.path, f.path) }
                case let .value(v):
                    if let k = acc.firstIndex(where: { IV.same($0.path, f.path) }) { acc[k].value = v } else { acc.append((f.path, v)) }
                }
                if try fields(i + 1, &acc, yield) { return true }
            }
            return false
        }
        for verb in pr.verbs {
            for resource in pr.resources {
                for rev in pr.revClasses {
                    var acc: [(path: String, value: V)] = []
                    if try fields(0, &acc, { a in try body(Rep(verb: verb, resource: resource, revClass: rev, assignments: a)) }) { return true }
                }
            }
        }
        return false
    }

    // ---- context building + admission ----

    final class TNode {
        var leaf: V?
        var children: [JKey: TNode] = [:]
        init(leaf: V? = nil) { self.leaf = leaf }
        var isLeaf: Bool { leaf != nil }
    }

    static func insert(_ root: TNode, _ segs: [String], _ value: V) {
        var node = root
        for key in segs.dropLast() {
            if node.isLeaf { return }
            if let next = node.children[JKey(key)], !next.isLeaf { node = next }
            else { let created = TNode(); node.children[JKey(key)] = created; node = created }
        }
        if let last = segs.last, !node.isLeaf { node.children[JKey(last)] = TNode(leaf: value) }
    }

    static func materialize(_ n: TNode) -> JObject {
        var out: JObject = [:]
        if n.isLeaf { return out }
        for (k, c) in n.children { out[k] = c.isLeaf ? c.leaf! : .object(materialize(c)) }
        return out
    }

    /// The action / subject / env objects of a representative.
    static func buildRoots(_ rep: Rep) -> (action: JObject, subject: JObject, env: JObject) {
        let roots: [String: TNode] = ["action": TNode(), "subject": TNode(), "env": TNode()]
        for a in rep.assignments {
            let segs = IV.split(a.path, ".")
            guard segs.count >= 2, let root = roots[segs[0]] else { continue }
            insert(root, Array(segs.dropFirst()), a.value)
        }
        var action: JObject = ["params": .object([:])]
        if let v = rep.verb { action["verb"] = v }
        if let r = rep.resource { action["resource"] = r }
        let at = roots["action"]!
        if !at.isLeaf {
            for (key, child) in at.children {
                if key.s == "verb" || key.s == "resource" { continue }
                if key.s == "params" { if !child.isLeaf { action["params"] = .object(materialize(child)) } }
                else { action[key] = child.isLeaf ? child.leaf! : .object(materialize(child)) }
            }
        }
        if let rc = rep.revClass { action["reversibility_class"] = rc }
        let st = roots["subject"]!, en = roots["env"]!
        return (action, st.isLeaf ? [:] : materialize(st), en.isLeaf ? [:] : materialize(en))
    }

    static func ctx(_ r: (action: JObject, subject: JObject, env: JObject)) -> V {
        .object(["action": .object(r.action), "subject": .object(r.subject), "env": .object(r.env)])
    }

    static func reversibilityOk(_ m: Model, _ rev: V?) -> Bool {
        guard let cap = m.revCap else { return true }
        guard let s = rev?.asString else { return false } // a reversibility_max caveat denies an action with no class
        guard let idx = REVERSIBILITY_ORDER.firstIndex(where: { IV.same($0, s) }) else { return false }
        return idx <= cap
    }

    /// Does a veto apply to this action? Veto polarity: whatever cannot be decided counts as applying.
    public static func vetoApplies(_ v: JSONValue?, _ ctx: JSONValue) throws -> Bool {
        if !Prohibitions.whenMatches(try rd(v, "when"), ctx) { return false }
        if let over = try rd(v, "over"), JS.truthy(over) {
            let path = mem(over, "path")
            let found = path?.asString.flatMap { Predicates.resolve(ctx, $0) }
            var isOver = true
            if let x = found, let d = IV.num(x), d.isFinite, d >= 0 { isOver = JSLoose.gt(x, mem(over, "threshold")) }
            if !isOver { return false }
        }
        // for an approval veto `unless` is the evidence a human approved; an approved action is the escalated path, not an autonomous one
        if !IV.same(try rd(v, "kind")?.asString, "approval"), let u = try rd(v, "unless"), JS.truthy(u) {
            guard case let .array(list) = u else { throw fail("v.unless.every is not a function") }
            if list.allSatisfy({ Predicates.conditionTri($0, ctx, SafeRegex.Budget()) == .t }) { return false }
        }
        return true
    }

    /// The ternary decision of the permission layer at a concrete context: "allow", "escalate" or "deny".
    static func decisionAtContext(_ m: Model, _ ctx: V) throws -> String {
        if !Predicates.evaluate(.array(m.predicates), ctx) { return "deny" }
        var escalate = false
        for v in m.vetoes {
            if !(try vetoApplies(v, ctx)) { continue }
            if IV.same(try rd(v, "kind")?.asString, "deny") { return "deny" }
            escalate = true
        }
        for t in m.tighten {
            if Predicates.conditionTri(try rd(t, "when") ?? .null, ctx, SafeRegex.Budget()) == .f { continue }
            if IV.same(try rd(t, "signal")?.asString, "deny") { return "deny" }
            escalate = true
        }
        var own = escalate ? "escalate" : "allow"
        for x in m.meets {
            let d = try decisionAtContext(x, ctx)
            if d == "deny" { return "deny" }
            if d == "escalate" { own = "escalate" }
        }
        return own
    }

    /// Ternary decision of a representative (static caveat gate first).
    static func decide(_ m: Model, _ rep: Rep) throws -> String {
        if !m.caveatSat { return "deny" }
        if !reversibilityOk(m, rep.revClass) { return "deny" }
        return try decisionAtContext(m, ctx(buildRoots(rep)))
    }

    /// Does the policy admit this representative (allow OR escalate: permitted, possibly with a human)?
    static func admits(_ m: Model, _ rep: Rep) throws -> Bool { try decide(m, rep) != "deny" }

    /// The context of a fully-specified action.
    static func contextOfAction(_ action: V?) throws -> V {
        var act: JObject = ["params": .object(JSLoose.spread(JS.present(try rd(action, "params")) ?? .object([:])))]
        if let v = try rd(action, "verb") { act["verb"] = v }
        if let r = try rd(action, "resource") { act["resource"] = r }
        if let rc = try rd(action, "reversibilityClass") { act["reversibility_class"] = rc }
        return .object(["action": .object(act), "subject": .object(JSLoose.spread(JS.present(mem(action, "subject")) ?? .object([:]))),
                        "env": .object(JSLoose.spread(JS.present(mem(action, "env")) ?? .object([:])))])
    }

    /// Ternary decision of a fully-specified action.
    public static func decideAction(_ m: Model, _ action: V?) throws -> String {
        if !m.caveatSat { return "deny" }
        if !reversibilityOk(m, try rd(action, "reversibilityClass")) { return "deny" }
        return try decisionAtContext(m, try contextOfAction(action))
    }

    public static func admitsAction(_ m: Model, _ action: V?) throws -> Bool { try decideAction(m, action) != "deny" }

    /// A representative as an action in the query / answer vocabulary.
    public static func repToAction(_ rep: Rep) -> V {
        let r = buildRoots(rep)
        var o: [(String, V?)] = [("verb", rep.verb), ("resource", rep.resource), ("params", r.action["params"] ?? .object([:])), ("reversibilityClass", rep.revClass)]
        if !r.subject.isEmpty { o.append(("subject", .object(r.subject))) }
        if !r.env.isEmpty { o.append(("env", .object(r.env))) }
        return obj(o)
    }

    /// Where a witness's `action.params` members landed in the reference's materialised object (its JSON.stringify member order).
    public final class WitnessOrder { var params: [String] = []; public init() {} }

    static func paramOrder(_ rep: Rep) -> [String] {
        var out: [String] = []
        let prefix = "action.params."
        for a in rep.assignments where IV.startsWith(a.path, prefix) {
            if let k = IV.split(IV.dropPrefix(a.path, prefix.unicodeScalars.count), ".").first, !out.contains(where: { IV.same($0, k) }) { out.append(k) }
        }
        return out
    }

    // ---- bounded search ----

    /// Walks the grid to the first representative for which `pred` holds; `overflow` (without walking) when the grid exceeds `max`.
    static func search(_ pr: Probes, _ pred: (Rep) throws -> Bool, _ max: Double) rethrows -> (hit: Rep?, overflow: Bool) {
        if productSize(pr) > max { return (nil, true) }
        var hit: Rep?
        try eachRep(pr) { r in if try pred(r) { hit = r; return true }; return false }
        return (hit, false)
    }

    /// Like `search`, collecting up to `limit` representatives.
    static func collect(_ pr: Probes, _ pred: (Rep) throws -> Bool, _ max: Double, _ limit: Int) rethrows -> (hits: [Rep], overflow: Bool) {
        if productSize(pr) > max { return ([], true) }
        var hits: [Rep] = []
        try eachRep(pr) { r in
            if try pred(r) { hits.append(r); if hits.count >= limit { return true } }
            return false
        }
        return (hits, false)
    }

    // ---- the relational queries ----

    struct Options { var maxCombinations: Double }

    /// The grid bound: a bound that is not a non-negative finite number falls back to the default (0 is allowed: every grid overflows).
    static func boundOf(_ opts: V?) -> Double {
        if let m = fin(mem(opts, "maxCombinations")), m >= 0 { return m }
        return DEFAULT_MAX_COMBINATIONS
    }

    static func revIndex(_ c: V?) -> Int { c?.asString.flatMap { s in REVERSIBILITY_ORDER.firstIndex { IV.same($0, s) } } ?? -1 }

    static func reasonOf(_ m: Model) -> String { m.caveatReason ?? "unknown" }

    static func probesFor(_ models: [Model], _ verb: V?) throws -> Probes {
        var pr = try collectProbes(ProbeInputs(predicateSets: try models.map { try probeSet($0) }, varyReversibility: models.contains { $0.revCap != nil }))
        if let v = verb { pr.verbs = [v] }
        return pr
    }

    /// Can any input complete `action` into one the policy admits? A returned witness is a concrete action verified against the evaluator.
    static func reachable(_ policy: V?, _ action: V?, _ opts: V? = nil) throws -> V {
        let model = try toModel(policy)
        let mx = boundOf(opts)
        if !model.caveatSat { return obj([("reachable", .bool(false)), ("reason", .string("caveats unsatisfiable: \(reasonOf(model))"))]) }
        let rc = try rd(action, "reversibilityClass")
        if let rc = rc, let cap = model.revCap {
            let idx = revIndex(rc)
            if idx < 0 || idx > cap { return obj([("reachable", .bool(false)), ("reason", .string("reversibility class '\(JS.toString(rc))' exceeds the caveat cap"))]) }
        }
        if try admitsAction(model, action) { return obj([("reachable", .bool(true)), ("witness", action)]) }
        let base = try collectProbes(ProbeInputs(predicateSets: [try probeSet(model)], varyReversibility: model.revCap != nil))
        let provided = JS.present(mem(action, "params")) ?? .object([:])
        let prefix = "action.params."
        let fields: [(path: String, values: [Cell])] = base.fields.map { (f: (path: String, values: [Cell])) -> (path: String, values: [Cell]) in
            if IV.startsWith(f.path, prefix), let o = provided.asObject, let v = o[JKey(IV.dropPrefix(f.path, prefix.unicodeScalars.count))] { return (f.path, [.value(v)]) }
            return f
        }
        let revClasses: [V?] = rc != nil ? [rc] : model.revCap != nil ? REVERSIBILITY_ORDER.map { Optional(V.string($0)) } : [nil]
        let pr = Probes(verbs: [mem(action, "verb")], resources: [mem(action, "resource")], revClasses: revClasses, fields: fields)
        let out = try search(pr, { try admits(model, $0) }, mx)
        if let hit = out.hit { return obj([("reachable", .bool(true)), ("witness", try mergeWitness(repToAction(hit), action))]) }
        if out.overflow { return obj([("reachable", .bool(true)), ("approximate", .bool(true)), ("reason", .string("representative grid exceeded the bound; could not prove unreachable"))]) }
        if !model.undecidable.isEmpty {
            return obj([("reachable", .bool(true)), ("approximate", .bool(true)),
                        ("reason", .string("over-approximated (\(model.undecidable.joined(separator: "; "))); could not construct a witness but cannot prove unreachable"))])
        }
        return obj([("reachable", .bool(false)), ("reason", .string("no predicate admits this action for any input (proven over the decided fragment)"))])
    }

    static func mergeWitness(_ witness: V, _ provided: V?) throws -> V {
        var params = JSLoose.spread(mem(witness, "params"))
        for (k, v) in JSLoose.spread(mem(provided, "params")) { params[k] = v }
        var o: [(String, V?)] = [("verb", mem(provided, "verb")), ("resource", mem(provided, "resource")), ("params", .object(params))]
        o.append(("reversibilityClass", JS.present(mem(provided, "reversibilityClass")) ?? mem(witness, "reversibilityClass")))
        o.append(("subject", mem(witness, "subject")))
        o.append(("env", mem(witness, "env")))
        return obj(o)
    }

    /// Is the policy vacuous (deny everything, optionally restricted to `verb`)? Fails safe to `alwaysDenies: false`.
    public static func alwaysDenies(_ policy: V?, _ verb: V?, _ opts: V? = nil, order: WitnessOrder? = nil) throws -> V {
        let model = try toModel(policy)
        let mx = boundOf(opts)
        if !model.caveatSat { return obj([("alwaysDenies", .bool(true)), ("reason", .string("caveats unsatisfiable: \(reasonOf(model))"))]) }
        let out = try search(try probesFor([model], verb), { try admits(model, $0) }, mx)
        if let hit = out.hit { order?.params = paramOrder(hit); return obj([("alwaysDenies", .bool(false)), ("witness", repToAction(hit))]) }
        if out.overflow { return obj([("alwaysDenies", .bool(false)), ("approximate", .bool(true)), ("reason", .string("grid exceeded the bound; cannot prove vacuity"))]) }
        if !model.undecidable.isEmpty {
            return obj([("alwaysDenies", .bool(false)), ("approximate", .bool(true)), ("reason", .string("over-approximated (\(model.undecidable.joined(separator: "; "))); cannot prove vacuity"))])
        }
        return obj([("alwaysDenies", .bool(true))])
    }

    /// Is the policy total for `verb` (admits every action of that verb)? Fails safe to `alwaysAllows: false`.
    public static func alwaysAllows(_ policy: JSONValue?, _ verb: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        let model = try toModel(policy)
        let mx = boundOf(opts)
        if !model.caveatSat { return obj([("alwaysAllows", .bool(false)), ("reason", .string("caveats unsatisfiable: \(reasonOf(model))"))]) }
        let out = try search(try probesFor([model], verb), { !(try admits(model, $0)) }, mx)
        if let hit = out.hit { return obj([("alwaysAllows", .bool(false)), ("counterexample", repToAction(hit))]) }
        if out.overflow { return obj([("alwaysAllows", .bool(false)), ("approximate", .bool(true)), ("reason", .string("grid exceeded the bound; cannot prove totality"))]) }
        if !model.undecidable.isEmpty {
            return obj([("alwaysAllows", .bool(false)), ("approximate", .bool(true)), ("reason", .string("over-approximated (\(model.undecidable.joined(separator: "; "))); cannot prove totality"))])
        }
        return obj([("alwaysAllows", .bool(true))])
    }

    static func approxNote(_ models: [Model], _ overflow: Bool) -> String? {
        if overflow { return "representative grid exceeded the bound; cannot prove the relation" }
        let reasons = uniq(models.flatMap { $0.undecidable })
        return reasons.isEmpty ? nil : "over-approximated (\(reasons.joined(separator: "; "))); cannot prove the relation"
    }

    private static func relation(_ a: V?, _ b: V?, _ opts: V?, _ key: String, _ witnessKey: String, _ order: WitnessOrder? = nil, _ pred: (Model, Model, Rep) throws -> Bool) throws -> V {
        let ma = try toModel(a), mb = try toModel(b)
        let mx = boundOf(opts)
        let out = try search(try probesFor([ma, mb], nil), { try pred(ma, mb, $0) }, mx)
        if let hit = out.hit { order?.params = paramOrder(hit); return obj([(key, .bool(false)), (witnessKey, repToAction(hit))]) }
        if let note = approxNote([ma, mb], out.overflow) { return obj([(key, .bool(false)), ("approximate", .bool(true)), ("reason", .string(note))]) }
        return obj([(key, .bool(true))])
    }

    /// Does `a` permit everything `b` permits (admitted(b) subset of admitted(a))? The delegation-safety check.
    public static func subsumes(_ a: V?, _ b: V?, _ opts: V? = nil, order: WitnessOrder? = nil) throws -> V {
        try relation(a, b, opts, "subsumes", "counterexample", order) { ma, mb, r in try admits(mb, r) && !(try admits(ma, r)) }
    }
    /// Are the two admitted sets disjoint (a witness is an action both admit)?
    public static func disjoint(_ a: JSONValue?, _ b: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        try relation(a, b, opts, "disjoint", "witness") { ma, mb, r in try admits(ma, r) && (try admits(mb, r)) }
    }
    /// Do the two policies admit exactly the same actions?
    public static func equivalent(_ a: JSONValue?, _ b: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        try relation(a, b, opts, "equivalent", "counterexample") { ma, mb, r in try admits(ma, r) != (try admits(mb, r)) }
    }

    // ---- intent conformance ----

    static func scopeMatches(_ scope: V?, _ resource: V?) throws -> Bool {
        guard case let .string(sc)? = scope else { throw fail("scope.startsWith is not a function") }
        if IV.same(sc, "*") { return true }
        guard let res = resource?.asString else { return false }
        if IV.startsWith(sc, "re:") {
            let src = IV.dropPrefix(sc, 3)
            if IV.u16(src) > 200 || IV.u16(res) > Predicates.MAX_RE_RESOURCE_LEN || !SafeRegex.isSafeSource(Array(src.utf16)) { return false }
            return SafeRegex.fullMatchTri(src, res, SafeRegex.Budget()) == true
        }
        if IV.endsWith(sc, "*") { return IV.startsWith(res, IV.text(sc.unicodeScalars.dropLast())) }
        return IV.same(sc, res)
    }

    static func intentViolationKinds(_ action: V, _ intent: V?, _ amountField: V?, _ minAmount: V?) throws -> [String] {
        var kinds: [String] = []
        let verbs = try rd(intent, "verbs")
        guard case let .array(vs)? = verbs else { throw fail("intent.verbs.includes is not a function") }
        let av = mem(action, "verb")
        if !(vs.contains { $0.asString.map { IV.same($0, "*") } ?? false } || vs.contains { same($0, av) }) { kinds.append("off-verb") }
        let scopes = arr(JS.present(mem(intent, "resourceScopes")))
        if !scopes.isEmpty {
            var any = false
            for s in scopes { if try scopeMatches(s, mem(action, "resource")) { any = true; break } }
            if !any { kinds.append("off-scope") }
        }
        if let mxA = mem(intent, "maxAmount") {
            let amt = mem(JS.present(mem(action, "params")) ?? .object([:]), JS.toString(amountField))
            if let a = fin(amt) {
                if JSLoose.gt(.double(a), mxA) { kinds.append("over-amount") } else if JSLoose.lt(.double(a), minAmount) { kinds.append("under-amount") }
            }
        }
        return kinds
    }

    /// Does the policy admit ONLY actions inside the declared intent envelope? Each reported violation is a concrete admitted action
    /// outside it; `conforms: true` is proven only for the decided fragment, anything else fails safe to `conforms: false, approximate`.
    public static func intentConformance(_ policy: JSONValue?, _ intent: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        let model = try toModel(policy)
        let mx = boundOf(opts)
        let amountField: V = JS.present(try rd(intent, "amountField")) ?? .string("amount")
        let minAmount: V = JS.present(mem(intent, "minAmount")) ?? .int(0)
        if !model.caveatSat { return obj([("conforms", .bool(true)), ("violations", .array([]))]) }
        var extra: [(path: String, cond: V)] = []
        if let maxAmt = mem(intent, "maxAmount") {
            let path = "action.params.\(JS.toString(amountField))"
            extra.append((path, .object(["field": .string(path), "op": .string("lte"), "value": maxAmt])))
            extra.append((path, .object(["field": .string(path), "op": .string("gte"), "value": minAmount])))
        }
        guard case let .array(iv)? = mem(intent, "verbs") else { throw fail("intent.verbs.filter is not a function") }
        let scopesIn = arr(JS.present(mem(intent, "resourceScopes")))
        var strScopes: [String] = []
        for s in scopesIn { guard let t = s.asString else { throw fail("r.startsWith is not a function") }; strScopes.append(t) }
        let pr = try collectProbes(ProbeInputs(predicateSets: [try probeSet(model)], extraVerbs: iv.compactMap { $0.asString }.filter { !IV.same($0, "*") },
                                               extraResources: strScopes, extraFieldConditions: extra, varyReversibility: model.revCap != nil))
        if productSize(pr) > mx {
            return obj([("conforms", .bool(false)), ("approximate", .bool(true)), ("violations", .array([])), ("reason", .string("grid exceeded the bound; cannot prove conformance"))])
        }
        var violations: [V] = []
        try eachRep(pr) { rep in
            if !(try admits(model, rep)) { return false }
            let action = repToAction(rep)
            let kinds = try intentViolationKinds(action, intent, amountField, minAmount)
            if !kinds.isEmpty {
                violations.append(.object(["action": action, "kinds": strs(kinds)]))
                if violations.count >= 16 { return true }
            }
            return false
        }
        if !violations.isEmpty { return obj([("conforms", .bool(false)), ("violations", .array(violations))]) }
        let intentRegex = strScopes.contains { IV.startsWith($0, "re:") }
        if !model.undecidable.isEmpty || intentRegex {
            var reasons = model.undecidable
            if intentRegex { reasons.append("re: intent resource scope not enumerated soundly") }
            return obj([("conforms", .bool(false)), ("approximate", .bool(true)), ("violations", .array([])),
                        ("reason", .string("over-approximated (\(reasons.joined(separator: "; "))); cannot prove conformance"))])
        }
        return obj([("conforms", .bool(true)), ("violations", .array([]))])
    }

    /// Concrete, exact admission of a fully-specified action (no existential search).
    static func admitsConcrete(_ policy: V?, _ action: V?) throws -> Bool { try admitsAction(try toModel(policy), action) }

    /// Whether a predicate's own numeric `where` conjunction is satisfiable (`amount >= 100 AND amount <= 10` is not).
    public static func predicateNumericSatisfiable(_ where_: JSONValue?) -> Bool {
        guard case let .array(w)? = where_ else { return true }
        return numericConjunctionSatisfiable(w)
    }
}
