import Foundation

/// Deriving the outcome space from the vocabulary of the policies and the structured intent slots, and compiling slots into the policy
/// they literally describe. Slots, policies and options are JSON trees.
public enum PCAIntentDerive {
    private struct Domain {
        let lo: Double
        let hi: Double
        let dist: String
    }

    /// Built-in numeric domains for common fields.
    private static func defaultDomain(_ path: String) -> Domain? {
        if IV.same(path, "action.params.amount") { return Domain(lo: 0.0, hi: 100000.0, dist: "loguniform") }
        if IV.same(path, "env.hour") { return Domain(lo: 0.0, hi: 23.0, dist: "uniform") }
        if IV.same(path, "action.params.count") { return Domain(lo: 0.0, hi: 1000.0, dist: "loguniform") }
        return nil
    }

    private final class FieldLits {
        var nums: [Double] = []
        var exacts: [String] = []
        var prefixes: [String] = []
    }

    private typealias Lits = [JKey: FieldLits]

    private static func lits(_ m: inout Lits, _ path: String) -> FieldLits {
        if let f = m[JKey(path)] { return f }
        let f = FieldLits()
        m[JKey(path)] = f
        return f
    }

    private static func addNum(_ f: FieldLits, _ x: Double) {
        if x.isNaN || x.isInfinite { return }
        for v in [x.rounded(.down) + 0.0, x.rounded(.up) + 0.0] where !f.nums.contains(v) { f.nums.append(v) }
    }

    private static func addStr(_ xs: inout [String], _ s: String) {
        if !IV.contains(xs, s) { xs.append(s) }
    }

    private static func has(_ o: JSONValue?, _ k: String) -> Bool { o?.asObject?[JKey(k)] != nil }

    private static func get(_ o: JSONValue?, _ k: String) -> JSONValue? { o?.asObject?[JKey(k)] }

    /// A set of strings in `TreeSet<String>` order (UTF-16 code units).
    static func uniqueSorted(_ xs: [String]) -> [String] {
        var seen = Set<JKey>()
        var out: [String] = []
        for x in xs where seen.insert(JKey(x)).inserted { out.append(x) }
        return out.sorted { GV.less($0, $1) }
    }

    private static func collectCond(_ c: JSONValue?, _ m: inout Lits, _ approx: inout [String]) throws {
        guard let co = c?.asObject else { return }
        if co[JKey("all_of")] != nil || co[JKey("any_of")] != nil || co[JKey("not")] != nil {
            if let l = co[JKey("all_of")]?.asArray {
                for x in l { try collectCond(x, &m, &approx) }
            } else if let l = co[JKey("any_of")]?.asArray {
                for x in l { try collectCond(x, &m, &approx) }
            } else if co[JKey("not")] != nil {
                try collectCond(co[JKey("not")], &m, &approx)
            }
            return
        }
        guard let field = co[JKey("field")]?.asString else { return }
        let op = co[JKey("op")]?.asString
        if co[JKey("ref")] != nil { approx.append("cross-field ref on \(field)") }
        if let o = op, IV.same(o, "like") || IV.same(o, "matches") || IV.same(o, "is_a") || IV.same(o, "member_of") { approx.append("\(o) on \(field)") }
        if IV.same(op, "exists") {
            _ = lits(&m, field)
            return
        }
        let f = lits(&m, field)
        let value = co[JKey("value")]
        var vals: [JSONValue?] = []
        if let l = value?.asArray { for x in l { vals.append(x) } } else { vals.append(value) }
        for v in vals {
            if let d = IV.num(v) {
                addNum(f, d)
            } else if let s = v?.asString {
                if IV.same(op, "prefix") { addStr(&f.prefixes, s) } else { addStr(&f.exacts, s) }
            }
        }
    }

    private static func addResource(_ r: JSONValue?, _ m: inout Lits, _ approx: inout [String]) {
        guard let s = r?.asString, !IV.same(s, "*") else { return }
        if IV.startsWith(s, "re:") {
            approx.append("re: resource matcher")
            return
        }
        let f = lits(&m, "action.resource")
        if IV.endsWith(s, "*") {
            addStr(&f.prefixes, IV.text(s.unicodeScalars.dropLast()))
        } else {
            addStr(&f.exacts, s)
        }
    }

    /// The verbs a predicate names, or nil for the wildcard.
    private static func verbsOf(_ p: JSONValue?) -> [String]? {
        let v = get(p, "verb")
        if let s = v?.asString { return IV.same(s, "*") ? nil : [s] }
        var out: [String] = []
        if let l = v?.asArray {
            for x in l { if let s = x.asString, IV.same(s, "*") { return nil } }
            for x in l { if let s = x.asString { out.append(s) } }
        }
        return out
    }

    private static func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("not a string") }
        return s
    }

    private static func strings(_ o: JSONValue?, _ into: inout [String]) throws {
        guard let l = o?.asArray else { return }
        for x in l { addStr(&into, try str(x)) }
    }

    /// Derive the space; `opts` members: policies, slots, domains, extraVerbs (all optional but policies).
    public static func deriveOmega(_ opts: JSONValue?, _ catalog: PCACatalog = PCACatalog.default) throws -> PCAIntentOmega.Omega {
        var approx: [String] = []
        var preds: [JSONValue] = []
        guard let policies = get(opts, "policies")?.asArray else { throw JSError("policies must be an array") }
        for p in policies {
            let n = PCAIntentPolicy.normalizePolicy(p)
            preds.append(contentsOf: n.get("predicates")?.asArray ?? [])
        }
        var explicitList: [String] = []
        if let extra = get(opts, "extraVerbs")?.asArray { for x in extra { explicitList.append(try str(x)) } }
        var wildcard = false
        for p in preds {
            if let vs = verbsOf(p) { explicitList.append(contentsOf: vs) } else { wildcard = true }
        }
        let slots = get(opts, "slots")
        if let sv = get(slots, "verbs")?.asArray { for x in sv { explicitList.append(try str(x)) } }
        if wildcard {
            var connectors: [String] = []
            for v in explicitList { addStr(&connectors, IV.split(v, ".")[0]) }
            for s in catalog.all() where connectors.isEmpty || IV.contains(connectors, s.connector) { explicitList.append(s.verb) }
        }
        let explicit = uniqueSorted(explicitList)
        let constraints: [JSONValue] = get(slots, "constraints")?.asArray ?? []
        let domains: JSONValue? = get(opts, "domains")?.isObject == true ? get(opts, "domains") : nil
        var out: [PCAIntentOmega.VerbSpace] = []
        for verb in explicit {
            var m = Lits()
            for p in preds {
                if let pv = verbsOf(p), !IV.contains(pv, verb) { continue }
                addResource(get(p, "resource"), &m, &approx)
                if let w = get(p, "where")?.asArray { for c in w { try collectCond(c, &m, &approx) } }
            }
            for sc in constraints {
                if has(sc, "verb") && !(get(sc, "verb")?.asString.map { IV.same($0, verb) } ?? false) { continue }
                let f = lits(&m, try str(get(sc, "path")))
                if has(sc, "max"), let d = IV.num(get(sc, "max")) { addNum(f, d) }
                if has(sc, "min"), let d = IV.num(get(sc, "min")) { addNum(f, d) }
                try strings(get(sc, "oneOf"), &f.exacts)
                try strings(get(sc, "noneOf"), &f.exacts)
                try strings(get(sc, "prefixOneOf"), &f.prefixes)
            }
            var dims: [PCAIntentOmega.Dim] = []
            for path in m.keys.map({ $0.s }).sorted(by: { GV.less($0, $1) }) {
                let f = m[JKey(path)]!
                if f.nums.count > 0 || (f.exacts.isEmpty && f.prefixes.isEmpty && defaultDomain(path) != nil) {
                    let cuts = PCAIntentOmega.sortedNums(f.nums)
                    let dom = defaultDomain(path)
                    var dlo: Double? = dom?.lo
                    var dhi: Double? = dom?.hi
                    var ddist: String? = dom?.dist
                    if let dd = domains?.get(path), dd.isObject {
                        dlo = try PCAIntentOmega.dbl(dd.get("lo"))
                        dhi = try PCAIntentOmega.dbl(dd.get("hi"))
                        ddist = dd.get("dist")?.asString
                    }
                    let maxCut = cuts.isEmpty ? 0.0 : cuts[cuts.count - 1]
                    let minCut = cuts.isEmpty ? 0.0 : cuts[0]
                    let lo = dlo ?? PCAIntentOmega.jmin(0.0, minCut - 1)
                    let hi = dhi ?? PCAIntentOmega.jmax(PCAIntentOmega.jmax(10.0, 2 * maxCut), maxCut + 10)
                    let dist = ddist ?? (lo >= 0 ? "loguniform" : "uniform")
                    let kept = cuts.filter { $0 >= lo && $0 <= hi }
                    dims.append(PCAIntentOmega.NumDim(path, lo, hi, kept, dist))
                } else {
                    var values: [PCAIntentOmega.CatValue] = []
                    for v in uniqueSorted(f.exacts) { values.append(PCAIntentOmega.CatValue("exact", v)) }
                    for v in uniqueSorted(f.prefixes) { values.append(PCAIntentOmega.CatValue("prefix", v)) }
                    values.append(PCAIntentOmega.CatValue("other", PCAIntentOmega.OTHER))
                    dims.append(PCAIntentOmega.CatDim(path, values))
                }
            }
            let spec = catalog.get(verb)
            out.append(PCAIntentOmega.VerbSpace(verb, spec?.reversibility ?? "irreversible", 0.0, dims))
        }
        for v in out { v.weight = 1.0 / Double(out.count) }
        return PCAIntentOmega.Omega(out, uniqueSorted(approx))
    }

    // ---- slots ----

    private static func leaf(_ field: String?, _ op: String, _ value: JSONValue?) -> JSONValue {
        var o = JObject()
        o[JKey("field")] = field.map { JSONValue.string($0) } ?? JSONValue.null
        o[JKey("op")] = .string(op)
        o[JKey("value")] = value ?? JSONValue.null
        return .object(o)
    }

    private static func slotConds(_ sc: JSONValue) throws -> [JSONValue] {
        var out: [JSONValue] = []
        var path: String?
        if let p = get(sc, "path"), !p.isNull { path = try str(p) }
        if has(sc, "min") { out.append(leaf(path, "gte", get(sc, "min"))) }
        if has(sc, "max") { out.append(leaf(path, "lte", get(sc, "max"))) }
        var anyOf: [JSONValue] = []
        if let oneOf = get(sc, "oneOf")?.asArray, !oneOf.isEmpty { anyOf.append(leaf(path, "in", .array(oneOf))) }
        if let pre = get(sc, "prefixOneOf")?.asArray { for p in pre { anyOf.append(leaf(path, "prefix", p)) } }
        if anyOf.count == 1 {
            out.append(anyOf[0])
        } else if anyOf.count > 1 {
            out.append(.object([JKey("any_of"): .array(anyOf)]))
        }
        if let none = get(sc, "noneOf")?.asArray, !none.isEmpty { out.append(leaf(path, "nin", .array(none))) }
        return out
    }

    /// Compile slots into the policy they literally describe (one predicate per slot verb).
    public static func slotsToPolicy(_ slots: JSONValue?) throws -> JSONValue {
        guard let verbs = get(slots, "verbs")?.asArray else { throw JSError("slots.verbs must be an array") }
        guard let cons = get(slots, "constraints")?.asArray else { throw JSError("slots.constraints must be an array") }
        var predicates: [JSONValue] = []
        for verb in verbs {
            var whereList: [JSONValue] = []
            for c in cons where !has(c, "verb") || IV.strictEq(get(c, "verb"), verb) { whereList.append(contentsOf: try slotConds(c)) }
            var p = JObject()
            p[JKey("verb")] = verb
            p[JKey("resource")] = .string("*")
            if !whereList.isEmpty { p[JKey("where")] = .array(whereList) }
            predicates.append(.object(p))
        }
        return .object([JKey("predicates"): .array(predicates), JKey("caveats"): .array([])])
    }
}
