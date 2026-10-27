import Foundation

// Ternary decision, tighten-only model rule (rule 21) and units check (rule 20): a port of packages/pca/src/decision.ts and
// envelope-rules.ts (the TypeScript is authoritative; reason strings are the same). deny < escalate < allow; `meet` (the
// minimum) is the only combinator, so escalate never becomes allow. Every function is total; anything malformed fails closed.

extension PCA {
    static let DECISION_RANK: [String: Int] = ["deny": 0, "escalate": 1, "allow": 2]

    /// The lower of two decisions; an unknown value is deny.
    public static func meet(_ a: String, _ b: String) -> String {
        guard let x = DECISION_RANK[a], let y = DECISION_RANK[b] else { return "deny" }
        return x <= y ? a : b
    }

    /// The highest decision a model signal permits (anything but `ok` / `escalate` is deny).
    public static func signalCeiling(_ s: JSONValue?) -> String {
        switch s?.asString {
        case "ok"?: return "allow"
        case "escalate"?: return "escalate"
        default: return "deny"
        }
    }

    /// G-T9: a model can only move a decision down.
    public static func tightenDecision(_ base: String, signal: JSONValue?) -> String { meet(base, signalCeiling(signal)) }

    /// An escalate with a verified answer is allow; an answer never upgrades a deny. Any other string is returned as is (the reference).
    public static func pepDecision(_ d: String, answered: Bool) -> String {
        return d == "escalate" && answered ? "allow" : d
    }

    static let ESCALATE_REASON_PREFIXES = ["intent_required:", "escalate:"]

    /// The ternary decision of a verdict `{allow, checks (name -> "pass"|"fail"|...), reasons}`: allow; else escalate iff at
    /// least one check failed and EVERY failing check is escalate-class (it has at least one reason `<check>: <body>` and
    /// every such body starts with an escalate prefix); else deny. A failing check with no reason of its own is a hard failure.
    public static func decisionOf(allow: Bool, checks: [String: String], reasons: [String]) -> String {
        if allow { return "allow" }
        var failing = 0
        for (name, status) in checks where status == "fail" {
            failing += 1
            let head = name + ": "
            let own = reasons.filter { IV.startsWith($0, head) }
            if own.isEmpty { return "deny" }
            for r in own {
                let body = IV.dropPrefix(r, head.unicodeScalars.count)
                if !ESCALATE_REASON_PREFIXES.contains(where: { IV.startsWith(body, $0) }) { return "deny" }
            }
        }
        return failing > 0 ? "escalate" : "deny"
    }

    // ---- shared rule 20/21 helpers ----

    static let MAX_TIGHTEN_RULES = 64

    /// `^action\.params\.[A-Za-z0-9_-]{1,64}$`
    static func isUnitParamPath(_ s: String) -> Bool {
        guard IV.startsWith(s, "action.params.") else { return false }
        let u = Array(s.unicodeScalars.dropFirst(14))
        return (1...64).contains(u.count) && u.allSatisfy {
            ($0.value >= 0x30 && $0.value <= 0x39) || ($0.value >= 0x41 && $0.value <= 0x5A) || ($0.value >= 0x61 && $0.value <= 0x7A) || $0 == "_" || $0 == "-"
        }
    }

    /// nil = closed shape; else the reason.
    static func closedMembers(_ o: JObject, _ required: [String], _ optional: [String], _ at: String) -> String? {
        for k in o.keys.sorted() where !required.contains(where: { IV.same($0, k.s) }) && !optional.contains(where: { IV.same($0, k.s) }) {
            return "unknown member '\(at).\(k.s)'"
        }
        for k in required where o[JKey(k)] == nil { return "missing member '\(at).\(k)'" }
        return nil
    }

    /// nil = well-formed. ABSENT is well-formed; JSON null is not an array.
    public static func tightenListError(_ t: JSONValue?) -> String? {
        guard let t = t else { return nil }
        guard case let .array(arr) = t else { return "tighten must be an array" }
        if arr.count > MAX_TIGHTEN_RULES { return "tighten has more than \(MAX_TIGHTEN_RULES) rules" }
        var ids = Set<JKey>()
        for (i, x) in arr.enumerated() {
            guard case let .object(r) = x else { return "tighten[\(i)] must be an object" }
            if let e = closedMembers(r, ["id", "when", "signal"], ["reason"], "tighten[\(i)]") { return e }
            guard let id = r["id"]?.asString, IV.isName(id) else { return "tighten[\(i)].id must match ^[a-z][a-z0-9_]{0,63}$" }
            if ids.contains(JKey(id)) { return "tighten[\(i)].id '\(id)' is a duplicate" }
            ids.insert(JKey(id))
            guard r["when"]?.isObject == true else { return "tighten[\(i)].when must be a condition object" }
            let sg = r["signal"]?.asString
            if sg != "escalate" && sg != "deny" { return "tighten[\(i)].signal must be 'escalate' or 'deny'" }
            if let rs = r["reason"] {
                guard let s = rs.asString, IV.u16(s) <= 256 else { return "tighten[\(i)].reason must be a string of at most 256 characters" }
            }
        }
        return nil
    }

    /// nil = well-formed policy unit tags `{ "action.params.<name>": {kind, currency?, exponent?} }`, closed.
    public static func unitTagsError(_ u: JSONValue?) -> String? {
        guard case let .object(m)? = u else { return "units must be an object" }
        if m.count > 64 { return "units has more than 64 entries" }
        for (jk, tv) in m {
            let k = jk.s
            if !isUnitParamPath(k) { return "units key '\(k)' must be an action.params.<name> path" }
            guard case let .object(t) = tv else { return "units['\(k)'] must be an object" }
            if let e = closedMembers(t, ["kind"], ["currency", "exponent"], "units['\(k)']") { return e }
            guard let kind = t["kind"]?.asString, (1...64).contains(IV.u16(kind)) else { return "units['\(k)'].kind must be a string of 1..64 characters" }
            if let c = t["currency"], !(c.asString.map { (1...16).contains(IV.u16($0)) } ?? false) {
                return "units['\(k)'].currency must be a string of 1..16 characters"
            }
            if let e = t["exponent"], !(IV.nonNeg(e).map { $0 <= 18 } ?? false) { return "units['\(k)'].exponent must be an integer in [0, 18]" }
        }
        return nil
    }

    // ---- rule 21: model polarity ----

    static let MODEL_ENV_ROOTS = ["class", "prov", "judge"]

    /// Is `path` a model-derived env path? `single` names the worlds decided by ONE oracle (`env.world.<name>`).
    static func isModelDerivedPath(_ path: String, _ single: [String]) -> Bool {
        let seg = IV.split(path, ".")
        guard IV.same(seg[0], "env"), seg.count >= 2 else { return false }
        if MODEL_ENV_ROOTS.contains(where: { IV.same($0, seg[1]) }) { return true }
        if IV.same(seg[1], "world") { return seg.count == 2 ? !single.isEmpty : single.contains { IV.same($0, seg[2]) } }
        return false
    }

    static func collectCondPaths(_ c: JSONValue?, _ out: inout Set<JKey>, _ depth: Int) {
        guard depth <= 64, case let .object(o)? = c else { return }
        for k in ["all_of", "any_of"] { if case let .array(xs)? = o[JKey(k)] { for x in xs { collectCondPaths(x, &out, depth + 1) } } }
        if let n = o["not"] { collectCondPaths(n, &out, depth + 1) }
        for k in ["field", "ref", "collection"] { if let s = o[JKey(k)]?.asString { out.insert(JKey(s)) } }
    }

    /// The paths of every `where` of the predicate lists (those `inScope` accepts), sorted by UTF-8 bytes.
    static func collectPredicatePaths(_ lists: [JSONValue], inScope: (JSONValue) -> Bool = { _ in true }) -> Set<JKey> {
        var out = Set<JKey>()
        for l in lists {
            guard case let .array(ps) = l else { continue }
            for p in ps where inScope(p) {
                if case let .array(w)? = p.get("where") { for c in w { collectCondPaths(c, &out, 0) } }
            }
        }
        return out
    }

    /// The model-derived paths grants read, sorted by UTF-8 bytes (de-duplicated).
    public static func modelPathsRead(_ lists: [JSONValue], single: [String] = []) -> [String] {
        collectPredicatePaths(lists).map { $0.s }.filter { isModelDerivedPath($0, single) }.sorted { IV.utf8Less($0, $1) }
    }

    public struct TightenResult: Equatable, Sendable {
        /// `ok`, `escalate` or `deny`.
        public let outcome: String
        /// Legacy compatibility in effect AND a grant actually reads a model-derived path: the verdict is degraded.
        public let legacy: Bool
        public let offending: [String]
        public let reason: String?
    }

    /// Rule 21 over `{predicates, tighten, polarity, single_source, context}`. Typing first: a grant-side `where` that reads
    /// a model-derived path is a refusal (`deny`) unless `polarity` is `legacy`. Then the rules in order: `when` true -> its
    /// signal; unknown -> escalate; false -> no effect. The outcome is the meet of all signals. Total.
    public static func decideTighten(_ input: JSONValue) -> TightenResult {
        func deny(_ why: String, _ off: [String] = []) -> TightenResult { TightenResult(outcome: "deny", legacy: false, offending: off, reason: why) }
        guard case let .object(inp) = input else { return deny("evaluation error (fail closed): input is not an object") }
        var single: [String] = []
        if case let .array(ss)? = inp["single_source"] { single = ss.compactMap { $0.asString } }
        let pol = inp["polarity"]
        if let p = pol, p.asString != "legacy" { return deny("model_polarity must be 'legacy' when present") }
        if let le = tightenListError(inp["tighten"]) { return deny("malformed tighten list: \(le)") }
        var lists: [JSONValue] = []
        if case let .array(ps)? = inp["predicates"] { lists = ps }
        let offending = modelPathsRead(lists, single: single)
        let legacy = pol != nil && !offending.isEmpty
        if !offending.isEmpty && !legacy {
            return deny("a grant's where reads model-derived path(s) \(offending.joined(separator: ", ")): a model may only tighten (move them into tighten[]) (rule 21)", offending)
        }
        var out = "ok"
        var reason: String?
        let ctx: JSONValue = inp["context"]?.isObject == true ? inp["context"]! : .object([:])
        var rules: [JSONValue] = []
        if case let .array(rs)? = inp["tighten"] { rules = rs }
        for x in rules {
            guard case let .object(r) = x, let id = r["id"]?.asString, let sig = r["signal"]?.asString, let when = r["when"] else { continue }
            func lower(_ s: String, _ why: String) {
                if DECISION_RANK[signalCeiling(.string(s))]! < DECISION_RANK[signalCeiling(.string(out))]! { out = s; reason = why }
            }
            switch Predicates.conditionTri(when, ctx, SafeRegex.Budget()) {
            case .t:
                let why = r["reason"]?.asString.map { " (\($0))" } ?? ""
                lower(sig, "\(sig == "deny" ? "denied by" : "escalate: asked by") tighten rule '\(id)'\(why)")
            case .u: lower("escalate", "escalate: rule '\(id)' could not be decided (a value it reads is missing or ill-typed)")
            case .f: break
            }
        }
        return TightenResult(outcome: out, legacy: legacy, offending: offending, reason: reason)
    }

    // ---- rule 20: units ----

    static func tagText(_ t: JObject?) -> String {
        guard let t = t else { return "no unit" }
        func show(_ v: JSONValue?) -> String {
            switch v {
            case let .string(s)?: return s
            case let .int(i)?: return String(i)
            case let .double(d)?: return Canonical.numberString(d)
            default: return "?"
            }
        }
        return show(t["kind"]) + (t["currency"].map { "/" + show($0) } ?? "") + (t["exponent"].map { "/e" + show($0) } ?? "")
    }

    static func sameTag(_ a: JObject, _ b: JObject) -> Bool {
        for k in ["kind", "currency", "exponent"] {
            let x = a[JKey(k)], y = b[JKey(k)]
            if x == nil && y == nil { continue }
            guard let xv = x, let yv = y, IV.strictEq(xv, yv) else { return false }
        }
        return true
    }

    /// Rule 20 over `{units, schema_units, verb_params, verb, predicates}`: (1) every policy tag whose parameter the verb
    /// declares equals the unit the schema declares for it, and (2) no grant-side `where` term in scope of the verb reads a
    /// unit-bearing parameter without a tag. Total: malformed input is `ok: false`.
    public static func decideUnits(_ input: JSONValue) -> (ok: Bool, reason: String) {
        func fail(_ m: String) -> (ok: Bool, reason: String) { (false, m) }
        guard case let .object(inp) = input else { return fail("evaluation error (fail closed): input is not an object") }
        if let te = unitTagsError(inp["units"]) { return fail(te) }
        guard case let .object(tags)? = inp["units"] else { return fail("units must be an object") }
        guard let verb = inp["verb"]?.asString, !verb.isEmpty else { return fail("the verb is missing") }
        var sUnits: JObject = [:]
        if let su = inp["schema_units"] {
            guard case let .object(o) = su else { return fail("the schema units table must be an object") }
            sUnits = o
        }
        guard case let .object(params)? = inp["verb_params"] else { return fail("the schema does not declare verb '\(verb)'") }
        func declared(_ path: String) -> (has: Bool, tag: JObject?) {
            guard case let .object(d)? = params[JKey(path)] else { return (false, nil) }
            if let id = d["unit"]?.asString, case let .object(t)? = sUnits[JKey(id)] { return (true, t) }
            return (true, nil)
        }
        for jk in tags.keys.sorted(by: { IV.utf8Less($0.s, $1.s) }) {
            let d = declared(jk.s)
            if !d.has { continue }
            guard case let .object(tag)? = tags[jk] else { continue }
            guard let st = d.tag, sameTag(st, tag) else {
                return fail("'\(jk.s)' is declared as \(tagText(d.tag)) by the action schema but the policy term is tagged \(tagText(tag)) (unit confusion)")
            }
        }
        var lists: [JSONValue] = []
        if case let .array(ps)? = inp["predicates"] { lists = ps }
        let read = collectPredicatePaths(lists) { p in
            switch p.get("verb") {
            case let .string(v)?: return IV.same(v, "*") || IV.same(v, verb)
            case let .array(vs)?: return vs.contains { $0.asString.map { IV.same($0, verb) } ?? false }
            default: return false
            }
        }
        for path in read.map({ $0.s }).sorted(by: { IV.utf8Less($0, $1) }) where isUnitParamPath(path) {
            let d = declared(path)
            if d.has, let t = d.tag, tags[JKey(path)] == nil {
                return fail("a policy term reads '\(path)' (\(tagText(t))) without a unit tag")
            }
        }
        return (true, "")
    }
}
