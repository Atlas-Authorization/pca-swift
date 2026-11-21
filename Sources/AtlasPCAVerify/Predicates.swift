import Foundation

/// The non-code predicate DSL of `packages/pca/src/predicates.ts` (`evaluatePredicates`), used by the Intent Layer v2
/// `layers` check (each ceiling G^org / G^site / G^std is a predicate set). Total; fails CLOSED. Conditions are
/// THREE-VALUED (`true` / `false` / `unknown`) so `not` / `any_of` / `all_of` get the reference verdict. Operators: eq, ne,
/// in, nin, lt, lte, gt, gte, prefix, exists, like, matches, is_a, member_of; groups all_of, any_of, not. Resource
/// matchers: exact, `*`, trailing-`*` prefix, `re:<pattern>` (the linear-time matcher of `SafeRegex`). The context is one
/// JSON object whose roots `action` / `subject` / `env` a dotted path starts from.
enum Predicates {
    static let MAX_RE_RESOURCE_LEN = 512
    static let MAX_RE_SRC_LEN = 200
    static let MAX_MATCHES_PATTERN_LEN = 200
    static let MAX_PATTERN_SUBJECT_LEN = 512
    static let MAX_LIKE_PATTERN_LEN = 512
    static let MAX_MEMBER_CLOSURE_NODES = 10_000

    enum Tri { case t, f, u }
    static func tri(_ b: Bool) -> Tri { b ? .t : .f }

    /// `resolvePath`: own properties only; numeric array indices without leading zeros; `__proto__` / `constructor` /
    /// `prototype` and unknown roots are not found.
    static func resolve(_ ctx: JSONValue, _ path: String) -> JSONValue? {
        if path.isEmpty { return nil }
        let segs = IV.split(path, ".")
        guard ["action", "subject", "env"].contains(where: { IV.same($0, segs[0]) }), var cur = ctx.get(segs[0]) else { return nil }
        for s in segs.dropFirst() {
            if IV.FORBIDDEN_SEGMENTS.contains(where: { IV.same($0, s) }) { return nil }
            switch cur {
            case let .array(a):
                guard isArrayIndex(s), let idx = Int(s), idx < a.count else { return nil }
                cur = a[idx]
            case let .object(o):
                guard let x = o[JKey(s)] else { return nil }
                cur = x
            default:
                return nil
            }
        }
        return cur
    }

    /// `/^(0|[1-9]\d*)$/`
    static func isArrayIndex(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        guard let f = u.first else { return false }
        if u.count == 1 && f == "0" { return true }
        guard f.value >= 0x31 && f.value <= 0x39 else { return false }
        return u.allSatisfy { $0.value >= 0x30 && $0.value <= 0x39 } && u.count <= 18 // longer indices exceed any array
    }

    /// `deepEq`: equality of the lenient canonical forms (numbers as binary64, strings by code point, objects by key set).
    static func deepEq(_ a: JSONValue, _ b: JSONValue) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case let (.bool(x), .bool(y)): return x == y
        case let (.string(x), .string(y)): return IV.same(x, y)
        case let (.array(x), .array(y)): return x.count == y.count && zip(x, y).allSatisfy { deepEq($0, $1) }
        case let (.object(x), .object(y)):
            return x.count == y.count && x.allSatisfy { k, v in y[k].map { deepEq(v, $0) } ?? false }
        default:
            if let x = IV.num(a), let y = IV.num(b) { return x.isFinite && y.isFinite && x == y }
            return false
        }
    }

    /// Order for lt / lte / gt / gte: finite numbers, or strings by UTF-8 bytes (a lone surrogate has no order).
    static func ordered(_ a: JSONValue, _ b: JSONValue) -> Int? {
        if let x = IV.num(a), let y = IV.num(b) {
            guard x.isFinite && y.isFinite else { return nil }
            return x < y ? -1 : (x > y ? 1 : 0)
        }
        if case let .string(x) = a, case let .string(y) = b {
            if Canonical.hasLoneSurrogate(x) || Canonical.hasLoneSurrogate(y) { return nil }
            let c = Canonical.compareUtf8(x, y)
            return c < 0 ? -1 : (c > 0 ? 1 : 0)
        }
        return nil
    }

    enum GlobTok: Equatable { case lit(UInt16), one, star }

    static func parseGlob(_ g: [UInt16]) -> [GlobTok]? {
        var out: [GlobTok] = []
        var i = 0
        while i < g.count {
            let ch = g[i]
            if ch == 0x5c {
                guard i + 1 < g.count else { return nil }
                out.append(.lit(g[i + 1]))
                i += 1
            } else if ch == 0x2a {
                if out.last != .star { out.append(.star) }
            } else if ch == 0x3f {
                out.append(.one)
            } else {
                out.append(.lit(ch))
            }
            i += 1
        }
        return out
    }

    /// Anchored glob over UTF-16 code units, O(|glob| x |s|).
    static func globMatch(_ glob: [UInt16], _ s: [UInt16]) -> Bool? {
        guard let toks = parseGlob(glob) else { return nil }
        var ti = 0, si = 0
        var starTi = -1, starSi = 0
        while si < s.count {
            let t: GlobTok? = ti < toks.count ? toks[ti] : nil
            if t == .star {
                ti += 1
                starTi = ti
                starSi = si
            } else if let tt = t, tt == .one || tt == .lit(s[si]) {
                ti += 1
                si += 1
            } else if starTi >= 0 {
                ti = starTi
                starSi += 1
                si = starSi
            } else {
                return false
            }
        }
        while ti < toks.count && toks[ti] == .star { ti += 1 }
        return ti == toks.count
    }

    static func typeTagMatch(_ v: JSONValue, _ t: String) -> Bool? {
        func tagged(_ s: String) -> Bool { IV.same(s, t) || IV.startsWith(s, t + "::") }
        switch v {
        case let .string(s): return tagged(s)
        case let .object(o):
            var decidable = false, matched = false
            if case let .string(ty)? = o["type"] { decidable = true; if tagged(ty) { matched = true } }
            if case let .array(tags)? = o["tags"] {
                decidable = true
                if tags.contains(where: { $0.asString.map { IV.same($0, t) } ?? false }) { matched = true }
            }
            return decidable ? matched : nil
        default:
            return nil
        }
    }

    static func neighbours(_ adj: JObject, _ node: String) -> [String] {
        if IV.FORBIDDEN_SEGMENTS.contains(where: { IV.same($0, node) }) { return [] }
        switch adj[JKey(node)] {
        case let .string(s)?: return [s]
        case let .array(a)?: return a.compactMap { $0.asString }
        default: return []
        }
    }

    static func memberClosure(_ start: String, _ adj: JObject) -> Set<JKey> {
        var seen: Set<JKey> = [JKey(start)]
        var queue = [start]
        var head = 0
        var visited = 0
        while head < queue.count && visited < MAX_MEMBER_CLOSURE_NODES {
            visited += 1
            let node = queue[head]
            head += 1
            for n in neighbours(adj, node) where seen.insert(JKey(n)).inserted { queue.append(n) }
        }
        return seen
    }

    static func paramsPresent(_ ctx: JSONValue) -> Bool {
        switch ctx.get("action")?.get("params") {
        case .object?, .array?: return true
        default: return false
        }
    }
    static func paramsRooted(_ p: String) -> Bool { IV.same(p, "action.params") || IV.startsWith(p, "action.params.") }

    /// The operand: a PRESENT `ref` of any type is a path that must resolve; else a present `value`. nil = unknown.
    static func operand(_ c: JObject, _ ctx: JSONValue) -> JSONValue? {
        if let r = c["ref"] {
            guard let rs = r.asString else { return nil }
            return resolve(ctx, rs)
        }
        return c["value"]
    }

    static func triLeaf(_ c: JObject, _ ctx: JSONValue, _ budget: SafeRegex.Budget) -> Tri {
        guard let field = c["field"]?.asString, !field.isEmpty, let op = c["op"]?.asString else { return .u }
        if paramsRooted(field) && !paramsPresent(ctx) { return .u }
        if let r = c["ref"]?.asString, paramsRooted(r), !paramsPresent(ctx) { return .u }
        let f = resolve(ctx, field)
        if IV.same(op, "exists") {
            if case .bool(false)? = c["value"] { return tri(f == nil) }
            return tri(f != nil)
        }
        guard let v = f else { return .u }
        if IV.same(op, "member_of") {
            guard case let .string(start) = v, let coll = c["collection"]?.asString, !coll.isEmpty,
                  case let .object(adj)? = resolve(ctx, coll), let target = operand(c, ctx) else { return .u }
            let targets: [String]
            switch target {
            case let .array(a): targets = a.compactMap { $0.asString }
            case let .string(s): targets = [s]
            default: targets = []
            }
            if targets.isEmpty { return .u }
            let reach = memberClosure(start, adj)
            return tri(targets.contains { reach.contains(JKey($0)) })
        }
        guard let o = operand(c, ctx) else { return .u }
        switch op {
        case "eq": return tri(deepEq(v, o))
        case "ne": return tri(!deepEq(v, o))
        case "in":
            guard case let .array(a) = o else { return .u }
            return tri(a.contains { deepEq(v, $0) })
        case "nin":
            guard case let .array(a) = o else { return .u }
            return tri(!a.contains { deepEq(v, $0) })
        case "lt", "lte", "gt", "gte":
            guard let ord = ordered(v, o) else { return .u }
            switch op {
            case "lt": return tri(ord < 0)
            case "lte": return tri(ord <= 0)
            case "gt": return tri(ord > 0)
            default: return tri(ord >= 0)
            }
        case "prefix":
            guard case let .string(s) = v, case let .string(p) = o else { return .u }
            return tri(Array(s.utf16).starts(with: Array(p.utf16)))
        case "like":
            guard case let .string(s) = v, case let .string(g) = o else { return .u }
            let (su, gu) = (Array(s.utf16), Array(g.utf16))
            if gu.count > MAX_LIKE_PATTERN_LEN || su.count > MAX_PATTERN_SUBJECT_LEN { return .u }
            guard let m = globMatch(gu, su) else { return .u }
            return tri(m)
        case "matches":
            guard case let .string(s) = v, case let .string(p) = o else { return .u }
            if IV.u16(p) > MAX_MATCHES_PATTERN_LEN || IV.u16(s) > MAX_PATTERN_SUBJECT_LEN { return .u }
            guard let m = SafeRegex.fullMatchTri(p, s, budget) else { return .u }
            return tri(m)
        case "is_a":
            guard case let .string(t) = o, !t.isEmpty, let m = typeTagMatch(v, t) else { return .u }
            return tri(m)
        default:
            return .u
        }
    }

    static func isGroup(_ o: JObject) -> Bool { o["all_of"] != nil || o["any_of"] != nil || o["not"] != nil }

    static func conditionTri(_ c: JSONValue, _ ctx: JSONValue, _ budget: SafeRegex.Budget, _ depth: Int = 0) -> Tri {
        guard case let .object(o) = c, depth <= Canonical.MAX_LENIENT_DEPTH else { return .u }
        if isGroup(o) {
            if let all = o["all_of"] {
                guard case let .array(a) = all, !a.isEmpty else { return .u }
                var sawUnknown = false
                for x in a {
                    switch conditionTri(x, ctx, budget, depth + 1) {
                    case .f: return .f
                    case .u: sawUnknown = true
                    case .t: break
                    }
                }
                return sawUnknown ? .u : .t
            }
            if let any = o["any_of"] {
                guard case let .array(a) = any, !a.isEmpty else { return .u }
                var sawUnknown = false
                for x in a {
                    switch conditionTri(x, ctx, budget, depth + 1) {
                    case .t: return .t
                    case .u: sawUnknown = true
                    case .f: break
                    }
                }
                return sawUnknown ? .u : .f
            }
            switch conditionTri(o["not"] ?? .null, ctx, budget, depth + 1) {
            case .t: return .f
            case .f: return .t
            case .u: return .u
            }
        }
        return triLeaf(o, ctx, budget)
    }

    static func verbMatches(_ p: JSONValue?, _ verb: String) -> Bool {
        switch p {
        case let .string(s)?: return IV.same(s, "*") || IV.same(s, verb)
        case let .array(a)?: return a.contains { $0.asString.map { IV.same($0, "*") || IV.same($0, verb) } ?? false }
        default: return false
        }
    }

    static func resourceMatches(_ pattern: JSONValue?, _ resource: String, _ budget: SafeRegex.Budget) -> Bool {
        guard let pv = pattern else { return true }
        guard case let .string(pat) = pv else { return false }
        if IV.same(pat, "*") { return true }
        if IV.startsWith(pat, "re:") {
            let src = IV.dropPrefix(pat, 3)
            if IV.u16(src) > MAX_RE_SRC_LEN || IV.u16(resource) > MAX_RE_RESOURCE_LEN { return false }
            return SafeRegex.fullMatchTri(src, resource, budget) == true
        }
        let pu = Array(pat.utf16)
        if pu.last == 0x2a { return Array(resource.utf16).starts(with: pu.dropLast()) }
        return IV.same(pat, resource)
    }

    static func predicateMatches(_ p: JSONValue, _ ctx: JSONValue, _ budget: SafeRegex.Budget) -> Bool {
        guard case let .object(o) = p, let action = ctx.get("action"), let verb = action.get("verb")?.asString,
              let resource = action.get("resource")?.asString else { return false }
        if !verbMatches(o["verb"], verb) { return false }
        if !resourceMatches(o["resource"], resource, budget) { return false }
        if let w = o["where"] {
            guard case let .array(conds) = w else { return false }
            for c in conds where conditionTri(c, ctx, budget) != .t { return false }
        }
        return true
    }

    /// `evaluatePredicates(predicates, ctx).allowed`: some predicate matches (verb AND resource AND every `where`); an
    /// empty or non-list predicate set allows nothing. One regex work budget per call (a document scope).
    static func evaluate(_ predicates: JSONValue?, _ ctx: JSONValue) -> Bool {
        guard case let .array(ps)? = predicates, !ps.isEmpty else { return false }
        let budget = SafeRegex.Budget()
        return ps.contains { predicateMatches($0, ctx, budget) }
    }

    // ---- B6 (0.5): name the limit that was not met (TypeScript firstUnmetLimit / describeCondition / showValue) ----

    static let OP_TEXT: [String: String] = [
        "eq": "==", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "in": "in", "nin": "not in", "prefix": "starts with",
        "like": "like", "matches": "matches", "is_a": "is a", "member_of": "member of",
    ]
    static let MAX_SHOWN_STRING = 64
    static let MAX_SHOWN_ITEMS = 8

    /// A scalar operand in a denial reason: only safe integers, booleans, null and plain short strings are spelled out.
    static func showValue(_ v: JSONValue?, _ depth: Int = 0) -> String {
        switch v {
        case .null?: return "null"
        case let .bool(b)?: return b ? "true" : "false"
        case .int?, .double?: return v?.safeInt.map { String($0) } ?? "<number>"
        case let .string(s)?:
            let plain = s.utf16.count <= MAX_SHOWN_STRING && s.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x22 && $0.value != 0x5c && $0.value <= 0xffff }
            return plain ? "\"\(s)\"" : "\"...\""
        case let .array(a)? where depth == 0:
            return a.count <= MAX_SHOWN_ITEMS ? "[" + a.map { showValue($0, 1) }.joined(separator: ", ") + "]" : "[...]"
        default: return "<value>"
        }
    }

    /// The condition as the limit a reader recognises: `amount <= 500`, `currency in ["usd", "eur"]`.
    static func describeCondition(_ c: JSONValue?, _ depth: Int = 0) -> String {
        let o: JObject
        switch c {
        case let .object(x)?: o = x
        case .array?: o = [:] // the reference treats an array as a leaf with no field or op
        default: return "<condition>"
        }
        if isGroup(o) {
            if depth >= 2 { return "(...)" }
            func kids(_ a: [JSONValue]) -> String { a.prefix(MAX_SHOWN_ITEMS).map { describeCondition($0, depth + 1) }.joined(separator: "; ") }
            if case let .array(a)? = o["all_of"] { return "all of (\(kids(a)))" }
            if case let .array(a)? = o["any_of"] { return "any of (\(kids(a)))" }
            if let n = o["not"] { return "not (\(describeCondition(n, depth + 1)))" }
            return "<condition>"
        }
        let f = o["field"]?.asString ?? "<field>"
        let name = IV.startsWith(f, "action.params.") ? IV.dropPrefix(f, "action.params.".unicodeScalars.count) : f
        let op = o["op"]?.asString
        if op == "exists" {
            if case .bool(false)? = o["value"] { return "\(name) absent" }
            return "\(name) present"
        }
        guard let t = op.flatMap({ OP_TEXT[$0] }) else { return "\(name) <condition>" }
        if let r = o["ref"] { return "\(name) \(t) \(r.asString ?? "<ref>")" }
        return "\(name) \(t) \(showValue(o["value"]))"
    }

    /// Inside an unmet top-level condition, the narrowest part that failed (an `all_of` points at its first unmet child).
    static func narrowestUnmet(_ c: JSONValue, _ ctx: JSONValue, _ budget: SafeRegex.Budget, _ depth: Int = 0) -> JSONValue {
        if depth < 4, case let .object(o) = c, isGroup(o), case let .array(xs)? = o["all_of"] {
            for x in xs where conditionTri(x, ctx, budget) != .t { return narrowestUnmet(x, ctx, budget, depth + 1) }
        }
        return c
    }

    /// When a predicate's verb and resource are in scope but a `where` limit is not met, the narrowest unmet limit described;
    /// nil when no predicate is in scope (the plain "no predicate permits" wording stays).
    static func firstUnmetLimit(_ predicates: JSONValue?, _ ctx: JSONValue, _ budget: SafeRegex.Budget) -> String? {
        guard case let .array(ps)? = predicates, let a = ctx.get("action"), let verb = a.get("verb")?.asString,
              let resource = a.get("resource")?.asString else { return nil }
        for p in ps {
            guard case let .object(o) = p, verbMatches(o["verb"], verb), resourceMatches(o["resource"], resource, budget),
                  case let .array(conds)? = o["where"] else { continue }
            for c in conds where conditionTri(c, ctx, budget) != .t { return describeCondition(narrowestUnmet(c, ctx, budget)) }
        }
        return nil
    }
}
