import Foundation

/// OPA / Rego to PCA predicates: only the "allow rule as a conjunction of input comparisons" idiom is modeled. Each `allow` body is
/// one predicate (rules OR together); any statement outside the subset drops the whole rule (a dropped conjunct could only widen the
/// allow), and a rule whose action or resource selectors contradict each other can never match and emits nothing.
extension PCAPolicyBridge {
    /// Throws only where the reference's recursive statement parser would overflow the stack (a long `not not not ...` chain).
    public static func regoToPca(_ moduleText: String) throws -> JSONValue {
        let report = Report("rego")
        var predicates: [JSONValue] = []
        let src = PBT.stripComments(PBT.u(moduleText), lead: PBT.u("#"))

        if let pkg = PBRego.packageName(src) { report.translated.append("package \(pkg)") }
        switch PBRego.defaultAllow(src) {
        case .some(true): report.skipped.append("`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny")
        case .none: report.skipped.append("no `default allow = false` found; assuming default-deny")
        case .some(false): break
        }
        for body in PBRego.extractAllowBodies(src, report) { try PBRego.translateRule(body, &predicates, report) }
        return bridgeResult(predicates, [], report)
    }
}

enum PBRego {
    typealias U = PBT.U
    static func u(_ s: String) -> U { PBT.u(s) }

    /// `\bpackage\s+([A-Za-z_][\w.]*)`: the first match.
    static func packageName(_ s: U) -> String? {
        let kw = u("package")
        var p = 0
        while p + kw.count <= s.count {
            if (p == 0 || !PBT.isWord(s[p - 1])) && PBT.startsWith(s, kw, p) {
                let e = p + kw.count
                if e < s.count && PBT.isWS(s[e]) {
                    let i = PBT.skipWS(s, e)
                    if i < s.count && PBT.isIdentStart(s[i]) {
                        var j = i + 1
                        while j < s.count && (PBT.isWord(s[j]) || s[j] == 0x2e) { j += 1 }
                        return PBT.str(PBT.sub(s, i, j))
                    }
                }
            }
            p += 1
        }
        return nil
    }

    /// `\bdefault\s+allow\s*(?::?=)\s*(true|false)\b`: the first match's value, nil when there is none.
    static func defaultAllow(_ s: U) -> Bool? {
        let kw = u("default"), al = u("allow")
        var p = 0
        while p + kw.count <= s.count {
            if (p == 0 || !PBT.isWord(s[p - 1])) && PBT.startsWith(s, kw, p) {
                let e = p + kw.count
                if e < s.count && PBT.isWS(s[e]) {
                    var i = PBT.skipWS(s, e)
                    if PBT.startsWith(s, al, i) {
                        i = PBT.skipWS(s, i + al.count)
                        if i < s.count && s[i] == 0x3a { i += 1 }
                        if i < s.count && s[i] == 0x3d {
                            i = PBT.skipWS(s, i + 1)
                            for (w, v) in [("true", true), ("false", false)] {
                                let wu = u(w)
                                if PBT.startsWith(s, wu, i) && (i + wu.count >= s.count || !PBT.isWord(s[i + wu.count])) { return v }
                            }
                        }
                    }
                }
            }
            p += 1
        }
        return nil
    }

    /// Each `allow { ... }` body (`allow = true {`, `allow := true {`, `allow if {` too), brace-aware.
    static func extractAllowBodies(_ s: U, _ report: PCAPolicyBridge.Report) -> [U] {
        var bodies: [U] = []
        let kw = u("allow")
        var from = 0
        while from < s.count {
            var open = -1
            var p = from
            while p + kw.count <= s.count {
                if (p == 0 || !PBT.isWord(s[p - 1])) && PBT.startsWith(s, kw, p) {
                    let e = p + kw.count
                    if e >= s.count || !PBT.isWord(s[e]) {
                        var i = PBT.skipWS(s, e)
                        var matched = false
                        if i < s.count && (s[i] == 0x3d || (s[i] == 0x3a && i + 1 < s.count && s[i + 1] == 0x3d)) {
                            i += s[i] == 0x3a ? 2 : 1
                            i = PBT.skipWS(s, i)
                            let t = u("true")
                            if PBT.startsWith(s, t, i) && (i + 4 >= s.count || !PBT.isWord(s[i + 4])) {
                                i = PBT.skipWS(s, i + 4)
                                matched = i < s.count && s[i] == 0x7b
                            }
                        } else if PBT.startsWith(s, u("if"), i) && (i + 2 >= s.count || !PBT.isWord(s[i + 2])) {
                            i = PBT.skipWS(s, i + 2)
                            matched = i < s.count && s[i] == 0x7b
                        } else {
                            matched = i < s.count && s[i] == 0x7b
                        }
                        if matched { open = i; break }
                    }
                }
                p += 1
            }
            if open < 0 { break }
            let close = PBT.matchDelim(s, open, 0x7b, 0x7d)
            if close < 0 {
                report.errors.append("unterminated `allow { ... }` block")
                break
            }
            bodies.append(PBT.sub(s, open + 1, close))
            from = close + 1
        }
        return bodies
    }

    enum Parsed {
        case verb(JSONValue)
        case resource(String)
        case condition(JSONValue)
        case unmodeled
    }

    static func translateRule(_ body: U, _ predicates: inout [JSONValue], _ report: PCAPolicyBridge.Report) throws {
        var statements: [U] = []
        var cur = U()
        for c in body {
            if c == 0x0a || c == 0x3b { statements.append(cur); cur = [] } else { cur.append(c) }
        }
        statements.append(cur)
        statements = statements.map(PBT.trim).filter { !$0.isEmpty }

        var verb: JSONValue = .string("*")
        var resource: String?
        var whereList: [JSONValue] = []

        for stmt in statements {
            switch try parseStatement(stmt, 0) {
            case .unmodeled:
                report.skipped.append("unmodeled statement \"\(PBT.truncate(stmt))\" — rule dropped (fail closed)")
                return
            case let .verb(v):
                // every statement must hold, so a second action selector NARROWS the first
                if verb == .string("*") {
                    verb = v
                } else {
                    let have = verb.asArray ?? [verb]
                    let next = v.asArray ?? [v]
                    let both = have.filter { next.contains($0) }
                    if both.isEmpty {
                        report.translated.append("rule can never match (contradictory action selectors), nothing emitted")
                        return
                    }
                    verb = both.count == 1 ? both[0] : .array(both)
                }
            case let .resource(r):
                if let have = resource, !IV.same(have, r) {
                    report.translated.append("rule can never match (contradictory resource selectors), nothing emitted")
                    return
                }
                resource = r
            case let .condition(c):
                whereList.append(c)
            }
        }
        predicates.append(PCAPolicyBridge.predicate(verb: verb, resource: resource, where: whereList))
        let on = (resource ?? "").isEmpty ? "" : " on \(resource!)"
        report.translated.append("allow → verb \(JS.stringify(verb))\(on) (\(whereList.count) condition(s))")
    }

    // ---- statements ------------------------------------------------------------------------------------------------------------

    static func parseStatement(_ stmt: U, _ d: Int) throws -> Parsed {
        if d > PCAPolicyBridge.MAX_FRAMES { throw JSError(PCAPolicyBridge.STACK) }
        let s = PBT.trim(stmt)

        // `not <stmt>`: the inner must resolve to a modeled condition
        if s.count >= 5, PBT.startsWith(s, u("not"), 0), PBT.isWS(s[3]) {
            let restStart = PBT.skipWS(s, 3)
            if restStart < s.count {
                let inner = try parseStatement(PBT.trim(PBT.sub(s, restStart, s.count)), d + 1)
                guard case let .condition(c) = inner else { return .unmodeled }
                // `not input.p == lit` is unification: an absent path makes it undefined, so the `not` holds; spell the existence out
                if case let .object(o) = c, o["op"]?.asString == "eq", let f = o["field"]?.asString {
                    var needs = [PCAPolicyBridge.leaf(f, "exists")]
                    if let r = o["ref"]?.asString { needs.append(PCAPolicyBridge.leaf(r, "exists")) }
                    return .condition(PCAPolicyBridge.not(.object(["all_of": .array(needs + [c])])))
                }
                return .condition(PCAPolicyBridge.not(c))
            }
        }

        if let b = parseBuiltin(s) { return b }

        if hasAssignOrQuantifier(s) { return .unmodeled }
        if s.contains(0x28) { return .unmodeled }
        if hasInputIndex(s) { return .unmodeled }

        guard let m = matchComparison(s) else { return .unmodeled }
        let sub = m.path
        let opTok = m.op
        let rhsRaw = m.rhs
        let field = "env." + PBT.str(sub)

        if opTok == "in" {
            guard let set = parseSetLiteral(rhsRaw) else { return .unmodeled }
            if PBT.str(sub) == "action" {
                let verbs = set.filter { $0.asString != nil }
                if verbs.count != set.count { return .unmodeled }
                return .verb(.array(verbs))
            }
            return .condition(PCAPolicyBridge.leaf(field, "in", value: .array(set)))
        }

        if opTok == "==" || opTok == "!=", isInputPath(rhsRaw) {
            return .condition(PCAPolicyBridge.leaf(field, opTok == "!=" ? "ne" : "eq", ref: "env." + PBT.str(PBT.sub(rhsRaw, 6, rhsRaw.count))))
        }

        guard let lit = toLiteral(rhsRaw) else { return .unmodeled }
        let subS = PBT.str(sub)
        if opTok == "==" {
            if subS == "action", case .string = lit { return .verb(lit) }
            if subS == "resource", case let .string(r) = lit { return .resource(r) }
            return .condition(PCAPolicyBridge.leaf(field, "eq", value: lit))
        }
        if opTok == "!=" { return .condition(PCAPolicyBridge.leaf(field, "ne", value: lit)) }

        // numeric comparisons only make sense against a number
        guard lit.isNumber else { return .unmodeled }
        let cmp = opTok == "<" ? "lt" : opTok == "<=" ? "lte" : opTok == ">" ? "gt" : "gte"
        return .condition(PCAPolicyBridge.leaf(field, cmp, value: lit))
    }

    /// `/:=|\bsome\b|\bevery\b|\[.*\|.*\]/`.
    static func hasAssignOrQuantifier(_ s: U) -> Bool {
        if PBT.indexOfSub(s, u(":=")) >= 0 { return true }
        for w in ["some", "every"] {
            let wu = u(w)
            var p = 0
            while p + wu.count <= s.count {
                if (p == 0 || !PBT.isWord(s[p - 1])) && PBT.startsWith(s, wu, p) && (p + wu.count >= s.count || !PBT.isWord(s[p + wu.count])) { return true }
                p += 1
            }
        }
        // a `[ ... | ... ]` inside one line (`.` does not cross a line terminator)
        var stage = 0
        for c in s {
            if PBT.isLineTerminator(c) { stage = 0; continue }
            if stage == 0 && c == 0x5b { stage = 1 } else if stage == 1 && c == 0x7c { stage = 2 } else if stage == 2 && c == 0x5d { return true }
        }
        return false
    }

    /// `/\binput\.[\w.]*\[/`.
    static func hasInputIndex(_ s: U) -> Bool {
        let kw = u("input.")
        var p = 0
        while p + kw.count <= s.count {
            if (p == 0 || !PBT.isWord(s[p - 1])) && PBT.startsWith(s, kw, p) {
                var i = p + kw.count
                while i < s.count && (PBT.isWord(s[i]) || s[i] == 0x2e) { i += 1 }
                if i < s.count && s[i] == 0x5b { return true }
            }
            p += 1
        }
        return false
    }

    /// `^input\.[\w.]+$`.
    static func isInputPath(_ x: U) -> Bool {
        x.count > 6 && PBT.startsWith(x, u("input."), 0) && PBT.allWordOrDot(PBT.sub(x, 6, x.count))
    }

    /// `^(input\.[\w.]+)\s*(==|!=|<=|>=|<|>|\bin\b)\s*(.+)$` (dot matches everything), with the engine's backtracking over the path.
    static func matchComparison(_ s: U) -> (path: U, op: String, rhs: U)? {
        guard PBT.startsWith(s, u("input."), 0) else { return nil }
        var e0 = 6
        while e0 < s.count && (PBT.isWord(s[e0]) || s[e0] == 0x2e) { e0 += 1 }
        var e = e0
        while e >= 7 {
            let p = PBT.skipWS(s, e)
            for op in ["==", "!=", "<=", ">=", "<", ">", "in"] {
                let ou = u(op)
                guard PBT.startsWith(s, ou, p) else { continue }
                if op == "in" && (PBT.isWord(s[p - 1]) || (p + 2 < s.count && PBT.isWord(s[p + 2]))) { continue }
                let q = PBT.skipWS(s, p + ou.count)
                if q < s.count { return (PBT.sub(s, 6, e), op, PBT.trim(PBT.sub(s, q, s.count))) }
            }
            e -= 1
        }
        return nil
    }

    /// `startswith(input.<p>, "pre")` and `glob.match("pat", null | [], input.<p>)`; nil means "not a builtin we model".
    static func parseBuiltin(_ s: U) -> Parsed? {
        func ws(_ i: inout Int) { i = PBT.skipWS(s, i) }
        func lit(_ i: inout Int, _ t: String) -> Bool {
            let tu = u(t)
            if PBT.startsWith(s, tu, i) { i += tu.count; return true }
            return false
        }
        func quoted(_ i: inout Int) -> U? {
            guard i < s.count, s[i] == 0x22 else { return nil }
            var j = i + 1
            while j < s.count && s[j] != 0x22 { j += 1 }
            guard j < s.count else { return nil }
            let r = PBT.sub(s, i + 1, j)
            i = j + 1
            return r
        }
        func inputPath(_ i: inout Int) -> U? {
            guard lit(&i, "input.") else { return nil }
            let from = i
            while i < s.count && (PBT.isWord(s[i]) || s[i] == 0x2e) { i += 1 }
            return i > from ? PBT.sub(s, from, i) : nil
        }

        var i = 0
        if lit(&i, "startswith(") {
            ws(&i)
            if let path = inputPath(&i) {
                ws(&i)
                if lit(&i, ",") {
                    ws(&i)
                    if let pre = quoted(&i) {
                        ws(&i)
                        if lit(&i, ")") && i == s.count {
                            return .condition(PCAPolicyBridge.leaf("env." + PBT.str(path), "prefix", value: .string(PBT.str(pre))))
                        }
                    }
                }
            }
            return nil
        }
        i = 0
        if lit(&i, "glob.match(") {
            ws(&i)
            if let pat = quoted(&i) {
                ws(&i)
                if lit(&i, ",") {
                    ws(&i)
                    var delim: String?
                    if lit(&i, "null") {
                        delim = "null"
                    } else if lit(&i, "[") {
                        ws(&i)
                        if lit(&i, "]") { delim = "[" }
                    }
                    if let dl = delim {
                        ws(&i)
                        if lit(&i, ",") {
                            ws(&i)
                            if let path = inputPath(&i) {
                                ws(&i)
                                if lit(&i, ")") && i == s.count {
                                    // character classes and brace alternation do not map onto the `like` glob
                                    if pat.contains(where: { $0 == 0x5b || $0 == 0x5d || $0 == 0x7b || $0 == 0x7d }) { return .unmodeled }
                                    // an EMPTY delimiter list splits on ".": only a pattern with no wildcard translates
                                    if dl == "[" && pat.contains(where: { $0 == 0x2a || $0 == 0x3f || $0 == 0x5c }) { return .unmodeled }
                                    return .condition(PCAPolicyBridge.leaf("env." + PBT.str(path), "like", value: .string(PBT.str(pat))))
                                }
                            }
                        }
                    }
                }
            }
        }
        return nil
    }

    // ---- literals --------------------------------------------------------------------------------------------------------------

    static func toLiteral(_ expr: U) -> JSONValue? {
        let s = PBT.trim(expr)
        if s.count >= 2, s.first == 0x22, s.last == 0x22, !PBT.sub(s, 1, s.count - 1).contains(0x22) { return .string(PBT.str(PBT.inner(s))) }
        let t = PBT.str(s)
        if t == "true" { return .bool(true) }
        if t == "false" { return .bool(false) }
        if PBCedar.isDecimal(s) { return PCAPolicyBridge.numberValue(t) }
        return nil
    }

    /// A Rego set `{"a","b"}` or array `["a","b"]` of scalar literals.
    static func parseSetLiteral(_ expr: U) -> [JSONValue]? {
        let s = PBT.trim(expr)
        let isSet = s.first == 0x7b && s.last == 0x7d
        let isArr = s.first == 0x5b && s.last == 0x5d
        guard isSet || isArr else { return nil }
        let items = PBT.splitTopLevel(PBT.inner(s), u(",")).map(PBT.trim).filter { !$0.isEmpty }
        var values: [JSONValue] = []
        for it in items {
            guard let lit = toLiteral(it) else { return nil }
            values.append(lit)
        }
        return values
    }
}

extension PBT {
    /// Index of the first occurrence of `p` in `x`, or -1.
    static func indexOfSub(_ x: U, _ p: U) -> Int {
        var i = 0
        while i + p.count <= x.count {
            if startsWith(x, p, i) { return i }
            i += 1
        }
        return -1
    }
}
