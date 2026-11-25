import Foundation

/// Cedar to PCA predicates. `permit` becomes a permit predicate, `forbid` a deny predicate (consume with `decide`); scope clauses and
/// `when` / `unless` blocks over `&&`, `||`, parentheses and comparison atoms map onto PCA conditions, and the trailing guard makes a
/// policy apply only when evaluating it reads no absent attribute (Cedar skips a policy whose condition raises an error). Anything
/// outside the subset (arithmetic, set methods, `if`, extension functions) drops the policy: a dropped `permit` grants nothing, a dropped
/// `forbid` is reported as an error so the translation fails closed.
extension PCAPolicyBridge {
    public static func cedarToPca(_ policyText: String) -> JSONValue { translateCedar(policyText, errorGuards: true) }

    /// `errorGuards: false` leaves the bare structure of each expression (not exact for policies that read attributes a request may lack).
    public static func translateCedar(_ policyText: String, errorGuards: Bool) -> JSONValue {
        let report = Report("cedar")
        var predicates: [JSONValue] = []
        var denies: [JSONValue] = []
        let cleaned = PBT.stripComments(PBT.u(policyText), lead: PBT.u("//"))
        let statements = PBT.splitTopLevel(cleaned, PBT.u(";")).map(PBT.trim).filter { !$0.isEmpty }
        for stmt in statements {
            do {
                try PBCedar.translateStatement(stmt, &predicates, &denies, report, errorGuards)
            } catch let e as Fail {
                report.errors.append("policy \"\(PBT.truncate(stmt))\": \(e.message)")
            } catch {
                report.errors.append("policy \"\(PBT.truncate(stmt))\": \(error)")
            }
        }
        return bridgeResult(predicates, denies, report)
    }
}

enum PBCedar {
    typealias U = PBT.U
    typealias Fail = PCAPolicyBridge.Fail
    static let ENTITY_PARENTS = "env.entity_parents"

    static func u(_ s: String) -> U { PBT.u(s) }

    /// Length of the leading `@name(...)` heads (with the whitespace around them), 0 when there is none.
    static func annotationLength(_ b: U) -> Int {
        var i = PBT.skipWS(b, 0)
        var end = 0
        while i < b.count && b[i] == 0x40 {
            var j = i + 1
            guard j < b.count, PBT.isIdentStart(b[j]) else { break }
            j += 1
            while j < b.count && PBT.isWord(b[j]) { j += 1 }
            j = PBT.skipWS(b, j)
            guard j < b.count, b[j] == 0x28 else { break }
            j += 1
            while j < b.count && b[j] != 0x29 { j += 1 }
            guard j < b.count else { break }
            j += 1
            j = PBT.skipWS(b, j)
            end = j
            i = j
        }
        return end
    }

    /// `^\s*(permit|forbid)\s*\(` (ASCII case-insensitive): true for forbid, false for permit, nil without a head.
    static func head(_ b: U) -> Bool? {
        let i = PBT.skipWS(b, 0)
        for (w, forbid) in [("permit", false), ("forbid", true)] {
            let wu = u(w)
            guard i + wu.count <= b.count else { continue }
            var ok = true
            for k in 0..<wu.count where PBT.lower(b[i + k]) != wu[k] { ok = false; break }
            if !ok { continue }
            let j = PBT.skipWS(b, i + wu.count)
            if j < b.count && b[j] == 0x28 { return forbid }
        }
        return nil
    }

    static func translateStatement(_ stmt: U, _ permits: inout [JSONValue], _ denies: inout [JSONValue], _ report: PCAPolicyBridge.Report, _ errorGuards: Bool) throws {
        var body = stmt
        let al = annotationLength(body)
        if al > 0 { body = PBT.sub(body, al, body.count) }

        guard let isForbid = head(body) else {
            report.skipped.append("unrecognized statement: \"\(PBT.truncate(stmt))\"")
            return
        }
        let openIdx = PBT.indexOf(body, 0x28)
        let closeIdx = PBT.matchDelim(body, openIdx, 0x28, 0x29)
        if closeIdx < 0 { throw Fail(message: "unterminated scope parentheses") }
        let scopeText = PBT.sub(body, openIdx + 1, closeIdx)
        let rest = PBT.sub(body, closeIdx + 1, body.count)

        let scope = try parseScope(scopeText)
        var whereList: [JSONValue] = scope.conds
        var guards: [JSONValue] = []

        for block in try parseConditionBlocks(rest) {
            guard let parsed = try parseExpr(block.text, 0) else {
                report.skipped.append("unmodeled \(block.kind)-condition \"\(PBT.truncate(block.text))\" — policy dropped (fail closed)")
                if isForbid {
                    report.errors.append("forbid could not be fully modeled and was dropped — treat result as fail-closed: \"\(PBT.truncate(stmt))\"")
                }
                return
            }
            whereList.append(block.kind == "when" ? parsed : PCAPolicyBridge.not(parsed))
            if let g = try noError(parsed, 0) { guards.append(g) }
        }

        let conditionCount = whereList.count
        if errorGuards && !guards.isEmpty { whereList.append(guards.count == 1 ? guards[0] : .object(["all_of": .array(guards)])) }

        let pred = PCAPolicyBridge.predicate(verb: scope.verb, resource: scope.resource, where: whereList)
        let on = (scope.resource ?? "").isEmpty ? "" : " on \(scope.resource!)"
        let text = "verb \(JS.stringify(scope.verb))\(on) (\(conditionCount) condition(s))"
        if !isForbid {
            permits.append(pred)
            report.translated.append("permit → \(text)")
        } else {
            denies.append(pred)
            report.translated.append("forbid → deny \(text)")
        }
    }

    // ---- scope -----------------------------------------------------------------------------------------------------------------

    struct Scope {
        var verb: JSONValue = .string("*")
        var resource: String?
        var conds: [JSONValue] = []
    }

    static func parseScope(_ scopeText: U) throws -> Scope {
        let clauses = PBT.splitTopLevel(scopeText, u(",")).map(PBT.trim).filter { !$0.isEmpty }
        var result = Scope()
        for clause in clauses {
            // ^(principal|action|resource)\b\s*(?:(==|in|is)\s*)?([\s\S]*)$
            var variable: String?
            var wordLen = 0
            for w in ["principal", "action", "resource"] {
                let wu = u(w)
                if PBT.startsWith(clause, wu, 0) && !(wu.count < clause.count && PBT.isWord(clause[wu.count])) {
                    variable = w
                    wordLen = wu.count
                    break
                }
            }
            guard let v = variable else { throw Fail(message: "unparseable scope clause \"\(PBT.truncate(clause))\"") }
            var i = PBT.skipWS(clause, wordLen)
            var op: String?
            for cand in ["==", "in", "is"] where PBT.startsWith(clause, u(cand), i) {
                op = cand
                i += 2
                break
            }
            guard let o = op else { continue }
            i = PBT.skipWS(clause, i)
            let operand = PBT.trim(PBT.sub(clause, i, clause.count))

            if v == "action" {
                if o == "==" {
                    guard let id = entityId(operand) else { throw Fail(message: "action == expects an Action entity, got \"\(PBT.truncate(operand))\"") }
                    result.verb = .string(id)
                } else if o == "in" && operand.first == 0x5b {
                    let items = PBT.splitTopLevel(PBT.inner(operand), u(",")).map(PBT.trim).filter { !$0.isEmpty }
                    var verbs: [JSONValue] = []
                    for it in items {
                        guard let id = entityId(it) else { throw Fail(message: "action in [...] expects Action entities, got \"\(PBT.truncate(it))\"") }
                        verbs.append(.string(id))
                    }
                    result.verb = .array(verbs)
                } else {
                    throw Fail(message: "unsupported action scope operator \"\(o)\"")
                }
            } else {
                let field = v == "resource" ? "action.resource" : "subject.id"
                if o == "==" {
                    guard let eid = entityUid(operand) else {
                        throw Fail(message: v == "resource" ? "resource == expects an entity, got \"\(PBT.truncate(operand))\"" : "principal == expects an entity, got \"\(PBT.truncate(operand))\"")
                    }
                    if v == "resource" { result.resource = eid } else { result.conds.append(PCAPolicyBridge.leaf(field, "eq", value: .string(eid))) }
                } else if o == "is" {
                    guard let t = typeName(operand) else { throw Fail(message: "\(v) is expects a type, got \"\(PBT.truncate(operand))\"") }
                    result.conds.append(PCAPolicyBridge.leaf(field, "is_a", value: .string(t)))
                } else {
                    guard let mem = memberOfCondition(field, operand) else { throw Fail(message: "\(v) in expects an entity (hierarchy), got \"\(PBT.truncate(operand))\"") }
                    result.conds.append(mem)
                }
            }
        }
        return result
    }

    // ---- conditions ------------------------------------------------------------------------------------------------------------

    /// `\b(when|unless)\b\s*\{` blocks, each with the text between its braces.
    static func parseConditionBlocks(_ rest: U) throws -> [(kind: String, text: U)] {
        var out: [(kind: String, text: U)] = []
        var from = 0
        let n = rest.count
        while from < n {
            var found = -1, openAt = -1
            var kind = ""
            var p = from
            search: while p < n {
                if p == 0 || !PBT.isWord(rest[p - 1]) {
                    for kw in ["when", "unless"] {
                        let ku = u(kw)
                        if PBT.startsWith(rest, ku, p) {
                            let e = p + ku.count
                            if e >= n || !PBT.isWord(rest[e]) {
                                let k = PBT.skipWS(rest, e)
                                if k < n && rest[k] == 0x7b {
                                    found = p
                                    openAt = k
                                    kind = kw
                                    break search
                                }
                            }
                        }
                    }
                }
                p += 1
            }
            if found < 0 { break }
            let close = PBT.matchDelim(rest, openAt, 0x7b, 0x7d)
            if close < 0 { throw Fail(message: "unterminated \(kind) block") }
            out.append((kind, PBT.sub(rest, openAt + 1, close)))
            from = close + 1
        }
        return out
    }

    /// `||` over `&&` over parenthesised groups over comparison atoms; nil when any atom is outside the subset.
    static func parseExpr(_ text: U, _ d: Int) throws -> JSONValue? {
        if d > PCAPolicyBridge.MAX_FRAMES { throw Fail(message: PCAPolicyBridge.STACK) }
        let t = PBT.trim(text)
        if t.isEmpty { return nil }

        let ors = PBT.splitTopLevel(t, u("||")).map(PBT.trim).filter { !$0.isEmpty }
        if ors.count > 1 {
            var subs: [JSONValue] = []
            var bad = false
            for o in ors { if let s = try parseExpr(o, d + 1) { subs.append(s) } else { bad = true } }
            if bad { return nil }
            return .object(["any_of": .array(subs)])
        }
        let ands = PBT.splitTopLevel(t, u("&&")).map(PBT.trim).filter { !$0.isEmpty }
        if ands.count > 1 {
            var subs: [JSONValue] = []
            var bad = false
            for a in ands { if let s = try parseExpr(a, d + 1) { subs.append(s) } else { bad = true } }
            if bad { return nil }
            return .object(["all_of": .array(subs)])
        }
        if t[0] == 0x28 && PBT.matchDelim(t, 0, 0x28, 0x29) == t.count - 1 { return try parseExpr(PBT.inner(t), d + 1) }
        return parseAtom(t)
    }

    static let symbolic: [(String, String)] = [("==", "eq"), ("!=", "ne"), ("<=", "lte"), (">=", "gte"), ("<", "lt"), (">", "gt")]

    static func parseAtom(_ text: U) -> JSONValue? {
        let t = PBT.trim(text)
        for (tok, op) in symbolic {
            let idx = PBT.indexOfTopLevel(t, u(tok))
            if idx >= 0 {
                return buildComparison(PBT.trim(PBT.sub(t, 0, idx)), op, PBT.trim(PBT.sub(t, idx + tok.count, t.count)))
            }
        }
        // ^([\s\S]*?\S)\s+(in|is|like|has)\s+([\s\S]+)$ : the first non-space character followed by spaces and a keyword
        var e = 1
        while e < t.count {
            if !PBT.isWS(t[e - 1]) && PBT.isWS(t[e]) {
                let p = PBT.skipWS(t, e)
                for kw in ["in", "is", "like", "has"] {
                    let ku = u(kw)
                    if PBT.startsWith(t, ku, p) {
                        let k = p + ku.count
                        if k + 1 < t.count && PBT.isWS(t[k]) {
                            return buildWordOp(PBT.trim(PBT.sub(t, 0, e)), kw, PBT.trim(PBT.sub(t, k, t.count)))
                        }
                    }
                }
            }
            e += 1
        }
        return nil
    }

    static func buildComparison(_ lhsRaw: U, _ op: String, _ rhsRaw: U) -> JSONValue? {
        guard let field = toFieldPath(lhsRaw) else { return nil }
        if field == "action.verb" {
            if op != "eq" && op != "ne" { return nil }
            guard let id = entityId(rhsRaw) else { return nil }
            return PCAPolicyBridge.leaf(field, op, value: .string(id))
        }
        if isPathExpr(rhsRaw), let refPath = toFieldPath(rhsRaw) { return PCAPolicyBridge.leaf(field, op, ref: refPath) }
        guard let lit = toLiteral(rhsRaw) else { return nil }
        return PCAPolicyBridge.leaf(field, op, value: lit)
    }

    static func isIdent(_ x: U) -> Bool { !x.isEmpty && PBT.isIdentStart(x[0]) && x.allSatisfy { PBT.isWord($0) } }

    static func buildWordOp(_ lhsRaw: U, _ kind: String, _ rhsRaw: U) -> JSONValue? {
        if kind == "has" {
            if !isIdent(rhsRaw) { return nil }
            guard let field = toFieldPath(lhsRaw + [0x2e] + rhsRaw) else { return nil }
            return PCAPolicyBridge.leaf(field, "exists")
        }
        guard let field = toFieldPath(lhsRaw) else { return nil }

        if field == "action.verb" {
            if kind != "in" { return nil }
            let inner = (rhsRaw.first == 0x5b && rhsRaw.last == 0x5d) ? PBT.inner(rhsRaw) : rhsRaw
            let ids = PBT.splitTopLevel(inner, u(",")).map(PBT.trim).filter { !$0.isEmpty }.map(entityId)
            if !ids.isEmpty && ids.allSatisfy({ $0 != nil }) { return PCAPolicyBridge.leaf(field, "in", value: .array(ids.map { .string($0!) })) }
            return nil
        }
        if kind == "is" {
            guard let t = typeName(rhsRaw) else { return nil }
            return PCAPolicyBridge.leaf(field, "is_a", value: .string(t))
        }
        if kind == "like" {
            guard rhsRaw.count >= 2, rhsRaw.first == 0x22, rhsRaw.last == 0x22 else { return nil }
            return PCAPolicyBridge.leaf(field, "like", value: .string(PBT.str(cedarLikeToGlob(PBT.inner(rhsRaw)))))
        }
        // kind == "in"
        if rhsRaw.first == 0x5b {
            let inner = rhsRaw.last == 0x5d ? PBT.inner(rhsRaw) : PBT.sub(rhsRaw, 1, rhsRaw.count)
            let items = PBT.splitTopLevel(inner, u(",")).map(PBT.trim).filter { !$0.isEmpty }
            let uids = items.map(entityUid)
            if !items.isEmpty && uids.allSatisfy({ $0 != nil }) {
                return PCAPolicyBridge.leaf(field, "member_of", value: .array(uids.map { .string($0!) }), collection: ENTITY_PARENTS)
            }
            var values: [JSONValue] = []
            for it in items {
                guard let lit = toLiteral(it) else { return nil }
                values.append(lit)
            }
            return PCAPolicyBridge.leaf(field, "in", value: .array(values))
        }
        return memberOfCondition(field, rhsRaw)
    }

    /// A `member_of` condition for `<field> in <entity|path>`.
    static func memberOfCondition(_ field: String, _ operand: U) -> JSONValue? {
        if let eid = entityUid(operand) { return PCAPolicyBridge.leaf(field, "member_of", value: .string(eid), collection: ENTITY_PARENTS) }
        if isPathExpr(operand), let ref = toFieldPath(operand) { return PCAPolicyBridge.leaf(field, "member_of", ref: ref, collection: ENTITY_PARENTS) }
        return nil
    }

    /// `^(principal|resource|action|context)\b`.
    static func isPathExpr(_ x: U) -> Bool {
        for w in ["principal", "resource", "action", "context"] {
            let wu = u(w)
            if PBT.startsWith(x, wu, 0) && !(wu.count < x.count && PBT.isWord(x[wu.count])) { return true }
        }
        return false
    }

    /// The PCA dotted field path of a Cedar scope-variable expression, nil when it is not a path.
    static func toFieldPath(_ x: U) -> String? {
        let s = PBT.str(x)
        switch s {
        case "principal": return "subject.id"
        case "resource": return "action.resource"
        case "action": return "action.verb"
        case "context": return "env"
        default: break
        }
        for (lead, mapped) in [("principal.", "subject."), ("resource.", "env.resource."), ("context.", "env.")] {
            let lu = u(lead)
            if PBT.startsWith(x, lu, 0) {
                let tail = PBT.sub(x, lu.count, x.count)
                if let f = tail.first, PBT.isIdentStart(f), tail.allSatisfy({ PBT.isWord($0) || $0 == 0x2e }) { return mapped + PBT.str(tail) }
            }
        }
        return nil
    }

    // ---- literals / entities ---------------------------------------------------------------------------------------------------

    /// `^[A-Za-z_]\w*(::[A-Za-z_]\w*)*$`.
    static func typeName(_ expr: U) -> String? {
        let s = PBT.trim(expr)
        var i = 0
        func ident() -> Bool {
            guard i < s.count, PBT.isIdentStart(s[i]) else { return false }
            i += 1
            while i < s.count && PBT.isWord(s[i]) { i += 1 }
            return true
        }
        guard ident() else { return nil }
        while i < s.count {
            guard PBT.startsWith(s, u("::"), i) else { return nil }
            i += 2
            guard ident() else { return nil }
        }
        return PBT.str(s)
    }

    /// `^(.+)::"([^"]*)"$` on the trimmed text: the part before `::` (no line terminator) and the quoted id.
    static func entityParts(_ expr: U) -> (prefix: U, id: U)? {
        let s = PBT.trim(expr)
        let n = s.count
        guard n >= 5, s[n - 1] == 0x22 else { return nil }
        var q = n - 2
        while q >= 0 && s[q] != 0x22 { q -= 1 }
        guard q >= 3, s[q - 1] == 0x3a, s[q - 2] == 0x3a else { return nil }
        let prefix = PBT.sub(s, 0, q - 2)
        if prefix.isEmpty || prefix.contains(where: PBT.isLineTerminator) { return nil }
        return (prefix, PBT.sub(s, q + 1, n - 1))
    }

    static func entityId(_ expr: U) -> String? { entityParts(expr).map { PBT.str($0.id) } }
    static func entityUid(_ expr: U) -> String? { entityParts(expr).map { PBT.str($0.prefix) + "::" + PBT.str($0.id) } }

    static func toLiteral(_ expr: U) -> JSONValue? {
        let s = PBT.trim(expr)
        if s.count >= 2, s.first == 0x22, s.last == 0x22, !PBT.sub(s, 1, s.count - 1).contains(0x22) { return .string(PBT.str(PBT.inner(s))) }
        let t = PBT.str(s)
        if t == "true" { return .bool(true) }
        if t == "false" { return .bool(false) }
        if isDecimal(s) { return PCAPolicyBridge.numberValue(t) }
        if let eid = entityUid(s) { return .string(eid) }
        return nil
    }

    /// `^-?\d+(\.\d+)?$`.
    static func isDecimal(_ s: U) -> Bool {
        var i = 0
        if i < s.count && s[i] == 0x2d { i += 1 }
        func digits() -> Bool {
            let from = i
            while i < s.count && s[i] >= 0x30 && s[i] <= 0x39 { i += 1 }
            return i > from
        }
        guard digits() else { return false }
        if i < s.count && s[i] == 0x2e {
            i += 1
            guard digits() else { return false }
        }
        return i == s.count
    }

    /// A Cedar `like` pattern (only `*` is a wildcard; `\*` is a literal star) as the PCA glob (`*` / `?` wildcards, `\` escapes).
    static func cedarLikeToGlob(_ inner: U) -> U {
        func esc(_ ch: UInt16) -> U { (ch == 0x2a || ch == 0x3f || ch == 0x5c) ? [0x5c, ch] : [ch] }
        var out = U()
        var i = 0
        while i < inner.count {
            let ch = inner[i]
            if ch == 0x5c {
                if i + 1 < inner.count {
                    let n = inner[i + 1]
                    if n == 0x2a { out += [0x5c, 0x2a] } else { out += esc(n) }
                    i += 2
                    continue
                }
                out += [0x5c, 0x5c]
                i += 1
                continue
            }
            if ch == 0x2a { out.append(0x2a); i += 1; continue }
            out += esc(ch)
            i += 1
        }
        return out
    }

    // ---- Cedar evaluation-error semantics ----------------------------------------------------------------------------------------

    static let TOTAL_FIELDS: Set<String> = ["subject.id", "action.verb", "action.resource", "env"]

    static func guardedPaths(_ field: String?) -> [String] {
        guard let f = field, !TOTAL_FIELDS.contains(f), !f.hasPrefix(ENTITY_PARENTS) else { return [] }
        return (f.hasPrefix("subject.") || f.hasPrefix("env.")) ? [f] : []
    }

    static func exists(_ f: String) -> JSONValue { PCAPolicyBridge.leaf(f, "exists") }

    /// "Evaluating this expression raises no Cedar error", as a condition (nil = it cannot). `a && b` / `a || b` evaluate left to right
    /// and stop once `a` decides, so `b` only needs its attributes present when `a` was true (for `&&`) or false (for `||`).
    static func noError(_ c: JSONValue, _ d: Int) throws -> JSONValue? {
        if d > PCAPolicyBridge.MAX_FRAMES { throw Fail(message: PCAPolicyBridge.STACK) }
        guard case let .object(o) = c else { return nil }
        if let n = o["not"] { return try noError(n, d + 1) }
        if o["all_of"] != nil || o["any_of"] != nil {
            let isAnd = o["all_of"] != nil
            let kids = (isAnd ? o["all_of"] : o["any_of"])?.asArray ?? []
            var acc: JSONValue?
            for kid in kids.reversed() {
                let n = try noError(kid, d + 1)
                var cont: JSONValue?
                if let a = acc { cont = PCAPolicyBridge.anyOf([isAnd ? PCAPolicyBridge.not(kid) : kid, a]) }
                if let nn = n { acc = cont == nil ? nn : PCAPolicyBridge.allOf([nn, cont!]) } else { acc = cont }
            }
            return acc
        }
        let field = o["field"]?.asString
        let ref = o["ref"]?.asString
        if o["op"]?.asString == "exists", let f = field {
            // `a.b has c` raises an error when `a.b` itself is missing; `principal has c` cannot.
            var base = f
            if let dot = f.lastIndex(of: "."), f.index(after: dot) != f.endIndex { base = String(f[f.startIndex..<dot]) }
            let parts = base.split(separator: ".", omittingEmptySubsequences: false).count
            let deep = parts >= (base.hasPrefix("env.resource") ? 3 : 2)
            let baseNeeds = deep ? guardedPaths(base).map(exists) : []
            return baseNeeds.isEmpty ? nil : PCAPolicyBridge.allOf(baseNeeds)
        }
        let needs = (guardedPaths(field) + guardedPaths(ref)).map(exists)
        return needs.isEmpty ? nil : PCAPolicyBridge.allOf(needs)
    }
}
