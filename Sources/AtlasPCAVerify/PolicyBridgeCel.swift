import Foundation

/// Strict CEL import (IAM Conditions / Kubernetes ValidatingAdmissionPolicy / SpiceDB caveat expressions): one boolean CEL expression
/// becomes a PCA `Condition` or is REJECTED with the construct named; there is no best-effort mode. The subset: dotted variables declared
/// in the schema, safe-integer / string / `true` / `false` / `timestamp("...Z")` literals, `&&` `||` `!` parentheses, `==` `!=` `<` `<=`
/// `>` `>=`, `x in [literals]`, `startsWith` / `endsWith` / `contains` of a non-empty string literal, and `has(v)` of an optional variable.
/// Positions are UTF-16 offsets. Results are `{ok: true, condition, fields}` / `{ok: false, code, message, at}` as `JSONValue`.
extension PCAPolicyBridge {
    public static func parseCel(_ expression: JSONValue?) -> JSONValue {
        do { return .object(["ok": .bool(true), "ast": try PBCel.parse(expression).json]) } catch let e as PBCel.Reject { return e.json } catch { return PBCel.internalError }
    }

    public static func celToCondition(_ expression: JSONValue?, _ schema: JSONValue?, order: KeyOrder? = nil) -> JSONValue {
        switch PBCel.condition(expression, schema, order) {
        case let .success(c, fields): return .object(["ok": .bool(true), "condition": c, "fields": strs(fields)])
        case let .failure(e): return e.json
        }
    }

    /// One expression as a permit predicate for `scope.verb` (and `scope.resource` when present).
    public static func celToPredicate(_ expression: JSONValue?, _ schema: JSONValue?, scope: JSONValue?, order: KeyOrder? = nil) throws -> JSONValue {
        switch PBCel.condition(expression, schema, order) {
        case let .failure(e): return e.json
        case let .success(c, fields):
            guard let sc = scope, sc != .null else { throw JSError("Cannot read properties of undefined (reading 'verb')") }
            var p: JObject = ["where": .array([c])]
            if let v = JSLoose.get(sc, "verb") { p["verb"] = v }
            if let r = JSLoose.get(sc, "resource") { p["resource"] = r }
            return .object(["ok": .bool(true), "predicate": .object(p), "fields": strs(fields)])
        }
    }

    /// A batch: every expression is translated or REPORTED; one rejection makes `report.errors` non-empty and `decide` then denies.
    public static func celConditionsToPca(_ items: JSONValue?, _ schema: JSONValue?, order: KeyOrder? = nil) throws -> JSONValue {
        guard case let .array(list)? = items else { throw JSError("items is not iterable") }
        let report = Report("cel")
        var predicates: [JSONValue] = []
        for it in list {
            let expression = try JSLoose.rd(it, "expression")
            let name = JS.toString(try JSLoose.rd(it, "name"))
            var scope: JObject = [:]
            if let v = JSLoose.get(it, "verb") { scope["verb"] = v }
            if let r = JSLoose.get(it, "resource") { scope["resource"] = r }
            let r = try celToPredicate(expression, schema, scope: .object(scope), order: order)
            if r.get("ok") == .bool(true) {
                if let p = r.get("predicate") { predicates.append(p) }
                let fields = (r.get("fields")?.asArray ?? []).compactMap { $0.asString }.joined(separator: ", ")
                report.translated.append("\(name): translated exactly (reads \(fields))")
            } else {
                let code = r.get("code")?.asString ?? ""
                let at = r.get("at").map { JS.toString($0) } ?? "0"
                report.errors.append("\(name): rejected (\(code)) at \(at): \(r.get("message")?.asString ?? "")")
            }
        }
        return bridgeResult(predicates, [], report)
    }
}

enum PBCel {
    typealias U = PBT.U
    static let MAX_EXPR = 4096
    static let MAX_DEPTH = 32
    static let MAX_NODES = 256
    static let MAX_LIST = 64
    static let MAX_STR = 256
    static let FORBIDDEN: Set<String> = ["__proto__", "constructor", "prototype"]
    static let internalError: JSONValue = .object(["ok": .bool(false), "code": .string("syntax"), "message": .string("internal error"), "at": .int(0)])

    struct Reject: Error {
        let code: String
        let message: String
        let at: Int
        var json: JSONValue { .object(["ok": .bool(false), "code": .string(code), "message": .string(message), "at": .int(Int64(at))]) }
    }
    static func rej(_ code: String, _ message: String, _ at: Int) -> Reject { Reject(code: code, message: message, at: at) }

    // ---- tokens ----------------------------------------------------------------------------------------------------------------

    enum Kind { case id, int, str, p }
    struct Tok { let k: Kind; let v: String; let at: Int }

    static let PUNCT = ["&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "(", ")", "[", "]", ",", ".", "-"]
    static let UNSUPPORTED_CH: [UInt16: String] = [
        0x2b: "arithmetic (+)", 0x2a: "arithmetic (*)", 0x2f: "arithmetic (/)", 0x25: "arithmetic (%)", 0x3f: "the conditional operator",
        0x3a: "the conditional operator / map literal", 0x7b: "map or message literal", 0x7d: "map or message literal", 0x40: "@",
        0x26: "bitwise &", 0x7c: "bitwise |", 0x5e: "^", 0x7e: "~", 0x3d: "assignment", 0x60: "quoted identifier",
    ]

    static func isDigit(_ c: UInt16) -> Bool { c >= 0x30 && c <= 0x39 }

    static func lex(_ src: U) throws -> [Tok] {
        var out: [Tok] = []
        var i = 0
        let n = src.count
        func at(_ k: Int) -> UInt16? { k < n ? src[k] : nil }
        while i < n {
            let c = src[i]
            if c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d { i += 1; continue }
            if c == 0x2f && at(i + 1) == 0x2f { throw rej("unsupported", "comments", i) }
            if PBT.isIdentStart(c) {
                var j = i + 1
                while j < n && PBT.isWord(src[j]) { j += 1 }
                let w = PBT.str(PBT.sub(src, i, j))
                if w.count == 1, "rbRB".contains(w), at(j) == 0x22 || at(j) == 0x27 {
                    throw rej("unsupported", "\(w.lowercased() == "r" ? "raw string" : "bytes") literal", i)
                }
                out.append(Tok(k: .id, v: w, at: i))
                i = j
                continue
            }
            if isDigit(c) {
                var j = i
                while j < n && isDigit(src[j]) { j += 1 }
                let nxt = at(j)
                if nxt == 0x2e, let d = at(j + 1), isDigit(d) { throw rej("unsupported", "double literal", i) }
                if nxt == 0x65 || nxt == 0x45 { throw rej("unsupported", "double literal", i) }
                if nxt == 0x75 || nxt == 0x55 { throw rej("unsupported", "unsigned integer literal", i) }
                if nxt == 0x78 || nxt == 0x58 { throw rej("unsupported", "hexadecimal literal", i) }
                if j - i > 1 && src[i] == 0x30 { throw rej("unsupported", "integer literal with a leading zero", i) }
                out.append(Tok(k: .int, v: PBT.str(PBT.sub(src, i, j)), at: i))
                i = j
                continue
            }
            if c == 0x22 || c == 0x27 {
                if at(i + 1) == c && at(i + 2) == c { throw rej("unsupported", "triple-quoted string", i) }
                var j = i + 1
                var s = U()
                while true {
                    guard j < n, src[j] != 0x0a, src[j] != 0x0d else { throw rej("syntax", "unterminated string", i) }
                    let d = src[j]
                    if d == c { break }
                    if d == 0x5c {
                        let e = at(j + 1)
                        var mapped: UInt16?
                        switch e {
                        case 0x5c?: mapped = 0x5c
                        case 0x22?: mapped = 0x22
                        case 0x27?: mapped = 0x27
                        case 0x6e?: mapped = 0x0a
                        case 0x74?: mapped = 0x09
                        case 0x72?: mapped = 0x0d
                        default: mapped = nil
                        }
                        guard let m = mapped else { throw rej("unsupported", "string escape \\" + (e.map { PBT.str([$0]) } ?? ""), j) }
                        s.append(m)
                        j += 2
                        continue
                    }
                    s.append(d)
                    j += 1
                }
                if s.count > MAX_STR { throw rej("too_complex", "string literal longer than \(MAX_STR)", i) }
                out.append(Tok(k: .str, v: PBT.str(s), at: i))
                i = j + 1
                continue
            }
            var matched: String?
            for p in PUNCT where PBT.startsWith(src, PBT.u(p), i) { matched = p; break }
            guard let p = matched else {
                if let m = UNSUPPORTED_CH[c] { throw rej("unsupported", m, i) }
                throw rej("syntax", "unexpected character '\(PBT.str([c]))'", i)
            }
            out.append(Tok(k: .p, v: p, at: i))
            i += p.count
        }
        return out
    }

    // ---- parser ----------------------------------------------------------------------------------------------------------------

    indirect enum Node {
        case or(Node, Node, Int)
        case and(Node, Node, Int)
        case not(Node, Int)
        case rel(String, Node, Node, Int)
        case int(Int64, Int)
        case str(String, Int)
        case bool(Bool, Int)
        case ts(Int64, Int)
        case list([Node], Int)
        case variable(String, Int)
        case has(Node, Int)
        case method(Node, String, Node, Int)

        var at: Int {
            switch self {
            case let .or(_, _, a), let .and(_, _, a), let .not(_, a), let .rel(_, _, _, a), let .int(_, a), let .str(_, a), let .bool(_, a), let .ts(_, a),
                 let .list(_, a), let .variable(_, a), let .has(_, a), let .method(_, _, _, a): return a
            }
        }

        var json: JSONValue {
            func o(_ t: String, _ a: Int, _ extra: [(String, JSONValue)]) -> JSONValue {
                var d: JObject = ["t": .string(t), "at": .int(Int64(a))]
                for (k, v) in extra { d[JKey(k)] = v }
                return .object(d)
            }
            switch self {
            case let .or(l, r, a): return o("or", a, [("l", l.json), ("r", r.json)])
            case let .and(l, r, a): return o("and", a, [("l", l.json), ("r", r.json)])
            case let .not(e, a): return o("not", a, [("e", e.json)])
            case let .rel(op, l, r, a): return o("rel", a, [("op", .string(op)), ("l", l.json), ("r", r.json)])
            case let .int(v, a): return o("int", a, [("v", .int(v))])
            case let .str(v, a): return o("str", a, [("v", .string(v))])
            case let .bool(v, a): return o("bool", a, [("v", .bool(v))])
            case let .ts(v, a): return o("ts", a, [("v", .int(v))])
            case let .list(items, a): return o("list", a, [("items", .array(items.map { $0.json }))])
            case let .variable(name, a): return o("var", a, [("name", .string(name))])
            case let .has(e, a): return o("has", a, [("e", e.json)])
            case let .method(t, fn, arg, a): return o("method", a, [("target", t.json), ("fn", .string(fn)), ("arg", arg.json)])
            }
        }
    }

    static let RELOPS: Set<String> = ["==", "!=", "<", "<=", ">", ">="]
    static let REJECTED_FUNCS: Set<String> = [
        "size", "matches", "exists", "all", "exists_one", "map", "filter", "int", "uint", "double", "string", "bytes", "bool", "duration", "type", "dyn", "min", "max",
        "getHours", "getDayOfWeek", "getMinutes", "getSeconds", "getFullYear", "getMonth", "getDate", "getDayOfMonth", "getDayOfYear", "getMilliseconds", "extract",
        "format", "lowerAscii", "upperAscii", "trim", "split", "join", "replace", "substring", "indexOf", "lastIndexOf", "charAt", "isIpv4", "inIpRange", "cidr", "ip",
        "isCIDR", "containsIp", "url", "quantity", "semver", "optional",
    ]

    struct Parser {
        let srcLen: Int
        let toks: [Tok]
        var pos = 0
        var nodes = 0

        init(_ src: U, _ toks: [Tok]) { srcLen = src.count; self.toks = toks }

        func peek() -> Tok? { pos < toks.count ? toks[pos] : nil }
        func isP(_ v: String) -> Bool { if let t = peek(), t.k == .p, t.v == v { return true }; return false }
        mutating func eat(_ v: String) -> Bool { if isP(v) { pos += 1; return true }; return false }
        mutating func need(_ v: String) throws { if !eat(v) { throw PBCel.rej("syntax", "expected '\(v)'", peek()?.at ?? srcLen) } }
        mutating func tick(_ at: Int) throws { nodes += 1; if nodes > PBCel.MAX_NODES { throw PBCel.rej("too_complex", "more than \(PBCel.MAX_NODES) nodes", at) } }
        func isRel(_ t: Tok) -> Bool { (t.k == .p && PBCel.RELOPS.contains(t.v)) || (t.k == .id && t.v == "in") }

        mutating func expr(_ d: Int) throws -> Node {
            if d > PBCel.MAX_DEPTH { throw PBCel.rej("too_complex", "nesting deeper than \(PBCel.MAX_DEPTH)", peek()?.at ?? 0) }
            return try or(d)
        }
        mutating func or(_ d: Int) throws -> Node {
            var l = try and(d)
            while isP("||") {
                let at = peek()!.at
                pos += 1
                try tick(at)
                l = .or(l, try and(d), at)
            }
            return l
        }
        mutating func and(_ d: Int) throws -> Node {
            var l = try rel(d)
            while isP("&&") {
                let at = peek()!.at
                pos += 1
                try tick(at)
                l = .and(l, try rel(d), at)
            }
            return l
        }
        mutating func rel(_ d: Int) throws -> Node {
            let l = try unary(d)
            guard let t = peek(), isRel(t) else { return l }
            pos += 1
            try tick(t.at)
            let n = Node.rel(t.v, l, try unary(d), t.at)
            if let u = peek(), isRel(u) { throw PBCel.rej("unsupported", "chained comparison", u.at) }
            return n
        }
        mutating func unary(_ d: Int) throws -> Node {
            if let t = peek(), t.k == .p, t.v == "!" {
                pos += 1
                try tick(t.at)
                if d + 1 > PBCel.MAX_DEPTH { throw PBCel.rej("too_complex", "nesting deeper than \(PBCel.MAX_DEPTH)", t.at) }
                return .not(try unary(d + 1), t.at)
            }
            if let t = peek(), t.k == .p, t.v == "-" {
                guard pos + 1 < toks.count, toks[pos + 1].k == .int else { throw PBCel.rej("unsupported", "unary minus on a non-literal", t.at) }
                let digits = toks[pos + 1].v
                pos += 2
                return try intNode("-" + digits, t.at)
            }
            return try member(d)
        }
        mutating func intNode(_ text: String, _ at: Int) throws -> Node {
            try tick(at)
            // a safe integer has at most 16 digits; anything longer (or past 2^53 - 1) is refused, as Number.isSafeInteger does
            let digits = text.hasPrefix("-") ? String(text.dropFirst()) : text
            guard digits.count <= 18, let v = Int64(text), abs(v) <= Canonical.MAX_SAFE else {
                throw PBCel.rej("unsupported", "integer literal outside the safe-integer range", at)
            }
            return .int(v, at)
        }
        mutating func args(_ d: Int) throws -> [Node] {
            var a: [Node] = []
            if !isP(")") {
                repeat { a.append(try expr(d + 1)) } while eat(",")
            }
            try need(")")
            return a
        }
        mutating func member(_ d: Int) throws -> Node {
            var n = try primary(d)
            while isP(".") {
                let dot = peek()!
                pos += 1
                guard let id = peek(), id.k == .id else { throw PBCel.rej("syntax", "expected a name after '.'", dot.at) }
                pos += 1
                if isP("(") {
                    pos += 1
                    let a = try args(d)
                    if id.v != "startsWith" && id.v != "endsWith" && id.v != "contains" { throw PBCel.rej("unsupported", "method '\(id.v)'", id.at) }
                    if a.count != 1 { throw PBCel.rej("syntax", "'\(id.v)' takes one argument", id.at) }
                    try tick(id.at)
                    n = .method(n, id.v, a[0], id.at)
                } else {
                    guard case let .variable(name, vat) = n else { throw PBCel.rej("unsupported", "field selection on something that is not a declared variable", dot.at) }
                    n = .variable(name + "." + id.v, vat)
                }
            }
            if isP("[") { throw PBCel.rej("unsupported", "index operator", peek()!.at) }
            return n
        }
        mutating func primary(_ d: Int) throws -> Node {
            guard let t = peek() else { throw PBCel.rej("syntax", "unexpected end of expression", srcLen) }
            if t.k == .int { pos += 1; return try intNode(t.v, t.at) }
            if t.k == .str { pos += 1; try tick(t.at); return .str(t.v, t.at) }
            if t.k == .p && t.v == "(" {
                pos += 1
                let e = try expr(d + 1)
                try need(")")
                return e
            }
            if t.k == .p && t.v == "[" {
                pos += 1
                var items: [Node] = []
                if !isP("]") {
                    repeat {
                        if items.count >= PBCel.MAX_LIST { throw PBCel.rej("too_complex", "list longer than \(PBCel.MAX_LIST)", t.at) }
                        items.append(try expr(d + 1))
                    } while eat(",")
                }
                try need("]")
                try tick(t.at)
                return .list(items, t.at)
            }
            if t.k == .id {
                pos += 1
                if t.v == "true" || t.v == "false" { try tick(t.at); return .bool(t.v == "true", t.at) }
                if t.v == "null" { throw PBCel.rej("unsupported", "null", t.at) }
                if isP("(") {
                    pos += 1
                    let a = try args(d)
                    if t.v == "has" {
                        guard a.count == 1, case .variable = a[0] else { throw PBCel.rej("syntax", "has() takes one declared variable", t.at) }
                        try tick(t.at)
                        return .has(a[0], t.at)
                    }
                    if t.v == "timestamp" {
                        guard a.count == 1, case let .str(s, _) = a[0] else { throw PBCel.rej("unsupported", "timestamp() of a non-literal", t.at) }
                        return .ts(try PBCel.parseTimestamp(s, t.at), t.at)
                    }
                    throw PBCel.rej("unsupported", PBCel.REJECTED_FUNCS.contains(t.v) ? "function '\(t.v)'" : "unknown function '\(t.v)'", t.at)
                }
                if t.v == "in" { throw PBCel.rej("syntax", "unexpected 'in'", t.at) }
                try tick(t.at)
                return .variable(t.v, t.at)
            }
            throw PBCel.rej("syntax", "unexpected '\(t.v)'", t.at)
        }
    }

    static func parse(_ expression: JSONValue?) throws -> Node {
        guard case let .string(text)? = expression, !text.isEmpty else { throw rej("syntax", "empty expression", 0) }
        let src = PBT.u(text)
        if src.count > MAX_EXPR { throw rej("too_complex", "expression longer than \(MAX_EXPR) characters", 0) }
        var p = Parser(src, try lex(src))
        let root = try p.expr(0)
        if p.pos < p.toks.count { throw rej("syntax", "unexpected '\(p.toks[p.pos].v)'", p.toks[p.pos].at) }
        return root
    }

    /// `timestamp("YYYY-MM-DDTHH:MM:SS[.mmm]Z")` as epoch milliseconds; anything that is not a real instant is refused.
    static func parseTimestamp(_ text: String, _ at: Int) throws -> Int64 {
        let s = PBT.u(text)
        let shape = rej("unsupported", "timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision", at)
        func digits(_ from: Int, _ count: Int) -> Int? {
            guard from + count <= s.count else { return nil }
            var v = 0
            for k in from..<(from + count) { guard isDigit(s[k]) else { return nil }; v = v * 10 + Int(s[k] - 0x30) }
            return v
        }
        guard s.count >= 20, let y = digits(0, 4), s[4] == 0x2d, let mo = digits(5, 2), s[7] == 0x2d, let d = digits(8, 2), s[10] == 0x54,
              let h = digits(11, 2), s[13] == 0x3a, let mi = digits(14, 2), s[16] == 0x3a, let sec = digits(17, 2) else { throw shape }
        var i = 19
        var frac = 0
        if i < s.count && s[i] == 0x2e {
            var j = i + 1
            while j < s.count && isDigit(s[j]) { j += 1 }
            let len = j - (i + 1)
            guard len >= 1, len <= 3 else { throw shape }
            var f = 0
            for k in (i + 1)..<j { f = f * 10 + Int(s[k] - 0x30) }
            for _ in len..<3 { f *= 10 }
            frac = f
            i = j
        }
        guard i == s.count - 1, s[i] == 0x5a else { throw shape }
        let notReal = rej("unsupported", "timestamp() is not a real instant", at)
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard mo >= 1, mo <= 12, d >= 1, d <= dim[mo - 1], h <= 23, mi <= 59, sec <= 59 else { throw notReal }
        // days from the civil date (proleptic Gregorian)
        let yy = Int64(mo <= 2 ? y - 1 : y)
        let era = (yy >= 0 ? yy : yy - 399) / 400
        let yoe = yy - era * 400
        let mp = Int64((mo + 9) % 12)
        let doy = (153 * mp + 2) / 5 + Int64(d) - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146097 + doe - 719468
        return ((days * 24 + Int64(h)) * 60 + Int64(mi)) * 60_000 + Int64(sec) * 1000 + Int64(frac)
    }

    // ---- translation -----------------------------------------------------------------------------------------------------------

    struct Var { let path: String; let type: String; let optional: Bool }

    enum Outcome {
        case success(JSONValue, [String])
        case failure(Reject)
    }

    /// `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$` as its segments.
    static func identSegments(_ s: String) -> [String]? {
        let segs = s.unicodeScalars.split(separator: ".", omittingEmptySubsequences: false).map { String(String.UnicodeScalarView($0)) }
        for seg in segs {
            guard let f = seg.utf16.first, PBT.isIdentStart(f), seg.utf16.allSatisfy({ PBT.isWord($0) }) else { return nil }
        }
        return segs
    }

    static func schemaError(_ s: JSONValue?, _ order: PCAPolicyBridge.KeyOrder?) -> String? {
        guard case let .object(so)? = s else { return "the schema must be an object" }
        guard case let .object(vars)? = so[JKey("vars")] else { return "the schema needs a vars object" }
        for name in PCAPolicyBridge.orderedKeys(vars, order) {
            let v = vars[JKey(name)]
            guard let segs = identSegments(name), !segs.contains(where: { FORBIDDEN.contains($0) }) else { return "bad variable name '\(name)'" }
            let rooted: Bool = {
                guard case let .object(vo)? = v, case let .string(path)? = vo[JKey("path")], let ps = identSegments(path), ps.count >= 2,
                      ["action", "subject", "env"].contains(ps[0]), !ps.contains(where: { FORBIDDEN.contains($0) }) else { return false }
                return true
            }()
            guard rooted, case let .object(vo)? = v else { return "variable '\(name)' needs a path rooted at action, subject or env" }
            guard case let .string(type)? = vo[JKey("type")], ["string", "int", "bool", "timestamp_ms"].contains(type) else { return "variable '\(name)' has an unsupported type" }
            if let o = vo[JKey("optional")], o.asBool == nil { return "variable '\(name)': optional must be a boolean" }
        }
        return nil
    }

    enum Operand {
        case v(Var, String)
        case lit(String, JSONValue)
        var type: String {
            switch self {
            case let .v(x, _): return x.type
            case let .lit(t, _): return t
            }
        }
    }

    static func condition(_ expression: JSONValue?, _ schema: JSONValue?, _ order: PCAPolicyBridge.KeyOrder?) -> Outcome {
        if let se = schemaError(schema, order) { return .failure(rej("bad_schema", se, 0)) }
        let ast: Node
        do { ast = try parse(expression) } catch let e as Reject { return .failure(e) } catch { return .failure(Reject(code: "syntax", message: "internal error", at: 0)) }

        var vars: JObject = [:]
        if case let .object(so)? = schema, case let .object(v)? = so[JKey("vars")] { vars = v }
        var fields = Set<String>()

        func own(_ name: String) -> Var? {
            guard case let .object(vo)? = vars[JKey(name)], case let .string(path)? = vo[JKey("path")], case let .string(type)? = vo[JKey("type")] else { return nil }
            return Var(path: path, type: type, optional: vo[JKey("optional")] == .bool(true))
        }
        func operand(_ n: Node) throws -> Operand {
            switch n {
            case let .variable(name, at):
                guard let v = own(name) else { throw rej("unknown_identifier", "'\(name)' is not declared in the schema", at) }
                return .v(v, name)
            case let .int(v, _): return .lit("int", .int(v))
            case let .str(v, _): return .lit("string", .string(v))
            case let .bool(v, _): return .lit("bool", .bool(v))
            case let .ts(v, _): return .lit("timestamp_ms", .int(v))
            default: throw rej("unsupported", "a computed value as a comparison operand", n.at)
            }
        }
        func read(_ o: Operand) -> String {
            if case let .v(v, _) = o { fields.insert(v.path); return v.path }
            return ""
        }
        func flat(_ n: Node, _ isOr: Bool, _ out: inout [Node]) {
            switch n {
            case let .or(l, r, _) where isOr: flat(l, isOr, &out); flat(r, isOr, &out)
            case let .and(l, r, _) where !isOr: flat(l, isOr, &out); flat(r, isOr, &out)
            default: out.append(n)
            }
        }
        func litValue(_ o: Operand) -> JSONValue {
            if case let .lit(_, v) = o { return v }
            return .null
        }

        func tr(_ n: Node) throws -> JSONValue {
            switch n {
            case .or:
                var parts: [Node] = []
                flat(n, true, &parts)
                return .object(["any_of": .array(try parts.map(tr))])
            case .and:
                var parts: [Node] = []
                flat(n, false, &parts)
                return .object(["all_of": .array(try parts.map(tr))])
            case let .not(e, _): return PCAPolicyBridge.not(try tr(e))
            case let .has(e, at):
                let o = try operand(e)
                guard case let .v(v, name) = o else { throw rej("syntax", "has() takes a declared variable", at) }
                if !v.optional { throw rej("has_requires_optional", "has(\(name)): mark the variable optional in the schema (its container must always be present)", at) }
                return PCAPolicyBridge.leaf(read(o), "exists", value: .bool(true))
            case let .variable(name, at):
                let o = try operand(n)
                var isBool = false
                if case let .v(v, _) = o, v.type == "bool" { isBool = true }
                throw rej("unsupported", "a bare variable '\(name)' as a condition\(isBool ? " (write \(name) == true)" : "")", at)
            case let .method(target, fn, arg, at):
                let t = try operand(target)
                guard case let .v(tv, _) = t, tv.type == "string" else { throw rej("type_mismatch", "\(fn) needs a string variable", at) }
                guard case let .str(lit, _) = arg, !lit.isEmpty else { throw rej("unsupported", "\(fn) of anything but a non-empty string literal", at) }
                if fn == "startsWith" { return PCAPolicyBridge.leaf(read(t), "prefix", value: .string(lit)) }
                var esc = String.UnicodeScalarView()
                for c in lit.unicodeScalars {
                    if c == "\\" || c == "*" || c == "?" { esc.append("\\") }
                    esc.append(c)
                }
                let e = String(esc)
                let glob = fn == "endsWith" ? "*" + e : "*" + e + "*"
                if glob.utf16.count > 512 { throw rej("too_complex", "literal too long for a glob", at) }
                return PCAPolicyBridge.leaf(read(t), "like", value: .string(glob))
            case let .rel(op, ln, rn, at):
                if op == "in" {
                    let l = try operand(ln)
                    guard case let .v(lv, _) = l else { throw rej("constant_expression", "the left side of \"in\" must be a declared variable", at) }
                    guard case let .list(items, _) = rn, !items.isEmpty else { throw rej("unsupported", "\"in\" against anything but a non-empty list literal", at) }
                    let ops = try items.map(operand)
                    for i in ops {
                        guard case .lit = i, i.type == lv.type else { throw rej("type_mismatch", "list items must be \(lv.type) literals", at) }
                    }
                    return PCAPolicyBridge.leaf(read(l), "in", value: .array(ops.map(litValue)))
                }
                let l = try operand(ln)
                let r = try operand(rn)
                if case .lit = l, case .lit = r { throw rej("constant_expression", "a comparison of two literals", at) }
                if l.type != r.type { throw rej("type_mismatch", "\(l.type) against \(r.type)", at) }
                let eqOp = op == "==" || op == "!="
                if !eqOp && l.type == "bool" { throw rej("type_mismatch", "ordering of booleans", at) }
                let pcaOp = ["==": "eq", "!=": "ne", "<": "lt", "<=": "lte", ">": "gt", ">=": "gte"][op]!
                let flip = ["eq": "eq", "ne": "ne", "lt": "gt", "lte": "gte", "gt": "lt", "gte": "lte"]
                if case .v = l, case .v = r { return PCAPolicyBridge.leaf(read(l), pcaOp, ref: read(r)) }
                if case .v = l { return PCAPolicyBridge.leaf(read(l), pcaOp, value: litValue(r)) }
                return PCAPolicyBridge.leaf(read(r), flip[pcaOp]!, value: litValue(l))
            default:
                throw rej("constant_expression", "a bare constant is not a condition", n.at)
            }
        }

        do {
            let c = try tr(ast)
            if fields.isEmpty { throw rej("constant_expression", "the expression reads no variable", 0) }
            return .success(c, fields.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) })
        } catch let e as Reject {
            return .failure(e)
        } catch {
            return .failure(Reject(code: "syntax", message: "internal error", at: 0))
        }
    }
}

extension JSONValue {
    var asBool: Bool? { if case let .bool(b) = self { return b } else { return nil } }
}
