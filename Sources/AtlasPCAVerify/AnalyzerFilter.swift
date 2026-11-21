import Foundation

/// Data filtering: a residual compiled to a parameterized SQL WHERE clause and to a UCAST tree.
///
/// Soundness rule: the filter may only ever return a SUBSET of what the evaluator admits. Anything it cannot express exactly (a regex
/// resource, a `ref`, `like` / `matches` / `member_of`, string ordering, a field with no column) makes the whole compile fail with a
/// reason (`ok: false`); it never emits a looser filter. SQL's three-valued logic is Kleene's, the evaluator's own: an unresolvable permit
/// condition is NULL and the row is dropped; a veto is wrapped in COALESCE(.., TRUE) so an unresolvable veto condition still excludes
/// the row. Filter expressions and UCAST trees are plain JSON (`JSONValue`); `nil` is JavaScript `undefined`.
fileprivate enum FlH {
    typealias V = JSONValue
    typealias A = PCAAnalyzer

    struct Unsupported: Error { let reason: String }

    static func tag(_ t: String) -> V { .object(["t": .string(t)]) }
    static let T_TRUE = tag("true"), T_FALSE = tag("false")

    static func isCompoundOf(_ x: V?, _ op: String) throws -> Bool {
        try IV.same(try A.rd(x, "type")?.asString, "compound") && IV.same(try A.rd(x, "operator")?.asString, op)
    }

    // ---- JS value semantics ----

    static func typeOf(_ v: V?) -> String {
        switch v {
        case nil: return "undefined"
        case .bool?: return "boolean"
        case .int?, .double?: return "number"
        case .string?: return "string"
        default: return "object"
        }
    }

    /// `a === b` (an object or array is only ever equal to itself, which a parsed tree never shares).
    static func strictEq(_ a: V?, _ b: V?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case (.null?, .null?): return true
        case let (.bool(x)?, .bool(y)?): return x == y
        case let (.string(x)?, .string(y)?): return IV.same(x, y)
        case let (x?, y?) where x.isNumber && y.isNumber: return JS.toNumber(x) == JS.toNumber(y)
        default: return false
        }
    }

    /// SameValueZero (`Array.prototype.includes`).
    static func sameValueZero(_ a: V?, _ b: V?) -> Bool {
        if let x = a, let y = b, x.isNumber, y.isNumber { let p = JS.toNumber(x), q = JS.toNumber(y); return p == q || (p.isNaN && q.isNaN) }
        return strictEq(a, b)
    }

    static func includes(_ list: V?, _ a: V?) throws -> Bool {
        guard case let .array(xs)? = list else { throw JSError("includes is not a function") }
        return xs.contains { sameValueZero($0, a) }
    }

    static func le(_ a: V?, _ b: V?) -> Bool {
        if case .string? = JSLoose.prim(a), case .string? = JSLoose.prim(b) { return !JSLoose.lt(b, a) }
        return JS.toNumber(JSLoose.prim(a)) <= JS.toNumber(JSLoose.prim(b))
    }
    static func ge(_ a: V?, _ b: V?) -> Bool { le(b, a) }

    /// `Object.prototype.hasOwnProperty.call(row, c) ? row[c] : null`.
    static func cell(_ row: V?, _ col: V?) throws -> V {
        guard let r = row, r != .null else { throw JSError("Cannot convert undefined or null to object") }
        return r.asObject?[JKey(JS.toString(col))] ?? .null
    }

    // ---- SQL form ----

    /// `/^[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?$/`
    static func validCol(_ s: String) -> Bool {
        let u = Array(s.utf16)
        var i = 0
        func ident() -> Bool {
            func head(_ c: UInt16) -> Bool { (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c == 0x5f }
            guard i < u.count, head(u[i]) else { return false }
            var n = 0
            i += 1
            while i < u.count, head(u[i]) || (u[i] >= 0x30 && u[i] <= 0x39) { n += 1; i += 1 }
            return n <= 62
        }
        guard ident() else { return false }
        if i == u.count { return true }
        guard u[i] == 0x2e else { return false }
        i += 1
        return ident() && i == u.count
    }

    static func scalar(_ v: V?) -> Bool {
        switch v {
        case .bool?, .string?: return true
        case let x? where x.isNumber: return JS.toNumber(x).isFinite
        default: return false
        }
    }

    static func colOf(_ path: V?, _ cols: V?) throws -> V {
        guard case let .string(p)? = path else { throw Unsupported(reason: "field '\(JS.toString(path))' has no usable column") }
        guard let cs = cols, cs != .null else { throw JSError("Cannot convert undefined or null to object") }
        guard let c = cs.asObject?[JKey(p)], validCol(JS.toString(c)) else { throw Unsupported(reason: "field '\(p)' has no usable column") }
        return c
    }

    static func and(_ xs: [V]) -> V { xs.isEmpty ? T_TRUE : xs.count == 1 ? xs[0] : .object(["t": .string("and"), "xs": .array(xs)]) }
    static func or(_ xs: [V]) -> V { xs.isEmpty ? T_FALSE : xs.count == 1 ? xs[0] : .object(["t": .string("or"), "xs": .array(xs)]) }
    static func not(_ x: V) -> V { .object(["t": .string("not"), "x": x]) }
    static func coalesce(_ x: V, _ def: Bool) -> V { .object(["t": .string("coalesce"), "x": x, "def": .bool(def)]) }
    static func nullTest(_ col: V, _ isNull: Bool) -> V { .object(["t": .string("null"), "col": col, "isNull": .bool(isNull)]) }
    static func cmp(_ col: V, _ op: String, _ v: V?) -> V { A.obj([("t", .string("cmp")), ("col", col), ("op", .string(op)), ("v", v)]) }

    static func cond(_ c: V?, _ cols: V?) throws -> V {
        guard let cv = c, cv.isObject || cv.isArray else { throw Unsupported(reason: "malformed condition") }
        if A.isGroup(cv) {
            if A.inObj(cv, "all_of"), let a = A.mem(cv, "all_of")?.asArray, !a.isEmpty { return and(try a.map { try cond($0, cols) }) }
            if A.inObj(cv, "any_of"), let a = A.mem(cv, "any_of")?.asArray, !a.isEmpty { return or(try a.map { try cond($0, cols) }) }
            if A.inObj(cv, "not") { return not(try cond(A.mem(cv, "not"), cols)) }
            throw Unsupported(reason: "empty condition group")
        }
        guard A.isLeaf(cv) else { throw Unsupported(reason: "malformed condition") }
        if A.mem(cv, "ref") != nil { throw Unsupported(reason: "cross-field ref") }
        let col = try colOf(A.mem(cv, "field"), cols)
        let v = A.mem(cv, "value")
        let op = A.mem(cv, "op")?.asString
        switch op {
        case "eq"?, "ne"?:
            if !scalar(v) { throw Unsupported(reason: "\(op!) against a non-scalar") }
            return cmp(col, op!, v)
        case "lt"?, "lte"?, "gt"?, "gte"?:
            guard let x = v, x.isNumber, JS.toNumber(x).isFinite else {
                throw Unsupported(reason: "string ordering follows UTF-8 byte order, which SQL collations do not guarantee")
            }
            return cmp(col, op!, v)
        case "in"?, "nin"?:
            guard case let .array(vs)? = v, !vs.isEmpty, vs.allSatisfy({ scalar($0) }) else { throw Unsupported(reason: "\(op!) needs a non-empty list of scalars") }
            return .object(["t": .string("in"), "col": col, "vs": .array(vs), "neg": .bool(op! == "nin")])
        case "prefix"?:
            guard case let .string(p)? = v else { throw Unsupported(reason: "prefix needs a string") }
            return .object(["t": .string("prefix"), "col": col, "prefix": .string(p)])
        case "exists"?:
            return nullTest(col, v == .bool(false))
        default:
            throw Unsupported(reason: "operator '\(JS.toString(A.mem(cv, "op")))' has no exact SQL form")
        }
    }

    static func resourceExpr(_ p: V?, _ cols: V?) throws -> V {
        let r = try A.rd(p, "resource")
        if r == nil || IV.same(r?.asString, "*") { return T_TRUE }
        let col = try colOf(.string("action.resource"), cols)
        guard case let .string(s)? = r else { throw JSError("r.startsWith is not a function") }
        if IV.startsWith(s, "re:") { throw Unsupported(reason: "regex resource matcher") }
        if IV.endsWith(s, "*") { return .object(["t": .string("prefix"), "col": col, "prefix": .string(IV.text(s.unicodeScalars.dropLast()))]) }
        return cmp(col, "eq", .string(s))
    }

    static func listOf(_ v: V?) throws -> [V] {
        guard case let .array(a)? = v else { throw JSError("map is not a function") }
        return a
    }

    static func vetoExpr(_ v: V, _ cols: V?) throws -> V {
        let when = try A.rd(v, "when")
        var ws: [V] = []
        if try A.rd(when, "resource") != nil { ws.append(coalesce(try resourceExpr(when, cols), true)) }
        for c in try (JS.present(try A.rd(when, "where")).map { try listOf($0) } ?? []) { ws.append(coalesce(try cond(c, cols), true)) }
        var parts: [V] = [and(ws)]
        if let over = try A.rd(v, "over"), JS.truthy(over) {
            let col = try colOf(try A.rd(over, "path"), cols)
            parts.append(or([nullTest(col, true), cmp(col, "lt", .int(0)), cmp(col, "gt", A.mem(over, "threshold"))]))
        }
        if !IV.same(try A.rd(v, "kind")?.asString, "approval"), let u = try A.rd(v, "unless"), JS.truthy(u), JS.toNumber(A.mem(u, "length")) > 0 {
            parts.append(not(and(try listOf(u).map { coalesce(try cond($0, cols), false) })))
        }
        return and(parts)
    }

    static func partExpr(_ p: V, _ cols: V?, _ include: V?) throws -> V {
        let autonomous = IV.same(include?.asString, "autonomous")
        let permit = or(try listOf(try A.rd(p, "predicates")).map { (x: V) throws -> V in
            var xs: [V] = [try resourceExpr(x, cols)]
            for c in try (JS.present(try A.rd(x, "where")).map { try listOf($0) } ?? []) { xs.append(try cond(c, cols)) }
            return and(xs)
        })
        var gates: [V] = [permit]
        for v in try listOf(try A.rd(p, "vetoes")) {
            let e = try vetoExpr(v, cols)
            // an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
            if IV.same(try A.rd(v, "kind")?.asString, "deny") || autonomous { gates.append(not(e)) }
        }
        for t in try listOf(try A.rd(p, "tighten")) {
            // admitted: tighten rules are ignored unless they deny
            if try autonomous || IV.same(try A.rd(t, "signal")?.asString, "deny") { gates.append(not(coalesce(try cond(try A.rd(t, "when"), cols), true))) }
        }
        return and(gates)
    }

    static func render(_ e: V?, _ postgres: Bool, _ params: inout [V]) throws -> String {
        func ph(_ v: V?, _ params: inout [V]) -> String {
            params.append(v ?? .null)
            return postgres ? "$\(params.count)" : "?"
        }
        let x = e
        let col = JS.toString(A.mem(x, "col"))
        switch (try A.rd(x, "t")?.asString) ?? "" {
        case "true": return "TRUE"
        case "false": return "FALSE"
        case "cmp":
            let sym = ["eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="][A.mem(x, "op")?.asString ?? ""] ?? "undefined"
            return "\(col) \(sym) \(ph(A.mem(x, "v"), &params))"
        case "in":
            var items: [String] = []
            for v in try listOf(A.mem(x, "vs")) { items.append(ph(v, &params)) }
            return "\(col) \(JS.truthy(A.mem(x, "neg")) ? "NOT IN" : "IN") (\(items.joined(separator: ", ")))"
        case "prefix":
            var esc = String.UnicodeScalarView()
            for u in JS.toString(A.mem(x, "prefix")).unicodeScalars {
                if u == "!" || u == "%" || u == "_" { esc.append("!") }
                esc.append(u)
            }
            return "\(col) LIKE \(ph(.string(String(esc) + "%"), &params)) ESCAPE '!'"
        case "null": return "\(col) IS \(JS.truthy(A.mem(x, "isNull")) ? "" : "NOT ")NULL"
        case "and": return "(" + (try listOf(A.mem(x, "xs")).map { try render($0, postgres, &params) }).joined(separator: " AND ") + ")"
        case "or": return "(" + (try listOf(A.mem(x, "xs")).map { try render($0, postgres, &params) }).joined(separator: " OR ") + ")"
        case "not": return "NOT (\(try render(A.mem(x, "x"), postgres, &params)))"
        case "coalesce": return "COALESCE(\(try render(A.mem(x, "x"), postgres, &params)), \(JS.truthy(A.mem(x, "def")) ? "TRUE" : "FALSE"))"
        default: throw JSError("unknown filter node")
        }
    }

    // ---- UCAST ----

    static func isEmpty(_ u: V?, _ op: String) throws -> Bool {
        try isCompoundOf(u, op) && (try A.rd(u, "value")?.asArray?.isEmpty ?? false)
    }

    /// Flatten, drop the identity and short-circuit on the absorbing element: meaning-preserving, and it keeps the tree readable.
    static func join(_ op: String, _ xs: [V]) throws -> V {
        let other = op == "and" ? "or" : "and"
        var flat: [V] = []
        for x in xs {
            if try isCompoundOf(x, op) { flat += A.arr(try A.rd(x, "value")) } else { flat.append(x) }
        }
        for x in flat {
            if try isEmpty(x, other) { return .object(["type": .string("compound"), "operator": .string(other), "value": .array([])]) }
        }
        let kept = try flat.filter { !(try isEmpty($0, op)) }
        if kept.count == 1 { return kept[0] }
        return .object(["type": .string("compound"), "operator": .string(op), "value": .array(kept)])
    }
    static func and2(_ xs: [V]) throws -> V { try join("and", xs) }
    static func or2(_ xs: [V]) throws -> V { try join("or", xs) }
    static func not2(_ x: V) -> V { .object(["type": .string("compound"), "operator": .string("not"), "value": .array([x])]) }
    static func fld(_ field: V?, _ op: String?, _ value: V?) -> V {
        A.obj([("type", .string("field")), ("field", field), ("operator", op.map { JSONValue.string($0) }), ("value", value)])
    }
    static func notNull(_ c: V?) -> V { fld(c, "ne", .null) }

    static func xs(_ x: V?) throws -> [V] { try listOf(A.mem(x, "xs")) }

    /// T(x): "x is definitely true" (both T and F are false when a referenced column is NULL).
    static func T(_ x: V?) throws -> V {
        let col = A.mem(x, "col")
        switch (try A.rd(x, "t")?.asString) ?? "" {
        case "true": return try and2([])
        case "false": return try or2([])
        case "cmp":
            if IV.same(A.mem(x, "op")?.asString, "ne") { return try and2([notNull(col), fld(col, "ne", A.mem(x, "v"))]) }
            return fld(col, A.mem(x, "op")?.asString, A.mem(x, "v"))
        case "in":
            return JS.truthy(A.mem(x, "neg")) ? try and2([notNull(col), fld(col, "nin", A.mem(x, "vs"))]) : fld(col, "in", A.mem(x, "vs"))
        case "prefix": return fld(col, "startswith", A.mem(x, "prefix"))
        case "null": return JS.truthy(A.mem(x, "isNull")) ? fld(col, "eq", .null) : notNull(col)
        case "and": return try and2(try xs(x).map { try T($0) })
        case "or": return try or2(try xs(x).map { try T($0) })
        case "not": return try F(A.mem(x, "x"))
        case "coalesce": return JS.truthy(A.mem(x, "def")) ? not2(try F(A.mem(x, "x"))) : try T(A.mem(x, "x"))
        default: throw JSError("unknown filter node")
        }
    }

    /// F(x): "x is definitely false".
    static func F(_ x: V?) throws -> V {
        let col = A.mem(x, "col")
        switch (try A.rd(x, "t")?.asString) ?? "" {
        case "true": return try or2([])
        case "false": return try and2([])
        case "cmp":
            let inv = ["eq": "ne", "ne": "eq", "lt": "gte", "lte": "gt", "gt": "lte", "gte": "lt"]
            return try and2([notNull(col), fld(col, inv[A.mem(x, "op")?.asString ?? ""], A.mem(x, "v"))])
        case "in": return JS.truthy(A.mem(x, "neg")) ? fld(col, "in", A.mem(x, "vs")) : try and2([notNull(col), fld(col, "nin", A.mem(x, "vs"))])
        case "prefix": return try and2([notNull(col), not2(fld(col, "startswith", A.mem(x, "prefix")))])
        case "null": return JS.truthy(A.mem(x, "isNull")) ? notNull(col) : fld(col, "eq", .null)
        case "and": return try or2(try xs(x).map { try F($0) })
        case "or": return try and2(try xs(x).map { try F($0) })
        case "not": return try T(A.mem(x, "x"))
        case "coalesce": return JS.truthy(A.mem(x, "def")) ? try F(A.mem(x, "x")) : not2(try T(A.mem(x, "x"))) // false exactly when x is not definitely true
        default: throw JSError("unknown filter node")
        }
    }

    // ---- evaluation ----

    static func kleene(_ x: V?, _ row: V?) throws -> Bool? {
        switch (try A.rd(x, "t")?.asString) ?? "" {
        case "true": return true
        case "false": return false
        case "cmp":
            let a = try cell(row, A.mem(x, "col")), b = A.mem(x, "v")
            if a == .null || typeOf(a) != typeOf(b) { return nil }
            switch A.mem(x, "op")?.asString {
            case "eq": return strictEq(a, b)
            case "ne": return !strictEq(a, b)
            case "lt": return JSLoose.lt(a, b)
            case "lte": return le(a, b)
            case "gt": return JSLoose.gt(a, b)
            default: return ge(a, b)
            }
        case "in":
            let a = try cell(row, A.mem(x, "col"))
            if a == .null { return nil }
            let hit = try includes(A.mem(x, "vs"), a)
            return JS.truthy(A.mem(x, "neg")) ? !hit : hit
        case "prefix":
            guard case let .string(s) = try cell(row, A.mem(x, "col")) else { return nil }
            return IV.startsWith(s, JS.toString(A.mem(x, "prefix")))
        case "null":
            guard case let .bool(want)? = A.mem(x, "isNull") else { return false } // `(c === null) === x.isNull` is never true for a non-boolean
            return (try cell(row, A.mem(x, "col")) == .null) == want
        case "and":
            var unk = false
            for y in try xs(x) {
                let v = try kleene(y, row)
                if v == false { return false }
                if v == nil { unk = true }
            }
            return unk ? nil : true
        case "or":
            var unk = false
            for y in try xs(x) {
                let v = try kleene(y, row)
                if v == true { return true }
                if v == nil { unk = true }
            }
            return unk ? nil : false
        case "not":
            guard let v = try kleene(A.mem(x, "x"), row) else { return nil }
            return !v
        case "coalesce":
            if let v = try kleene(A.mem(x, "x"), row) { return v }
            guard case let .bool(d)? = A.mem(x, "def") else { throw JSError("coalesce default is not a boolean") }
            return d
        default: throw JSError("unknown filter node")
        }
    }
}

extension PCAAnalyzer {
    /// Compile a residual to a parameterized SQL filter and a UCAST tree, or say why it cannot be done exactly (`ok: false`).
    public static func toFilter(_ res: JSONValue?, _ o: JSONValue?) -> JSONValue {
        do {
            if IV.same(try rd(res, "decision")?.asString, "never") {
                return obj([("ok", .bool(true)), ("expr", FlH.T_FALSE), ("sql", .string("FALSE")), ("params", .array([])), ("ucast", try toUcast(FlH.T_FALSE))])
            }
            let include = JS.present(try rd(o, "include")) ?? .string("autonomous")
            let policy = try rd(res, "policy")
            let own = try JSLoose.rest(policy, without: "meet")
            let parts: [V] = [.object(own)] + (try JS.spread(JS.present(mem(policy, "meet")) ?? .array([])))
            let cols = mem(o, "columns")
            let expr = FlH.and(try parts.map { try FlH.partExpr($0, cols, include) })
            var params: [V] = []
            let dialect = JS.present(mem(o, "dialect")) ?? .string("postgres")
            let sql = try FlH.render(expr, IV.same(dialect.asString, "postgres"), &params)
            return obj([("ok", .bool(true)), ("expr", expr), ("sql", .string(sql)), ("params", .array(params)), ("ucast", try toUcast(expr))])
        } catch let e as FlH.Unsupported {
            return obj([("ok", .bool(false)), ("reason", .string(e.reason))])
        } catch {
            return obj([("ok", .bool(false)), ("reason", .string("filter compilation error"))])
        }
    }

    /// Evaluate a filter expression over one row (Kleene semantics): true | false | null (unknown).
    public static func evalFilter(_ e: JSONValue?, _ row: JSONValue?) throws -> JSONValue {
        guard let r = try FlH.kleene(e, row) else { return .null }
        return .bool(r)
    }

    /// The filter as a UCAST tree whose rows are exactly those the SQL form selects.
    public static func toUcast(_ e: JSONValue?) throws -> JSONValue { try FlH.T(e) }

    /// Evaluate a UCAST tree over one row (two-valued; a comparison with NULL is false, `eq null` / `ne null` test for NULL).
    public static func evalUcast(_ u: JSONValue?, _ row: JSONValue?) throws -> Bool {
        if IV.same(try rd(u, "type")?.asString, "compound") {
            let list = arr(mem(u, "value"))
            switch mem(u, "operator")?.asString {
            case "and"?:
                for c in list { if !(try evalUcast(c, row)) { return false } }
                return true
            case "or"?:
                for c in list { if try evalUcast(c, row) { return true } }
                return false
            default: return !(try evalUcast(list.first, row))
            }
        }
        let a = try FlH.cell(row, mem(u, "field")), v = mem(u, "value")
        let op = mem(u, "operator")?.asString
        if op == "eq" && v == .null { return a == .null }
        if op == "ne" && v == .null { return a != .null }
        if a == .null { return false }
        let sameType = FlH.typeOf(a) == FlH.typeOf(v)
        switch op {
        case "eq"?: return FlH.strictEq(a, v)
        case "ne"?: return sameType && !FlH.strictEq(a, v)
        case "lt"?: return sameType && JSLoose.lt(a, v)
        case "lte"?: return sameType && FlH.le(a, v)
        case "gt"?: return sameType && JSLoose.gt(a, v)
        case "gte"?: return sameType && FlH.ge(a, v)
        case "in"?: return try FlH.includes(v, a)
        case "nin"?: return !(try FlH.includes(v, a))
        case "startswith"?:
            guard case let .string(s) = a else { return false }
            return IV.startsWith(s, JS.toString(v))
        default: throw JSError("unknown UCAST operator")
        }
    }
}
