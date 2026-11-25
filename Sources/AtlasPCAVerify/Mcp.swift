import Foundation

/// The MCP adapter's pure surface: the `WWW-Authenticate` parser and step-up planner (with the typed `pca_need` requirement), the RFC 9207
/// `iss` table, the client conformance matrix, the tool-result proof meta, the `PCA-Action` header, and the v1 action-schema draft from an MCP
/// tool list (JSON Schema flattening, the developer's decisions, the closed-world tool-call check). Values are the parsed-JSON model
/// (`JSONValue`). Whatever the draft cannot represent is flagged in `todo` and declared `string`, which rejects every non-string value, so the
/// draft fails closed until the developer refines it.
/// `pcaFetch` (the client transport wrapper over an injected fetch) and the structural tool wrapper are in AdapterKit.swift. Header objects arrive
/// without insertion order, so own-key order is code-unit order.
public enum PCAMcp {
    public static let MCP_CLIENT_REVISIONS = ["2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "draft"]
    public static let RESULT_META_KEY = "x-pca-action"
    static let MAX_REF_DEPTH = 8
    static let MAX_REF_NODES = 20_000

    static func typeError(_ m: String) -> JSError { JSError("TypeError: \(m)") }
    static func eq(_ a: String, _ b: String) -> Bool { a.unicodeScalars.elementsEqual(b.unicodeScalars) }
    static func u16Less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }
    static func utf8Less(_ a: String, _ b: String) -> Bool { a.utf8.lexicographicallyPrecedes(b.utf8) }

    // ---- JS-model helpers ----

    /// `{...x}`: an object copies, a list or a string gives its indices, anything else gives nothing.
    static func spreadObj(_ x: JSONValue?) -> JObject {
        switch x {
        case let .object(o)?: return o
        case let .array(a)?:
            var o: JObject = [:]
            for (i, v) in a.enumerated() { o[JKey(String(i))] = v }
            return o
        case let .string(s)?:
            var o: JObject = [:]
            for (i, u) in s.utf16.enumerated() { o[JKey(String(i))] = .string(String(decoding: [u], as: UTF16.self)) }
            return o
        default: return [:]
        }
    }

    /// `[...x]` of a member: absent / null is empty, a list copies, a string spreads by code point, anything else throws.
    static func iter(_ x: JSONValue?) throws -> [JSONValue] {
        guard let v = JS.present(x) else { return [] }
        return try JS.spread(v)
    }

    /// Object.keys of a parsed value, in code-unit order (an object has no insertion order here), index keys of a list or string first.
    static func keysOf(_ o: JSONValue?) -> [String] {
        switch o {
        case let .object(m)?:
            let idx = m.keys.compactMap { k in JS.indexKey(k.s).map { (k.s, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
            return idx + m.keys.map { $0.s }.filter { JS.indexKey($0) == nil }.sorted(by: u16Less)
        case let .array(a)?: return a.indices.map { String($0) }
        case let .string(s)?: return s.utf16.indices.map { String($0.utf16Offset(in: s)) }
        default: return []
        }
    }

    static func valueOf(_ o: JSONValue?, _ k: String) -> JSONValue? {
        switch o {
        case let .object(m)?: return m[JKey(k)]
        case let .array(a)?: return JS.indexKey(k).flatMap { Int($0) < a.count ? a[Int($0)] : nil }
        case let .string(s)?: return JS.indexKey(k).flatMap { i in Int(i) < s.utf16.count ? .string(String(decoding: [Array(s.utf16)[Int(i)]], as: UTF16.self)) : nil }
        default: return nil
        }
    }

    static func has(_ v: JSONValue?, _ k: String) -> Bool { v?.asObject?[JKey(k)] != nil }
    static func opt(_ v: JSONValue?, _ k: String) -> JSONValue? { JS.present(valueOf(v, k)) }

    static func numberOf(_ v: JSONValue?) -> Double? {
        switch v { case let .int(i)?: return Double(i); case let .double(d)?: return d; default: return nil }
    }

    /// `Number.isSafeInteger(x)` (no coercion).
    static func safeInt(_ v: JSONValue?) -> Bool {
        guard let d = numberOf(v), d.isFinite else { return false }
        return d == d.rounded() && abs(d) <= 9_007_199_254_740_991
    }

    /// `===` over parsed JSON scalars (strings by code points, numbers by value; containers are never identical).
    static func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.string(x)?, .string(y)?): return eq(x, y)
        case let (.bool(x)?, .bool(y)?): return x == y
        case (.null?, .null?): return true
        default:
            if let x = numberOf(a), let y = numberOf(b) { return x == y }
            return false
        }
    }

    /// `x.slice(0, 1024)` of a string (UTF-16 units) or a list; anything else is not a function.
    static func slice1024(_ d: JSONValue?) throws -> JSONValue {
        switch d {
        case let .string(s)?: return s.utf16.count > 1024 ? .string(String(decoding: Array(s.utf16.prefix(1024)), as: UTF16.self)) : .string(s)
        case let .array(a)?: return .array(Array(a.prefix(1024)))
        default: throw typeError("slice is not a function")
        }
    }

    // ---- tool results and headers ----

    /// The result with the proof of the call in `_meta["x-pca-action"]`; `pca` is {encoded}. Existing members and `_meta` keys are kept.
    public static func guardToolResult(_ pca: JSONValue?, _ result: JSONValue?) throws -> JSONValue {
        guard let r = result, r != .null else { throw typeError("Cannot read properties of null (reading '_meta')") }
        let prev = valueOf(r, "_meta")
        var meta: JObject = [:]
        if JS.truthy(prev), prev?.isObject == true || prev?.isArray == true { meta = spreadObj(prev) }
        guard let p = pca, p != .null else { throw typeError("Cannot read properties of null (reading 'encoded')") }
        // `{ ...prevMeta, key: pca.encoded }`: an absent `encoded` is undefined, which replaces (and so removes) a previous value
        meta[JKey(RESULT_META_KEY)] = p.asObject?[JKey("encoded")]
        var out = spreadObj(r)
        out[JKey("_meta")] = .object(meta)
        return .object(out)
    }

    /// The `PCA-Action` header of an encoded PCActn: base64url of its UTF-8 text.
    public static func pcaHeaders(_ encoded: String) -> [String: String] { ["PCA-Action": Base64URLStrict.encode(Array(encoded.utf8))] }

    // ---- WWW-Authenticate / step-up ----

    /// The need a `pca_need` auth-param carries: {ok: true, need} or {ok: false, code}; nil when the header names none.
    public static func pcaNeedFromChallenge(_ header: JSONValue?) -> JSONValue? {
        guard let h = header?.asString else { return nil }
        let u = Array(h.unicodeScalars)
        let key = Array("pca_need=\"".unicodeScalars)
        func matchAt(_ p: Int) -> String? {
            guard p + key.count <= u.count, Array(u[p..<(p + key.count)]) == key else { return nil }
            var i = p + key.count
            let s = i
            while i < u.count, u[i] != "\"", u[i] != "\\" { i += 1 }
            guard i < u.count, u[i] == "\"" else { return nil }
            return String(String.UnicodeScalarView(u[s..<i]))
        }
        var found: String?
        for s in 0...u.count {
            if s == 0, let m = matchAt(0) { found = m; break }
            if s < u.count, u[s] == "," || Attest.isJSSpace(u[s]), let m = matchAt(s + 1) { found = m; break }
        }
        guard let inner = found else { return nil }
        let r = A2a.decodeNeed(.string(inner))
        if let need = r.need { return .object(["ok": .bool(true), "need": need]) }
        return .object(["ok": .bool(false), "code": .string(r.code ?? "bad_json")])
    }

    /// Every challenge of a WWW-Authenticate header (quoted strings, several challenges): {scheme, params}, names lower-cased, a repeated
    /// parameter keeps its first value, "constructor" and "__proto__" are never stored. Tolerant of garbage: it never throws.
    public static func parseChallenges(_ header: JSONValue?) -> [JSONValue] {
        guard let h = header?.asString else { return [] }
        let b = Array(h.utf8)
        let n = b.count
        var i = 0
        var out: [(scheme: String, params: JObject)] = []
        func skip(_ commas: Bool) { while i < n, b[i] == 0x20 || b[i] == 0x09 || (commas && b[i] == 0x2c) { i += 1 } }
        func token() -> String {
            let s = i
            while i < n, ![0x20, 0x09, 0x2c, 0x3d, 0x22].contains(b[i]) { i += 1 }
            return String(decoding: b[s..<i], as: UTF8.self)
        }
        skip(true)
        while i < n {
            let name = token()
            if name.isEmpty { i += 1; continue } // a stray quote or equals sign: skip it
            skip(false)
            let key = name.lowercased()
            if i < n, b[i] == 0x3d {
                i += 1
                skip(false)
                var val: String
                if i < n, b[i] == 0x22 {
                    i += 1
                    var v: [UInt8] = []
                    while i < n, b[i] != 0x22 {
                        if b[i] == 0x5c, i + 1 < n { i += 1 }
                        v.append(b[i]); i += 1
                    }
                    i += 1 // closing quote
                    val = String(decoding: v, as: UTF8.self)
                } else {
                    val = token()
                }
                if !out.isEmpty, out[out.count - 1].params[JKey(key)] == nil, key != "constructor", key != "__proto__" {
                    out[out.count - 1].params[JKey(key)] = .string(val)
                }
            } else {
                out.append((key, [:]))
            }
            skip(true)
        }
        return out.map { .object(["scheme": .string($0.scheme), "params": .object($0.params)]) }
    }

    /// What to do with a response: re-authorize with the union of the scopes already requested and the challenge's (sorted); hand a valid
    /// `pca_need` to the approval flow (pcaAware, the scope union kept as the fallback); or give up (not an insufficient_scope challenge, the
    /// retry limit, or a union that adds nothing). `state`: requested, attempts, maxAttempts (3), pcaAware. It never approves anything.
    public static func planStepUp(_ status: JSONValue?, _ wwwAuthenticate: JSONValue?, _ state: JSONValue?) throws -> JSONValue {
        guard let st = state, st != .null else { throw typeError("Cannot read properties of null (reading 'maxAttempts')") }
        let max = opt(st, "maxAttempts").map { JS.toNumber($0) } ?? 3
        func giveUp(_ r: String) -> JSONValue { .object(["action": .string("give_up"), "reason": .string(r)]) }
        var bearer: JObject?
        if numberOf(status) == 403 {
            for c in parseChallenges(wwwAuthenticate) where c.get("scheme")?.asString == "bearer" { bearer = c.get("params")?.asObject; break }
        }
        guard let params = bearer, params[JKey("error")]?.asString == "insufficient_scope" else { return giveUp("not_insufficient_scope") }
        let attemptsIn = valueOf(st, "attempts")
        let attemptsN = JS.toNumber(attemptsIn)
        if !(attemptsN.isFinite && attemptsN < max) { return giveUp("retry_limit") }
        let requested = try JS.spread(valueOf(st, "requested"))
        var union: [JSONValue] = []
        func add(_ v: JSONValue) { if !union.contains(where: { strictEq($0, v) }) { union.append(v) } }
        for r in requested { add(r) }
        if let scope = params[JKey("scope")]?.asString {
            for x in scope.split(separator: " ", omittingEmptySubsequences: true) { add(.string(String(x))) }
        }
        // Array.prototype.sort(): by the UTF-16 code units of String(x), stable
        union = union.enumerated().sorted { a, b in
            let x = JS.toString(a.element), y = JS.toString(b.element)
            return eq(x, y) ? a.offset < b.offset : u16Less(x, y)
        }.map { $0.element }
        let attempts: JSONValue = attemptsIn?.asString.map { JSONValue.string($0 + "1") } ?? .double(JS.toNumber(attemptsIn) + 1)
        if valueOf(st, "pcaAware") == .bool(true), let r = pcaNeedFromChallenge(wwwAuthenticate), r.get("ok") == .bool(true) {
            return .object(["action": .string("pca"), "need": r.get("need") ?? .null, "fallbackScopes": .array(union), "attempts": attempts])
        }
        // a missing or malformed pca_need is not an error: fall through to the stock behaviour
        if union.allSatisfy({ s in requested.contains(where: { strictEq($0, s) }) }) { return giveUp("no_new_scope") }
        return .object(["action": .string("scope"), "scopes": .array(union), "attempts": attempts])
    }

    /// The code of a `pca_need` that is present but unusable (for client logs), else nil.
    public static func pcaNeedProblem(_ wwwAuthenticate: JSONValue?) -> String? {
        guard let r = pcaNeedFromChallenge(wwwAuthenticate), r.get("ok") == .bool(false) else { return nil }
        return r.get("code")?.asString
    }

    /// The RFC 9207 `iss` table for an authorization response, with no normalization. `a`: recordedIssuer, issParameterSupported, iss
    /// (an absent iss differs from a null one).
    public static func checkAuthorizationResponseIss(_ a: JSONValue?) throws -> JSONValue {
        guard let av = a, av != .null else { throw typeError("Cannot read properties of null (reading 'recordedIssuer')") }
        guard let rec = valueOf(av, "recordedIssuer")?.asString, !rec.isEmpty else { return .object(["proceed": .bool(false), "reason": .string("no_recorded_issuer")]) }
        guard let iss = av.asObject?[JKey("iss")] else {
            return valueOf(av, "issParameterSupported") == .bool(true) ? .object(["proceed": .bool(false), "reason": .string("iss_missing")]) : .object(["proceed": .bool(true)])
        }
        return strictEq(iss, .string(rec)) ? .object(["proceed": .bool(true)]) : .object(["proceed": .bool(false), "reason": .string("iss_mismatch")])
    }

    // ---- client conformance matrix ----

    static func row(_ id: String, _ requirement: String, _ section: String, _ levels: [String]) -> JSONValue {
        var l: JObject = [:]
        for (r, v) in zip(MCP_CLIENT_REVISIONS, levels) { l[JKey(r)] = .string(v) }
        return .object(["id": .string(id), "requirement": .string(requirement), "levels": .object(l), "section": .string(section)])
    }

    /// The MCP authorization client requirements by spec revision.
    public static func mcpAuthClientRows() -> [JSONValue] {
        [
            row("parse-www-authenticate", "Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.", "Protected Resource Metadata Discovery Requirements", ["n/a", "MUST", "MUST", "MUST", "MUST"]),
            row("step-up-on-insufficient-scope", "Respond to 403 insufficient_scope by re-authorizing with an increased scope set.", "Step-Up Authorization Flow", ["n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"]),
            row("scope-union", "The new scope set is the union of the previously requested set and the challenge scopes.", "Step-Up Authorization Flow, step 2", ["n/a", "n/a", "n/a", "SHOULD", "SHOULD"]),
            row("retry-limit", "Retry no more than a few times and track upgrade attempts per resource and operation.", "Step-Up Authorization Flow, step 4", ["n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"]),
            row("iss-validation-table", "Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.", "Authorization Response Validation", ["n/a", "n/a", "n/a", "MUST", "MUST"]),
            row("pca-need-ignored-by-stock-client", "A client that does not know pca_need behaves exactly as without it.", "RFC 9110 section 11.2 (unknown auth-params are ignored)", ["EXT", "EXT", "EXT", "EXT", "EXT"]),
        ]
    }

    // ---- site action schema (the v1 draft) ----

    /// The draft's shared state: the decisions the developer must still make, and the remaining node budget of one tool.
    final class Ctx {
        var root: JSONValue?
        let todo: Todo
        var left: Int?
        init(root: JSONValue?, todo: Todo) { self.root = root; self.todo = todo }
    }
    final class Todo { var items: [String] = [] }

    /// Follow a local `#/a/b` JSON pointer in `root`; nil when absent, not local, or not an object / list.
    static func pointer(_ root: JSONValue?, _ ref: String) -> JSONValue? {
        guard ref.hasPrefix("#/") else { return nil }
        var cur = root
        for raw in String(ref.dropFirst(2)).components(separatedBy: "/") {
            let seg = raw.replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
            switch cur {
            case let .object(o)?:
                guard let v = o[JKey(seg)] else { return nil }
                cur = v
            case let .array(a)?:
                guard seg.utf8.count <= 9, JS.indexKey(seg) != nil, let i = Int(seg), i < a.count else { return nil }
                cur = a[i]
            default: return nil
            }
        }
        return cur?.isObject == true || cur?.isArray == true ? cur : nil
    }

    static func typeIsNull(_ m: JObject) -> Bool {
        switch m[JKey("type")] {
        case .string(let t)?: return t == "null"
        case let .array(a)?: return a.allSatisfy { $0 == .string("null") }
        default: return false
        }
    }

    /// The member as a list of strings when it is one (an enum), else nil.
    static func stringEnum(_ m: JObject) -> [JSONValue]? {
        guard let a = m[JKey("enum")]?.asArray, a.allSatisfy({ $0.asString != nil }) else { return nil }
        return a
    }

    /// Flatten what a parameter declaration cannot carry: follow local `$ref`s, merge `allOf`, collapse `anyOf` / `oneOf` to its single non-null
    /// variant (or to the union of string constants).
    static func flatten(_ s: JSONValue?, _ c: Ctx, _ whereAt: String, _ depth: Int = 0) throws -> JObject {
        guard let sv = s, sv.isObject || sv.isArray else { return [:] }
        c.left = (c.left ?? MAX_REF_NODES) - 1
        if c.left! < 0 {
            if c.left == -1 { c.todo.items.append("\(whereAt): schema expansion stopped after \(MAX_REF_NODES) nodes (declared string; refine or drop)") }
            return [:]
        }
        if depth > MAX_REF_DEPTH {
            c.todo.items.append("\(whereAt): schema nesting or reference chain deeper than \(MAX_REF_DEPTH) (declared string; refine or drop)")
            return [:]
        }
        var cur = spreadObj(sv)
        if let ref = sv.asObject?[JKey("$ref")]?.asString {
            guard let target = pointer(c.root, ref) else {
                c.todo.items.append("\(whereAt): reference '\(String(decoding: Array(ref.utf16.prefix(120)), as: UTF16.self))' is not a local reference that resolves (declared string; refine or drop)")
                return [:]
            }
            var merged = try flatten(target, c, whereAt, depth + 1)
            for (k, v) in cur where k.s != "$ref" { merged[k] = v }
            cur = merged
        }
        if let allOf = cur[JKey("allOf")]?.asArray {
            var rest = cur
            rest[JKey("allOf")] = nil
            var acc: JObject = [:]
            for item in allOf {
                let m = try flatten(item, c, whereAt, depth + 1)
                var next = acc
                for (k, v) in m { next[k] = v }
                var props = spreadObj(acc[JKey("properties")])
                for (k, v) in spreadObj(m[JKey("properties")]) { props[k] = v }
                next[JKey("properties")] = .object(props)
                next[JKey("required")] = .array(try iter(acc[JKey("required")]) + (try iter(m[JKey("required")])))
                acc = next
            }
            cur = acc
            for (k, v) in rest { cur[k] = v }
        }
        if let alts = (JS.present(cur[JKey("anyOf")]) ?? JS.present(cur[JKey("oneOf")]))?.asArray {
            var rest = cur
            rest[JKey("anyOf")] = nil
            rest[JKey("oneOf")] = nil
            var live: [JObject] = []
            for a in alts {
                let f = try flatten(a, c, whereAt, depth + 1)
                if !typeIsNull(f) { live.append(f) }
            }
            if live.count == 1 {
                var out = live[0]
                for (k, v) in rest { out[k] = v }
                return out
            }
            var consts: [[JSONValue]?] = []
            for m in live {
                if let k = m[JKey("const")]?.asString { consts.append([.string(k)]) } else { consts.append(stringEnum(m)) }
            }
            if live.count > 1, consts.allSatisfy({ $0 != nil }) {
                var out = rest
                out[JKey("type")] = .string("string")
                var uniq: [JSONValue] = []
                for v in consts.flatMap({ $0! }) where !uniq.contains(where: { strictEq($0, v) }) { uniq.append(v) }
                out[JKey("enum")] = .array(uniq)
                return out
            }
            c.todo.items.append("\(whereAt): a union of \(live.count) schemas has no schema representation (declared string; refine or drop)")
            return rest
        }
        if let k = cur[JKey("const")], k.asString != nil, cur[JKey("enum")] == nil { cur[JKey("enum")] = .array([k]) }
        return cur
    }

    /// `Array.isArray(t) ? t.find(x => x !== 'null') : t` for the `type` member (nil = undefined).
    static func typeOf(_ s: JObject) -> JSONValue? {
        guard let t = s[JKey("type")] else { return nil }
        if let a = t.asArray { return a.first { $0 != .string("null") } }
        return t
    }

    /// A JSON Schema property as a parameter declaration; unrepresentable shapes become `string` placeholders flagged in `todo`.
    static func declOf(_ name: String, _ schema: JSONValue?, _ required: Bool, _ c: Ctx) throws -> JSONValue {
        let s = try flatten(schema, c, "action.params.\(name)")
        let t = typeOf(s)
        var base: JObject = ["semantic": JS.present(s[JKey("x-pca-semantic")]) ?? .string("unknown"),
                             "sensitivity": JS.present(s[JKey("x-pca-sensitivity")]) ?? .string("material")]
        if !required { base[JKey("required")] = .bool(false) }
        if JS.truthy(s[JKey("description")]) { base[JKey("description")] = try slice1024(s[JKey("description")]) }
        if !JS.truthy(s[JKey("x-pca-semantic")]) { c.todo.items.append("action.params.\(name): semantic type") }
        let enumStrings = stringEnum(s)
        func decl(_ type: String, _ extra: [(String, JSONValue)] = []) -> JSONValue {
            var o = base
            o[JKey("type")] = .string(type)
            for (k, v) in extra { o[JKey(k)] = v }
            return .object(o)
        }
        func bound(_ k: String) -> JSONValue? { safeInt(s[JKey(k)]) ? s[JKey(k)] : nil }
        let ts = t?.asString
        if ts == "integer" {
            var extra: [(String, JSONValue)] = []
            if let m = bound("minimum") { extra.append(("min", m)) } else if safeInt(s[JKey("exclusiveMinimum")]) { extra.append(("min", .double(numberOf(s[JKey("exclusiveMinimum")])! + 1))) }
            if let m = bound("maximum") { extra.append(("max", m)) } else if safeInt(s[JKey("exclusiveMaximum")]) { extra.append(("max", .double(numberOf(s[JKey("exclusiveMaximum")])! - 1))) }
            if JS.truthy(s[JKey("x-pca-unit")]) { extra.append(("unit", s[JKey("x-pca-unit")]!)) }
            if JS.truthy(s[JKey("x-pca-accumulates-into")]) { extra.append(("accumulates_into", s[JKey("x-pca-accumulates-into")]!)) }
            return decl("integer", extra)
        }
        if ts == "boolean" { return decl("boolean") }
        if ts == "string", s[JKey("format")]?.asString == "date" { return decl("date") }
        if ts == "string" {
            var extra: [(String, JSONValue)] = []
            if let e = enumStrings { extra.append(("values", .array(e))) }
            if safeInt(s[JKey("maxLength")]), numberOf(s[JKey("maxLength")])! > 0 { extra.append(("max_len", s[JKey("maxLength")]!)) }
            return decl("string", extra)
        }
        if ts == "array" {
            let it = try flatten(s[JKey("items")], c, "action.params.\(name)[]")
            let itEnum = stringEnum(it)
            if JS.truthy(s[JKey("uniqueItems")]), let e = itEnum {
                var extra: [(String, JSONValue)] = [("values", .array(e))]
                if let m = bound("minItems") { extra.append(("min_items", m)) }
                if let m = bound("maxItems") { extra.append(("max_items", m)) }
                return decl("set", extra)
            }
            let itT: JSONValue? = it[JKey("type")]?.asArray.map { $0.first ?? .null } ?? it[JKey("type")]
            var extra: [(String, JSONValue)] = []
            if itT == .string("integer") { extra.append(("items", .string("integer"))) }
            if let m = bound("maxItems") { extra.append(("max_items", m)) }
            if let m = bound("minItems") { extra.append(("min_items", m)) }
            return decl("array", extra)
        }
        c.todo.items.append("action.params.\(name): type '\(JS.toString(t))' has no schema representation (declared string; refine or drop)")
        return decl("string")
    }

    static func isSchemaName(_ s: String) -> Bool {
        let n = s.utf8.count
        return n >= 1 && n <= 64 && s.unicodeScalars.allSatisfy { ($0.value >= 0x30 && $0.value <= 0x39) || ($0.value >= 0x41 && $0.value <= 0x5a) || ($0.value >= 0x61 && $0.value <= 0x7a) || $0 == "_" }
    }

    /// Draft a v1 action schema from an MCP tool list. Verb = verbPrefix + tool name; every write verb is drafted `irreversible` (the
    /// fail-closed default). `site`: site, aud, version, verbPrefix. Returns {schema, todo}: the decisions the developer must still make are in `todo`.
    public static func draftActionSchemaFromMcp(_ tools: JSONValue?, _ site: JSONValue?) throws -> JSONValue {
        guard let list = tools?.asArray else { throw typeError("tools is not iterable") }
        let todo = Todo()
        var verbs: [JSONValue] = []
        for t in list {
            if t == .null { throw typeError("Cannot read properties of null (reading 'inputSchema')") }
            let c = Ctx(root: valueOf(t, "inputSchema"), todo: todo)
            let tname = has(t, "name") ? JS.toString(valueOf(t, "name")) : "undefined"
            let input = try flatten(valueOf(t, "inputSchema"), c, "\(tname): inputSchema")
            let props = JS.present(input[JKey("properties")]) ?? .object([:])
            let req = try iter(input[JKey("required")])
            var params: JObject = [:]
            for name in keysOf(props).sorted(by: utf8Less) {
                guard isSchemaName(name) else {
                    todo.items.append("\(tname): parameter '\(name)' is not a schema name ([A-Za-z0-9_]{1,64}); rename it")
                    continue
                }
                params[JKey("action.params.\(name)")] = try declOf(name, valueOf(props, name), req.contains { strictEq($0, .string(name)) }, c)
            }
            let read = valueOf(valueOf(t, "annotations"), "readOnlyHint") == .bool(true)
            let verb = (opt(site, "verbPrefix").map { JS.toString($0) } ?? "") + tname
            if !read { todo.items.append("\(verb): reversibility (drafted irreversible)") }
            var v: JObject = ["verb": .string(verb), "kind": .string(read ? "read" : "write"), "params": .object(params),
                              "reversibility": .string(read ? "reversible" : "irreversible")]
            var mcp: JObject = [:]
            if has(t, "name") { mcp[JKey("tool")] = valueOf(t, "name") }
            v[JKey("mcp")] = .object(mcp)
            if JS.truthy(valueOf(t, "description")) { v[JKey("description")] = try slice1024(valueOf(t, "description")) }
            verbs.append(.object(v))
        }
        verbs = verbs.enumerated().sorted { a, b in
            let x = a.element.get("verb")?.asString ?? "", y = b.element.get("verb")?.asString ?? ""
            return eq(x, y) ? a.offset < b.offset : utf8Less(x, y)
        }.map { $0.element }
        guard let sv = site, sv != .null else { throw typeError("Cannot read properties of null (reading 'site')") }
        var schema: JObject = ["v": .int(1), "kind": .string("pca-action-schema"), "verbs": .array(verbs)]
        for k in ["site", "aud", "version"] { if let v = sv.asObject?[JKey(k)] { schema[JKey(k)] = v } }
        return .object(["schema": .object(schema), "todo": .array(todo.items.map { .string($0) })])
    }

    /// Record the developer's decisions on a draft (a new value): reversibility and parameter fields per verb, and unit declarations. A verb or
    /// parameter the draft does not have throws: the schema is closed, so a typo must not silently publish a looser schema.
    /// `d`: {verbs: {verb: {reversibility?, params?: {path: fields}}}, units?}.
    public static func applySchemaDecisions(_ draft: JSONValue?, _ d: JSONValue?) throws -> JSONValue {
        guard var out = draft else { throw JSError("SyntaxError: draft is undefined") }
        guard let dv = d, dv != .null else { throw typeError("Cannot read properties of null (reading 'units')") }
        if JS.truthy(valueOf(dv, "units")) {
            guard case var .object(o) = out else { throw typeError("draft is not an object") }
            var merged = spreadObj(JS.present(o[JKey("units")]) ?? .object([:]))
            for (k, v) in spreadObj(valueOf(dv, "units")) { merged[k] = v }
            o[JKey("units")] = .object(merged)
            out = .object(o)
        }
        guard let dverbs = opt(dv, "verbs") else { throw typeError("Cannot convert undefined or null to object") }
        for verb in keysOf(dverbs) {
            let dvv = valueOf(dverbs, verb)
            guard case var .object(o) = out, var list = o[JKey("verbs")]?.asArray else { throw typeError("out.verbs.find is not a function") }
            var at: Int?
            for (i, x) in list.enumerated() {
                if x == .null { throw typeError("Cannot read properties of null (reading 'verb')") }
                if strictEq(x.asObject?[JKey("verb")], .string(verb)) { at = i; break }
            }
            guard let i = at, var vo = list[i].asObject else { throw JSError("applySchemaDecisions: the draft has no verb '\(verb)'") }
            guard let dvx = dvv, dvx != .null else { throw typeError("Cannot read properties of null (reading 'reversibility')") }
            if JS.truthy(valueOf(dvx, "reversibility")) { vo[JKey("reversibility")] = valueOf(dvx, "reversibility") }
            let dp = opt(dvx, "params") ?? .object([:])
            for path in keysOf(dp) {
                guard let pv = vo[JKey("params")], pv != .null else { throw typeError("Cannot read properties of undefined (reading '\(path)')") }
                let p = valueOf(pv, path)
                guard JS.truthy(p) else { throw JSError("applySchemaDecisions: verb '\(verb)' has no parameter '\(path)'") }
                if var po = p?.asObject, var params = pv.asObject {
                    for (k, v) in spreadObj(valueOf(dp, path)) { po[k] = v }
                    params[JKey(path)] = .object(po)
                    vo[JKey("params")] = .object(params)
                }
            }
            list[i] = .object(vo)
            o[JKey("verbs")] = .array(list)
            out = .object(o)
        }
        return out
    }

    /// The schema entry that declares the MCP tool (`mcp.tool`), or nil.
    static func entryOfTool(_ schema: JSONValue?, _ toolName: JSONValue?) throws -> JObject? {
        guard let sv = schema, sv != .null else { throw typeError("Cannot read properties of null (reading 'verbs')") }
        guard let verbs = valueOf(sv, "verbs")?.asArray else { throw typeError("schema.verbs.find is not a function") }
        for v in verbs {
            if v == .null { throw typeError("Cannot read properties of null (reading 'mcp')") }
            if let tool = v.asObject?[JKey("mcp")]?.asObject?[JKey("tool")], strictEq(tool, toolName) { return v.asObject }
        }
        return nil
    }

    /// The schema verb an MCP tool maps to (by `mcp.tool`), or nil.
    public static func verbOfTool(_ schema: JSONValue?, _ toolName: JSONValue?) throws -> JSONValue? {
        try entryOfTool(schema, toolName)?[JKey("verb")]
    }

    /// Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb). Returns {ok, code?, path?, reason?, verb?}.
    public static func conformToolCall(_ schema: JSONValue?, _ toolName: JSONValue?, _ args: JSONValue?) throws -> JSONValue {
        guard let verbV = try verbOfTool(schema, toolName) else {
            return .object(["ok": .bool(false), "code": .string("unknown_verb"), "reason": .string("MCP tool '\(JS.toString(toolName))' is not declared by the site schema")])
        }
        guard let verb = verbV.asString, let doc = schema else { throw typeError("verb is not a string") }
        let r = ActionSchema.conform(doc, verb: verb, params: args ?? .null)
        if r.ok { return .object(["ok": .bool(true), "verb": ActionSchema.verb(doc, verb).map { .object($0) } ?? .null]) }
        var o: JObject = ["ok": .bool(false), "code": .string(r.code), "reason": .string(r.reason)]
        if let p = r.path { o[JKey("path")] = .string(p) }
        return .object(o)
    }
}
