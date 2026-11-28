import Foundation

/// What every importer shares: result shapes, text hygiene, verb naming, the bounded `$ref` resolver, the JSON Schema to parameter flattening, and the
/// single place a draft def is assembled (always `unreviewed`). Sources, reports and defs are JSON trees.
public enum ImportCommon {
    public static let IMPORT_KINDS = ["openapi", "mcp", "graphql", "grpc", "asyncapi", "jsonschema"]
    public static let DEFAULT_EXTENSIONS = ["x-pca-verb", "x-pca-role", "x-pca-internal"]

    static let NS = "[a-z][a-z0-9_]{0,31}"
    static let VERB = "[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}"
    static let ALIAS = "[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,5}"
    private static let ID_ROLE = "id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}"
    private static let X_ROLE = "x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}"
    private static let RTYPE = "[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,4}"
    private static let MAX_TITLE_BYTES = 120, MAX_DESCRIPTION_BYTES = 1024, MAX_DEF_PARAMS = 64, MAX_PARAM_PATH_DEPTH = 3

    public static let CORE_ROLES = [
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    ]

    // ---- context ----

    /// Per-import state: the namespace, limits, notes, source reference and what is already emitted.
    public final class Ctx {
        public let ns: String
        public let kind: String
        public let lim: ImportLimits
        public var source: JObject
        public let ext: [JSONValue]
        /// Parsed-source root that `#/...` references resolve in.
        public var root: JSONValue?
        public var todo: [JSONValue] = []
        var verbs: [String] = []
        var verbSet = Set<JKey>()
        var aliases = Set<JKey>()
        public var defs: [JSONValue] = []
        init(ns: String, kind: String, lim: ImportLimits, source: JObject, ext: [JSONValue], root: JSONValue?) {
            self.ns = ns; self.kind = kind; self.lim = lim; self.source = source; self.ext = ext; self.root = root
        }
    }

    /// The expansion budget of one operation: every schema node visited costs one.
    public final class Budget {
        public var left: Int
        public var exhausted = false
        init(_ left: Int) { self.left = left }
    }

    static func newBudget(_ c: Ctx) -> Budget { Budget(Int(c.lim.maxRefNodes)) }

    public static func newCtx(_ kind: String, _ source: JSONValue?, _ opts: JObject?, bytes: [UInt8]? = nil) throws -> Ctx {
        guard let ns = opts?[JKey("ns")]?.asString, Actions.fullMatch(NS, ns) else { throw ActionKitError(code: "bad_ns", message: "ns must match [a-z][a-z0-9_]{0,31}") }
        let lim = try ImportLimits.resolve(opts?[JKey("limits")])
        let digest: String
        if let b = bytes {
            if Int64(b.count) > lim.maxBytes { throw ActionKitError(code: "import_limit", message: "the source is larger than \(lim.maxBytes) bytes") }
            digest = Jx.b64u(Jx.sha256(b))
        } else if case let .string(s)? = source {
            try lim.textSizeCheck(s)
            digest = Jx.b64u(Jx.sha256(Jx.utf8(s)))
        } else {
            try lim.checkParsed(source)
            digest = Jx.b64u(Jx.sha256(Jx.utf8(Canonical.canonicalize(source ?? .null))))
        }
        let now: JSONValue = JS.present(opts?[JKey("now")]) ?? .int(0)
        guard Jx.isSafe(now), (IV.num(now) ?? -1) >= 0 else { throw ActionKitError(code: "bad_opts", message: "now must be a non-negative integer") }
        let uri: JSONValue = JS.present(opts?[JKey("uri")]) ?? .string("source:\(kind)")
        let lic: JSONValue = JS.present(opts?[JKey("licence")]) ?? .string("unknown")
        let src = Jx.obj(["kind": .string(kind), "uri": .string(clip(uri, 2048)), "spec_digest": .string(digest), "licence": .string(clip(lic, 128)), "imported_at": now])
        var ext: [JSONValue] = []
        if let ae = JS.present(opts?[JKey("allowExtensions")]) { ext = try Jx.spreadList(ae) } else { ext = DEFAULT_EXTENSIONS.map { .string($0) } }
        return Ctx(ns: ns, kind: kind, lim: lim, source: src, ext: ext, root: source)
    }

    static func addTodo(_ c: Ctx, _ where_: String, _ code: String, _ message: String) {
        // a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
        if c.todo.count < 5000 { c.todo.append(.object(Jx.obj(["where": .string(clip(.string(where_), 200)), "code": .string(code), "message": .string(clip(.string(message), 400))]))) }
        else if c.todo.count == 5000 { c.todo.append(.object(Jx.obj(["where": .string("*"), "code": .string("todo_truncated"), "message": .string("further notes omitted")]))) }
    }

    static func finish(_ c: Ctx) -> JObject { Jx.obj(["defs": .array(c.defs), "todo": .array(c.todo), "source": .object(c.source)]) }

    // ---- text hygiene ----

    private static func ctrl(_ x: UInt32) -> Bool {
        x <= 8 || x == 0x0B || x == 0x0C || (0x0E...0x1F).contains(x) || (0x7F...0x9F).contains(x) || x == 0x2028 || x == 0x2029 || (0x202A...0x202E).contains(x) || (0x2066...0x2069).contains(x)
    }

    private static func u8cp(_ cp: UInt32) -> Int { cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4 }

    /// NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to `maxBytes` at a code point.
    public static func clip(_ o: JSONValue?, _ maxBytes: Int) -> String {
        guard case let .string(s)? = o else { return "" }
        var b = String.UnicodeScalarView()
        for u in s.unicodeScalars { b.append(ctrl(u.value) ? " " : u) }
        let n = String(b).precomposedStringWithCanonicalMapping
        var w = String.UnicodeScalarView()
        var inSp = false
        for u in n.unicodeScalars {
            if Jx.jsSpace(u) { if !inSp { w.append(" ") }; inSp = true } else { w.append(u); inSp = false }
        }
        let t = Jx.jsTrim(String(w))
        if t.utf8.count <= maxBytes { return t }
        var out = String.UnicodeScalarView()
        var used = 0
        for u in t.unicodeScalars {
            if used + u8cp(u.value) > maxBytes { break }
            used += u8cp(u.value)
            out.append(u)
        }
        return Jx.jsTrim(String(out))
    }

    /// First non-empty of the arguments, clipped.
    static func firstText(_ max: Int, _ xs: [JSONValue?]) -> String {
        for x in xs { let t = clip(x, max); if !t.isEmpty { return t } }
        return ""
    }

    // ---- tokens and verbs ----

    private static let camel1 = try! NSRegularExpression(pattern: "([a-z0-9])([A-Z])")
    private static let camel2 = try! NSRegularExpression(pattern: "([A-Z]+)([A-Z][a-z])")
    private static func sub(_ re: NSRegularExpression, _ s: String) -> String { re.stringByReplacingMatches(in: s, range: NSRange(location: 0, length: s.utf16.count), withTemplate: "$1 $2") }

    /// Lowercase word tokens of a name: camelCase, snake, kebab, dotted and slashed names alike.
    public static func tokensOf(_ name: JSONValue?) -> [String] {
        let s0 = Jx.str(name).decomposedStringWithCompatibilityMapping
        var b = String.UnicodeScalarView()
        for u in s0.unicodeScalars where u.value < 0x300 || u.value > 0x36F { b.append(u) }
        let s = sub(camel2, sub(camel1, String(b))).lowercased()
        var out: [String] = []
        var cur = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            if (u.value >= 97 && u.value <= 122) || (u.value >= 48 && u.value <= 57) { cur.append(u) }
            else if !cur.isEmpty { out.append(String(cur)); cur = String.UnicodeScalarView() }
        }
        if !cur.isEmpty { out.append(String(cur)) }
        return out
    }

    /// Words that name an action; they lead or trail a name and become the last verb segment.
    public static let ACTION_WORDS: Set<String> = [
        "get", "list", "read", "fetch", "find", "search", "query", "show", "describe", "create", "add", "new", "make", "insert", "post", "put", "set", "update", "patch", "edit", "modify",
        "delete", "remove", "destroy", "drop", "send", "notify", "publish", "invite", "cancel", "refund", "charge", "pay", "run", "exec", "execute", "invoke", "start", "stop",
        "enable", "disable", "approve", "reject", "close", "open", "merge", "export", "import", "upload", "download", "subscribe", "unsubscribe", "revoke", "grant", "transfer",
    ]

    private static func seg(_ toks: [String]) -> String {
        let s = toks.joined(separator: "_")
        if s.utf16.count <= 32 { return s }
        var h = String(Jx.b64u(Jx.sha256(Jx.utf8(s))).unicodeScalars.filter { ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || ($0.value >= 48 && $0.value <= 57) }.map { Character($0) }).lowercased()
        h = String(h.prefix(4))
        while h.count < 4 { h += "0" }
        return String(s.prefix(27)) + "_" + h
    }

    /// A verb `<ns>.<noun...>.<action>` from a raw operation name. Explicit separators (`. / :` and white space) each become a segment; a camelCase or
    /// snake name with a leading or trailing action word becomes `<noun>.<action>`; any other name is one segment.
    public static func verbOf(_ ns: String, _ raw: JSONValue?) -> String {
        let r = Array(Jx.str(raw).unicodeScalars)
        var parts: [[String]] = []
        var cur = String.UnicodeScalarView()
        for i in 0...r.count {
            if i == r.count || r[i] == "." || r[i] == "/" || r[i] == ":" || Jx.jsSpace(r[i]) {
                let t = tokensOf(.string(String(cur)))
                if !t.isEmpty { parts.append(t) }
                cur = String.UnicodeScalarView()
            } else { cur.append(r[i]) }
        }
        var segs: [String] = []
        if parts.count >= 2 { for p in parts { segs.append(seg(p)) } }
        else {
            let t = parts.isEmpty ? ["op"] : parts[0]
            if t.count >= 2 && ACTION_WORDS.contains(t[0]) { segs.append(seg(Array(t[1...]))); segs.append(seg([t[0]])) }
            else if t.count >= 2 && ACTION_WORDS.contains(t[t.count - 1]) { segs.append(seg(Array(t[..<(t.count - 1)]))); segs.append(seg([t[t.count - 1]])) }
            else { segs.append(seg(t)) }
        }
        if segs.count > 5 { segs = Array(segs[0..<2]) + Array(segs[(segs.count - 3)...]) }
        let v = ns + "." + segs.joined(separator: ".")
        if !Actions.fullMatch(VERB, v) || v.utf8.count > 128 { return "\(ns).op" }
        return v
    }

    /// The short NL-layer alias of a raw name (snake tokens), or nil when it is not a valid alias or equals the verb.
    public static func aliasOf(_ raw: JSONValue?, _ verb: String?) -> String? {
        let a = tokensOf(raw).joined(separator: "_")
        return !a.isEmpty && a.utf16.count <= 64 && Actions.fullMatch(ALIAS, a) && a != verb ? a : nil
    }

    /// "createCustomer" to "Create customer": the title when the source gave none.
    public static func humanize(_ name: JSONValue?) -> String {
        let t = tokensOf(name)
        if t.isEmpty { return "" }
        return t[0].prefix(1).uppercased() + t[0].dropFirst() + t.dropFirst().map { " " + $0 }.joined()
    }

    /// Make `verb` unique inside the import (`_2`, `_3` on the last segment), noting the collision.
    static func uniqueVerb(_ c: Ctx, _ verb: String, _ where_: String) throws -> String {
        if !c.verbSet.contains(JKey(verb)) { return verb }
        for n in 2..<100_000 {
            let sfx = "_\(n)"
            let dot = verb.lastIndex(of: ".")
            let head = dot.map { String(verb[...$0]) } ?? ""
            let last = dot.map { String(verb[verb.index(after: $0)...]) } ?? verb
            let cand = head + String(last.prefix(min(last.count, 32 - sfx.count))) + sfx
            if !c.verbSet.contains(JKey(cand)) && Actions.fullMatch(VERB, cand) {
                addTodo(c, where_, "duplicate_verb", "verb '\(verb)' is taken by an earlier operation; this one is '\(cand)'")
                return cand
            }
        }
        throw ActionKitError(code: "import_limit", message: "too many operations map to one verb")
    }

    // ---- JSON Schema: bounded resolution ----

    static func own(_ o: JSONValue?, _ k: String) -> Bool { has(o, k) }
    private static func has(_ o: JSONValue?, _ k: String) -> Bool { o?.asObject?[JKey(k)] != nil }

    /// Follow a local `#/a/b` JSON pointer in `root`; nil when absent, not local, or not an object.
    public static func pointer(_ root: JSONValue?, _ refO: JSONValue?) -> JSONValue? {
        guard case let .string(ref)? = refO, ref.hasPrefix("#/") else { return nil }
        var cur: JSONValue? = root
        let rest = String(ref.dropFirst(2))
        for raw in rest.components(separatedBy: "/") {
            let s = raw.replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
            let seg = Jx.decodeUriComponent(s) ?? s
            if case let .object(o)? = cur {
                guard let x = o[JKey(seg)] else { return nil }
                cur = x
            } else if case let .array(a)? = cur {
                // an array's own "length" is a number: no object results either way
                guard Actions.fullMatch("0|[1-9][0-9]{0,9}", seg), let i = Int(seg), i < a.count else { return nil }
                cur = a[i]
            } else { return nil }
        }
        if case .object? = cur { return cur }
        if case .array? = cur { return cur }
        return nil
    }

    private static func mergeAll(_ a: JObject, _ m: JObject) throws -> JObject {
        var out = a
        for k in JS.keyOrder(m) { out[o: k.s] = m[k] } // a spread: new members in the source's order, an existing one keeps its place
        var props: JObject = [:]
        Jx.spread(&props, a[JKey("properties")])
        Jx.spread(&props, m[JKey("properties")])
        var req: [JSONValue] = []
        if let r = JS.present(a[JKey("required")]) { req += try Jx.spreadList(r) }
        if let r = JS.present(m[JKey("required")]) { req += try Jx.spreadList(r) }
        out[o: "properties"] = .object(props)
        out[o: "required"] = .array(req)
        return out
    }

    private static func without(_ m: JObject, _ ks: [String]) -> JObject { var o = m; for k in ks { o[JKey(k)] = nil }; return o }

    private static func isNullType(_ t: JSONValue?) -> Bool {
        if t == .string("null") { return true }
        if case let .array(a)? = t, !a.isEmpty { return a.allSatisfy { $0 == .string("null") } }
        return false
    }

    static func resolveSchema(_ s: JSONValue?, _ c: Ctx, _ bud: Budget, _ where_: String, _ chain: [String] = [], _ depth: Int = 0) throws -> JObject {
        guard case let .object(s0)? = s else { return [:] }
        if bud.left <= 0 {
            if !bud.exhausted {
                bud.exhausted = true
                addTodo(c, where_, "ref_budget", "schema expansion stopped after \(c.lim.maxRefNodes) nodes (declared string; refine or drop)")
            }
            return [:]
        }
        bud.left -= 1
        if depth > Int(c.lim.maxRefDepth) {
            addTodo(c, where_, "ref_depth", "schema nesting or reference chain deeper than \(c.lim.maxRefDepth) (declared string; refine or drop)")
            return [:]
        }
        var cur = s0
        if case let .string(ref)? = cur[JKey("$ref")] {
            if chain.contains(ref) {
                addTodo(c, where_, "cyclic_ref", "reference '\(clip(.string(ref), 120))' is cyclic (declared string; refine or drop)")
                return [:]
            }
            guard let target = pointer(c.root, .string(ref)) else {
                addTodo(c, where_, "unresolved_ref", "reference '\(clip(.string(ref), 120))' is not a local reference that resolves (declared string; refine or drop)")
                return [:]
            }
            var merged = try resolveSchema(target, c, bud, where_, chain + [ref], depth + 1)
            for (k, v) in without(cur, ["$ref"]) { merged[k] = v }
            cur = merged
        }
        if case let .array(allOf)? = cur[JKey("allOf")] {
            let rest = without(cur, ["allOf"])
            var acc: JObject = [:]
            for m in try allOf.map({ try resolveSchema($0, c, bud, where_, chain, depth + 1) }) { acc = try mergeAll(acc, m) }
            for k in JS.keyOrder(rest) { acc[o: k.s] = rest[k] }
            cur = acc
        }
        var alts: [JSONValue]? = nil
        if case let .array(a)? = cur[JKey("anyOf")] { alts = a } else if case let .array(a)? = cur[JKey("oneOf")] { alts = a }
        if let alts = alts {
            let rest = without(cur, ["anyOf", "oneOf"])
            let all = try alts.map { try resolveSchema($0, c, bud, where_, chain, depth + 1) }
            let live = all.filter { !isNullType($0[JKey("type")]) }
            if live.count == 1 { var out = live[0]; for k in JS.keyOrder(rest) { out[o: k.s] = rest[k] }; return out }
            var consts: [[JSONValue]?] = []
            var allConst = true
            for m in live {
                var k: [JSONValue]? = nil
                if case .string? = m[JKey("const")] { k = [m[JKey("const")]!] }
                else if case let .array(ev)? = m[JKey("enum")], ev.allSatisfy({ $0.asString != nil }) { k = ev }
                if k == nil { allConst = false }
                consts.append(k)
            }
            if live.count > 1 && allConst {
                var out = rest
                out[o: "type"] = .string("string")
                var u: [JSONValue] = []
                for k in consts { for x in k! where !u.contains(x) { u.append(x) } }
                out[o: "enum"] = .array(u)
                return out
            }
            addTodo(c, where_, "union", "a union of \(live.count) schemas has no representation (declared string; refine or drop)")
            return rest
        }
        if case .string? = cur[JKey("const")], cur[JKey("enum")] == nil { cur[o: "enum"] = .array([cur[JKey("const")]!]) }
        return cur
    }

    // ---- JSON Schema to params ----

    /// Param name segment hygiene: `[A-Za-z0-9_]{1,64}`; anything else is replaced by `_`.
    public static func paramSeg(_ raw: String) -> String {
        var b = [UInt16]()
        var allUs = true
        for u in raw.utf16 {
            let ok = (u >= 65 && u <= 90) || (u >= 97 && u <= 122) || (u >= 48 && u <= 57) || u == 95
            b.append(ok ? u : 95)
            if u != 95 && ok { allUs = false }
        }
        var s = allUs ? [] : b
        if s.count > 64 { s = Array(s[0..<64]) }
        return s.isEmpty ? "p" : String(decoding: s, as: UTF16.self)
    }

    private static let FORMATS = ["email": "email", "uuid": "uuid", "uri": "url", "url": "url", "idn-email": "email", "semver": "semver"]
    private static let RESERVED: Set<String> = ["__proto__", "constructor", "prototype"]
    private static let INT_ROLES: Set<String> = ["money.amount", "money.fee", "count.limit", "bytes.size"]

    private static func isRoleOk(_ r: String) -> Bool { CORE_ROLES.contains(r) || Actions.fullMatch(ID_ROLE, r) || Actions.fullMatch(X_ROLE, r) }

    private static func plainStr(_ x: JSONValue) -> Bool {
        guard case let .string(s) = x, !s.isEmpty, s.utf8.count <= 256 else { return false }
        return s == s.precomposedStringWithCanonicalMapping
    }

    private static func enumStrOf(_ en: JSONValue?) -> [JSONValue]? {
        guard case let .array(l)? = en, !l.isEmpty, l.count <= 256, l.allSatisfy(plainStr) else { return nil }
        var out: [JSONValue] = []
        for x in l where !out.contains(x) { out.append(x) }
        return out
    }

    private static func firstNonNull(_ t: JSONValue?) -> JSONValue? {
        if case let .array(a)? = t { return a.first { $0 != .string("null") } }
        return t
    }

    /// A leaf schema to a param def. Unrepresentable shapes become `string` placeholders, noted.
    static func leafParam(_ s: JObject, _ required: Bool, _ c: Ctx, _ bud: Budget, _ where_: String) throws -> JObject {
        let t0 = JS.present(firstNonNull(s[JKey("type")]))
        let enumStr = enumStrOf(s[JKey("enum")])
        var t: JSONValue? = t0
        if t == nil { if enumStr != nil { t = .string("string") } else if Jx.isList(s[JKey("items")]) || Jx.isObj(s[JKey("items")]) { t = .string("array") } }
        var base: JObject = [:]
        base[o: "type"] = .string("string")   // positioned like every later member, so `type` stays first
        if !required { base[o: "required"] = .bool(false) }
        let desc = clip(s[JKey("description")], 280)
        if !desc.isEmpty { base[o: "description"] = .string(desc) }
        let roleExt: String? = c.ext.contains(.string("x-pca-role")) ? s[JKey("x-pca-role")]?.asString : nil
        func withRole(_ p: JObject) -> JObject {
            guard let r = roleExt else { return p }
            if !isRoleOk(r) || (INT_ROLES.contains(r) && p[JKey("type")] != .string("integer")) {
                addTodo(c, where_, "role_ignored", "x-pca-role '\(clip(.string(r), 64))' is not valid for a \(Jx.str(p[JKey("type")])) parameter")
                return p
            }
            var q = p
            q[o: "role"] = .string(r)
            return q
        }
        let fmt = s[JKey("format")]
        if t == .string("integer") || (t == .string("number") && (fmt == .string("int32") || fmt == .string("int64"))) {
            var p = base
            p[o: "type"] = .string("integer")
            let mn = s[JKey("minimum")], mx = s[JKey("maximum")], exMin = s[JKey("exclusiveMinimum")], exMax = s[JKey("exclusiveMaximum")]
            if Jx.isInt(mn) && exMin != .bool(true) { p[o: "min"] = mn }
            else if Jx.isInt(exMin) { p[o: "min"] = Jx.num(Jx.num(exMin)! + 1) }
            else if Jx.isInt(mn) && exMin == .bool(true) { p[o: "min"] = Jx.num(Jx.num(mn)! + 1) }
            if Jx.isInt(mx) && exMax != .bool(true) { p[o: "max"] = mx }
            else if Jx.isInt(exMax) { p[o: "max"] = Jx.num(Jx.num(exMax)! - 1) }
            else if Jx.isInt(mx) && exMax == .bool(true) { p[o: "max"] = Jx.num(Jx.num(mx)! - 1) }
            if let a = p[JKey("min")], let b = p[JKey("max")], Jx.num(a)! > Jx.num(b)! { p[o: "min"] = nil; p[o: "max"] = nil }
            return withRole(p)
        }
        if t == .string("boolean") { var p = base; p[o: "type"] = .string("boolean"); return withRole(p) }
        if t == .string("string") {
            let f = fmt?.asString ?? ""
            var p = base
            if f == "date" { p[o: "type"] = .string("date"); return withRole(p) }
            if f == "date-time" { p[o: "type"] = .string("datetime"); return withRole(p) }
            if let e = enumStr { p[o: "values"] = .array(e) }
            else if case let .array(ea)? = s[JKey("enum")], !ea.isEmpty { addTodo(c, where_, "enum_dropped", "enum values are not 1..256 plain strings (declared as a free string; refine)") }
            if let ff = FORMATS[f] { p[o: "format"] = .string(ff) }
            let ml = s[JKey("maxLength")]
            if Jx.isInt(ml), let d = Jx.num(ml), d > 0, d <= 16_777_216 { p[o: "max_len"] = ml }
            return withRole(p)
        }
        if t == .string("array") {
            let it = try resolveSchema(s[JKey("items")], c, bud, where_ + "[]")
            let itEnum = enumStrOf(it[JKey("enum")])
            var lim: JObject = [:]
            let mi = s[JKey("maxItems")], ni = s[JKey("minItems")]
            if Jx.isInt(mi), Jx.num(mi)! >= 0 { lim[o: "max_items"] = mi }
            if Jx.isInt(ni), Jx.num(ni)! >= 0 { lim[o: "min_items"] = ni }
            if let a = lim[JKey("min_items")], let b = lim[JKey("max_items")], Jx.num(a)! > Jx.num(b)! { lim[o: "min_items"] = nil; lim[o: "max_items"] = nil }
            if s[JKey("uniqueItems")] == .bool(true), let ie = itEnum {
                var p = base
                p[o: "type"] = .string("set")
                p[o: "values"] = .array(ie)
                for k in JS.keyOrder(lim) { p[o: k.s] = lim[k] } // a spread: the members in their own insertion order, positioned after the ones already set
                return withRole(p)
            }
            let itT = JS.present(firstNonNull(it[JKey("type")]))
            let items: String? = itT == .string("integer") ? "integer" : itT == .string("string") ? "string" : itT == .string("boolean") ? "boolean" : nil
            if items == nil, let x = itT { addTodo(c, where_, "array_items", "array items of type '\(clip(.string(Jx.str(x)), 40))' are not declared (items left open)") }
            var p = base
            p[o: "type"] = .string("array")
            if let i = items { p[o: "items"] = .string(i) }
            for k in JS.keyOrder(lim) { p[o: k.s] = lim[k] } // a spread: the members in their own insertion order, positioned after the ones already set
            return withRole(p)
        }
        if t == .string("number") { addTodo(c, where_, "unsupported_type", "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)") }
        else { addTodo(c, where_, "unsupported_type", "type '\(clip(.string(t == nil ? "none" : Jx.str(t)), 40))' has no representation (declared string; refine or drop)") }
        var p = base
        p[o: "type"] = .string("string")
        return withRole(p)
    }

    /// Assign a schema property the way `obj[name] = v` does: the engine's `__proto__` setter keeps no member.
    static func putProp(_ m: inout JObject, _ name: String, _ v: JSONValue) { if name != "__proto__" { m[o: name] = v } }

    /// Flatten an object schema into params: nested objects become dotted names up to three segments; an object below that (or without properties) is a
    /// `string` placeholder; a child of an optional parent is optional. At most 64 params; the rest are dropped, noted.
    static func flattenObject(_ schema: JObject, _ c: Ctx, _ bud: Budget, _ where_: String, _ out: inout JObject, _ prefix: [String] = [], _ parentRequired: Bool = true) throws {
        let props: JObject = schema[JKey("properties")]?.asObject ?? [:]
        var req = Set<JKey>()
        for x in Jx.a(schema[JKey("required")]) { if let s = x.asString { req.insert(JKey(s)) } }
        let names = props.keys.map { $0.s }.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        for name in names {
            if RESERVED.contains(name) { addTodo(c, "\(where_): \(name)", "skipped_param", "parameter name '\(name)' is reserved; dropped"); continue }
            let child = try resolveSchema(props[JKey(name)], c, bud, "\(where_): \(name)")
            if child[JKey("readOnly")] == .bool(true) { continue }
            let sname = paramSeg(name)
            if sname != name { addTodo(c, "\(where_): \(name)", "renamed_param", "parameter '\(clip(.string(name), 80))' is declared as '\(sname)'") }
            let path = prefix + [sname]
            let full = path.joined(separator: ".")
            let required = parentRequired && req.contains(JKey(name))
            let childProps = child[JKey("properties")]?.asObject
            let isObject = child[JKey("type")] == .string("object") || (child[JKey("type")] == nil && childProps != nil)
            if isObject, let cp = childProps, !cp.isEmpty, path.count < MAX_PARAM_PATH_DEPTH {
                try flattenObject(child, c, bud, "\(where_): \(full)", &out, path, required)
                continue
            }
            if out.count >= MAX_DEF_PARAMS { addTodo(c, where_, "too_many_params", "more than \(MAX_DEF_PARAMS) parameters; '\(full)' and the rest are dropped"); return }
            var clash = out[JKey(full)] != nil
            if !clash { for k in JS.keyOrder(out) where k.s.hasPrefix(full + ".") || full.hasPrefix(k.s + ".") { clash = true; break } }
            if clash { addTodo(c, "\(where_): \(full)", "skipped_param", "parameter '\(full)' collides with another; kept the first"); continue }
            out[o: full] = .object(try isObject ? placeholderObject(child, required, c, "\(where_): \(full)") : leafParam(child, required, c, bud, "\(where_): \(full)"))
        }
    }

    private static func placeholderObject(_ s: JObject, _ required: Bool, _ c: Ctx, _ where_: String) -> JObject {
        addTodo(c, where_, "object_leaf", "an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)")
        var p: JObject = [:]
        p[o: "type"] = .string("string")
        if !required { p[o: "required"] = .bool(false) }
        let d = clip(s[JKey("description")], 280)
        if !d.isEmpty { p[o: "description"] = .string(d) }
        return p
    }

    // ---- assembling a draft def ----

    /// A draft operation: what the importer knows before the def is assembled.
    public struct Draft {
        /// Raw operation name (operationId, tool name, field, rpc, ...).
        public var name: JSONValue?
        public var verb: String?
        public var title: JSONValue?
        public var description: JSONValue?
        public var effects: [String]?
        public var scope: String?
        public var params: JObject?
        public var idempotency: JObject?
        public var traits: [String]?
        public var noAlias = false
        public var bindings: JObject?
        public init() {}
    }

    /// Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted). Returns the def or nil.
    @discardableResult
    static func emitDef(_ c: Ctx, _ d: Draft) throws -> JObject? {
        if Int64(c.defs.count) >= c.lim.maxOps { throw ActionKitError(code: "import_limit", message: "more than \(c.lim.maxOps) operations") }
        let rawVerb = d.verb ?? verbOf(c.ns, d.name)
        let verb = try uniqueVerb(c, Actions.fullMatch(VERB, rawVerb) ? rawVerb : verbOf(c.ns, d.name), Jx.str(d.name))
        let segs = verb.components(separatedBy: ".")
        let rtype = segs.count > 2 ? segs[0..<(segs.count - 1)].joined(separator: ".") : segs[0]
        let title = firstText(MAX_TITLE_BYTES, [d.title, .string(humanize(d.name)), .string(verb)])
        let description = clip(d.description, min(MAX_DESCRIPTION_BYTES, 600))
        let alias = d.noAlias ? nil : aliasOf(d.name, verb)
        var def: JObject = [:]
        def[o: "v"] = .int(1); def[o: "kind"] = .string("pca-action-def"); def[o: "verb"] = .string(verb)
        if let a = alias, !c.aliases.contains(JKey(a)), !c.verbSet.contains(JKey(a)) { def[o: "aliases"] = .array([.string(a)]) }
        def[o: "title"] = .string(title.isEmpty ? verb : title)
        if !description.isEmpty { def[o: "description"] = .string(description) }
        def[o: "effects"] = Jx.strs(Jx.sortUniq(d.effects ?? []))
        def[o: "resource"] = .object(Jx.obj(["type": .string(Actions.fullMatch(RTYPE, rtype) ? rtype : segs[0]),
                                                 "id": .object(Jx.obj(["prefix": .string(""), "class": .string("any_safe"), "len": .array([.int(1), .int(128)])])),
                                                 "scope": d.scope.map { .string($0) } ?? .null]))
        def[o: "params"] = .object(d.params ?? [:])
        if let i = d.idempotency { def[o: "idempotency"] = .object(i) }
        if let t = d.traits, !t.isEmpty { def[o: "traits"] = Jx.strs(Jx.sortUniq(t)) }
        if let b = d.bindings { def[o: "bindings"] = .object(b) }
        def[o: "review"] = .object(Jx.obj(["state": .string("unreviewed")]))
        def[o: "source"] = .object(Jx.obj(["kind": c.source[JKey("kind")] ?? .null, "uri": c.source[JKey("uri")] ?? .null, "spec_digest": c.source[JKey("spec_digest")] ?? .null,
                                              "licence": c.source[JKey("licence")] ?? .null, "imported_at": c.source[JKey("imported_at")] ?? .null]))
        if let bad = Actions.validateDef(.object(def)) {
            addTodo(c, Jx.str(d.name), "invalid_def", "not emitted: \(bad)")
            return nil
        }
        c.verbs.append(verb)
        c.verbSet.insert(JKey(verb))
        if case let .array(al)? = def[JKey("aliases")], let a = al.first?.asString { c.aliases.insert(JKey(a)) }
        c.defs.append(.object(def))
        return def
    }

    /// Add a declared trait to a draft (used for hint-derived traits such as network egress).
    static func withTrait(_ traits: [String]?, _ t: String) -> [String] {
        var s = traits ?? []
        if !s.contains(t) { s.append(t) }
        return s
    }
}
