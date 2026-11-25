import Foundation

/// The action-schema vocabulary and the drafting importers: the exported constants, the schema verb lookup, the wallet-floor test, the MCP hint mapping and
/// the importers that turn an MCP tool list or an OpenAPI document into an unsigned draft schema with a todo list (JSON-schema flattening with `$ref`,
/// `allOf`, `anyOf` and `oneOf`, bounded in depth and in nodes). Documents are the language-neutral JSON of the wire; the importers are pure.
public enum PCAActionSchema {
    public static let ACTION_SCHEMA_DOMAIN = ActionSchema.DOMAIN
    public static let ACTION_SCHEMA_REF_DOMAIN = ActionSchema.REF_DOMAIN
    public static let ACTION_SCHEMA_KIND = ActionSchema.KIND
    public static let WELL_KNOWN_PCA_ACTIONS_PATH = "/.well-known/pca-actions.json"
    public static let SENSITIVITIES = ActionSchema.SENSITIVITIES
    public static let SCHEMA_REVERSIBILITY = ActionSchema.REVERSIBILITY
    public static let PARAM_TYPES = ActionSchema.PARAM_TYPES
    public static let PARAM_TYPES_V2 = ActionSchema.PARAM_TYPES_V2
    public static let SCHEMA_V2_EFFECTS = ActionSchema.V2_EFFECTS
    public static let SCHEMA_V2_CAVEATS = ActionSchema.V2_CAVEATS
    public static let SCHEMA_V2_PRULES = ActionSchema.V2_PRULES
    public static let SCHEMA_V2_CONTEXT = ActionSchema.V2_CONTEXT
    public static let SCHEMA_V2_TAGS = ActionSchema.V2_TAGS
    public static let SCHEMA_V2_PROVENANCE = ActionSchema.V2_PROVENANCE
    public static let MAX_SCHEMA_VERBS = ActionSchema.MAX_VERBS
    public static let MAX_SCHEMA_PARAMS = ActionSchema.MAX_PARAMS
    public static let MAX_SCHEMA_VALUES = ActionSchema.MAX_VALUES
    public static let DEFAULT_MAX_LEN = ActionSchema.DEFAULT_MAX_LEN
    public static let DEFAULT_MAX_ITEMS = ActionSchema.DEFAULT_MAX_ITEMS
    public static let WALLET_FLOOR_PREFIXES = PCAIntentSchema.WALLET_FLOOR_PREFIXES
    public static let WALLET_FLOOR_EXACT = PCAIntentSchema.WALLET_FLOOR_EXACT
    /// The source text of the parameter-path patterns (a parameter path is `action.params.<name>`; v2 allows two nested segments).
    public static let PARAM_PATH_RE = "^action\\.params\\.[A-Za-z0-9_]{1,64}$"
    public static let PARAM_PATH_RE_V2 = "^action\\.params\\.[A-Za-z0-9_]{1,64}(?:\\.[A-Za-z0-9_]{1,64}){0,2}$"
    public static let UNIT_ID_RE = "^[a-z0-9_]+(?:\\.[a-z0-9_]+)*$"

    /// The first verb declaration of `doc` named `verb` (an own member lookup: `__proto__` and `constructor` never match), or nil.
    public static func schemaVerb(_ doc: JSONValue, _ verb: String) -> JSONValue? { ActionSchema.verb(doc, verb).map { .object($0) } }

    /// Whether the wallet floor covers a semantic type: an exact member or a prefix match (`floor` is `{prefixes?, exact?}`; absent members take the defaults).
    public static func floorApplies(_ semantic: String, _ floor: JSONValue?) -> Bool {
        func list(_ k: String, _ d: [String]) -> [String] { floor?.get(k)?.asArray.map { $0.compactMap { $0.asString } } ?? d }
        if list("exact", PCAIntentSchema.WALLET_FLOOR_EXACT).contains(where: { IV.same($0, semantic) }) { return true }
        return list("prefixes", PCAIntentSchema.WALLET_FLOOR_PREFIXES).contains { IV.startsWith(semantic, $0) }
    }

    /// The reversibility an MCP tool's annotations imply: read-only is a reversible read, destructive a write at least rate-limited, anything else a write.
    public static func reversibilityFromMcpHints(_ a: JSONValue?) -> (kind: String, atLeast: String) {
        if a?.get("readOnlyHint") == .bool(true) { return ("read", "reversible") }
        if a?.get("destructiveHint") == .bool(true) { return ("write", "rate_limited") }
        return ("write", "reversible")
    }

    // MARK: JSON-schema flattening

    private static let MAX_REF_DEPTH = 8
    private static let MAX_REF_NODES = 20_000

    private final class Ctx {
        let root: JSONValue?
        var todo: [String]
        var left: Int?
        init(root: JSONValue?, todo: [String]) { self.root = root; self.todo = todo }
    }

    private static func slice1024(_ s: String) -> String {
        let u = Array(s.utf16)
        return u.count <= 1024 ? s : String(decoding: u[0..<1024], as: UTF16.self)
    }

    /// `ref` as a JSON pointer into `root` (local `#/` references only); an object or array target, else nil.
    private static func pointer(_ root: JSONValue?, _ ref: String) -> JSONValue? {
        guard ref.unicodeScalars.starts(with: "#/".unicodeScalars) else { return nil }
        var cur = root
        for raw in ref.dropFirst(2).split(separator: "/", omittingEmptySubsequences: false) {
            let seg = String(raw).replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
            switch cur {
            case let .object(o)?: cur = o[JKey(seg)]
            case let .array(a)?: cur = JS.indexKey(seg).flatMap { Int($0) < a.count ? a[Int($0)] : nil }
            default: return nil
            }
            if cur == nil { return nil }
        }
        switch cur { case .object?, .array?: return cur; default: return nil }
    }

    private static func isNullType(_ m: JObject) -> Bool {
        switch m["type"] {
        case .string("null")?: return true
        case let .array(a)?: return a.allSatisfy { $0 == .string("null") }
        default: return false
        }
    }

    private static func stringEnum(_ v: JSONValue?) -> [String]? {
        guard case let .array(a)? = v, a.allSatisfy({ $0.asString != nil }) else { return nil }
        return a.compactMap { $0.asString }
    }

    private static func merged(_ a: JObject, _ b: JObject) -> JObject { var o = a; for (k, v) in b { o[k] = v }; return o }

    private static func flatten(_ s: JSONValue?, _ c: Ctx, _ whereAt: String, _ depth: Int = 0) -> JObject {
        guard case let .object(s0)? = s else { return [:] }
        c.left = (c.left ?? MAX_REF_NODES) - 1
        if c.left! < 0 {
            if c.left! == -1 { c.todo.append("\(whereAt): schema expansion stopped after \(MAX_REF_NODES) nodes (declared string; refine or drop)") }
            return [:]
        }
        if depth > MAX_REF_DEPTH {
            c.todo.append("\(whereAt): schema nesting or reference chain deeper than \(MAX_REF_DEPTH) (declared string; refine or drop)")
            return [:]
        }
        var cur = s0
        if case let .string(ref)? = s0["$ref"] {
            guard let target = pointer(c.root, ref) else {
                c.todo.append("\(whereAt): reference '\(String(decoding: Array(ref.utf16.prefix(120)), as: UTF16.self))' is not a local reference that resolves (declared string; refine or drop)")
                return [:]
            }
            var siblings = s0
            siblings["$ref"] = nil
            cur = merged(flatten(target, c, whereAt, depth + 1), siblings)
        }
        if case let .array(all)? = cur["allOf"] {
            var rest = cur
            rest["allOf"] = nil
            var acc = JObject()
            for m in all.map({ flatten($0, c, whereAt, depth + 1) }) {
                var next = merged(acc, m)
                next["properties"] = .object(merged(acc["properties"]?.asObject ?? [:], m["properties"]?.asObject ?? [:]))
                next["required"] = .array((acc["required"]?.asArray ?? []) + (m["required"]?.asArray ?? []))
                acc = next
            }
            cur = merged(acc, rest)
        }
        let altsV = JS.present(cur["anyOf"]) ?? cur["oneOf"]
        if case let .array(alts)? = altsV {
            var rest = cur
            rest["anyOf"] = nil
            rest["oneOf"] = nil
            let live = alts.map { flatten($0, c, whereAt, depth + 1) }.filter { !isNullType($0) }
            if live.count == 1 { return merged(live[0], rest) }
            let consts: [[String]?] = live.map { m in
                if case let .string(k)? = m["const"] { return [k] }
                return stringEnum(m["enum"])
            }
            if live.count > 1, consts.allSatisfy({ $0 != nil }) {
                var seen = Set<JKey>(), values: [JSONValue] = []
                for x in consts.flatMap({ $0 ?? [] }) where seen.insert(JKey(x)).inserted { values.append(.string(x)) }
                var o = rest
                o["type"] = .string("string")
                o["enum"] = .array(values)
                return o
            }
            c.todo.append("\(whereAt): a union of \(live.count) schemas has no schema representation (declared string; refine or drop)")
            return rest
        }
        if let k = cur["const"], k.asString != nil, cur["enum"] == nil { cur["enum"] = .array([k]) }
        return cur
    }

    private static func safeInt(_ v: JSONValue?) -> Int64? { v?.safeInt }

    private static func declOfJsonSchema(_ name: String, _ schema: JSONValue?, _ required: Bool, _ c: Ctx) -> JSONValue {
        let s = flatten(schema, c, "action.params.\(name)")
        var t: JSONValue?
        if case let .array(a)? = s["type"] { t = a.first { $0 != .string("null") } } else { t = s["type"] }
        var base: JObject = ["semantic": JS.present(s["x-pca-semantic"]) ?? .string("unknown"), "sensitivity": JS.present(s["x-pca-sensitivity"]) ?? .string("material")]
        if !required { base["required"] = .bool(false) }
        if JS.truthy(s["description"]), let d = s["description"]?.asString { base["description"] = .string(slice1024(d)) }
        if !JS.truthy(s["x-pca-semantic"]) { c.todo.append("action.params.\(name): semantic type") }
        let enumStrings = stringEnum(s["enum"])
        func with(_ extra: JObject) -> JSONValue { .object(merged(base, extra)) }
        switch t?.asString {
        case "integer"?:
            var o: JObject = ["type": .string("integer")]
            if let m = safeInt(s["minimum"]) { o["min"] = .int(m) } else if let m = safeInt(s["exclusiveMinimum"]) { o["min"] = .int(m + 1) }
            if let m = safeInt(s["maximum"]) { o["max"] = .int(m) } else if let m = safeInt(s["exclusiveMaximum"]) { o["max"] = .int(m - 1) }
            if JS.truthy(s["x-pca-unit"]), let u = s["x-pca-unit"] { o["unit"] = u }
            if JS.truthy(s["x-pca-accumulates-into"]), let a = s["x-pca-accumulates-into"] { o["accumulates_into"] = a }
            return with(o)
        case "boolean"?: return with(["type": .string("boolean")])
        case "string"? where s["format"] == .string("date"): return with(["type": .string("date")])
        case "string"?:
            var o: JObject = ["type": .string("string")]
            if let e = enumStrings { o["values"] = .array(e.map { .string($0) }) }
            if let m = safeInt(s["maxLength"]), m > 0 { o["max_len"] = .int(m) }
            return with(o)
        case "array"?:
            let it = flatten(s["items"], c, "action.params.\(name)[]")
            let itEnum = stringEnum(it["enum"])
            if JS.truthy(s["uniqueItems"]), let e = itEnum {
                var o: JObject = ["type": .string("set"), "values": .array(e.map { .string($0) })]
                if let m = safeInt(s["minItems"]) { o["min_items"] = .int(m) }
                if let m = safeInt(s["maxItems"]) { o["max_items"] = .int(m) }
                return with(o)
            }
            var itT: JSONValue? = it["type"]
            if case let .array(a)? = it["type"] { itT = a.first }
            var o: JObject = ["type": .string("array")]
            if itT == .string("integer") { o["items"] = .string("integer") }
            if let m = safeInt(s["maxItems"]) { o["max_items"] = .int(m) }
            if let m = safeInt(s["minItems"]) { o["min_items"] = .int(m) }
            return with(o)
        default:
            c.todo.append("action.params.\(name): type '\(JS.toString(t))' has no schema representation (declared string; refine or drop)")
            return with(["type": .string("string")])
        }
    }

    private static func schemaName(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        return (1...64).contains(u.count) && u.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0.value == 95 }
    }

    private static func utf8Sorted(_ xs: [String]) -> [String] { xs.sorted { Canonical.compareUtf8($0, $1) < 0 } }

    private static func sortedVerbs(_ verbs: [JSONValue]) -> [JSONValue] { verbs.sorted { Canonical.compareUtf8($0.get("verb")?.asString ?? "", $1.get("verb")?.asString ?? "") < 0 } }

    private static func draft(_ site: JSONValue, _ verbs: [JSONValue], _ todo: [String]) -> JSONValue {
        .object(["schema": .object(["v": .int(1), "kind": .string(ACTION_SCHEMA_KIND), "site": site.get("site") ?? .null, "aud": site.get("aud") ?? .null, "version": site.get("version") ?? .null,
                                    "verbs": .array(sortedVerbs(verbs))]), "todo": .array(todo.map { .string($0) })])
    }

    /// An unsigned draft `{schema, todo}` from an MCP tool list: one verb per tool (named `site.verbPrefix` + the tool name), one parameter per input
    /// property, writes drafted `irreversible` unless the hints say read-only. Every guess the importer made is a todo line.
    public static func draftSchemaFromMcpTools(_ tools: JSONValue, _ site: JSONValue) throws -> JSONValue {
        guard case let .array(list) = tools else { throw JSError("tools is not iterable") }
        var todo: [String] = []
        var verbs: [JSONValue] = []
        for t in list {
            guard t.isObject else { throw JSError("Cannot read properties of \(t.isNull ? "null" : "undefined")") }
            let name = JS.toString(t.get("name"))
            let c = Ctx(root: t.get("inputSchema"), todo: todo)
            let input = flatten(t.get("inputSchema"), c, "\(name): inputSchema")
            let props = input["properties"]?.asObject ?? [:]
            let req = Set((input["required"]?.asArray ?? []).compactMap { $0.asString }.map { Array($0.utf16) })
            var params = JObject()
            for pname in utf8Sorted(props.keys.map { $0.s }) {
                if !schemaName(pname) { c.todo.append("\(name): parameter '\(pname)' is not a schema name ([A-Za-z0-9_]{1,64}); rename it"); continue }
                params[JKey("action.params." + pname)] = declOfJsonSchema(pname, props[JKey(pname)], req.contains(Array(pname.utf16)), c)
            }
            let h = reversibilityFromMcpHints(t.get("annotations"))
            let verb = (site.get("verbPrefix")?.asString ?? "") + name
            if h.kind == "write" { c.todo.append("\(verb): reversibility (drafted irreversible)") }
            var v: JObject = ["verb": .string(verb), "kind": .string(h.kind), "params": .object(params), "reversibility": .string(h.kind == "read" ? "reversible" : "irreversible"),
                              "mcp": .object(["tool": t.get("name") ?? .null])]
            if JS.truthy(t.get("description")), let d = t.get("description")?.asString { v["description"] = .string(slice1024(d)) }
            verbs.append(.object(v))
            todo = c.todo
        }
        return draft(site, verbs, todo)
    }

    private static func jsonBodySchema(_ b: JSONValue?) -> JSONValue? {
        guard case let .object(content)? = b?.get("content") else { return nil }
        let keys = utf8Sorted(content.keys.map { $0.s })
        func plusJson(_ k: String) -> Bool {
            let l = k.lowercased()
            guard l.hasPrefix("application/") else { return false }
            let rest = l.dropFirst("application/".count)
            let head = rest.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            return head.hasSuffix("+json")
        }
        guard let key = keys.first(where: { $0.lowercased() == "application/json" }) ?? keys.first(where: plusJson) else { return nil }
        return content[JKey(key)]?.get("schema")
    }

    /// An unsigned draft `{schema, todo}` from an OpenAPI document: one verb per operation with an operationId (`x-pca-verb` renames it, `x-pca-kind` and
    /// `x-pca-reversibility` override the guess), parameters from the JSON request body, the path and the query. Everything else is a todo line.
    public static func draftSchemaFromOpenApi(_ doc: JSONValue, _ site: JSONValue) throws -> JSONValue {
        var todo: [String] = []
        var verbs: [JSONValue] = []
        let c = Ctx(root: doc, todo: [])
        func deref(_ x: JSONValue?) -> JSONValue? {
            guard let x = x, x.isObject else { return nil }
            guard case let .string(ref)? = x.get("$ref") else { return x }
            let t = pointer(doc, ref)
            if t == nil { c.todo.append("reference '\(String(decoding: Array(ref.utf16.prefix(120)), as: UTF16.self))' is not a local reference that resolves") }
            return t
        }
        var seen = Set<[UInt16]>()
        let paths = doc.get("paths")?.asObject ?? [:]
        for path in utf8Sorted(paths.keys.map { $0.s }) {
            guard let ops = paths[JKey(path)]?.asObject else { throw JSError("Cannot read properties of null (reading 'parameters')") }
            let shared = ops["parameters"]?.asArray ?? []
            for method in utf8Sorted(ops.keys.map { $0.s }) {
                guard let op = ops[JKey(method)], op.isObject, JS.truthy(op.get("operationId")) else { continue }
                let opId = JS.toString(op.get("operationId"))
                c.left = MAX_REF_NODES
                let kindOverride = op.get("x-pca-kind")
                let read = JS.truthy(kindOverride) ? kindOverride == .string("read") : (method.lowercased() == "get" || method.lowercased() == "head")
                let verb = JS.present(op.get("x-pca-verb")) ?? op.get("operationId") ?? .null
                let verbText = JS.toString(verb)
                if !seen.insert(Array(verbText.utf16)).inserted { c.todo.append("\(verbText): declared by more than one operation; give each a distinct x-pca-verb") }
                var params = JObject()
                func addName(_ name: String, _ sch: JSONValue, _ required: Bool, _ source: String) {
                    if !schemaName(name) { c.todo.append("\(opId): parameter '\(name)' is not a schema name; rename it"); return }
                    let key = JKey("action.params." + name)
                    if params[key] != nil { c.todo.append("\(opId): '\(name)' is declared by both the \(source) and another source; kept the first"); return }
                    params[key] = declOfJsonSchema(name, sch, required, c)
                }
                let body = flatten(jsonBodySchema(deref(op.get("requestBody"))), c, "\(opId): request body")
                let bprops = body["properties"]?.asObject ?? [:]
                let breq = Set((body["required"]?.asArray ?? []).compactMap { $0.asString }.map { Array($0.utf16) })
                for name in utf8Sorted(bprops.keys.map { $0.s }) { addName(name, bprops[JKey(name)] ?? .null, breq.contains(Array(name.utf16)), "request body") }
                var mergedParams: [String: JSONValue] = [:]
                for raw in shared + (op.get("parameters")?.asArray ?? []) {
                    guard let q = deref(raw), let qn = q.get("name")?.asString, let qi = q.get("in")?.asString else { continue }
                    mergedParams[qi + ":" + qn] = q
                }
                for key in utf8Sorted(Array(mergedParams.keys)) {
                    let q = mergedParams[key]!
                    let qin = q.get("in")!.asString!, qname = q.get("name")!.asString!
                    if qin != "path" && qin != "query" {
                        c.todo.append("\(opId): \(qin) parameter '\(qname)' is not an action parameter (the schema sees path, query and body parameters only)")
                        continue
                    }
                    var sch = q.get("schema")?.asObject ?? [:]
                    if JS.truthy(q.get("description")), !JS.truthy(sch["description"]), let d = q.get("description") { sch["description"] = d }
                    addName(qname, .object(sch), qin == "path" || q.get("required") == .bool(true), "\(qin) parameters")
                }
                let revOverride = op.get("x-pca-reversibility")
                let rev = JS.present(revOverride) ?? .string(read ? "reversible" : "irreversible")
                if !read && !JS.truthy(revOverride) { c.todo.append("\(verbText): reversibility (drafted irreversible)") }
                var v: JObject = ["verb": verb, "kind": .string(read ? "read" : "write"), "params": .object(params), "reversibility": rev, "openapi": .object(["operationId": op.get("operationId") ?? .null])]
                if JS.truthy(op.get("description")), let d = op.get("description")?.asString { v["description"] = .string(slice1024(d)) }
                verbs.append(.object(v))
            }
        }
        todo = c.todo
        return draft(site, verbs, todo)
    }
}
