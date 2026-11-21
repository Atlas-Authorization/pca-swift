import Foundation

private func utf8Less(_ a: String, _ b: String) -> Bool { Array(a.utf8).lexicographicallyPrecedes(Array(b.utf8)) }

/// GraphQL SDL or introspection JSON to drafts. Query fields are reads, Mutation fields are writes, Subscription fields are streaming reads; arguments and
/// input objects are flattened to dotted params. There is no method signal; everything stays `unreviewed`.
public enum GraphqlImporter {
    // ---- model ----

    /// `named` (name), `list` (of) or `nonnull` (of).
    public final class GqlType {
        public let k: String
        public let name: String?
        public let of: GqlType?
        init(_ k: String, _ name: String?, _ of: GqlType?) { self.k = k; self.name = name; self.of = of }
        static func named(_ n: String) -> GqlType { GqlType("named", n, nil) }
        func toJson() -> JSONValue { k == "named" ? AK.obj(["k": .string(k), "name": .string(name ?? "")]) : AK.obj(["k": .string(k), "of": of!.toJson()]) }
    }

    public struct GqlArg {
        public let name: String
        public let type: GqlType
        public let desc: String?
        func toJson() -> JSONValue {
            var m = Jx.obj(["name": .string(name), "type": type.toJson()])
            if let d = desc { m[o: "desc"] = .string(d) }
            return .object(m)
        }
    }

    public struct GqlField {
        public let name: String
        public let args: [GqlArg]
        public let type: GqlType
        public let deprecated: Bool
        public let desc: String?
        func toJson() -> JSONValue {
            var m = Jx.obj(["name": .string(name), "args": .array(args.map { $0.toJson() }), "type": type.toJson(), "deprecated": .bool(deprecated)])
            if let d = desc { m[o: "desc"] = .string(d) }
            return .object(m)
        }
    }

    public final class GqlTypeDef {
        public let kind: String
        public let name: String
        public var fields: [GqlField]
        public var values: [String]
        init(_ kind: String, _ name: String, _ fields: [GqlField], _ values: [String]) { self.kind = kind; self.name = name; self.fields = fields; self.values = values }
    }

    public final class GqlSchema {
        public private(set) var order: [String] = []
        public private(set) var types: [JKey: GqlTypeDef] = [:]
        public var query: String?
        public var mutation: String?
        public var subscription: String?

        func put(_ name: String, _ d: GqlTypeDef) { if types[JKey(name)] == nil { order.append(name) }; types[JKey(name)] = d }

        /// `{types: [[name, {kind, name, fields, values}]...], query?, mutation?, subscription?}`.
        public func toJson() -> JSONValue {
            let ts: [JSONValue] = order.map { k in
                let v = types[JKey(k)]!
                return .array([.string(k), AK.obj(["kind": .string(v.kind), "name": .string(v.name), "fields": .array(v.fields.map { $0.toJson() }), "values": Jx.strs(v.values)])])
            }
            var m = Jx.obj(["types": .array(ts)])
            if let q = query { m[o: "query"] = .string(q) }
            if let q = mutation { m[o: "mutation"] = .string(q) }
            if let q = subscription { m[o: "subscription"] = .string(q) }
            return .object(m)
        }
    }

    // ---- SDL lexer ----

    private struct Tok { let t: String; let v: String }

    private static func nameStart(_ c: UInt16) -> Bool { c == 0x5F || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) }
    private static func nameChar(_ c: UInt16) -> Bool { nameStart(c) || (c >= 48 && c <= 57) }
    private static func text(_ u: [UInt16], _ a: Int, _ b: Int) -> String { String(decoding: u[a..<b], as: UTF16.self) }
    private static func starts(_ u: [UInt16], _ s: String, _ i: Int) -> Bool {
        let p = Array(s.utf16)
        return i + p.count <= u.count && Array(u[i..<(i + p.count)]) == p
    }

    private static func lex(_ src: String, _ maxTokens: Int) throws -> [Tok] {
        var out: [Tok] = []
        let u = Array(src.utf16)
        var i = 0
        let n = u.count
        while i < n {
            let ch = u[i]
            let push: Tok
            if ch == 0x20 || ch == 0x09 || ch == 0x0A || ch == 0x0D || ch == 0x2C || ch == 0xFEFF { i += 1; continue }
            if ch == 0x23 { while i < n && u[i] != 0x0A { i += 1 }; continue }
            if ch == 0x22 {
                if starts(u, "\"\"\"", i) {
                    var j = i + 3
                    var s: [UInt16] = []
                    while j < n && !starts(u, "\"\"\"", j) {
                        if starts(u, "\\\"\"\"", j) { s += [0x22, 0x22, 0x22]; j += 4 } else { s.append(u[j]); j += 1 }
                    }
                    if j >= n { throw ActionKitError(code: "bad_source", message: "unterminated GraphQL block string") }
                    push = Tok(t: "str", v: String(decoding: s, as: UTF16.self))
                    i = j + 3
                } else {
                    var j = i + 1
                    var s: [UInt16] = []
                    while j < n && u[j] != 0x22 {
                        if u[j] == 0x0A { throw ActionKitError(code: "bad_source", message: "unterminated GraphQL string") }
                        if u[j] == 0x5C { if j + 1 < n { s.append(u[j + 1]) }; j += 2 } else { s.append(u[j]); j += 1 }
                    }
                    if j >= n { throw ActionKitError(code: "bad_source", message: "unterminated GraphQL string") }
                    push = Tok(t: "str", v: String(decoding: s, as: UTF16.self))
                    i = j + 1
                }
            } else if nameStart(ch) {
                var j = i + 1
                while j < n && nameChar(u[j]) { j += 1 }
                push = Tok(t: "name", v: text(u, i, j))
                i = j
            } else if ch == 0x2D || (ch >= 48 && ch <= 57) {
                var j = i + 1
                while j < n && (u[j] == 0x2D || u[j] == 0x2B || u[j] == 0x2E || (u[j] >= 48 && u[j] <= 57) || u[j] == 0x65 || u[j] == 0x45) { j += 1 }
                push = Tok(t: "int", v: text(u, i, j))
                i = j
            } else if starts(u, "...", i) { push = Tok(t: "punct", v: "..."); i += 3 }
            else if "!$&():=@[]{|}".utf16.contains(ch) { push = Tok(t: "punct", v: text(u, i, i + 1)); i += 1 }
            else { throw ActionKitError(code: "bad_source", message: "unexpected character in GraphQL source at offset \(i)") }
            if out.count >= maxTokens { throw ActionKitError(code: "import_limit", message: "the GraphQL source has too many tokens") }
            out.append(push)
        }
        if out.count >= maxTokens { throw ActionKitError(code: "import_limit", message: "the GraphQL source has too many tokens") }
        out.append(Tok(t: "eof", v: ""))
        return out
    }

    // ---- SDL parser (type system definitions only; executable documents are rejected) ----

    private final class P {
        let toks: [Tok]
        let schema: GqlSchema
        let maxDepth: Int
        var i = 0
        init(_ toks: [Tok], _ schema: GqlSchema, _ maxDepth: Int) { self.toks = toks; self.schema = schema; self.maxDepth = maxDepth }

        func cur() -> Tok { toks[i] }
        @discardableResult func next() -> Tok { let t = toks[i]; if t.t != "eof" { i += 1 }; return t }
        func isV(_ v: String) -> Bool { cur().t != "str" && cur().v == v }
        @discardableResult func eat(_ v: String) -> Bool { if isV(v) { i += 1; return true }; return false }
        func expect(_ v: String) throws { if !eat(v) { throw ActionKitError(code: "bad_source", message: "GraphQL parse error: expected '\(v)' near '\(ImportCommon.clip(.string(cur().v), 30))'") } }
        @discardableResult func name() throws -> String {
            let t = next()
            if t.t != "name" { throw ActionKitError(code: "bad_source", message: "GraphQL parse error: expected a name near '\(ImportCommon.clip(.string(t.v), 30))'") }
            return t.v
        }
        func desc() -> String? { cur().t == "str" ? next().v : nil }
        func eof() -> Bool { cur().t == "eof" }

        func type(_ depth: Int) throws -> GqlType {
            if depth > maxDepth { throw ActionKitError(code: "import_limit", message: "GraphQL type nesting is too deep") }
            let t: GqlType
            if eat("[") { t = GqlType("list", nil, try type(depth + 1)); try expect("]") } else { t = GqlType.named(try name()) }
            return eat("!") ? GqlType("nonnull", nil, t) : t
        }

        /// Skip a constant value (default values, directive arguments).
        func value(_ depth: Int) throws {
            if depth > maxDepth { throw ActionKitError(code: "import_limit", message: "GraphQL value nesting is too deep") }
            let t = cur()
            if t.t == "str" || t.t == "int" || t.t == "name" { i += 1; return }
            if eat("[") { while !isV("]") && !eof() { try value(depth + 1) }; try expect("]"); return }
            if eat("{") { while !isV("}") && !eof() { try name(); try expect(":"); try value(depth + 1) }; try expect("}"); return }
            if eat("$") { try name(); return }
            throw ActionKitError(code: "bad_source", message: "GraphQL parse error: unexpected '\(ImportCommon.clip(.string(t.v), 30))'")
        }

        func directives() throws -> Bool {
            var deprecated = false
            while eat("@") {
                let n = try name()
                if n == "deprecated" { deprecated = true }
                if eat("(") { while !isV(")") && !eof() { try name(); try expect(":"); try value(0) }; try expect(")") }
            }
            return deprecated
        }

        func args() throws -> [GqlArg] {
            var out: [GqlArg] = []
            if !eat("(") { return out }
            while !isV(")") {
                if eof() { throw ActionKitError(code: "bad_source", message: "GraphQL parse error: unterminated argument list") }
                var d = desc()
                if d?.isEmpty == true { d = nil }
                let n = try name()
                try expect(":")
                let ty = try type(0)
                if eat("=") { try value(0) }
                _ = try directives()
                out.append(GqlArg(name: n, type: ty, desc: d))
            }
            try expect(")")
            return out
        }

        func fields(_ input: Bool) throws -> [GqlField] {
            var out: [GqlField] = []
            if !eat("{") { return out }
            while !isV("}") {
                if eof() { throw ActionKitError(code: "bad_source", message: "GraphQL parse error: unterminated field list") }
                var d = desc()
                if d?.isEmpty == true { d = nil }
                let n = try name()
                let a: [GqlArg] = try input ? [] : args()
                try expect(":")
                let ty = try type(0)
                if input && eat("=") { try value(0) }
                let dep = try directives()
                out.append(GqlField(name: n, args: a, type: ty, deprecated: dep, desc: d))
            }
            try expect("}")
            return out
        }

        func def() throws {
            _ = desc()
            let kw = try name()
            if kw == "extend" { try def(); return }
            if kw == "schema" {
                _ = try directives()
                try expect("{")
                while !isV("}") {
                    if eof() { throw ActionKitError(code: "bad_source", message: "GraphQL parse error: unterminated schema block") }
                    let op = try name(); try expect(":"); let ty = try name()
                    if op == "query" { schema.query = ty } else if op == "mutation" { schema.mutation = ty } else if op == "subscription" { schema.subscription = ty }
                }
                try expect("}")
                return
            }
            if kw == "scalar" { let n = try name(); _ = try directives(); merge(GqlTypeDef("scalar", n, [], [])); return }
            if kw == "directive" {
                try expect("@"); try name(); _ = try args()
                if cur().v == "repeatable" { i += 1 }
                if cur().v == "on" { i += 1 }
                eat("|")
                try name()
                while eat("|") { try name() }
                return
            }
            if kw == "type" || kw == "interface" || kw == "input" {
                let n = try name()
                if cur().v == "implements" { i += 1; eat("&"); try name(); while eat("&") { try name() } }
                _ = try directives()
                merge(GqlTypeDef(kw == "type" ? "object" : kw == "input" ? "input" : "interface", n, try fields(kw == "input"), []))
                return
            }
            if kw == "union" {
                let n = try name(); _ = try directives()
                if eat("=") { eat("|"); try name(); while eat("|") { try name() } }
                merge(GqlTypeDef("union", n, [], []))
                return
            }
            if kw == "enum" {
                let n = try name(); _ = try directives()
                var values: [String] = []
                if eat("{") {
                    while !isV("}") {
                        if eof() { throw ActionKitError(code: "bad_source", message: "GraphQL parse error: unterminated enum") }
                        _ = desc(); values.append(try name()); _ = try directives()
                    }
                    try expect("}")
                }
                merge(GqlTypeDef("enum", n, [], values))
                return
            }
            throw ActionKitError(code: "bad_source", message: "GraphQL parse error: unsupported definition '\(ImportCommon.clip(.string(kw), 30))' (only type-system definitions are imported)")
        }

        func merge(_ d: GqlTypeDef) {
            if let old = schema.types[JKey(d.name)] { old.fields += d.fields; old.values += d.values } else { schema.put(d.name, d) }
        }
    }

    public static func parseGraphqlSdl(_ src: String, _ maxTokens: Int = 2_000_000) throws -> GqlSchema {
        let toks = try lex(src, maxTokens)
        let schema = GqlSchema()
        let p = P(toks, schema, 32)
        while !p.eof() { try p.def() }
        return schema
    }

    // ---- introspection to model ----

    private static func introspectType(_ t: JSONValue?, _ depth: Int) throws -> GqlType {
        guard depth <= 16, case let .object(m)? = t else { throw ActionKitError(code: "bad_source", message: "malformed introspection type reference") }
        if m[JKey("kind")] == .string("NON_NULL") { return GqlType("nonnull", nil, try introspectType(m[JKey("ofType")], depth + 1)) }
        if m[JKey("kind")] == .string("LIST") { return GqlType("list", nil, try introspectType(m[JKey("ofType")], depth + 1)) }
        guard let nm = m[JKey("name")]?.asString else { throw ActionKitError(code: "bad_source", message: "malformed introspection type reference") }
        return GqlType.named(nm)
    }

    private static func rootName(_ s: JObject, _ k: String) -> String? { s[JKey(k)]?.asObject?[JKey("name")]?.asString }

    private static func fieldOf(_ f: JSONValue) throws -> GqlField? {
        guard case let .object(m) = f, let name = m[JKey("name")]?.asString else { return nil }
        var args: [GqlArg] = []
        if case let .array(al)? = m[JKey("args")] {
            for a in al {
                guard case let .object(ao) = a, let an = ao[JKey("name")]?.asString else { continue }
                args.append(GqlArg(name: an, type: try introspectType(ao[JKey("type")], 0), desc: ao[JKey("description")]?.asString))
            }
        }
        let type = try m[JKey("type")] == nil ? GqlType.named("String") : introspectType(m[JKey("type")], 0)
        return GqlField(name: name, args: args, type: type, deprecated: m[JKey("isDeprecated")] == .bool(true), desc: m[JKey("description")]?.asString)
    }

    private static let KINDS = ["OBJECT": "object", "INPUT_OBJECT": "input", "ENUM": "enum", "SCALAR": "scalar", "INTERFACE": "interface", "UNION": "union"]

    public static func fromIntrospection(_ doc: JSONValue?) throws -> GqlSchema {
        let root: JSONValue? = Jx.get(doc, "data")?.asObject != nil ? Jx.get(doc, "data") : doc
        guard let sm = Jx.get(root, "__schema")?.asObject, case let .array(types)? = sm[JKey("types")] else { throw ActionKitError(code: "bad_source", message: "not a GraphQL introspection result (no __schema.types)") }
        let schema = GqlSchema()
        if let q = rootName(sm, "queryType"), !q.isEmpty { schema.query = q }
        if let m = rootName(sm, "mutationType"), !m.isEmpty { schema.mutation = m }
        if let s = rootName(sm, "subscriptionType"), !s.isEmpty { schema.subscription = s }
        for to in types {
            guard case let .object(t) = to, let name = t[JKey("name")]?.asString, let rk = t[JKey("kind")]?.asString else { continue }
            if name.hasPrefix("__") { continue }
            guard let kind = KINDS[rk] else { continue }
            let fieldsRaw = kind == "input" ? t[JKey("inputFields")] : t[JKey("fields")]
            var fields: [GqlField] = []
            if case let .array(fl)? = fieldsRaw { for f in fl { if let g = try fieldOf(f) { fields.append(g) } } }
            var values: [String] = []
            if case let .array(el)? = t[JKey("enumValues")] { for e in el { if let n = e.get("name")?.asString { values.append(n) } } }
            schema.put(name, GqlTypeDef(kind, name, fields, values))
        }
        return schema
    }

    // ---- model to JSON-schema-like to params ----

    private static func scalar(_ name: String) -> JObject? {
        switch name {
        case "Int": return Jx.obj(["type": .string("integer"), "format": .string("int32")])
        case "String", "ID": return Jx.obj(["type": .string("string")])
        case "Boolean": return Jx.obj(["type": .string("boolean")])
        case "Float": return Jx.obj(["type": .string("number")])
        case "Date": return Jx.obj(["type": .string("string"), "format": .string("date")])
        case "DateTime": return Jx.obj(["type": .string("string"), "format": .string("date-time")])
        case "Email": return Jx.obj(["type": .string("string"), "format": .string("email")])
        case "UUID": return Jx.obj(["type": .string("string"), "format": .string("uuid")])
        case "URL", "URI": return Jx.obj(["type": .string("string"), "format": .string("url")])
        default: return nil
        }
    }

    private struct R { let s: JObject; let nonnull: Bool }

    /// A GraphQL type as a JSON-schema-like node; input objects expand with a cycle guard and a node budget.
    private static func schemaOf(_ t: GqlType, _ gs: GqlSchema, _ c: ImportCommon.Ctx, _ bud: ImportCommon.Budget, _ stack: [String], _ where_: String) -> R {
        var nonnull = false
        var cur = t
        while cur.k == "nonnull" { nonnull = true; cur = cur.of! }
        if cur.k == "list" { return R(s: Jx.obj(["type": .string("array"), "items": .object(schemaOf(cur.of!, gs, c, bud, stack, where_).s)]), nonnull: nonnull) }
        let name = cur.name ?? ""
        let before = bud.left
        bud.left -= 1
        if before <= 0 {
            if !bud.exhausted { bud.exhausted = true; ImportCommon.addTodo(c, where_, "ref_budget", "type expansion stopped at the node budget (declared string; refine or drop)") }
            return R(s: [:], nonnull: nonnull)
        }
        if let sc = scalar(name) { return R(s: sc, nonnull: nonnull) }
        guard let def = gs.types[JKey(name)] else {
            ImportCommon.addTodo(c, where_, "unknown_type", "type '\(ImportCommon.clip(.string(name), 60))' is not defined in the schema (declared string)")
            return R(s: [:], nonnull: nonnull)
        }
        if def.kind == "enum" {
            var vs: [JSONValue] = []
            for v in def.values where !vs.contains(.string(v)) { vs.append(.string(v)) }
            return R(s: Jx.obj(["type": .string("string"), "enum": .array(vs)]), nonnull: nonnull)
        }
        if def.kind == "scalar" { return R(s: Jx.obj(["type": .string("string")]), nonnull: nonnull) }
        if def.kind == "input" {
            if stack.contains(name) {
                ImportCommon.addTodo(c, where_, "cyclic_ref", "input type '\(ImportCommon.clip(.string(name), 60))' is recursive (declared string; refine or drop)")
                return R(s: [:], nonnull: nonnull)
            }
            var properties: JObject = [:]
            var required: [JSONValue] = []
            let ns = stack + [name]
            for f in def.fields {
                let r = schemaOf(f.type, gs, c, bud, ns, where_)
                var p = r.s
                if let d = f.desc, !d.isEmpty { p[o: "description"] = .string(d) }
                ImportCommon.putProp(&properties, f.name, .object(p))
                if r.nonnull { required.append(.string(f.name)) }
            }
            return R(s: Jx.obj(["type": .string("object"), "properties": .object(properties), "required": .array(required)]), nonnull: nonnull)
        }
        ImportCommon.addTodo(c, where_, "output_type", "type '\(ImportCommon.clip(.string(name), 60))' is an output type and cannot be an argument (declared string)")
        return R(s: [:], nonnull: nonnull)
    }

    public static func importGraphql(_ source: JSONValue?, _ opts: JObject?) throws -> JObject {
        let c = try ImportCommon.newCtx("graphql", source, opts)
        let gs = try { () throws -> GqlSchema in
            if case let .string(s)? = source { return try parseGraphqlSdl(s) }
            return try fromIntrospection(source)
        }()
        let roots = [(gs.query ?? "Query", "query"), (gs.mutation ?? "Mutation", "mutation"), (gs.subscription ?? "Subscription", "subscription")]
        for (rootName, op) in roots {
            guard let rt = gs.types[JKey(rootName)] else { continue }
            let fs = rt.fields.sorted { utf8Less($0.name, $1.name) }
            for f in fs {
                let where_ = op + " " + ImportCommon.clip(.string(f.name), 80)
                c.root = nil
                let bud = ImportCommon.newBudget(c)
                var properties: JObject = [:]
                var required: [JSONValue] = []
                for a in f.args {
                    let r = schemaOf(a.type, gs, c, bud, [], where_ + "(" + a.name + ")")
                    var p = r.s
                    if let d = a.desc, !d.isEmpty { p[o: "description"] = .string(d) }
                    ImportCommon.putProp(&properties, a.name, .object(p))
                    if r.nonnull { required.append(.string(a.name)) }
                }
                var params: JObject = [:]
                try ImportCommon.flattenObject(Jx.obj(["type": .string("object"), "properties": .object(properties), "required": .array(required)]), c, bud, where_, &params)
                if f.deprecated { ImportCommon.addTodo(c, where_, "deprecated", "the field is marked @deprecated") }
                var d = ImportCommon.Draft()
                d.name = .string(f.name)
                if let desc = f.desc, !desc.isEmpty { d.title = .string(Jx.splitLF(desc)[0]) } else { d.title = .string(f.name) }
                d.description = f.desc.map { .string($0) }
                d.effects = [op == "mutation" ? "update" : "read"]
                d.scope = "one"
                d.params = params
                if op == "subscription" { d.traits = ImportCommon.withTrait(nil, "pca.bulk") }
                if op != "mutation" { d.idempotency = Jx.obj(["mode": .string("natural")]) }
                d.bindings = Jx.obj(["graphql": .object(Jx.obj(["op": .string(op), "field": .string(ImportCommon.clip(.string(f.name), 200))]))])
                try ImportCommon.emitDef(c, d)
            }
        }
        return ImportCommon.finish(c)
    }
}
