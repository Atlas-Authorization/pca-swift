import Foundation

private func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

/// `import` then `suggest` as one call, the importer registry of the command line, and the text forms the CLI prints and reads (JSON Lines of defs). Pure:
/// no file system, no network (the caller fetches and writes). YAML is not handled here: a YAML source is parsed by the caller and passed in as the
/// already-parsed JSON tree.
public enum ImportPipeline {
    /// Kept for callers of the first importer: the default operation bound.
    public static let MAX_IMPORT_OPS = 20_000

    /// Import one source of the given kind. Every def is `unreviewed`. `opts`: the common options (plus `verb` etc. for jsonschema). `bytes`: a binary
    /// gRPC descriptor set (the source of kind `grpc` is then the bytes).
    public static func importActions(_ kind: String?, _ source: JSONValue?, _ opts: JObject?, bytes: [UInt8]? = nil) throws -> JObject {
        let kinds = ImportCommon.IMPORT_KINDS.joined(separator: ", ")
        guard let k = kind else { throw ActionKitError(code: "bad_kind", message: "unknown import kind 'null' (one of \(kinds))") }
        switch k {
        case "openapi": return try OpenApiImporter.importOpenApi(source, opts)
        case "mcp": return try McpImporter.importMcp(source, opts)
        case "graphql": return try GraphqlImporter.importGraphql(source, opts)
        case "grpc": return try GrpcImporter.importGrpc(source, opts, bytes: bytes)
        case "asyncapi": return try AsyncApiImporter.importAsyncApi(source, opts)
        case "jsonschema": return try JsonSchemaImporter.importJsonSchema(source, opts)
        default: throw ActionKitError(code: "bad_kind", message: "unknown import kind '\(k)' (one of \(kinds))")
        }
    }

    /// The command-line importer shape: `{defs, todo: ["<where>: <message>"]}`. A JSON Schema import needs `verb` in the options. Kinds are exactly
    /// `ImportCommon.IMPORT_KINDS`.
    public static func runImporter(_ kind: String, _ doc: JSONValue?, _ opts: JObject) throws -> JObject {
        if !ImportCommon.IMPORT_KINDS.contains(kind) { throw JSError("no importer '\(kind)'") }
        if kind == "jsonschema" && !Jx.truthy(opts[JKey("verb")]) { throw JSError("a JSON Schema import needs --verb <ns.noun.action>") }
        let r = try importActions(kind, doc, opts)
        let todo: [JSONValue] = Jx.a(r[JKey("todo")]).map { .string(Jx.str(Jx.get($0, "where")) + ": " + Jx.str(Jx.get($0, "message"))) }
        return Jx.obj(["defs": r[JKey("defs")] ?? .null, "todo": .array(todo)])
    }

    /// What `suggestDefs` reads: `mode` (`rules` default, `model`, `none`), rule set (nil: the shipped one), registry, model adapters.
    public struct SuggestOpts {
        public var mode: String?
        public var rules: JObject?
        public var registry: TraitRegistry?
        public var models: [ModelAdapter]?
        public init() {}
    }

    /// Suggest for already imported defs. Returns `{defs (state suggested), errors: [{verb, model, error}]}`.
    public static func suggestDefs(_ defs: [JObject], _ o: SuggestOpts?) throws -> JObject {
        let so = o ?? SuggestOpts()
        let mode = so.mode ?? "rules"
        if mode == "none" { return Jx.obj(["defs": .array(defs.map { .object($0) }), "errors": .array([])]) }
        let registry = so.registry ?? Actions.coreRegistry
        let rules = so.rules ?? ImportRules.DEFAULT_RULES
        let digest = try so.rules == nil ? JS.toString(ImportRules.DEFAULT_RULES_SEALED[JKey("digest")]) : ImportSuggest.rulesDigest(rules)
        var out: [JSONValue] = [], errors: [JSONValue] = []
        for d in defs {
            var s = try ImportSuggest.suggestWithRules(d, rules, registry)
            var models: [JSONValue]? = nil
            if mode == "model" {
                let run = ImportModel.suggestWithModels(d, so.models ?? [], registry)
                for e in Jx.a(run[JKey("errors")]) { var m: JObject = [JKey("verb"): d[JKey("verb")] ?? .null]; for (k, v) in AK.o(e) { m[k] = v }; errors.append(.object(m)) }
                var tr = Set<String>()
                for t in Jx.a(s[JKey("traits")]) { tr.insert(Jx.str(t)) }
                for t in Jx.a(AK.o(run[JKey("suggestion")])[JKey("traits")]) { tr.insert(Jx.str(t)) }
                s = Jx.obj(["traits": Jx.strs(tr.sorted(by: u16less)), "roles": s[JKey("roles")] ?? .null, "tags": s[JKey("tags")] ?? .null, "fired": s[JKey("fired")] ?? .null])
                models = Jx.a(run[JKey("models")])
            }
            var by = Jx.obj(["rules": .object(Jx.obj(["version": rules[JKey("version")] ?? .null, "digest": .string(digest), "fired": s[JKey("fired")] ?? .null]))])
            if let ms = models, !ms.isEmpty { by[o: "models"] = .array(ms) }
            out.append(.object(ImportSuggest.applySuggestion(d, s, by)))
        }
        return Jx.obj(["defs": .array(out), "errors": .array(errors)])
    }

    /// Import then suggest: the import report with `defs` replaced by the suggested defs, plus `suggestErrors`.
    public static func importAndSuggest(_ kind: String?, _ source: JSONValue?, _ opts: JObject?, _ suggest: SuggestOpts?, bytes: [UInt8]? = nil) throws -> JObject {
        var r = try importActions(kind, source, opts, bytes: bytes)
        let defs = Jx.a(r[JKey("defs")]).map { AK.o($0) }
        let s = try suggestDefs(defs, suggest)
        r[o: "defs"] = s[JKey("defs")]
        r[o: "suggestErrors"] = s[JKey("errors")]
        return r
    }

    // ---- JSON Lines ----

    /// One def per line, strict canonical JSON, sorted by verb: byte-reproducible.
    public static func defsToJsonl(_ defs: [JObject]) throws -> String {
        let sorted = defs.enumerated().sorted { x, y in
            let a = Jx.str(x.element[JKey("verb")]), b = Jx.str(y.element[JKey("verb")])
            return a == b ? x.offset < y.offset : u16less(a, b)
        }.map { $0.element }
        var sb = ""
        for (i, d) in sorted.enumerated() {
            if i > 0 { sb += "\n" }
            guard let c = IV.strictCanon(.object(d)) else { throw JSError("a def is outside the strict JSON profile") }
            sb += c
        }
        if !defs.isEmpty { sb += "\n" }
        return sb
    }

    /// Parse and validate a JSONL file of defs. Throws ActionKitError `bad_defs` naming the first bad line.
    public static func jsonlToDefs(_ text: String) throws -> [JObject] {
        var out: [JObject] = []
        for (i, raw) in Jx.splitLF(text).enumerated() {
            let l = Jx.jsTrim(raw)
            if l.isEmpty { continue }
            guard let v = try? StrictJSON.parseLenient(l) else { throw ActionKitError(code: "bad_defs", message: "line \(i + 1): not JSON") }
            if let bad = Actions.validateDef(v) { throw ActionKitError(code: "bad_defs", message: "line \(i + 1): \(bad)") }
            out.append(AK.o(v))
        }
        return out
    }
}
