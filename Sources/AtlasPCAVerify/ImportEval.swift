import Foundation

private func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

/// Measure the suggestion rules against a labeled corpus. Every corpus entry is turned into a source document of its own kind, run through the REAL
/// importer and the REAL suggestion engine, and the traits the system flags are compared with the labels. Precision and recall per trait, with an exact
/// Clopper-Pearson bound on each. These are heuristic numbers on a reviewed corpus, published as what they are, never as a safety guarantee.
public enum ImportEval {
    public static let LABEL_SHORT: [(String, String)] = [
        ("money", "money_moving"), ("destr", "destructive"), ("comm", "external_communication"), ("priv", "privilege_change"), ("exp", "data_export"), ("exec", "code_execution"),
        ("cred", "credential_access"), ("bulk", "bulk"), ("pii", "pii_access"), ("pub", "public_exposure"), ("pers", "persistence"), ("infra", "infra_mutation"), ("cost", "cost_incurring"),
        ("legal", "legal_binding"), ("imp", "impersonation"), ("egress", "network_egress"), ("fin", "financial_data_read"), ("reg", "regulated_data"), ("sched", "scheduled"), ("spawn", "agent_spawning"),
    ]

    private static func pad4(_ n: Int) -> String { let s = String(n); return String(repeating: "0", count: max(0, 4 - s.count)) + s }

    /// The hand-labeled TSV: `kind, name, location, params, labels, description` per line. Throws on a short line or an unknown label.
    public static func parseHandTsv(_ text: String) throws -> [JSONValue] {
        var out: [JSONValue] = []
        var n = 0
        for line in Jx.splitLF(text) {
            if Jx.jsTrim(line).isEmpty || line.hasPrefix("#") { continue }
            let c = line.components(separatedBy: "\t")
            if c.count < 6 { throw JSError("hand corpus line needs 6 columns: " + String(decoding: Array(line.utf16.prefix(80)), as: UTF16.self)) }
            let kind = c[0], name = c[1], loc = c[2], params = c[3], labels = c[4], description = c[5]
            n += 1
            var e: JObject = [JKey("id"): .string("hand-" + pad4(n)), JKey("src"): .string("hand"), JKey("kind"): .string(kind), JKey("name"): .string(name)]
            e[JKey("params")] = params == "-" ? .array([]) : Jx.strs(params.components(separatedBy: ","))
            var ls: [String] = []
            if labels != "-" { for l in labels.components(separatedBy: ",") { ls.append(LABEL_SHORT.first { $0.0 == l }?.1 ?? l) } }
            e[JKey("labels")] = Jx.strs(ls)
            e[JKey("description")] = .string(description)
            if kind == "openapi" {
                if let sp = loc.firstIndex(of: " ") { e[JKey("method")] = .string(String(loc[..<sp])); e[JKey("path")] = .string(String(loc[loc.index(after: sp)...])) }
                else { e[JKey("method")] = .string(loc); e[JKey("path")] = .string("") }
            }
            for l in ls where !LABEL_SHORT.contains(where: { $0.1 == l }) { throw JSError("unknown label '\(l)' in \(name)") }
            out.append(.object(e))
        }
        return out
    }

    /// One JSON entry per non-blank line.
    public static func parseCorpusJsonl(_ text: String) throws -> [JSONValue] {
        try Jx.splitLF(text).filter { !Jx.jsTrim($0).isEmpty }.map { try StrictJSON.parseLenient($0) }
    }

    // ---- entries to source documents ----

    private static let SPEC_RE = try! NSRegularExpression(pattern: "^[^:]+:([a-z]+)(?::(.+))?\\z")
    private static let TYPE_RE = try! NSRegularExpression(pattern: "^[^:]+:([a-z]+)")
    private static let FIRST_WORD = try! NSRegularExpression(pattern: "^[A-Za-z][a-z0-9]*")
    private static let PATH_PARAM = try! NSRegularExpression(pattern: "\\{([^}]+)\\}")

    private static func group(_ re: NSRegularExpression, _ s: String, _ g: Int) -> String? {
        let r = NSRange(location: 0, length: s.utf16.count)
        guard let m = re.firstMatch(in: s, range: r), m.numberOfRanges > g, m.range(at: g).location != NSNotFound, let rr = Range(m.range(at: g), in: s) else { return nil }
        return String(s[rr])
    }

    private static func schemaOf(_ spec: String) -> JObject {
        let type = group(SPEC_RE, spec, 1), format = group(SPEC_RE, spec, 2)
        if type == "array" { return Jx.obj(["type": .string("array"), "items": .object(Jx.obj(["type": .string("string")]))]) }
        var o = Jx.obj(["type": .string(type == "number" ? "number" : (type ?? "string"))])
        if let f = format, !f.isEmpty { o[JKey("format")] = .string(f) }
        return o
    }

    /// `spec.slice(0, spec.indexOf(':'))`: with no colon the slice drops the last character.
    private static func pname(_ spec: String) -> String {
        let u = Array(spec.utf16)
        let end = u.firstIndex(of: 0x3A) ?? (u.count - 1)
        return end <= 0 ? "" : String(decoding: u[0..<end], as: UTF16.self)
    }

    private static let READ_FIRST: Set<String> = [
        "get", "list", "find", "search", "count", "describe", "show", "lookup", "check", "validate", "preview", "calculate", "estimate",
        "convert", "format", "compare", "summarize", "sort", "filter", "read", "fetch", "query", "view", "browse", "open",
    ]

    private static func firstWord(_ n: String) -> String { (group(FIRST_WORD, n, 0) ?? n).lowercased() }

    private static func strs(_ o: JSONValue?) -> [String] { Jx.a(o).map { $0.asString ?? "" } }

    private static func openapiDoc(_ es: [JObject]) -> JSONValue {
        var paths: JObject = [:]
        for e in es {
            let method = (e[JKey("method")]?.asString ?? "get").lowercased()
            let body = ["post", "put", "patch"].contains(method)
            var props: JObject = [:]
            let ps = strs(e[JKey("params")])
            for p in ps { ImportCommon.putProp(&props, pname(p), .object(schemaOf(p))) }
            var pathParams: [JSONValue] = []
            var ppNames: [String] = []
            let path = e[JKey("path")]?.asString ?? ""
            for m in PATH_PARAM.matches(in: path, range: NSRange(location: 0, length: path.utf16.count)) {
                guard let rr = Range(m.range(at: 1), in: path) else { continue }
                let nm = String(path[rr])
                ppNames.append(nm)
                pathParams.append(.object(Jx.obj(["name": .string(nm), "in": .string("path"), "required": .bool(true), "schema": .object(Jx.obj(["type": .string("string")]))])))
            }
            var op: JObject = [:]
            if Jx.truthy(e[JKey("name")]) { op[JKey("operationId")] = e[JKey("name")] }
            if Jx.truthy(e[JKey("description")]) { op[JKey("summary")] = e[JKey("description")] }
            var parameters = pathParams
            if !body { for p in ps where !ppNames.contains(pname(p)) { parameters.append(.object(Jx.obj(["name": .string(pname(p)), "in": .string("query"), "schema": .object(schemaOf(p))]))) } }
            op[JKey("parameters")] = .array(parameters)
            if body && !ps.isEmpty {
                op[JKey("requestBody")] = .object(Jx.obj(["content": .object(Jx.obj(["application/json": .object(Jx.obj(["schema": .object(Jx.obj(["type": .string("object"), "properties": .object(props), "required": .array([])]))]))]))]))
            }
            var item = AK.o(paths[JKey(e[JKey("path")]?.asString ?? "")])
            item[JKey(method)] = .object(op)
            paths[JKey(e[JKey("path")]?.asString ?? "")] = .object(item)
        }
        return .object(Jx.obj(["openapi": .string("3.0.3"), "info": .object(Jx.obj(["title": .string("corpus"), "version": .string("1")])), "paths": .object(paths)]))
    }

    private static func gqlType(_ spec: String) -> String {
        switch group(TYPE_RE, spec, 1) ?? "string" { case "string": return "String"; case "integer": return "Int"; case "boolean": return "Boolean"; case "array": return "[String]"; default: return "String" }
    }

    private static func graphqlSdl(_ es: [JObject]) -> String {
        var q: [String] = [], m: [String] = []
        for e in es {
            let name = e[JKey("name")]?.asString ?? ""
            let ps = strs(e[JKey("params")])
            var args = ""
            if !ps.isEmpty { args = "(" + ps.map { pname($0) + ": " + gqlType($0) }.joined(separator: ", ") + ")" }
            let line = "  \"" + (e[JKey("description")]?.asString ?? "").replacingOccurrences(of: "\"", with: "'") + "\"\n  " + name + args + ": String"
            if READ_FIRST.contains(firstWord(name)) || Actions.fullMatch("[a-z]+s?", name) { q.append(line) } else { m.append(line) }
        }
        return (q.isEmpty ? "" : "type Query {\n" + q.joined(separator: "\n") + "\n}\n") + (m.isEmpty ? "" : "type Mutation {\n" + m.joined(separator: "\n") + "\n}\n")
    }

    private static func protoType(_ spec: String) -> String {
        switch group(TYPE_RE, spec, 1) ?? "string" { case "string": return "string"; case "integer": return "int64"; case "boolean": return "bool"; case "array": return "repeated string"; default: return "string" }
    }

    private static func protoText(_ es: [JObject]) -> String {
        var order: [String] = []
        var svcs: [String: [JObject]] = [:]
        for e in es {
            let k = (e[JKey("name")]?.asString ?? "").components(separatedBy: "/")[0]
            if svcs[k] == nil { order.append(k) }
            svcs[k, default: []].append(e)
        }
        var msgs = ["message Empty {}"]
        var out: [String] = []
        for svc in order {
            var rpcs: [String] = []
            for e in svcs[svc]! {
                let parts = (e[JKey("name")]?.asString ?? "").components(separatedBy: "/")
                let mname = parts.count > 1 ? parts[1] : "undefined"
                let ps = strs(e[JKey("params")])
                let fs = ps.enumerated().map { "  " + protoType($0.element) + " " + pname($0.element) + " = \($0.offset + 1);" }
                msgs.append("message " + mname + "Request {\n" + fs.joined(separator: "\n") + "\n}")
                rpcs.append("  rpc \(mname)(\(mname)Request) returns (Empty);")
            }
            out.append("service " + svc + " {\n" + rpcs.joined(separator: "\n") + "\n}")
        }
        return "syntax = \"proto3\";\npackage corpus;\n" + msgs.joined(separator: "\n") + "\n" + out.joined(separator: "\n") + "\n"
    }

    private static func asyncDoc(_ es: [JObject]) -> JSONValue {
        var channels: JObject = [:]
        for e in es {
            var props: JObject = [:]
            for p in strs(e[JKey("params")]) { ImportCommon.putProp(&props, pname(p), .object(schemaOf(p))) }
            channels[JKey(e[JKey("name")]?.asString ?? "")] = .object(Jx.obj(["publish": .object(Jx.obj(["summary": e[JKey("description")] ?? .null,
                "message": .object(Jx.obj(["payload": .object(Jx.obj(["type": .string("object"), "properties": .object(props)]))]))]))]))
        }
        return .object(Jx.obj(["asyncapi": .string("2.6.0"), "info": .object(Jx.obj(["title": .string("corpus"), "version": .string("1")])), "channels": .object(channels)]))
    }

    private static func mcpDoc(_ es: [JObject]) -> JSONValue {
        .array(es.map { e in
            var props: JObject = [:]
            for p in strs(e[JKey("params")]) { ImportCommon.putProp(&props, pname(p), .object(schemaOf(p))) }
            return .object(Jx.obj(["name": e[JKey("name")] ?? .null, "description": e[JKey("description")] ?? .null, "inputSchema": .object(Jx.obj(["type": .string("object"), "properties": .object(props)]))]))
        })
    }

    private static func keyOf(_ e: JObject) -> String {
        e[JKey("kind")] == .string("openapi") ? (JS.present(e[JKey("method")]).map { Jx.str($0).uppercased() } ?? "GET") + " " + Jx.str(e[JKey("path")]) : Jx.str(e[JKey("name")])
    }

    private static func defKey(_ d: JObject) -> String {
        let b = d[JKey("bindings")]
        let oa = Jx.get(b, "openapi")
        if Jx.truthy(Jx.get(oa, "path")) { return Jx.str(Jx.get(oa, "method")) + " " + Jx.str(Jx.get(oa, "path")) }
        if let o = JS.present(Jx.get(oa, "operationId")) { return Jx.str(o) }
        if let t = JS.present(Jx.get(Jx.get(b, "mcp"), "tool")) { return Jx.str(t) }
        if let f = JS.present(Jx.get(Jx.get(b, "graphql"), "field")) { return Jx.str(f) }
        let g = Jx.get(b, "grpc")
        if Jx.truthy(g) { let sv = Jx.str(Jx.get(g, "service")).components(separatedBy: "."); return sv[sv.count - 1] + "/" + Jx.str(Jx.get(g, "method")) }
        if let c = JS.present(Jx.get(Jx.get(b, "asyncapi"), "channel")) { return Jx.str(c) }
        return ""
    }

    /// Import every entry with the real importer of its kind. Returns `{defs: {id: def}, todo: n}` (an entry whose def was not emitted is absent).
    public static func importCorpus(_ entries: [JSONValue]) throws -> JObject {
        var defs: JObject = [:]
        var todo: Int64 = 0
        var order: [String] = []
        var groups: [String: [JObject]] = [:]
        for eo in entries {
            let e = AK.o(eo)
            let g = Jx.str(e[JKey("kind")]) + "|" + (JS.present(e[JKey("spec")]).map { Jx.str($0) } ?? "")
            if groups[g] == nil { order.append(g) }
            groups[g, default: []].append(e)
        }
        let opts = Jx.obj(["ns": .string("corpus"), "limits": .object(Jx.obj(["max_ops": .int(50_000), "max_nodes": .int(20_000_000), "max_bytes": .int(200_000_000)]))])
        for gk in order {
            let es = groups[gk]!
            let kind = gk.components(separatedBy: "|")[0]
            let src: JSONValue = kind == "openapi" ? openapiDoc(es) : kind == "mcp" ? mcpDoc(es) : kind == "graphql" ? .string(graphqlSdl(es)) : kind == "grpc" ? .string(protoText(es)) : asyncDoc(es)
            let r = try ImportPipeline.importActions(kind, src, opts)
            todo += Int64(Jx.a(r[JKey("todo")]).count)
            var byKey: JObject = [:]
            for d in Jx.a(r[JKey("defs")]) { byKey[JKey(defKey(AK.o(d)))] = d }
            for e in es { if let d = byKey[JKey(keyOf(e))], let id = e[JKey("id")]?.asString { defs[JKey(id)] = d } }
        }
        return Jx.obj(["defs": .object(defs), "todo": .int(todo)])
    }

    // ---- scoring ----

    /// Deterministic split of the real corpus by specification: rules are tuned on `tune` specs only; `holdout` specs are never looked at when editing rules.
    public static func realSplit(_ spec: JSONValue?) -> String {
        let s = spec == nil ? "" : Jx.str(spec)
        var h: UInt32 = 2166136261
        for sc in s.unicodeScalars {
            let code = UInt32(String(sc).utf16.first!)
            h = (h ^ code) &* 16777619
        }
        return ((h >> 7) % 2) == 0 ? "tune" : "holdout"
    }

    private static func sourceOf(_ e: JObject) -> String { e[JKey("src")] == .string("real") ? "real/" + realSplit(e[JKey("spec")]) : Jx.str(e[JKey("src")]) }

    private static func stat(_ trait: String, _ rows: [(Bool, Bool)], _ alpha: Double) throws -> JObject {
        var tp = 0, fp = 0, fn = 0
        for r in rows { if r.0 && r.1 { tp += 1 } else if r.1 { fp += 1 } else if r.0 { fn += 1 } }
        let pos = tp + fn, pred = tp + fp
        var o: JObject = [JKey("trait"): .string(trait), JKey("positives"): .int(Int64(pos)), JKey("predicted"): .int(Int64(pred)), JKey("tp"): .int(Int64(tp)), JKey("fp"): .int(Int64(fp)), JKey("fn"): .int(Int64(fn))]
        o[JKey("precision")] = pred == 0 ? .null : Jx.num(Double(tp) / Double(pred))
        o[JKey("recall")] = pos == 0 ? .null : Jx.num(Double(tp) / Double(pos))
        o[JKey("recall_lower")] = pos == 0 ? .null : Jx.num(1 - (try PCAIntentStats.clopperPearsonUpper(Double(fn), Double(pos), alpha)))
        // the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
        o[JKey("precision_lower")] = (pred == 0 || pred > 600) ? .null : Jx.num(1 - (try PCAIntentStats.clopperPearsonUpper(Double(fp), Double(pred), alpha)))
        return o
    }

    private static func strip(_ t: String) -> String { t.hasPrefix("pca.") ? String(t.dropFirst(4)) : t }

    private static func score(_ es: [JObject], _ pred: [String: Set<String>], _ traitNames: [String], _ alpha: Double) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for t in traitNames {
            let rows: [(Bool, Bool)] = es.map { e in (Jx.a(e[JKey("labels")]).contains(.string(t)), pred[Jx.str(e[JKey("id")])]?.contains(t) ?? false) }
            let s = try stat(t, rows, alpha)
            if (IV.num(s[JKey("positives")]) ?? 0) > 0 || (IV.num(s[JKey("predicted")]) ?? 0) > 0 { out.append(.object(s)) }
        }
        return out
    }

    /// `evalSuggest`: `rules` and `registry` default to the shipped ones; `alpha` to 0.05.
    public static func evalSuggest(_ entriesO: [JSONValue], _ rulesIn: JObject?, _ registryIn: TraitRegistry?, _ alphaIn: Double?) throws -> JObject {
        let rules = rulesIn ?? ImportRules.DEFAULT_RULES
        let registry = registryIn ?? Actions.coreRegistry
        let alpha = alphaIn ?? 0.05
        let entries = entriesO.map { AK.o($0) }
        let defs = AK.o(try importCorpus(entriesO)[JKey("defs")])
        var names = Set<String>()
        for t in registry.traits.keys where t.s != "pca.unreviewed" && t.s != "pca.irreversible" { names.insert(strip(t.s)) }
        let traitNames = names.sorted(by: u16less)
        var flagged: [String: Set<String>] = [:], added: [String: Set<String>] = [:]
        for e in entries {
            let id = Jx.str(e[JKey("id")])
            guard let d = defs[JKey(id)].map({ AK.o($0) }) else { continue }
            let s = try ImportSuggest.suggestWithRules(d, rules, registry)
            let sd = ImportSuggest.applySuggestion(d, s, Jx.obj(["rules": .object(Jx.obj(["version": rules[JKey("version")] ?? .null, "digest": .string(""), "fired": s[JKey("fired")] ?? .null]))]))
            var fl = Set<String>()
            for t in try Actions.closure(registry, ActionEffective.hintTraits(sd)) where t != "pca.unreviewed" { fl.insert(strip(t)) }
            flagged[id] = fl
            var ad = Set<String>()
            for t in Jx.a(s[JKey("traits")]) { ad.insert(strip(t.asString ?? "")) }
            added[id] = ad
        }
        var sources = Set<String>()
        var anyReal = false
        for e in entries { sources.insert(sourceOf(e)); if e[JKey("src")] == .string("real") { anyReal = true } }
        if anyReal { sources.insert("real") }
        var bySource: JObject = [:]
        for s in sources.sorted(by: u16less) {
            let es = entries.filter { s == "real" ? $0[JKey("src")] == .string("real") : sourceOf($0) == s }
            bySource[JKey(s)] = .object(Jx.obj(["entries": .int(Int64(es.count)), "flagged": .array(try score(es, flagged, traitNames, alpha))]))
        }
        return Jx.obj(["alpha": Jx.num(alpha), "entries": .int(Int64(entries.count)), "mapped": .int(Int64(defs.count)), "rules_version": rules[JKey("version")] ?? .null,
                       "flagged": .array(try score(entries, flagged, traitNames, alpha)), "suggested": .array(try score(entries, added, traitNames, alpha)), "by_source": .object(bySource)])
    }

    /// `BigDecimal(x * 100).setScale(1, HALF_UP)` of a double, written plain, with a percent sign.
    private static func pct(_ x: JSONValue?) -> String {
        guard let x = x, x != .null, let v = IV.num(x) else { return "-" }
        let d = v * 100
        let scaled = d * 10
        let exactErr = fma(d, 10, -scaled)
        let hi = scaled.rounded(.down)
        let frac = scaled - hi
        let up = frac > 0.5 || (frac == 0.5 && exactErr >= 0)
        let n = Int64(hi) + (up ? 1 : 0)
        return "\(n / 10).\(n % 10)%"
    }

    private static func table(_ stats: [JSONValue]) -> String {
        var rows = ["| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for so in stats {
            let s = AK.o(so)
            rows.append("| " + Jx.str(s[JKey("trait")]) + " | " + Jx.str(s[JKey("positives")]) + " | " + Jx.str(s[JKey("predicted")]) + " | " + pct(s[JKey("recall")]) + " | " + pct(s[JKey("recall_lower")]) + " | " + pct(s[JKey("precision")]) + " | " +
                        Jx.str(s[JKey("fn")]) + " | " + Jx.str(s[JKey("fp")]) + " |")
        }
        return rows.joined(separator: "\n")
    }

    public static func renderEvalMarkdown(_ r: JObject) -> String {
        var parts = [
            "# Suggestion rules " + Jx.str(r[JKey("rules_version")]) + ": measured on a labeled corpus",
            "",
            Jx.str(r[JKey("entries")]) + " labeled operations (" + Jx.str(r[JKey("mapped")]) + " imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = " + Jx.str(r[JKey("alpha")]) + ".",
            "These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.",
            "",
            "## What a reviewer is shown (importer facts plus suggestions)", "", table(Jx.a(r[JKey("flagged")])), "",
            "## What the suggestion rules added", "", table(Jx.a(r[JKey("suggested")])), "",
        ]
        let bs = AK.o(r[JKey("by_source")])
        for k in JS.keyOrder(bs) {
            let v = bs[k]
            parts.append("## Source: " + k.s + " (" + Jx.str(Jx.get(v, "entries")) + " operations)")
            parts.append("")
            parts.append(table(Jx.a(Jx.get(v, "flagged"))))
            parts.append("")
        }
        return parts.joined(separator: "\n")
    }

    private static func findTrait(_ flagged: JSONValue?, _ t: String) -> JSONValue? { Jx.a(flagged).first { $0.get("trait") == .string(t) } }

    /// Empty when the report meets the floors; else one line per failure.
    public static func floorFailures(_ r: JObject, _ f: JObject) -> [String] {
        var out: [String] = []
        let bySource = AK.o(r[JKey("by_source")])
        let real = bySource[JKey("real/holdout")]
        let fr = AK.o(f[JKey("real")])
        let minEntries = IV.num(fr[JKey("min_entries")]) ?? 0
        if real == nil || (IV.num(Jx.get(real, "entries")) ?? 0) < minEntries {
            out.append("the real-spec hold-out has " + (real == nil ? "0" : Jx.str(Jx.get(real, "entries"))) + " operations, fewer than the required " + Jx.str(fr[JKey("min_entries")]))
        }
        let entries = IV.num(r[JKey("entries")]) ?? 0, mapped = IV.num(r[JKey("mapped")]) ?? 0
        if mapped < entries { out.append(String(Int64(entries - mapped)) + " corpus operations were not imported") }
        let rl = AK.o(fr[JKey("recall_lower")])
        for k in JS.keyOrder(rl) {
            let t = k.s, floorV = rl[k]
            let s = real.flatMap { findTrait(Jx.get($0, "flagged"), t) }
            let needO = AK.o(fr[JKey("min_positives")])[k]
            let need = needO == nil ? "0" : Jx.str(needO)
            let needN = needO == nil ? 0.0 : (IV.num(needO) ?? 0)
            if s == nil || (IV.num(Jx.get(s, "positives")) ?? 0) < needN {
                out.append(t + ": " + (s == nil ? "0" : Jx.str(Jx.get(s, "positives"))) + " real labeled positives, fewer than the " + need + " the floor needs")
            } else if JS.present(Jx.get(s, "recall_lower")) == nil || (IV.num(Jx.get(s, "recall_lower")) ?? 0) < (IV.num(floorV) ?? 0) {
                out.append(t + ": hold-out recall lower bound " + pct(Jx.get(s, "recall_lower")) + " is below the recorded floor " + pct(floorV))
            }
        }
        let syn = bySource[JKey("syn")]
        let rg = AK.o(AK.o(f[JKey("regression")])[JKey("recall_lower")])
        for k in JS.keyOrder(rg) {
            let s = syn.flatMap { findTrait(Jx.get($0, "flagged"), k.s) }
            if s == nil || JS.present(Jx.get(s, "recall_lower")) == nil || (IV.num(Jx.get(s, "recall_lower")) ?? 0) < (IV.num(rg[k]) ?? 0) {
                out.append(k.s + ": regression-set recall lower bound " + pct(s == nil ? nil : Jx.get(s, "recall_lower")) + " is below " + pct(rg[k]))
            }
        }
        return out
    }
}
