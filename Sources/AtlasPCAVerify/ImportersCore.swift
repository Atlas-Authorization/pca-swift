import Foundation

private func utf8Less(_ a: String, _ b: String) -> Bool { Array(a.utf8).lexicographicallyPrecedes(Array(b.utf8)) }

/// OpenAPI 3.x and Swagger 2 to drafts: one def per operation; the method gives the initial effects.
public enum OpenApiImporter {
    private static let METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"]
    private static let EFFECT_OF = ["get": "read", "head": "read", "options": "read", "trace": "read", "post": "create", "put": "update", "patch": "update", "delete": "delete"]
    private static let NATURAL: Set<String> = ["get", "head", "options", "trace", "put", "delete"]
    private static let BODY_TYPES = ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"]
    private static let VERSIONISH = "(?i:v[0-9]+(?:\\.[0-9]+)?|api|rest|public|latest)"
    private static let JSON_SUFFIX = try! NSRegularExpression(pattern: "^application/[^;]*\\+json(?:;|\\z)", options: [.caseInsensitive])
    private static let X_VERB = "[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}"

    /// Follow a `$ref` chain (local only, bounded); returns the target (object or array), or nil after noting why.
    private static func deref(_ c: ImportCommon.Ctx, _ x: JSONValue?, _ where_: String) -> JSONValue? {
        guard case let .object(o0)? = x else { return nil }
        if o0[JKey("$ref")]?.asString == nil { return x }
        var seen: [String] = []
        var cur: JSONValue? = x
        while case let .object(o)? = cur, let ref = o[JKey("$ref")]?.asString {
            if seen.contains(ref) || Int64(seen.count) > c.lim.maxRefDepth { ImportCommon.addTodo(c, where_, "cyclic_ref", "a reference chain is cyclic or too deep"); return nil }
            seen.append(ref)
            guard let t = ImportCommon.pointer(c.root, .string(ref)) else { ImportCommon.addTodo(c, where_, "unresolved_ref", "reference '\(ImportCommon.clip(.string(ref), 120))' does not resolve locally"); return nil }
            cur = t
        }
        return cur
    }

    private static func endsWithParam(_ seg: String) -> Bool {
        let u = Array(seg.utf16)
        if u.count < 3 || u[0] != 0x7B || u[u.count - 1] != 0x7D { return false }
        for ch in u[1..<(u.count - 1)] where ch == 0x0A || ch == 0x0D || ch == 0x2028 || ch == 0x2029 { return false }
        return true
    }

    /// Path to the noun tokens and whether it ends in a path parameter.
    private static func pathFacts(_ path: String) -> (nouns: [String], ewp: Bool) {
        let segs = path.components(separatedBy: "/").filter { !$0.isEmpty }
        let ewp = segs.last.map(endsWithParam) ?? false
        var nouns: [String] = []
        for s in segs where !s.contains("{") && !s.contains("}") && !Actions.fullMatch(VERSIONISH, s) { nouns += ImportCommon.tokensOf(.string(s)) }
        return (nouns, ewp)
    }

    /// A Swagger 2 parameter in the OpenAPI 3 shape the rest of the importer reads.
    private static func swagger2Param(_ p: JObject) -> JObject {
        if p[JKey("schema")] != nil || p[JKey("in")] == .string("body") { return p }
        var sch = p
        var out: JObject = [:]
        for k in ["name", "in", "required", "description"] { if let v = p[JKey(k)] { out[o: k] = v }; sch[o: k] = nil }
        out[o: "schema"] = .object(sch)
        return out
    }

    private static func lowerTrimType(_ k: String) -> String {
        let l = k.lowercased()
        let cut = l.firstIndex(of: ";").map { String(l[..<$0]) } ?? l
        return Jx.jsTrim(cut)
    }

    /// The request body schema: nil when there is none to declare (`undefined`).
    private static func bodySchemaOf(_ c: ImportCommon.Ctx, _ op: JObject, _ params: [JObject], _ swagger: Bool, _ where_: String) -> JSONValue? {
        if swagger {
            for q in params where q[JKey("in")] == .string("body") { return q[JKey("schema")] }
            return nil
        }
        let rb = deref(c, op[JKey("requestBody")], where_)
        guard case let .object(content)? = Jx.get(rb, "content") else { return nil }
        let keys = content.keys.map { $0.s }.sorted(by: utf8Less)
        var pick: String? = nil
        for t in BODY_TYPES {
            for k in keys where lowerTrimType(k) == t { pick = k; break }
            if pick != nil { break }
        }
        if pick == nil {
            for k in keys where JSON_SUFFIX.firstMatch(in: k, range: NSRange(location: 0, length: k.utf16.count)) != nil { pick = k; break }
        }
        guard let p = pick else {
            if !keys.isEmpty { ImportCommon.addTodo(c, where_, "body_type", "request body media types (" + keys.prefix(3).map { ImportCommon.clip(.string($0), 40) }.joined(separator: ", ") + ") are not form or JSON; the body is not declared") }
            return nil
        }
        return content[JKey(p)]?.asObject?[JKey("schema")]
    }

    private static func isIdemKey(_ name: String) -> Bool { name.utf16.count == 15 && name.lowercased() == "idempotency-key" && name.unicodeScalars.allSatisfy { $0.value <= 0x7f } }

    public static func importOpenApi(_ source: JSONValue?, _ opts: JObject?) throws -> JObject {
        let c = try ImportCommon.newCtx("openapi", source, opts)
        guard case let .object(src)? = source else { throw ActionKitError(code: "bad_source", message: "an OpenAPI document must be an object") }
        let swagger = src[JKey("swagger")]?.asString?.hasPrefix("2") ?? false
        let v3 = src[JKey("openapi")]?.asString?.hasPrefix("3.") ?? false
        if !swagger && !v3 { throw ActionKitError(code: "bad_source", message: "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')") }
        let paths = src[JKey("paths")]?.asObject ?? [:]
        let globalSecurity: [JSONValue]? = src[JKey("security")]?.asArray
        let ns = opts?[JKey("ns")]?.asString ?? ""
        for path in paths.keys.map({ $0.s }).sorted(by: utf8Less) {
            guard let item0 = deref(c, paths[JKey(path)], path) else { continue }
            let shared = Jx.get(item0, "parameters")?.asArray ?? []
            for method in METHODS {
                guard case let .object(op)? = Jx.get(item0, method) else { continue }
                let where_ = method.uppercased() + " " + ImportCommon.clip(.string(path), 120)
                let operationId: String? = { if let s = op[JKey("operationId")]?.asString, !s.isEmpty, s.utf16.count <= 200 { return s }; return nil }()
                let pf = pathFacts(path)
                let nameRaw: String? = c.ext.contains(.string("x-pca-verb")) ? op[JKey("x-pca-verb")]?.asString : nil
                let verb: String
                if let nr = nameRaw, Actions.fullMatch(X_VERB, nr), nr.hasPrefix(ns + ".") { verb = nr }
                else if let oid = operationId { verb = ImportCommon.verbOf(ns, .string(oid)) }
                else {
                    var w = Array(pf.nouns.suffix(2))
                    w.append(method == "get" && !pf.ewp ? "list" : method)
                    verb = ImportCommon.verbOf(ns, .string(w.joined(separator: " ")))
                }
                c.root = source
                let bud = ImportCommon.newBudget(c)
                // parameters: the operation's own win over the path item's (by in+name)
                var mergedKeys: [String] = []
                var merged: [String: JObject] = [:]
                var raws = shared
                if let own = op[JKey("parameters")]?.asArray { raws += own }
                for raw in raws {
                    guard case let .object(q0)? = deref(c, raw, where_), let qn = q0[JKey("name")]?.asString, let qi = q0[JKey("in")]?.asString else { continue }
                    let q = swagger ? swagger2Param(q0) : q0
                    let key = "\(qi):\(qn)"
                    if merged[key] == nil { mergedKeys.append(key) }
                    merged[key] = q
                }
                let all = mergedKeys.map { merged[$0]! }
                var params: JObject = [:]
                var idemParam: String? = nil
                if let body = bodySchemaOf(c, op, all, swagger, where_) {
                    let b = try ImportCommon.resolveSchema(body, c, bud, "\(where_): request body")
                    if b[JKey("type")] == .string("object") || Jx.isObj(b[JKey("properties")]) { try ImportCommon.flattenObject(b, c, bud, where_, &params) }
                    else { ImportCommon.addTodo(c, where_, "body_shape", "the request body is not an object schema; it is not declared") }
                }
                let sorted = all.sorted { utf8Less("\(Jx.str($0[JKey("in")])):\(Jx.str($0[JKey("name")]))", "\(Jx.str($1[JKey("in")])):\(Jx.str($1[JKey("name")]))") }
                for q in sorted {
                    let name = Jx.str(q[JKey("name")])
                    let inn = q[JKey("in")]
                    if inn == .string("header") && isIdemKey(name) { idemParam = "idempotency_key"; continue }
                    if inn == .string("body") { continue }
                    if inn != .string("path") && inn != .string("query") && inn != .string("formData") {
                        ImportCommon.addTodo(c, where_, "param_location", ImportCommon.clip(inn, 12) + " parameter '" + ImportCommon.clip(.string(name), 60) + "' is not an action parameter (path, query and body only)")
                        continue
                    }
                    let sname = ImportCommon.paramSeg(name)
                    if sname != name { ImportCommon.addTodo(c, "\(where_): \(name)", "renamed_param", "parameter '" + ImportCommon.clip(.string(name), 80) + "' is declared as '" + sname + "'") }
                    var taken = params[JKey(sname)] != nil
                    if !taken { for k in params.keys where k.s.hasPrefix(sname + ".") { taken = true; break } }
                    if taken {
                        ImportCommon.addTodo(c, "\(where_): \(name)", "skipped_param", "'\(sname)' is declared by the body and by a \(Jx.str(inn)) parameter; kept the body's")
                        continue
                    }
                    if params.count >= 64 { ImportCommon.addTodo(c, where_, "too_many_params", "more than 64 parameters; the rest are dropped"); break }
                    var merge: JObject = [:]
                    let qs = JS.present(q[JKey("schema")])
                    Jx.spread(&merge, qs ?? .object([:]))
                    let qsDesc: JSONValue? = qs.flatMap { Jx.get($0, "description") }
                    if Jx.truthy(q[JKey("description")]) && !Jx.truthy(qsDesc) { merge[o: "description"] = q[JKey("description")] }
                    let sch = try ImportCommon.resolveSchema(.object(merge), c, bud, "\(where_): \(name)")
                    params[o: sname] = .object(try ImportCommon.leafParam(sch, inn == .string("path") || q[JKey("required")] == .bool(true), c, bud, "\(where_): \(name)"))
                }
                if let ip = idemParam, params[JKey(ip)] == nil { params[o: ip] = .object(Jx.obj(["type": .string("string"), "required": .bool(false), "max_len": .int(255)])) } else { idemParam = nil }
                let scope = pf.ewp || method == "post" ? "one" : "set"
                let natural = NATURAL.contains(method)
                // security scopes are a note, not a field
                let sec: [JSONValue]? = op[JKey("security")]?.asArray ?? globalSecurity
                var scopes: [String] = []
                if let sec = sec {
                    for r in sec { if case let .object(ro) = r { for k in JS.keyOrder(ro) { if case let .array(v)? = ro[k] { for x in v { if let s = x.asString, !scopes.contains(s) { scopes.append(s) } } } } } }
                    scopes.sort(by: utf8Less)
                }
                if !scopes.isEmpty { ImportCommon.addTodo(c, where_, "required_scope", "requires scope: " + scopes.prefix(12).map { ImportCommon.clip(.string($0), 60) }.joined(separator: ", ")) }
                if op[JKey("deprecated")] == .bool(true) { ImportCommon.addTodo(c, where_, "deprecated", "the operation is marked deprecated") }
                for k in JS.keyOrder(op) where k.s.hasPrefix("x-") && !c.ext.contains(.string(k.s)) { ImportCommon.addTodo(c, where_, "extension_ignored", "extension '" + ImportCommon.clip(.string(k.s), 60) + "' is ignored (not allow-listed)"); break }
                var d = ImportCommon.Draft()
                d.name = .string(operationId ?? where_)
                d.noAlias = operationId == nil
                d.verb = verb
                if let s = op[JKey("summary")]?.asString, !s.isEmpty { d.title = .string(s) } else { d.title = operationId.map { .string($0) } }
                if let s = op[JKey("description")]?.asString { d.description = .string(s) } else if let s = op[JKey("summary")]?.asString { d.description = .string(s) }
                d.effects = [EFFECT_OF[method]!]
                d.scope = scope
                d.params = params
                if let ip = idemParam { d.idempotency = Jx.obj(["mode": .string("key_param"), "param": .string(ip)]) } else if natural { d.idempotency = Jx.obj(["mode": .string("natural")]) }
                d.bindings = Jx.obj(["openapi": .object(Jx.obj(["operationId": .string(operationId ?? ImportCommon.clip(.string(method + "_" + path), 200)), "method": .string(method.uppercased()), "path": .string(ImportCommon.clip(.string(path), 240))]))])
                try ImportCommon.emitDef(c, d)
            }
        }
        return ImportCommon.finish(c)
    }
}

/// MCP `tools/list` to drafts. The annotations are hints from the tool's own server and are untrusted: they can only add restriction (destructive, network
/// egress) or describe a harmless-looking shape; every output is `unreviewed`.
public enum McpImporter {
    /// `tools/list` result `{tools: [...]}`, or the tool array itself.
    public static func importMcp(_ source: JSONValue?, _ opts: JObject?) throws -> JObject {
        let c = try ImportCommon.newCtx("mcp", source, opts)
        let tools: [JSONValue]? = source?.asArray ?? source?.asObject?[JKey("tools")]?.asArray
        guard let ts = tools else { throw ActionKitError(code: "bad_source", message: "an MCP source is a tool array or a tools/list result {tools: [...]}") }
        var seen = Set<JKey>()
        for raw in ts {
            guard case let .object(t) = raw, let name = t[JKey("name")]?.asString, !name.isEmpty, name.utf16.count <= 256 else {
                ImportCommon.addTodo(c, "(tool)", "skipped_op", "an entry without a usable name is skipped")
                continue
            }
            if seen.contains(JKey(name)) { ImportCommon.addTodo(c, name, "duplicate_tool", "a tool name listed twice; the first is kept"); continue }
            seen.insert(JKey(name))
            c.root = t[JKey("inputSchema")]
            let bud = ImportCommon.newBudget(c)
            let input = try ImportCommon.resolveSchema(t[JKey("inputSchema")], c, bud, "\(name): inputSchema")
            var params: JObject = [:]
            try ImportCommon.flattenObject(input, c, bud, name, &params)
            let a = t[JKey("annotations")]?.asObject ?? [:]
            // readOnly claims safety, so it is honoured only when nothing contradicts it
            let read = a[JKey("readOnlyHint")] == .bool(true) && a[JKey("destructiveHint")] != .bool(true)
            let effects = read ? ["read"] : a[JKey("destructiveHint")] == .bool(true) ? ["update", "delete"] : ["update"]
            var d = ImportCommon.Draft()
            d.name = .string(name)
            if let s = a[JKey("title")]?.asString, !s.isEmpty { d.title = .string(s) } else { d.title = t[JKey("title")] }
            d.description = t[JKey("description")]
            d.effects = effects
            d.scope = "one"
            d.params = params
            if a[JKey("idempotentHint")] == .bool(true) { d.idempotency = Jx.obj(["mode": .string("natural")]) }
            if a[JKey("openWorldHint")] == .bool(true) { d.traits = ImportCommon.withTrait(nil, "pca.network_egress") }
            d.bindings = Jx.obj(["mcp": .object(Jx.obj(["tool": .string(ImportCommon.clip(.string(name), 256))]))])
            try ImportCommon.emitDef(c, d)
        }
        return ImportCommon.finish(c)
    }
}

/// "I have a function signature": one JSON Schema plus a verb the caller gives, to one def.
public enum JsonSchemaImporter {
    private static let EFFECTS = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"]

    /// `opts`: the common import options plus `verb` (required, in the namespace), `title`, `description`, `effects` (default update).
    public static func importJsonSchema(_ schema: JSONValue?, _ opts: JObject?) throws -> JObject {
        let c = try ImportCommon.newCtx("jsonschema", schema, opts)
        let ns = opts?[JKey("ns")]?.asString ?? ""
        guard let verb = opts?[JKey("verb")]?.asString, Actions.fullMatch(ImportCommon.VERB, verb), verb.hasPrefix(ns + ".") else { throw ActionKitError(code: "bad_verb", message: "verb must be a valid verb in namespace '\(ns)'") }
        let effO: JSONValue = JS.present(opts?[JKey("effects")]) ?? .array([.string("update")])
        guard case let .array(el) = effO, !el.isEmpty, el.allSatisfy({ $0.asString.map { EFFECTS.contains($0) } ?? false }) else { throw ActionKitError(code: "bad_effects", message: "effects must be 1+ known effects") }
        let effects = el.compactMap { $0.asString }
        guard case .object? = schema else { throw ActionKitError(code: "bad_source", message: "a JSON Schema must be an object") }
        let bud = ImportCommon.newBudget(c)
        let root = try ImportCommon.resolveSchema(schema, c, bud, verb)
        var params: JObject = [:]
        if root[JKey("type")] == .string("object") || Jx.isObj(root[JKey("properties")]) { try ImportCommon.flattenObject(root, c, bud, verb, &params) }
        else { ImportCommon.addTodo(c, verb, "not_object", "the schema is not an object schema: the def has no parameters") }
        var d = ImportCommon.Draft()
        d.name = .string(verb.components(separatedBy: ".").dropFirst().joined(separator: "_"))
        d.verb = verb
        if let t = JS.present(opts?[JKey("title")]) { d.title = t } else if case .string? = root[JKey("title")] { d.title = root[JKey("title")] }
        d.description = JS.present(opts?[JKey("description")]) ?? .string(ImportCommon.clip(root[JKey("description")], 600))
        d.effects = effects
        d.scope = "one"
        d.params = params
        d.bindings = [:]
        try ImportCommon.emitDef(c, d)
        return ImportCommon.finish(c)
    }
}

/// AsyncAPI 2.x / 3.x to drafts. Sending to a channel is effect `send`, receiving is `read`; the message payload becomes the params. A broker publish
/// leaves the trust domain, so it stays `send` unless the channel carries the allow-listed `x-pca-internal: true`.
public enum AsyncApiImporter {
    private static func deref(_ c: ImportCommon.Ctx, _ x: JSONValue?, _ where_: String, _ depth: Int = 0) -> JObject? {
        guard case let .object(m)? = x else { return nil }
        guard let ref = m[JKey("$ref")]?.asString else { return m }
        if Int64(depth) > c.lim.maxRefDepth { ImportCommon.addTodo(c, where_, "ref_depth", "a reference chain is too deep"); return nil }
        guard let t = ImportCommon.pointer(c.root, .string(ref)) else { ImportCommon.addTodo(c, where_, "unresolved_ref", "reference '\(ImportCommon.clip(.string(ref), 120))' does not resolve locally"); return nil }
        return deref(c, t, where_, depth + 1)
    }

    private static func payloadParams(_ c: ImportCommon.Ctx, _ msgs: [JSONValue], _ where_: String, _ params: inout JObject, _ bud: ImportCommon.Budget) throws {
        let resolved = msgs.compactMap { deref(c, $0, where_) }
        if resolved.isEmpty { return }
        if resolved.count > 1 { ImportCommon.addTodo(c, where_, "message_variants", "\(resolved.count) message variants: only the first is declared") }
        guard let payload = resolved[0][JKey("payload")] else { return }
        let s = try ImportCommon.resolveSchema(payload, c, bud, "\(where_): payload")
        if s[JKey("type")] == .string("object") || Jx.isObj(s[JKey("properties")]) { try ImportCommon.flattenObject(s, c, bud, where_, &params) }
        else { ImportCommon.addTodo(c, where_, "payload_shape", "the message payload is not an object schema; it is not declared") }
    }

    private static func channelParams(_ c: ImportCommon.Ctx, _ ch: JObject, _ where_: String, _ params: inout JObject) {
        guard let ps = deref(c, ch[JKey("parameters")], where_) else { return }
        for name in ps.keys.map({ $0.s }).sorted(by: utf8Less) {
            let s = ImportCommon.paramSeg(name)
            if params[JKey(s)] != nil { continue }
            params[o: s] = .object(Jx.obj(["type": .string("string"), "max_len": .int(256)]))
        }
    }

    private static func emit(_ c: ImportCommon.Ctx, _ source: JObject, _ ns: String, _ opName: String?, _ chName: String, _ ch: JObject, _ action: String, _ op: JObject, _ msgs: [JSONValue]) throws {
        let where_ = action + " " + ImportCommon.clip(.string(chName), 100)
        let bud = ImportCommon.newBudget(c)
        c.root = .object(source)
        var params: JObject = [:]
        channelParams(c, ch, where_, &params)
        try payloadParams(c, msgs, where_, &params, bud)
        let inTrust = c.ext.contains(.string("x-pca-internal")) && ch[JKey("x-pca-internal")] == .bool(true)
        var d = ImportCommon.Draft()
        d.name = .string(opName ?? where_)
        d.noAlias = opName == nil
        d.verb = opName == nil ? ImportCommon.verbOf(ns, .string("\(chName) \(action)")) : nil
        if case .string? = op[JKey("summary")] { d.title = op[JKey("summary")] }
        if case .string? = op[JKey("description")] { d.description = op[JKey("description")] }
        d.effects = [action == "receive" ? "read" : inTrust ? "create" : "send"]
        d.scope = "one"
        d.params = params
        d.bindings = Jx.obj(["asyncapi": .object(Jx.obj(["channel": .string(ImportCommon.clip(.string(chName), 250)), "op": .string(action)]))])
        try ImportCommon.emitDef(c, d)
    }

    public static func importAsyncApi(_ source: JSONValue?, _ opts: JObject?) throws -> JObject {
        let c = try ImportCommon.newCtx("asyncapi", source, opts)
        guard case let .object(src)? = source, let ver = src[JKey("asyncapi")]?.asString, ver.hasPrefix("2.") || ver.hasPrefix("3.") else {
            throw ActionKitError(code: "bad_source", message: "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')")
        }
        let ns = opts?[JKey("ns")]?.asString ?? ""
        let channels = src[JKey("channels")]?.asObject ?? [:]
        if ver.hasPrefix("3") {
            let ops = src[JKey("operations")]?.asObject ?? [:]
            for id in ops.keys.map({ $0.s }).sorted(by: utf8Less) {
                guard let op = deref(c, ops[JKey(id)], id), let action = op[JKey("action")]?.asString, action == "send" || action == "receive" else {
                    ImportCommon.addTodo(c, id, "skipped_op", "an operation without action send|receive is skipped")
                    continue
                }
                guard let chRef = deref(c, op[JKey("channel")], id) else { continue }
                let chName: String
                if let a = chRef[JKey("address")]?.asString { chName = a }
                else if case let .object(co)? = op[JKey("channel")], let r = co[JKey("$ref")]?.asString { chName = r.components(separatedBy: "/").last ?? r }
                else { chName = id }
                var msgs: [JSONValue] = []
                if let m = op[JKey("messages")]?.asArray, !m.isEmpty { msgs = m }
                else if let cm = chRef[JKey("messages")]?.asObject { msgs = cm.keys.map { $0.s }.sorted(by: utf8Less).map { cm[JKey($0)]! } }
                try emit(c, src, ns, id, chName, chRef, action, op, msgs)
            }
        } else {
            for chName in channels.keys.map({ $0.s }).sorted(by: utf8Less) {
                guard let ch = deref(c, channels[JKey(chName)], chName) else { continue }
                // 2.x: publish is what a client does to the channel (a send); subscribe is what a client receives
                for (ka, act) in [("publish", "send"), ("subscribe", "receive")] {
                    guard let op = deref(c, ch[JKey(ka)], chName) else { continue }
                    let m = deref(c, op[JKey("message")], chName)
                    let msgs: [JSONValue] = m.map { $0[JKey("oneOf")]?.asArray ?? [.object($0)] } ?? []
                    let oid: String? = { if let s = op[JKey("operationId")]?.asString, !s.isEmpty { return s }; return nil }()
                    try emit(c, src, ns, oid, chName, ch, act, op, msgs)
                }
            }
        }
        return ImportCommon.finish(c)
    }
}
