import Foundation

/// SCIM 2.0 provisioning of agents (mirrors `@atlasauth/pca-scim`): the passport -> /Agents resource mapping, a request-level
/// /Agents handler over an in-memory store (list with `attr eq "value"` filters and paging, create, replace, PATCH, delete), the
/// Entra / Okta payloads and their push. Identities are attested passports: the resource id is the passport fingerprint.
public enum PCAScim {
    public static let AGENT_SCHEMA_URN = "urn:ietf:params:scim:schemas:atlas:2.0:Agent"
    public static let LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    public static let PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    public static let ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
    public static let AGENT_RESOURCE_TYPE = "Agent"
    public static let ENTRA_AGENT_EXTENSION_URN = "urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent"
    public static let OKTA_AGENT_EXTENSION_URN = "urn:okta:scim:schemas:custom:1.0:Agent"
    static let SCIM_CONTENT_TYPE = "application/scim+json"
    static let FILTERABLE: Set<String> = ["userName", "displayName", "externalId", "id", "active", "owner"]
    static let MUTABLE_PATHS: Set<String> = ["active", "displayName", "externalId", "owner", "capabilities", "holder"]

    /// A request-level refusal: the SCIM `scimType` and the detail.
    public struct ScimValueError: Error, CustomStringConvertible {
        public let scimType: String
        public let detail: String
        public var description: String { detail }
    }

    static func s(_ v: String) -> JSONValue { .string(v) }

    // ---- dates / URIs ----

    /// Date.prototype.toISOString of `new Date(ms)` (RangeError outside the Date range).
    static func isoString(_ ms: Double) throws -> String {
        guard ms.isFinite, abs(ms) <= 8.64e15 else { throw JSError("Invalid time value") }
        let t = Int64(ms.rounded(.towardZero))
        var days = t / 86_400_000, rem = t % 86_400_000
        if rem < 0 { rem += 86_400_000; days -= 1 }
        // civil from days (Howard Hinnant)
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        let y = yoe + era * 400 + (m <= 2 ? 1 : 0)
        func p(_ v: Int64, _ n: Int) -> String { let s = String(v); return String(repeating: "0", count: max(0, n - s.count)) + s }
        let year = (0...9999).contains(y) ? p(y, 4) : (y < 0 ? "-" : "+") + p(abs(y), 6)
        return "\(year)-\(p(m, 2))-\(p(d, 2))T\(p(rem / 3_600_000, 2)):\(p(rem / 60_000 % 60, 2)):\(p(rem / 1000 % 60, 2)).\(p(rem % 1000, 3))Z"
    }

    /// encodeURIComponent.
    static func encodeURIComponent(_ v: String) -> String {
        let keep = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()".utf8)
        return v.utf8.map { keep.contains($0) ? String(UnicodeScalar($0)) : String(format: "%%%02X", $0) }.joined()
    }

    // ---- passport -> resource ----

    public struct MetaInput {
        public var baseUrl: String? = nil
        public var created: String? = nil
        public var lastModified: String? = nil
        /// Epoch ms (nil = the system clock).
        public var now: (() -> Double)? = nil
        public init() {}
    }

    static func strictHash(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }

    /// The /Agents resource of a passport under a projection (owner, displayName, externalId, active, capabilities, holder).
    public static func passportToScim(_ passport: JObject, _ proj: JObject, _ meta: MetaInput = MetaInput()) throws -> JSONValue {
        let id = passport["id"]
        var base: JObject = ["schemas": .array([s(AGENT_SCHEMA_URN)]), "passport": .object(passport)]
        if let i = id { base["id"] = i; base["passportRef"] = i }
        let dn = proj["displayName"].flatMap { $0 == .null ? nil : $0 }
        base["displayName"] = dn ?? s("\(JS.toString(passport["model_id"])) (\(JS.toString(passport["operator"])))")
        base["active"] = proj["active"].flatMap { $0 == .null ? nil : $0 } ?? .bool(true)
        if let o = proj["owner"] { base["owner"] = o }
        switch proj["capabilities"] {
        case let .array(a)?: base["capabilities"] = .array(a)
        case let .string(t)? where !t.isEmpty: base["capabilities"] = .array(t.unicodeScalars.map { s(String($0)) }) // spread of a string
        default: base["capabilities"] = .array([])
        }
        if let e = proj["externalId"] { base["externalId"] = e }
        if let h = proj["holder"] { base["holder"] = h }
        let now = meta.now ?? { Date().timeIntervalSince1970 * 1000 }
        // the reference writes `id` and `owner` into the record whether or not they exist, and its strict hash refuses an undefined member
        if id == nil || proj["owner"] == nil { throw JSError("canonicalize: unsupported type undefined") }
        let root = meta.baseUrl.map { b in String(b.reversed().drop { $0 == "/" }.reversed()) } ?? ""
        let m: JObject = ["resourceType": s(AGENT_RESOURCE_TYPE), "created": s(try meta.created ?? isoString(now())),
                          "lastModified": s(try meta.lastModified ?? isoString(now())),
                          "location": s("\(root)/Agents/\(encodeURIComponent(JS.toString(id)))"), "version": s("W/\"\(try strictHash(.object(base)))\"")]
        base["meta"] = .object(m)
        return .object(base)
    }

    // ---- request bodies ----

    static func rec(_ v: JSONValue?) -> JObject? { v?.asObject }
    static func str(_ v: JSONValue?) -> String? { v?.asString }
    static func bool(_ v: JSONValue?) -> Bool? {
        switch v {
        case let .bool(b)?: return b
        case .string("true")?: return true
        case .string("false")?: return false
        default: return nil
        }
    }
    static func strings(_ v: JSONValue?) -> [String]? {
        guard let a = v?.asArray else { return nil }
        let out = a.compactMap { $0.asString }
        return out.count == a.count ? out : nil
    }

    static func readIdentity(_ body: JObject) throws -> JObject {
        if let n = rec(body["passport"]) {
            guard let model = str(n["model_id"]), let op = str(n["operator"]) else {
                throw ScimValueError(scimType: "invalidValue", detail: "passport.model_id and passport.operator are required")
            }
            var id: JObject = ["model_id": s(model), "operator": s(op), "hardware_rooted": .bool(bool(n["hardware_rooted"]) ?? false),
                               "issued_at": n["issued_at"].flatMap { $0.isNumber ? $0 : nil } ?? .int(0)]
            for k in ["weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"] {
                if let v = str(n[JKey(k)]) { id[JKey(k)] = s(v) }
            }
            if let w = bool(n["weights_measured"]) { id["weights_measured"] = .bool(w) }
            return id
        }
        guard let model = str(body["model"]) ?? str(body["model_id"]), let op = str(body["operator"]) else {
            throw ScimValueError(scimType: "invalidValue", detail: "an Agent requires either a `passport` object or `model` + `operator`")
        }
        return ["model_id": s(model), "operator": s(op), "hardware_rooted": .bool(bool(body["hardwareRooted"]) ?? false), "issued_at": .int(0)]
    }

    static func readProjection(_ body: JObject) -> JObject {
        var p: JObject = ["owner": s(str(body["owner"]) ?? str(body["operator"]) ?? str(rec(body["passport"])?["operator"]) ?? "")]
        if let v = str(body["displayName"]) { p["displayName"] = s(v) }
        if let v = str(body["externalId"]) { p["externalId"] = s(v) }
        if let v = bool(body["active"]) { p["active"] = .bool(v) }
        if let v = strings(body["capabilities"]) { p["capabilities"] = .array(v.map(s)) }
        if let v = str(body["holder"]) { p["holder"] = s(v) }
        return p
    }

    /// {identity, projection} of a create body.
    public static func scimToProvisioningRequest(_ value: JSONValue?) throws -> JSONValue {
        guard let body = rec(value) else { throw ScimValueError(scimType: "invalidSyntax", detail: "request body must be a JSON object") }
        if let sc = body["schemas"], !(sc.asArray?.contains(s(AGENT_SCHEMA_URN)) ?? false) {
            throw ScimValueError(scimType: "invalidValue", detail: "schemas must include \(AGENT_SCHEMA_URN)")
        }
        return .object(["identity": .object(try readIdentity(body)), "projection": .object(readProjection(body))])
    }

    public static func scimError(_ status: Int, _ detail: String, _ scimType: String? = nil) -> JSONValue {
        var b: JObject = ["schemas": .array([s(ERROR_SCHEMA)]), "status": s(String(status)), "detail": s(detail)]
        if let t = scimType { b["scimType"] = s(t) }
        return .object(b)
    }

    public static func scimListResponse(_ resources: [JSONValue], _ totalResults: JSONValue, _ startIndex: JSONValue) -> JSONValue {
        .object(["schemas": .array([s(LIST_RESPONSE_SCHEMA)]), "totalResults": totalResults, "startIndex": startIndex,
                 "itemsPerPage": .int(Int64(resources.count)), "Resources": .array(resources)])
    }

    // ---- filters ----

    static func isWord(_ u: Unicode.Scalar) -> Bool { u.isASCII && (u.properties.isAlphabetic || ("0"..."9").contains(u) || u == "_") }
    static func isLineTerminator(_ u: Unicode.Scalar) -> Bool { u == "\n" || u == "\r" || u == "\u{2028}" || u == "\u{2029}" }

    /// `attr eq "value"` / `attr eq true|false` (only the filterable attributes): (attr, value).
    public static func parseFilter(_ filter: JSONValue?) throws -> (attr: String, value: JSONValue) {
        guard let f = filter?.asString else { throw ScimValueError(scimType: "invalidFilter", detail: "filter must be a string") }
        let bad = ScimValueError(scimType: "invalidFilter", detail: "unsupported filter (only `attr eq \"value\"` is supported): \(f)")
        let u = Array(f.unicodeScalars)
        var i = 0
        func spaces() -> Int { let s = i; while i < u.count, Attest.isJSSpace(u[i]) { i += 1 }; return i - s }
        _ = spaces()
        let a0 = i
        while i < u.count, isWord(u[i]) { i += 1 }
        guard i > a0 else { throw bad }
        let attr = String(String.UnicodeScalarView(u[a0..<i]))
        guard spaces() > 0, i + 2 <= u.count, String(String.UnicodeScalarView(u[i..<(i + 2)])).lowercased() == "eq" else { throw bad }
        i += 2
        guard spaces() > 0, i < u.count else { throw bad }
        var value: JSONValue
        if u[i] == "\"" {
            i += 1
            var raw = String.UnicodeScalarView()
            var closed = false
            while i < u.count {
                let c = u[i]
                if c == "\\" {
                    guard i + 1 < u.count, !isLineTerminator(u[i + 1]) else { throw bad }
                    raw.append(u[i + 1]) // `\\(.)` -> `$1`
                    i += 2
                } else if c == "\"" {
                    i += 1; closed = true; break
                } else {
                    raw.append(c); i += 1
                }
            }
            guard closed else { throw bad }
            value = .string(String(raw))
        } else {
            let rest = String(String.UnicodeScalarView(u[i...])).lowercased()
            if rest.hasPrefix("true") { value = .bool(true); i += 4 } else if rest.hasPrefix("false") { value = .bool(false); i += 5 } else { throw bad }
        }
        _ = spaces()
        guard i == u.count else { throw bad }
        guard FILTERABLE.contains(attr) else { throw ScimValueError(scimType: "invalidFilter", detail: "filter attribute not supported: \(attr)") }
        return (attr, value)
    }

    static func matches(_ a: JObject, _ attr: String, _ v: JSONValue) -> Bool {
        let k: String
        switch attr {
        case "userName", "displayName": k = "displayName"
        case "externalId", "id", "owner", "active": k = attr
        default: return false
        }
        return PCASdJwt.strictEq(a[JKey(k)], v)
    }

    // ---- store + handler ----

    /// An insertion-ordered store of {resource, passport} by resource id (replacing keeps the position).
    public final class MemoryStore {
        var order: [String] = []
        var byId: [String: (resource: JObject, passport: JObject)] = [:]
        public init() {}
        public func all() -> [(resource: JObject, passport: JObject)] { order.compactMap { byId[$0] } }
        public func get(_ id: JSONValue?) -> (resource: JObject, passport: JObject)? { id?.asString.flatMap { byId[$0] } }
        public func put(_ resource: JObject, _ passport: JObject) {
            let id = JS.toString(resource["id"])
            if byId[id] == nil { order.append(id) }
            byId[id] = (resource, passport)
        }
        public func delete(_ id: JSONValue?) -> Bool {
            guard let i = id?.asString, byId.removeValue(forKey: i) != nil else { return false }
            order.removeAll { $0 == i }
            return true
        }
    }

    static func json(_ status: Int, _ body: JSONValue?, _ extra: JObject = [:]) -> JSONValue {
        var h: JObject = ["content-type": s(SCIM_CONTENT_TYPE)]
        for (k, v) in extra { h[k] = v }
        var r: JObject = ["status": .int(Int64(status)), "headers": .object(h)]
        if let b = body { r["body"] = b }
        return .object(r)
    }
    static func error(_ status: Int, _ detail: String, _ scimType: String? = nil) -> JSONValue { json(status, scimError(status, detail, scimType)) }
    static func error(_ e: ScimValueError) -> JSONValue { error(400, e.detail, e.scimType) }
    static func resource(_ status: Int, _ r: JSONValue) -> JSONValue {
        json(status, r, ["location": r.get("meta")?.get("location") ?? .null, "etag": r.get("meta")?.get("version") ?? .null])
    }

    static func intParam(_ v: JSONValue?, _ fallback: Double) -> Double {
        guard let x = v else { return fallback }
        let n = JS.toNumber(x)
        return n.isFinite && n == n.rounded(.towardZero) ? n : fallback
    }

    static func page(_ items: [JSONValue], start: Double, count: Double?) -> [JSONValue] {
        let n = Double(items.count)
        let lo = min(max(start - 1, 0), n)
        let hi = count.map { min(max(start - 1 + $0, 0), n) } ?? n
        return lo < hi ? Array(items[Int(lo)..<Int(hi)]) : []
    }

    /// A request-level /Agents handler. Requests are {method, id?, query?, body?}; responses {status, body?, headers}.
    public final class Handler {
        let store: MemoryStore
        let authenticate: ((JSONValue) throws -> Bool)?
        let baseUrl: String?
        let now: (() -> Double)?

        /// `authenticate` (true admits the request) is required unless `allowUnauthenticated` is set explicitly.
        public init(store: MemoryStore, authenticate: ((JSONValue) throws -> Bool)?, allowUnauthenticated: Bool = false,
                    baseUrl: String? = nil, now: (() -> Double)? = nil) throws {
            if authenticate == nil && !allowUnauthenticated {
                throw JSError("scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)")
            }
            self.store = store; self.authenticate = authenticate; self.baseUrl = baseUrl; self.now = now
        }

        func meta() -> MetaInput {
            var m = MetaInput()
            m.baseUrl = baseUrl
            m.now = now
            return m
        }

        func list(_ q: JSONValue?) throws -> JSONValue {
            var items = store.all().map { JSONValue.object($0.resource) }
            let qo = q?.asObject
            if let f = qo?["filter"], f != .string("") {
                let p: (attr: String, value: JSONValue)
                do { p = try parseFilter(f) } catch let e as ScimValueError { return error(e) }
                items = items.filter { matches($0.asObject ?? [:], p.attr, p.value) }
            }
            let total = Double(items.count)
            let start = max(1, intParam(qo?["startIndex"], 1))
            let count = qo?["count"].map { max(0, intParam($0, total)) }
            return json(200, scimListResponse(page(items, start: start, count: count), PCASdJwt.jnum(total), PCASdJwt.jnum(start)))
        }

        func create(_ body: JSONValue?) throws -> JSONValue {
            let req: JSONValue
            do { req = try scimToProvisioningRequest(body) } catch let e as ScimValueError { return error(e) }
            let passport = try PCAIssue.issuePassport(req.get("identity")?.asObject ?? [:])
            let id = passport["id"]
            if store.get(id) != nil {
                return error(409, "an agent with this attested identity already exists (id \(JS.toString(id)))", "uniqueness")
            }
            let r = try passportToScim(passport, req.get("projection")?.asObject ?? [:], meta())
            store.put(r.asObject ?? [:], passport)
            return resource(201, r)
        }

        func rematerialize(_ existing: (resource: JObject, passport: JObject), _ proj: JObject) throws -> JSONValue {
            var m = meta()
            m.created = existing.resource["meta"]?.get("created")?.asString
            let r = try passportToScim(existing.passport, proj, m)
            store.put(r.asObject ?? [:], existing.passport)
            return resource(200, r)
        }

        func replace(_ id: JSONValue?, _ body: JSONValue?) throws -> JSONValue {
            guard let existing = store.get(id) else { return error(404, "Agent \(JS.toString(id)) not found") }
            guard let b = rec(body) else { return error(400, "request body must be a JSON object", "invalidSyntax") }
            var proj = readProjection(b)
            if proj["owner"] == s("") { proj["owner"] = existing.resource["owner"] }
            return try rematerialize(existing, proj)
        }

        func patch(_ id: JSONValue?, _ body: JSONValue?) throws -> JSONValue {
            guard let existing = store.get(id) else { return error(404, "Agent \(JS.toString(id)) not found") }
            let r = existing.resource
            var proj: JObject = ["owner": r["owner"] ?? .null, "active": r["active"] ?? .null, "capabilities": r["capabilities"] ?? .array([])]
            for k in ["displayName", "externalId", "holder"] { if let v = r[JKey(k)] { proj[JKey(k)] = v } }
            if r["owner"] == nil { proj["owner"] = nil }
            do {
                for op in try readPatchOps(body) { try applyPatchOp(&proj, op) }
            } catch let e as ScimValueError {
                return error(e)
            }
            return try rematerialize(existing, proj)
        }

        /// The response to one request. Throws only where the reference throws (a value that cannot be canonically hashed).
        public func handle(_ req: JSONValue) throws -> JSONValue {
            if let auth = authenticate {
                let ok = (try? auth(req)) ?? false
                if !ok {
                    var e = error(401, "authentication required").asObject ?? [:]
                    e["headers"] = .object(["content-type": s(SCIM_CONTENT_TYPE), "www-authenticate": s("Bearer")])
                    return .object(e)
                }
            }
            let id = req.get("id"), body = req.get("body")
            switch req.get("method") {
            case .string("GET")?:
                guard let i = id else { return try list(req.get("query")) }
                guard let e = store.get(i) else { return error(404, "Agent \(JS.toString(i)) not found") }
                return resource(200, .object(e.resource))
            case .string("POST")?:
                if id != nil { return error(405, "POST is not allowed on an individual Agent") }
                return try create(body)
            case .string("PUT")?:
                if id == nil { return error(405, "PUT requires an Agent id") }
                return try replace(id, body)
            case .string("PATCH")?:
                if id == nil { return error(405, "PATCH requires an Agent id") }
                return try patch(id, body)
            case .string("DELETE")?:
                if id == nil { return error(405, "DELETE requires an Agent id") }
                if !store.delete(id) { return error(404, "Agent \(JS.toString(id)) not found") }
                return .object(["status": .int(204), "headers": .object([:])])
            default:
                return error(405, "method not allowed: \(JS.toString(req.get("method")))")
            }
        }
    }

    // ---- PATCH ----

    struct PatchOp { let op: String; let path: String?; let value: JSONValue? }

    static func readPatchOps(_ value: JSONValue?) throws -> [PatchOp] {
        guard let body = rec(value) else { throw ScimValueError(scimType: "invalidSyntax", detail: "PATCH body must be a JSON object") }
        guard let ops = body["Operations"]?.asArray, !ops.isEmpty else {
            throw ScimValueError(scimType: "invalidValue", detail: "PATCH requires a non-empty Operations array")
        }
        return try ops.map { raw in
            let o = rec(raw)
            let op = str(o?["op"])?.lowercased()
            guard let p = op, p == "add" || p == "replace" || p == "remove" else {
                throw ScimValueError(scimType: "invalidValue", detail: "unsupported PATCH op: \(JS.toString(o?["op"]))")
            }
            return PatchOp(op: p, path: str(o?["path"]), value: o?["value"])
        }
    }

    static func applyScalar(_ proj: inout JObject, _ path: String, _ op: String, _ value: JSONValue?) throws {
        switch path {
        case "active":
            if op == "remove" { proj["active"] = .bool(true); return }
            guard let b = bool(value) else { throw ScimValueError(scimType: "invalidValue", detail: "`active` must be a boolean") }
            proj["active"] = .bool(b)
        case "capabilities":
            if op == "remove" { proj["capabilities"] = .array([]); return }
            guard let arr = strings(value) else { throw ScimValueError(scimType: "invalidValue", detail: "`capabilities` must be a string array") }
            proj["capabilities"] = .array((op == "add" ? (proj["capabilities"]?.asArray ?? []) : []) + arr.map(s))
        default:
            if op == "remove" {
                if path == "displayName" || path == "owner" { throw ScimValueError(scimType: "mutability", detail: "`\(path)` cannot be removed") }
                proj[JKey(path)] = nil // externalId / holder
                return
            }
            guard let v = str(value) else { throw ScimValueError(scimType: "invalidValue", detail: "`\(path)` must be a string") }
            proj[JKey(path)] = s(v)
        }
    }

    /// Object.keys order where the vector keeps it: integer keys ascending, then the rest (insertion order is not kept by a parsed
    /// object, so they follow in code-unit order; it only decides which of several bad keys is reported).
    static func keyOrder(_ o: JObject) -> [String] {
        let ks = o.keys.map { $0.s }
        let idx = ks.filter { JS.indexKey($0) != nil }.sorted { JS.indexKey($0)! < JS.indexKey($1)! }
        return idx + ks.filter { JS.indexKey($0) == nil }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
    }

    static func applyPatchOp(_ proj: inout JObject, _ op: PatchOp) throws {
        guard let path = op.path else {
            if op.op == "remove" { throw ScimValueError(scimType: "noTarget", detail: "a `remove` op requires a `path`") }
            guard let obj = rec(op.value) else { throw ScimValueError(scimType: "invalidValue", detail: "a pathless PATCH value must be an object") }
            for key in keyOrder(obj) {
                guard MUTABLE_PATHS.contains(key) else { throw ScimValueError(scimType: "mutability", detail: "attribute is immutable or unknown: \(key)") }
                try applyScalar(&proj, key, "replace", obj[JKey(key)])
            }
            return
        }
        guard MUTABLE_PATHS.contains(path) else { throw ScimValueError(scimType: "mutability", detail: "attribute is immutable or unknown: \(path)") }
        try applyScalar(&proj, path, op.op, op.value)
    }

    // ---- registry ----

    /// Passports by id (a later passport with the same id replaces the earlier one in place).
    public static func buildRegistry(_ passports: [JObject]) -> [JObject] {
        var order: [String] = [], byId: [String: JObject] = [:]
        for p in passports {
            let id = JS.toString(p["id"])
            if byId[id] == nil { order.append(id) }
            byId[id] = p
        }
        return order.compactMap { byId[$0] }
    }

    // ---- Entra / Okta ----

    static func put(_ o: inout JObject, _ k: String, _ v: JSONValue?) { if let x = v { o[JKey(k)] = x } }

    static func extensionAttributes(_ a: JObject) -> JSONValue {
        let p = a["passport"]
        var x: JObject = ["capabilities": a["capabilities"] ?? .array([])]
        put(&x, "owner", a["owner"]); put(&x, "model", p?.get("model_id")); put(&x, "operator", p?.get("operator"))
        put(&x, "hardwareRooted", p?.get("hardware_rooted")); put(&x, "passportRef", a["passportRef"]); put(&x, "holder", a["holder"])
        return .object(x)
    }
    static let PAYLOAD_ORDER = ["schemas", "userName", "externalId", "displayName", "active", ENTRA_AGENT_EXTENSION_URN, OKTA_AGENT_EXTENSION_URN,
                                "owner", "model", "operator", "hardwareRooted", "capabilities", "passportRef", "holder"]

    static func payload(_ a: JObject, _ urn: String, userName: Bool) -> JSONValue {
        var o: JObject = ["schemas": .array([s(AGENT_SCHEMA_URN), s(urn)]), JKey(urn): extensionAttributes(a)]
        if userName { put(&o, "userName", a["passportRef"]) }
        put(&o, "externalId", a["externalId"].flatMap { $0 == .null ? nil : $0 } ?? a["passportRef"])
        put(&o, "displayName", a["displayName"]); put(&o, "active", a["active"])
        return .object(o)
    }

    public static func toEntraAgentPayload(_ a: JObject) -> JSONValue { payload(a, ENTRA_AGENT_EXTENSION_URN, userName: false) }
    public static func toOktaScimPayload(_ a: JObject) -> JSONValue { payload(a, OKTA_AGENT_EXTENSION_URN, userName: true) }

    /// One HTTP exchange: (url, method, headers, body) -> (ok, status, json). `json` throwing means no JSON body.
    public typealias Fetch = (_ url: String, _ method: String, _ headers: [(String, String)], _ body: String) throws -> (ok: Bool, status: Int, json: () throws -> JSONValue)

    /// POST the payload (bearer token) and return {ok, status, body}.
    public static func pushProvision(_ payload: JSONValue, endpoint: String, token: String, fetch: Fetch) throws -> JSONValue {
        let res = try fetch(endpoint, "POST", [("authorization", "Bearer \(token)"), ("content-type", SCIM_CONTENT_TYPE)], JS.stringify(payload, order: PAYLOAD_ORDER))
        let body = (try? res.json()) ?? .null
        return .object(["ok": .bool(res.ok), "status": .int(Int64(res.status)), "body": body])
    }
}
