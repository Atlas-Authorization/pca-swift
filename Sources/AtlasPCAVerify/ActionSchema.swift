import Foundation

/// Signed action schemas, closed world (Intent Layer v2 V1; conformance rule 14). Mirrors
/// `packages/pca/src/action-schema.ts`: the `pca-action-schema` v1 shape, the site signature under the discovery key whose
/// `kid` matches (the suite is pinned by the KEY entry), the content address, and `conformAction` (the ordered ⊠ rules).
enum ActionSchema {
    static let DOMAIN = "atlas-pca/action-schema/v1\u{0}"
    static let REF_DOMAIN = "atlas-pca/action-schema-ref/v1"
    static let KIND = "pca-action-schema"
    static let MAX_VERBS = 256
    static let MAX_PARAMS = 64
    static let MAX_VALUES = 256
    static let DEFAULT_MAX_LEN: Int64 = 1024
    static let DEFAULT_MAX_ITEMS: Int64 = 64
    static let SENSITIVITIES = ["free", "material", "critical"]
    static let REVERSIBILITY = ["reversible", "rate_limited", "irreversible"]
    static let PARAM_TYPES = ["string", "integer", "boolean", "date", "set", "array"]
    static let DOC_KEYS = ["v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig"]
    static let VERB_KEYS = ["verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description"]
    static let PARAM_KEYS = ["type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items", "min_items", "max_items",
                             "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description"]
    static let SIG_KEYS = ["alg", "kid", "value", "pq_value"]

    private static func has(_ list: [String], _ k: JKey) -> Bool { list.contains { JKey($0) == k } }
    private static func isIn(_ list: [String], _ v: JSONValue?) -> Bool { v?.asString.map { IV.contains(list, $0) } ?? false }
    /// `isStr(v, max)`: a non-empty string without a lone surrogate of at most `max` UTF-8 bytes.
    private static func isStr(_ v: JSONValue?, _ max: Int = 256) -> Bool {
        guard let s = v?.asString else { return false }
        return !s.isEmpty && !Canonical.hasLoneSurrogate(s) && IV.u8(s) <= max
    }
    private static func strings(_ v: JSONValue?) -> [String]? {
        guard case let .array(a)? = v else { return nil }
        var out: [String] = []
        for x in a { guard let s = x.asString else { return nil }; out.append(s) }
        return out
    }

    static func paramDeclError(_ path: String, _ dv: JSONValue, _ units: JObject?) -> String? {
        if !IV.isTopParamPath(path) { return "parameter path '\(path)' is not action.params.<name>" }
        if IV.isReserved(IV.dropPrefix(path, 14)) { return "parameter name '\(path)' is reserved (__proto__ / constructor / prototype)" }
        guard case let .object(d) = dv else { return "\(path): declaration must be an object" }
        for k in d.keys where !has(PARAM_KEYS, k) { return "\(path): unknown member '\(k.s)'" }
        if !isIn(PARAM_TYPES, d["type"]) { return "\(path): unknown type" }
        let type = d["type"]!.asString!
        if !isStr(d["semantic"], 128) { return "\(path): semantic must be a non-empty string" }
        if !isIn(SENSITIVITIES, d["sensitivity"]) { return "\(path): unknown sensitivity" }
        if let r = d["required"], case .bool = r {} else if d["required"] != nil { return "\(path): required must be a boolean" }
        if let vv = d["values"] {
            guard let vs = strings(vv), !vs.isEmpty, vs.count <= MAX_VALUES, vs.allSatisfy({ isStr(.string($0)) }) else {
                return "\(path): values must be 1..\(MAX_VALUES) strings"
            }
            if !IV.distinct(vs) { return "\(path): values must be distinct" }
            if type != "string" && type != "set" { return "\(path): values apply to string and set only" }
        }
        if type == "set" && d["values"] == nil { return "\(path): a set needs values" }
        let itemsInteger = d["items"]?.asString.map { IV.same($0, "integer") } ?? false
        for k in ["min", "max"] {
            if let x = d[JKey(k)], IV.int(x) == nil || (type != "integer" && !(type == "array" && itemsInteger)) {
                return "\(path): \(k) must be a safe integer on an integer parameter"
            }
        }
        if let lo = IV.int(d["min"]), let hi = IV.int(d["max"]), lo > hi { return "\(path): min > max" }
        if let u = d["unit"] {
            guard type == "integer", let us = u.asString, let units = units, units[JKey(us)] != nil else {
                return "\(path): unit must name a declared unit of an integer parameter"
            }
        }
        if let ml = d["max_len"], (IV.int(ml) ?? 0) < 1 { return "\(path): max_len must be a positive safe integer" }
        if let it = d["items"], type != "array" || !isStr(it, 64) { return "\(path): items applies to array only" }
        for k in ["min_items", "max_items"] {
            if let x = d[JKey(k)], IV.nonNeg(x) == nil || (type != "set" && type != "array") {
                return "\(path): \(k) must be a non-negative safe integer on a set or array"
            }
        }
        if let lo = IV.int(d["min_items"]), let hi = IV.int(d["max_items"]), lo > hi { return "\(path): min_items > max_items" }
        if d["default"] == .null { return "\(path): default must not be null (absent = no default)" }
        if let p = d["principal_neutral_default"] {
            guard case let .bool(b) = p else { return "\(path): principal_neutral_default must be a boolean" }
            if b && d["default"] == nil { return "\(path): principal_neutral_default needs a default" }
        }
        if let ai = d["accumulates_into"] {
            if type != "integer" { return "\(path): accumulates_into applies to integer parameters only" }
            guard case let .array(a) = ai, !a.isEmpty, a.count <= 8 else { return "\(path): accumulates_into must be 1..8 unit ids" }
            let us = a.compactMap { $0.asString }
            if us.count != a.count || !us.allSatisfy({ IV.u16($0) <= 64 && IV.isUnitId($0) }) { return "\(path): accumulates_into entries must be unit ids" }
            if !IV.distinct(us) { return "\(path): accumulates_into must be distinct" }
        }
        if let x = d["issued_by_site"], case .bool = x {} else if d["issued_by_site"] != nil { return "\(path): issued_by_site must be a boolean" }
        if let x = d["description"], !isStr(x, 1024) { return "\(path): description must be a string" }
        return nil
    }

    static func verbDeclError(_ vv: JSONValue, _ units: JObject?) -> String? {
        guard case let .object(v) = vv else { return "verb entry must be an object" }
        for k in v.keys where !has(VERB_KEYS, k) { return "verb entry: unknown member '\(k.s)'" }
        if !isStr(v["verb"], 128) { return "verb entry: verb must be a non-empty string" }
        let at = "verb '\(v["verb"]!.asString!)'"
        if !isIn(["read", "write"], v["kind"]) { return "\(at): kind must be read or write" }
        guard case let .object(params)? = v["params"] else { return "\(at): params must be an object" }
        if params.count > MAX_PARAMS { return "\(at): more than \(MAX_PARAMS) parameters" }
        for (p, d) in params.sorted(by: { $0.key < $1.key }) {
            if let e = paramDeclError(p.s, d, units) { return "\(at): \(e)" }
        }
        if let r = v["reversibility"], !isIn(REVERSIBILITY, r) { return "\(at): unknown reversibility" }
        if let rbv = v["reversibility_by"] {
            guard case let .object(r) = rbv, r.keys.allSatisfy({ has(["param", "map", "default"], $0) }) else {
                return "\(at): reversibility_by must be {param, map, default?}"
            }
            guard let rp = r["param"]?.asString, params[JKey(rp)] != nil else { return "\(at): reversibility_by.param must be a declared parameter" }
            guard case let .object(m)? = r["map"], !m.isEmpty, m.values.allSatisfy({ isIn(REVERSIBILITY, $0) }) else {
                return "\(at): reversibility_by.map must map values to reversibility classes"
            }
            if let dft = r["default"], !isIn(REVERSIBILITY, dft) { return "\(at): reversibility_by.default is not a reversibility class" }
        }
        if let m = v["mcp"] {
            guard case let .object(o) = m, o.count == 1, isStr(o["tool"], 128) else { return "\(at): mcp must be {tool}" }
        }
        if let m = v["openapi"] {
            guard case let .object(o) = m, o.count == 1, isStr(o["operationId"], 128) else { return "\(at): openapi must be {operationId}" }
        }
        for k in ["harm", "effects", "returns"] {
            if let x = v[JKey(k)], !x.isObject { return "\(at): \(k) must be an object" }
        }
        if let w = v["world"], !w.isArray { return "\(at): world must be an array" }
        if let x = v["description"], !isStr(x, 1024) { return "\(at): description must be a string" }
        return nil
    }

    /// `actionSchemaShapeError(doc)` (signed). nil = well-formed.
    static func shapeError(_ docV: JSONValue) -> String? {
        guard case let .object(doc) = docV else { return "schema is not an object" }
        for k in doc.keys where !has(DOC_KEYS, k) { return "unknown member '\(k.s)'" }
        if IV.num(doc["v"]) != 1 { return "unsupported schema version" }
        if !IV.same(doc["kind"]?.asString, KIND) { return "kind must be '\(KIND)'" }
        if !isStr(doc["site"], 2048) || !isStr(doc["aud"], 256) || !isStr(doc["version"], 128) { return "site, aud and version must be non-empty strings" }
        var units: JObject?
        if let uv = doc["units"] {
            guard case let .object(u) = uv else { return "units must be an object" }
            units = u
            for (id, x) in u {
                if !IV.isUnitId(id.s) || IV.u16(id.s) > 64 { return "unit id '\(id.s)' is malformed" }
                guard case let .object(uo) = x, isStr(uo["kind"], 64) else { return "unit '\(id.s)' must be an object with a kind" }
                if !uo.keys.allSatisfy({ has(["kind", "currency", "exponent"], $0) }) { return "unit '\(id.s)': unknown member" }
                if let c = uo["currency"], !isStr(c, 16) { return "unit '\(id.s)': currency must be a string" }
                if let e = uo["exponent"], !((IV.nonNeg(e) ?? 99) <= 18) { return "unit '\(id.s)': exponent must be an integer in [0, 18]" }
            }
        }
        if let s = doc["state"], !s.isArray { return "state must be an array" }
        guard case let .array(verbs)? = doc["verbs"], !verbs.isEmpty, verbs.count <= MAX_VERBS else { return "verbs must be 1..\(MAX_VERBS) entries" }
        var seen = Set<JKey>()
        for v in verbs {
            if let e = verbDeclError(v, units) { return e }
            let name = JKey(v.get("verb")!.asString!)
            if !seen.insert(name).inserted { return "verb '\(name.s)' is declared twice" }
        }
        guard case let .object(s)? = doc["sig"] else { return "sig must be an object" }
        for k in s.keys where !has(SIG_KEYS, k) { return "sig: unknown member '\(k.s)'" }
        if let se = IV.suiteError(s["alg"]) { return "sig.alg: \(se)" }
        if !isStr(s["kid"], 128) { return "sig.kid must be a non-empty string" }
        if !(s["value"]?.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "sig.value is not canonical base64url" }
        if let pv = s["pq_value"], !(pv.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "sig.pq_value is not canonical base64url" }
        var body = doc
        body["sig"] = nil
        if let ce = IV.strictCanonError(.object(body)) { return "malformed schema: \(ce)" }
        return nil
    }

    static func message(_ doc: JObject) -> [UInt8]? {
        var body = doc
        body["sig"] = nil
        return IV.message(DOMAIN, .object(body))
    }

    /// `verifyActionSchema(doc, keys)`: shape, `sig.kid` names a listed key, `sig.alg` equals that key's `alg`, signature.
    static func verify(_ docV: JSONValue, keys: JSONValue?) -> (ok: Bool, reason: String) {
        if let e = shapeError(docV) { return (false, e) }
        guard case let .object(doc) = docV, case let .object(sig)? = doc["sig"], let kid = sig["kid"]?.asString else { return (false, "malformed schema") }
        guard case let .array(ks)? = keys else { return (false, "the schema keys must be an array") }
        var key: JObject?
        for k in ks { if case let .object(o) = k, IV.same(o["kid"]?.asString, kid) { key = o; break } }
        guard let k = key else { return (false, "no schema key with kid '\(kid)'") }
        if let pq = k["pq_pk"], pq.asString == nil { return (false, "the schema key pq_pk must be a string") }
        guard let pk = k["pk"]?.asString, Base64URLStrict.isValid(pk, length: 32) else { return (false, "schema key pk is not canonical base64url (32 bytes)") }
        if let kse = IV.suiteError(k["alg"]) { return (false, "schema key: \(kse)") }
        guard let ka = IV.sigAlg(k["alg"]), ka == IV.sigAlg(sig["alg"]) else { return (false, "sig.alg does not match the pinned key suite") }
        guard let msg = message(doc) else { return (false, "malformed schema") }
        let pin = k["pq_pk"].map { $0.asString ?? "" }
        switch IV.verifyPinned(alg: .string(ka), identity: pk, artifactPqPk: k["pq_pk"], msg: msg, sig: sig["value"], pqSig: sig["pq_value"], pin: pin) {
        case .valid: break
        case .unsupported: return (false, IV.UNSUPPORTED_SUITE)
        case .invalid: return (false, "schema signature invalid")
        }
        return (true, "")
    }

    /// `actionSchemaDigest(doc)` = base64url(sha256(strictCanonical({d, s: doc}))); nil where the reference throws.
    static func digest(_ doc: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(REF_DOMAIN), "s": doc]))
    }

    /// `schemaVerb(doc, verb)`: the first verb entry named `verb` (a string), as an object.
    static func verb(_ doc: JSONValue, _ verb: String) -> JObject? {
        guard case let .array(vs)? = doc.get("verbs") else { return nil }
        for v in vs {
            if case let .object(o) = v, IV.same(o["verb"]?.asString, verb) { return o }
        }
        return nil
    }

    // ---- conformance (⊠) ----

    /// `isCalendarDate`: `^(\d{4})-(\d{2})-(\d{2})$`, years 0001-9999, Gregorian leap rule.
    static func isCalendarDate(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        guard u.count == 10, u[4] == "-", u[7] == "-" else { return false }
        func digits(_ r: Range<Int>) -> Int? {
            var n = 0
            for k in r { guard u[k].value >= 0x30 && u[k].value <= 0x39 else { return nil }; n = n * 10 + Int(u[k].value - 0x30) }
            return n
        }
        guard let y = digits(0..<4), let mo = digits(5..<7), let d = digits(8..<10) else { return false }
        if y < 1 || mo < 1 || mo > 12 || d < 1 { return false }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
        return d <= dim
    }

    /// `paramValueViolation(d, x)`: nil = in the declared domain, else (code, reason).
    static func valueViolation(_ d: JObject, _ x: JSONValue) -> (String, String)? {
        let maxLen = IV.num(d["max_len"]) ?? Double(DEFAULT_MAX_LEN)
        let maxLenText = d["max_len"].map { IntentV2.jsString($0) } ?? String(DEFAULT_MAX_LEN)
        func strOk(_ e: JSONValue) -> Bool {
            guard case let .string(s) = e else { return false }
            return !Canonical.hasLoneSurrogate(s) && Double(IV.u8(s)) <= maxLen
        }
        let values = strings(d["values"])
        switch d["type"]?.asString ?? "" {
        case "string":
            guard case let .string(s) = x, !Canonical.hasLoneSurrogate(s) else { return ("bad_type", "expected a string") }
            if Double(IV.u8(s)) > maxLen { return ("out_of_domain", "longer than \(maxLenText) UTF-8 bytes") }
            if let vs = values, !IV.contains(vs, s) { return ("out_of_domain", "not one of the declared values") }
            return nil
        case "integer":
            guard let i = IV.int(x) else { return ("bad_type", "expected a safe integer") }
            if let lo = IV.num(d["min"]), Double(i) < lo { return ("out_of_domain", "below min \(IntentV2.jsString(d["min"]!))") }
            if let hi = IV.num(d["max"]), Double(i) > hi { return ("out_of_domain", "above max \(IntentV2.jsString(d["max"]!))") }
            return nil
        case "boolean":
            if case .bool = x { return nil }
            return ("bad_type", "expected a boolean")
        case "date":
            guard case let .string(s) = x else { return ("bad_type", "expected a YYYY-MM-DD string") }
            return isCalendarDate(s) ? nil : ("out_of_domain", "not a calendar date YYYY-MM-DD")
        case "set":
            guard case let .array(a) = x else { return ("bad_type", "expected an array of strings") }
            let ss = a.compactMap { $0.asString }
            if ss.count != a.count { return ("bad_type", "expected an array of strings") }
            if !IV.distinct(ss) { return ("out_of_domain", "set members must be distinct") }
            let vs = values ?? []
            if !ss.allSatisfy({ IV.contains(vs, $0) }) { return ("out_of_domain", "set member not among the declared values") }
            let lo = IV.num(d["min_items"]) ?? 0, hi = IV.num(d["max_items"]) ?? Double(vs.count)
            if Double(ss.count) < lo || Double(ss.count) > hi { return ("out_of_domain", "set size outside the declared bounds") }
            return nil
        case "array":
            guard case let .array(a) = x else { return ("bad_type", "expected an array") }
            let ints = d["items"]?.asString.map { IV.same($0, "integer") } ?? false
            for e in a {
                if ints ? IV.int(e) == nil : !strOk(e) {
                    return ("bad_type", ints ? "array items must be safe integers" : "array items must be strings of at most \(maxLenText) UTF-8 bytes")
                }
                if ints, let i = IV.int(e) {
                    if let lo = IV.num(d["min"]), Double(i) < lo { return ("out_of_domain", "array item outside min/max") }
                    if let hi = IV.num(d["max"]), Double(i) > hi { return ("out_of_domain", "array item outside min/max") }
                }
            }
            let lo = IV.num(d["min_items"]) ?? 0, hi = IV.num(d["max_items"]) ?? Double(DEFAULT_MAX_ITEMS)
            if Double(a.count) < lo || Double(a.count) > hi { return ("out_of_domain", "array length outside the declared bounds") }
            return nil
        default:
            return ("bad_type", "unknown declared type")
        }
    }

    /// `conformAction(doc, verb, params)`: (ok, code, path). First failure wins: params_not_object; unknown_verb; an
    /// undeclared key (UTF-8 order); then every declared path in UTF-8 order: missing_param / bad_type / out_of_domain.
    static func conform(_ doc: JSONValue, verb: String, params: JSONValue) -> (ok: Bool, code: String, path: String?, reason: String) {
        guard case let .object(p) = params else { return (false, "params_not_object", nil, "params must be a JSON object") }
        guard let v = self.verb(doc, verb), case let .object(decl)? = v["params"] else { return (false, "unknown_verb", nil, "verb '\(verb)' is not declared by the schema") }
        for k in p.keys.sorted() {
            let path = "action.params." + k.s
            if decl[JKey(path)] == nil { return (false, "undeclared_param", path, "parameter '\(path)' is not declared for '\(verb)'") }
        }
        for path in decl.keys.sorted() {
            guard case let .object(d)? = decl[path] else { return (false, "bad_type", path.s, "'\(path.s)': malformed parameter declaration") }
            let name = IV.dropPrefix(path.s, 14)
            guard let x = p[JKey(name)] else {
                if case .bool(false)? = d["required"] { continue }
                return (false, "missing_param", path.s, "required parameter '\(path.s)' is missing")
            }
            if let (code, why) = valueViolation(d, x) { return (false, code, path.s, "'\(path.s)': \(why)") }
        }
        return (true, "", nil, "")
    }

    /// `canonProjection`: `env.canon.<name>` for every PRESENT boolean ("true" / "false"), set (strict canonical JSON of
    /// its members sorted by UTF-8 bytes) and array (strict canonical JSON as sent) parameter.
    static func canonProjection(_ doc: JSONValue, verb: String, params: JObject) -> JObject {
        var out: JObject = [:]
        guard let v = self.verb(doc, verb), case let .object(decl)? = v["params"] else { return out }
        for path in decl.keys.sorted() {
            let name = IV.dropPrefix(path.s, 14)
            guard let x = params[JKey(name)], let type = decl[path]?.get("type")?.asString else { continue }
            switch type {
            case "boolean":
                if case .bool(true) = x { out[JKey(name)] = .string("true") } else { out[JKey(name)] = .string("false") }
            case "set":
                let members = (x.asArray ?? []).sorted { a, b in IV.utf8Less(a.asString ?? "", b.asString ?? "") }
                if let c = IV.strictCanon(.array(members)) { out[JKey(name)] = .string(c) }
            case "array":
                if let c = IV.strictCanon(x) { out[JKey(name)] = .string(c) }
            default:
                break
            }
        }
        return out
    }
}

extension PCA {
    /// Rule 14 on its own (`primitives.intent_schema`): `sig` (verifyActionSchema), `digest` (when sig is valid) and the
    /// conformance verdict `{ok, code?, path?}` of `verb` / `params` against `schema`.
    public static func intentSchemaPrimitive(schema: JSONValue, keys: JSONValue, verb: String, params: JSONValue)
        -> (sig: Bool, digest: String?, conformOk: Bool, code: String?, path: String?) {
        let s = IV.normalized(schema)
        let v = ActionSchema.verify(s, keys: IV.normalized(keys))
        let c = ActionSchema.conform(s, verb: verb, params: IV.normalized(params))
        return (v.ok, v.ok ? ActionSchema.digest(s) : nil, c.ok, c.ok ? nil : c.code, c.ok ? nil : c.path)
    }
}
