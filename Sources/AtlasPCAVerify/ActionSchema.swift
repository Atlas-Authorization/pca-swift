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
    // ---- v2 (action kit): the same document plus effects/traits/def/floors on a verb, typed params with role/format/tags ----
    static let PARAM_TYPES_V2 = PARAM_TYPES + ["datetime", "duration", "object_ref"]
    static let DOC_KEYS_V2 = DOC_KEYS + ["traits_digest", "trait_defs", "pack"]
    static let VERB_KEYS_V2 = VERB_KEYS + ["traits", "def", "floors", "confirmation"]
    static let PARAM_KEYS_V2 = PARAM_KEYS + ["role", "format", "tags", "provenance_min"]
    static let V2_EFFECTS = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"]
    static let V2_CAVEATS = ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"]
    static let V2_PRULES = ["array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
                            "pay_has_idempotency", "recipient_param_declared", "secret_not_logged"]
    static let V2_CONTEXT = ["approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"]
    static let V2_TAGS = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"]
    static let V2_PROVENANCE = ["first_party", "tool", "agent"]

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

    static func paramDeclError(_ path: String, _ dv: JSONValue, _ units: JObject?, v2: Bool = false) -> String? {
        if !(v2 ? isParamPathV2(path) : IV.isTopParamPath(path)) { return "parameter path '\(path)' is not action.params.<name>" }
        if IV.split(IV.dropPrefix(path, 14), ".").contains(where: { IV.isReserved($0) }) { return "parameter name '\(path)' is reserved (__proto__ / constructor / prototype)" }
        guard case let .object(d) = dv else { return "\(path): declaration must be an object" }
        for k in d.keys where !has(v2 ? PARAM_KEYS_V2 : PARAM_KEYS, k) { return "\(path): unknown member '\(k.s)'" }
        if !isIn(v2 ? PARAM_TYPES_V2 : PARAM_TYPES, d["type"]) { return "\(path): unknown type" }
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
            if let x = d[JKey(k)], IV.int(x) == nil || (type != "integer" && !(v2 && type == "duration") && !(type == "array" && itemsInteger)) {
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
        if v2 {
            if let r = d["role"], !isStr(r, 128) { return "\(path): role must be a non-empty string" }
            if let f = d["format"], f.asString.map({ formatCheck($0) == nil }) ?? true || (type != "string" && type != "object_ref") {
                return "\(path): format must be a known format on a string parameter"
            }
            if let t = d["tags"] {
                guard let ts = strings(t), ts.count <= V2_TAGS.count, IV.distinct(ts), ts.allSatisfy({ IV.contains(V2_TAGS, $0) }) else {
                    return "\(path): tags must be distinct known tags"
                }
            }
            if let pm = d["provenance_min"], !isIn(V2_PROVENANCE, pm) { return "\(path): unknown provenance_min" }
        }
        return nil
    }

    /// `action.params.<name>` with up to three dotted segments of `[A-Za-z0-9_]{1,64}` (v2 flattened form).
    static func isParamPathV2(_ s: String) -> Bool {
        guard IV.startsWith(s, "action.params.") else { return false }
        let segs = IV.split(IV.dropPrefix(s, 14), ".")
        return (1...3).contains(segs.count) && segs.allSatisfy { g in
            (1...64).contains(g.utf8.count) && g.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 95 }
        }
    }

    /// `schemaFloorsError(f)`: shape of a materialized profile. nil = well-formed.
    static func floorsError(_ fv: JSONValue?) -> String? {
        guard case let .object(f)? = fv else { return "floors must be an object" }
        for k in f.keys where !has(["risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"], k) { return "floors: unknown member '\(k.s)'" }
        func rng(_ x: JSONValue?, _ lo: Int64, _ hi: Int64) -> Bool { IV.int(x).map { $0 >= lo && $0 <= hi } ?? false }
        if !rng(f["risk"], 0, 3) || !rng(f["esc"], 0, 3) { return "floors.risk and floors.esc must be integers in 0..3" }
        if !isIn(REVERSIBILITY, f["rev"]) { return "floors.rev is not a reversibility class" }
        if !rng(f["blast_ppm"], 0, 1_000_000) { return "floors.blast_ppm must be an integer in 0..1000000" }
        for (name, ok) in [("caveats", { (x: String) in IV.contains(V2_CAVEATS, x) }),
                           ("context", { (x: String) in IV.contains(V2_CONTEXT, x) || isTaintContext(x) }),
                           ("prules", { (x: String) in IV.contains(V2_PRULES, x) })] {
            guard let a = strings(f[JKey(name)]), a.count <= 64, a.allSatisfy(ok) else { return "floors.\(name) must be an array of known entries" }
            for i in 1..<max(a.count, 1) where !IV.utf8Less(a[i - 1], a[i]) { return "floors.\(name) must be sorted and distinct" }
        }
        return nil
    }

    /// Shape of a v2 verb's `confirmation` (the signature check is rule 22). nil = well-formed.
    static func confirmationShapeError(_ cv: JSONValue?) -> String? {
        guard case let .object(c)? = cv else { return "confirmation must be an object" }
        for k in c.keys where !has(["def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"], k) { return "confirmation: unknown member '\(k.s)'" }
        func b64(_ x: JSONValue?, _ n: Int) -> Bool { x?.asString.map { Base64URLStrict.isValid($0, length: n) } ?? false }
        if !b64(c["def_digest"], 32) || !b64(c["traits_digest"], 32) || !b64(c["facts_digest"], 32) { return "confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests" }
        if !b64(c["sig"], 64) { return "confirmation: sig must be a canonical base64url 64-byte signature" }
        guard let ft = strings(c["final_traits"]), ft.count <= 64, ft.allSatisfy({ Actions.isTraitId($0) }) else { return "confirmation: final_traits must be trait ids" }
        for i in 1..<max(ft.count, 1) where !IV.utf8Less(ft[i - 1], ft[i]) { return "confirmation: final_traits must be sorted and distinct" }
        guard case let .array(dm)? = c["dismissed"], dm.count <= 64 else { return "confirmation: dismissed must be an array" }
        for d in dm {
            guard case let .object(o) = d, o.keys.allSatisfy({ has(["trait", "reason"], $0) }), let t = o["trait"]?.asString, Actions.isTraitId(t), isStr(o["reason"], 256) else {
                return "confirmation: dismissed entries must be {trait, reason}"
            }
        }
        if !isStr(c["reviewer_kid"], 128) { return "confirmation: reviewer_kid must be a non-empty string" }
        if !(IV.safe(c["ts"]).map { $0 >= 0 } ?? false) { return "confirmation: ts must be a non-negative safe integer" }
        return nil
    }

    /// `session_taint_max:[a-z_]{1,16}`
    static func isTaintContext(_ s: String) -> Bool {
        guard IV.startsWith(s, "session_taint_max:") else { return false }
        let r = Array(IV.dropPrefix(s, 18).utf8)
        return (1...16).contains(r.count) && r.allSatisfy { ($0 >= 97 && $0 <= 122) || $0 == 95 }
    }

    static func verbDeclError(_ vv: JSONValue, _ units: JObject?, v2: Bool = false) -> String? {
        guard case let .object(v) = vv else { return "verb entry must be an object" }
        for k in v.keys where !has(v2 ? VERB_KEYS_V2 : VERB_KEYS, k) { return "verb entry: unknown member '\(k.s)'" }
        if !isStr(v["verb"], 128) { return "verb entry: verb must be a non-empty string" }
        let at = "verb '\(v["verb"]!.asString!)'"
        if !isIn(["read", "write"], v["kind"]) { return "\(at): kind must be read or write" }
        guard case let .object(params)? = v["params"] else { return "\(at): params must be an object" }
        if params.count > MAX_PARAMS { return "\(at): more than \(MAX_PARAMS) parameters" }
        for (p, d) in params.sorted(by: { $0.key < $1.key }) {
            if let e = paramDeclError(p.s, d, units, v2: v2) { return "\(at): \(e)" }
        }
        if v2 {
            for p in params.keys { for q in params.keys where q != p && IV.startsWith(q.s, p.s + ".") { return "\(at): parameter '\(p.s)' is both a value and the parent of '\(q.s)'" } }
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
        for k in (v2 ? ["harm", "returns"] : ["harm", "effects", "returns"]) {
            if let x = v[JKey(k)], !x.isObject { return "\(at): \(k) must be an object" }
        }
        if v2 {
            guard let ef = strings(v["effects"]), !ef.isEmpty, ef.count <= V2_EFFECTS.count, ef.allSatisfy({ IV.contains(V2_EFFECTS, $0) }) else {
                return "\(at): effects must be 1..\(V2_EFFECTS.count) known effects"
            }
            for i in 1..<max(ef.count, 1) where !IV.utf8Less(ef[i - 1], ef[i]) { return "\(at): effects must be sorted and distinct" }
            if (v["kind"]?.asString == "read") != ef.allSatisfy({ $0 == "read" }) { return "\(at): kind read must hold exactly when every effect is read" }
            guard let tr = strings(v["traits"]), tr.count <= 64, tr.allSatisfy({ Actions.isTraitId($0) }) else { return "\(at): traits must be trait ids" }
            for i in 1..<max(tr.count, 1) where !IV.utf8Less(tr[i - 1], tr[i]) { return "\(at): traits must be sorted and distinct" }
            if !(v["def"]?.asString.map { Base64URLStrict.isValid($0, length: 32) } ?? false) { return "\(at): def must be a canonical base64url SHA-256 digest" }
            if let fe = floorsError(v["floors"]) { return "\(at): \(fe)" }
            if let c = v["confirmation"], let ce = confirmationShapeError(c) { return "\(at): \(ce)" }
        }
        if let w = v["world"], !w.isArray { return "\(at): world must be an array" }
        if let x = v["description"], !isStr(x, 1024) { return "\(at): description must be a string" }
        return nil
    }

    /// `actionSchemaShapeError(doc, {signed})`; an unsigned document must not carry `sig`. nil = well-formed.
    static func shapeError(_ docV: JSONValue, signed: Bool = true) -> String? {
        guard case let .object(doc) = docV else { return "schema is not an object" }
        let v2 = IV.num(doc["v"]) == 2
        for k in doc.keys where !has(v2 ? DOC_KEYS_V2 : DOC_KEYS, k) { return "unknown member '\(k.s)'" }
        if IV.num(doc["v"]) != 1 && !v2 { return "unsupported schema version" }
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
        if v2 {
            if let td = doc["traits_digest"], !(td.asString.map { Base64URLStrict.isValid($0, length: 32) } ?? false) { return "traits_digest must be a canonical base64url SHA-256 digest" }
            if let tdf = doc["trait_defs"], !(tdf.asArray.map { $0.count <= 64 && $0.allSatisfy { $0.isObject } } ?? false) { return "trait_defs must be an array of up to 64 objects" }
            if let pk = doc["pack"] {
                guard case let .object(o) = pk, o.count == 3, isStr(o["ns"], 64), isStr(o["version"], 128),
                      o["root"]?.asString.map({ Base64URLStrict.isValid($0, length: 32) }) ?? false else { return "pack must be {ns, version, root}" }
            }
        }
        guard case let .array(verbs)? = doc["verbs"], !verbs.isEmpty, verbs.count <= MAX_VERBS else { return "verbs must be 1..\(MAX_VERBS) entries" }
        var seen = Set<JKey>()
        for v in verbs {
            if let e = verbDeclError(v, units, v2: v2) { return e }
            let name = JKey(v.get("verb")!.asString!)
            if !seen.insert(name).inserted { return "verb '\(name.s)' is declared twice" }
        }
        if signed {
            guard case let .object(s)? = doc["sig"] else { return "sig must be an object" }
            for k in s.keys where !has(SIG_KEYS, k) { return "sig: unknown member '\(k.s)'" }
            if let se = IV.suiteError(s["alg"]) { return "sig.alg: \(se)" }
            if !isStr(s["kid"], 128) { return "sig.kid must be a non-empty string" }
            if !(s["value"]?.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "sig.value is not canonical base64url" }
            if let pv = s["pq_value"], !(pv.asString.map { Base64URLStrict.isValid($0) } ?? false) { return "sig.pq_value is not canonical base64url" }
        } else if doc["sig"] != nil { return "an unsigned schema must not carry sig" }
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

    // ---- v2 string formats (syntactic; ECMAScript `\s` is spelled out, `\d` is ASCII, every match is whole-string) ----

    private static let jsWs = "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    private static let datetimeRe = "([0-9]{4}-[0-9]{2}-[0-9]{2})T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\\.[0-9]{1,3})?Z"
    private static let formatRes: [String: String] = [
        "email": "[A-Za-z0-9._%+\\-]{1,64}@[A-Za-z0-9\\-]{1,63}(?:\\.[A-Za-z0-9\\-]{1,63})+",
        "url": "[A-Za-z][A-Za-z0-9+.\\-]{0,31}://[^\(jsWs)/?#]+[^\(jsWs)]*",
        "uri_https": "https://[^\(jsWs)/?#]+[^\(jsWs)]*",
        "uuid": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "phone_e164": "\\+[1-9][0-9]{6,14}",
        "iso_country": "[A-Z]{2}", "iso_currency": "[A-Z]{3}", "sha256": "[0-9a-f]{64}",
        "semver": "(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z\\-]+(?:\\.[0-9A-Za-z\\-]+)*)?(?:\\+[0-9A-Za-z\\-]+(?:\\.[0-9A-Za-z\\-]+)*)?",
        "cidr4": "([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})/([0-9]{1,2})",
        "cidr6": "([0-9a-fA-F:]{2,39})/([0-9]{1,3})",
        "iban": "[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}",
        "idfmt": "id:[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}",
        "idval": "[A-Za-z0-9._:\\-]{1,128}",
    ]
    private static var reCache: [String: NSRegularExpression] = [:]
    private static let reLock = NSLock()

    /// The capture groups (1...) of a whole-string match, or nil. Group 0 is not returned.
    private static func groups(_ pattern: String, _ s: String) -> [String]? {
        reLock.lock(); defer { reLock.unlock() }
        let re: NSRegularExpression
        if let c = reCache[pattern] { re = c } else {
            guard let n = try? NSRegularExpression(pattern: "\\A(?:" + pattern + ")\\z") else { return nil }
            reCache[pattern] = n; re = n
        }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, options: [], range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (0..<m.numberOfRanges).dropFirst().map { m.range(at: $0).location == NSNotFound ? "" : ns.substring(with: m.range(at: $0)) }
    }
    private static func firstMatch(_ pattern: String, _ s: String) -> String? { groups(pattern, s)?.first }
    private static func matches(_ key: String, _ s: String) -> Bool { groups(formatRes[key]!, s) != nil }
    private static func canonDec(_ n: String) -> Bool { Int(n).map { String($0) == n } ?? false }

    private static func ibanOk(_ s: String) -> Bool {
        guard matches("iban", s) else { return false }
        var rem = 0
        for ch in Array(s.utf8.dropFirst(4)) + Array(s.utf8.prefix(4)) {
            let v = ch >= 65 ? Int(ch) - 55 : Int(ch) - 48
            rem = (v > 9 ? rem * 100 + v : rem * 10 + v) % 97
        }
        return rem == 1
    }
    private static func cidrOk(_ s: String) -> Bool {
        if let g = groups(formatRes["cidr4"]!, s) {
            return g[0..<4].allSatisfy { Int($0)! <= 255 && canonDec($0) } && Int(g[4])! <= 32 && canonDec(g[4])
        }
        if let g = groups(formatRes["cidr6"]!, s) {
            return g[0].filter { $0 == ":" }.count >= 2 && !g[0].contains(":::") && Int(g[1])! <= 128 && canonDec(g[1])
        }
        return false
    }
    /// The checker of a v2 `format`, or nil when the format is unknown. `id:<type>` accepts a 1..128 character safe id.
    static func formatCheck(_ f: String) -> ((String) -> Bool)? {
        switch f {
        case "email": return { $0.utf16.count <= 254 && matches("email", $0) }
        case "iban": return ibanOk
        case "cidr": return cidrOk
        case "url", "uri_https", "uuid", "phone_e164", "iso_country", "iso_currency", "semver", "sha256": return { matches(f, $0) }
        default: return matches("idfmt", f) ? { matches("idval", $0) } : nil
        }
    }
    private static func formatViolation(_ d: JObject, _ x: String) -> (String, String)? {
        guard let f = d["format"] else { return nil }
        let name = f.asString ?? ""
        if let ck = formatCheck(name), ck(x) { return nil }
        return ("out_of_domain", "not a valid \(name)")
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
            return formatViolation(d, s)
        case "object_ref":
            guard case let .string(s) = x, !Canonical.hasLoneSurrogate(s), !s.isEmpty else { return ("bad_type", "expected a non-empty id string") }
            if Double(IV.u8(s)) > maxLen { return ("out_of_domain", "longer than \(maxLenText) UTF-8 bytes") }
            return formatViolation(d, s)
        case "datetime":
            guard case let .string(s) = x else { return ("bad_type", "expected an RFC 3339 UTC string") }
            if let m = firstMatch(datetimeRe, s), isCalendarDate(m) { return nil }
            return ("out_of_domain", "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z")
        case "duration":
            guard let i = IV.int(x) else { return ("bad_type", "expected a safe integer (milliseconds)") }
            if i < 0 { return ("out_of_domain", "a duration is not negative") }
            if let lo = IV.num(d["min"]), Double(i) < lo { return ("out_of_domain", "below min \(IntentV2.jsString(d["min"]!))") }
            if let hi = IV.num(d["max"]), Double(i) > hi { return ("out_of_domain", "above max \(IntentV2.jsString(d["max"]!))") }
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
