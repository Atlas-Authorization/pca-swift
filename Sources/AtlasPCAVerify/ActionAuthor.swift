import Foundation

/// Authoring forms of an action definition: param and resource shorthands, the expansion of an authoring entry into a def, the loader of an authoring
/// document, and typed param constructors. The shorthands and the expansion are the reference's, so one action has one digest however it was written.
/// Input is an already parsed document; YAML text is not parsed here (a YAML front end hands its parsed value to `loadActionsValue`).
public enum ActionAuthor {
    /// Largest authoring file the loader reads.
    public static let MAX_AUTHOR_BYTES = 1 << 20
    public static let IDEMPOTENCY_PARAM = "idempotency_key"
    public static let ACTION_DEF_KIND = "pca-action-def"
    /// Effects whose repeat is not harmless: an absent idempotency declaration gets a key parameter.
    public static let AUTO_IDEMPOTENT_EFFECTS = ["send", "pay", "create", "provision", "publish"]

    public static let RESOURCE_SCOPES = ["one", "set", "tenant", "global"]
    public static let ID_CLASSES = ["digits", "hex", "alnum", "slug", "uuid", "any_safe"]
    public static let BLAST_RADII = ["one", "bounded", "tenant", "global"]
    public static let PROVENANCE_LEVELS = ["first_party", "tool", "agent"]
    private static let ENTRY_KEYS: Set<String> = ["v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
                                                  "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since"]
    private static let FILE_KEYS: Set<String> = ["ns", "since", "actions"]

    private static func err(_ code: String, _ msg: String) -> ActionKitError { AK.fail(code, msg) }

    private static func isDigit(_ c: UInt8) -> Bool { c >= 48 && c <= 57 }
    private static func isLower(_ c: UInt8) -> Bool { c >= 97 && c <= 122 }

    /// `-?[0-9]{1,15}`
    private static func isIntArg(_ s: String) -> Bool {
        var u = Array(s.utf8)
        if u.first == 45 { u.removeFirst() }
        return (1...15).contains(u.count) && u.allSatisfy(isDigit)
    }

    private static func num(_ s: String) -> JSONValue {
        // Number("-0") is -0 (refused later by the strict-JSON profile): keep the sign of a negative zero
        let v = Int64(s) ?? 0
        return v == 0 && s.hasPrefix("-") ? .double(-0.0) : .int(v)
    }

    // ---- param shorthands ----

    private struct Args { var pos: [String] = []; var named: [(String, String)] = []
        func named(_ k: String) -> String? { named.first { $0.0 == k }?.1 }
    }

    private static func trim(_ s: String) -> String { Attest.jsTrim(s) }

    private static func splitArgs(_ s: String) -> Args {
        var a = Args()
        for raw in s.components(separatedBy: ",") {
            let x = trim(raw)
            if x.isEmpty { continue }
            if let eq = x.firstIndex(of: "="), eq != x.startIndex {
                let k = trim(String(x[..<eq])), v = trim(String(x[x.index(after: eq)...]))
                if let i = a.named.firstIndex(where: { $0.0 == k }) { a.named[i].1 = v } else { a.named.append((k, v)) }
            } else { a.pos.append(x) }
        }
        return a
    }

    private static func intArg(_ s: String?, _ what: String) throws -> JSONValue? {
        guard let s = s else { return nil }
        if !isIntArg(s) { throw err("bad_shorthand", "\(what) must be an integer, got '\(s)'") }
        return num(s)
    }

    private static func only(_ a: Args, _ pos: Int, _ names: [String], _ shorthand: String) throws {
        if a.pos.count > pos { throw err("bad_shorthand", "'\(shorthand)' takes at most \(pos) positional argument(s)") }
        for (k, _) in a.named where !names.contains(k) { throw err("bad_shorthand", "'\(shorthand)' has no option '\(k)'") }
    }

    private static func listArg(_ s: String, _ shorthand: String) throws -> JSONValue {
        let xs = s.components(separatedBy: "|").map { trim($0) }
        if xs.contains("") { throw err("bad_shorthand", "'\(shorthand)' needs values separated by |") }
        return AK.strs(xs)
    }

    private static func bare(_ name: String, _ inner: String?) throws {
        if inner != nil { throw err("bad_shorthand", "'\(name)' takes no arguments") }
    }

    /// `[a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?` then `(?:\(([^\n\r  ]*)\))?(\?)?`, matching the whole string. Nil = no match.
    private static func splitShorthand(_ s: String) -> (name: String, inner: String?, optional: Bool)? {
        let u = Array(s.utf16)
        var i = 0
        func isLowerU(_ c: UInt16) -> Bool { c >= 97 && c <= 122 }
        func isIdU(_ c: UInt16) -> Bool { isLowerU(c) || (c >= 48 && c <= 57) || c == 95 }
        while i < u.count && (isLowerU(u[i]) || u[i] == 95) { i += 1 }
        if i == 0 { return nil }
        if i < u.count && u[i] == 58 {
            i += 1
            var segs = 0
            while true {
                let st = i
                while i < u.count && isIdU(u[i]) { i += 1 }
                if i == st { return nil }
                segs += 1
                if i < u.count && u[i] == 46 && segs < 4 { i += 1; continue }
                break
            }
        }
        let name = String(decoding: u[..<i], as: UTF16.self)
        var rest = Array(u[i...])
        var opt = false
        if rest.last == 63 { opt = true; rest.removeLast() }
        if rest.isEmpty { return (name, nil, opt) }
        guard rest.count >= 2, rest.first == 40, rest.last == 41 else { return nil }
        let inner = Array(rest[1..<(rest.count - 1)])
        if inner.contains(where: { $0 == 10 || $0 == 13 || $0 == 0x2028 || $0 == 0x2029 }) { return nil }
        return (name, String(decoding: inner, as: UTF16.self), opt)
    }

    private static func with(_ base: JObject, _ k: String, _ v: JSONValue?) -> JObject { var b = base; if let v = v { b[JKey(k)] = v }; return b }

    /// Expand one param shorthand. Forms: email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N) int(MIN..MAX) count(MAX)
    /// money(CCY|@param, max=N, min=N, exp=N, provenance=first_party|tool|agent) id:<type> enum(a|b) set(a|b) array(items, max=N). A trailing `?` makes the param optional.
    public static func parseParamShorthand(_ src: String) throws -> JObject {
        guard let m = splitShorthand(trim(src)) else { throw err("bad_shorthand", "unknown param shorthand '\(src)'") }
        let name = m.name, inner = m.inner
        let a = splitArgs(inner ?? "")
        var p: JObject
        switch name {
        case "email": try bare(name, inner); p = ["type": .string("string"), "role": .string("contact.email"), "format": .string("email"), "tags": AK.strs(["pii"]), "max_len": .int(254)]
        case "phone": try bare(name, inner); p = ["type": .string("string"), "role": .string("contact.phone"), "format": .string("phone_e164"), "tags": AK.strs(["pii"]), "max_len": .int(16)]
        case "url": try bare(name, inner); p = ["type": .string("string"), "role": .string("url.target"), "format": .string("url"), "max_len": .int(2048)]
        case "uuid": try bare(name, inner); p = ["type": .string("string"), "format": .string("uuid"), "max_len": .int(36)]
        case "ccy": try bare(name, inner); p = ["type": .string("string"), "role": .string("money.currency"), "format": .string("iso_currency"), "max_len": .int(3)]
        case "country": try bare(name, inner); p = ["type": .string("string"), "format": .string("iso_country"), "max_len": .int(2)]
        case "secret": try bare(name, inner); p = ["type": .string("string"), "role": .string("credential.secret"), "tags": AK.strs(["secret"]), "max_len": .int(512)]
        case "bool": try bare(name, inner); p = ["type": .string("boolean")]
        case "date": try bare(name, inner); p = ["type": .string("date")]
        case "datetime": try bare(name, inner); p = ["type": .string("datetime")]
        case "duration":
            try only(a, 1, [], "duration")
            let max = try intArg(a.pos.first, "duration max (ms)")
            p = ["type": .string("duration")]
            if let mx = max { p["min"] = .int(0); p["max"] = mx }
        case "text", "string":
            try only(a, 1, [], name)
            let n = try intArg(a.pos.first, "\(name) length")
            p = with(["type": .string("string")], "max_len", n)
        case "message":
            try only(a, 1, [], "message")
            let n = try intArg(a.pos.first, "message length")
            p = ["type": .string("string"), "role": .string("text.message"), "tags": AK.strs(["free_text_outbound"]), "max_len": n ?? .int(1024)]
        case "int":
            try only(a, 1, [], "int")
            p = ["type": .string("integer")]
            if let r = a.pos.first {
                let parts = r.components(separatedBy: "..")
                guard parts.count == 2, isIntArg(parts[0]), isIntArg(parts[1]) else { throw err("bad_shorthand", "int takes MIN..MAX, for example int(0..100)") }
                p["min"] = num(parts[0]); p["max"] = num(parts[1])
            }
        case "count":
            try only(a, 1, [], "count")
            let mx = try intArg(a.pos.first, "count max")
            p = ["type": .string("integer"), "role": .string("count.limit"), "min": .int(1)]
            if let mx = mx { p["max"] = mx }
            p["unit"] = AK.obj(["kind": .string("count")])
        case "money":
            try only(a, 1, ["max", "min", "exp", "provenance"], "money")
            guard let c = a.pos.first else { throw err("bad_shorthand", "money needs a currency: money(USD) or money(@currency_param)") }
            let ccy: JSONValue = c.hasPrefix("@") ? AK.obj(["from": .string(String(c.dropFirst()))]) : .string(c)
            let mx = try intArg(a.named("max"), "money max")
            // an amount defaults to provenance first_party (the value must not come from an untrusted tool or agent output)
            let prov = a.named("provenance") ?? "first_party"
            if !PROVENANCE_LEVELS.contains(prov) { throw err("bad_shorthand", "money provenance must be one of " + PROVENANCE_LEVELS.joined(separator: ", ")) }
            let mn = try intArg(a.named("min"), "money min")
            p = ["type": .string("integer"), "role": .string("money.amount"), "min": mn ?? .int(1)]
            if let mx = mx { p["max"] = mx }
            let ex = try intArg(a.named("exp"), "money exp")
            p["unit"] = AK.obj(["kind": .string("money"), "ccy": ccy, "exp": ex ?? .int(2)])
            p["provenance_min"] = .string(prov)
        case "enum", "set":
            guard let inn = inner else { throw err("bad_shorthand", "\(name) needs values: \(name)(a|b|c)") }
            p = ["type": .string(name == "enum" ? "string" : "set"), "values": try listArg(inn, name)]
        case "array":
            try only(a, 1, ["max", "min"], "array")
            let items = a.pos.first
            guard items == "string" || items == "integer" else { throw err("bad_shorthand", "array(items): items is string or integer") }
            let mx = try intArg(a.named("max"), "array max"), mn = try intArg(a.named("min"), "array min")
            p = ["type": .string("array"), "items": .string(items!)]
            if let mn = mn { p["min_items"] = mn }
            if let mx = mx { p["max_items"] = mx }
        default:
            if name.hasPrefix("id:") {
                try bare(name, inner)
                p = ["type": .string("string"), "role": .string("id." + String(name.dropFirst(3))), "max_len": .int(64)]
            } else { throw err("bad_shorthand", "unknown param shorthand '\(name)'") }
        }
        if m.optional { p["required"] = .bool(false) }
        return p
    }

    // ---- resource shorthand ----

    /// `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`. A prefix pattern is scope one
    /// (class alnum, length 8..32 after the prefix); `*` is scope set; a bare type is tenant. Returns `{type, id, scope}`.
    public static func parseResourceShorthand(_ src: String) throws -> JObject {
        var s = trim(src)
        var scope: String?
        // `@([a-z]+)\z`
        let u = Array(s.utf16)
        var j = u.count
        while j > 0 && u[j - 1] >= 97 && u[j - 1] <= 122 { j -= 1 }
        if j < u.count && j > 0 && u[j - 1] == 64 {
            let word = String(decoding: u[j...], as: UTF16.self)
            if !RESOURCE_SCOPES.contains(word) { throw err("bad_shorthand", "unknown resource scope '@\(word)'") }
            scope = word
            s = String(decoding: u[..<(j - 1)], as: UTF16.self)
        }
        let su = Array(s.utf16)
        guard let colon = su.firstIndex(of: 58) else { return ["type": .string(s), "id": .string("*"), "scope": .string(scope ?? "tenant")] }
        let type = String(decoding: su[..<colon], as: UTF16.self)
        let idsrc = String(decoding: su[(colon + 1)...], as: UTF16.self)
        if idsrc == "*" { return ["type": .string(type), "id": .string("*"), "scope": .string(scope ?? "set")] }
        let iu = Array(idsrc.utf16)
        guard let star = iu.firstIndex(of: 42) else { return ["type": .string(type), "id": AK.obj(["exact": .string(idsrc)]), "scope": .string(scope ?? "one")] }
        let prefix = String(decoding: iu[..<star], as: UTF16.self)
        let rest = String(decoding: iu[(star + 1)...], as: UTF16.self)
        var cls = "alnum"
        var lo: Int64 = 8, hi: Int64 = 32
        if !rest.isEmpty {
            // `\{([a-z_]+),([0-9]{1,3})\.\.([0-9]{1,3})\}`
            let bad = err("bad_shorthand", "resource id '\(idsrc)': expected prefix*{class,min..max}")
            guard rest.hasPrefix("{"), rest.hasSuffix("}") else { throw bad }
            let body = String(rest.dropFirst().dropLast())
            let c1 = body.components(separatedBy: ",")
            guard c1.count == 2, !c1[0].isEmpty, c1[0].utf8.allSatisfy({ isLower($0) || $0 == 95 }) else { throw bad }
            let r = c1[1].components(separatedBy: "..")
            guard r.count == 2, (1...3).contains(r[0].utf8.count), (1...3).contains(r[1].utf8.count), r[0].utf8.allSatisfy(isDigit), r[1].utf8.allSatisfy(isDigit),
                  ID_CLASSES.contains(c1[0]) else { throw bad }
            cls = c1[0]; lo = Int64(r[0])!; hi = Int64(r[1])!
        }
        return ["type": .string(type), "id": AK.obj(["prefix": .string(prefix), "class": .string(cls), "len": .array([.int(lo), .int(hi)])]), "scope": .string(scope ?? "one")]
    }

    // ---- action expansion ----

    private static func asList(_ v: JSONValue?) -> JSONValue? {
        if let s = v?.asString { return .array([.string(s)]) }
        return v
    }

    /// The title an action gets when it names none: the action word and its nouns, "acme.invoice.send" gives "Send invoice".
    public static func defaultTitle(_ verb: String) -> String {
        let all = verb.components(separatedBy: ".")
        let seg = Array(all.dropFirst())
        let act = seg.last ?? verb
        var parts = [act]
        if seg.count > 1 { parts += seg[0..<(seg.count - 1)] }
        let t = parts.joined(separator: " ").replacingOccurrences(of: "_", with: " ")
        return t.isEmpty ? t : String(t.prefix(1)).uppercased() + String(t.dropFirst())
    }

    private static func isOne(_ v: JSONValue?) -> Bool { IV.num(v) == 1 }

    /// The strict-JSON check of a def under construction, in insertion order; a nil value is JavaScript `undefined` (never a JSON value).
    private static func profileError(_ pairs: [(String, JSONValue?)]) -> String? {
        for (k, v) in pairs {
            if Canonical.hasLoneSurrogate(k) || !(k.precomposedStringWithCanonicalMapping.unicodeScalars.elementsEqual(k.unicodeScalars)) { return "member name is not NFC / has a lone surrogate" }
            guard let v = v else { return "only JSON values are allowed" }
            if let e = Actions.jsonProfileError(v, 1) { return e }
        }
        return nil
    }

    /// Expand one authoring entry (shorthands or full def members) to an action def. Throws ActionKitError `bad_action` for a malformed entry.
    /// Returns `{def, notes}` (notes: the auto-added idempotency key).
    public static func expandAction(_ entryO: JSONValue?, _ since: String?) throws -> JSONValue {
        guard case let .object(entry)? = entryO else { throw err("bad_action", "an action must be an object") }
        let order = JS.keyOrder(entry)
        for k in order where !ENTRY_KEYS.contains(k.s) { throw err("bad_action", "unknown member '\(k.s)'") }
        if entry[JKey("v")] != nil && !isOne(entry["v"]) { throw err("bad_action", "unsupported def version") }
        if entry[JKey("kind")] != nil && entry["kind"] != .string(ACTION_DEF_KIND) { throw err("bad_action", "kind must be '\(ACTION_DEF_KIND)'") }
        guard let verb = entry["verb"]?.asString else { throw err("bad_action", "verb is required") }
        var notes: [JSONValue] = []
        if entry[JKey("kind")] != nil {
            // the full form (a `kind` member) is taken exactly as written: no shorthands, no defaults, validateDef decides
            var full: JObject = ["v": .int(1)]
            for (k, v) in entry { full[k] = v }
            var pairs: [(String, JSONValue?)] = [("v", full["v"])]
            for k in order where k.s != "v" { pairs.append((k.s, entry[k])) }
            if entry[JKey("v")] != nil { pairs[0].1 = entry["v"] }
            if let je = profileError(pairs) { throw err("bad_action", "not strict JSON: \(je)") }
            return AK.obj(["def": .object(full), "notes": .array(notes)])
        }
        var out: [(String, JSONValue?)] = [("v", .int(1)), ("kind", .string(ACTION_DEF_KIND)), ("verb", .string(verb))]
        func put(_ k: String, _ v: JSONValue?) {
            if let i = out.firstIndex(where: { $0.0 == k }) { out[i].1 = v } else { out.append((k, v)) }
        }
        func get(_ k: String) -> JSONValue?? { out.first { $0.0 == k }?.1 }
        if entry[JKey("aliases")] != nil { put("aliases", asList(entry["aliases"])) }
        put("title", AK.pres(entry, "title") ?? .string(defaultTitle(verb)))
        if entry[JKey("description")] != nil { put("description", entry["description"]) }
        put("effects", entry[JKey("effects")] != nil ? asList(entry["effects"]) : nil)
        if entry[JKey("resource")] == nil { put("resource", nil) }
        else if let rs = entry["resource"]?.asString { put("resource", .object(try parseResourceShorthand(rs))) }
        else { put("resource", entry["resource"]) }
        var params: JObject = [:]
        if entry[JKey("params")] != nil {
            guard case let .object(po)? = entry["params"] else { throw err("bad_action", "params must be an object") }
            for k in JS.keyOrder(po) {
                let v = po[k]!
                params[k] = v.asString != nil ? .object(try parseParamShorthand(v.asString!)) : v
            }
        }
        if entry[JKey("reversibility")] != nil { put("reversibility", entry["reversibility"]) }
        if entry[JKey("blast")] != nil { put("blast", entry["blast"]?.asString != nil ? AK.obj(["radius": entry["blast"]!]) : entry["blast"]) }
        if let bs = entry["blast"]?.asString, !BLAST_RADII.contains(bs) { throw err("bad_action", "unknown blast radius '\(bs)'") }
        if entry[JKey("side_effects")] != nil { put("side_effects", entry["side_effects"]) }
        // idempotency: a string is the mode; absent on a non-idempotent effect gets the key parameter (the linter notes it)
        var effects: [JSONValue] = []
        if case let .some(.some(ev)) = get("effects"), case let .array(ea) = ev { effects = ea }
        var idemDefined = entry[JKey("idempotency")] != nil
        var idem: JSONValue? = entry["idempotency"]
        if let m = idem?.asString { idem = m == "key_param" ? AK.obj(["mode": .string("key_param"), "param": .string(IDEMPOTENCY_PARAM)]) : AK.obj(["mode": .string(m)]) }
        if !idemDefined {
            let auto = effects.contains { $0.asString.map { AUTO_IDEMPOTENT_EFFECTS.contains($0) } ?? false }
            if auto {
                idem = AK.obj(["mode": .string("key_param"), "param": .string(IDEMPOTENCY_PARAM)])
                idemDefined = true
                notes.append(AK.obj(["verb": .string(verb), "message": .string("\(IDEMPOTENCY_PARAM) auto-added")]))
            }
        }
        if let io = idem, io.get("mode") == .string("key_param"), io.get("param") == .string(IDEMPOTENCY_PARAM), params[JKey(IDEMPOTENCY_PARAM)] == nil {
            params[JKey(IDEMPOTENCY_PARAM)] = AK.obj(["type": .string("string"), "max_len": .int(64)])
        }
        if idemDefined { put("idempotency", idem ?? .null) }
        put("params", .object(params))
        for k in ["context", "traits"] where entry[JKey(k)] != nil { put(k, asList(entry[JKey(k)])) }
        for k in ["audience", "compensates", "bindings", "examples", "source"] where entry[JKey(k)] != nil { put(k, entry[JKey(k)]) }
        put("review", AK.pres(entry, "review") ?? AK.obj(["state": .string("authored")]))
        if let sin = AK.pres(entry, "since") ?? since.map({ .string($0) }) { put("since", sin) }
        let pairs = out
        if let je = profileError(pairs) { throw err("bad_action", "not strict JSON: \(je)") }
        var def: JObject = [:]
        for (k, v) in out { if let v = v { def[JKey(k)] = v } }
        return AK.obj(["def": .object(def), "notes": .array(notes)])
    }

    // ---- the document loader ----

    private static func hasProtoKey(_ v: JSONValue, _ depth: Int) -> Bool {
        if depth > 40 { return true }
        switch v {
        case let .array(a): return a.contains { hasProtoKey($0, depth + 1) }
        case let .object(o): return o.contains { $0.key.s == "__proto__" || hasProtoKey($0.value, depth + 1) }
        default: return false
        }
    }

    private static func isNs(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard (1...32).contains(u.count), isLower(u[0]) else { return false }
        return u.dropFirst().allSatisfy { isLower($0) || isDigit($0) || $0 == 95 }
    }

    private static func failed(_ message: String, ns: String? = nil) -> JSONValue {
        var r: JObject = ["defs": .array([]), "notes": .array([]), "errors": .array([AK.obj(["message": .string(message)])]), "locs": .object([:]), "rules": .object([:])]
        if let n = ns { r["ns"] = .string(n) }
        return .object(r)
    }

    /// Expand an already parsed document (`{ns, since?, actions: [...]}`, or one raw def). Never throws. Returns `{defs, notes, errors, locs, rules[, ns]}`.
    public static func loadActionsValue(_ docO: JSONValue?) -> JSONValue {
        guard let docO = docO else { return failed("the document must be an object") }
        if hasProtoKey(docO, 0) { return failed("the document contains a '__proto__' member or nests deeper than 40") }
        guard case let .object(doc) = docO else { return failed("the document must be an object") }
        var entries: [JSONValue]
        var since: String?
        var ns: String?
        if doc["kind"] == .string(ACTION_DEF_KIND) { entries = [docO] }
        else {
            for k in JS.keyOrder(doc) where !FILE_KEYS.contains(k.s) { return failed("unknown top-level member '\(k.s)' (expected ns, since, actions)") }
            guard let n = doc["ns"]?.asString, isNs(n) else { return failed("ns must be a lowercase identifier") }
            ns = n
            if let s = doc["since"]?.asString { since = s }
            else if doc[JKey("since")] != nil { return failed("since must be a string", ns: ns) }
            guard case let .array(a)? = doc["actions"] else { return failed("actions must be a list", ns: ns) }
            entries = a
        }
        var defs: [JSONValue] = [], notes: [JSONValue] = [], errors: [JSONValue] = []
        var rulesOut: JObject = [:]
        func errorOf(_ index: Int, _ verb: String?, _ message: String) -> JSONValue {
            var m: JObject = ["index": .int(Int64(index))]
            if let v = verb, !v.isEmpty { m["verb"] = .string(v) }
            m["message"] = .string(message)
            return .object(m)
        }
        for (index, e) in entries.enumerated() {
            let verb = e.get("verb")?.asString
            do {
                // `rules` is the action's business rules block: validated against the def, kept out of the def (and its digest)
                var hasRules = false
                var rules: JSONValue?
                var entry: JSONValue = e
                if case var .object(eo) = e, eo[JKey("rules")] != nil {
                    hasRules = true
                    rules = eo.removeValue(forKey: JKey("rules"))
                    entry = .object(eo)
                }
                let ex = try expandAction(entry, since)
                let def = AK.o(ex.get("def"))
                if let bad = Actions.validateDef(.object(def)) { errors.append(errorOf(index, verb, bad)); continue }
                if hasRules {
                    if let re = ActionBusinessRules.businessRulesError(def, rules) { errors.append(errorOf(index, verb, re)); continue }
                    if let v = def["verb"]?.asString, let r = rules { rulesOut[JKey(v)] = r }
                }
                defs.append(.object(def))
                notes += AK.arr(ex.get("notes"))
            } catch let ke as ActionKitError {
                errors.append(errorOf(index, verb, ke.message))
            } catch {
                errors.append(errorOf(index, verb, "malformed action: \(error)"))
            }
        }
        var r: JObject = ["defs": .array(defs), "notes": .array(notes), "errors": .array(errors), "locs": .object([:]), "rules": .object(rulesOut)]
        if let n = ns { r["ns"] = .string(n) }
        return .object(r)
    }

    // ---- the typed builder ----

    /// Typed param constructors; each returns the same param the matching shorthand expands to (`x` members are merged over it; may be nil).
    public enum P {
        private static func merge(_ p: JObject, _ x: JObject?) -> JObject { var q = p; if let x = x { for (k, v) in x { q[k] = v } }; return q }
        public static func email(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("email"), x) }
        public static func phone(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("phone"), x) }
        public static func url(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("url"), x) }
        public static func uuid(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("uuid"), x) }
        public static func ccy(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("ccy"), x) }
        public static func country(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("country"), x) }
        public static func secret(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("secret"), x) }
        public static func bool(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("bool"), x) }
        public static func date(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("date"), x) }
        public static func datetime(_ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("datetime"), x) }
        public static func duration(_ maxMs: Int64?, _ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand(maxMs.map { "duration(\($0))" } ?? "duration"), x) }
        public static func message(_ maxLen: Int64?, _ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand(maxLen.map { "message(\($0))" } ?? "message"), x) }
        public static func text(_ maxLen: Int64?, _ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand(maxLen.map { "text(\($0))" } ?? "text"), x) }
        public static func intRange(_ min: Int64?, _ max: Int64?, _ x: JObject? = nil) throws -> JObject {
            merge(try parseParamShorthand(min != nil && max != nil ? "int(\(min!)..\(max!))" : "int"), x)
        }
        public static func count(_ max: Int64?, _ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand(max.map { "count(\($0))" } ?? "count"), x) }
        /// `ccy`: a literal ISO code, or a map `{from: param}` naming the currency param. `o`: `{max?, min?, exp?}` (may be nil).
        public static func money(_ ccy: JSONValue?, _ o: JObject?, _ x: JObject? = nil) throws -> JObject {
            var b = "money(" + (ccy?.asString ?? "@" + JS.toString(ccy?.get("from")))
            for k in ["max", "min", "exp"] { if let v = o.flatMap({ AK.pres($0, k) }) { b += ", \(k)=" + JS.toString(v) } }
            return merge(try parseParamShorthand(b + ")"), x)
        }
        public static func id(_ type: String, _ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("id:\(type)"), x) }
        public static func enumOf(_ values: [String], _ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("enum(" + values.joined(separator: "|") + ")"), x) }
        public static func setOf(_ values: [String], _ x: JObject? = nil) throws -> JObject { merge(try parseParamShorthand("set(" + values.joined(separator: "|") + ")"), x) }
        public static func array(_ items: String, _ max: Int64?, _ x: JObject? = nil) throws -> JObject {
            merge(try parseParamShorthand(max.map { "array(\(items), max=\($0))" } ?? "array(\(items))"), x)
        }
        public static func optional(_ d: JObject) -> JObject { var c = d; c["required"] = .bool(false); return c }
    }

    /// The typed constructor over the JSON form: `action("acme.invoice.send", spec)`. Same expansion as the loader (so the same digest);
    /// throws ActionKitError on a malformed spec.
    public static func action(_ verb: String, _ spec: JObject?) throws -> JSONValue {
        var entry: JObject = ["verb": .string(verb)]
        if let s = spec { for (k, v) in s { entry[k] = v } }
        let def = AK.o(try expandAction(.object(entry), nil).get("def"))
        if let bad = Actions.validateDef(.object(def)) { throw err("bad_action", "\(verb): \(bad)") }
        return .object(def)
    }
}
