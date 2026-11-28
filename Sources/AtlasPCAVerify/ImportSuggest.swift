import Foundation

private func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

/// The deterministic suggestion layer: a versioned rule set proposes traits, param roles and param tags for a draft def. Union only: a suggestion can ADD a
/// trait, a role (to a param that has none) or a tag, never remove or replace anything, and it never marks a def confirmed. A suggested def is still
/// `pca.unreviewed` for floor purposes until a pinned reviewer signs it. Defs, rule sets and suggestions are JSON trees.
public enum ImportSuggest {
    public static let SUGGEST_RULES_KIND = "pca-suggest-rules"
    public static let SUGGEST_RULES_DOMAIN = "atlas-pca/suggest-rules/v1"

    private static let MATCH_KEYS = ["methods", "path_re", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_types", "param_formats", "roles", "effects"]
    public static let PARAM_TAGS = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"]
    private static let PARAM_TYPES = ["string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"]
    private static let MAX_RULES = 1024, MAX_LIST = 64

    // a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
    private static let NESTED_QUANTIFIER = try! NSRegularExpression(pattern: "\\([^)]*[+*][^)]*\\)[+*{]|\\([^)]*\\|[^)]*\\)[+*{]")
    private static let BACKREF = try! NSRegularExpression(pattern: "\\\\[1-9]")
    private static let LOOKAROUND = try! NSRegularExpression(pattern: "\\(\\?[<=!]")
    private static func found(_ re: NSRegularExpression, _ s: String) -> Bool { re.firstMatch(in: s, range: NSRange(location: 0, length: s.utf16.count)) != nil }

    private static let CORE_ROLES = [
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    ]

    public static func isRole(_ r: String) -> Bool { CORE_ROLES.contains(r) || Actions.fullMatch("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}", r) || Actions.fullMatch("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}", r) }

    private static func isStrList(_ v: JSONValue?, _ max: Int) -> Bool {
        guard case let .array(a)? = v, !a.isEmpty, a.count <= max else { return false }
        return a.allSatisfy { if case let .string(s) = $0 { return !s.isEmpty && s.utf16.count <= 64 }; return false }
    }

    // ---- JavaScript regular expression to an ICU pattern (the bounded subset the rules use) ----

    private static let JS_SPACE = "\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF"

    private static func isHex(_ s: [UInt16], _ from: Int, _ n: Int) -> Bool {
        if from + n > s.count { return false }
        return s[from..<(from + n)].allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102) }
    }

    /// The end of a `{n}`, `{n,}` or `{n,m}` quantifier starting at `i`, or -1.
    private static func quantEnd(_ s: [UInt16], _ i: Int) -> Int {
        var j = i + 1, d = 0
        while j < s.count && s[j] >= 48 && s[j] <= 57 { j += 1; d += 1 }
        if d == 0 { return -1 }
        if j < s.count && s[j] == 0x2C { j += 1; while j < s.count && s[j] >= 48 && s[j] <= 57 { j += 1 } }
        return j < s.count && s[j] == 0x7D ? j + 1 : -1
    }

    /// Compile a JavaScript pattern (no flags); an error where the engine would raise SyntaxError.
    static func jsRegex(_ str: String) throws -> NSRegularExpression {
        let s = Array(str.utf16)
        var o = ""
        let n = s.count
        var i = 0, depth = 0
        var inClass = false, canQuant = false
        func ch(_ u: UInt16) -> String { String(decoding: [u], as: UTF16.self) }
        func sub(_ a: Int, _ b: Int) -> String { String(decoding: s[a..<b], as: UTF16.self) }
        func asciiAlnum(_ e: UInt16) -> Bool { (e >= 48 && e <= 57) || (e >= 65 && e <= 90) || (e >= 97 && e <= 122) }
        func bad(_ m: String) -> JSError { JSError("invalid regular expression: " + m) }
        while i < n {
            let c = s[i]
            if inClass {
                if c == 0x5D { o += "]"; inClass = false; canQuant = true; i += 1; continue }
                if c == 0x5C {
                    if i + 1 >= n { throw bad("\\ at end of pattern") }
                    let e = s[i + 1]
                    i += 2
                    let es = ch(e)
                    if e == 0x73 { o += JS_SPACE }
                    else if e == 0x53 { o += "[^" + JS_SPACE + "]" }
                    else if e == 0x64 { o += "0-9" }
                    else if e == 0x44 { o += "[^0-9]" }
                    else if e == 0x77 { o += "A-Za-z0-9_" }
                    else if e == 0x57 { o += "[^A-Za-z0-9_]" }
                    else if e == 0x62 { o += "\\x08" }
                    else if e == 0x74 || e == 0x6E || e == 0x66 || e == 0x72 { o += "\\" + es }
                    else if e == 0x76 { o += "\\u000B" }
                    else if e == 0x30 { o += "\\x00" }
                    else if e == 0x78 && isHex(s, i, 2) { o += "\\x" + sub(i, i + 2); i += 2 }
                    else if e == 0x75 && isHex(s, i, 4) { o += "\\u" + sub(i, i + 4); i += 4 }
                    else if e < 128 && !asciiAlnum(e) { o += "\\" + es }
                    else { o += es }
                    continue
                }
                if c == 0x5B || c == 0x26 || c == 0x5E { o += "\\" + ch(c) } else { o += ch(c) }
                i += 1
                continue
            }
            switch c {
            case 0x5C:
                if i + 1 >= n { throw bad("\\ at end of pattern") }
                let e = s[i + 1]
                i += 2
                canQuant = true
                let es = ch(e)
                if e == 0x62 || e == 0x42 { o += "\\" + es; canQuant = false }
                else if e == 0x64 { o += "[0-9]" }
                else if e == 0x44 { o += "[^0-9]" }
                else if e == 0x77 { o += "[A-Za-z0-9_]" }
                else if e == 0x57 { o += "[^A-Za-z0-9_]" }
                else if e == 0x73 { o += "[" + JS_SPACE + "]" }
                else if e == 0x53 { o += "[^" + JS_SPACE + "]" }
                else if e == 0x74 || e == 0x6E || e == 0x66 || e == 0x72 { o += "\\" + es }
                else if e == 0x76 { o += "\\u000B" }
                else if e == 0x30 { o += "\\x00" }
                else if e >= 0x31 && e <= 0x39 { o += "\\" + es }
                else if e == 0x78 && isHex(s, i, 2) { o += "\\x" + sub(i, i + 2); i += 2 }
                else if e == 0x75 && isHex(s, i, 4) { o += "\\u" + sub(i, i + 4); i += 4 }
                else if e == 0x63 && i < n && ((s[i] >= 65 && s[i] <= 90) || (s[i] >= 97 && s[i] <= 122)) { o += "\\c" + ch(s[i]); i += 1 }
                else if e == 0x63 { o += "\\\\c" }
                else if e < 128 && !asciiAlnum(e) { o += "\\" + es }
                else { o += es }
            case 0x28:
                if i + 1 < n && s[i + 1] == 0x3F {
                    if i + 2 < n && (s[i + 2] == 0x3A || s[i + 2] == 0x3D || s[i + 2] == 0x21) { o += "(?" + ch(s[i + 2]); i += 3 }
                    else { throw bad("invalid group") }
                } else { o += "("; i += 1 }
                depth += 1
                canQuant = false
            case 0x29:
                if depth == 0 { throw bad("unmatched )") }
                depth -= 1; o += ")"; canQuant = true; i += 1
            case 0x7C: o += "|"; canQuant = false; i += 1
            case 0x2A, 0x2B, 0x3F:
                if !canQuant { throw bad("nothing to repeat") }
                o += ch(c); i += 1
                if i < n && s[i] == 0x3F { o += "?"; i += 1 }
                canQuant = false
            case 0x7B:
                let e = quantEnd(s, i)
                if e < 0 { o += "\\{"; canQuant = true; i += 1 }
                else {
                    if !canQuant { throw bad("nothing to repeat") }
                    o += sub(i, e); i = e
                    if i < n && s[i] == 0x3F { o += "?"; i += 1 }
                    canQuant = false
                }
            case 0x7D: o += "\\}"; canQuant = true; i += 1
            case 0x5D: o += "\\]"; canQuant = true; i += 1
            case 0x5B:
                if i + 1 < n && s[i + 1] == 0x5D { o += "(?!)"; i += 2; canQuant = true }
                else if i + 2 < n && s[i + 1] == 0x5E && s[i + 2] == 0x5D { o += "[\\s\\S]"; i += 3; canQuant = true }
                else {
                    inClass = true; i += 1
                    if i < n && s[i] == 0x5E { o += "[^"; i += 1 } else { o += "[" }
                }
            case 0x2E: o += "[^\\n\\r\\u2028\\u2029]"; canQuant = true; i += 1
            case 0x5E: o += "^"; canQuant = false; i += 1
            case 0x24: o += "\\z"; canQuant = false; i += 1
            default: o += ch(c); canQuant = true; i += 1
            }
        }
        if inClass || depth != 0 { throw bad("unterminated pattern") }
        do { return try NSRegularExpression(pattern: o) } catch { throw bad("\(error)") }
    }

    // ---- rule set validation, digest, signature ----

    private static let RULE_MEMBERS = ["v", "kind", "version", "rules", "digest", "sig"]
    private static let RULE_KEYS = ["id", "match", "adds", "note"]

    /// Nil if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names.
    public static func suggestRulesError(_ r: JSONValue?, _ known: Set<String>?) -> String? {
        guard case let .object(o)? = r else { return "rules must be an object" }
        for k in JS.keyOrder(o) where !RULE_MEMBERS.contains(k.s) { return "unknown member '\(k.s)'" }
        guard IV.num(o[JKey("v")]) == 1, o[JKey("kind")] == .string(SUGGEST_RULES_KIND) else { return "not a suggest-rules document (v 1)" }
        guard let version = o[JKey("version")]?.asString, Actions.fullMatch("[0-9]+\\.[0-9]+\\.[0-9]+", version) else { return "version must be semver" }
        guard case let .array(rs)? = o[JKey("rules")], !rs.isEmpty, rs.count <= MAX_RULES else { return "rules must be 1..\(MAX_RULES) entries" }
        var ids: [String] = []
        for x in rs {
            guard case let .object(rule) = x else { return "a rule must be an object" }
            for k in JS.keyOrder(rule) where !RULE_KEYS.contains(k.s) { return "rule: unknown member '\(k.s)'" }
            guard let rid = rule[JKey("id")]?.asString, Actions.fullMatch("SR-[0-9]{3,4}", rid), !ids.contains(rid) else { return "rule ids must be unique SR-nnn" }
            let w = rid
            ids.append(rid)
            guard let note = rule[JKey("note")]?.asString, !note.isEmpty, note.utf16.count <= 200 else { return "\(w): note must be 1..200 characters" }
            guard case let .object(m)? = rule[JKey("match")], !m.isEmpty else { return "\(w): match must be a non-empty object" }
            for k in JS.keyOrder(m) where !MATCH_KEYS.contains(k.s) { return "\(w): unknown match member '\(k.s)'" }
            for k in ["methods", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_formats", "roles"] where m[JKey(k)] != nil && !isStrList(m[JKey(k)], MAX_LIST) {
                return "\(w): match.\(k) must be 1..\(MAX_LIST) short strings"
            }
            if m[JKey("methods")] != nil { for s in Jx.a(m[JKey("methods")]) { if let ss = s.asString, ss != ss.uppercased() { return "\(w): methods are uppercase" } } }
            if m[JKey("param_types")] != nil {
                var badT = !isStrList(m[JKey("param_types")], MAX_LIST)
                if !badT { for t in Jx.a(m[JKey("param_types")]) where !PARAM_TYPES.contains(t.asString ?? "") { badT = true; break } }
                if badT { return "\(w): match.param_types is not a list of param types" }
            }
            if m[JKey("effects")] != nil && !isStrList(m[JKey("effects")], 12) { return "\(w): match.effects must be a list of effects" }
            if m[JKey("path_re")] != nil {
                guard let pr = m[JKey("path_re")]?.asString, !pr.isEmpty, pr.utf16.count <= 128 else { return "\(w): path_re must be 1..128 characters" }
                if found(NESTED_QUANTIFIER, pr) || found(BACKREF, pr) || found(LOOKAROUND, pr) {
                    return "\(w): path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)"
                }
                do { _ = try jsRegex(pr) } catch { return "\(w): path_re is not a regular expression" }
            }
            let hasParam = m[JKey("param_names")] != nil || m[JKey("param_names_all")] != nil || m[JKey("param_formats")] != nil || m[JKey("roles")] != nil
            if m[JKey("param_types")] != nil && m[JKey("param_names")] == nil && m[JKey("param_formats")] == nil && m[JKey("param_names_all")] == nil { return "\(w): param_types needs param_names, param_names_all or param_formats" }
            if !isStrList(rule[JKey("adds")], 16) { return "\(w): adds must be 1..16 entries" }
            for ao in Jx.a(rule[JKey("adds")]) {
                let a = ao.asString ?? ""
                if a.hasPrefix("tag:") {
                    if !PARAM_TAGS.contains(String(a.dropFirst(4))) { return "\(w): unknown tag '\(a)'" }
                    if !hasParam { return "\(w): a tag needs a param matcher" }
                } else if isRole(a) {
                    if !hasParam { return "\(w): a role needs a param matcher" }
                } else if Actions.fullMatch("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}", a) {
                    if let k = known, !k.contains(a) { return "\(w): unknown trait '\(a)'" }
                } else { return "\(w): '\(a)' is not a trait, role or tag:" }
            }
        }
        return nil
    }

    /// b64u sha256 of the strict canonical rule set (without digest and sig).
    public static func rulesDigest(_ r: JObject) throws -> String {
        var body: JObject = [:]
        for k in ["v", "kind", "version", "rules"] { if let v = r[JKey(k)] { body[JKey(k)] = v } }
        guard let h = IV.strictHash(AK.obj(["d": .string(SUGGEST_RULES_DOMAIN), "rules": .object(body)])) else { throw JSError("the rules are outside the strict JSON profile") }
        return h
    }

    public static func sealRules(_ r: JObject) throws -> JObject {
        var out = r
        out[JKey("digest")] = .string(try rulesDigest(r))
        return out
    }

    private static func rulesMessage(_ digest: String) throws -> [UInt8] {
        guard let m = IV.message(SUGGEST_RULES_DOMAIN + "\u{0}", AK.obj(["digest": .string(digest)])) else { throw JSError("the digest is outside the strict JSON profile") }
        return m
    }

    /// Sign a rule set as the rules publisher (a release step; the signature covers the digest).
    public static func signRules(_ r: JObject, _ kid: String, _ key: PCAEdKey) throws -> JObject {
        if let bad = suggestRulesError(.object(r), nil) { throw ActionKitError(code: "bad_rules", message: bad) }
        var sealed = try sealRules(r)
        let sig = try key.sign(try rulesMessage(JS.toString(sealed[JKey("digest")])))
        sealed[JKey("sig")] = AK.obj(["alg": .string("ed25519"), "kid": .string(kid), "value": .string(Base64URLStrict.encode(sig))])
        return sealed
    }

    /// Verify a signed rule set against pinned publisher keys (`[{kid, pk}]`): shape, digest, signature. Never throws.
    public static func verifyRules(_ doc: JSONValue?, _ pins: [JObject]) -> JObject {
        func no(_ why: String) -> JObject { [JKey("ok"): .bool(false), JKey("reason"): .string(why)] }
        if let bad = suggestRulesError(doc, nil) { return no(bad) }
        let d = AK.o(doc)
        guard let dg = try? rulesDigest(d), d[JKey("digest")] == .string(dg) else { return no("digest does not match the rules") }
        if !Jx.truthy(d[JKey("sig")]) { return no("the rule set is not signed") }
        let sig = d[JKey("sig")]
        let kid = Jx.get(sig, "kid")
        guard let key = pins.first(where: { kid != nil && kid != .null && kid == $0[JKey("kid")] }) else {
            return no("no pinned rules key '" + (Jx.has(sig, "kid") ? Jx.str(kid) : "undefined") + "'")
        }
        guard let pk = key[JKey("pk")]?.asString, let value = Jx.get(sig, "value")?.asString, let msg = try? rulesMessage(JS.toString(d[JKey("digest")])), Ed25519Strict.verifyB64u(pk, msg, value) else {
            return no("rules signature invalid")
        }
        return [JKey("ok"): .bool(true)]
    }

    // ---- facts ----

    /// Light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` to `charg`).
    public static func stem(_ t: String) -> String {
        var s = Array(t.utf16)
        func ends(_ x: String) -> Bool { let p = Array(x.utf16); return s.count >= p.count && Array(s[(s.count - p.count)...]) == p }
        if s.count > 4 && ends("ies") { s = Array(s[0..<(s.count - 3)]) + [0x79] }
        else if (ends("sses") || ends("xes") || ends("zes") || ends("ches") || ends("shes")) && s.count > 4 { s = Array(s[0..<(s.count - 2)]) }
        else if s.count > 3 && ends("s") && !ends("ss") { s = Array(s[0..<(s.count - 1)]) }
        if s.count > 5 && ends("ing") { s = Array(s[0..<(s.count - 3)]) }
        else if s.count > 4 && ends("ed") { s = Array(s[0..<(s.count - 2)]) }
        if s.count > 3 && ends("e") { s = Array(s[0..<(s.count - 1)]) }
        return String(decoding: s, as: UTF16.self)
    }

    private static let SEP = "|"

    public struct FParam { public let name: String; public let tokens: [String]; public let type: String?; public let format: String?; public let role: String? }

    /// What the rules read of a def: methods, binding locations, stemmed name tokens (with and without path segments), params and effects.
    public struct Facts {
        public var methods: Set<String> = []
        public var locs: [String] = []
        public var tokens: [String] = []
        public var strict: [String] = []
        public var params: [FParam] = []
        public var effects: Set<String> = []

        public func toJson() -> JSONValue {
            let ps: [JSONValue] = params.map { p in
                var m = Jx.obj(["name": .string(p.name), "tokens": Jx.strs(p.tokens), "type": p.type.map { .string($0) } ?? .null])
                if let f = p.format { m[o: "format"] = .string(f) }
                if let r = p.role { m[o: "role"] = .string(r) }
                return .object(m)
            }
            return AK.obj(["methods": Jx.strs(methods.sorted(by: u16less)), "locs": Jx.strs(locs), "tokens": Jx.strs(tokens), "strict": Jx.strs(strict), "params": .array(ps), "effects": Jx.strs(effects.sorted(by: u16less))])
        }
    }

    private static func stems(_ toks: [String]) -> [String] { toks.map(stem) }
    private static func up(_ s: JSONValue?) -> String { Jx.str(s).uppercased() }

    public static func factsOf(_ d: JObject) -> Facts {
        let b: JSONValue = JS.present(d[JKey("bindings")]) ?? .object([:])
        var f = Facts()
        var src: [[String]] = [], isPath: [Bool] = []
        let verbSegs = Jx.str(d[JKey("verb")]).components(separatedBy: ".")
        var vt: [String] = []
        for seg in verbSegs.dropFirst() { vt += ImportCommon.tokensOf(.string(seg)) }
        src.append(vt); isPath.append(false)
        if case let .array(al)? = d[JKey("aliases")] { for a in al { src.append(ImportCommon.tokensOf(a)); isPath.append(false) } }
        src.append(ImportCommon.tokensOf(d[JKey("title")])); isPath.append(false)
        let oa = Jx.get(b, "openapi")
        if Jx.truthy(oa) {
            src.append(ImportCommon.tokensOf(Jx.get(oa, "operationId"))); isPath.append(false)
            if Jx.truthy(Jx.get(oa, "method")) { f.methods.insert(up(Jx.get(oa, "method"))) }
            if Jx.truthy(Jx.get(oa, "path")) {
                let p = Jx.str(Jx.get(oa, "path"))
                f.locs.append(p)
                src.append(pathTokens(p)); isPath.append(true)
            }
        }
        let http = Jx.get(b, "http")
        if Jx.truthy(http) {
            f.methods.insert(up(Jx.get(http, "method")))
            let p = Jx.str(Jx.get(http, "path"))
            f.locs.append(p)
            src.append(pathTokens(p)); isPath.append(true)
        }
        let mcp = Jx.get(b, "mcp")
        if Jx.truthy(mcp) { f.locs.append(Jx.str(Jx.get(mcp, "tool"))); src.append(ImportCommon.tokensOf(Jx.get(mcp, "tool"))); isPath.append(false) }
        let gql = Jx.get(b, "graphql")
        if Jx.truthy(gql) { f.methods.insert(up(Jx.get(gql, "op"))); f.locs.append(Jx.str(Jx.get(gql, "field"))); src.append(ImportCommon.tokensOf(Jx.get(gql, "field"))); isPath.append(false) }
        let grpc = Jx.get(b, "grpc")
        if Jx.truthy(grpc) {
            f.locs.append(Jx.str(Jx.get(grpc, "service")) + "/" + Jx.str(Jx.get(grpc, "method")))
            src.append(ImportCommon.tokensOf(Jx.get(grpc, "service"))); isPath.append(false)
            src.append(ImportCommon.tokensOf(Jx.get(grpc, "method"))); isPath.append(false)
        }
        let asy = Jx.get(b, "asyncapi")
        if Jx.truthy(asy) { f.methods.insert(up(Jx.get(asy, "op"))); f.locs.append(Jx.str(Jx.get(asy, "channel"))); src.append(ImportCommon.tokensOf(Jx.get(asy, "channel"))); isPath.append(false) }
        for i in 0..<src.count {
            if !f.tokens.isEmpty { f.tokens.append(SEP) }
            f.tokens += stems(src[i])
            if !isPath[i] { if !f.strict.isEmpty { f.strict.append(SEP) }; f.strict += stems(src[i]) }
        }
        let params = d[JKey("params")]?.asObject ?? [:]
        for name in params.keys.map({ $0.s }).sorted(by: u16less) {
            let p = params[JKey(name)]
            let fm = Jx.get(p, "format"), ro = Jx.get(p, "role")
            f.params.append(FParam(name: name, tokens: stems(ImportCommon.tokensOf(.string(name))), type: Jx.get(p, "type")?.asString, format: Jx.truthy(fm) ? Jx.str(fm) : nil, role: Jx.truthy(ro) ? Jx.str(ro) : nil))
        }
        f.locs = f.locs.map { l in l.utf16.count > 512 ? String(decoding: Array(l.utf16.prefix(512)), as: UTF16.self) : l }
        if case let .array(el)? = d[JKey("effects")] { for e in el { f.effects.insert(Jx.str(e)) } }
        return f
    }

    private static func pathTokens(_ p: String) -> [String] {
        var out: [String] = []
        for s in p.components(separatedBy: "/") where !s.isEmpty && !s.contains("{") && !s.contains("}") { out += ImportCommon.tokensOf(.string(s)) }
        return out
    }

    /// True iff the stemmed pattern occurs as a contiguous run in `hay`.
    private static func hasSeq(_ hay: [String], _ pat: [String]) -> Bool {
        if pat.isEmpty { return false }
        var i = 0
        while i + pat.count <= hay.count {
            if Array(hay[i..<(i + pat.count)]) == pat { return true }
            i += 1
        }
        return false
    }

    private static func patOf(_ s: String) -> [String] { stems(ImportCommon.tokensOf(.string(s))) }

    public static func emptySuggestion() -> JObject { Jx.obj(["traits": .array([]), "roles": .object([:]), "tags": .object([:]), "fired": .array([])]) }

    private static let INT_ROLES: Set<String> = ["money.amount", "money.fee", "count.limit", "bytes.size"]

    private static func roleFits(_ role: String, _ type: String?) -> Bool {
        if INT_ROLES.contains(role) { return type == "integer" }
        if role.hasPrefix("time.") { return type == "date" || type == "datetime" || type == "integer" }
        return type == "string"
    }

    private static func strs(_ o: JSONValue?) -> [String] { Jx.a(o).map { Jx.str($0) } }

    /// Run the rules over a def. Only trait ids in `registry` (when given) can be suggested; anything else is dropped (the closed vocabulary).
    /// Pure and deterministic. Returns `{traits, roles, tags, fired}`.
    public static func suggestWithRules(_ d: JObject, _ rules: JObject, _ registry: TraitRegistry?) throws -> JObject {
        let f = factsOf(d)
        var traits = Set<String>()
        var roles: JObject = [:]
        var tags: [String: Set<String>] = [:]
        var fired: [JSONValue] = []
        guard case let .array(ruleList)? = rules[JKey("rules")] else { throw JSError("rules.rules is not iterable") }
        for ro in ruleList {
            guard case let .object(rule) = ro else { throw JSError("a rule must be an object") }
            guard case let .object(m)? = rule[JKey("match")] else { throw JSError("a rule match must be an object") }
            if Jx.truthy(m[JKey("methods")]) { if !strs(m[JKey("methods")]).contains(where: { f.methods.contains($0) }) { continue } }
            if Jx.truthy(m[JKey("effects")]) { if !strs(m[JKey("effects")]).contains(where: { f.effects.contains($0) }) { continue } }
            if Jx.truthy(m[JKey("name_tokens")]) { if !strs(m[JKey("name_tokens")]).contains(where: { hasSeq(f.tokens, patOf($0)) }) { continue } }
            if Jx.truthy(m[JKey("name_tokens_strict")]) { if !strs(m[JKey("name_tokens_strict")]).contains(where: { hasSeq(f.strict, patOf($0)) }) { continue } }
            if Jx.truthy(m[JKey("path_re")]) {
                let re = try jsRegex(Jx.str(m[JKey("path_re")]))
                if !f.locs.contains(where: { re.firstMatch(in: $0, range: NSRange(location: 0, length: $0.utf16.count)) != nil }) { continue }
            }
            if Jx.truthy(m[JKey("roles")]) {
                let rs = strs(m[JKey("roles")])
                if !f.params.contains(where: { $0.role != nil && rs.contains($0.role!) }) { continue }
            }
            var matched: [FParam] = []
            let paramCond = m[JKey("param_names")] != nil || m[JKey("param_formats")] != nil
            let ptypes: [String]? = Jx.truthy(m[JKey("param_types")]) ? strs(m[JKey("param_types")]) : nil
            if paramCond {
                var pats: [[String]] = []
                if Jx.truthy(m[JKey("param_names")]) { for n in strs(m[JKey("param_names")]) { pats.append(patOf(n)) } }
                for p in f.params {
                    if let pt = ptypes, !(p.type.map { pt.contains($0) } ?? false) { continue }
                    if Jx.truthy(m[JKey("param_names")]) { if !pats.contains(where: { hasSeq(p.tokens, $0) }) { continue } }
                    if Jx.truthy(m[JKey("param_formats")]) && (p.format == nil || !strs(m[JKey("param_formats")]).contains(p.format!)) { continue }
                    matched.append(p)
                }
                if matched.isEmpty { continue }
            }
            if Jx.truthy(m[JKey("param_names_all")]) {
                var ok = true
                for n in strs(m[JKey("param_names_all")]) {
                    let q = patOf(n)
                    let has = f.params.contains { hasSeq($0.tokens, q) && (ptypes == nil || ($0.type.map { ptypes!.contains($0) } ?? false) || $0.type == "string") }
                    if !has { ok = false; break }
                }
                if !ok { continue }
            }
            fired.append(rule[JKey("id")] ?? .null)
            for a in strs(rule[JKey("adds")]) {
                if a.hasPrefix("tag:") {
                    for p in matched { tags[p.name, default: []].insert(String(a.dropFirst(4))) }
                } else if !isRole(a) {
                    if registry == nil || registry!.traits[JKey(a)] != nil { traits.insert(a) }
                } else {
                    for p in matched where p.role == nil && roles[JKey(p.name)] == nil && roleFits(a, p.type) { roles[JKey(p.name)] = .string(a) }
                }
            }
        }
        traits.remove("pca.unreviewed")
        var tagOut: JObject = [:]
        for k in tags.keys { tagOut[JKey(k)] = Jx.strs(tags[k]!.sorted(by: u16less)) }
        return Jx.obj(["traits": Jx.strs(traits.sorted(by: u16less)), "roles": .object(roles), "tags": .object(tagOut), "fired": .array(fired)])
    }

    private static func sortedUnion(_ ls: [JSONValue]?...) -> [JSONValue] {
        var s = Set<String>()
        for l in ls { if let l = l { for x in l { s.insert(Jx.str(x)) } } }
        return s.sorted(by: u16less).map { .string($0) }
    }

    /// Union two suggestions (the restrictive direction, so no intersection is needed).
    public static func unionSuggestions(_ a: JObject, _ b: JObject) -> JObject {
        var roles = AK.o(b[JKey("roles")])
        for (k, v) in AK.o(a[JKey("roles")]) { roles[k] = v }
        var tags: JObject = [:]
        let ta = AK.o(a[JKey("tags")]), tb = AK.o(b[JKey("tags")])
        for k in Set(ta.keys).union(tb.keys) { tags[k] = .array(sortedUnion(ta[k]?.asArray, tb[k]?.asArray)) }
        let fired = AK.arr(a[JKey("fired")]) + AK.arr(b[JKey("fired")])
        return Jx.obj(["traits": .array(sortedUnion(AK.arr(a[JKey("traits")]), AK.arr(b[JKey("traits")]))), "roles": .object(roles), "tags": .object(tags), "fired": .array(fired)])
    }

    /// Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is removed or
    /// replaced, no attestation is created, and `review.state` goes from `unreviewed` to `suggested`. `by`: `{rules?: {version, digest, fired}, models?: [...]}`.
    public static func applySuggestion(_ d: JObject, _ s: JObject, _ by: JObject) -> JObject {
        var params: JObject = [:]
        var addedRoles: JObject = [:], addedTags: JObject = [:]
        let sroles = AK.o(s[JKey("roles")]), stags = AK.o(s[JKey("tags")])
        for (name, pv) in AK.o(d[JKey("params")]) {
            let p = AK.o(pv)
            var q = p
            if let role = JS.present(sroles[name]), JS.present(p[JKey("role")]) == nil, let rs = role.asString, roleFits(rs, p[JKey("type")]?.asString) { q[o: "role"] = role; addedRoles[name] = role }
            if let t = JS.present(stags[name]) {
                let have = AK.arr(p[JKey("tags")])
                let fresh = AK.arr(t).filter { !have.contains($0) }
                if !fresh.isEmpty { q[o: "tags"] = .array(sortedUnion(have, fresh)); addedTags[name] = .array(fresh) }
            }
            params[name] = .object(q)
        }
        let dtraits = AK.arr(d[JKey("traits")])
        let freshTraits = AK.arr(s[JKey("traits")]).filter { !dtraits.contains($0) }
        // a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
        var idempotency = JS.present(d[JKey("idempotency")])
        if AK.arr(s[JKey("traits")]).contains(.string("pca.money_moving")) && (idempotency == nil || idempotency?.get("mode") == .string("none")) {
            idempotency = AK.obj(["mode": .string("key_param"), "param": .string("idempotency_key")])
            if params[JKey("idempotency_key")] == nil { params[o: "idempotency_key"] = AK.obj(["type": .string("string"), "max_len": .int(64), "required": .bool(false)]) }
        }
        let review = AK.o(d[JKey("review")])
        let prev = review[JKey("suggested_by")]?.asObject ?? [:]
        let prevAdded: JObject = JS.present(prev[JKey("added")]).map { AK.o($0) } ?? Jx.obj(["traits": .array([]), "roles": .object([:]), "tags": .object([:])])
        var addedRolesAll = AK.o(prevAdded[JKey("roles")])
        for (k, v) in addedRoles { addedRolesAll[k] = v }
        let prevTags = AK.o(prevAdded[JKey("tags")])
        var tagsAll: JObject = [:]
        for k in Set(prevTags.keys).union(addedTags.keys) { tagsAll[k] = .array(sortedUnion(prevTags[k]?.asArray, addedTags[k]?.asArray)) }
        let added = Jx.obj(["traits": .array(sortedUnion(AK.arr(prevAdded[JKey("traits")]), freshTraits)), "roles": .object(addedRolesAll), "tags": .object(tagsAll)])
        let rules = JS.present(by[JKey("rules")]) ?? prev[JKey("rules")]
        let models = AK.arr(prev[JKey("models")]) + AK.arr(by[JKey("models")])
        var suggestedBy: JObject = [:]
        if let r = JS.present(rules) { suggestedBy[o: "rules"] = r }
        if !models.isEmpty { suggestedBy[o: "models"] = .array(models) }
        suggestedBy[o: "added"] = .object(added)
        let st = review[JKey("state")]
        let state: JSONValue = (st == .string("unreviewed") || st == .string("suggested")) ? .string("suggested") : (st ?? .null)
        var out = d
        out[o: "params"] = .object(params)
        if let i = idempotency { out[o: "idempotency"] = i }
        if !freshTraits.isEmpty || !dtraits.isEmpty { out[o: "traits"] = .array(sortedUnion(dtraits, AK.arr(s[JKey("traits")]))) }
        var nr = review
        nr[o: "state"] = state
        nr[o: "suggested_by"] = .object(suggestedBy)
        out[o: "review"] = .object(nr)
        return out
    }
}

/// The shipped suggestion rules: DATA, versioned. Every rule only ADDS. These are heuristics measured against a labeled corpus; none is a safety guarantee.
public enum ImportRules {
    public static let DEFAULT_RULES_VERSION = "1.1.0"

    public static let DEFAULT_RULES: JObject = AK.o(IV.normalized((try? StrictJSON.parseLenient(ImportRulesData.JSON_TEXT)) ?? .null))

    /// The default rule set with its digest.
    public static let DEFAULT_RULES_SEALED: JObject = (try? ImportSuggest.sealRules(DEFAULT_RULES)) ?? DEFAULT_RULES

    /// The digest recorded when the rule set was published.
    public static func publishedDigest() -> String { ImportRulesData.SEALED_DIGEST }
}
