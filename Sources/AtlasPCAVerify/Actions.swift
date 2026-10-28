import Foundation

/// Action kit (native port of the small deterministic core of the reference `pca-actions` package): strict ActionDef parse,
/// normalize and canonical digest, the trait registry and its closure/floor algebra, rule 22 (FloorDecision and the schema
/// floor integrity check), the pack Merkle root and inclusion proof, and T(d)/eff(d) with the signed human confirmation. Integers and sets only; every function
/// is pure. The shared vectors pin every output byte for byte. ActionSchema v2 parsing and the v2 parameter types and formats
/// of `conformAction` live in ActionSchema.swift.
public struct ActionKitError: Error, Equatable {
    public let code: String
    public let message: String
}

/// A restriction profile: componentwise max / union lattice (risk, rev, blast, esc; caveats, context, prules).
public struct Profile: Equatable, Sendable {
    public var risk: Int
    public var rev: String
    public var blastPpm: Int
    public var esc: Int
    public var caveats: [String]
    public var context: [String]
    public var prules: [String]

    public init(risk: Int = 0, rev: String = "reversible", blastPpm: Int = 0, esc: Int = 0, caveats: [String] = [], context: [String] = [], prules: [String] = []) {
        self.risk = risk; self.rev = rev; self.blastPpm = blastPpm; self.esc = esc
        self.caveats = Actions.sortUniq(caveats); self.context = Actions.sortUniq(context); self.prules = Actions.sortUniq(prules)
    }

    public static let bottom = Profile()

    public var json: JSONValue {
        .object(["risk": .int(Int64(risk)), "rev": .string(rev), "blast_ppm": .int(Int64(blastPpm)), "esc": .int(Int64(esc)),
                 "caveats": .array(caveats.map { .string($0) }), "context": .array(context.map { .string($0) }), "prules": .array(prules.map { .string($0) })])
    }

    /// Parse a profile that already passed `Actions.profileError` (or nil when a member is missing / mistyped).
    public init?(json v: JSONValue?) {
        guard case let .object(o)? = v, let r = IV.int(o["risk"]), let rv = o["rev"]?.asString, let b = IV.int(o["blast_ppm"]), let e = IV.int(o["esc"]),
              let c = Actions.strings(o["caveats"]), let x = Actions.strings(o["context"]), let p = Actions.strings(o["prules"]) else { return nil }
        self.init(risk: Int(r), rev: rv, blastPpm: Int(b), esc: Int(e), caveats: c, context: x, prules: p)
    }
}

public struct TraitDef: Equatable, Sendable {
    public let id: String
    public let implies: [String]
    public let floor: Profile
    public let cardPhrase: String
}

public struct TraitRegistry: Sendable {
    public let traits: [JKey: TraitDef]
    func json() -> [JSONValue] {
        traits.values.map { t in .object(["id": .string(t.id), "implies": .array(t.implies.map { .string($0) }), "floor": t.floor.json, "card_phrase": .string(t.cardPhrase)]) }
    }
}

public enum Actions {
    // ---- vocabularies ---------------------------------------------------------------------------------------------------
    static let EFFECTS = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"]
    static let REVERSIBILITY = ["reversible", "rate_limited", "irreversible"]
    static let REV_RANK: [String: Int] = ["reversible": 0, "rate_limited": 1, "irreversible": 2]
    static let BLAST_RADII = ["one", "bounded", "tenant", "global"]
    static let BLAST_PPM: [String: Int] = ["one": 50_000, "bounded": 300_000, "tenant": 700_000, "global": 1_000_000]
    static let RESOURCE_SCOPES = ["one", "set", "tenant", "global"]
    static let SCOPE_BLAST: [String: String] = ["one": "one", "set": "bounded", "tenant": "tenant", "global": "global"]
    static let PARAM_TYPES = ["string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"]
    static let SENSITIVITY_RANK: [String: Int] = ["free": 0, "material": 1, "critical": 2]
    static let PROVENANCE = ["first_party", "tool", "agent"]
    static let CORE_ROLES = [
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    ]
    static let PARAM_TAGS = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"]
    static let PARAM_FORMATS = ["email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256"]
    static let UNIT_KINDS = ["money", "count", "bytes", "duration", "ratio"]
    static let CAVEAT_KINDS = ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"]
    static let CONTEXT_KEYS = ["approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"]
    static let PARAM_RULE_IDS = ["array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
                                 "pay_has_idempotency", "recipient_param_declared", "secret_not_logged"]
    static let IDEMPOTENCY_MODES = ["key_param", "natural", "none"]
    static let REVIEW_STATES = ["authored", "unreviewed", "suggested", "confirmed"]
    static let BINDING_KINDS = ["mcp", "openapi", "http", "graphql", "grpc", "asyncapi"]
    static let ID_CLASSES = ["digits", "hex", "alnum", "slug", "uuid", "any_safe"]
    static let PARAM_KEYS = ["type", "role", "required", "values", "min", "max", "max_len", "items", "min_items", "max_items", "format", "unit", "tags",
                             "provenance_min", "sensitivity", "accumulates", "default", "principal_neutral_default", "description"]
    static let DEF_KEYS = ["v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
                           "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since"]
    static let INT_ROLES = ["money.amount", "money.fee", "count.limit", "bytes.size"]
    static let VERB_FACTS_DOMAIN = "atlas-pca/action-verb-facts/v1"
    static let DEF_DIGEST_DOMAIN = "atlas-pca/action-def/v1"
    static let TRAITS_DIGEST_DOMAIN = "atlas-pca/action-traits/v1"
    static let ROLES_DIGEST_DOMAIN = "atlas-pca/action-roles/v1"
    static let PACK_DIGEST_DOMAIN = "atlas-pca/action-pack/v1"

    // ---- helpers --------------------------------------------------------------------------------------------------------

    static func strings(_ v: JSONValue?) -> [String]? {
        guard case let .array(a)? = v else { return nil }
        var out: [String] = []
        for x in a { guard let s = x.asString else { return nil }; out.append(s) }
        return out
    }
    static func sortUniq(_ xs: [String]) -> [String] {
        var out: [String] = []
        for x in xs.sorted(by: IV.utf8Less) where out.last.map({ !IV.same($0, x) }) ?? true { out.append(x) }
        return out
    }
    static func isStr(_ v: JSONValue?, _ max: Int = 256) -> Bool {
        guard let s = v?.asString else { return false }
        return !s.isEmpty && IV.u8(s) <= max
    }
    static func inList(_ list: [String], _ v: JSONValue?) -> Bool { v?.asString.map { IV.contains(list, $0) } ?? false }
    static func subset(_ a: [String], _ b: [String]) -> Bool { a.allSatisfy { IV.contains(b, $0) } }
    static func isInt(_ v: JSONValue?) -> Bool { IV.int(v) != nil }

    // ASCII pattern pieces (a non-ASCII byte never matches, like the reference's ASCII classes).
    private static func lower(_ c: UInt8) -> Bool { c >= 97 && c <= 122 }
    private static func digit(_ c: UInt8) -> Bool { c >= 48 && c <= 57 }
    private static func ldu(_ c: UInt8) -> Bool { lower(c) || digit(c) || c == 95 }
    private static func segs(_ s: String) -> [[UInt8]] { s.utf8.split(separator: 46, omittingEmptySubsequences: false).map { Array($0) } }
    /// `[a-z][a-z0-9_]{0,first-1}` then `(\.[a-z0-9_]{1,rest}){minTail,maxTail}`
    private static func dotted(_ s: String, first: Int, rest: Int, tail: ClosedRange<Int>) -> Bool {
        let g = segs(s)
        guard let h = g.first, !h.isEmpty, h.count <= first, lower(h[0]), h.allSatisfy(ldu), tail.contains(g.count - 1) else { return false }
        return g.dropFirst().allSatisfy { !$0.isEmpty && $0.count <= rest && $0.allSatisfy(ldu) }
    }
    static func isVerb(_ s: String) -> Bool { dotted(s, first: 32, rest: 32, tail: 1...5) }
    static func isAlias(_ s: String) -> Bool { dotted(s, first: 32, rest: 32, tail: 0...5) }
    static func isResourceType(_ s: String) -> Bool { dotted(s, first: 32, rest: 32, tail: 0...4) }
    static func isTraitId(_ s: String) -> Bool {
        let g = segs(s)
        return g.count == 2 && zip(g, [32, 64]).allSatisfy { (x, m) in !x.isEmpty && x.count <= m && lower(x[0]) && x.allSatisfy(ldu) }
    }
    static func isParamName(_ s: String) -> Bool {
        let g = segs(s)
        return (1...3).contains(g.count) && g.allSatisfy { x in (1...64).contains(x.count) && x.allSatisfy { ldu($0) || ($0 >= 65 && $0 <= 90) } }
    }
    private static func dotSegs(_ s: String, _ r: ClosedRange<Int>) -> Bool {
        let g = segs(s)
        return r.contains(g.count) && g.allSatisfy { !$0.isEmpty && $0.allSatisfy(ldu) }
    }
    static func isRole(_ v: JSONValue?) -> Bool {
        guard let r = v?.asString else { return false }
        if IV.contains(CORE_ROLES, r) { return true }
        if IV.startsWith(r, "id.") { return dotSegs(IV.dropPrefix(r, 3), 1...4) }
        if IV.startsWith(r, "x.") { return dotSegs(IV.dropPrefix(r, 2), 2...4) }
        return false
    }
    static func isFormat(_ v: JSONValue?) -> Bool {
        guard let f = v?.asString else { return false }
        return IV.contains(PARAM_FORMATS, f) || (IV.startsWith(f, "id:") && dotSegs(IV.dropPrefix(f, 3), 1...4))
    }
    static func isContextKey(_ s: String) -> Bool { IV.contains(CONTEXT_KEYS, s) || ActionSchema.isTaintContext(s) }

    private static func strList(_ v: JSONValue?, _ max: Int, _ ok: (String) -> Bool) -> Bool {
        guard let a = strings(v), a.count <= max else { return false }
        return a.allSatisfy(ok) && IV.distinct(a)
    }

    // ---- strict JSON profile + ActionDef validation ---------------------------------------------------------------------------

    private static func nfc(_ s: String) -> Bool { s.precomposedStringWithCanonicalMapping.unicodeScalars.elementsEqual(s.unicodeScalars) }

    /// Strict JSON profile: NFC strings without lone surrogates, safe integers only, depth <= 32.
    public static func jsonProfileError(_ v: JSONValue, _ depth: Int = 0) -> String? {
        if depth > 32 { return "nesting deeper than 32" }
        switch v {
        case .null, .bool: return nil
        case .int, .double: return IV.int(v) != nil ? nil : "numbers must be safe integers (no floats, no -0)"
        case let .string(s):
            if Canonical.hasLoneSurrogate(s) { return "string has a lone surrogate" }
            return nfc(s) ? nil : "string is not NFC"
        case let .array(a):
            for x in a { if let e = jsonProfileError(x, depth + 1) { return e } }
            return nil
        case let .object(o):
            for (k, x) in o {
                if Canonical.hasLoneSurrogate(k.s) || !nfc(k.s) { return "member name is not NFC / has a lone surrogate" }
                if let e = jsonProfileError(x, depth + 1) { return e }
            }
            return nil
        }
    }

    private static let classChars: [String: String] = {
        let d = "0123456789", l = "abcdefghijklmnopqrstuvwxyz"
        return ["digits": d, "hex": d + "abcdef", "alnum": d + l + l.uppercased(), "slug": d + l + "-_", "uuid": d + "abcdef-", "any_safe": d + l + l.uppercased() + "._-:/"]
    }()
    private static func inClass(_ s: String, _ c: String) -> Bool { let cs = Set(classChars[c]!.unicodeScalars); return s.unicodeScalars.allSatisfy { cs.contains($0) } }

    static func idPatternError(_ p: JSONValue?) -> String? {
        if p?.asString == "*" { return nil }
        guard case let .object(o)? = p else { return "resource.id must be '*', {exact} or {prefix, class, len}" }
        let keys = o.keys.map { $0.s }.sorted(by: IV.utf8Less).joined(separator: ",")
        if keys == "exact" {
            if let e = o["exact"]?.asString, (1...128).contains(e.utf16.count), inClass(e, "any_safe") { return nil }
            return "resource.id.exact must be 1..128 safe characters"
        }
        if keys != "class,len,prefix" { return "resource.id must be '*', {exact} or {prefix, class, len}" }
        guard let pre = o["prefix"]?.asString, pre.utf16.count <= 32, inClass(pre, "any_safe") else { return "resource.id.prefix must be up to 32 safe characters" }
        if !inList(ID_CLASSES, o["class"]) { return "resource.id.class is not an id class" }
        guard case let .array(ln)? = o["len"], ln.count == 2, let lo = IV.int(ln[0]), let hi = IV.int(ln[1]), (1...128).contains(lo), (1...128).contains(hi) else {
            return "resource.id.len must be [min, max] in 1..128"
        }
        if lo > hi { return "resource.id.len: min > max" }
        if o["class"]?.asString == "uuid" && (!pre.isEmpty || lo != 36 || hi != 36) { return "a uuid id has no prefix and length exactly [36, 36]" }
        return nil
    }

    static func paramNameError(_ name: String) -> String? {
        if !isParamName(name) { return "param name '\(name)' is malformed" }
        if IV.split(name, ".").contains(where: { IV.isReserved($0) }) { return "param name '\(name)' is reserved" }
        return nil
    }

    private static func isUnitCcy(_ s: String) -> Bool { s.utf8.count == 3 && s.utf8.allSatisfy { $0 >= 65 && $0 <= 90 } }

    private static func paramError(_ name: String, _ pv: JSONValue, _ names: Set<JKey>) -> String? {
        guard case let .object(p) = pv else { return "\(name): declaration must be an object" }
        for k in p.keys where !PARAM_KEYS.contains(where: { IV.same($0, k.s) }) { return "\(name): unknown member '\(k.s)'" }
        guard inList(PARAM_TYPES, p["type"]) else { return "\(name): unknown type" }
        let t = p["type"]!.asString!
        if let r = p["role"], !isRole(r) { return "\(name): unknown role" }
        if let r = p["role"]?.asString, IV.contains(INT_ROLES, r), t != "integer" { return "\(name): role requires an integer parameter" }
        if let r = p["required"], case .bool = r {} else if p["required"] != nil { return "\(name): required must be a boolean" }
        if let vv = p["values"] {
            guard let vs = strings(vv), (1...256).contains(vs.count), vs.allSatisfy({ isStr(.string($0)) }) else { return "\(name): values must be 1..256 non-empty strings" }
            if !IV.distinct(vs) { return "\(name): values must be distinct" }
            if t != "string" && t != "set" { return "\(name): values apply to string and set only" }
        }
        if t == "set" && p["values"] == nil { return "\(name): a set needs values" }
        let intLike = t == "integer" || t == "duration" || (t == "array" && p["items"]?.asString == "integer")
        for k in ["min", "max"] where p[JKey(k)] != nil {
            if !isInt(p[JKey(k)]) || !intLike { return "\(name): \(k) must be a safe integer on an integer parameter" }
        }
        if let lo = IV.int(p["min"]), let hi = IV.int(p["max"]), lo > hi { return "\(name): min > max" }
        if let ml = p["max_len"] {
            guard let n = IV.int(ml), (1...16_777_216).contains(n), ["string", "array", "object_ref"].contains(t) else { return "\(name): max_len must be 1..16777216 on a string or array" }
        }
        if let it = p["items"], t != "array" || !isStr(it, 64) { return "\(name): items applies to array only" }
        for k in ["min_items", "max_items"] where p[JKey(k)] != nil {
            if IV.nonNeg(p[JKey(k)]) == nil || (t != "set" && t != "array") { return "\(name): \(k) must be a non-negative integer on a set or array" }
        }
        if let lo = IV.int(p["min_items"]), let hi = IV.int(p["max_items"]), lo > hi { return "\(name): min_items > max_items" }
        if p["format"] != nil && (!isFormat(p["format"]) || (t != "string" && t != "object_ref")) { return "\(name): format must be a known format on a string parameter" }
        if let u = p["unit"] {
            if t != "integer" { return "\(name): unit applies to integer parameters only" }
            guard case let .object(uo) = u, inList(UNIT_KINDS, uo["kind"]) else { return "\(name): unit.kind is not a known kind" }
            if uo["kind"]?.asString == "money" {
                if uo.keys.contains(where: { !["kind", "ccy", "exp"].contains($0.s) }) { return "\(name): unit has unknown members" }
                guard let ex = IV.int(uo["exp"]), (0...18).contains(ex) else { return "\(name): unit.exp must be an integer in 0..18" }
                if let c = uo["ccy"]?.asString {
                    if !isUnitCcy(c) { return "\(name): unit.ccy must be an ISO 4217 style code" }
                } else if case let .object(co)? = uo["ccy"], co.count == 1, let from = co["from"]?.asString, names.contains(JKey(from)) {
                } else { return "\(name): unit.ccy.from must name a declared parameter" }
            } else if uo.count != 1 { return "\(name): unit has unknown members" }
        }
        if let tg = p["tags"] {
            guard let ts = strings(tg), ts.count <= PARAM_TAGS.count, ts.allSatisfy({ IV.contains(PARAM_TAGS, $0) }), IV.distinct(ts) else { return "\(name): tags must be distinct known tags" }
        }
        if p["provenance_min"] != nil && !inList(PROVENANCE, p["provenance_min"]) { return "\(name): unknown provenance_min" }
        if p["sensitivity"] != nil && !inList(["free", "material", "critical"], p["sensitivity"]) { return "\(name): unknown sensitivity" }
        if let a = p["accumulates"] {
            if t != "integer" { return "\(name): accumulates applies to integer parameters only" }
            guard let us = strings(a), (1...8).contains(us.count), us.allSatisfy({ $0.utf16.count <= 64 && IV.isUnitId($0) }), IV.distinct(us) else { return "\(name): accumulates must be 1..8 distinct unit ids" }
        }
        if p["default"] == .null { return "\(name): default must not be null (absent = no default)" }
        if let pn = p["principal_neutral_default"] {
            guard case let .bool(b) = pn else { return "\(name): principal_neutral_default must be a boolean" }
            if b && p["default"] == nil { return "\(name): principal_neutral_default needs a default" }
        }
        if let d = p["description"], !isStr(d, 1024) { return "\(name): description must be a string up to 1024 bytes" }
        return nil
    }

    private static func bindingsError(_ bv: JSONValue) -> String? {
        guard case let .object(b) = bv else { return "bindings must be an object" }
        let shapes: [String: ([String], [String])] = ["mcp": (["tool"], []), "openapi": (["operationId"], ["method", "path"]), "http": (["method", "path"], []),
                                                      "graphql": (["op", "field"], []), "grpc": (["service", "method"], []), "asyncapi": (["channel", "op"], [])]
        for (k, v) in b.sorted(by: { $0.key < $1.key }) {
            guard BINDING_KINDS.contains(where: { IV.same($0, k.s) }), let (req, opt) = shapes[k.s] else { return "bindings: unknown kind '\(k.s)'" }
            guard case let .object(o) = v else { return "bindings.\(k.s) must be an object" }
            for m in o.keys where !(req + opt).contains(where: { IV.same($0, m.s) }) { return "bindings.\(k.s): unknown member '\(m.s)'" }
            for m in req where !isStr(o[JKey(m)], 256) { return "bindings.\(k.s).\(m) must be a non-empty string" }
            for m in opt where o[JKey(m)] != nil && !isStr(o[JKey(m)], 256) { return "bindings.\(k.s).\(m) must be a non-empty string" }
        }
        if let g = b["graphql"], !inList(["query", "mutation", "subscription"], g.get("op")) { return "bindings.graphql.op is not a GraphQL operation kind" }
        if let a = b["asyncapi"], !inList(["send", "receive"], a.get("op")) { return "bindings.asyncapi.op must be send or receive" }
        return nil
    }

    private static func reviewError(_ rv: JSONValue?) -> String? {
        guard case let .object(r)? = rv else { return "review must be an object" }
        for k in r.keys where !["state", "attestation", "suggested_by"].contains(where: { IV.same($0, k.s) }) { return "review: unknown member '\(k.s)'" }
        if !inList(REVIEW_STATES, r["state"]) { return "review.state is not a review state" }
        if let av = r["attestation"] {
            guard case let .object(a) = av else { return "review.attestation must be an object" }
            for k in a.keys where !["def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"].contains(where: { IV.same($0, k.s) }) {
                return "review.attestation: unknown member '\(k.s)'"
            }
            if !isStr(a["def_digest"], 64) || !isStr(a["traits_digest"], 64) || !isStr(a["facts_digest"], 64) || !isStr(a["reviewer_kid"], 128) || IV.nonNeg(a["ts"]) == nil {
                return "review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required"
            }
            if !strList(a["final_traits"], 32, isTraitId) { return "review.attestation.final_traits must be distinct trait ids" }
            guard case let .array(d)? = a["dismissed"], d.count <= 32, d.allSatisfy({ x in
                guard case let .object(o) = x, o.count == 2, let t = o["trait"]?.asString else { return false }
                return isTraitId(t) && isStr(o["reason"], 256)
            }) else { return "review.attestation.dismissed must be {trait, reason} entries" }
            if let s = a["sig"], !isStr(s, 4096) { return "review.attestation.sig must be a string" }
        }
        return nil
    }

    /// nil if `x` is a well-formed ActionDef (structure only: registry, prules and lint checks are separate).
    public static func validateDef(_ x: JSONValue) -> String? {
        if let je = jsonProfileError(x) { return "not strict JSON: " + je }
        guard case let .object(d) = x else { return "def must be an object" }
        for k in d.keys where !DEF_KEYS.contains(where: { IV.same($0, k.s) }) { return "unknown member '\(k.s)'" }
        if IV.int(d["v"]) != 1 { return "unsupported def version" }
        if d["kind"]?.asString != "pca-action-def" { return "kind must be 'pca-action-def'" }
        guard let verb = d["verb"]?.asString, isVerb(verb), IV.u8(verb) <= 128 else { return "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)" }
        if let al = d["aliases"] {
            if !strList(al, 16, { isAlias($0) && IV.u8($0) <= 128 }) || IV.contains(strings(al)!, verb) { return "aliases must be distinct verb-shaped names other than the verb" }
        }
        if !isStr(d["title"], 120) { return "title must be a non-empty string up to 120 bytes" }
        if let ds = d["description"], !isStr(ds, 1024) { return "description must be a string" }
        guard strList(d["effects"], EFFECTS.count, { IV.contains(EFFECTS, $0) }), !strings(d["effects"])!.isEmpty else { return "effects must be 1..12 distinct known effects" }
        guard case let .object(r)? = d["resource"], r.count == 3, r["id"] != nil, r["scope"] != nil, r["type"] != nil else { return "resource must be {type, id, scope}" }
        guard let rt = r["type"]?.asString, isResourceType(rt), rt.utf16.count <= 128 else { return "resource.type is malformed" }
        if let e = idPatternError(r["id"]) { return e }
        if !inList(RESOURCE_SCOPES, r["scope"]) { return "resource.scope is not a scope" }
        guard case let .object(params)? = d["params"] else { return "params must be an object" }
        let names = params.keys.sorted()
        if names.count > 64 { return "more than 64 parameters" }
        let nameSet = Set(names)
        for n in names {
            if let e = paramNameError(n.s) { return e }
            for m in names where m != n && IV.startsWith(m.s, n.s + ".") { return "param '\(n.s)' is both a value and the parent of '\(m.s)'" }
        }
        for n in names { if let e = paramError(n.s, params[n]!, nameSet) { return e } }
        if let rv = d["reversibility"] {
            if rv.asString == nil {
                guard case let .object(ro) = rv, ro.keys.allSatisfy({ ["by", "map", "default"].contains($0.s) }) else { return "reversibility must be a class or {by, map, default?}" }
                guard let by = ro["by"]?.asString, nameSet.contains(JKey(by)) else { return "reversibility.by must name a declared parameter" }
                guard case let .object(m)? = ro["map"], (1...256).contains(m.count), m.allSatisfy({ isStr(.string($0.key.s), 128) && inList(REVERSIBILITY, $0.value) }) else {
                    return "reversibility.map must map values to reversibility classes"
                }
                if let df = ro["default"], !inList(REVERSIBILITY, df) { return "reversibility.default is not a class" }
            } else if !inList(REVERSIBILITY, rv) { return "unknown reversibility class" }
        }
        if let bv = d["blast"] {
            guard case let .object(b) = bv, b.keys.allSatisfy({ ["radius", "ppm"].contains($0.s) }), inList(BLAST_RADII, b["radius"]) else { return "blast must be {radius, ppm?}" }
            if let pp = b["ppm"], !(IV.int(pp).map { (0...1_000_000).contains($0) } ?? false) { return "blast.ppm must be an integer in 0..1000000" }
        }
        if let sv = d["side_effects"] {
            guard case let .array(s) = sv, s.count <= 16, s.allSatisfy({ e in
                guard case let .object(o) = e, o.count == 2 else { return false }
                return isStr(o["target"], 128) && inList(EFFECTS, o["kind"])
            }) else { return "side_effects must be {target, kind} entries" }
        }
        if let iv = d["idempotency"] {
            guard case let .object(i) = iv, i.keys.allSatisfy({ ["mode", "param"].contains($0.s) }), inList(IDEMPOTENCY_MODES, i["mode"]) else { return "idempotency must be {mode, param?}" }
            let bad = i["mode"]?.asString == "key_param" ? !(i["param"]?.asString.map { nameSet.contains(JKey($0)) } ?? false) : i["param"] != nil
            if bad { return "idempotency.param is required for key_param (a declared parameter) and forbidden otherwise" }
        }
        if let c = d["context"], !strList(c, 16, isContextKey) { return "context must be distinct known context keys" }
        if let t = d["traits"], !strList(t, 32, isTraitId) { return "traits must be distinct trait ids" }
        if let a = d["audience"], a.asString != "resource" { return "audience must be 'resource'" }
        if let c = d["compensates"], !(c.asString.map { isVerb($0) } ?? false) { return "compensates must be a verb" }
        if let b = d["bindings"], let e = bindingsError(b) { return e }
        if let exv = d["examples"] {
            guard case let .array(ex) = exv, ex.count <= 32 else { return "examples must be an array of up to 32 entries" }
            for e in ex {
                guard case let .object(o) = e, o.keys.allSatisfy({ ["params", "under", "expect"].contains($0.s) }), o["params"]?.isObject == true,
                      inList(["allow", "escalate", "deny"], o["expect"]) else { return "example must be {params, under?, expect}" }
            }
        }
        if let e = reviewError(d["review"]) { return e }
        if let sv = d["source"] {
            guard case let .object(s) = sv, s.keys.allSatisfy({ ["kind", "uri", "spec_digest", "licence", "imported_at"].contains($0.s) }), isStr(s["kind"], 64), isStr(s["uri"], 2048),
                  isStr(s["spec_digest"], 128), isStr(s["licence"], 128), s["imported_at"] == nil || IV.nonNeg(s["imported_at"]) != nil else {
                return "source must be {kind, uri, spec_digest, licence, imported_at?}"
            }
        }
        if let s = d["since"], !isStr(s, 64) { return "since must be a string" }
        return nil
    }

    // ---- profile lattice + trait registry -----------------------------------------------------------------------------------

    public static func profileError(_ pv: JSONValue?) -> String? {
        guard case let .object(p)? = pv else { return "profile must be an object" }
        for k in p.keys where !["risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"].contains(where: { IV.same($0, k.s) }) { return "profile: unknown member '\(k.s)'" }
        func rng(_ x: JSONValue?, _ hi: Int64) -> Bool { IV.int(x).map { $0 >= 0 && $0 <= hi } ?? false }
        if !rng(p["risk"], 3) { return "profile.risk must be an integer in 0..3" }
        if !inList(REVERSIBILITY, p["rev"]) { return "profile.rev is not a reversibility class" }
        if !rng(p["blast_ppm"], 1_000_000) { return "profile.blast_ppm must be an integer in 0..1000000" }
        if !rng(p["esc"], 3) { return "profile.esc must be an integer in 0..3" }
        for (name, ok) in [("caveats", { (x: String) in IV.contains(CAVEAT_KINDS, x) }), ("context", isContextKey), ("prules", { (x: String) in IV.contains(PARAM_RULE_IDS, x) })] {
            guard let a = strings(p[JKey(name)]), a.count <= 64, a.allSatisfy(ok) else { return "profile.\(name) must be an array of known \(name) entries" }
            for i in 1..<max(a.count, 1) where !IV.utf8Less(a[i - 1], a[i]) { return "profile.\(name) must be sorted and distinct" }
        }
        return nil
    }

    public static func join(_ p: Profile, _ q: Profile) -> Profile {
        Profile(risk: max(p.risk, q.risk), rev: REV_RANK[p.rev]! >= REV_RANK[q.rev]! ? p.rev : q.rev, blastPpm: max(p.blastPpm, q.blastPpm), esc: max(p.esc, q.esc),
                caveats: p.caveats + q.caveats, context: p.context + q.context, prules: p.prules + q.prules)
    }
    public static func joinAll(_ ps: [Profile]) -> Profile { ps.reduce(Profile.bottom, join) }
    public static func leq(_ p: Profile, _ q: Profile) -> Bool {
        p.risk <= q.risk && REV_RANK[p.rev]! <= REV_RANK[q.rev]! && p.blastPpm <= q.blastPpm && p.esc <= q.esc
            && subset(p.caveats, q.caveats) && subset(p.context, q.context) && subset(p.prules, q.prules)
    }

    /// nil if `defs` form a valid registry, else the first reason: ids well formed and distinct, `pca.` reserved unless `core`, implies resolve,
    /// a trait only extends what it implies (T5), no cycle, implies depth <= 8.
    public static func registryError(_ defs: [JSONValue], core: Bool = false) -> String? {
        if defs.count > 512 { return "a registry holds at most 512 traits" }
        var by: [JKey: JObject] = [:]
        var order: [JKey] = []
        for tv in defs {
            guard case let .object(t) = tv else { return "trait must be an object" }
            guard let id = t["id"]?.asString, isTraitId(id) else { return "trait id '\(t["id"]?.asString ?? "?")' is malformed" }
            if IV.startsWith(id, "pca.") && !core { return "trait '\(id)': the pca. namespace is reserved for core traits" }
            if by[JKey(id)] != nil { return "trait '\(id)' is defined twice" }
            guard let im = strings(t["implies"]), im.count <= 8, IV.distinct(im) else { return "trait '\(id)': implies must be up to 8 distinct trait ids" }
            if let pe = profileError(t["floor"]) { return "trait '\(id)': \(pe)" }
            guard let cp = t["card_phrase"]?.asString, (1...120).contains(cp.utf16.count) else { return "trait '\(id)': card_phrase must be a non-empty string up to 120 characters" }
            by[JKey(id)] = t
            order.append(JKey(id))
        }
        for id in order {
            let t = by[id]!
            for u in strings(t["implies"])! {
                guard let ud = by[JKey(u)] else { return "trait '\(id.s)' implies unknown trait '\(u)'" }
                if !leq(Profile(json: ud["floor"])!, Profile(json: t["floor"])!) { return "trait '\(id.s)': floor is below the floor of implied '\(u)'" }
            }
        }
        var depth: [JKey: Int] = [:]
        var visiting = Set<JKey>()
        func walk(_ id: JKey) -> Int {
            if let d = depth[id] { return d }
            if visiting.contains(id) { return -1 }
            visiting.insert(id)
            var d = 1
            for u in strings(by[id]!["implies"])! {
                let du = walk(JKey(u))
                if du < 0 { return -1 }
                d = max(d, du + 1)
            }
            visiting.remove(id)
            depth[id] = d
            return d
        }
        for id in order {
            let d = walk(id)
            if d < 0 { return "trait '\(id.s)': implies cycle" }
            if d > 8 { return "trait '\(id.s)': implies depth \(d) exceeds 8" }
        }
        return nil
    }

    static func registry(from defs: [JSONValue]) -> TraitRegistry {
        var m: [JKey: TraitDef] = [:]
        for case let .object(t) in defs {
            let id = t["id"]!.asString!
            m[JKey(id)] = TraitDef(id: id, implies: strings(t["implies"])!, floor: Profile(json: t["floor"])!, cardPhrase: t["card_phrase"]!.asString!)
        }
        return TraitRegistry(traits: m)
    }

    public static func buildRegistry(_ defs: [JSONValue], core: Bool = false) throws -> TraitRegistry {
        if let e = registryError(defs, core: core) { throw ActionKitError(code: "bad_registry", message: e) }
        return registry(from: defs)
    }

    /// The core registry extended with custom traits (which must not use `pca.` and must extend what they imply).
    public static func extendRegistry(_ base: TraitRegistry, _ custom: [JSONValue]) throws -> TraitRegistry {
        for c in custom {
            guard let id = c.get("id")?.asString, base.traits[JKey(id)] == nil, !IV.startsWith(id, "pca.") else {
                throw ActionKitError(code: "bad_registry", message: "custom trait may not redefine a core trait")
            }
        }
        return try buildRegistry(base.json() + custom, core: true)
    }

    public static func closure(_ reg: TraitRegistry, _ ids: [String]) throws -> [String] {
        var seen = Set<JKey>()
        var stack = ids
        while let id = stack.popLast() {
            if seen.contains(JKey(id)) { continue }
            guard let t = reg.traits[JKey(id)] else { throw ActionKitError(code: "unknown_trait", message: "unknown trait '\(id)'") }
            seen.insert(JKey(id))
            stack.append(contentsOf: t.implies)
        }
        return seen.map { $0.s }.sorted(by: IV.utf8Less)
    }

    public static func floorOf(_ reg: TraitRegistry, _ ids: [String]) throws -> Profile {
        joinAll(try closure(reg, ids).map { reg.traits[JKey($0)]!.floor })
    }

    /// FloorDecision(G, call, rho): deny if rho.esc > G.max_esc; escalate if a caveat is missing from G, a context key from the call, or rho.esc > G.preauth_esc; else allow.
    public static func floorDecision(grantCaveats: [String], maxEsc: Int, preauthEsc: Int, callContext: [String], rho: Profile) -> String {
        if rho.esc > maxEsc { return "deny" }
        if !subset(rho.caveats, grantCaveats) || !subset(rho.context, callContext) || rho.esc > preauthEsc { return "escalate" }
        return "allow"
    }

    // [id, implies, own floor, card phrase] - the 22 core traits
    private static let coreTable: [(String, [String], Profile, String)] = [
        ("money_moving", [], Profile(risk: 3, rev: "rate_limited", blastPpm: 700_000, esc: 2, caveats: ["amount_cap", "count_cap", "window"], context: ["idempotency"], prules: ["money_has_currency", "money_amount_bounded", "pay_has_idempotency"]), "moves money"),
        ("destructive", [], Profile(risk: 2, rev: "rate_limited", esc: 1, caveats: ["resource_scope"], prules: ["id_not_wildcard"]), "deletes or destroys data"),
        ("irreversible", [], Profile(risk: 2, rev: "irreversible", esc: 1, context: ["fresh_revocation"]), "cannot be undone"),
        ("external_communication", [], Profile(risk: 2, rev: "irreversible", caveats: ["recipient_scope", "rate_cap"], prules: ["recipient_param_declared"]), "sends to people outside your organisation"),
        ("data_export", [], Profile(risk: 2, caveats: ["resource_scope", "count_cap"], prules: ["export_bounded"]), "exports data"),
        ("privilege_change", [], Profile(risk: 3, esc: 3, caveats: ["resource_scope", "short_expiry"]), "changes who can do what"),
        ("code_execution", [], Profile(risk: 3, rev: "irreversible", esc: 2, caveats: ["resource_scope"], context: ["sandbox_attested"]), "runs code or commands"),
        ("credential_access", [], Profile(risk: 3, esc: 3, prules: ["secret_not_logged"]), "reads or handles credentials"),
        ("bulk", [], Profile(risk: 2, caveats: ["count_cap"], prules: ["array_bounded"]), "acts on many items at once"),
        ("pii_access", [], Profile(risk: 1, caveats: ["resource_scope"]), "touches personal data"),
        ("public_exposure", [], Profile(risk: 2, rev: "irreversible", esc: 1), "makes content public"),
        ("persistence", [], Profile(risk: 2, caveats: ["short_expiry"], context: ["revocable"]), "creates standing access or infrastructure"),
        ("infra_mutation", [], Profile(risk: 2, rev: "rate_limited", caveats: ["resource_scope"]), "changes infrastructure"),
        ("cost_incurring", [], Profile(risk: 1, caveats: ["amount_cap"]), "incurs cost"),
        ("legal_binding", [], Profile(risk: 3, rev: "irreversible", esc: 3), "legally or cryptographically binds you"),
        ("impersonation", ["external_communication"], Profile(risk: 2, esc: 1), "acts as a person"),
        ("network_egress", [], Profile(risk: 1, caveats: ["recipient_scope"]), "reaches out to the network"),
        ("financial_data_read", [], Profile(risk: 1, caveats: ["resource_scope"]), "reads financial data"),
        ("regulated_data", [], Profile(risk: 2, esc: 1), "handles regulated data"),
        ("scheduled", [], Profile(risk: 2, caveats: ["short_expiry", "count_cap"]), "runs later or repeatedly"),
        ("unreviewed", [], Profile(risk: 3, rev: "irreversible", blastPpm: 1_000_000, esc: 2, caveats: ["approval_ref", "resource_scope"], context: ["dry_run_first"]), "has not been reviewed yet"),
        ("agent_spawning", [], Profile(risk: 2, caveats: ["count_cap"]), "starts another agent"),
    ]

    /// The core trait registry (floor = own highlights joined with the implied floors).
    public static let coreRegistry: TraitRegistry = {
        var floors: [String: Profile] = [:]
        var defs: [JSONValue] = []
        for (name, implies, own, phrase) in coreTable {
            let id = "pca." + name
            let imp = implies.map { "pca." + $0 }
            let fl = imp.reduce(own) { join($0, floors[$1]!) }
            floors[id] = fl
            defs.append(.object(["id": .string(id), "implies": .array(imp.map { .string($0) }), "floor": fl.json, "card_phrase": .string(phrase)]))
        }
        return try! buildRegistry(defs, core: true)
    }()

    static let EFFECT_TRAITS: [String: [String]] = [
        "read": [], "create": [], "update": [], "delete": ["pca.destructive"], "send": ["pca.external_communication"], "pay": ["pca.money_moving"],
        "exec": ["pca.code_execution"], "privilege": ["pca.privilege_change"], "export": ["pca.data_export"], "publish": ["pca.public_exposure"],
        "provision": ["pca.persistence", "pca.scheduled"], "sign": ["pca.legal_binding"],
    ]
    static let TAG_TRAITS: [String: [String]] = [
        "pii": ["pca.pii_access"], "phi": ["pca.pii_access", "pca.regulated_data"], "pci": ["pca.regulated_data"],
        "secret": ["pca.credential_access"], "credential": ["pca.credential_access"],
    ]
    static let ROLE_TRAITS: [String: [String]] = [
        "credential.secret": ["pca.credential_access"], "credential.token": ["pca.credential_access"], "credential.key": ["pca.credential_access"],
        "url.target": ["pca.network_egress"],
    ]
    static let ROLE_SENSITIVITY_FLOOR: [String: String] = [
        "money.amount": "critical", "money.currency": "material", "money.fee": "material", "party.payee": "critical", "party.payer": "material",
        "contact.email": "material", "contact.phone": "material", "contact.address": "material", "person.name": "material", "person.dob": "material",
        "person.national_id": "critical", "credential.secret": "critical", "credential.token": "critical", "credential.key": "critical",
        "code.command": "critical", "query.sql": "critical", "text.message": "material",
    ]
    static let TAG_SENSITIVITY_FLOOR: [String: String] = [
        "pii": "material", "phi": "material", "pci": "material", "secret": "critical", "credential": "critical",
        "free_text_outbound": "material", "code": "material", "path": "material", "sql": "material",
    ]

    private static func strMap(_ m: [String: [String]]) -> JSONValue { .object(Dictionary(uniqueKeysWithValues: m.map { (JKey($0.key), JSONValue.array($0.value.map { .string($0) })) })) }
    private static func strMap1(_ m: [String: String]) -> JSONValue { .object(Dictionary(uniqueKeysWithValues: m.map { (JKey($0.key), JSONValue.string($0.value)) })) }

    /// Digest of a trait registry (sorted by id): what a pack pins as `traits_digest`.
    public static func traitsDigest(_ reg: TraitRegistry) -> String {
        let ts = reg.traits.values.sorted { IV.utf8Less($0.id, $1.id) }.map { t in
            JSONValue.object(["id": .string(t.id), "implies": .array(sortUniq(t.implies).map { .string($0) }), "floor": t.floor.json, "card_phrase": .string(t.cardPhrase)])
        }
        return IV.strictHash(.object(["d": .string(TRAITS_DIGEST_DOMAIN), "traits": .array(ts)]))!
    }

    /// Digest of the implication and sensitivity tables the trait expansion reads.
    public static func tablesDigest() -> String {
        IV.strictHash(.object(["d": .string(ROLES_DIGEST_DOMAIN), "roles": .array(CORE_ROLES.map { .string($0) }), "effect_traits": strMap(EFFECT_TRAITS),
                               "role_traits": strMap(ROLE_TRAITS), "tag_traits": strMap(TAG_TRAITS), "role_sensitivity": strMap1(ROLE_SENSITIVITY_FLOOR),
                               "tag_sensitivity": strMap1(TAG_SENSITIVITY_FLOOR)]))!
    }

    // ---- normalize + digest -------------------------------------------------------------------------------------------------

    static func isReadOnly(_ effects: [String]) -> Bool { !effects.isEmpty && effects.allSatisfy { $0 == "read" } }
    private static func maxSens(_ a: String, _ b: String) -> String { SENSITIVITY_RANK[a]! >= SENSITIVITY_RANK[b]! ? a : b }

    static func effectiveParamSensitivity(_ p: JObject) -> String {
        var f = "free"
        if let r = p["role"]?.asString, let x = ROLE_SENSITIVITY_FLOOR[r] { f = maxSens(f, x) }
        for t in strings(p["tags"]) ?? [] { if let x = TAG_SENSITIVITY_FLOOR[t] { f = maxSens(f, x) } }
        return maxSens(p["sensitivity"]?.asString ?? "free", f)
    }

    private static func maxRev(_ xs: [String]) -> String {
        var out = "reversible"
        for b in xs { if let rb = REV_RANK[b], rb > REV_RANK[out]! { out = b } }
        return out
    }

    /// Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have.
    static func worstReversibility(_ r: JSONValue, _ params: JObject) -> String {
        if let s = r.asString { return s }
        guard case let .object(ro) = r, let by = ro["by"]?.asString, case let .object(m)? = ro["map"] else { return "irreversible" }
        let mapped = m.keys.sorted().compactMap { m[$0]?.asString }
        var domain: [String]?
        if case let .object(d)? = params[JKey(by)] {
            if d["type"]?.asString == "boolean" { domain = ["true", "false"] } else if d["type"]?.asString == "string", let vs = strings(d["values"]) { domain = vs }
        }
        let covered = domain.map { $0.allSatisfy { m[JKey($0)] != nil } } ?? false
        return maxRev(covered ? mapped : mapped + [ro["default"]?.asString ?? "irreversible"])
    }

    private static func normalizeParam(_ p: JObject) -> JSONValue {
        var out = p
        out["required"] = .bool({ if case let .bool(b)? = p["required"] { return b } else { return true } }())
        if let t = strings(p["tags"]) { out["tags"] = .array(sortUniq(t).map { .string($0) }) }
        out["sensitivity"] = .string(effectiveParamSensitivity(p))
        if let a = strings(p["accumulates"]) { out["accumulates"] = .array(sortUniq(a).map { .string($0) }) }
        else if p["role"]?.asString == "money.amount", case let .object(u)? = p["unit"], u["kind"]?.asString == "money", let c = u["ccy"]?.asString {
            out["accumulates"] = .array([.string("money." + c.lowercased())])
        }
        return .object(out)
    }

    /// The authoring-independent form of a def (assumes validateDef passed): defaults filled, sets sorted, review/examples/source/since removed.
    public static func normalize(_ d: JObject) -> JObject {
        let effects = strings(d["effects"])!
        let rev: JSONValue = d["reversibility"] ?? .string(isReadOnly(effects) ? "reversible" : "irreversible")
        let res = d["resource"]!.asObject!
        let blast = d["blast"]?.asObject
        let radius = blast?["radius"]?.asString ?? SCOPE_BLAST[res["scope"]!.asString!]!
        var params: JObject = [:]
        for (k, v) in d["params"]!.asObject! { params[k] = normalizeParam(v.asObject!) }
        var nrev = rev
        if case let .object(ro) = rev {
            var o: JObject = ["by": ro["by"]!, "map": ro["map"]!]
            if let df = ro["default"] { o["default"] = df }
            nrev = .object(o)
        }
        var idem: JObject = ["mode": .string(d["idempotency"]?.get("mode")?.asString ?? "none")]
        if let p = d["idempotency"]?.get("param") { idem["param"] = p }
        let ses = (d["side_effects"]?.asArray ?? []).map { $0.asObject! }.sorted { a, b in
            let ta = Array(a["target"]!.asString!.utf16), tb = Array(b["target"]!.asString!.utf16)
            if ta != tb { return ta.lexicographicallyPrecedes(tb) }
            return IV.utf8Less(a["kind"]!.asString!, b["kind"]!.asString!)
        }.map { JSONValue.object(["target": $0["target"]!, "kind": $0["kind"]!]) }
        var out: JObject = [
            "v": .int(1), "kind": d["kind"]!, "verb": d["verb"]!, "aliases": .array(sortUniq(strings(d["aliases"]) ?? []).map { .string($0) }), "title": d["title"]!,
            "effects": .array(sortUniq(effects).map { .string($0) }),
            "resource": .object(["type": res["type"]!, "id": res["id"]!, "scope": res["scope"]!]),
            "params": .object(params), "reversibility": nrev,
            "blast": .object(["radius": .string(radius), "ppm": .int(Int64(max(BLAST_PPM[radius]!, Int(IV.int(blast?["ppm"]) ?? 0))))]),
            "side_effects": .array(ses), "idempotency": .object(idem),
            "context": .array(sortUniq(strings(d["context"]) ?? []).map { .string($0) }), "traits": .array(sortUniq(strings(d["traits"]) ?? []).map { .string($0) }),
            "bindings": d["bindings"] ?? .object([:]),
        ]
        if let ds = d["description"] { out["description"] = ds }
        if let a = d["audience"] { out["audience"] = a }
        if let c = d["compensates"] { out["compensates"] = c }
        return out
    }

    /// b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it.
    public static func defDigest(_ d: JObject) -> String {
        IV.strictHash(.object(["d": .string(DEF_DIGEST_DOMAIN), "def": .object(normalize(d))])) ?? ""
    }

    // ---- pack Merkle root + inclusion proof ---------------------------------------------------------------------------------

    private static func leaf(_ digest: String) -> JSONValue { .object(["d": .string(PACK_DIGEST_DOMAIN), "def": .string(digest)]) }
    private static func sortedDigests(_ digests: [String]) throws -> [String] {
        let s = sortUniq(digests)
        if s.count != digests.count { throw ActionKitError(code: "duplicate_def", message: "a pack lists a def digest twice") }
        if s.isEmpty { throw ActionKitError(code: "empty_pack", message: "a pack has at least one def") }
        return s
    }
    public static func packRoot(_ digests: [String]) throws -> String { Merkle.merkleRoot(try sortedDigests(digests).map(leaf))! }

    /// RFC 6962 inclusion proof of `digest` in the pack made of `digests`: {index, size, path: [{side, hash}]} bottom-up.
    public static func packProof(_ digests: [String], _ digest: String) throws -> JSONValue {
        let s = try sortedDigests(digests)
        guard let i = s.firstIndex(where: { IV.same($0, digest) }) else { throw ActionKitError(code: "not_in_pack", message: "the digest is not in the pack") }
        var seg = s.map { Merkle.leafHash(leaf($0)) }
        var idx = i
        var path: [JSONValue] = []
        while seg.count > 1 {
            let k = Int(Merkle.split(UInt64(seg.count)))
            if idx < k {
                path.append(.object(["side": .string("R"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(seg[k...]))))]))
                seg = Array(seg[..<k])
            } else {
                path.append(.object(["side": .string("L"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(seg[..<k]))))]))
                seg = Array(seg[k...])
                idx -= k
            }
        }
        return .object(["index": .int(Int64(i)), "size": .int(Int64(s.count)), "path": .array(path.reversed())])
    }

    public static func verifyPackProof(root: String, proof: JSONValue, digest: String) -> Bool {
        Merkle.verifyInclusion(root, proof.asObject, leaf(digest))
    }

    // ---- T(d), decl(d), eff(d) ----------------------------------------------------------------------------------------------

    /// Traits implied by effects, roles, tags, scope and reversibility. `params`: type / role / tags / max_items presence.
    static func impliedFromFacts(effects: [String], params: [JObject], scope: String?, worstRev: String) throws -> [String] {
        var out: [String] = []
        for e in effects {
            guard let t = EFFECT_TRAITS[e] else { throw ActionKitError(code: "schema_floor_forged", message: "unknown effect") }
            out += t
        }
        let ro = isReadOnly(effects)
        for p in params {
            if let r = p["role"]?.asString {
                out += ROLE_TRAITS[r] ?? []
                if ro && IV.startsWith(r, "money.") { out.append("pca.financial_data_read") }
            }
            for t in strings(p["tags"]) ?? [] { out += TAG_TRAITS[t] ?? [] }
            if p["type"]?.asString == "array" && p["max_items"] == nil { out.append("pca.bulk") }
        }
        if let s = scope, s != "one" { out.append("pca.bulk") }
        if worstRev == "irreversible" { out.append("pca.irreversible") }
        return sortUniq(out)
    }

    // ---- human confirmation: the only thing that lowers a def's traits below the top of the registry ---------------------------

    static let KEY_ROLES = ["reviewer", "importer", "model", "publisher"]
    static let REVIEW_DOMAIN = "atlas-pca/action-review/v2\u{0}"

    /// JS `String.prototype.trim` whitespace.
    private static func jsBlank(_ s: String) -> Bool {
        let ws: [UInt32] = [9, 10, 11, 12, 13, 32, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF]
        return s.unicodeScalars.allSatisfy { ws.contains($0.value) || (0x2000...0x200A).contains($0.value) }
    }
    private static func jsLess(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    /// nil if the pin set is sound: distinct kids, canonical keys, known roles, no key that is both a reviewer and a machine. Any error => nothing is confirmed.
    public static func reviewerPinsError(_ pv: JSONValue?) -> String? {
        guard case let .object(p)? = pv, case let .array(keys)? = p["keys"] else { return "pins must be {keys: [...]}" }
        var kids = Set<JKey>(), machine = Set<JKey>()
        var reviewers: [String] = []
        for kv in keys {
            guard case let .object(k) = kv, let kid = k["kid"]?.asString, (1...128).contains(IV.u16(kid)) else { return "a pinned key needs a kid" }
            if !kids.insert(JKey(kid)).inserted { return "kid '\(kid)' is pinned twice" }
            guard let pk = k["pk"]?.asString, Base64URLStrict.isValid(pk, length: 32) else { return "key '\(kid)': pk is not canonical base64url (32 bytes)" }
            guard let roles = strings(k["roles"]), !roles.isEmpty, roles.allSatisfy({ IV.contains(KEY_ROLES, $0) }), IV.distinct(roles) else { return "key '\(kid)': roles must be distinct known roles" }
            let isReviewer = IV.contains(roles, "reviewer"), isMachine = IV.contains(roles, "importer") || IV.contains(roles, "model")
            if isReviewer && isMachine { return "key '\(kid)': an importer or model key cannot hold the reviewer role" }
            for t in ["not_before", "not_after"] { if let x = k[JKey(t)], !(IV.safe(x).map { $0 >= 0 } ?? false) { return "key '\(kid)': \(t) must be a non-negative integer" } }
            if isMachine { machine.insert(JKey(pk)) }
            if isReviewer { reviewers.append(pk) }
        }
        if reviewers.contains(where: { machine.contains(JKey($0)) }) { return "the same key material is pinned as an importer or model key" }
        return nil
    }

    /// `REVIEW_DOMAIN \0 ++ strictCanonical(body)`; nil where the body is malformed (the reference throws).
    static func reviewMessage(_ a: JObject) -> [UInt8]? {
        guard let dd = a["def_digest"]?.asString, let td = a["traits_digest"]?.asString, let fd = a["facts_digest"]?.asString, let fin = strings(a["final_traits"]), case let .array(dm)? = a["dismissed"],
              let kid = a["reviewer_kid"]?.asString, let ts = a["ts"] else { return nil }
        var ds: [(String, String)] = []
        for d in dm {
            guard case let .object(o) = d, let t = o["trait"]?.asString, let r = o["reason"]?.asString else { return nil }
            ds.append((t, r))
        }
        ds.sort { jsLess($0.0, $1.0) }
        return IV.message(REVIEW_DOMAIN, .object(["def_digest": .string(dd), "traits_digest": .string(td), "facts_digest": .string(fd), "final_traits": .array(sortUniq(fin).map { .string($0) }),
                                                  "dismissed": .array(ds.map { .object(["trait": .string($0.0), "reason": .string($0.1)]) }), "reviewer_kid": .string(kid), "ts": ts]))
    }

    /// The checks the def level and the verb level share: signed, registry digest accepted, final traits covered, dismissals sound, reviewer key pinned
    /// with the reviewer role and valid at `ts`, signature. `pins` already passed `reviewerPinsError`. Never throws; false = unconfirmed.
    private static func attestationValid(_ a: JObject, _ pins: JObject, _ reg: TraitRegistry, facts: String? = nil, covers: ([String]) -> Bool) -> Bool {
        guard let sig = a["sig"]?.asString, let td = a["traits_digest"]?.asString, let fin = strings(a["final_traits"]), case let .array(dm)? = a["dismissed"],
              let kid = a["reviewer_kid"]?.asString, let ts = IV.safe(a["ts"]), case let .array(keys)? = pins["keys"] else { return false }
        var accepted = [traitsDigest(reg)]
        if let extra = pins["traits_digests"] { guard let l = strings(extra) else { return false }; accepted += l }
        guard IV.contains(accepted, td), facts.map({ IV.same(a["facts_digest"]?.asString, $0) }) ?? true, covers(fin) else { return false }
        for d in dm {
            guard case let .object(o) = d, let t = o["trait"]?.asString, let r = o["reason"]?.asString, !IV.contains(fin, t), !jsBlank(r) else { return false }
        }
        guard let key = keys.first(where: { IV.same($0.get("kid")?.asString, kid) }), IV.contains(strings(key.get("roles")) ?? [], "reviewer"), let pk = key.get("pk")?.asString else { return false }
        if let nb = IV.safe(key.get("not_before")), ts < nb { return false }
        if let na = IV.safe(key.get("not_after")), ts > na { return false }
        guard let msg = reviewMessage(a) else { return false }
        return Ed25519Strict.verifyB64u(pk, msg, sig)
    }

    /// Def level: `review.state == confirmed` with an attestation over THIS def digest, whose final traits are the def's declared traits.
    /// `pins` absent / bad / any failed check => false (unconfirmed).
    public static func isConfirmed(_ d: JObject, _ reg: TraitRegistry, _ pins: JSONValue?) -> Bool {
        guard case let .object(p)? = pins, reviewerPinsError(pins) == nil, case let .object(rv)? = d["review"], IV.same(rv["state"]?.asString, "confirmed"),
              case let .object(a)? = rv["attestation"], IV.same(a["def_digest"]?.asString, defDigest(d)) else { return false }
        let declared = sortUniq(strings(d["traits"]) ?? [])
        return attestationValid(a, p, reg) { fin in sortUniq(fin).elementsEqual(declared) { IV.same($0, $1) } }
    }

    /// Digest of what a verb says about the action: the verb as presented minus `traits`, `floors`, `confirmation` and `def`.
    public static func factsDigest(_ v: JObject) -> String {
        var f = v
        for k in ["traits", "floors", "confirmation", "def"] { f[JKey(k)] = nil }
        return IV.strictHash(.object(["d": .string(VERB_FACTS_DOMAIN), "verb": .object(f)])) ?? ""
    }

    /// Verb level: the verb's `confirmation` covers the verb's `def` digest and every signed final trait is carried by `traits`.
    public static func verbConfirmed(_ v: JObject, _ reg: TraitRegistry, _ pins: JSONValue?) -> Bool {
        guard case let .object(p)? = pins, reviewerPinsError(pins) == nil, case let .object(a)? = v["confirmation"],
              let def = v["def"]?.asString, IV.same(a["def_digest"]?.asString, def) else { return false }
        let carried = strings(v["traits"]) ?? []
        return attestationValid(a, p, reg, facts: factsDigest(v)) { fin in fin.allSatisfy { IV.contains(carried, $0) } }
    }

    /// Every trait id of the registry: the effective traits of anything unconfirmed.
    public static func topTraits(_ reg: TraitRegistry) -> [String] { reg.traits.keys.map { $0.s }.sorted(by: IV.utf8Less) }

    /// Declared + implied-by-facts traits: what the def would have if a reviewer signed it as it stands. Never enforcement on its own.
    public static func hintTraits(_ d: JObject) -> [String] {
        let n = normalize(d)
        let params = n["params"]!.asObject!
        let ids = strings(n["traits"])! + ((try? impliedFromFacts(effects: strings(n["effects"])!, params: params.values.map { $0.asObject! }, scope: n["resource"]!.get("scope")!.asString,
                                                                  worstRev: worstReversibility(n["reversibility"]!, params))) ?? [])
        return sortUniq(ids)
    }

    /// T(d): "unconfirmed means maximally dangerous" - the top of the registry unless a pinned reviewer signed the def.
    public static func traitsOf(_ d: JObject, _ reg: TraitRegistry, _ pins: JSONValue? = nil) -> [String] {
        isConfirmed(d, reg, pins) ? hintTraits(d) : topTraits(reg)
    }

    public static func declProfile(_ d: JObject) -> Profile {
        let n = normalize(d)
        let params = n["params"]!.asObject!
        let critical = params.values.contains { SENSITIVITY_RANK[effectiveParamSensitivity($0.asObject!)]! >= 2 }
        let effects = strings(n["effects"])!
        return Profile(risk: critical ? 2 : (isReadOnly(effects) ? 0 : 1), rev: worstReversibility(n["reversibility"]!, params),
                       blastPpm: Int(IV.int(n["blast"]!.get("ppm"))!), context: strings(n["context"])!)
    }

    /// {traits, closure, floor, decl, eff}: eff = decl join F(T(d)).
    public static func effective(_ d: JObject, _ reg: TraitRegistry, _ pins: JSONValue? = nil) throws -> (confirmed: Bool, traits: [String], closure: [String], floor: Profile, decl: Profile, eff: Profile) {
        let confirmed = isConfirmed(d, reg, pins)
        let tr = confirmed ? hintTraits(d) : topTraits(reg)
        let fl = try floorOf(reg, tr)
        let dp = declProfile(d)
        return (confirmed, tr, try closure(reg, tr), fl, dp, join(dp, fl))
    }

    // ---- rule 22: integrity of the carried traits and floors --------------------------------------------------------------

    /// Recompute from the verb's own visible facts that its `traits` contain every implied trait and that its `floors` are at least the floor
    /// of the traits' closure and of the declared reversibility, and (unless `confirmation` verifies under the pinned reviewer keys `pins`) that it carries every trait of `reg`. nil = consistent; else `<code>: <reason>`. Never throws.
    public static func schemaVerbFloorError(_ v: JObject, _ reg: TraitRegistry, _ pins: JSONValue? = nil) -> String? {
        guard let effects = strings(v["effects"]), let traits = strings(v["traits"]), v["floors"] != nil else { return "schema_floor_forged: not a v2 verb" }
        do {
            guard case let .object(vp)? = v["params"] else { return "schema_floor_forged: params" }
            var byName: JObject = [:]
            var facts: [JObject] = []
            for (path, pv) in vp {
                guard case let .object(p) = pv else { return "schema_floor_forged: malformed parameter" }
                var e: JObject = ["type": p["type"] ?? .null]
                if let vs = p["values"] { e["values"] = vs }
                byName[JKey(IV.dropPrefix(path.s, 14))] = .object(e)
                facts.append(p)
            }
            var decl: JSONValue
            if case let .object(rb)? = v["reversibility_by"] {
                var o: JObject = ["by": .string(IV.dropPrefix(rb["param"]?.asString ?? "", 14)), "map": rb["map"] ?? .object([:])]
                if let df = rb["default"] { o["default"] = df }
                decl = .object(o)
            } else if let r = v["reversibility"] {
                decl = r
            } else {
                decl = .string(v["kind"]?.asString == "read" ? "reversible" : "irreversible")
            }
            let worst = worstReversibility(decl, byName)
            for t in try impliedFromFacts(effects: effects, params: facts, scope: nil, worstRev: worst) where !IV.contains(traits, t) {
                return "schema_traits_forged: missing implied trait \(t)"
            }
            // unconfirmed means maximally dangerous: no valid signed confirmation => the verb must carry EVERY trait of the registry
            if !verbConfirmed(v, reg, pins) {
                for t in topTraits(reg) where !IV.contains(traits, t) { return "schema_traits_forged: unconfirmed action must carry every trait (missing \(t))" }
            }
            let fl = try floorOf(reg, traits)
            guard let carried = Profile(json: v["floors"]), leq(fl, carried) else { return "schema_floor_forged: floors are below the floor of the carried traits" }
            if (REV_RANK[carried.rev] ?? -1) < (REV_RANK[worst] ?? -1) { return "schema_floor_forged: floors.rev is below the declared reversibility" }
            return nil
        } catch let e as ActionKitError {
            return "\(e.code): \(e.message)"
        } catch {
            return "schema_floor_forged: \(error)"
        }
    }

    /// Core + the document's own `trait_defs` (checked); when it carries `traits_digest` the registry must hash to it.
    public static func registryOfSchema(_ doc: JObject) throws -> TraitRegistry {
        var reg = coreRegistry
        if case let .array(td)? = doc["trait_defs"], !td.isEmpty { reg = try extendRegistry(coreRegistry, td) }
        if let d = doc["traits_digest"], d.asString.map({ !IV.same($0, traitsDigest(reg)) }) ?? true {
            throw ActionKitError(code: "traits_digest_mismatch", message: "the document's traits_digest does not match its trait registry")
        }
        return reg
    }

    /// Rule 22's integrity half for a whole v2 document. nil = consistent. Never throws.
    public static func schemaFloorError(_ doc: JObject, _ pins: JSONValue? = nil) -> String? {
        do {
            let reg = try registryOfSchema(doc)
            for vv in doc["verbs"]?.asArray ?? [] {
                guard case let .object(v) = vv else { return "bad_registry: verb entry must be an object" }
                if let e = schemaVerbFloorError(v, reg, pins) { return "\(v["verb"]?.asString ?? ""): \(e)" }
            }
            return nil
        } catch let e as ActionKitError {
            return "\(e.code): \(e.message)"
        } catch {
            return "bad_registry: \(error)"
        }
    }
}
