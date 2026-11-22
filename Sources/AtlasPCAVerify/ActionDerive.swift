import Foundation

/// Everything an action def yields: the signed schema verb (v2) and document, the operation binding, risk inputs, policy predicates,
/// Goal IR ontology terms, the policy card, the escalation tier and MCP annotations. Pure and deterministic.
public enum ActionDerive {
    public static let MAX_PARAM_PATH_DEPTH = 3
    public static let ESC_TIERS = ["auto", "confirm", "cosign", "stepup"]
    public static let RISK_NAMES = ["low", "elevated", "high", "critical"]
    /// Reversibility score per effective class (1 = fully reversible).
    public static let REVERSIBILITY_SCORE: [String: Double] = ["reversible": 1.0, "rate_limited": 0.4, "irreversible": 0.0]

    private static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    private static func isReadOnly(_ effects: JSONValue?) -> Bool {
        guard let e = effects?.asArray, !e.isEmpty else { return false }
        return e.allSatisfy { $0 == .string("read") }
    }

    // ---- flattened params ----

    private static func walk(_ out: inout JObject, _ prefix: String, _ depth: Int, _ v: JSONValue) {
        if case let .object(o) = v, depth < MAX_PARAM_PATH_DEPTH, !o.isEmpty {
            for k in JS.keyOrder(o) { walk(&out, prefix.isEmpty ? k.s : prefix + "." + k.s, depth + 1, o[k]!) }
        } else { out[JKey(prefix)] = v }
    }

    /// Nested plain objects become dotted keys (up to MAX_PARAM_PATH_DEPTH segments); arrays and scalars are leaves.
    public static func flattenParams(_ params: JObject) -> JObject {
        var out: JObject = [:]
        for k in JS.keyOrder(params) { walk(&out, k.s, 1, params[k]!) }
        return out
    }

    /// The unique param carrying `role`, or throws `no_param` / `ambiguous_param`.
    public static func paramByRole(_ d: JObject, _ role: String) throws -> String {
        var hits: [String] = []
        for (k, v) in AK.o(d["params"]) where v.get("role") == .string(role) { hits.append(k.s) }
        hits.sort(by: u16less)
        let verb = JS.toString(d["verb"])
        if hits.isEmpty { throw AK.fail("no_param", "'\(verb)' has no parameter with role \(role)") }
        if hits.count > 1 { throw AK.fail("ambiguous_param", "'\(verb)' has several parameters with role \(role)") }
        return hits[0]
    }

    /// read if effects = {read}; irreversible if so declared; external_send if effects meet {send, publish, export}; else reversible.
    public static func effectClass(_ d: JObject) throws -> String {
        let n = try Actions.normalize(d)
        if isReadOnly(n["effects"]) { return "read" }
        if Actions.worstReversibility(n["reversibility"] ?? .null, AK.o(n["params"])) == "irreversible" { return "irreversible" }
        for e in AK.arr(n["effects"]) where e == .string("send") || e == .string("publish") || e == .string("export") { return "external_send" }
        return "reversible"
    }

    // ---- signed schema (v2) ----

    private static func unitId(_ p: JObject) -> String? {
        guard let u = AK.pres(p, "unit") else { return nil }
        if u.get("kind") != .string("money") { return u.get("kind")?.asString }
        if let c = u.get("ccy")?.asString { return "money." + c.lowercased() }
        return nil
    }

    private static func unitDecl(_ p: JObject) -> JSONValue {
        let u = p["unit"]
        if u?.get("kind") != .string("money") { return AK.obj(["kind": u?.get("kind") ?? .null]) }
        var m: JObject = ["kind": .string("money"), "currency": u?.get("ccy") ?? .null]
        if let e = AK.o(u)[JKey("exp")] { m["exponent"] = e }
        return .object(m)
    }

    private static func toParamDecl(_ n: JObject) -> JSONValue {
        var d: JObject = ["type": n["type"] ?? .null, "semantic": AK.pres(n, "role") ?? .string("generic." + JS.toString(n["type"])), "sensitivity": n["sensitivity"] ?? .null]
        if n["required"] != .bool(true) { d["required"] = .bool(false) }
        if let v = n["values"] { d["values"] = v }
        for k in ["min", "max", "max_len", "items", "min_items", "max_items", "format", "provenance_min", "default", "principal_neutral_default", "description"] {
            if let v = n[JKey(k)] { d[JKey(k)] = v }
        }
        if let uid = unitId(n) { d["unit"] = .string(uid) }
        if let a = n["accumulates"] { d["accumulates_into"] = a }
        if let r = n["role"] { d["role"] = r }
        if let t = n["tags"] { d["tags"] = t }
        return .object(d)
    }

    /// The signed v2 verb declaration of a def and the unit entries it needs: `{verb, units}`.
    public static func toSchemaVerb(_ d: JObject, _ reg: TraitRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JSONValue {
        let n = try Actions.normalize(d)
        let eff = try ActionEffective.effective(d, reg, attestationVerified)
        var params: JObject = [:], units: JObject = [:]
        let np = AK.o(n["params"])
        for k in JS.keyOrder(np) {
            let p = AK.o(np[k])
            params[JKey("action.params." + k.s)] = toParamDecl(p)
            if let id = unitId(p) { units[JKey(id)] = unitDecl(p) }
        }
        var v: JObject = ["verb": n["verb"] ?? .null, "kind": .string(isReadOnly(n["effects"]) ? "read" : "write"), "params": .object(params), "effects": n["effects"] ?? .array([]),
                          "traits": eff["traits"] ?? .null, "def": .string(try Actions.defDigest(d)), "floors": eff["eff"] ?? .null]
        if eff["confirmed"] == .bool(true), let att = AK.o(d["review"])["attestation"], case let .object(ao) = att, ao["sig"] != nil, ao["sig"] != .null { v["confirmation"] = att }
        let rev = n["reversibility"] ?? .null
        if rev.asString != nil { v["reversibility"] = rev }
        else {
            var rb: JObject = ["param": .string("action.params." + JS.toString(rev.get("by"))), "map": rev.get("map") ?? .null]
            if let df = JS.present(rev.get("default")) { rb["default"] = df }
            v["reversibility_by"] = .object(rb)
        }
        let b = n["bindings"]
        if let m = JS.present(b?.get("mcp")) { v["mcp"] = AK.obj(["tool": m.get("tool") ?? .null]) }
        if let o = JS.present(b?.get("openapi")) { v["openapi"] = AK.obj(["operationId": o.get("operationId") ?? .null]) }
        if let ds = n["description"] { v["description"] = ds }
        return AK.obj(["verb": .object(v), "units": .object(units)])
    }

    /// The unsigned v2 schema document of a set of defs (verbs sorted by name; units merged, a conflicting redefinition refused). `meta`: {site, aud, version, pack?}.
    public static func toSchemaDoc(_ defs: [JSONValue], _ reg: TraitRegistry, _ meta: JObject, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JSONValue {
        var verbs: [JSONValue] = []
        var units: JObject = [:]
        var seen = Set<JKey>()
        var sortedDefs: [(String, JSONValue)] = []
        for d in defs { guard let v = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }; sortedDefs.append((v, d)) }
        sortedDefs.sort { u16less($0.0, $1.0) }
        for (verb, d) in sortedDefs {
            if !seen.insert(JKey(verb)).inserted { throw AK.fail("duplicate_verb", "verb '\(verb)' appears twice") }
            let o = try toSchemaVerb(AK.o(d), reg, attestationVerified)
            verbs.append(o.get("verb") ?? .null)
            let ou = AK.o(o.get("units"))
            for uk in JS.keyOrder(ou) {
                let u = ou[uk]!
                if let prev = units[uk], !(prev.get("kind") == u.get("kind") && prev.get("currency") == u.get("currency") && AK.sameMember(AK.o(prev), AK.o(u), "exponent")) {
                    throw AK.fail("unit_conflict", "unit '\(uk.s)' is declared with two different definitions")
                }
                units[uk] = u
            }
        }
        var doc: JObject = ["v": .int(2), "kind": .string("pca-action-schema"), "site": meta["site"] ?? .null, "aud": meta["aud"] ?? .null, "version": meta["version"] ?? .null]
        if !units.isEmpty { doc["units"] = .object(units) }
        doc["verbs"] = .array(verbs)
        doc["traits_digest"] = .string(Actions.traitsDigest(reg))
        let custom = reg.traits.values.filter { !$0.id.hasPrefix("pca.") }.sorted { u16less($0.id, $1.id) }
        if !custom.isEmpty {
            doc["trait_defs"] = .array(custom.map { t in AK.obj(["id": .string(t.id), "implies": AK.strs(t.implies), "floor": t.floor.json, "card_phrase": .string(t.cardPhrase)]) })
        }
        if let p = AK.pres(meta, "pack") { doc["pack"] = p }
        return .object(doc)
    }

    // ---- operation binding ----

    /// The PcaOperation of a call to this def: `{ok: true, op: {verb, resource, params}}` or `{ok: false, reason}`. `callParams` are the call's params.
    public static func operationOf(_ d: JObject, _ callParams: JObject) throws -> JSONValue {
        let flat = flattenParams(callParams)
        let dp = AK.o(d["params"])
        let declared = AK.sortedKeys(dp)
        var params: JObject = [:]
        for k in declared { if let v = flat[JKey(k)] { params[JKey(k)] = v } }
        let res = AK.o(d["resource"])
        guard let type = res["type"]?.asString else { throw AK.fail("bad_def", "resource.type") }
        let id = res["id"]
        let scope = res["scope"]?.asString
        let resource: String
        if id != .string("*"), id?.asObject?[JKey("exact")] != nil {
            resource = type + ":" + JS.toString(id?.get("exact"))
        } else {
            var idParam: String?
            for n in declared where AK.o(dp[JKey(n)])["role"] == .string("id.\(type)") { idParam = n; break }
            let v = idParam.flatMap { params[JKey($0)] }
            if let s = v?.asString {
                if !(try ActionIdPattern.idMatches(id, s)) { return AK.obj(["ok": .bool(false), "reason": .string("the id '\(s)' does not match the resource pattern of \(JS.toString(d["verb"]))")]) }
                resource = type + ":" + s
            } else if scope != "one" { resource = type + ":*" }
            else { return AK.obj(["ok": .bool(false), "reason": .string("\(JS.toString(d["verb"])) needs a parameter with role id.\(type) to name its resource")]) }
        }
        return AK.obj(["ok": .bool(true), "op": AK.obj(["verb": d["verb"] ?? .null, "resource": .string(resource), "params": .object(params)])])
    }

    // ---- risk ----

    private static func unit01(_ x: Double) -> Double { min(1.0, max(0.0, x)) }

    /// Risk inputs for a call. `eff` is an `ActionEffective.effective` result; `params` the call's params (or nil); `opts` {kappa?, taint?}.
    public static func riskOf(_ d: JObject, _ eff: JObject, _ params: JObject?, _ opts: JObject?) throws -> JSONValue {
        let e = AK.o(eff["eff"])
        guard let ppm = IV.num(e["blast_ppm"]) else { throw AK.fail("bad_eff", "blast_ppm") }
        var blast = unit01(ppm / 1_000_000)
        var money: [String] = []
        for (k, v) in AK.o(d["params"]) where v.get("role") == .string("money.amount") { money.append(k.s) }
        money.sort(by: u16less)
        if let first = money.first {
            let flat = params.map { flattenParams($0) } ?? [:]
            let amount = flat[JKey(first)]
            let a = IV.num(amount), k = IV.num(opts?["kappa"])
            let ok = amount != nil && amount != .null && amount?.asString == nil && a != nil && a!.isFinite && a! >= 0 && k != nil && k! > 0
            blast = ok ? unit01(a! / k!) : 1.0
        }
        guard let rev = e["rev"]?.asString, let score = REVERSIBILITY_SCORE[rev] else { throw AK.fail("bad_eff", "rev") }
        var out: JObject = ["reversibility": .double(score), "blastRadius": .double(blast), "confidence": .int(1)]
        if let td = IV.num(opts?["taint"]), td.isFinite { out["taint"] = .double(unit01(td)) }
        return .object(out)
    }

    // ---- predicates ----

    /// The resource matcher of a def's pattern (`<type>:<prefix>*`, `<type>:<exact>` or `<type>:*`).
    public static func resourceMatcher(_ d: JObject) -> String {
        let r = AK.o(d["resource"])
        let id = r["id"]
        let type = JS.toString(r["type"])
        if id == .string("*") { return type + ":*" }
        if id?.asObject?[JKey("exact")] != nil { return type + ":" + JS.toString(id?.get("exact")) }
        return type + ":" + JS.toString(id?.get("prefix")) + "*"
    }

    /// The policy predicate scaffold; `limits.max_amount` adds a per-call ceiling on the `money.amount` parameter (a def with none throws).
    public static func predicatesOf(_ d: JObject, _ limits: JObject?) throws -> JSONValue {
        var out: JObject = ["verb": d["verb"] ?? .null, "resource": .string(resourceMatcher(d))]
        if let l = limits, let m = l["max_amount"] {
            guard let i = IV.int(m), i >= 0 else { throw AK.fail("bad_limit", "max_amount must be a non-negative safe integer") }
            let name = try paramByRole(d, "money.amount")
            out["where"] = .array([AK.obj(["field": .string("action.params.\(name)"), "op": .string("lte"), "value": m]),
                                   AK.obj(["field": .string("action.params.\(name)"), "op": .string("gte"), "value": .int(0)])])
        }
        return .object(out)
    }

    // ---- Goal IR ontology terms ----

    private static func sortedStrings(_ vals: JSONValue?) throws -> JSONValue {
        var l: [String] = []
        for x in AK.arr(vals) { guard let s = x.asString else { throw AK.fail("bad_def", "values") }; l.append(s) }
        l.sort(by: u16less)
        return AK.strs(l)
    }

    private static func ontParam(_ d: JObject, _ p: JObject) throws -> JSONValue {
        if let u = AK.pres(p, "unit") {
            let kind = u.get("kind")
            if kind == .string("money") {
                if let c = u.get("ccy")?.asString { return AK.obj(["kind": .string("money"), "ccys": AK.strs([c])]) }
                let from = u.get("ccy")?.get("from")?.asString
                let cp = from.flatMap { AK.o(d["params"])[JKey($0)] }
                let vals = JS.present(cp?.get("values"))
                return AK.obj(["kind": .string("money"), "ccys": vals != nil ? try sortedStrings(vals) : .array([])])
            }
            let k = kind == .string("duration") ? "duration" : kind == .string("bytes") ? "bytes" : kind == .string("ratio") ? "ratio" : "count"
            return AK.obj(["kind": .string(k)])
        }
        let role = p["role"]?.asString, format = p["format"]?.asString
        if let r = role, r.hasPrefix("id.") { return AK.obj(["kind": .string("id"), "of": .string(String(r.dropFirst(3)))]) }
        if let f = format, f.hasPrefix("id:") { return AK.obj(["kind": .string("id"), "of": .string(String(f.dropFirst(3)))]) }
        guard let t = p["type"]?.asString else { throw AK.fail("bad_def", "param type") }
        switch t {
        case "duration": return AK.obj(["kind": .string("duration")])
        case "datetime", "date": return AK.obj(["kind": .string("instant")])
        case "integer": return AK.obj(["kind": .string("count")])
        case "boolean": return AK.obj(["kind": .string("enum"), "values": AK.strs(["false", "true"])])
        case "set": return AK.obj(["kind": .string("enum"), "values": try sortedStrings(AK.pres(p, "values") ?? .array([]))])
        case "string": return AK.pres(p, "values") != nil ? AK.obj(["kind": .string("enum"), "values": try sortedStrings(p["values"])]) : AK.obj(["kind": .string("text")])
        default: return AK.obj(["kind": .string("text")])
        }
    }

    /// Ontology terms for a set of defs; the effect class is DERIVED (`effectClass`).
    public static func toOntology(_ defs: [JSONValue], _ reg: TraitRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JSONValue {
        var typeOrder: [String] = [], types: [String: String] = [:]
        var units: JObject = [:], aliases: JObject = [:], traits: JObject = [:]
        var verbs: [JSONValue] = []
        var sortedDefs: [(String, JSONValue)] = []
        for d in defs { guard let v = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }; sortedDefs.append((v, d)) }
        sortedDefs.sort { u16less($0.0, $1.0) }
        for (verb, dO) in sortedDefs {
            let d = AK.o(dO)
            let res = AK.o(d["resource"])
            guard let rtype = res["type"]?.asString else { throw AK.fail("bad_def", "resource.type") }
            let id = res["id"]
            var prefix = ""
            if !(id == .string("*") || id?.asObject?[JKey("exact")] != nil) {
                guard let pf = id?.get("prefix")?.asString else { throw AK.fail("bad_def", "resource.id.prefix") }
                prefix = pf
            }
            if types[rtype] == nil { types[rtype] = prefix; typeOrder.append(rtype) }
            var params: JObject = [:]
            let dp = AK.o(d["params"])
            for name in AK.sortedKeys(dp) {
                params[JKey(name)] = try ontParam(d, AK.o(dp[JKey(name)]))
                if let u = AK.pres(AK.o(dp[JKey(name)]), "unit") {
                    if u.get("kind") == .string("money"), let ccy = u.get("ccy")?.asString {
                        var m: JObject = ["kind": .string("money")]
                        if let e = u.asObject?[JKey("exp")] { m["exponent"] = e }
                        units[JKey(ccy)] = .object(m)
                    } else if u.get("kind") != .string("money"), let k = u.get("kind")?.asString {
                        units[JKey(k)] = AK.obj(["kind": .string(k)])
                    }
                }
            }
            verbs.append(AK.obj(["id": .string(verb), "effect": .string(try effectClass(d)), "resource_type": .string(rtype), "params": .object(params)]))
            if let al = AK.pres(d, "aliases") {
                for a in AK.arr(al) {
                    guard let s = a.asString else { throw AK.fail("bad_def", "alias") }
                    if let prev = aliases[JKey(s)], prev != d["verb"] { throw AK.fail("alias_collision", "alias '\(s)' names two verbs") }
                    aliases[JKey(s)] = d["verb"] ?? .null
                }
            }
            traits[JKey(verb)] = try ActionEffective.effective(d, reg, attestationVerified)["traits"] ?? .null
        }
        let tl: [JSONValue] = typeOrder.map { AK.obj(["id": .string($0), "id_prefix": .string(types[$0] ?? "")]) }
        return AK.obj(["types": .array(tl), "units": .object(units), "verbs": .array(verbs), "aliases": .object(aliases), "traits": .object(traits)])
    }

    // ---- policy card + escalation + MCP annotations ----

    private static func sentence(_ s: String) -> String {
        if let l = s.utf16.last, l == 46 || l == 33 || l == 63 { return s }
        return s + "."
    }

    private static func joinList(_ xs: [String]) -> String {
        if xs.count <= 1 { return xs.first ?? "" }
        return xs.dropLast().joined(separator: ", ") + " and " + xs[xs.count - 1]
    }

    /// The policy card of a def: deterministic text from its title and the phrases of its trait closure (riskiest first).
    public static func cardOf(_ d: JObject, _ eff: JObject, _ reg: TraitRegistry) throws -> JSONValue {
        let ids = AK.arr(eff["traits"]).compactMap { $0.asString }
        var ordered: [TraitDef] = []
        for id in try Actions.closure(reg, ids) { guard let t = reg.traits[JKey(id)] else { throw AK.fail("unknown_trait", id) }; ordered.append(t) }
        ordered.sort { a, b in a.floor.risk != b.floor.risk ? a.floor.risk > b.floor.risk : u16less(a.id, b.id) }
        var phrases: [String] = []
        for t in ordered where !phrases.contains(where: { IV.same($0, t.cardPhrase) }) { phrases.append(t.cardPhrase) }
        let e = AK.o(eff["eff"])
        guard let title = d["title"]?.asString, let risk = IV.int(e["risk"]), let esc = IV.int(e["esc"]), (0..<4).contains(Int(risk)), (0..<4).contains(Int(esc)) else { throw AK.fail("bad_def", "card") }
        let confirmed = eff["confirmed"] == .bool(true)
        let tail: String
        if confirmed { tail = phrases.isEmpty ? "This action only reads." : "This action " + joinList(phrases) + "." }
        else { tail = "This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it " + joinList(phrases) + "." }
        let text = sentence(title) + " " + tail
        return AK.obj(["verb": d["verb"] ?? .null, "title": .string(title), "text": .string(text), "risk": .string(RISK_NAMES[Int(risk)]), "escalation": .string(ESC_TIERS[Int(esc)]),
                       "reversibility": e["rev"] ?? .null, "blast_ppm": e["blast_ppm"] ?? .null, "needs": e["caveats"] ?? .null, "context": e["context"] ?? .null])
    }

    /// The minimum escalation tier of the effective profile: `{tier, name}`.
    public static func escalationOf(_ eff: JObject) throws -> JSONValue {
        guard let t = IV.int(AK.o(eff["eff"])["esc"]), (0..<4).contains(Int(t)) else { throw AK.fail("bad_eff", "esc") }
        return AK.obj(["tier": .int(t), "name": .string(ESC_TIERS[Int(t)])])
    }

    /// Advisory MCP tool annotations (read-only / destructive / idempotent / open-world).
    public static func mcpAnnotationsOf(_ d: JObject, _ eff: JObject) -> JSONValue {
        let cl = AK.arr(eff["closure"])
        let confirmed = eff["confirmed"] == .bool(true)
        let ro = isReadOnly(d["effects"])
        let mode = AK.o(d["idempotency"])["mode"]
        let idem = mode != nil && mode != .null && mode != .string("none")
        return AK.obj(["readOnlyHint": .bool(confirmed && ro), "destructiveHint": .bool(cl.contains(.string("pca.destructive"))), "idempotentHint": .bool(confirmed && (idem || ro)),
                       "openWorldHint": .bool(cl.contains(.string("pca.network_egress")) || cl.contains(.string("pca.external_communication")))])
    }
}

/// The plain-language profile of one def: its policy card, the effective profile, and what a grant must carry before the action is auto-allowed. Deterministic text.
public enum ActionExplain {
    private static func blastText(_ ppm: Int64) -> String { ppm % 1000 == 0 ? "\(ppm / 1000)k" : "\(ppm)ppm" }
    private static func join(_ xs: JSONValue?) -> String { AK.arr(xs).map { JS.toString($0) }.joined(separator: ", ") }

    public static func explainDef(_ d: JObject, _ reg: TraitRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> String {
        let eff = try ActionEffective.effective(d, reg, attestationVerified)
        let card = AK.o(try ActionDerive.cardOf(d, eff, reg))
        let e = AK.o(eff["eff"])
        let confirmed = eff["confirmed"] == .bool(true)
        let rev = e["rev"]?.asString ?? ""
        var lines: [String] = []
        lines.append(JS.toString(card["text"]))
        let revText = rev == "irreversible" ? "irreversible" : rev == "rate_limited" ? "rate limited" : "reversible"
        lines.append("effective: risk \(IV.int(e["risk"]) ?? 0), \(revText), blast \(blastText(IV.int(e["blast_ppm"]) ?? 0)), escalation: \(JS.toString(card["escalation"]))")
        let needs = AK.arr(card["needs"])
        lines.append("grant must carry: " + (needs.isEmpty ? "nothing" : join(card["needs"])))
        if !AK.arr(card["context"]).isEmpty { lines.append("call must carry: " + join(card["context"])) }
        let closure = join(eff["closure"])
        let state = AK.o(d["review"])["state"]?.asString
        lines.append("traits: " + (closure.isEmpty ? "none" : closure))
        lines.append("review: " + (confirmed ? (state ?? "null") : (state ?? "null") + ", not confirmed by a signed review"))
        if !confirmed {
            let h = AK.o(eff["hint"])
            let hc = join(h["closure"])
            let he = AK.o(h["eff"])
            lines.append("until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk \(IV.int(he["risk"]) ?? 0), escalation tier \(IV.int(he["esc"]) ?? 0), traits: " + (hc.isEmpty ? "none" : hc))
        }
        return lines.joined(separator: "\n")
    }
}

/// The facade's view of an action def: the spec rows a facade compiles permissions and limits from (reversibility class, blast preset,
/// the amount parameter), DERIVED from the effective profile of the def instead of written by hand.
public enum ActionFacade {
    /// One def to one facade row. Reversibility and blast are the EFFECTIVE values. `reviewed` prices the def as REVIEWED (declared + implied traits).
    public static func specOfDef(_ d: JObject, _ reg: TraitRegistry, reviewed: Bool, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JSONValue {
        let full = try ActionEffective.effective(d, reg, attestationVerified)
        let e = reviewed ? AK.o(full["hint"]) : full
        guard let verb = d["verb"]?.asString else { throw AK.fail("bad_def", "verb") }
        let us = Array(verb.utf16)
        let dot = us.firstIndex(of: 46)
        let connector = dot.map { String(decoding: us[..<$0], as: UTF16.self) } ?? verb
        let action = dot.map { String(decoding: us[($0 + 1)...], as: UTF16.self) } ?? ""
        var amountField: String?
        do { amountField = try ActionDerive.paramByRole(d, "money.amount") } catch is ActionKitError { amountField = nil }
        let eff = AK.o(e["eff"])
        guard let ppm = IV.num(eff["blast_ppm"]) else { throw AK.fail("bad_eff", "blast_ppm") }
        var out: JObject = ["connector": .string(connector), "action": .string(action), "verb": .string(verb), "reversibility": eff["rev"] ?? .null, "blastRadius": .double(ppm / 1_000_000)]
        if let a = amountField { out["amountField"] = .string(a) }
        out["description"] = AK.pres(d, "description") ?? d["title"] ?? .null
        if let al = d["aliases"]?.asArray, !al.isEmpty {
            var s: [String] = []
            for a in al { guard let x = a.asString else { throw AK.fail("bad_def", "alias") }; s.append(x) }
            s.sort { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
            out["aliases"] = AK.strs(s)
        }
        out["traits"] = e["closure"] ?? .null
        return .object(out)
    }

    /// The facade rows of a pack, in the pack's own order.
    public static func facadeSpecs(_ defs: [JSONValue], _ reg: TraitRegistry, reviewed: Bool, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> [JSONValue] {
        try defs.map { try specOfDef(AK.o($0), reg, reviewed: reviewed, attestationVerified) }
    }
}
