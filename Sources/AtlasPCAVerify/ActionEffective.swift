import Foundation

/// From an action def to its trait set T(d), declared profile decl(d) and effective profile `eff_R(d) = decl(d) join F_R(T(d))`, plus the
/// structural param rules and the profile lattice over profile objects (`{risk, rev, blast_ppm, esc, caveats, context, prules}`).
public enum ActionEffective {
    public static let PARAM_RULE_IDS = Actions.PARAM_RULE_IDS

    // ---- profile lattice ----
    private static func prof(_ v: JSONValue) throws -> Profile {
        guard let p = Profile(json: v) else { throw AK.fail("bad_profile", "not a profile") }
        return p
    }
    public static func join(_ p: JSONValue, _ q: JSONValue) throws -> JSONValue { Actions.join(try prof(p), try prof(q)).json }
    public static func leq(_ p: JSONValue, _ q: JSONValue) throws -> Bool { Actions.leq(try prof(p), try prof(q)) }
    public static func profileEq(_ p: JSONValue, _ q: JSONValue) throws -> Bool { try leq(p, q) && leq(q, p) }

    // ---- effective ----

    /// True iff the def's attestation is valid (the caller's verifier decides). Nil = never confirmed.
    public static func isConfirmed(_ d: JObject, _ attestationVerified: ((JObject) -> Bool)?) -> Bool { attestationVerified?(d) ?? false }

    public static func hintTraits(_ d: JObject) throws -> [String] { try Actions.hintTraits(d) }

    public static func traitsOf(_ d: JObject, _ reg: TraitRegistry, _ attestationVerified: ((JObject) -> Bool)?) throws -> [String] {
        try isConfirmed(d, attestationVerified) ? hintTraits(d) : Actions.topTraits(reg)
    }

    private static func view(_ decl: Profile, _ reg: TraitRegistry, _ traits: [String]) throws -> (json: JObject, floor: Profile, eff: Profile, traits: [String], closure: [String]) {
        let floor = try Actions.floorOf(reg, traits)
        let cl = try Actions.closure(reg, traits)
        let eff = Actions.join(decl, floor)
        return (["traits": AK.strs(traits), "closure": AK.strs(cl), "floor": floor.json, "eff": eff.json], floor, eff, traits, cl)
    }

    /// `{traits, closure, floor, eff, confirmed, decl, hint: {traits, closure, floor, eff}, clamps}`.
    public static func effective(_ d: JObject, _ reg: TraitRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JObject {
        guard Actions.normalizable(d) else { throw JSError("effective: the def is not a well-formed action definition") }
        let decl = try Actions.declProfile(d)
        let hint = try view(decl, reg, hintTraits(d))
        let confirmed = isConfirmed(d, attestationVerified)
        let main = confirmed ? hint : try view(decl, reg, Actions.topTraits(reg))
        var clamps: [JSONValue] = []
        let rr = Actions.REV_RANK
        if AK.pres(d, "reversibility") != nil, (rr[decl.rev] ?? 2) < (rr[hint.floor.rev] ?? 2) {
            clamps.append(AK.obj(["field": .string("rev"), "declared": .string(decl.rev), "floor": .string(hint.floor.rev)]))
        }
        if AK.pres(d, "blast") != nil, decl.blastPpm < hint.floor.blastPpm {
            clamps.append(AK.obj(["field": .string("blast_ppm"), "declared": .int(Int64(decl.blastPpm)), "floor": .int(Int64(hint.floor.blastPpm))]))
        }
        var out = main.json
        out["confirmed"] = .bool(confirmed)
        out["decl"] = decl.json
        out["hint"] = .object(hint.json)
        out["clamps"] = .array(clamps)
        return out
    }

    /// The hint profile after adding trait `t` to the declared traits (never lower). Analysis only.
    public static func effWithTrait(_ d: JObject, _ t: String, _ reg: TraitRegistry) throws -> JSONValue {
        var c = d
        var tr = AK.arr(d["traits"])
        tr.append(.string(t))
        c["traits"] = .array(tr)
        return AK.o(try effective(c, reg)["hint"])["eff"] ?? .null
    }

    // ---- structural param rules ----

    private static func withRole(_ params: JObject, _ pred: (String) -> Bool) -> [JObject] {
        var out: [JObject] = []
        for k in JS.keyOrder(params) {
            let p = AK.o(params[k])
            if let r = p["role"]?.asString, pred(r) { out.append(p) }
        }
        return out
    }

    /// The rules the def violates, among `ids`; nil = all of them.
    public static func prulesViolations(_ d: JObject, _ ids: [String]? = nil) throws -> [String] {
        let n = try Actions.normalize(d)
        let params = AK.o(n["params"])
        let res = AK.o(n["resource"])
        var bad: [String] = []
        for id in ids ?? PARAM_RULE_IDS {
            var ok = true
            switch id {
            case "money_has_currency":
                for e in withRole(params, { $0 == "money.amount" || $0 == "money.fee" }) {
                    guard case let .object(u)? = e["unit"], u["kind"]?.asString == "money" else { ok = false; break }
                    if u["ccy"]?.asString != nil { continue }
                    let from = u["ccy"]?.get("from")?.asString
                    guard let f = from, case let .object(c)? = params[JKey(f)], c["role"]?.asString == "money.currency", c["format"]?.asString == "iso_currency" else { ok = false; break }
                }
            case "money_amount_bounded":
                for p in withRole(params, { $0 == "money.amount" }) where !(p["type"]?.asString == "integer" && AK.pres(p, "min") != nil && AK.pres(p, "max") != nil) { ok = false; break }
            case "id_not_wildcard":
                ok = !(res["id"]?.asString == "*" && res["scope"]?.asString == "one")
            case "recipient_param_declared":
                ok = n["audience"]?.asString == "resource" || !withRole(params, { $0 == "party.payee" || $0.hasPrefix("contact.") }).isEmpty
            case "array_bounded":
                for pv in params.values where AK.o(pv)["type"]?.asString == "array" && AK.pres(AK.o(pv), "max_items") == nil { ok = false; break }
            case "export_bounded":
                ok = res["scope"]?.asString == "one"
                if !ok { for p in withRole(params, { $0 == "count.limit" }) where AK.pres(p, "max") != nil { ok = true; break } }
            case "secret_not_logged":
                for p in withRole(params, { $0.hasPrefix("credential.") }) {
                    guard case let .array(tg)? = p["tags"], tg.contains(.string("secret")) else { ok = false; break }
                }
            case "pay_has_idempotency":
                ok = !AK.arr(n["effects"]).contains(.string("pay")) || AK.o(n["idempotency"])["mode"]?.asString != "none"
            default: break
            }
            if !ok { bad.append(id) }
        }
        return bad
    }

    /// The rules the effective profile requires but the def does not satisfy (the load-time check).
    public static func requiredPrulesViolated(_ d: JObject, _ eff: JSONValue) throws -> [String] {
        try prulesViolations(d, AK.arr(AK.o(eff)["prules"]).compactMap { $0.asString })
    }
}
