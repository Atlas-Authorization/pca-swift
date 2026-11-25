import Foundation

/// liftLegacy: the total, conservative lift of the facade's `{permissions, limits}` input to a Goal plus IR ontology. The corrected
/// semantics of the facade's old limit bugs live here: `$200/day` is a SLIDING 86 400 000 ms sum bound (not a per-call ceiling plus a
/// one-day lifetime); a `$` limit on a verb with no amount field is an error; every limit is its own bound, so adding a limit only
/// narrows. Money parameters are integers in MINOR units of USD (cents).
public enum PCAGoalLegacy {
    private static func usd() -> JSONValue { GV.obj([("k", .string("money")), ("ccy", .string("USD"))]) }

    private static func cmp(_ op: String, _ l: JSONValue, _ r: JSONValue) -> JSONValue {
        GV.obj([("k", .string("cmp")), ("op", .string(op)), ("l", l), ("r", r)])
    }

    private static func usdLit(_ n: Int64) -> JSONValue {
        GV.obj([("k", .string("lit")), ("v", GV.obj([("k", .string("q")), ("q", GV.obj([("u", usd()), ("n", .int(n))]))]))])
    }

    /// JavaScript Math.round: nearest integer, ties toward +infinity.
    private static func jsRound(_ v: Double) -> Double {
        let f = v.rounded(.down)
        return v - f >= 0.5 ? f + 1 : f
    }

    private static func bad(_ m: String) -> JSError { JSError(m) }

    /// Lift a legacy permission object (`{connector: [action, ...]}`) and limits (`{verb or action: "$500/day"}`) to
    /// {goal, ontology}. `limits`, `catalog`, `notAfter`, `notBefore` and `nlDigest` may be nil.
    public static func liftLegacy(_ permissions: JSONValue, _ limits: JSONValue?, _ catalog: PCACatalog?, _ principal: String,
                                  _ notAfter: Int64?, _ notBefore: Int64?, _ nlDigest: String?) throws -> JSONValue {
        let raw: JObject = limits?.asObject ?? [:]
        // the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
        guard let perms = permissions.asObject else { throw bad("compilePolicy: permissions must be an object") }
        var pairs: [(String, [String])] = []
        for k in perms.keys.sorted(by: { GV.less($0.s, $1.s) }) {
            guard let acts = perms[k]?.asArray else { throw bad("compilePolicy: permissions.\(k.s) must be an array") }
            pairs.append((k.s, acts.map { GV.jsStr($0) }))
        }
        // only text limits reach the facade compiler; a non-text limit of a granted verb is refused below
        var textLimits: [String: String] = [:]
        for (k, v) in raw { if let s = v.asString { textLimits[k.s] = s } }
        let specs = try PCAFacade.compilePolicy(permissions: pairs, limits: textLimits, catalog: catalog ?? .default, now: 0).actions
        var grants: [JSONValue] = []
        var bounds: [JSONValue] = []
        var verbs: [JSONValue] = []
        for s in specs {
            let gid = "g:" + s.verb
            var amountPath: String? = nil
            if let f = s.amountField, !f.isEmpty { amountPath = f }
            var params: [JSONValue] = []
            if let ap = amountPath { params.append(GV.obj([("path", .string(ap)), ("ty", GV.obj([("k", .string("q")), ("u", usd())]))])) }
            verbs.append(GV.obj([("verb", .string(s.verb)), ("cls", .string(s.reversibility)), ("params", .array(params))]))
            let resource = s.resource ?? "*"
            if (resource.contains("*") || resource.contains("?") || resource.hasPrefix("re:")) && resource != "*" {
                throw bad("liftLegacy: resource pattern '\(resource)' of \(s.verb) is not expressible; name exact resources or acknowledge a wildcard")
            }
            // own(verb) ?? own(action): a null verb limit falls through to the action; a present null action limit is malformed (parseLimit refuses it)
            // the facade compiler only saw text limits: a non-text limit that would apply to this action is malformed
            var applied: JSONValue? = nil
            for k in [s.verb, s.action] + s.aliases where applied == nil {
                if let v = raw[JKey(k)], v != .null { applied = v }
            }
            if let ap = applied, ap.asString == nil { throw bad("parseLimit: empty limit") }
            var rawLimit: JSONValue? = raw[JKey(s.verb)]
            if rawLimit == .null { rawLimit = nil }
            var has = rawLimit != nil
            if !has {
                has = raw[JKey(s.action)] != nil
                rawLimit = raw[JKey(s.action)]
            }
            var cond: JSONValue = GV.obj([("k", .string("true"))])
            if has {
                guard let text = rawLimit?.asString else { throw bad("parseLimit: empty limit") }
                let lim = try PCAFacade.parseLimit(text)
                if lim.unit == "usd" {
                    guard let ap = amountPath else {
                        throw bad("liftLegacy: '$' limit on '\(s.verb)' but the catalog gives that verb no amount field, so the limit could not be enforced")
                    }
                    let mm = jsRound(lim.amount * 100)
                    if mm.isNaN || mm.isInfinite || abs(mm) > Double(GV.MAX_SAFE) { throw bad("liftLegacy: limit for \(s.verb) is out of range") }
                    let minor = Int64(mm)
                    let amt = GV.obj([("k", .string("param")), ("path", .string(ap)), ("ty", GV.obj([("k", .string("q")), ("u", usd())]))])
                    cond = GV.obj([("k", .string("and")), ("a", cmp("gte", amt, usdLit(0))), ("b", cmp("lte", amt, usdLit(minor)))])
                    if let pm = lim.periodMs {
                        bounds.append(GV.obj([
                            ("bid", .string("b:" + s.verb)), ("sel", GV.obj([("k", .string("gids")), ("gids", .array([.string(gid)]))])), ("agg", .string("sum")),
                            ("value", amt), ("key", .string("")), ("window", GV.obj([("k", .string("sliding")), ("ms", .int(pm))])),
                            ("scope", GV.obj([("k", .string("session"))])), ("cap", GV.obj([("u", usd()), ("n", .int(minor))])), ("onExceed", .string("deny")),
                        ]))
                    }
                } else {
                    if lim.amount != lim.amount.rounded(.toNearestOrEven) || abs(lim.amount) > Double(GV.MAX_SAFE) {
                        throw bad("liftLegacy: count limit for \(s.verb) must be a whole number")
                    }
                    let count = GV.obj([("k", .string("count"))])
                    var window: JSONValue = GV.obj([("k", .string("lifetime"))])
                    if let pm = lim.periodMs { window = GV.obj([("k", .string("sliding")), ("ms", .int(pm))]) }
                    bounds.append(GV.obj([
                        ("bid", .string("b:" + s.verb)), ("sel", GV.obj([("k", .string("gids")), ("gids", .array([.string(gid)]))])), ("agg", .string("count")),
                        ("value", GV.obj([("k", .string("lit")), ("v", GV.obj([("k", .string("q")), ("q", GV.obj([("u", count), ("n", .int(1))]))]))])), ("key", .string("")),
                        ("window", window), ("scope", GV.obj([("k", .string("session"))])), ("cap", GV.obj([("u", count), ("n", .int(Int64(lim.amount)))])),
                        ("onExceed", .string("deny")),
                    ]))
                }
            }
            let res: JSONValue = resource == "*"
                ? GV.obj([("k", .string("any")), ("reason", .string("legacy default: no resource scope given"))])
                : GV.obj([("k", .string("exact")), ("id", .string(resource))])
            grants.append(GV.obj([("gid", .string(gid)), ("verb", .string(s.verb)), ("res", res), ("cond", cond)]))
        }
        // no two grants share a gid (checked after the sort, so the sort needs no stability)
        grants.sort { GV.less(GV.get($0, "gid")?.asString ?? "", GV.get($1, "gid")?.asString ?? "") }
        bounds.sort { GV.less(GV.get($0, "bid")?.asString ?? "", GV.get($1, "bid")?.asString ?? "") }
        if grants.count > 1 {
            for i in 1..<grants.count where GV.get(grants[i], "gid") == GV.get(grants[i - 1], "gid") {
                throw bad("liftLegacy: duplicate grant " + GV.jsStr(GV.get(grants[i], "gid")))
            }
        }
        var mayTouch: [JSONValue] = []
        var wildcardAck: [JSONValue] = []
        for g in grants {
            mayTouch.append(GV.get(g, "gid") ?? .null)
            if GV.kind(GV.get(g, "res")) == "any" { wildcardAck.append(GV.get(g, "gid") ?? .null) }
        }
        let goal = GV.obj([
            ("v", .int(1)), ("principal", .string(principal)), ("ontDigest", .string("legacy-catalog")), ("nlDigest", .string(nlDigest ?? "")), ("sources", .array([])),
            ("grants", .array(grants)), ("prohibits", .array([])), ("bounds", .array(bounds)),
            ("validity", GV.obj([("notBefore", .int(notBefore ?? 0)), ("notAfter", .int(notAfter ?? GV.MAX_SAFE)), ("maxIdle", .int(0))])),
            ("deleg", GV.obj([("maxDepth", .int(16)), ("narrowOnly", .bool(true)), ("mayTouch", .array(mayTouch))])),
            ("escalateOn", .array([])), ("wildcardAck", .array(wildcardAck)), ("holes", .array([])),
        ])
        verbs.sort { GV.less(GV.get($0, "verb")?.asString ?? "", GV.get($1, "verb")?.asString ?? "") }
        var uniq: [JSONValue] = []
        for i in verbs.indices where i == 0 || GV.get(verbs[i - 1], "verb") != GV.get(verbs[i], "verb") { uniq.append(verbs[i]) }
        return GV.obj([("goal", goal), ("ontology", GV.obj([("verbs", .array(uniq)), ("rels", .array([]))]))])
    }
}
