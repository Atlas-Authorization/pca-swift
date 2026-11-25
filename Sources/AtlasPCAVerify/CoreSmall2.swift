import Foundation

// The agent-native caveat context, the reversibility class of an action, the denial wording naming an unmet limit and the server-side risk inputs
// of the connector catalog.
extension PCA {
    /// The tool call derived from an action context `{action: {verb, params}, toolBinding?}`: `{tool, args, toolSignatureDigest?}`.
    public static func toolCallOf(_ action: JSONValue?) -> JSONValue {
        let a = action?.get("action")
        var out: [(String, JSONValue)] = [("tool", .string(a?.get("verb")?.asString ?? "")), ("args", a?.get("params")?.isObject == true ? a!.get("params")! : .object([:]))]
        if let b = action?.get("toolBinding")?.asString { out.append(("toolSignatureDigest", .string(b))) }
        return PCAApprovalChannels.obj(out)
    }

    /// A stock caveat context extended with the action and its derived tool call so `predicates` / `tool_schema` caveats can be evaluated. The derived
    /// members are applied LAST: a caller-supplied context can never substitute a different action or tool call.
    public static func agentCaveatContext(_ base: JSONValue?, _ action: JSONValue?) -> JSONValue {
        var m = base?.asObject ?? [:]
        m[JKey("action")] = action ?? .null
        m[JKey("toolCall")] = toolCallOf(action)
        return .object(m)
    }

    /// THE reversibility class of an action for `reversibility_max` caveats: the action's own class, else the class of the plan node `nodeId` names (the
    /// signed `plan.node_id`), else nil, which no `reversibility_max` caveat accepts (fail closed).
    public static func resolveReversibilityClass(_ action: JSONValue?, plan: [JSONValue]?, nodeId: String?) -> String? {
        if let own = JS.present(action?.get("action")?.get("reversibility_class")) { return own.asString ?? JS.toString(own) }
        guard let id = nodeId, let plan = plan else { return nil } // no node named: never a guess
        return plan.first { $0.get("id")?.asString.map { IV.same($0, id) } ?? false }?.get("reversibility_class")?.asString
    }

    /// The denial wording naming the unmet limit (`<limit> not satisfied for <verb> on <resource>`), or nil when none is in scope. Never throws.
    public static func namedUnmetLimitReason(_ predicates: JSONValue?, _ ctx: JSONValue?) -> String? {
        guard let c = ctx, c.isObject, let limit = Predicates.firstUnmetLimit(predicates, c, SafeRegex.Budget()) else { return nil }
        let a = c.get("action")
        return "\(limit) not satisfied for \(IntentWB.jsOpt(a?.get("verb"))) on \(IntentWB.jsOpt(a?.get("resource")))"
    }

    /// Reversibility score per class (1 = fully reversible), the scale the hosted adjudicator uses.
    public static let CATALOG_REVERSIBILITY_SCORE: [String: Double] = ["reversible": 1, "rate_limited": 0.4, "costly": 0.4, "irreversible": 0]

    /// The server's risk inputs for an action the catalog knows, read only from the server's own data: `reversibility` from the class score,
    /// `blastRadius` from the catalog (or, for an amount-bearing action, `amount / kappa` from the verified params and the grant's signed risk policy,
    /// the worst case 1 when either is unusable), `confidence` 1 and, when `taint` is supplied, `taint` in [0, 1]. An unknown verb yields `{}`.
    public static func catalogRisk(verb: String, params: JSONValue?, grant: JSONValue, catalog: PCACatalog = .default, taint: Double? = nil) -> JSONValue {
        guard let spec = catalog.get(verb) else { return .object([:]) }
        func unit(_ x: Double) -> Double { Swift.min(1, Swift.max(0, x)) }
        var blast = unit(spec.blastRadius)
        if let f = spec.amountField {
            let amount = params?.get(f).flatMap { IV.num($0) }
            let kappa = readEnvelope(grant)?.get("risk_policy")?.get("kappa").flatMap { IV.num($0) }
            if let a = amount, a.isFinite, a >= 0, let k = kappa, k.isFinite, k > 0 { blast = unit(a / k) } else { blast = 1 }
        }
        var out: [(String, JSONValue)] = [("reversibility", PCARiskBudgets.num(CATALOG_REVERSIBILITY_SCORE[spec.reversibility] ?? 0)), ("blastRadius", PCARiskBudgets.num(blast)),
                                          ("confidence", .int(1))]
        if let t = taint, t.isFinite { out.append(("taint", PCARiskBudgets.num(unit(t)))) }
        return PCAApprovalChannels.obj(out)
    }
}
