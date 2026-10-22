import Foundation

/// PCA 0.4.1 policy-layer caveat helpers, mirroring `policyCaveats` (packages/pca/src/policy-vm.ts) and
/// `agentNativeCaveatEvaluator` / `envelopeCaveatEvaluator` (agent-native.ts, predicates.ts).
///
/// The core verifier (`PCA.verify`) does NOT evaluate caveats. A resource server that enforces a grant's caveats calls
/// `PCA.evaluateCaveats(PCA.policyCaveats(grant: grant, chain: pcactn["cap_chain"]), context: ctx)` with its own action
/// params. 0.4.1 security fix (TypeScript policy layer): caveats on the ROOT grant outside the envelope are enforced exactly
/// like the caveats delegation hops append; this helper pair includes them.
extension PCA {
    /// The caveat type `readEnvelope` reads (evaluated separately by the full verifier, never as a caveat here).
    public static let ENVELOPE_CAVEAT = "envelope"
    static let REVERSIBILITY_ORDER = ["reversible", "rate_limited", "irreversible"]

    /// Every caveat the policy layer evaluates for an action under `grant` delegated along `chain` (root first): the grant's
    /// `caveats` without its FIRST `envelope` caveat (order kept), then the caveats the hops appended (the last chain
    /// element's `caveats` beyond the grant's). A grant whose `caveats` is not a JSON array hands that value through (`nil`
    /// when absent or when `grant` is not an object); `evaluateCaveats` refuses it.
    public static func policyCaveats(grant: JSONValue, chain: JSONValue?) -> JSONValue? {
        guard let csv = grant.asObject?[JKey("caveats")] else { return nil }
        guard let cs = csv.asArray else { return csv }
        var out = cs
        if let i = cs.firstIndex(where: { sameString($0.asObject?[JKey("type")], ENVELOPE_CAVEAT) }) { out.remove(at: i) }
        if let leaf = chain?.asArray?.last, let lc = leaf.asObject?[JKey("caveats")]?.asArray, lc.count > cs.count {
            out += lc[cs.count...]
        }
        return .array(out)
    }

    /// Evaluate a caveat list against an action context: `ok` iff every caveat is satisfied; `failed` = the unsatisfied
    /// caveats' `type` strings in order (`"<malformed>"` when `type` is not a string). A value that is not a JSON array gives
    /// `(false, ["<malformed caveats>"])`. Total. Fail closed: a type this evaluator does not implement (note, envelope,
    /// resource_prefix, predicates, tool_schema, ...) is unsatisfied.
    ///
    /// `context` is a JSON object: `now` (epoch ms), `delegation_depth`?, `blast_radius`?, `reversibility_class`?,
    /// `recent_action_times`?, `action` {verb, resource, reversibility_class, params}.
    ///  - `max_spend` {usd}: usd finite >= 0; `action.params` (an object) has an own finite `amount` with 0 <= amount <= usd,
    ///    and an own `currency`, when present, is exactly "usd" or "USD". Does not need `now`.
    ///  - everything below needs a finite `now`: `expires` {at} now < at; `not_before` {at} now >= at; `rate` {max, per_secs}
    ///    fewer than max entries t of `recent_action_times` with now - per_secs*1000 < t <= now; `max_blast_radius` {max}
    ///    blast_radius <= max; `reversibility_max` {class} `context.reversibility_class` no more severe than class;
    ///    `delegation_depth` {max} depth <= max; `budget_alloc` {limit} limit finite >= 0.
    public static func evaluateCaveats(_ caveats: JSONValue?, context: JSONValue) -> (ok: Bool, failed: [String]) {
        guard let list = caveats?.asArray else { return (false, ["<malformed caveats>"]) }
        var failed: [String] = []
        for cv in list where !caveatSatisfied(cv, context) {
            failed.append(cv.asObject?[JKey("type")]?.asString ?? "<malformed>")
        }
        return (failed.isEmpty, failed)
    }

    /// Exact code-point equality (Swift `==` on String is canonical equivalence; JSON strings compare by code points).
    private static func sameString(_ v: JSONValue?, _ s: String) -> Bool {
        guard let x = v?.asString else { return false }
        return x.unicodeScalars.elementsEqual(s.unicodeScalars)
    }

    /// A finite JSON number as a Double (never a bool or a string).
    private static func finite(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d.isFinite ? d : nil
        default: return nil
        }
    }

    /// The action's spend in USD as `max_spend` reads it (own params.amount, finite >= 0, currency absent / "usd" / "USD").
    private static func actionSpendUsd(_ action: JSONValue?) -> Double? {
        guard let params = action?.asObject?[JKey("params")]?.asObject, let amountV = params[JKey("amount")],
              let amount = finite(amountV), amount >= 0 else { return nil }
        if let cur = params[JKey("currency")], !sameString(cur, "usd") && !sameString(cur, "USD") { return nil }
        return amount
    }

    private static func caveatSatisfied(_ cv: JSONValue, _ ctxV: JSONValue) -> Bool {
        guard let c = cv.asObject, let ctx = ctxV.asObject else { return false }
        let type = c[JKey("type")]
        if sameString(type, "max_spend") {
            guard let lim = finite(c[JKey("usd")]), lim >= 0, let spend = actionSpendUsd(ctx[JKey("action")]) else { return false }
            return spend <= lim
        }
        // Every known type is ASCII; for an all-ASCII string Swift's `==` (canonical equivalence) is exact code-point equality.
        guard let now = finite(ctx[JKey("now")]), let t = type?.asString, t.unicodeScalars.allSatisfy({ $0.isASCII }) else { return false }
        switch t {
        case "expires":
            guard let at = finite(c[JKey("at")]) else { return false }
            return now < at
        case "not_before":
            guard let at = finite(c[JKey("at")]) else { return false }
            return now >= at
        case "rate":
            guard let max = finite(c[JKey("max")]), let per = finite(c[JKey("per_secs")]), per > 0,
                  let times = ctx[JKey("recent_action_times")]?.asArray else { return false }
            let lo = now - per * 1000
            let n = times.reduce(0) { acc, tv in
                guard let t = finite(tv), t > lo, t <= now else { return acc }
                return acc + 1
            }
            return Double(n) < max
        case "max_blast_radius":
            guard let max = finite(c[JKey("max")]), let br = finite(ctx[JKey("blast_radius")]) else { return false }
            return br <= max
        case "reversibility_max":
            guard let cls = c[JKey("class")], let cur = ctx[JKey("reversibility_class")],
                  let li = REVERSIBILITY_ORDER.firstIndex(where: { sameString(cls, $0) }),
                  let ci = REVERSIBILITY_ORDER.firstIndex(where: { sameString(cur, $0) }) else { return false }
            return ci <= li
        case "delegation_depth":
            guard let max = finite(c[JKey("max")]), let d = finite(ctx[JKey("delegation_depth")]) else { return false }
            return d <= max
        case "budget_alloc":
            guard let lim = finite(c[JKey("limit")]) else { return false }
            return lim >= 0
        case IntentSession.CAVEAT:
            // Intent Layer v2 session binding (rule 13): no per-action constraint here; satisfied iff well-formed.
            return IntentSession.caveatError(cv) == nil
        default:
            return false
        }
    }
}
