import Foundation

/// Outcome verification: postconditions on observed effects. A postcondition is a set of conditions in the ordinary predicate language
/// over the requested action (`action.params.*`, `action.resource`) and the observed effect at `env.effect.*`, evaluated by the one
/// evaluator. A clause whose `ref` names an action parameter the action does not carry is not applicable and is skipped. Results: ok,
/// violated (a negative runtime observation), pending (the effect record lacks a field a clause reads).
public enum PCAIntentEffects {
    private static func leaf(_ field: String, _ op: String, _ ref: String?, _ value: JSONValue?) -> JSONValue {
        var m: JObject = [:]
        m[JKey("field")] = JSONValue.string("env.effect." + field)
        m[JKey("op")] = JSONValue.string(op)
        if let r = ref { m[JKey("ref")] = JSONValue.string(r) } else { m[JKey("value")] = value ?? JSONValue.null }
        return JSONValue.object(m)
    }

    private static func pc(_ id: String, _ verb: String, _ description: String, _ whereClauses: [JSONValue]) -> JSONValue {
        return JSONValue.object([JKey("id"): JSONValue.string(id), JKey("verb"): JSONValue.string(verb),
                                 JKey("description"): JSONValue.string(description), JKey("where"): JSONValue.array(whereClauses)])
    }

    private static let ZERO: JSONValue = JSONValue.int(0)

    /// Postconditions for the built-in connectors' state-changing verbs.
    public static let DEFAULT_POSTCONDITIONS: [JSONValue] = [
        pc("stripe.refund.amount", "stripe.refund", "the refunded amount is at most the requested amount", [leaf("amount", "lte", "action.params.amount", nil), leaf("amount", "gte", nil, ZERO)]),
        pc("stripe.refund.recipient", "stripe.refund", "the refund went to the requested recipient", [leaf("recipient", "eq", "action.params.recipient", nil)]),
        pc("stripe.charge.amount", "stripe.charge", "the charged amount is at most the requested amount", [leaf("amount", "lte", "action.params.amount", nil), leaf("amount", "gte", nil, ZERO)]),
        pc("stripe.payout.amount", "stripe.payout", "the paid-out amount is at most the requested amount", [leaf("amount", "lte", "action.params.amount", nil), leaf("amount", "gte", nil, ZERO)]),
        pc("stripe.payout.recipient", "stripe.payout", "the payout went to the requested recipient", [leaf("recipient", "eq", "action.params.recipient", nil)]),
        pc("gmail.send.to", "gmail.send", "the mail went only to the requested address", [leaf("to", "eq", "action.params.to", nil)]),
        pc("slack.post_message.channel", "slack.post_message", "the message was posted in the requested channel", [leaf("channel", "eq", "action.params.channel", nil)]),
        pc("files.write.path", "files.write", "the written path is the requested resource", [leaf("path", "eq", "action.resource", nil)]),
        pc("files.delete.path", "files.delete", "the deleted path is the requested resource", [leaf("path", "eq", "action.resource", nil)]),
        pc("github.merge_pr.repo", "github.merge_pr", "the merge landed in the requested repository", [leaf("repo", "eq", "action.resource", nil)]),
        pc("calendar.create_event.hour", "calendar.create_event", "the event starts at the requested hour", [leaf("hour", "eq", "env.hour", nil)]),
    ]

    private static func has(_ o: JSONValue?, _ k: String) -> Bool { return o?.asObject?[JKey(k)] != nil }

    private static func leaves(_ c: JSONValue?, _ out: inout [(field: String, ref: String?)]) {
        guard let o = c?.asObject else { return }
        if has(c, "all_of") || has(c, "any_of") || has(c, "not") {
            if let a = o[JKey("all_of")]?.asArray { for x in a { leaves(x, &out) } }
            else if let a = o[JKey("any_of")]?.asArray { for x in a { leaves(x, &out) } }
            else if has(c, "not") { leaves(o[JKey("not")], &out) }
            return
        }
        if let f = o[JKey("field")]?.asString { out.append((f, o[JKey("ref")]?.asString)) }
    }

    /// Own-property walk of a dotted path: does a value exist there?
    private static func defined(_ root: JSONValue, _ path: String) -> Bool {
        var cur: JSONValue = root
        for k in IV.split(path, ".") {
            guard let o = cur.asObject, let n = o[JKey(k)] else { return false }
            cur = n
        }
        return true
    }

    /// The evaluator's context for an action plus its observed effect.
    public static func effectContext(_ vs: WalletVerb, _ o: JSONValue, _ effect: JSONValue?) -> JSONValue {
        let a: JObject = PCAIntentPolicy.outcomeToAction(vs, o)
        var action: JObject = [:]
        action[JKey("verb")] = a[JKey("verb")] ?? JSONValue.null
        action[JKey("resource")] = a[JKey("resource")] ?? JSONValue.null
        action[JKey("params")] = PCAIntentRuntime.jsonNums(a[JKey("params")])
        action[JKey("reversibility_class")] = JSONValue.string(vs.reversibility)
        var ctx: JObject = [:]
        ctx[JKey("action")] = JSONValue.object(action)
        if let s = a[JKey("subject")] { ctx[JKey("subject")] = PCAIntentRuntime.jsonNums(s) }
        var env: JObject = [:]
        if let e = a[JKey("env")], let eo = PCAIntentRuntime.jsonNums(e).asObject { for (k, v) in eo { env[k] = v } }
        env[JKey("effect")] = effect ?? JSONValue.null
        ctx[JKey("env")] = JSONValue.object(env)
        return JSONValue.object(ctx)
    }

    /// {status, violated, missing, checked, notApplicable}. `pcs` nil = the default postconditions.
    public static func checkPostconditions(_ vs: WalletVerb, _ o: JSONValue, _ effect: JSONValue?, _ pcs: [JSONValue]? = nil) throws -> JSONValue {
        let ctx: JSONValue = effectContext(vs, o, effect)
        var violated: [JSONValue] = []
        var checked: [JSONValue] = []
        var notApplicable: [JSONValue] = []
        var missing: [String] = []
        let verb: String? = o.get("verb")?.asString
        for pcv in (pcs ?? DEFAULT_POSTCONDITIONS) {
            if verb == nil || !IV.same(verb, pcv.get("verb")?.asString) { continue }
            guard let wh = pcv.get("where")?.asArray else { throw JSError("checkPostconditions: where is not a list") }
            var ls: [(field: String, ref: String?)] = []
            for c in wh { leaves(c, &ls) }
            if ls.contains(where: { l in
                guard let r = l.ref else { return false }
                return !IV.startsWith(r, "env.effect.") && !defined(ctx, r)
            }) {
                notApplicable.append(pcv.get("id") ?? JSONValue.null)
                continue
            }
            var need: [String] = []
            for l in ls {
                if IV.startsWith(l.field, "env.effect.") { need.append(l.field) }
                if let r = l.ref, !r.isEmpty, IV.startsWith(r, "env.effect.") { need.append(r) }
            }
            let lacking: [String] = need.filter { !defined(ctx, $0) }
            if !lacking.isEmpty { missing.append(contentsOf: lacking); continue }
            checked.append(pcv.get("id") ?? JSONValue.null)
            let pred: JSONValue = JSONValue.object([JKey("verb"): JSONValue.string(verb ?? ""), JKey("resource"): JSONValue.string("*"), JKey("where"): JSONValue.array(wh)])
            if !Predicates.evaluate(JSONValue.array([pred]), ctx) { violated.append(pcv.get("id") ?? JSONValue.null) }
        }
        var uniq: [String] = []
        for m in missing.sorted(by: { WJ.u16Less($0, $1) }) { if uniq.last.map({ !IV.same($0, m) }) ?? true { uniq.append(m) } }
        var rep: JObject = [:]
        rep[JKey("status")] = JSONValue.string(!violated.isEmpty ? "violated" : (!uniq.isEmpty ? "pending" : "ok"))
        rep[JKey("violated")] = JSONValue.array(violated)
        rep[JKey("missing")] = JSONValue.array(uniq.map { JSONValue.string($0) })
        rep[JKey("checked")] = JSONValue.array(checked)
        rep[JKey("notApplicable")] = JSONValue.array(notApplicable)
        return JSONValue.object(rep)
    }
}
