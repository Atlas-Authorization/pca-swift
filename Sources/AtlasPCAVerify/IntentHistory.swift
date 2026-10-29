import Foundation

/// Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and
/// monitors. The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from the
/// session's event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are pure: the
/// store, its lock and the reservation are the host's. Reference throws are `nil` results ("store corruption": fail closed).
enum IntentHistory {
    /// A reserved or committed event counts toward a cap (a reservation counts as soon as it is made).
    static func isCountedStatus(_ s: JSONValue?) -> Bool { IV.same(s?.asString, "reserved") || IV.same(s?.asString, "committed") }

    /// Does the counted event stamped `ti` still count at `t`? task: always; sliding(ms): (t-ms, t]; period(ms, t0): the period
    /// containing t; and every event stamped AFTER t. A time that is not a safe integer is in no window (fail closed).
    static func inWindow(_ win: JSONValue?, _ ti: JSONValue?, _ t: JSONValue?) -> Bool {
        guard let fi = IV.int(ti).map({ Double($0) }), let ft = IV.int(t).map({ Double($0) }) else { return false }
        if fi > ft { return true }
        switch win?.get("kind")?.asString {
        case "task"?: return true
        case "sliding"?: return fi > ft - (IV.num(win?.get("ms")) ?? .nan)
        case "period"?:
            let ms = IV.num(win?.get("ms")) ?? .nan, t0 = IV.num(win?.get("t0")) ?? .nan
            return ((fi - t0) / ms).rounded(.down) == ((ft - t0) / ms).rounded(.down)
        default: return false
        }
    }

    /// The canonical key of the grouping parameter, "•" when ungrouped, nil when the parameter is missing or not a string / safe integer.
    static func accKeyOf(_ a: JObject, _ params: JObject) -> String? {
        guard let k = a["key"]?.asString else { return "•" }
        guard let x = params[JKey(IV.dropPrefix(k, 14))] else { return nil }
        return IntentAcc.distinctKey(x)
    }

    static func emptyPre(_ agg: String) -> JSONValue {
        switch agg {
        case "sum": return .object(["sum": .int(0)])
        case "count": return .object(["count": .int(0)])
        case "max": return .object(["max": .int(0)])
        default: return .object(["values": .array([])])
        }
    }

    /// The pre-state of an accumulator for a candidate action. nil is the reference's throw: a past event's value or time is
    /// unreadable (store corruption), the candidate's key is missing, or a sum leaves the safe-integer range.
    static func accPreState(_ a: JObject, _ history: [JSONValue], _ candParams: JObject, _ candT: JSONValue?, _ schema: JSONValue?) -> JSONValue? {
        guard let key = accKeyOf(a, candParams), IV.int(candT) != nil else { return nil }
        let win = a["win"]
        var sum = 0.0, count = 0.0, mx = 0.0
        var vals: [String] = []
        for ev in history {
            let counted = isCountedStatus(ev.get("status"))
            if counted && IV.int(ev.get("t")) == nil { return nil }
            if !counted || !inWindow(win, ev.get("t"), candT) { continue }
            let verb = ev.get("verb")?.asString ?? ""
            if !IntentAcc.selects(a, verb, schema) { continue }
            let params = ev.get("params")?.asObject ?? [:]
            guard let ek = accKeyOf(a, params), IV.same(ek, key) else { continue }
            guard let v = IntentAcc.valueOf(a, verb, params, schema) else { return nil }
            sum += v.val
            count += 1
            mx = max(mx, v.val)
            if let k = v.key { vals.append(k) }
        }
        switch a["agg"]?.asString {
        case "sum"?: return IV.isSafeDouble(sum) ? .object(["sum": .double(sum)]) : nil
        case "count"?: return .object(["count": .double(count)])
        case "max"?: return .object(["max": .double(mx)])
        default:
            vals.sort { IV.utf8Less($0, $1) }
            var out: [JSONValue] = []
            for (i, v) in vals.enumerated() where i == 0 || !IV.same(v, vals[i - 1]) { out.append(.string(v)) }
            return .object(["values": .array(out)])
        }
    }

    /// post(ξ, ω, t): the pre-state combined with ω when ω is selected, else the pre-state's value. nil: throws.
    static func accPost(_ a: JObject, _ history: [JSONValue], _ verb: String, _ params: JObject, _ t: JSONValue?, _ schema: JSONValue?) -> Double? {
        let agg = a["agg"]?.asString ?? ""
        var pre: JSONValue?
        if a["key"]?.asString != nil && accKeyOf(a, params) == nil { pre = emptyPre(agg) }
        if pre == nil {
            guard let p = accPreState(a, history, params, t, schema) else { return nil }
            pre = p
        }
        guard let preState = pre else { return nil }
        if !IntentAcc.selects(a, verb, schema) { return IntentAcc.preValue(agg, preState) }
        guard let v = IntentAcc.valueOf(a, verb, params, schema) else { return nil }
        return IntentAcc.combine(agg, preState, v.val, v.key)
    }

    /// The start state of a monitor.
    static func monitorInitialState(_ m: JObject) -> String {
        switch m["kind"]?.asString {
        case "requires_prior"?, "precedes"?: return "unmet"
        case "never"?: return "clean"
        case "always"?: return "ok"
        default: return "idle"
        }
    }

    /// One monitor step on one event; statuses that do not count leave the state unchanged.
    static func monitorStep(_ m: JObject, _ q: String, _ e: JObject) -> String {
        let counts: Bool
        if IV.same(m["status"]?.asString, "committed") { counts = IV.same(e["status"]?.asString, "committed") } else { counts = isCountedStatus(e["status"]) }
        if !counts { return q }
        var action: JObject = [:]
        for k in ["verb", "resource", "params"] { if let x = e[JKey(k)] { action[JKey(k)] = x } }
        let ctx: JSONValue = .object(["action": .object(action)])
        func match(_ p: JSONValue?) -> Bool { p.map { Predicates.predicateMatches($0, ctx, SafeRegex.Budget()) } ?? false }
        switch m["kind"]?.asString {
        case "requires_prior"?, "precedes"?: return q == "met" || match(m["p"]) ? "met" : "unmet"
        case "never"?: return q == "seen" || match(m["p"]) ? "seen" : "clean"
        case "always"?: return q == "broken" || !match(m["p"]) ? "broken" : "ok"
        case "responds_within"?:
            if q == "missed" { return "missed" }
            let w = IV.num(m["within"]) ?? .nan
            var pending = 0.0
            var has = false
            if IV.startsWith(q, "pending:") {
                pending = Double(IV.dropPrefix(q, 8)) ?? .nan
                has = true
            }
            if has {
                if match(m["q"]) { has = false }
                else if pending - 1 <= 0 { return "missed" }
                else { pending -= 1 }
            }
            if match(m["p"]) {
                if !has { pending = w; has = true } else { pending = min(pending, w) }
            }
            return has ? "pending:" + Canonical.numberString(pending) : "idle"
        default: return q
        }
    }

    /// q(ξ): the fold of the monitor over the history (admission order, current statuses).
    static func monitorState(_ m: JObject, _ history: [JSONValue]) -> String {
        var q = monitorInitialState(m)
        for ev in history { q = monitorStep(m, q, ev.asObject ?? [:]) }
        return q
    }
}
