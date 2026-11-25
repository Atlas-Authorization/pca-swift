import Foundation

/// The multi-agent budget algebra over trust budgets `{B, tau, asOf?}`: allocating a sub-agent's budget out of its parent's, consolidated debits (a
/// sub-agent's spend ALSO debits every ancestor, so a swarm can never collectively spend more than a node's allocation) and the full re-confirmation
/// recharge. Every refusal changes nothing and names the reason.
public enum PCARiskBudgets {
    /// A JS number as the wire carries it: an integer when it is one, `null` for NaN and the infinities (JSON.stringify).
    static func num(_ d: Double) -> JSONValue { d.isFinite ? PCAFacade.jsNum(d) : .null }

    /// `Math.min` (any NaN gives NaN).
    static func jsMin(_ a: Double, _ b: Double) -> Double { a.isNaN || b.isNaN ? .nan : Swift.min(a, b) }

    private static func no(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    private static func debit(_ b: JSONValue, _ x: Double) -> JSONValue {
        var o = b.asObject ?? [:]
        let cur = JS.toNumber(b.get("B"))
        let v = cur.isNaN ? Double.nan : Swift.max(0, cur - x)
        o[JKey("B")] = num(v)
        return .object(o)
    }

    /// Allocate a sub-agent budget `B_sub = alloc`, guarded by `0 <= alloc <= parent.B`: `{ok:true, sub}` or `{ok:false, reason}`.
    public static func subBudget(_ parent: JSONValue, alloc: Double) -> JSONValue {
        if !alloc.isFinite || alloc < 0 { return no("allocation must be finite and >= 0") }
        if !(JS.toNumber(parent.get("B")).isFinite && alloc <= JS.toNumber(parent.get("B"))) { return no("allocation exceeds parent remaining budget") }
        var sub: JObject = ["B": num(alloc)]
        if let t = parent.get("tau") { sub["tau"] = t }
        if let a = JS.present(parent.get("asOf")) ?? parent.get("tau") { sub["asOf"] = a }
        return .object(["ok": .bool(true), "sub": .object(sub)])
    }

    /// A sub-agent's debit ALSO debits the parent. Fails (no state change) if either cannot cover `c`: `{ok:true, parent, sub}` or `{ok:false, reason}`.
    public static func debitConsolidated(_ parent: JSONValue, _ sub: JSONValue, _ c: Double) -> JSONValue {
        let x = Risk.nz(c)
        if !(JS.toNumber(sub.get("B")).isFinite && JS.toNumber(sub.get("B")) >= x) { return no("sub-agent budget insufficient") }
        if !(JS.toNumber(parent.get("B")).isFinite && JS.toNumber(parent.get("B")) >= x) { return no("parent budget insufficient") }
        return .object(["ok": .bool(true), "parent": debit(parent, x), "sub": debit(sub, x)])
    }

    /// `debitConsolidated` along a root-to-leaf budget path of N levels: every node must cover `c`; if ANY cannot, nothing is debited and the first
    /// offender is named. `{ok:true, nodes}` or `{ok:false, reason}`.
    public static func debitConsolidatedPath(_ path: [JSONValue], _ c: Double) -> JSONValue {
        let x = Risk.nz(c)
        for (i, node) in path.enumerated() where !(JS.toNumber(node.get("B")) >= x) {
            return no("budget node at depth \(i) insufficient (need \(JS.number(x)), have \(JS.toString(node.get("B"))))")
        }
        return .object(["ok": .bool(true), "nodes": .array(path.map { debit($0, x) })])
    }

    /// Full goal re-confirmation: `B = bMax, tau = asOf = now`.
    public static func rechargeFull(bMax: Double, now: Double) -> JSONValue {
        .object(["B": num(Risk.nz(bMax)), "tau": num(now), "asOf": num(now)])
    }
}
