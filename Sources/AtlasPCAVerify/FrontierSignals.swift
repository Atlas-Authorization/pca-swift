import Foundation

/// Turns each intent-frontier result into a model signal that can only lower a decision (`ok` is neutral, `escalate` asks a human, `deny` refuses),
/// and tightens baseline risk inputs with the objective's. Total functions: anything that is not a result is `deny`. Results are the reference's
/// objects as JSON trees.
public enum PCAFrontierSignals {
    private static func record(_ v: JSONValue?) -> JSONValue? { v?.isObject == true ? v : nil }

    /// A semantic-threshold result: `ok` is `ok`, a refusal is `escalate`; a value that is no result (or whose `ok` is no boolean) is `deny`.
    public static func semanticSignal(_ result: JSONValue?) -> String {
        guard let r = record(result), case let .bool(ok)? = r.get("ok") else { return "deny" }
        return ok ? "ok" : "escalate"
    }

    /// A progress result: `ok` is `ok`; a refusal escalates only for the reasons `exploration-exhausted` and `budget-exceeded` (exact), else `deny`.
    public static func progressSignal(_ result: JSONValue?) -> String {
        guard let r = record(result), case let .bool(ok)? = r.get("ok") else { return "deny" }
        if ok { return "ok" }
        if case let .string(why)? = r.get("reason"), why == "exploration-exhausted" || why == "budget-exceeded" { return "escalate" }
        return "deny"
    }

    /// An objective-risk resolution: modes `none` and `objective` are `ok`; `mismatch` is `ok` only with `onMismatch` exactly `heuristic`.
    public static func objectiveSignal(_ res: JSONValue?) -> String {
        guard let r = record(res), case let .string(mode)? = r.get("mode") else { return "deny" }
        if mode == "none" || mode == "objective" { return "ok" }
        if mode == "mismatch" { return r.get("onMismatch") == .string("heuristic") ? "ok" : "deny" }
        return "deny"
    }

    /// `Math.min` / `Math.max`: a signed zero orders (-0 < 0).
    private static func jsMin(_ a: Double, _ b: Double) -> Double { a == 0 && b == 0 ? (a.sign == .minus ? a : b) : Swift.min(a, b) }
    private static func jsMax(_ a: Double, _ b: Double) -> Double { a == 0 && b == 0 ? (a.sign == .minus ? b : a) : Swift.max(a, b) }

    /// When baseline and objective reversibility and blast radius are ALL finite numbers: reversibility is the lower and blast radius the higher;
    /// otherwise BOTH are the worst case (0 and 1). The semantic distance is the objective's when a finite number, else 1. No clamping. A missing
    /// baseline or objective throws (the reference reads a property of it).
    public static func tightenRiskInputs(_ baseline: JSONValue?, _ objective: JSONValue?) throws -> JSONValue {
        guard let b = baseline, b != .null, let o = objective, o != .null else { throw JSError("Cannot read properties of null") }
        func fin(_ v: JSONValue?, _ k: String) -> Double? { ToolSchema.fin(v?.get(k)) }
        var rev = 0.0, blast = 1.0
        if let br = fin(b, "reversibility"), let or = fin(o, "reversibility"), let bb = fin(b, "blastRadius"), let ob = fin(o, "blastRadius") {
            rev = jsMin(br, or)
            blast = jsMax(bb, ob)
        }
        return .object(["reversibility": PCAFacade.jsNum(rev), "blastRadius": PCAFacade.jsNum(blast),
                        "semanticDistance": PCAFacade.jsNum(fin(o, "semanticDistance") ?? 1)])
    }
}
