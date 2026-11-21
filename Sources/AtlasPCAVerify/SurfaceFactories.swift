import Foundation

// The reference's factory and fold functions of core pca, under their reference names (the classes behind them are `PCAExecutor` and `PlanRegistry`).
extension PCA {
    /// A check the intent-v2 pipeline reported: `reason` is nil for a failing check without a reason of its own.
    public struct V2Check: Equatable {
        public var name: String
        public var ok: Bool
        public var reason: String?
        public init(name: String, ok: Bool, reason: String? = nil) { self.name = name; self.ok = ok; self.reason = reason }
    }

    /// The ordered reason list of a verdict: the core's own reason(s), then one `<check>: <reason>` for EVERY failing check the intent-v2 pipeline reported that is not
    /// already listed (the core keeps only its first failure; the v2 checks are the escalate-class ones, so each failed one must be visible to the ternary decision). A
    /// failing check without a reason of its own contributes nothing (it is then read as a hard failure, never as an escalation). Duplicates are listed once, in the order
    /// first seen.
    public static func foldV2Reasons(_ base: [String], _ v2: [V2Check]) -> [String] {
        var out = base
        for c in v2 where !c.ok {
            guard let r = c.reason else { continue }
            let line = "\(c.name): \(r)"
            if !out.contains(where: { IV.same($0, line) }) { out.append(line) }
        }
        return out
    }

    /// Validate the wire form of a PCActn (with the intent, intent-session and fresh-at slots validated). nil when well-formed, else a short reason. Never traps.
    public static func validateWireV2(_ p: JSONValue?) -> String? { p.map { Wire.validate($0) } ?? "PCActn is not an object" }

    /// The at-most-once executor over `options` (the reference's `createExecutor`).
    public static func createExecutor(_ options: ExecutorOptions) -> PCAExecutor { PCAExecutor(options) }

    /// The plan registry over an atomic key/value store (the reference's `createPlanRegistry`; in memory by default, for ONE process).
    public static func createPlanRegistry(kv: AtomicKV = MemoryAtomicKV(), prefix: String = "pca-plan:", now: (() -> Int64)? = nil,
                                          validator: ((PlanRecord) throws -> PlanValidation)? = nil) -> PlanRegistry {
        PlanRegistry(kv: kv, prefix: prefix, now: now, validator: validator)
    }
}

extension PCA {
    /// The label a hook declares (the reference's `assuranceLabelOf`; `withAssuranceLabel` is its `setAssuranceLabel`), or nil for an unlabelled one.
    public static func assuranceLabelOf(_ hook: Any?) -> AssuranceLabel? { labelOf(hook) }

    /// Refresh a report after more checks were decided (the replay counter, default-deny of required checks): a check that is no longer `pass` loses its level, a new check
    /// is added, `unsupported` stays. `checks` is the (name, status) list in decision order.
    public static func refreshAssurance(_ report: AssuranceReport, _ checks: [(name: String, status: String)]) -> AssuranceReport {
        var r = report
        for (name, status) in checks {
            let was = r[name]
            if was?.outcome == "unsupported" { continue }
            if status != "pass" { r.set(name, CheckAssurance(outcome: status)) } else if was == nil || was?.outcome != "pass" { r.set(name, CheckAssurance(outcome: "pass")) }
        }
        return r
    }
}

extension PCA {
    /// The thresholds a risk-adaptive multi-signature may require (t of the agent, guardian and principal roles).
    public static let VALID_THRESHOLDS = [1, 2, 3]
    /// The share-binding version of the agent-leaf signature the guardian and principal shares bind to.
    public static let AGENT_LEAF_SHARE_BINDING_VERSION = "2.1"
}
