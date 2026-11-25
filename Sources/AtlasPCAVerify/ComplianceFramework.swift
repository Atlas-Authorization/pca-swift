import Foundation

/// The control-status report over a console activity stream: EU AI Act, SOC 2 or GDPR controls mapped from the policy, the activity events
/// and the approval decisions. An evidence mapping, not a certification. Same JS value semantics as `PCACompliance`; a non-finite number
/// is `null` in the produced JSON.
extension PCACompliance {
    static let frameworkReportIds = ["eu-ai-act", "soc2", "gdpr"]

    struct FrameworkSummary {
        var totalActions = 0, autonomous = 0, humanOverseen = 0, denied = 0, attributableAgents = 0
        var autonomousBound = 0.0, maxTaintObserved = 0.0
    }

    static func numS(_ d: Double) -> String { JS.toString(.double(d)) }

    static func baseSummary(_ input: JSONValue?) throws -> (FrameworkSummary, [JSONValue], JSONValue) {
        let eventsRaw = try P.prop(input, "events")
        let riskPolicy = try P.prop(try P.prop(input, "policy"), "riskPolicy")
        guard case let .array(e)? = eventsRaw else { throw JSError("e.filter is not a function") }
        var s = FrameworkSummary()
        s.totalActions = e.count
        var uid = 0
        var agents = Set<String>()
        var step = 0
        var taint = 0.0
        var ats: [Double] = []
        for x in e {
            let outcome = try P.prop(x, "outcome")
            if outcome == .string("auto") || outcome == .string("executed") { s.autonomous += 1 }
            if outcome == .string("step_up") { step += 1 }
            if outcome == .string("deny") { s.denied += 1 }
            agents.insert(setKey(try P.prop(x, "agent"), &uid))
            let tv = try P.prop(x, "taint")
            let tn: Double = tv == nil ? 0 : (finiteOf(tv) ?? .infinity)
            taint = P.jsMax(taint, tn)
            if let a = finiteOf(try P.prop(x, "at")) { ats.append(a) }
        }
        var decisions = 0
        let dv = try P.prop(input, "decisions")
        if dv != nil, dv != .null, let l = try P.length(dv), let n = numberOf(l), n.isFinite, abs(n) < 1e9 { decisions = Int(n) }
        s.humanOverseen = step + decisions
        s.attributableAgents = agents.count
        // safetyBound(p) * p.kappa
        let kappa = P.toNumber(try P.prop(riskPolicy, "kappa"))
        let bound = kappa > 0 ? P.jsMax(0, P.toNumber(try P.prop(riskPolicy, "bMax"))) / kappa : 0
        s.autonomousBound = bound * kappa
        s.maxTaintObserved = taint
        let period: JSONValue = .object(["from": numJSON(ats.min() ?? 0), "to": numJSON(ats.max() ?? 0)])
        return (s, e, period)
    }

    static func ctl(_ id: String, _ name: String, _ ok: Bool, fail: Bool = false, _ evidence: String) -> JSONValue {
        .object(["id": .string(id), "name": .string(name), "status": .string(ok ? "pass" : (fail ? "fail" : "warn")), "evidence": .string(evidence)])
    }

    static func frameworkControls(_ fw: String, _ input: JSONValue?, _ s: FrameworkSummary) throws -> [JSONValue] {
        switch fw {
        case "eu-ai-act":
            let goal = JS.truthy(try P.prop(input, "hasGoalCommitment"))
            let oversight = s.humanOverseen > 0 || s.autonomousBound.isFinite
            return [
                ctl("art12-record-keeping", "Automatic logging of events", s.totalActions > 0, "\(s.totalActions) attributable actions recorded"),
                ctl("art14-human-oversight", "Human oversight", oversight, "\(s.humanOverseen) human-reviewed actions; autonomous bound \(numS(s.autonomousBound))"),
                ctl("art15-robustness", "Bounded autonomy (accuracy/robustness)", s.autonomousBound.isFinite, fail: true, "machine-checked safety bound = \(numS(s.autonomousBound)) between human co-signs"),
                ctl("art13-transparency", "Transparency / traceability", goal, goal ? "every action binds to a signed goal commitment (lineage)" : "no goal commitment supplied"),
            ]
        case "soc2":
            var constrained = false
            if case let .array(p)? = try P.optprop(try P.prop(input, "policy"), "predicates"), !p.isEmpty { constrained = true }
            return [
                ctl("cc6.1-access", "Logical access \u{2014} least privilege", constrained,
                    constrained ? "actions constrained by signed predicates + capability attenuation (deny by default)" : "the supplied policy lists no predicates"),
                ctl("cc7.2-monitoring", "Monitoring of anomalies", s.totalActions > 0, "\(s.denied) denied + \(s.humanOverseen) escalated actions captured"),
                ctl("cc7.3-audit-trail", "Audit trail", s.totalActions > 0, "\(s.totalActions) content-addressed actions across \(s.attributableAgents) agents"),
                ctl("cc8.1-change", "Change management (policy integrity)", constrained,
                    constrained ? "policy is signed into the grant; tampering breaks verification" : "the supplied policy lists no predicates"),
            ]
        default:
            let goal = JS.truthy(try P.prop(input, "hasGoalCommitment"))
            let erasure = JS.truthy(try P.prop(input, "erasureSupported"))
            return [
                ctl("art5-purpose", "Purpose limitation", goal, goal ? "actions bound to a committed goal/purpose" : "no goal commitment supplied"),
                ctl("art5-minimization", "Data minimisation", s.totalActions > 0, "taint-gated data flows; max taint observed = \(numS(s.maxTaintObserved))"),
                ctl("art5-accountability", "Accountability", s.attributableAgents > 0, "\(s.attributableAgents) attributable agent identities"),
                ctl("art17-erasure", "Right to erasure", erasure, erasure ? "erasure path wired" : "erasure path not asserted"),
            ]
        }
    }

    /// The evidence report for a framework (`eu-ai-act`, `soc2`, `gdpr`) from `{policy, events, decisions?, hasGoalCommitment?, erasureSupported?}`.
    /// `now` (epoch ms, kept as given) defaults to the clock. A malformed input or an unknown framework is refused.
    public static func frameworkReport(_ framework: JSONValue?, _ input: JSONValue?, _ now: JSONValue? = nil) throws -> JSONValue {
        let (s, _, period) = try baseSummary(input)
        let key = t(framework)
        guard frameworkReportIds.contains(key) else {
            throw JSError("frameworkReport: unknown framework '\(key)' (have: \(frameworkReportIds.joined(separator: ", ")))")
        }
        let controls = try frameworkControls(key, input, s)
        let pass = !controls.contains { $0.get("status") == .string("fail") }
        let summary: JSONValue = .object([
            "totalActions": .int(Int64(s.totalActions)), "autonomous": .int(Int64(s.autonomous)), "humanOverseen": .int(Int64(s.humanOverseen)),
            "denied": .int(Int64(s.denied)), "attributableAgents": .int(Int64(s.attributableAgents)),
            "autonomousBound": numJSON(s.autonomousBound), "maxTaintObserved": numJSON(s.maxTaintObserved),
        ])
        return .object(["framework": framework ?? .null, "generatedAt": now ?? nowMs(), "period": period, "summary": summary,
                        "controls": .array(controls), "pass": .bool(pass)])
    }

    /// `new Date(x).toISOString()` for the values a report's `generatedAt` takes; a date string is refused (not parsed).
    static func isoOfDate(_ v: JSONValue?) throws -> String {
        let ms: Double
        switch v {
        case .null?: ms = 0
        case let .bool(b)?: ms = b ? 1 : 0
        case .int?, .double?: ms = numberOf(v)!
        default: throw JSError("Invalid time value")
        }
        guard let s = PCASiem.isoString(ms) else { throw JSError("Invalid time value") }
        return s
    }

    /// A short Markdown block (for an audit package) for a framework report.
    public static func frameworkReportToMarkdown(_ report: JSONValue?) throws -> String {
        let r = report
        var lines: [String] = []
        lines.append("# PCA compliance evidence \u{2014} \(t(try P.prop(r, "framework")))")
        lines.append("")
        let summary = try P.prop(r, "summary")
        let when = try isoOfDate(try P.prop(r, "generatedAt"))
        lines.append("Generated \(when) \u{00B7} \(t(try P.prop(summary, "totalActions"))) actions \u{00B7} \(t(try P.prop(summary, "attributableAgents"))) agents \u{00B7} overall: \(JS.truthy(try P.prop(r, "pass")) ? "PASS" : "FAIL")")
        lines.append("")
        lines.append("| Control | Status | Evidence |")
        lines.append("| --- | --- | --- |")
        guard case let .array(controls)? = try P.prop(r, "controls") else { throw JSError("r.controls.map is not a function") }
        for c in controls {
            let status = try upper(try P.prop(c, "status"))
            lines.append("| \(t(try P.prop(c, "name"))) (\(t(try P.prop(c, "id")))) | \(status) | \(t(try P.prop(c, "evidence"))) |")
        }
        lines.append("")
        lines.append("_Evidence mapping, not a legal certification._")
        return lines.joined(separator: "\n")
    }
}
