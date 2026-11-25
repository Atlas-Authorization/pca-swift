import Foundation

/// Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction floor, and the
/// regret of a choice the grant admits (utility is the principal's, supplied by the caller). 
public enum PCAIntentProvenance {
    static let FRICTION_ORDER: [String] = ["tap", "hold", "typed", "device"]

    /// The fixed banner for a tainted value (web / agent / tool); nil for trusted and first-party values.
    public static func provenanceBanner(_ level: String?, _ what: String? = nil) -> String? {
        let w: String = what ?? "value"
        switch level {
        case "web"?: return "This \(w) was suggested by content on the page, not by you."
        case "agent"?: return "This \(w) came from your agent, not from you or the site."
        case "tool"?: return "This \(w) came from another service, not from you or this site."
        default: return nil
        }
    }

    /// True for the tainted levels (tool, web, agent).
    public static func isTainted(_ level: String?) -> Bool { return level == "tool" || level == "web" || level == "agent" }

    /// The friction a value needs: the maximum of `base` and the provenance floor (tainted critical: typed; tainted material: hold; else tap).
    public static func provenanceFriction(_ base: String?, _ sensitivity: String?, _ level: String?) -> String {
        let floor: String = !isTainted(level) ? "tap" : (sensitivity == "critical" ? "typed" : "hold")
        let bi: Int = base.flatMap { b in FRICTION_ORDER.firstIndex(of: b) } ?? -1
        let fi: Int = FRICTION_ORDER.firstIndex(of: floor) ?? 0
        return FRICTION_ORDER[max(bi, fi)]
    }

    /// One choice: the options feasible at the time, the chosen one, membership in the effective grant and the principal's utility.
    public struct RegretCase {
        public var feasible: [PCAIntentOmega.Outcome]
        public var chosen: PCAIntentOmega.Outcome
        public var admits: (PCAIntentOmega.Outcome) -> Bool
        public var utility: (PCAIntentOmega.Outcome) -> Double
        public init(_ feasible: [PCAIntentOmega.Outcome], _ chosen: PCAIntentOmega.Outcome, _ admits: @escaping (PCAIntentOmega.Outcome) -> Bool, _ utility: @escaping (PCAIntentOmega.Outcome) -> Double) {
            self.feasible = feasible; self.chosen = chosen; self.admits = admits; self.utility = utility
        }
    }

    /// Within-grant regret of one choice: {regret, best, admitted}. Only options inside the grant compete.
    public static func withinGrantRegret(_ c: RegretCase) -> JSONValue {
        let admitted: Bool = c.admits(c.chosen)
        var best: PCAIntentOmega.Outcome? = nil
        var bestU: Double = -Double.infinity
        for o in c.feasible {
            if !c.admits(o) { continue }
            let u: Double = c.utility(o)
            if u > bestU { bestU = u; best = o }
        }
        var regret: Double = 0.0
        if admitted, best != nil {
            let d: Double = bestU - c.utility(c.chosen)
            // Math.max(0, d): NaN stays NaN
            regret = d.isNaN ? Double.nan : (d > 0 ? d : 0.0)
        }
        var r: JObject = [:]
        r[JKey("regret")] = WJ.plain(JSONValue.double(regret))
        r[JKey("best")] = best.map { PCAIntentOmega.outcomeToJson($0) } ?? JSONValue.null
        r[JKey("admitted")] = JSONValue.bool(admitted)
        return JSONValue.object(r)
    }

    /// Aggregate regret over choices: {cases, admitted, positive, mean, max, regret_est_ppm} (ppm of the utility scale `scale`).
    public static func regretReport(_ cases: [RegretCase], _ scale: Double = 1.0) -> JSONValue {
        var admitted: Int = 0
        var positive: Int = 0
        var sum: Double = 0.0
        var mx: Double = 0.0
        for c in cases {
            let r: JSONValue = withinGrantRegret(c)
            guard case .bool(true)? = r.get("admitted") else { continue }
            admitted += 1
            let reg: Double = IV.num(r.get("regret")) ?? Double.nan
            sum += reg
            if reg > 0 { positive += 1 }
            if reg > mx { mx = reg }
        }
        let mean: Double = admitted > 0 ? sum / Double(admitted) : 0.0
        var o: JObject = [:]
        o[JKey("cases")] = WJ.plain(JSONValue.double(Double(cases.count)))
        o[JKey("admitted")] = WJ.plain(JSONValue.double(Double(admitted)))
        o[JKey("positive")] = WJ.plain(JSONValue.double(Double(positive)))
        o[JKey("mean")] = WJ.plain(JSONValue.double(mean))
        o[JKey("max")] = WJ.plain(JSONValue.double(mx))
        o[JKey("regret_est_ppm")] = WJ.plain(JSONValue.double(WJ.jsRound((mean / (scale > 0 ? scale : 1.0)) * 1_000_000)))
        return JSONValue.object(o)
    }
}
