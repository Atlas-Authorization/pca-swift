import Foundation

/// Checking an executed action's effect against its postconditions and feeding a violation back, and the Monte Carlo form of the
/// residual-risk estimate.
public enum PCAIntentOutcome {
    /// Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes the action's
    /// cell; ok and pending change nothing. `pcs` nil = the default postconditions. Returns {report, divergence?}.
    public static func verifyOutcome(_ l: PCAIntentLearner, _ o: JSONValue, _ effect: JSONValue?, _ pcs: [JSONValue]? = nil) throws -> JSONValue {
        let verb: String = o.get("verb")?.asString ?? "\u{0}"
        guard let vs = l.omega.verb(verb) else { throw JSError("verifyOutcome: no verb \(verb) in Omega") }
        let report: JSONValue = try PCAIntentEffects.checkPostconditions(vs, o, effect, pcs)
        var r: JObject = [:]
        r[JKey("report")] = report
        if let s = report.get("status")?.asString, IV.same(s, "violated") {
            r[JKey("divergence")] = try PCAIntentMap.applyDivergence(l, o, 0)
        }
        return JSONValue.object(r)
    }

    /// The Monte Carlo residual-risk estimate of the learner's grant over `samples` draws (default 20000) with the seeded generator (default 7).
    public static func estimateResidualRiskMC(_ l: PCAIntentLearner, _ samples: Int? = nil, _ seed: Double? = nil) throws -> Double {
        let m: Int = samples ?? 20000
        let rand: () -> Double = PCAIntentOmega.rng(seed ?? 7.0)
        let omega: PCAIntentOmega.Omega = PCAIntentLattice.omegaOf(l)
        let syn: JSONValue = l.synthesize()
        let grant: JSONValue = JSONValue.object([JKey("predicates"): syn.get("predicates") ?? JSONValue.array([]), JKey("caveats"): syn.get("caveats") ?? JSONValue.array([])])
        let g: PCAIntentPolicy.TypedAdmitter = try PCAIntentPolicy.typedAdmitter(grant)
        var r: Double = 0.0
        var i: Int = 0
        while i < m {
            let s: PCAIntentOmega.Sample = try PCAIntentOmega.sampleOutcome(omega, rand)
            if g.admits(s.vs, s.o) {
                r += (1 - l.acceptance(PCAIntentOmega.outcomeToJson(s.o))) * PCAIntentOmega.harmOf(s.vs, s.o, PCAIntentOmega.DEFAULT_HARM)
            }
            i += 1
        }
        return r / Double(m)
    }
}
