import Foundation

/// Measuring a grant against an intent over the outcome space: risk R(G) = E[1_G (1 - a) h], burden B(G) = E[1_notG a],
/// R_max = E[(1 - a) h], fidelity F = 1 - R / R_max, by Monte Carlo with the real evaluator on both sides or exactly by summing over cells.
public enum PCAIntentMetrics {
    /// The acceptability of an outcome in [0, 1].
    public typealias Acceptability = (PCAIntentOmega.VerbSpace, PCAIntentOmega.Outcome) -> Double

    public static func acceptabilityOf(_ policy: JSONValue?) throws -> Acceptability {
        let a: PCAIntentPolicy.TypedAdmitter = try PCAIntentPolicy.typedAdmitter(policy)
        return { (vs: PCAIntentOmega.VerbSpace, o: PCAIntentOmega.Outcome) -> Double in a.admits(vs, o) ? 1.0 : 0.0 }
    }

    public struct GrantMetrics {
        public var risk: Double
        public var burden: Double
        public var riskMax: Double
        public var fidelity: Double
        public var samples: Double
        public var riskHalfWidth: Double
        public var meanHarm: Double?

        public func toJson() -> JSONValue {
            var m: JObject = [:]
            m[JKey("risk")] = PCAIntentOmega.jn(risk)
            m[JKey("burden")] = PCAIntentOmega.jn(burden)
            m[JKey("riskMax")] = PCAIntentOmega.jn(riskMax)
            m[JKey("fidelity")] = PCAIntentOmega.jn(fidelity)
            if let mh = meanHarm {
                m[JKey("meanHarm")] = PCAIntentOmega.jn(mh)
            } else {
                m[JKey("samples")] = PCAIntentOmega.jn(samples)
                m[JKey("riskHalfWidth")] = PCAIntentOmega.jn(riskHalfWidth)
            }
            return JSONValue.object(m)
        }
    }

    /// Monte Carlo over the workload; `hMax` nil = the largest harm drawn.
    public static func measureGrant(_ omega: PCAIntentOmega.Omega, _ grant: JSONValue?, _ acceptability: Acceptability, _ samples: Double = 20000.0, _ seed: Double = 1.0,
                                    _ harm: PCAIntentHarmModel = PCAIntentOmega.DEFAULT_HARM, _ hMax: Double? = nil) throws -> GrantMetrics {
        let m: Double = samples
        let rand: () -> Double = PCAIntentOmega.rng(seed)
        let g: PCAIntentPolicy.TypedAdmitter = try PCAIntentPolicy.typedAdmitter(grant)
        var r: Double = 0.0
        var b: Double = 0.0
        var rm: Double = 0.0
        var hm: Double = 0.0
        var i: Double = 0.0
        while i < m {
            let s: PCAIntentOmega.Sample = try PCAIntentOmega.sampleOutcome(omega, rand)
            let a: Double = acceptability(s.vs, s.o)
            let h: Double = PCAIntentOmega.harmOf(s.vs, s.o, harm)
            hm = PCAIntentOmega.jmax(hm, h)
            if g.admits(s.vs, s.o) { r += (1 - a) * h } else { b += a }
            rm += (1 - a) * h
            i += 1
        }
        r /= m
        b /= m
        rm /= m
        return GrantMetrics(risk: r, burden: b, riskMax: rm, fidelity: rm > 0 ? 1 - r / rm : 1.0, samples: m,
                            riskHalfWidth: PCAIntentStats.hoeffdingHalfWidth(hMax ?? hm, m), meanHarm: nil)
    }

    /// Exact R, B, R_max, F by summing over the cells; valid when grant and acceptability are constant on each cell.
    public static func measureGrantExact(_ omega: PCAIntentOmega.Omega, _ grant: JSONValue?, _ acceptability: Acceptability,
                                         _ harm: PCAIntentHarmModel = PCAIntentOmega.DEFAULT_HARM) throws -> GrantMetrics {
        let g: PCAIntentPolicy.TypedAdmitter = try PCAIntentPolicy.typedAdmitter(grant)
        var r: Double = 0.0
        var b: Double = 0.0
        var rm: Double = 0.0
        var eh: Double = 0.0
        for vs in omega.verbs {
            let n: Double = PCAIntentOmega.verbCellCount(vs)
            var c: Double = 0.0
            while c < n {
                let idx: [Int] = PCAIntentOmega.decodeCell(vs, c)
                let o: PCAIntentOmega.Outcome = PCAIntentOmega.cellRep(vs, idx)
                let st: PCAIntentOmega.Stats = PCAIntentOmega.cellStats(vs, idx, harm)
                let a: Double = acceptability(vs, o)
                eh += st.mass * st.harm
                rm += st.mass * (1 - a) * st.harm
                if g.admits(vs, o) { r += st.mass * (1 - a) * st.harm } else { b += st.mass * a }
                c += 1
            }
        }
        return GrantMetrics(risk: r, burden: b, riskMax: rm, fidelity: rm > 0 ? 1 - r / rm : 1.0, samples: 0.0, riskHalfWidth: 0.0, meanHarm: eh)
    }
}
