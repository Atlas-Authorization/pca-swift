import Foundation

/// The behavioral immune system: authorization that gets more paranoid when something is off. It learns a principal's normal risk
/// distribution from the stream of its agents' actions, detects drift, volatility and violation bursts, and under suspicion PROPOSES a tightened
/// risk policy (a lower theta so more actions need a human, a higher kappa so each costs more budget). It never mutates a signed grant, the
/// adaptation is a pure, reversible function of the current threat score, and it can only ever make authorization stricter (kappa' >= kappa,
/// theta' <= theta, everything else equal). The anomaly score is a heuristic (an EWMA and a z-score over one principal's history): a slow
/// attacker can drift the baseline, and it proves nothing about whether an agent is compromised. The signed tightening proposals and the durable
/// immune store are in ImmuneProposals.swift.
public enum PCAImmune {
    /// Welford running mean and variance.
    public struct Baseline: Equatable {
        public var n: Double = 0
        public var mean: Double = 0
        /// Sum of squared deviations.
        public var m2: Double = 0
    }

    public struct Config: Equatable {
        /// EWMA smoothing of the recent signal (0 < alpha <= 1).
        public var alpha = 0.3
        /// Half-life (ms) of the recent step-up / deny counters.
        public var halfLifeMs = 3_600_000.0
        /// z-score at which drift saturates.
        public var driftZSat = 3.0
        /// Decayed step-up count at which volatility saturates.
        public var stepUpSat = 5.0
        /// Decayed deny count at which the violation signal saturates.
        public var denySat = 3.0
        public init() {}
        public static let `default` = Config()
    }

    public struct State: Equatable {
        public var baseline = Baseline()
        /// EWMA of recent risk.
        public var ewma = 0.0
        /// Decayed count of recent step-ups.
        public var stepUps = 0.0
        /// Decayed count of recent denies.
        public var denies = 0.0
        public var lastAt = 0.0
        public var seeded = false
        public init() {}
    }

    public static let INITIAL_STATE = State()

    static func clamp01(_ x: Double) -> Double { x < 0 ? 0 : (x > 1 ? 1 : x) }

    public static func updateBaseline(_ b: Baseline, _ r: Double) -> Baseline {
        let x = r.isFinite ? r : 0
        let n = b.n + 1
        let delta = x - b.mean
        let mean = b.mean + delta / n
        return Baseline(n: n, mean: mean, m2: b.m2 + delta * (x - mean))
    }

    /// Population standard deviation (0 until two samples).
    public static func baselineStd(_ b: Baseline) -> Double { b.n >= 2 ? (b.m2 / b.n).squareRoot() : 0 }

    static func decay(_ count: Double, _ dtMs: Double, _ halfLifeMs: Double) -> Double {
        if dtMs <= 0 || count == 0 { return count }
        return count * pow(0.5, dtMs / halfLifeMs)
    }

    /// Fold one observation into the state. A non-finite timestamp is pinned to the last good one, so it can never poison the state.
    public static func observe(_ state: State, r: Double, at: Double, stepUp: Bool = false, denied: Bool = false, cfg: Config = .default) -> State {
        let rr = clamp01(r.isFinite ? r : 0)
        let t = at.isFinite ? at : state.lastAt
        let dt = state.seeded ? max(0, t - state.lastAt) : 0
        var s = State()
        s.baseline = updateBaseline(state.baseline, rr)
        s.ewma = state.seeded ? cfg.alpha * rr + (1 - cfg.alpha) * state.ewma : rr
        s.stepUps = decay(state.stepUps, dt, cfg.halfLifeMs) + (stepUp ? 1 : 0)
        s.denies = decay(state.denies, dt, cfg.halfLifeMs) + (denied ? 1 : 0)
        s.lastAt = t
        s.seeded = true
        return s
    }

    static let MAX_COUNT = 1e9

    /// Why the state is malformed (non-finite, negative, out of bound), nil when it is well formed.
    public static func validate(_ s: State) -> String? {
        func inRange(_ x: Double, _ lo: Double, _ hi: Double) -> Bool { x.isFinite && x >= lo && x <= hi }
        if !inRange(s.baseline.n, 0, MAX_COUNT) || s.baseline.n.rounded() != s.baseline.n || (s.baseline.n == 0 && s.baseline.n.sign == .minus) { return "baseline.n must be an integer in [0, 1e9]" }
        if !inRange(s.baseline.mean, 0, 1) { return "baseline.mean must be in [0, 1]" }
        if !inRange(s.baseline.m2, 0, MAX_COUNT) { return "baseline.m2 must be finite and >= 0" }
        if !inRange(s.ewma, 0, 1) { return "ewma must be in [0, 1]" }
        if !inRange(s.stepUps, 0, MAX_COUNT) { return "stepUps must be finite and >= 0" }
        if !inRange(s.denies, 0, MAX_COUNT) { return "denies must be finite and >= 0" }
        if !inRange(s.lastAt, 0, Double(Canonical.MAX_SAFE)) { return "lastAt must be a finite non-negative time" }
        return nil
    }

    public struct Assessment: Equatable {
        /// "calm", "elevated" or "high".
        public var level: String
        public var score: Double
        public var signals: [String]
        public var drift: Double
        public var volatility: Double
        public var violation: Double
    }

    /// `x.toFixed(d)`: the exact decimal expansion rounded half up (a tie takes the larger value).
    static func toFixed(_ x: Double, _ d: Int) -> String {
        if !x.isFinite || abs(x) >= 1e21 { return JS.toString(.double(x)) }
        let neg = x < 0
        let full = String(format: "%.\(d + 60)f", abs(x))
        let parts = full.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var digits = Array(parts[0]) + Array(parts[1].prefix(d))
        let next = parts[1].dropFirst(d).first ?? "0"
        if next >= "5" {
            var i = digits.count - 1
            while i >= 0 {
                if digits[i] == "9" { digits[i] = "0"; i -= 1 } else { digits[i] = Character(UnicodeScalar(digits[i].unicodeScalars.first!.value + 1)!); break }
            }
            if i < 0 { digits.insert("1", at: 0) }
        }
        let ip = digits.count - d
        let text = d == 0 ? String(digits) : String(digits[..<ip]) + "." + String(digits[ip...])
        return (neg ? "-" : "") + text
    }

    /// Assess the current threat: drift (recent mean risk above the baseline, in std units), volatility (the decayed step-up count) and
    /// violation (the decayed deny count); the score is the largest of the three, the level thresholds 0.33 and 0.66. A malformed state is `high`.
    public static func assess(_ state: State, _ cfg: Config = .default) -> Assessment {
        if let bad = validate(state) {
            return Assessment(level: "high", score: 1, signals: ["invalid immune state: \(bad)"], drift: 1, volatility: 1, violation: 1)
        }
        let std = baselineStd(state.baseline)
        var signals: [String] = []
        var drift = 0.0
        if state.baseline.n >= 5 && std > 1e-9 {
            let z = (state.ewma - state.baseline.mean) / std
            drift = clamp01(z / cfg.driftZSat)
            if drift > 0.33 { signals.append("risk drifted \(toFixed(z, 1))\u{3c3} above baseline") }
        }
        let volatility = clamp01(state.stepUps / cfg.stepUpSat)
        if volatility > 0.33 { signals.append("elevated step-up rate (\(toFixed(state.stepUps, 1)))") }
        let violation = clamp01(state.denies / cfg.denySat)
        if violation > 0.33 { signals.append("repeated policy violations (\(toFixed(state.denies, 1)))") }
        let score = max(drift, volatility, violation)
        return Assessment(level: score >= 0.66 ? "high" : score >= 0.33 ? "elevated" : "calm", score: score, signals: signals, drift: drift, volatility: volatility, violation: violation)
    }

    public struct AdaptConfig: Equatable {
        /// The most kappa is raised to at score 1.
        public var maxKappaMult = 3.0
        /// The least theta is lowered to at score 1 (0 < x <= 1).
        public var minThetaMult = 0.4
        public init() {}
        public static let `default` = AdaptConfig()
    }

    public struct Adaptation {
        public var policy: JObject
        public var changed: Bool
        public var rationale: String
    }

    /// Why `adapted` is looser than `base` (kappa' >= kappa, theta' <= theta, the rest identical), nil when it only tightens.
    public static func noWidenViolation(_ base: JObject, _ adapted: JObject) -> String? {
        func n(_ p: JObject, _ k: String) -> Double? { IV.num(p[JKey(k)]) }
        guard let bk = n(base, "kappa"), let ak = n(adapted, "kappa"), ak >= bk else { return "kappa decreased" }
        guard let b1 = n(base, "theta1"), let a1 = n(adapted, "theta1"), a1 <= b1 else { return "theta1 increased" }
        guard let b2 = n(base, "theta2"), let a2 = n(adapted, "theta2"), a2 <= b2 else { return "theta2 increased" }
        for k in ["lambda", "rho", "bMax"] where n(adapted, k) != n(base, k) { return "\(k) changed" }
        let bw = base[JKey("weights")]?.asObject ?? [:], aw = adapted[JKey("weights")]?.asObject ?? [:]
        for k in bw.keys where IV.num(aw[k]) != IV.num(bw[k]) { return "weights.\(k.s) changed" }
        return nil
    }

    /// The adapted policy, derived FROM the base (never compounded) and the threat score: score 0 gives the base unchanged, higher scores raise
    /// kappa toward `maxKappaMult` times and lower theta toward `minThetaMult` times. A non-finite score is the worst case; the result is re-validated.
    public static func adapt(_ base: JObject, _ a: Assessment, _ cfg: AdaptConfig = .default) -> Adaptation {
        let s = a.score.isFinite ? clamp01(a.score) : 1
        if s == 0 { return Adaptation(policy: base, changed: false, rationale: "calm \u{2014} baseline policy") }
        let kappaMult = 1 + (cfg.maxKappaMult - 1) * s
        let thetaMult = 1 - (1 - cfg.minThetaMult) * s
        func num(_ k: String) -> Double { IV.num(base[JKey(k)]) ?? .nan }
        var p = base
        // `weights: { ...base.weights }`: a copy of an object's members, and an empty object where there is nothing to spread (absent, null, a number)
        switch base["weights"] {
        case let .object(w)?: p["weights"] = .object(w)
        case let .array(xs)?: var m = JObject(); for (i, x) in xs.enumerated() { m[JKey(String(i))] = x }; p["weights"] = .object(m)
        case let .string(t)?: var m = JObject(); for (i, c) in t.utf16.enumerated() { m[JKey(String(i))] = .string(String(utf16CodeUnits: [c], count: 1)) }; p["weights"] = .object(m)
        default: p["weights"] = .object([:])
        }
        p["kappa"] = PCAFacade.jsNum(num("kappa") * kappaMult)
        p["theta1"] = PCAFacade.jsNum(clamp01(num("theta1") * thetaMult))
        p["theta2"] = PCAFacade.jsNum(clamp01(num("theta2") * thetaMult))
        if let bad = PCA.validateRiskPolicy(.object(p)) ?? noWidenViolation(base, p) {
            return Adaptation(policy: base, changed: false, rationale: "adaptation rejected (\(bad)) \u{2014} kept baseline")
        }
        let why = a.signals.isEmpty ? "threat score \(toFixed(s, 2))" : a.signals.joined(separator: "; ")
        return Adaptation(policy: p, changed: true, rationale: "\(a.level): \(why) \u{2192} \u{3ba} \u{d7}\(toFixed(kappaMult, 2)), \u{3b8} \u{d7}\(toFixed(thetaMult, 2))")
    }
}
