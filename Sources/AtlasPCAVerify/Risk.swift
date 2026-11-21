import Foundation

/// Risk functional, threshold map and decaying trust budget (spec section 10): a port of packages/pca/src/risk.ts. Pure and deterministic.
/// Time is epoch milliseconds; `lambda` is budget drained PER SECOND. Non-finite inputs fail closed (treated as the worst case).
public enum Risk {
    /// The order of the six normalized inputs (all in [0, 1]).
    public static let KEYS = ["semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"]
    /// The worst case per input: risk-increasing inputs 1, reversibility and confidence 0.
    public static let WORST: [Double] = [1, 0, 1, 1, 0, 1]

    static func clamp01(_ x: Double) -> Double { x < 0 ? 0 : (x > 1 ? 1 : x) }
    /// non-finite => worst; else clamp to [0, 1].
    static func unit(_ x: Double?, _ worst: Double) -> Double { x.flatMap { $0.isFinite ? clamp01($0) : nil } ?? worst }
    static func wt(_ x: Double?) -> Double { if let v = x, v.isFinite, v > 0 { return v }; return 0 }
    static func nz(_ x: Double) -> Double { x.isFinite && x > 0 ? x : 0 }

    /// r = clamp(a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1). `inputs` follows `KEYS`; `weights` is the policy's `weights` object.
    public static func riskScore(_ inputs: [Double?], weights w: JObject) -> Double {
        func wv(_ k: String) -> Double? { ToolSchema.fin(w[JKey(k)]) }
        func at(_ i: Int) -> Double? { i < inputs.count ? inputs[i] : nil }
        let r = wt(wv("alpha")) * unit(at(0), 1)
            + wt(wv("beta")) * (1 - unit(at(1), 0))
            + wt(wv("gamma")) * unit(at(2), 1)
            + wt(wv("delta")) * unit(at(3), 1)
            + wt(wv("epsilon")) * (1 - unit(at(4), 0))
            + wt(wv("zeta")) * unit(at(5), 1)
        return clamp01(r)
    }

    public struct Required: Equatable, Sendable {
        public var t: Int
        public var proof: String
        public var optimisticAllowed: Bool
        public init(t: Int, proof: String, optimisticAllowed: Bool) {
            self.t = t
            self.proof = proof
            self.optimisticAllowed = optimisticAllowed
        }
    }

    /// r <= theta1 -> t=1 (claim, optimistic ok unless irreversible); theta1 < r <= theta2 -> t=2 (standard); r > theta2 -> t=3 (strong). NaN r => worst.
    public static func requiredThreshold(_ r: Double, theta1: Double, theta2: Double, irreversible: Bool = false) -> Required {
        let x = r.isFinite ? r : 1
        if x <= theta1 { return Required(t: 1, proof: "claim", optimisticAllowed: !irreversible) }
        if x <= theta2 { return Required(t: 2, proof: "standard", optimisticAllowed: false) }
        return Required(t: 3, proof: "strong", optimisticAllowed: false)
    }

    static let PROOF_FOR_T = [1: "claim", 2: "standard", 3: "strong"]
    static let PROOF_RANK = ["claim": 0, "standard": 1, "strong": 2]

    /// Raise a requirement to at least `minT` and keep it coherent; never lowers anything.
    public static func escalate(_ rt: Required, minT: Int) -> Required {
        let t = max(rt.t, minT)
        let floor = PROOF_FOR_T[t] ?? "strong"
        let proof = (PROOF_RANK[rt.proof] ?? 2) >= (PROOF_RANK[floor] ?? 2) ? rt.proof : floor
        return Required(t: t, proof: proof, optimisticAllowed: t > 1 ? false : rt.optimisticAllowed)
    }

    // ---- trust budget ----

    public struct Budget: Equatable, Sendable {
        /// current budget in [0, bMax]
        public var b: Double
        /// last human-touch time (ms)
        public var tau: Double
        /// time (ms) the budget was last brought up to date by `leak`; defaults to tau
        public var asOf: Double?
        public init(b: Double, tau: Double, asOf: Double? = nil) {
            self.b = b
            self.tau = tau
            self.asOf = asOf
        }

        /// `{B, tau, asOf}`; nil unless B and tau are finite numbers.
        public init?(json: JSONValue?) {
            guard case let .object(o)? = json, let b = ToolSchema.fin(o[JKey("B")]), let tau = ToolSchema.fin(o[JKey("tau")]) else { return nil }
            self.b = b
            self.tau = tau
            self.asOf = ToolSchema.fin(o[JKey("asOf")])
        }

        public var json: JSONValue {
            var o: JObject = ["B": .double(b), "tau": .double(tau)]
            if let a = asOf { o["asOf"] = .double(a) }
            return .object(o)
        }
    }

    /// c(A) = kappa * r(A). Non-finite r => the cost of r = 1.
    public static func cost(_ r: Double, kappa: Double) -> Double { nz(kappa) * clamp01(r.isFinite ? r : 1) }

    /// Passive leak dB/dt = -lambda since the last update. Idempotent for repeated calls at the same `now`.
    public static func leak(_ b: Budget, now: Double, lambda: Double) -> Budget {
        let from = b.asOf ?? b.tau
        let dt = (now.isFinite && from.isFinite) ? max(0, now - from) : 0
        let nb = max(0, b.b - nz(lambda) * (dt / 1000))
        return Budget(b: nb, tau: b.tau, asOf: now.isFinite ? max(now, from) : from)
    }

    /// B <- max(0, B - cost). Callers must check B >= cost first (`admit` does).
    public static func debit(_ b: Budget, _ c: Double) -> Budget { Budget(b: max(0, b.b - nz(c)), tau: b.tau, asOf: b.asOf) }

    /// Normalized age since the last human touch: clamp((now - tau) / horizonMs, 0, 1).
    public static func ageSinceTouch(_ b: Budget, now: Double, horizonMs: Double = 3_600_000) -> Double {
        if !now.isFinite || !b.tau.isFinite || !(horizonMs > 0) { return 1 }
        return clamp01((now - b.tau) / horizonMs)
    }

    public struct Admission: Equatable, Sendable {
        /// t=1 auto path: no human, no co-signer needed.
        public var admit: Bool
        public var needStepUp: Bool
        public var t: Int
        /// The action proceeds WITHOUT a human co-signature (t=1 auto-admit, or t=2 where the guardian auto-cosigns) and so MUST be debited
        /// kappa * r. Only t=3 (a human step-up) is unmetered.
        public var metered: Bool
    }

    /// The machine-only band is t=1 AND t=2, so BOTH are metered: an action at t < 3 proceeds only if B >= c(A), and is then debited; when
    /// the budget cannot cover it the action escalates to t=3 (human step-up). `t` is the band of r (non-irreversible); `covers` is B >= c(A).
    public static func admit(t: Int, covers: Bool) -> Admission {
        if t < 3 && !covers { return Admission(admit: false, needStepUp: true, t: 3, metered: false) }
        if t == 1 { return Admission(admit: true, needStepUp: false, t: 1, metered: true) }
        if t == 2 { return Admission(admit: false, needStepUp: true, t: 2, metered: true) }
        return Admission(admit: false, needStepUp: true, t: 3, metered: false)
    }

    // ---- plan geodesic ----

    static let PRE_KEYS = ["after", "depends_on", "requires", "nodes"]
    static let POST_KEYS = ["before", "enables", "then", "next"]

    static func refsOf(_ x: JSONValue?, _ keys: [String]) -> [String] {
        var out: [String] = []
        func add(_ v: JSONValue?) {
            if case let .string(s)? = v { out.append(s) } else if case let .array(a)? = v { for e in a { if case let .string(s) = e { out.append(s) } } }
        }
        add(x)
        if case let .object(o)? = x { for k in keys { add(o[JKey(k)]) } }
        return out
    }

    /// Normalized geodesic distance in the committed plan DAG, in [0, 1] (an approximation, as documented in the reference): BFS hop count over
    /// the UNDIRECTED graph of node references divided by (n - 1); with no edges at all, index distance |i - j| / (n - 1); unknown node => 1.
    public static func planGeodesic(_ plan: [JSONValue], from fromId: String, to goalId: String) -> Double {
        var idx: [String: Int] = [:]
        for (i, n) in plan.enumerated() { if case let .string(id)? = n.get("id") { idx[id] = i } }
        guard let a = idx[fromId], let b = idx[goalId] else { return 1 }
        if a == b { return 0 }
        let n = plan.count
        var adj = [Set<Int>](repeating: [], count: n)
        var edges = 0
        func link(_ i: Int, _ j: Int) {
            if i == j { return }
            if !adj[i].contains(j) { edges += 1 }
            adj[i].insert(j)
            adj[j].insert(i)
        }
        for (i, node) in plan.enumerated() {
            for id in refsOf(node.get("pre"), PRE_KEYS) { if let j = idx[id] { link(j, i) } }
            for id in refsOf(node.get("post"), POST_KEYS) { if let j = idx[id] { link(i, j) } }
        }
        if edges == 0 { return clamp01(Double(abs(a - b)) / Double(n - 1)) }
        var dist = [Int](repeating: -1, count: n)
        dist[a] = 0
        var q = [a]
        var h = 0
        while h < q.count {
            let u = q[h]
            h += 1
            for v in adj[u].sorted() where dist[v] == -1 {
                dist[v] = dist[u] + 1
                q.append(v)
            }
        }
        return dist[b] < 0 ? 1 : clamp01(Double(dist[b]) / Double(n - 1))
    }
}
