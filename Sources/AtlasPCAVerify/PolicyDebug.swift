import Foundation

/// The replayable policy debugger (the reference's `policy-debug`): `explainRisk` decomposes the risk score into its six weighted terms,
/// `explainDecision` explains a `decide` input by re-running `decide` (never a re-implementation of its arithmetic), `applyDelta` and
/// `counterfactual` re-run the core under single edits and report which edits flip the outcome, `auditPCActn` re-verifies a PCActn and
/// attaches the explanation. Arguments and results are the reference's objects as JSON trees; a non-finite number stays a `.double`.
/// NOTE: this `explainDecision` explains the Policy VM's `decide`; it is not `PCAExplain.explainDecision` (the verification explainer).
public enum PCAPolicyDebug {
    private static let TERMS: [(name: String, weight: String, inverted: Bool)] = [
        ("semanticDistance", "alpha", false), ("reversibility", "beta", true), ("blastRadius", "gamma", false),
        ("taint", "delta", false), ("confidence", "epsilon", true), ("age", "zeta", false),
    ]

    private static func num(_ d: Double) -> JSONValue { d.isFinite ? PCAFacade.jsNum(d) : .double(d) }
    private static func jsMax(_ a: Double, _ b: Double) -> Double { a.isNaN || b.isNaN ? .nan : Swift.max(a, b) }
    private static func jsMin(_ a: Double, _ b: Double) -> Double { a.isNaN || b.isNaN ? .nan : Swift.min(a, b) }
    private static func fin(_ v: JSONValue?) -> Double? { ToolSchema.fin(v) }

    /// Decompose `riskScore(inputs, weights)` into its six additive terms; `r = max(clamp(rawSum), clamp(rFloor))`.
    public static func explainRisk(_ inputs: JSONValue, _ weights: JSONValue, _ rFloorIn: JSONValue? = nil) -> JSONValue {
        let rFloor = fin(rFloorIn) ?? 0
        var terms: [JSONValue] = []
        var rawSum = 0.0
        for (i, t) in TERMS.enumerated() {
            let w = Risk.wt(fin(weights.get(t.weight)))
            let input = fin(inputs.get(t.name)).map { Risk.clamp01($0) } ?? Risk.WORST[i]
            let effective = t.inverted ? 1 - input : input
            let contribution = w * effective
            rawSum += contribution
            terms.append(.object(["term": .string(t.name), "weight": num(w), "input": num(input), "effective": num(effective),
                                  "contribution": num(contribution), "inverted": .bool(t.inverted)]))
        }
        let rScore = Risk.clamp01(rawSum)
        let r = Swift.max(rScore, Risk.clamp01(rFloor))
        return .object(["inputs": inputs, "weights": weights, "terms": .array(terms), "rawSum": num(rawSum), "rScore": num(rScore),
                        "rFloor": num(Risk.clamp01(rFloor)), "r": num(r)])
    }

    /// The risk policy of the grant's envelope, else the default policy.
    private static func policyOf(_ env: JSONValue?) -> JSONValue {
        env?.get("risk_policy") ?? .object(PCAFacade.DEFAULT_RISK_POLICY)
    }

    /// `leak(budget, now, lambda)` over the reference's budget object (a member that is not a number reads as NaN).
    private static func leak(_ b: JSONValue?, now: JSONValue?, lambda: Double) -> JSONValue {
        let from: JSONValue? = JS.present(b?.get("asOf")) ?? b?.get("tau")
        let nowF = fin(now), fromF = fin(from)
        // a clock or a budget stamp that is not a finite number fails closed: depleted, the stamps untouched
        guard let nowN = nowF, let fromN = fromF else {
            var o: JObject = ["B": .int(0)]
            if let t = b?.get("tau") { o["tau"] = t }
            if let a = b?.get("asOf") { o["asOf"] = a }
            return .object(o)
        }
        let dt = Swift.max(0, nowN - fromN)
        let nb = jsMax(0, JS.toNumber(b?.get("B")) - Risk.nz(lambda) * (dt / 1000))
        var o: JObject = ["B": num(nb)]
        if let t = b?.get("tau") { o["tau"] = t }
        o["asOf"] = num(jsMax(nowN, fromN))
        return .object(o)
    }

    /// The risk inputs and floor exactly as `decide` resolves them (fail-closed fill, plan geodesic for a missing distance, age from the budget).
    private static func resolveRisk(_ input: JSONValue, _ env: JSONValue) -> (inputs: JSONValue, rFloor: Double, leaked: JSONValue) {
        let pol = env.get("risk_policy")
        let leaked = leak(input.get("budget"), now: input.get("now"), lambda: JS.toNumber(pol?.get("lambda")))
        let riskObj = input.get("risk")?.asObject
        var vals = Risk.WORST
        for (i, t) in TERMS.enumerated() { if let v = fin(riskObj?[JKey(t.name)]) { vals[i] = v } }
        let plan = input.get("plan")
        if JS.truthy(plan) && riskObj?["semanticDistance"] == nil {
            var goal = JS.present(input.get("goalNodeId"))
            if goal == nil, case let .array(pa)? = plan { goal = JS.present(pa.last?.get("id")) }
            if case let .string(a)? = input.get("nodeId"), case let .string(g)? = goal, case let .array(pa)? = plan {
                vals[0] = Risk.planGeodesic(pa, from: a, to: g)
            } else { vals[0] = 1 }
        }
        if riskObj?["age"] == nil {
            let hv = input.get("ageHorizonMs")
            let horizon: Double = hv == nil ? 3_600_000 : (fin(hv) ?? .nan)
            let tau = fin(leaked.get("tau")), nowF = fin(input.get("now"))
            vals[5] = (nowF == nil || tau == nil || !(horizon > 0)) ? 1 : Risk.clamp01((nowF! - tau!) / horizon)
        }
        var rFloor = 0.0
        if let rf = fin(input.get("rFloor")) { rFloor = Swift.min(1, Swift.max(0, rf)) }
        var io = JObject()
        for (i, t) in TERMS.enumerated() { io[JKey(t.name)] = num(vals[i]) }
        return (.object(io), rFloor, leaked)
    }

    /// Replay `decide(input)` and decompose it: the risk and its terms, the required threshold, the leak / debit budget trajectory.
    public static func explainDecision(_ input: JSONValue) throws -> JSONValue {
        let decision = try PCAPolicyVm.decide(input)
        let env = PCA.readEnvelope(input.get("grant") ?? .null)
        let pol = policyOf(env)
        let risk: JSONValue
        let leaked: JSONValue?
        if let env = env {
            let r = resolveRisk(input, env)
            leaked = r.leaked
            risk = explainRisk(r.inputs, pol.get("weights") ?? .null, num(r.rFloor))
        } else {
            leaked = input.get("budget")
            var worst = JObject()
            for (i, t) in TERMS.enumerated() { worst[JKey(t.name)] = num(Risk.WORST[i]) }
            let zero: JObject = ["alpha": .int(0), "beta": .int(0), "gamma": .int(0), "delta": .int(0), "epsilon": .int(0), "zeta": .int(0)]
            let r = decision.get("r") ?? .null
            risk = .object(["inputs": .object(worst), "weights": .object(zero), "terms": .array([]), "rawSum": r, "rScore": r, "rFloor": .int(0), "r": r])
        }
        let kappa = JS.toNumber(pol.get("kappa")), bMax = JS.toNumber(pol.get("bMax"))
        let rv = JS.toNumber(decision.get("r"))
        var budget: JObject = ["cost": num(Risk.nz(kappa) * Risk.clamp01(rv.isFinite ? rv : 1)), "safetyBound": num(kappa > 0 ? jsMax(0, bMax) / kappa : 0)]
        if let b = input.get("budget") { budget["before"] = b }
        if let l = leaked { budget["leaked"] = l }
        if let a = decision.get("budget") { budget["after"] = a }
        let rt = decision.get("requiredThreshold") ?? .null
        return .object([
            "decision": decision, "risk": risk, "requiredThreshold": rt, "t": rt.get("t") ?? .null,
            "autoAllow": decision.get("admit") ?? .null, "needStepUp": decision.get("needStepUp") ?? .null,
            "releaseGuardianShare": decision.get("releaseGuardianShare") ?? .null, "budget": .object(budget),
            "reasons": decision.get("reasons") ?? .null, "envelopeValid": .bool(env != nil),
        ])
    }

    // ---- counterfactuals ----

    private static func entries(_ v: JSONValue?) -> [(String, JSONValue)] {
        guard case let .object(o)? = v else { return [] }
        return JS.keyOrder(o).map { ($0.s, o[$0]!) }
    }

    private static func describe(_ d: JSONValue) -> JSONValue {
        if JS.truthy(d.get("label")), let l = d.get("label") { return l }
        var parts: [String] = []
        let hc = d.get("humanCosign")
        if JS.truthy(hc) {
            parts.append(hc?.isObject == true && JS.truthy(hc?.get("full")) ? "human re-confirms goal (B←Bmax)" : "human co-signs (B+ρ)")
        }
        for (k, v) in entries(d.get("risk")) { parts.append("\(k)=\(JS.toString(v))") }
        for (k, v) in entries(d.get("budget")) { parts.append("budget.\(k)=\(JS.toString(v))") }
        if let f = d.get("rFloor") { parts.append("caution=\(JS.toString(f))") }
        if let n = d.get("now") { parts.append("now=\(JS.toString(n))") }
        for (k, v) in entries(d.get("caveatContext")) { parts.append("ctx.\(k)=\(JS.stringify(v))") }
        return .string(parts.isEmpty ? "no-op" : parts.joined(separator: ", "))
    }

    private static func spread(_ a: JSONValue?, _ b: JSONValue?) -> JObject {
        var o = a?.asObject ?? [:]
        for (k, v) in b?.asObject ?? [:] { o[k] = v }
        return o
    }

    /// The hypothetical `decide` input a delta denotes. Pure: the input is not changed.
    public static func applyDelta(_ input: JSONValue, _ d: JSONValue) -> JSONValue {
        let now: JSONValue? = JS.present(d.get("now")) ?? input.get("now")
        var budget = spread(input.get("budget"), d.get("budget"))
        let hc = d.get("humanCosign")
        if JS.truthy(hc) {
            let pol = policyOf(PCA.readEnvelope(input.get("grant") ?? .null))
            let full = hc?.isObject == true && hc?.get("full") == .bool(true)
            let bMax = Risk.nz(JS.toNumber(pol.get("bMax")))
            var nb: JObject = [:]
            if let n = now { nb["tau"] = n; nb["asOf"] = n }
            nb["B"] = num(full ? bMax : jsMin(bMax, JS.toNumber(budget[JKey("B")]) + Risk.nz(JS.toNumber(pol.get("rho")))))
            budget = nb
        }
        var next = input.asObject ?? [:]
        if let n = now { next["now"] = n } else { next["now"] = nil }
        next["budget"] = .object(budget)
        next["risk"] = .object(spread(input.get("risk"), d.get("risk")))
        next["caveatContext"] = .object(spread(input.get("caveatContext"), d.get("caveatContext")))
        if let f = d.get("rFloor") { next["rFloor"] = f }
        return .object(next)
    }

    /// Replay the decision under each single change and report which one flips allow / deny or moves the required threshold.
    public static func counterfactual(_ input: JSONValue, _ deltas: JSONValue) throws -> JSONValue {
        let baseline = try explainDecision(input)
        let bt = JS.toNumber(baseline.get("t")), br = JS.toNumber(baseline.get("risk")?.get("r"))
        var outcomes: [JSONValue] = [], flipping: [JSONValue] = [], moving: [JSONValue] = []
        for d in deltas.asArray ?? [] {
            let ex = try explainDecision(applyDelta(input, d))
            let t = JS.toNumber(ex.get("t"))
            let dir = t > bt ? "raised" : t < bt ? "lowered" : "same"
            let flips = ex.get("autoAllow") != baseline.get("autoAllow")
            let label = describe(d)
            outcomes.append(.object([
                "label": label, "delta": d, "explanation": ex, "flipsAllow": .bool(flips), "allow": ex.get("autoAllow") ?? .null,
                "thresholdDirection": .string(dir), "changesThreshold": .bool(dir != "same"), "t": ex.get("t") ?? .null,
                "rDelta": num(JS.toNumber(ex.get("risk")?.get("r")) - br),
            ]))
            if flips { flipping.append(label) }
            if dir != "same" { moving.append(label) }
        }
        return .object(["baseline": baseline, "outcomes": .array(outcomes), "flipping": .array(flipping), "thresholdChanging": .array(moving)])
    }

    // ---- full audit ----

    /// The verifier's per-check table in the reference's spelling: `pass` / `fail` / `not-enforced` (no hook, no audience asked for, the explicit
    /// plan-root opt-out) / `unsupported` (a carried bond).
    private static func verifyTable(_ p: JSONValue, _ grant: JSONValue, _ opts: JSONValue) -> JSONValue {
        let audience: PCA.Audience
        switch opts.get("audience") {
        case nil: audience = .unset
        case .null?: audience = .any
        case let .string(s)?: audience = .id(s)
        default: audience = .unset
        }
        let now = opts.get("nowEpoch").flatMap { IV.int($0) } ?? Int64(Date().timeIntervalSince1970 * 1000)
        let roots = opts.get("authorizedPlanRoots")?.asArray?.compactMap { $0.asString }
        let v = PCA.verify(pcactn: p, grant: grant, now: now, audience: audience, authorizedPlanRoots: roots,
                           insecureSkipPlanRootCheck: opts.get("insecureSkipPlanRootCheck") == .bool(true))
        var checks = JObject()
        for (k, ok) in v.checks { checks[JKey(k == "chain" ? "cap_chain" : k)] = .string(ok ? "pass" : "fail") }
        if v.checks["wire"] == false { return .object(["allow": .bool(false), "checks": .object(checks), "reason": .string(v.reason)]) }
        let hasAud = !(p.get("aud")?.asString ?? "").isEmpty
        if v.checks["audience"] == true, case .any = audience { checks["audience"] = .string("not-enforced") }
        if v.checks["audience"] == true, case .unset = audience, !hasAud { checks["audience"] = .string("not-enforced") }
        if checks["plan_root_authorized"] == nil { checks["plan_root_authorized"] = .string("not-enforced") }
        for h in ["taint_gate", "attestation", "threshold", "revocation"] { checks[JKey(h)] = .string("not-enforced") }
        if p.get("bond_ref") != nil { checks["bond"] = .string("unsupported") }
        var o: JObject = ["allow": .bool(v.allow), "checks": .object(checks)]
        if !v.reason.isEmpty { o["reason"] = .string(v.reason.hasPrefix("chain: ") ? "cap_" + v.reason : v.reason) }
        return .object(o)
    }

    /// The verifier's per-check table plus the decision decomposition for the SAME action. `opts`: grant, nowEpoch?, audience? (`null` = the explicit
    /// opt-out, absent = none given), insecureSkipPlanRootCheck?, authorizedPlanRoots?.
    public static func auditPCActn(_ p: JSONValue, _ input: JSONValue, _ opts: JSONValue) throws -> JSONValue {
        .object(["verify": verifyTable(p, opts.get("grant") ?? .null, opts), "explanation": try explainDecision(input)])
    }
}
