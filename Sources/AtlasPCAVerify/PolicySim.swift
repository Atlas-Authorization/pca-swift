import Foundation

/// Policy simulation, static lints and the budget forecast over a compiled policy. Pure and offline: it composes the predicate and caveat
/// evaluators with the trust-budget algebra, mutates nothing and signs nothing. A planning tool: the resource server's verifier remains the
/// authority at run time. Actions are JSON objects `{verb, resource, params?, at?}`; the catalog is the JSON catalog (`Catalog`).
public enum PolicySim {
    /// `Math.max(0, Math.min(1, x))` (NaN stays NaN).
    private static func unit(_ x: Double) -> Double { x.isNaN ? x : (x > 0 ? min(1, x) : 0) }
    /// `Math.max(a, b)` (NaN wins).
    private static func jsMax(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? Double.nan : max(a, b) }
    private static func num(_ p: JObject, _ k: String) -> Double { IV.num(p[JKey(k)]) ?? Double.nan }

    private static func riskOf(_ policy: PCACompiledPolicy, _ spec: JSONValue?, _ params: JSONValue?) -> Double {
        if policy.budgetModel == "dollars", let field = spec?.get("amountField")?.asString, !field.isEmpty {
            let amount = JS.toNumber(params?.get(field)), kappa = num(policy.riskPolicy, "kappa")
            if amount.isFinite && kappa > 0 { return unit(amount / kappa) }
        }
        guard let s = spec else { return 0.8 }
        return unit(JS.toNumber(s.get("blastRadius")))
    }

    /// Replays actions in time order against the policy, threading the trust budget as the server would (leak between actions, debit
    /// `kappa * r` on every machine-only admit, step-up when the budget cannot cover a machine-band action). `start` is the start TIME: an
    /// action without `at` occurs at `start + index`, and the budget starts at the policy's `bMax`. An action with no finite time is
    /// reported as denied, not skipped. Returns `{results: [{action, outcome, t?, r, reason?, budgetAfter}], auto, stepUp, deny, endBudget,
    /// peakRisk, autonomousRisk}` with outcome `auto`, `step_up` or `deny`.
    public static func simulate(_ policy: PCACompiledPolicy, _ actions: [JSONValue], catalog: Catalog.ActionCatalog = Catalog.DEFAULT_CATALOG, start: Double = 0) -> JSONValue {
        var timed: [(a: JSONValue, at: Double, i: Int)] = []
        var untimed: [JSONValue] = []
        for (i, a) in actions.enumerated() {
            let at: Double? = JS.present(a.get("at")) == nil ? start + Double(i) : IV.num(a.get("at"))
            if let t = at, t.isFinite { timed.append((a, t, i)) } else { untimed.append(a) }
        }
        timed.sort { ($0.at, $0.i) < ($1.at, $1.i) }

        let rp = policy.riskPolicy
        let kappa = num(rp, "kappa"), lambda = num(rp, "lambda"), theta1 = num(rp, "theta1"), theta2 = num(rp, "theta2")
        var budget = Risk.Budget(b: num(rp, "bMax"), tau: start, asOf: start)
        var recent: [JSONValue] = []
        var results: [JSONValue] = []
        var peak = 0.0, autonomous = 0.0
        var counts = ["auto": 0, "step_up": 0, "deny": 0]
        func push(_ a: JSONValue, _ outcome: String, t: Int? = nil, r: Double, reason: String? = nil) {
            var o: JObject = [:]
            o[o: "action"] = a
            o[o: "outcome"] = .string(outcome)
            if let t = t { o[o: "t"] = .int(Int64(t)) }
            o[o: "r"] = PD.num(r)
            if let why = reason { o[o: "reason"] = .string(why) }
            o[o: "budgetAfter"] = PD.num(budget.b)
            results.append(.object(o))
            counts[outcome, default: 0] += 1
        }
        for a in untimed { push(a, "deny", r: 1, reason: "action has no finite time") }

        let predicates: JSONValue = .array(policy.predicates), caveats: JSONValue = .array(policy.caveats)
        for (a, at, _) in timed {
            let spec = a.get("verb")?.asString.flatMap { catalog.get($0) }
            let cls = spec?.get("reversibility") ?? .string("irreversible")
            var action: JObject = [:]
            action[o: "verb"] = a.get("verb")
            action[o: "resource"] = a.get("resource")
            action[o: "params"] = JS.present(a.get("params")) ?? .object([:])
            action[o: "reversibility_class"] = cls
            let r = riskOf(policy, spec, a.get("params"))
            peak = jsMax(peak, r)

            let denied = PCA.envelopePredicatesError(predicates, .object(["action": .object(action)]), SafeRegex.Budget())
            budget = Risk.leak(budget, now: at, lambda: lambda)
            if let why = denied { push(a, "deny", r: r, reason: why); continue }
            let cav = PCA.evaluateCaveats(caveats, context: .object(["now": PD.num(at), "blast_radius": spec?.get("blastRadius") ?? .int(1), "reversibility_class": cls,
                                                                      "recent_action_times": .array(recent)]))
            if !cav.ok { push(a, "deny", r: r, reason: "caveat(s) failed: " + cav.failed.joined(separator: ", ")); continue }
            let cost = Risk.cost(r, kappa: kappa)
            let adm = Risk.admit(t: Risk.requiredThreshold(r, theta1: theta1, theta2: theta2).t, covers: Risk.covers(budget.b, cost))
            if adm.t == 1 && adm.admit {
                budget.b -= cost
                autonomous += r
                recent.append(PD.num(at))
                push(a, "auto", t: 1, r: r)
            } else {
                // t=2 (guardian auto-cosign) and t=3 (human) both surface as a step-up in the planning view
                push(a, "step_up", t: adm.t, r: r, reason: adm.needStepUp ? "requires tier \(adm.t)" : nil)
            }
        }
        var out: JObject = [:]
        out[o: "results"] = .array(results)
        out[o: "auto"] = .int(Int64(counts["auto"] ?? 0))
        out[o: "stepUp"] = .int(Int64(counts["step_up"] ?? 0))
        out[o: "deny"] = .int(Int64(counts["deny"] ?? 0))
        out[o: "endBudget"] = PD.num(budget.b)
        out[o: "peakRisk"] = PD.num(peak)
        out[o: "autonomousRisk"] = PD.num(autonomous)
        return .object(out)
    }

    /// Static lints over a compiled policy, as `{level, code, message}` rows: `error` is almost certainly a mistake (a limit that matches no
    /// granted action), `warn` a real risk worth a second look, `info` a notable but intentional property. `limitOrder` is the order the
    /// limit names were written in (default: code-unit order); it only orders the `limit-unmatched` rows.
    public static func lintPolicy(_ policy: PCACompiledPolicy, catalog: Catalog.ActionCatalog = Catalog.DEFAULT_CATALOG, limitOrder: [String]? = nil) -> [JSONValue] {
        var lints: [JSONValue] = []
        func add(_ level: String, _ code: String, _ message: String) {
            var o: JObject = [:]
            o[o: "level"] = .string(level)
            o[o: "code"] = .string(code)
            o[o: "message"] = .string(message)
            lints.append(.object(o))
        }
        func sev(_ c: String) -> Int { PCA.REVERSIBILITY_ORDER.firstIndex(where: { IV.same($0, c) }) ?? -1 }
        var granted = Set<JKey>()
        for s in policy.actions { for name in [s.verb, s.action] + s.aliases { granted.insert(JKey(name)) } }
        let keys = limitOrder ?? policy.inputLimits.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        for key in keys where policy.inputLimits[key] != nil && !granted.contains(JKey(key)) {
            add("error", "limit-unmatched", "limit for '\(key)' matches no granted action")
        }
        for spec in policy.actions {
            let pred = policy.predicates.first { IV.same($0.get("verb")?.asString, spec.verb) }
            let resource = pred?.get("resource")
            let broad = !JS.truthy(resource) || resource == .string("*")
            if !(spec.amountField ?? "").isEmpty && !policy.limits.contains(where: { IV.same($0.verb, spec.verb) }) {
                add("warn", "money-unbounded", "money action '\(spec.verb)' has no per-call limit — spend is bounded only by the trust budget")
            }
            if broad && sev(spec.reversibility) >= 1 {
                add("warn", "broad-resource", "'\(spec.verb)' (\(spec.reversibility)) matches ANY resource — consider a resource prefix")
            }
            if catalog.get(spec.verb) == nil {
                add("info", "uncatalogued", "'\(spec.verb)' is not in the catalog — treated conservatively (irreversible, high blast radius)")
            }
        }
        let theta2 = num(policy.riskPolicy, "theta2"), bMax = num(policy.riskPolicy, "bMax"), kappa = num(policy.riskPolicy, "kappa")
        if theta2 >= 1 {
            let irreversible = policy.actions.contains { sev($0.reversibility) >= 2 }
            add(irreversible ? "warn" : "info", "no-step-up-band",
                "theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted" + (irreversible ? " — including irreversible actions" : ""))
        }
        if kappa > 0 && bMax / kappa > 100 {
            add("warn", "large-autonomy", "autonomous bound is \(JS.toString(.double((bMax / kappa + 0.5).rounded(.down))))× a max-risk action between human co-signs")
        }
        return lints
    }

    /// Forecasts a plan against a policy: how the budget drains, the index of the first action forced to a step-up and how many co-signs
    /// the whole plan needs. `{steps: [{verb, resource, outcome, r, budgetAfter}], firstStepUpAt?, autonomousRisk, forcesCosign,
    /// cosignsNeeded, endBudget}`.
    public static func forecast(_ policy: PCACompiledPolicy, _ plan: [JSONValue], catalog: Catalog.ActionCatalog = Catalog.DEFAULT_CATALOG, start: Double = 0) -> JSONValue {
        let rep = simulate(policy, plan, catalog: catalog, start: start)
        let steps: [JSONValue] = (rep.get("results")?.asArray ?? []).map { r in
            var o: JObject = [:]
            o[o: "verb"] = r.get("action")?.get("verb")
            o[o: "resource"] = r.get("action")?.get("resource")
            o[o: "outcome"] = r.get("outcome")
            o[o: "r"] = r.get("r")
            o[o: "budgetAfter"] = r.get("budgetAfter")
            return .object(o)
        }
        var out: JObject = [:]
        out[o: "steps"] = .array(steps)
        if let first = steps.firstIndex(where: { $0.get("outcome") == .string("step_up") }) { out[o: "firstStepUpAt"] = .int(Int64(first)) }
        out[o: "autonomousRisk"] = rep.get("autonomousRisk")
        out[o: "forcesCosign"] = .bool((rep.get("stepUp")?.safeInt ?? 0) > 0)
        out[o: "cosignsNeeded"] = rep.get("stepUp")
        out[o: "endBudget"] = rep.get("endBudget")
        return .object(out)
    }

    /// Recommends `kappa` / `bMax` so an agent can take `targetActions` autonomous actions of typical risk `perActionRisk` (clamped to
    /// [1e-6, 1]) between human co-signs: `bMax = targetActions * perActionRisk * kappa`. Throws on a non-finite input or a `kappa` that is
    /// not positive. `{kappa, bMax, autonomousBound, rationale}`.
    public static func recommendPolicy(targetActions: Double, perActionRisk: Double, kappa: Double = 1) throws -> JSONValue {
        if !kappa.isFinite || kappa <= 0 { throw JSError("recommendPolicy: kappa must be a positive finite number") }
        if !targetActions.isFinite || !perActionRisk.isFinite { throw JSError("recommendPolicy: targetActions and perActionRisk must be finite numbers") }
        let r = max(1e-6, min(1, perActionRisk))
        let n = targetActions > 0 ? targetActions : 0
        let bMax = n * r * kappa
        var out: JObject = [:]
        out[o: "kappa"] = PD.num(kappa)
        out[o: "bMax"] = PD.num(bMax)
        out[o: "autonomousBound"] = PD.num(bMax / kappa)
        out[o: "rationale"] = .string("Σr ≤ bMax/κ = \(PCAImmune.toFixed(bMax / kappa, 3)) ≥ \(JS.toString(.double(n)))×\(PCAImmune.toFixed(r, 3)) actions before a human co-sign")
        return .object(out)
    }

    /// The proven autonomous bound of a risk policy (`bMax / kappa` risk units; 0 when kappa is not above 0).
    public static func autonomyBoundOf(_ riskPolicy: JSONValue?) -> Double { SafetyCertificate.safetyCertificateBound(riskPolicy) }
}
