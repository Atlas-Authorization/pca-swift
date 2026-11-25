import Foundation

/// Runtime conformance: how an action the grant admits is routed (deny / allow / optimistic / jit-consent) from the map's posterior,
/// the judge-panel hook and its intent-conformance attestation (IC-Att), re-verification of an IC-Att, and recording a just-in-time
/// consent decision as a runtime observation. Outcomes are `{verb, values}` values.
public enum PCAIntentRouting {
    /// Routing options; every field optional (nil = default): theta2 (0.5), hMax (the space's harm maximum), bondPolicy.
    public struct RouteOptions {
        public var theta2: Double?
        public var hMax: Double?
        public var bondPolicy: PCAIntentBond.BondPolicy?

        public init() {}

        public init(json o: JSONValue?) throws {
            guard let o = o, !o.isNull else { return }
            guard let m = o.asObject else { throw JSError("RouteOptions: not an object") }
            func num(_ k: String) throws -> Double? {
                guard let v = m[JKey(k)], !v.isNull else { return nil }
                guard let d = IV.num(v) else { throw JSError("RouteOptions: \(k) must be a number") }
                return d
            }
            theta2 = try num("theta2")
            hMax = try num("hMax")
            if let b = m["bondPolicy"], !b.isNull { bondPolicy = try PCAIntentBond.BondPolicy.fromJson(b) }
        }
    }

    // ---- harm (the learner's harm model over the verb space) ----

    /// h(vs, o): the verb weight times every dimension's factor at the outcome's value.
    static func harmOf(_ vs: WalletVerb, _ o: JSONValue, _ harm: WalletOmegaMath.HarmModel) -> Double {
        var h = harm.verb(vs)
        for d in vs.dims {
            let x: JSONValue? = o.get("values")?.get(d.path)
            h *= harm.dim(d, d.isNum ? IV.num(x) : nil)
        }
        return h
    }

    /// The largest harm any outcome of the space can have.
    static func harmMax(_ omega: WalletOmega, _ harm: WalletOmegaMath.HarmModel) -> Double {
        var m = 0.0
        for vs in omega.verbs {
            var f = harm.verb(vs)
            for d in vs.dims {
                if d.isNum {
                    let a = harm.dim(d, Double(d.lo)), b = harm.dim(d, Double(d.hi))
                    f *= (a.isNaN || b.isNaN) ? Double.nan : (a > b ? a : b)
                } else {
                    var best = -Double.infinity
                    for _ in d.values { let x = harm.dim(d, nil); if x.isNaN { best = Double.nan; break }; if x > best { best = x } }
                    f *= best
                }
            }
            if f.isNaN { return f }
            if f > m { m = f }
        }
        return m
    }

    private static func verbOf(_ l: PCAIntentLearner, _ verb: String?) -> WalletVerb? {
        guard let verb = verb else { return nil }
        return l.omega.verb(verb)
    }

    private static func clamp01(_ x: Double) -> Double {
        if x.isNaN { return x }
        return x < 0.0 ? 0.0 : (x > 1.0 ? 1.0 : x)
    }

    /// The routing decision `{route, p, inGrant, vetoed, reversibility, harm, risk, judges, bond?, reason}`.
    public static func routeAction(_ l: PCAIntentLearner, _ o: JSONValue, _ opts: RouteOptions) throws -> JSONValue {
        let vs: WalletVerb? = verbOf(l, o.get("verb")?.asString)
        var r: JObject = [:]
        guard let verbSpace = vs, WalletOmegaMath.cellOf(verbSpace, values: o.get("values")) != nil else {
            r["route"] = .string("deny"); r["p"] = .double(0.0); r["inGrant"] = .bool(false); r["vetoed"] = .bool(false)
            r["reversibility"] = .string(vs?.reversibility ?? "unknown")
            r["harm"] = .double(0.0); r["risk"] = .double(1.0); r["judges"] = .bool(false)
            r["reason"] = .string("outside the Intent Map's outcome space")
            return .object(r)
        }
        let p: Double = l.acceptance(o)
        let inGrant: Bool = l.admitsOutcome(o)
        let vetoed: Bool = l.isVetoed(o)
        let harm: Double = harmOf(verbSpace, o, l.harm)
        let hMax: Double = opts.hMax ?? harmMax(l.omega, l.harm)
        let risk: Double = clamp01(((1 - p) * harm) / (hMax > 0 ? hMax : 1.0))
        let theta2: Double = opts.theta2 ?? 0.5
        r["p"] = .double(p); r["inGrant"] = .bool(inGrant); r["vetoed"] = .bool(vetoed); r["reversibility"] = .string(verbSpace.reversibility)
        r["harm"] = .double(harm); r["risk"] = .double(risk)
        if !inGrant {
            r["route"] = .string("deny"); r["judges"] = .bool(false)
            r["reason"] = .string(vetoed ? "the cell was vetoed by a runtime divergence" : "outside the conservative grant (p_n < \u{03C4})")
            return .object(r)
        }
        let irreversible = IV.same(verbSpace.reversibility, "irreversible")
        let judges: Bool = irreversible || p < 1 - 1e-12 || risk >= theta2
        if irreversible {
            r["route"] = .string("jit-consent"); r["judges"] = .bool(judges)
            r["reason"] = .string("irreversible: just-in-time consent on the rendered action")
            return .object(r)
        }
        if judges {
            r["route"] = .string("optimistic"); r["judges"] = .bool(true)
            r["bond"] = .double(try PCAIntentBond.bondAmount(opts.bondPolicy ?? PCAIntentBond.DEFAULT_BOND_POLICY, harm))
            r["reason"] = .string(p < 1 - 1e-12 ? "unconfirmed region (p_n < 1): bonded claim + judges" : "risk \u{2265} \u{03B8}\u{2082}: bonded claim + judges")
            return .object(r)
        }
        r["route"] = .string("allow"); r["judges"] = .bool(false)
        r["reason"] = .string("confirmed region, reversible, low risk")
        return .object(r)
    }

    /// The judge input for an outcome: ctx = {intentRef, mapDigest, statementText, slots, goalCommitment}.
    public static func judgeInputOf(_ l: PCAIntentLearner, _ o: JSONValue, _ ctx: JSONValue) throws -> JSONValue {
        let verb: String = o.get("verb")?.asString ?? "undefined"
        guard let vs = verbOf(l, o.get("verb")?.asString) else { throw JSError("judgeInputOf: no verb \(verb) in Omega") }
        return try PCAIntentRuntime.judgeInputOf(vs, o, l.acceptance(o), ctx)
    }

    /// The consent prompt for an action.
    public static func jitConsentRequest(_ l: PCAIntentLearner, _ o: JSONValue, _ intentRef: String?, _ mapDigest: String?) throws -> JSONValue {
        let verb: String = o.get("verb")?.asString ?? "undefined"
        guard let vs = verbOf(l, o.get("verb")?.asString) else { throw JSError("jitConsentRequest: no verb \(verb) in Omega") }
        return try PCAIntentRuntime.jitConsentRequest(vs, o, l.acceptance(o), intentRef, mapDigest)
    }

    /// Record the principal's consent decision (approve = 1, deny = 0 and the cell is vetoed) as a runtime observation.
    public static func recordJitDecision(_ l: PCAIntentLearner, _ req: JSONValue, _ decision: String?) throws -> JSONValue {
        guard let verb = req.get("verb")?.asString else { throw JSError("recordJitDecision: request has no verb") }
        let outcome: JSONValue = .object(["verb": .string(verb), "values": .object(req.get("values")?.asObject ?? [:])])
        return try PCAIntentMap.applyDivergence(l, outcome, IV.same(decision, "approve") ? 1 : 0)
    }

    private static func toPpm(_ x: Double) -> JSONValue? {
        x.isNaN || x.isInfinite ? nil : WJ.plain(.double(WJ.jsRound(x * 1000000.0)))
    }

    /// A member that is present and not null.
    private static func present(_ v: JSONValue?) -> JSONValue? {
        guard let v = v, !v.isNull else { return nil }
        return v
    }

    /// Verify a panel's verdicts for one action and produce the IC-Att. `opts`: judgeKeys, k, calibration?, pqPins?.
    public static func intentConformanceAttestation(_ input: JSONValue, _ verdicts: [JSONValue], _ opts: JSONValue, _ attestationGate: ((JSONValue) -> Bool)?) throws -> JSONValue {
        var o: JObject = [:]
        o["judgeKeys"] = opts.get("judgeKeys") ?? .null
        o["k"] = opts.get("k") ?? .null
        o["goalCommitment"] = input.get("goalCommitment") ?? .null
        o["actionDigest"] = input.get("actionDigest") ?? .null
        let calibration: JSONValue? = present(opts.get("calibration"))
        if let c = calibration { o["calibration"] = c }
        if let pins = present(opts.get("pqPins")) { o["pqPins"] = pins }
        let r: JSONValue = try PCAIntentSemantic.verifySemanticThreshold(.array(verdicts), .object(o), attestationGate)
        let digests: [String] = verdicts.map { PCAIntentRuntime.verdictDigest($0) }.sorted { WJ.u16Less($0, $1) }
        var att: JObject = [:]
        att["v"] = .int(1)
        att["kind"] = .string("pca-ic-att")
        att["intent_ref"] = input.get("intentRef") ?? .null
        att["map_digest"] = input.get("mapDigest") ?? .null
        att["action_digest"] = input.get("actionDigest") ?? .null
        att["goal_commitment"] = input.get("goalCommitment") ?? .null
        att["verdict_digests"] = .array(digests.map { JSONValue.string($0) })
        att["calibration_digest"] = try calibration.map { JSONValue.string(try PCAIntentRuntime.calibrationDigest($0)) } ?? .null
        att["k"] = opts.get("k") ?? .null
        att["ok"] = r.get("ok") ?? .null
        att["agree_count"] = r.get("agreeCount") ?? .null
        guard let score = IV.num(r.get("aggregateScore")) else { throw JSError("intentConformanceAttestation: the semantic check returned no aggregate score") }
        att["aggregate_score_ppm"] = toPpm(score) ?? .int(0)
        if let cut = r.get("cutoff") {
            att["cutoff_ppm"] = IV.num(cut).flatMap { toPpm($0) } ?? .null
        } else {
            att["cutoff_ppm"] = .null
        }
        if let reason = present(r.get("reason")) { att["reason"] = reason }
        return .object(att)
    }

    /// A judge panel: any set of model judges. Returns their signed verdicts.
    public typealias JudgePanel = (JSONValue) throws -> [JSONValue]

    /// Ask the panel and attest: `{att, verdicts}`.
    public static func checkIntentConformance(_ panel: JudgePanel, _ input: JSONValue, _ opts: JSONValue, _ attestationGate: ((JSONValue) -> Bool)?) throws -> JSONValue {
        let verdicts: [JSONValue] = try panel(input)
        let att: JSONValue = try intentConformanceAttestation(input, verdicts, opts, attestationGate)
        return .object(["att": att, "verdicts": .array(verdicts)])
    }

    /// Re-verify an IC-Att from the verdicts it names: `{ok, problems}`.
    public static func verifyICAtt(_ att: JSONValue?, _ input: JSONValue, _ verdicts: [JSONValue], _ opts: JSONValue, _ attestationGate: ((JSONValue) -> Bool)?) throws -> JSONValue {
        let again: JSONValue = try intentConformanceAttestation(input, verdicts, opts, attestationGate)
        var problems: [JSONValue] = []
        if PCAIntentRuntime.icAttDigest(again) != PCAIntentRuntime.icAttDigest(att) { problems.append(.string("IC-Att does not match the recomputation from its verdicts")) }
        if again.get("ok") != .bool(true) {
            let reason: String = again.get("reason").map { IntentV2.jsString($0) } ?? "unknown"
            problems.append(.string("panel does not pass: " + reason))
        }
        return .object(["ok": .bool(problems.isEmpty), "problems": .array(problems)])
    }
}
