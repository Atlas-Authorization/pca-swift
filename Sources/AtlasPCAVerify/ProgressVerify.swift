import Foundation

/// Proof of progress, the verifier side: the step and trajectory checks (in the reference's order, the first failure wins), the mode and charge rule, and
/// the holder-signed steps. Results are the reference's objects (`{ok: true, charge}` / `{ok: false, reason}`; trajectories add `at`).
extension PCAProgress {
    /// A denial with its reason code.
    struct ProgressError: Error { let code: String; let message: String }

    /// The guard of a transition `{seq, before, after, action_digest}`: only the value `true` allows (a throw or any other value denies).
    public typealias StepGuard = (_ transition: JSONValue) throws -> JSONValue
    /// An attestation hook over a step: only `true` passes.
    public typealias StateAttestationVerifier = (_ step: JSONValue) throws -> JSONValue

    /// The options of the step check. `expected*` members are compared only when given; `registry` is evaluated per use (a registry that cannot be built
    /// is a malformed check); `trustedStateSources` is an allowlist; attested state is required unless `requireAttestedState` is exactly `false`.
    public struct VerifyStepOptions {
        public var expectedSeq: JSONValue?
        public var expectedPrev: JSONValue?
        public var expectedActionDigest: JSONValue?
        public var expectedBeforeDigest: JSONValue?
        public var expectedAfterDigest: JSONValue?
        public var registry: (() throws -> PotentialRegistry)?
        public var guardFn: StepGuard?
        public var trustedStateSources: [JSONValue]?
        public var requireAttestedState: JSONValue?
        public var attestation: StateAttestationVerifier?
        public init() {}
    }

    /// The options of the trajectory check (the step options minus the `expected*` ones, plus the starting state and the expected action digests).
    public struct VerifyTrajectoryOptions {
        public var step = VerifyStepOptions()
        public var initial: JSONValue?
        public var initialDigest: JSONValue?
        public var expectedActionDigests: [JSONValue]?
        public init() {}
    }

    private static func registryOf(_ r: (() throws -> PotentialRegistry)?) throws -> PotentialRegistry { try r?() ?? DEFAULT_POTENTIALS }

    private static func resolve(_ goal: JSONValue, _ reg: PotentialRegistry) throws -> PotentialSpec {
        guard let id = goal.get("potential")?.asString, let spec = reg.get(id) else { throw ProgressError(code: "unknown-potential", message: "unknown potential") }
        let want = goal.get("embedder")?.asString ?? ""
        if !spec.embedder.utf16.elementsEqual(want.utf16) { throw ProgressError(code: "embedder-mismatch", message: "embedder mismatch") }
        return spec
    }

    /// The integer potential of a state: unknown id and embedder mismatch have their own denial, anything else wrong with the value is `bad-potential`.
    static func potentialOf(_ goal: JSONValue, _ reg: PotentialRegistry, _ state: JSONValue?) throws -> Int64 {
        let spec = try resolve(goal, reg)
        let p: Int64
        do {
            guard let i = try spec.fn(goal.get("objective"), state)?.safeInt else { throw ProgressError(code: "bad-potential", message: "potential: safe integer required") }
            p = i
        } catch let e as ProgressError { throw e } catch { throw ProgressError(code: "bad-potential", message: (error as? JSError)?.message ?? "potential failed") }
        if p < 0 { throw ProgressError(code: "bad-potential", message: "potential must be >= 0") }
        return p
    }

    static func denialOf(_ e: Error) -> String { (e as? ProgressError)?.code ?? "bad-potential" }

    /// Progress when the potential fell by at least epsilon (or reached 0 from above); else exploration, charged the shortfall.
    static func classify(_ pb: Int64, _ pa: Int64, _ epsilon: Int64) throws -> (mode: String, charge: Int64) {
        let required = Double(pb) - Double(epsilon)
        if Double(pa) <= required || (pa == 0 && pb > 0) { return ("progress", 0) }
        let charge = Double(pa) - required
        guard let c = JSONValue.double(charge).safeInt else { throw ProgressError(code: "bad-potential", message: "charge: safe integer required") }
        return ("exploration", c)
    }

    static func runGuard(_ g: StepGuard, _ t: JSONValue) -> Bool { (try? g(t)) == .bool(true) }

    static func stepBodyDigest(_ s: JObject) throws -> String {
        var body = s
        body["t"] = .string("pca-progress-step")
        body["v"] = .int(Int64(PROGRESS_VERSION))
        return try hashStrict(.object(body))
    }

    private static func isStep(_ s: JSONValue?) -> Bool {
        guard case let .object(o)? = s else { return false }
        func str(_ k: String) -> Bool { o[JKey(k)]?.asString != nil }
        func int(_ k: String) -> Bool { o[JKey(k)]?.safeInt != nil }
        guard str("goal_commitment"), int("seq"), o[JKey("seq")]!.safeInt! >= 0, str("before_digest"), str("after_digest"), str("action_digest"),
              o[JKey("mode")] == .string("progress") || o[JKey("mode")] == .string("exploration"), int("potential_before"), int("potential_after"), int("charge"),
              str("state_source"), str("evidence_digest"), str("prev"), str("digest"), o[JKey("before")] != nil, o[JKey("after")] != nil else { return false }
        return true
    }

    private static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if let x = ToolSchema.fin(a), let y = ToolSchema.fin(b) { return x == y }
        if case let .string(x)? = a, case let .string(y)? = b { return x.utf16.elementsEqual(y.utf16) }
        return false
    }

    private static func fail(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    /// Verify one step against a goal commitment: goal commitment, shape, the step's commitment, expected seq / prev / action / state digests, the body
    /// digest, the state digests, the potentials, mode and charge, the state-source rules, the guard and the attestation hook. Never throws; an unexpected
    /// fault is `malformed`.
    public static func verifyProgressStep(_ goal: JSONValue?, _ commitment: JSONValue?, _ step: JSONValue?, _ opts: VerifyStepOptions = VerifyStepOptions()) -> JSONValue {
        do {
            guard verifyGoalCommitment(goal, commitment), let goal = goal else { return fail("goal-mismatch") }
            guard isStep(step), case let .object(s)? = step else { return fail("malformed") }
            if !same(s[JKey("goal_commitment")], commitment) { return fail("goal-mismatch") }
            if let e = opts.expectedSeq, !same(s[JKey("seq")], e) { return fail("seq-mismatch") }
            if let e = opts.expectedPrev, !same(s[JKey("prev")], e) { return fail("chain-break") }
            if let e = opts.expectedActionDigest, !same(s[JKey("action_digest")], e) { return fail("action-mismatch") }
            if let e = opts.expectedBeforeDigest, !same(s[JKey("before_digest")], e) { return fail("state-mismatch") }
            if let e = opts.expectedAfterDigest, !same(s[JKey("after_digest")], e) { return fail("state-mismatch") }
            var body = s
            body[JKey("digest")] = nil
            if !(try stepBodyDigest(body)).utf16.elementsEqual(s[JKey("digest")]!.asString!.utf16) { return fail("digest-mismatch") }
            let before = s[JKey("before")]!, after = s[JKey("after")]!
            if try !(try stateDigest(before)).utf16.elementsEqual(s[JKey("before_digest")]!.asString!.utf16)
                || !(try stateDigest(after)).utf16.elementsEqual(s[JKey("after_digest")]!.asString!.utf16) { return fail("state-digest-mismatch") }
            let reg = try registryOf(opts.registry)
            let pb: Int64, pa: Int64, cls: (mode: String, charge: Int64)
            do {
                pb = try potentialOf(goal, reg, before)
                pa = try potentialOf(goal, reg, after)
                cls = try classify(pb, pa, goal.get("epsilon")!.safeInt!)
            } catch { return fail(denialOf(error)) }
            if pb != s[JKey("potential_before")]!.safeInt! || pa != s[JKey("potential_after")]!.safeInt! { return fail("potential-mismatch") }
            if s[JKey("mode")]!.asString! != cls.mode { return fail("mode-mismatch") }
            if s[JKey("charge")]!.safeInt! != cls.charge { return fail("charge-mismatch") }
            let source = s[JKey("state_source")]!
            if let trusted = opts.trustedStateSources, !trusted.contains(where: { same($0, source) }) { return fail("untrusted-state-source") }
            if opts.requireAttestedState != .bool(false) && source.asString == "" { return fail("untrusted-state-source") }
            let t: JSONValue = .object(["seq": s[JKey("seq")]!, "before": before, "after": after, "action_digest": s[JKey("action_digest")]!])
            if let g = opts.guardFn, !runGuard(g, t) { return fail("prohibited") }
            if let a = opts.attestation, (try? a(.object(s))) != .bool(true) { return fail("attestation-failed") }
            return .object(["ok": .bool(true), "charge": .int(cls.charge)])
        } catch { return fail("malformed") }
    }

    private static func trajFail(_ reason: String, _ at: Int) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason), "at": .int(Int64(at))]) }

    /// Verify a whole trajectory: every step with its index as the expected seq and the previous digest as the expected prev, then continuity of the
    /// states and the exploration budget. `{ok, spent, remaining, reached, finalPotential, steps, head}` or `{ok: false, reason, at}`.
    public static func verifyTrajectory(_ goal: JSONValue?, _ commitment: JSONValue?, _ steps: JSONValue?, _ opts: VerifyTrajectoryOptions = VerifyTrajectoryOptions()) -> JSONValue {
        guard verifyGoalCommitment(goal, commitment), let goal = goal else { return trajFail("goal-mismatch", -1) }
        guard case let .array(list)? = steps else { return trajFail("malformed", -1) }
        if let exp = opts.expectedActionDigests, exp.count != list.count { return trajFail("action-mismatch", min(exp.count, list.count)) }
        var anchor: String?
        do {
            if let d = opts.initialDigest, d != .null { anchor = d.asString ?? "\u{0}non-string" }
            else if let i = opts.initial { anchor = try stateDigest(i) }
        } catch { return trajFail("malformed", -1) }
        var prev = GENESIS
        var spent: Int64 = 0
        var finalPotential: Int64 = -1
        if list.isEmpty, let initial = opts.initial {
            do { finalPotential = try potentialOf(goal, try registryOf(opts.step.registry), initial) } catch { return trajFail(denialOf(error), -1) }
        }
        let budget = goal.get("explorationBudget")!.safeInt!
        for (i, s) in list.enumerated() {
            var so = opts.step
            so.expectedSeq = .int(Int64(i))
            so.expectedPrev = .string(prev)
            so.expectedActionDigest = opts.expectedActionDigests?[i]
            let r = verifyProgressStep(goal, commitment, s, so)
            if r.get("ok") != .bool(true) { return trajFail(r.get("reason")?.asString ?? "malformed", i) }
            if let a = anchor, s.get("before_digest")?.asString != a { return trajFail("discontinuous-state", i) }
            let (sum, overflow) = spent.addingReportingOverflow(r.get("charge")!.safeInt!)
            spent = sum
            if overflow || abs(spent) > Canonical.MAX_SAFE || spent > budget { return trajFail("budget-exceeded", i) }
            anchor = s.get("after_digest")?.asString
            prev = s.get("digest")!.asString!
            finalPotential = s.get("potential_after")!.safeInt!
        }
        return .object(["ok": .bool(true), "spent": .int(spent), "remaining": .int(budget - spent), "reached": .bool(finalPotential == 0), "finalPotential": .int(finalPotential),
                        "steps": .int(Int64(list.count)), "head": .string(prev)])
    }

    // ---- signed steps ----

    /// The signed message: the strict canonical bytes of `{d: domain, b: {holder, goal_commitment, action_digest, before_digest, after_digest, seq, prev, step_digest}}`.
    static func sigMessage(_ step: JObject, _ holder: String) throws -> [UInt8] {
        let b: JObject = ["holder": .string(holder), "goal_commitment": step[JKey("goal_commitment")]!, "action_digest": step[JKey("action_digest")]!,
                          "before_digest": step[JKey("before_digest")]!, "after_digest": step[JKey("after_digest")]!, "seq": step[JKey("seq")]!,
                          "prev": step[JKey("prev")]!, "step_digest": step[JKey("digest")]!]
        return try Canonical.canonicalBytes(.object(["d": .string(PROGRESS_SIG_DOMAIN), "b": .object(b)]))
    }

    /// The holder's signature over a step: `{step, holder, sig}` with plain deterministic Ed25519 over the domain-separated binding. The key is not
    /// checked to match `holderPublicKey`.
    public static func signProgressStep(_ step: JSONValue, key: PCAEdKey, holderPublicKey: String) throws -> JSONValue {
        guard case let .object(s) = step else { throw err("signProgressStep: step must be an object") }
        for k in ["goal_commitment", "action_digest", "before_digest", "after_digest", "seq", "prev", "digest"] where s[JKey(k)] == nil { throw err("signProgressStep: step.\(k) is required") }
        return .object(["step": step, "holder": .string(holderPublicKey), "sig": .string(Base64URLStrict.encode(try key.sign(try sigMessage(s, holderPublicKey))))])
    }

    private static func signedParts(_ signed: JSONValue?) -> (step: JObject, holder: String, sig: String)? {
        guard case let .object(o)? = signed, let h = o[JKey("holder")]?.asString, let sg = o[JKey("sig")]?.asString, isStep(o[JKey("step")]),
              case let .object(st)? = o[JKey("step")] else { return nil }
        return (st, h, sg)
    }

    /// Verify a holder-signed step: shape, holder, action, goal, signature, then the unsigned step check.
    public static func verifySignedProgressStep(_ goal: JSONValue?, _ commitment: JSONValue?, _ signed: JSONValue?, expectedHolder: JSONValue?, expectedActionDigest: JSONValue?,
                                                _ opts: VerifyStepOptions = VerifyStepOptions()) -> JSONValue {
        do {
            guard let p = signedParts(signed) else { return fail("malformed") }
            if !same(.string(p.holder), expectedHolder) { return fail("holder-mismatch") }
            if !same(p.step[JKey("action_digest")], expectedActionDigest) { return fail("action-mismatch") }
            if !same(p.step[JKey("goal_commitment")], commitment) { return fail("goal-mismatch") }
            if !PCAIntentKit.verifyEd(.string(p.holder), try sigMessage(p.step, p.holder), .string(p.sig)) { return fail("bad-signature") }
            var o = opts
            o.expectedActionDigest = expectedActionDigest
            return verifyProgressStep(goal, commitment, .object(p.step), o)
        } catch { return fail("malformed") }
    }

    /// Verify a signed trajectory: every holder, action and signature first (the first failure at its index), then the trajectory over the bare steps.
    public static func verifySignedTrajectory(_ goal: JSONValue?, _ commitment: JSONValue?, _ signed: JSONValue?, expectedHolder: JSONValue?, expectedActionDigests: [JSONValue],
                                              _ opts: VerifyTrajectoryOptions = VerifyTrajectoryOptions()) -> JSONValue {
        guard case let .array(list)? = signed else { return trajFail("malformed", -1) }
        if expectedActionDigests.count != list.count { return trajFail("action-mismatch", min(expectedActionDigests.count, list.count)) }
        var steps: [JSONValue] = []
        for (i, sp) in list.enumerated() {
            guard let p = signedParts(sp) else { return trajFail("malformed", i) }
            if !same(.string(p.holder), expectedHolder) { return trajFail("holder-mismatch", i) }
            if !same(p.step[JKey("action_digest")], expectedActionDigests[i]) { return trajFail("action-mismatch", i) }
            guard let msg = try? sigMessage(p.step, p.holder) else { return trajFail("malformed", i) }
            if !PCAIntentKit.verifyEd(.string(p.holder), msg, .string(p.sig)) { return trajFail("bad-signature", i) }
            steps.append(.object(p.step))
        }
        var o = opts
        o.expectedActionDigests = expectedActionDigests
        return verifyTrajectory(goal, commitment, .array(steps), o)
    }
}
