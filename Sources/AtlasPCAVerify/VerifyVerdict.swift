import Foundation

// The resource-server verifier `verifyPCActn` of the reference, reported as its FULL verdict: `allow`, the recomputed risk `r`, the
// `requiredThreshold`, every check with its status (`pass`, `fail`, `not-enforced`, `unsupported`), the reasons in order, the budget after the
// decision and the per-check assurance report. The checks are the core verifier's (`PCA.verify`), the hooks and enforcement gates in the reference's
// order, then the server checks (pq pin, grant binding, operation, params, plan, revocation epoch, beacon, attestation, budget, risk inputs,
// reversibility, the Policy VM decision, delegated caveats, the threshold rule, the assurance requirement), the unsupported features and the
// default-deny fold of the required checks. It never throws: any internal fault is a fail-closed verdict.
extension PCA {
    /// The hook types of the core verification step (declared with the gateway, which runs the same step).
    public typealias HookOutcome = PCAGateway.HookOutcome
    public typealias VerifyHook = PCAGateway.VerifyHook

    /// The checks a verdict must have passed unless `require` says otherwise (the stateless profile).
    public static let VERDICT_REQUIRED_CHECKS = ["counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]

    /// The operation the server will execute. A verb or resource that is not a string is `nil` (the check then fails closed).
    public struct VerdictOperation {
        public var verb: String?
        public var resource: String?
        public var params: JSONValue?
        public init(verb: String?, resource: String?, params: JSONValue? = nil) {
            self.verb = verb
            self.resource = resource
            self.params = params
        }
    }

    /// The guardian-signed revocation epoch the verifier holds for the grant.
    public struct VerdictEpoch {
        public var epoch: JSONValue
        public var guardianPublic: String
        public var lastAcceptedEpoch: Double?
        public var maxAgeMs: Double?
        public init(epoch: JSONValue, guardianPublic: String, lastAcceptedEpoch: Double? = nil, maxAgeMs: Double? = nil) {
            self.epoch = epoch
            self.guardianPublic = guardianPublic
            self.lastAcceptedEpoch = lastAcceptedEpoch
            self.maxAgeMs = maxAgeMs
        }
    }

    /// What the resource server knows about the request (all optional): the reference's `PcaContext`.
    public struct VerdictContext {
        public var params: JSONValue?
        public var subject: JSONValue?
        public var env: JSONValue?
        /// The committed plan (a JSON array of plan nodes).
        public var plan: JSONValue?
        public var planAuthorized: Bool?
        public var reversibilityClass: String?
        public var risk: JObject?
        /// `{B, tau, asOf?}`. Absent: the fail-closed default (B = 0).
        public var budget: JSONValue?
        public var recentActionTimes: [Double]?
        public var revocationEpoch: VerdictEpoch?
        public var beacon: BeaconInput?
        public init() {}
    }

    /// The options of `verifyVerdict` (the reference's `VerifyPCActnOptions`).
    public struct VerifyVerdictOptions {
        public var grant: JSONValue
        public var insecureSkipPlanRootCheck = false
        /// `.any` is the reference's `audience: null` (accept any); `.unset` is an absent audience.
        public var audience: Audience = .unset
        public var attestation: VerifyHook?
        public var threshold: VerifyHook?
        public var revocation: VerifyHook?
        public var zk: VerifyHook?
        public var now: Int64?
        /// Set when the caller's clock is no finite number at all (a string, NaN, an infinity): the reference answers a fail-closed verdict, whatever `now` says.
        public var clockNotFinite = false
        public var context = VerdictContext()
        public var require: [String]?
        public var allowedSuites: [String]?
        public var pqPins: [String: String]?
        public var intent: IntentPolicy?
        public var intentV2: IntentV2Context?
        public var freshAt: FreshAtPolicy?
        public var operation: VerdictOperation?
        public var enforce = PCAGateway.EnforceGates()
        public var requireRiskInputs: [String] = []
        public var assurance = false
        public var requireAssurance: AssuranceRequirement?
        public var allowUnsupported: [String] = []
        public var k1: K1Input?
        /// A misconfiguration the typed options cannot carry (for example a `require` that is not a list): the verdict fails closed with it
        /// once the PCActn has been decoded and its wire form checked.
        public var fault: String?
        public init(grant: JSONValue) { self.grant = grant }
    }

    public struct RequiredThresholdVerdict: Equatable {
        public var t: Int
        public var proof: String
        public var optimisticAllowed: Bool
        public init(t: Int, proof: String, optimisticAllowed: Bool) {
            self.t = t
            self.proof = proof
            self.optimisticAllowed = optimisticAllowed
        }
        static let worst = RequiredThresholdVerdict(t: 3, proof: "strong", optimisticAllowed: false)
        var json: JSONValue { .object(["t": .int(Int64(t)), "proof": .string(proof), "optimisticAllowed": .bool(optimisticAllowed)]) }
    }

    /// The full verdict of `verifyVerdict`.
    public struct PcaVerdict {
        public var allow: Bool
        public var r: Double
        public var requiredThreshold: RequiredThresholdVerdict
        /// name -> status, in the order decided.
        public var checkNames: [String]
        public var checks: [String: CheckStatus]
        public var reasons: [String]
        /// `{B, tau, asOf}`: present only when the reference reports one.
        public var budget: JSONValue?
        public var assurance: AssuranceReport?
        public var k1Bound: [BoundCaveat]?

        /// The verdict as the reference writes it.
        public var json: JSONValue {
            var c: JObject = [:]
            for n in checkNames { c[JKey(n)] = .string(checks[n]?.rawValue ?? "") }
            var o: JObject = ["allow": .bool(allow), "r": PD.num(r), "requiredThreshold": requiredThreshold.json, "checks": .object(c),
                              "reasons": .array(reasons.map { .string($0) })]
            if let b = budget { o["budget"] = b }
            if let a = assurance { o["assurance"] = a.json }
            return .object(o)
        }
    }

    // MARK: entry points

    /// Verify a PCActn (an object, or its encoded text) against the stored grant. Never throws.
    public static func verifyVerdict(_ pcactn: JSONValue, _ o: VerifyVerdictOptions) -> PcaVerdict {
        var v = verdictChecks(pcactn, o)
        // a verdict that stopped before the checks ran still reports its outcomes when asked
        if (o.assurance || o.requireAssurance != nil) && v.assurance == nil {
            v.assurance = buildAssuranceReport(AssuranceSources(checks: v.checkNames.map { NamedStatus(name: $0, status: v.checks[$0]?.rawValue ?? "fail") }))
        }
        return v
    }

    private static func verdictFailClosed(_ reason: String, _ checks: [(String, CheckStatus)] = []) -> PcaVerdict {
        let all = checks + [("malformed", CheckStatus.fail)]
        return PcaVerdict(allow: false, r: 1, requiredThreshold: .worst, checkNames: all.map { $0.0 },
                          checks: Dictionary(all, uniquingKeysWith: { _, b in b }), reasons: [reason])
    }

    /// The default-deny fold (`enforceRequired`): every required check must be `pass`; one that is not turns the verdict to a deny and, unless it
    /// already failed, is recorded as `fail` with the reason `<name>: required check is <status|absent> (default-deny: not enforced by this resource server)`.
    private static func verdictEnforce(_ v: inout PcaVerdict, _ required: [String]) {
        let original = v.checks
        for raw in required {
            let name = raw == "counter" && original["counter"] == nil ? (original["replay"] != nil ? "replay" : "counter_format") : raw
            let was = v.checks[name]
            if was == .pass { continue }
            v.allow = false
            if was == .fail { continue }
            let shown = original[name] == .unsupported ? "unsupported" : (was == nil ? "absent" : CheckStatus.notEnforced.rawValue)
            v.reasons.append("\(name): required check is \(shown) (default-deny: not enforced by this resource server)")
            if was == nil { v.checkNames.append(name) }
            v.checks[name] = .fail
        }
    }

    private static func verdictChecks(_ input: JSONValue, _ o: VerifyVerdictOptions) -> PcaVerdict {
        var pIn = input
        if case let .string(text) = input {
            if text.utf8.count > MAX_ARTIFACT_BYTES { return verdictFailClosed("undecodable PCActn: \(ARTIFACT_SIZE_REASON)") }
            do { pIn = try StrictJSON.parse(text) } catch { return verdictFailClosed("undecodable PCActn: strict JSON: \(error)") }
            if !pIn.isObject { return verdictFailClosed("undecodable PCActn: decodePCActn: not an object") }
        }
        switch pIn {
        case .object, .array: break
        default: return verdictFailClosed("PCActn is not an object")
        }
        if o.clockNotFinite { return verdictFailClosed("the verifier clock is not a finite time") }
        do {
            return try verdictSteps(pIn, o)
        } catch {
            return verdictFailClosed("verifier error (fail closed): \((error as? InternalError)?.what ?? "\(error)")")
        }
    }

    private static func verdictSteps(_ pIn: JSONValue, _ o: VerifyVerdictOptions) throws -> PcaVerdict {
        let grant = o.grant
        guard case let .object(g) = grant, case .array? = g["caveats"] else { throw InternalError(what: "the grant is not a capability") }
        let now = o.now ?? Int64((Date().timeIntervalSince1970 * 1000).rounded(.down))
        let p = pIn.asObject ?? [:]
        let hookCtx = pIn

        // the operation's params are the action params (predicates, caveats, digest)
        var ctx = o.context
        let ctxParams = o.context.params
        if let op = o.operation, let pr = op.params { ctx.params = pr }

        // rules 20 / 21 read the stored grant's signed envelope: when it carries any, the v2 pipeline needs the plaintext params and host env
        let needsModel = needsModelRules(grant)
        var v2ctx = o.intentV2
        if v2ctx != nil || needsModel {
            var m: JObject = v2ctx?.value.asObject ?? [:]
            if m["params"] == nil || m["params"] == .null { m["params"] = ctx.params }
            if m["env"] == nil || m["env"] == .null { m["env"] = ctx.env }
            v2ctx = IntentV2Context(.object(m))
        }
        let v2d: (checks: [IntentV2.Check], env: IntentV2Env?, legacy: Bool)? = p["intent_session"] != nil || needsModel
            ? IntentV2.decide(p, grant: grant, ctx: v2ctx, now: now) : nil

        // ---- the core verifier (verifyPCActnCore): the plan root is decided below from the server's own plan, so the core defers to it
        let core = verify(pcactn: pIn, grant: grant, now: now, audience: o.audience, allowedSuites: o.allowedSuites, intentPolicy: o.intent, intentV2: v2ctx,
                          freshAt: o.freshAt, insecureSkipPlanRootCheck: true)
        if core.checks["wire"] == false {
            return verdictFailClosed(core.reason.isEmpty ? "wire: malformed PCActn" : core.reason, [("wire", .fail)])
        }
        var names: [String] = []
        var checks: [String: CheckStatus] = [:]
        func cset(_ n: String, _ s: CheckStatus) {
            if checks[n] == nil { names.append(n) }
            checks[n] = s
        }
        var coreReason: String?
        func cfail(_ n: String, _ why: String) {
            cset(n, .fail)
            if coreReason == nil { coreReason = "\(n): \(why)" }
        }
        // the core's checks in its order; its own failure texts under the reference names (`chain` is `cap_chain`)
        let hasAud = !(p["aud"]?.asString ?? "").isEmpty
        for n in CORE_CHECK_ORDER + core.checks.keys.sorted() where core.checks[n] != nil && checks[n == "chain" ? "cap_chain" : n] == nil {
            if n == "zk_compliance" { continue } // decided with the hooks below
            var s: CheckStatus = core.checks[n] == true ? .pass : .fail
            if n == "audience" && s == .pass {
                switch o.audience {
                case .any: s = .notEnforced
                case .unset: if !hasAud { s = .notEnforced }
                case .id: break
                }
            }
            cset(n == "chain" ? "cap_chain" : n, s)
        }
        coreReason = core.reasons.first { !IV.startsWith($0, "zk_compliance:") }.map { IV.startsWith($0, "chain: ") ? "cap_" + $0 : $0 }
        if checks.values.allSatisfy({ $0 != .fail }) { coreReason = nil }

        // M1 taint gate, M3 freshness gate, the hooks (attestation with its gate, threshold, revocation, zk) and the bond: the core's own order
        var hookT: Double?
        func run(_ name: String, _ hook: VerifyHook?) throws {
            let r = try hook?(hookCtx, grant, now) ?? .notEnforced
            if r.enforced && !r.ok { cfail(name, r.reason ?? "rejected") } else { cset(name, r.enforced ? .pass : .notEnforced) }
            if name == "threshold" && r.enforced { hookT = r.t }
        }
        do {
            if let tg = o.enforce.taint {
                let r = Taint.gate(p["provenance"], registry: tg.registry, resourceGraphNode: tg.resourceGraphNode, maxTaint: tg.maxTaint)
                if r.ok { cset("taint_gate", .pass) } else { cfail("taint_gate", r.reason ?? "rejected") }
            } else {
                cset("taint_gate", .notEnforced)
            }
            if let fg = o.enforce.freshness {
                if let why = freshnessAnchorError(p, fg, now) { cfail("freshness", why) } else { cset("freshness", .pass) }
            }
            let gate = o.enforce.attestation
            try run("attestation", gate?.verifier ?? o.attestation)
            if let gt = gate, gt.required, checks["attestation"] == .notEnforced {
                cfail("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)")
            }
            try run("threshold", o.threshold)
            try run("revocation", o.revocation)
            if p["zk_compliance"] != nil {
                try run("zk_compliance", o.zk)
                if checks["zk_compliance"] != .pass && checks["zk_compliance"] != .fail {
                    cfail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof")
                }
            }
            if p["bond_ref"] != nil { cset("bond", .notEnforced) }
        } catch {
            cset("malformed", .fail)
            if coreReason == nil { coreReason = "malformed PCActn: \(errMessageOf(error))" }
        }
        let coreAllow = !checks.values.contains(.fail)
        let unsupported: [String] = p["bond_ref"] != nil && checks["bond"] == .notEnforced ? ["bond"] : []

        // ---- the verdict fold
        var reasons: [String] = (!coreAllow && coreReason != nil) ? [coreReason!] : []
        func fail(_ name: String, _ why: String) {
            if checks[name] == nil { names.append(name) }
            checks[name] = .fail
            reasons.append("\(name): \(why)")
        }
        func mark(_ name: String, _ s: CheckStatus) {
            if checks[name] == nil { names.append(name) }
            checks[name] = s
        }
        // the core keeps only its first failure; the v2 checks are the escalate-class ones, so every failed one is reported
        if let v2 = v2d {
            let base = reasons
            let folded = foldV2Reasons(base, v2.checks.map { V2Check(name: $0.name, ok: $0.ok, reason: $0.reason.isEmpty ? nil : $0.reason) })
            reasons += folded.dropFirst(base.count)
        }
        if let late = o.fault { throw InternalError(what: late) }

        // the server-side PQ pin for a grant whose issuer is pinned
        if let pins = o.pqPins {
            let r = pqPinCheck(grant: g, pins: pins)
            if r.pass { mark("pq_pin", .pass) } else { fail("pq_pin", r.reason) }
        }

        // grant_ref binds the object to this grant
        if IV.same(p["grant_ref"]?.asString, g["id"]?.asString) { mark("grant_ref", .pass) } else { fail("grant_ref", "does not reference the supplied grant") }

        let action = p["action"]?.asObject ?? [:]
        // the proof must be for the operation the server will execute: verb, resource and (when given) the exact params
        if let op = o.operation {
            let signed = "\(IntentWB.jsOpt(action["verb"])) on \(IntentWB.jsOpt(action["resource"]))"
            if op.verb == nil || op.resource == nil {
                fail("operation", "the server operation has no verb / resource (fail closed)")
            } else if !IV.same(action["verb"]?.asString, op.verb) || !IV.same(action["resource"]?.asString, op.resource) {
                fail("operation", "the proof is for \(signed), but this operation is \(op.verb!) on \(op.resource!)")
            } else if let pr = op.params, !IV.same(try verdictHash(pr), action["params_digest"]?.asString) {
                fail("operation", "the proof's params_digest does not match the params of this \(op.verb!) operation")
            } else if let pr = op.params, let cp = ctxParams, try verdictHash(cp) != verdictHash(pr) {
                fail("operation", "context.params differ from the operation params")
            } else {
                mark("operation", .pass)
            }
        }

        // params plaintext must open the committed digest
        if let pr = ctx.params {
            if IV.same(try verdictHash(pr), action["params_digest"]?.asString) { mark("params_digest", .pass) } else { fail("params_digest", "supplied params do not hash to action.params_digest") }
        } else {
            mark("params_digest", .notEnforced)
        }

        // the server's own copy of the plan must be the committed one
        var planNodes: [JSONValue]?
        if let pl = ctx.plan, !pl.isNull {
            guard case let .array(nodes) = pl else { throw InternalError(what: "ctx.plan.map is not a function") }
            if nodes.contains(where: { $0.isNull }) { throw InternalError(what: "Cannot read properties of null (reading 'id')") }
            planNodes = nodes
        }
        let planRoot = p["plan"]?.get("root")?.asString
        let rootMatches = planNodes.flatMap { knownPlanRoot($0) }.map { IV.same($0, planRoot) } ?? false
        if planNodes == nil {
            if o.insecureSkipPlanRootCheck { mark("plan_root_authorized", .notEnforced) } else {
                fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)")
            }
        } else if !rootMatches {
            fail("plan_root_authorized", "known plan does not match plan.root")
        } else if ctx.planAuthorized == true {
            mark("plan_root_authorized", .pass)
        } else if ctx.planAuthorized == false {
            fail("plan_root_authorized", "the plan root has not been authorized by the principal")
        } else if o.insecureSkipPlanRootCheck {
            mark("plan_root_authorized", .notEnforced)
        } else {
            fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)")
        }

        if let re = ctx.revocationEpoch {
            let r = checkRevocationEpoch(re.epoch, EpochCheckOptions(guardianPublic: re.guardianPublic, now: Double(now), grantRef: g["id"]?.asString,
                                                                    lastAcceptedEpoch: re.lastAcceptedEpoch, pcactnEpoch: IV.num(p["freshness"]?.get("epoch")), maxAgeMs: re.maxAgeMs))
            if r.ok {
                if checks["freshness"] != .fail { mark("freshness", .pass) }
            } else {
                fail("freshness", r.reason ?? "revocation epoch rejected")
            }
        } else if checks["freshness"] == nil {
            mark("freshness", .notEnforced)
        }

        do {
            let bc = ctx.beacon
            let r = bc.map { Beacons.verifyLivenessBeacon($0.beacon, issuers: $0.issuers, now: now, instance: $0.instance, scope: g["id"]?.asString, pqPins: $0.pqPins) }
            let seq = bc.flatMap { IV.num($0.beacon.get("seq")) }
            let replayed = bc != nil && (r?.ok ?? false) && bc?.lastAcceptedSeq != nil && seq != nil && seq! < Double(bc!.lastAcceptedSeq!)
            var binds = false
            if let b = bc, r?.ok == true, !replayed {
                do { binds = IV.same(p["freshness"]?.get("beacon_ref")?.asString, try Beacons.beaconRef(b.beacon)) } catch {
                    throw InternalError(what: "the beacon is outside the strict JSON profile")
                }
            }
            switch Beacons.beaconDecision(present: bc != nil, ok: r?.ok ?? false, replayed: replayed, refBinds: binds) {
            case "rejected": fail("beacon", r?.reason ?? "beacon rejected")
            case "replayed": fail("beacon", "beacon seq \(PD.js(bc?.beacon.get("seq"))) is older than the last accepted \(PD.numStr(Double(bc?.lastAcceptedSeq ?? 0))) (replay)")
            case "unbound": fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon")
            case "pass": mark("beacon", .pass)
            default: mark("beacon", .notEnforced)
            }
        }

        // require-when-bound: a grant whose agent_binding constrains the model / measurement / operator / weights REQUIRES a bound attestation
        let env = readEnvelope(grant)
        if requiresAttestation(env?.get("agent_binding")) && checks["attestation"] != .pass {
            fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED")
        }

        let chain = p["cap_chain"]?.asArray ?? []
        let leaf = chain.last
        let depth = max(0, chain.count - 1)
        // an ABSENT budget fails CLOSED: a deny-metered budget (B = 0) forces machine-only actions with a cost to step up
        let hasBudget = ctx.budget != nil && ctx.budget != .null
        let budgetIn: JSONValue = hasBudget ? ctx.budget! : .object(["B": .int(0), "tau": .int(now), "asOf": .int(now)])
        mark("budget", hasBudget ? .pass : .notEnforced)
        if !hasBudget {
            reasons.append("budget: no budget supplied \u{2014} fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge")
        }

        // taint: ONLY a server-supplied value counts; a missing one is priced at the worst case by the Policy VM
        let risk: JObject = ctx.risk ?? [:]
        if !o.requireRiskInputs.isEmpty {
            let missing = o.requireRiskInputs.filter { k in !(ToolSchema.fin(risk[JKey(k)]) != nil || (k == "semanticDistance" && planNodes != nil)) }
            if !missing.isEmpty { fail("risk_inputs", "required risk input(s) not supplied by the server: \(missing.joined(separator: ", "))") } else { mark("risk_inputs", .pass) }
        }

        // reversibility: the server's authoritative class wins; the agent may only be stricter
        let declared = action["reversibility_class"]
        var reversibility = declared
        if let serverClass = ctx.reversibilityClass {
            let dr = classRank(declared), sr = classRank(.string(serverClass))
            if dr < sr {
                fail("reversibility", "declared class '\(IntentWB.jsOpt(declared))' is less restrictive than the authoritative '\(serverClass)'")
            } else {
                mark("reversibility", .pass)
            }
            reversibility = dr > sr ? declared : .string(serverClass)
        }
        var inner: JObject = [:]
        if let x = action["verb"] { inner["verb"] = x }
        if let x = action["resource"] { inner["resource"] = x }
        if let x = ctx.params { inner["params"] = x }
        if let x = reversibility { inner["reversibility_class"] = x }
        var actx: JObject = ["action": .object(inner)]
        if let s = ctx.subject { actx["subject"] = s }
        if let e = v2Env(p, grant, v2ctx, now, ctx.env) { actx["env"] = e }
        if let tb = p["tool_binding"]?.asString { actx["toolBinding"] = .string(tb) }
        let actionCtx = JSONValue.object(actx)

        var dIn: JObject = ["grant": grant, "trustedRoot": grant, "action": actionCtx, "risk": .object(risk), "budget": budgetIn, "now": .int(now)]
        if let pins = o.pqPins {
            var po: JObject = [:]
            for (k, v) in pins { po[JKey(k)] = .string(v) }
            dIn["pqPins"] = .object(po)
        }
        if let nodes = planNodes { dIn["plan"] = .array(nodes) }
        if let nid = p["plan"]?.get("node_id") { dIn["nodeId"] = nid }
        var cc: JObject = ["delegationDepth": .int(Int64(depth))]
        if let t = ctx.recentActionTimes { cc["recentActionTimes"] = .array(t.map { .double($0) }) }
        dIn["caveatContext"] = .object(cc)
        if let k = o.k1 { dIn["k1"] = verdictK1JSON(k, actionDigest: dischargeActionDigest(pcactn: pIn)) }
        if let c = p["caution"], case .int = c { dIn["rFloor"] = c } else if let c = p["caution"], case .double = c { dIn["rFloor"] = c }
        let d = try PCAPolicyVm.decide(.object(dIn))
        let release = d.get("releaseGuardianShare") == .bool(true)
        let rt = d.get("requiredThreshold")
        let tReq = Int(IV.num(rt?.get("t")) ?? 3)
        let reqThreshold = RequiredThresholdVerdict(t: tReq, proof: rt?.get("proof")?.asString ?? "strong", optimisticAllowed: rt?.get("optimisticAllowed") == .bool(true))
        let dr = IV.num(d.get("r")) ?? 1

        // caveats added by delegation hops (beyond the root's) are conjunctive too
        var k1Bound: [BoundCaveat]?
        if let leafCap = leaf {
            let gcs = g["caveats"]?.asArray ?? []
            guard case let .array(lc)? = leafCap.get("caveats") else { throw InternalError(what: "Cannot read properties of undefined (reading 'slice')") }
            let extra = Array(lc.dropFirst(gcs.count))
            let useK1 = lc.contains(where: { isK1Caveat($0) }) || o.k1?.narrow != nil
            var k1r: K1Result?
            if useK1 {
                var k = o.k1
                k?.actionDigest = dischargeActionDigest(pcactn: pIn)
                k1r = evaluateK1(grant: grant, chain: p["cap_chain"], k1: k, now: now, action: .object(inner))
            }
            if let kr = k1r { k1Bound = kr.bound }
            var cctx: JObject = ["now": .int(now), "delegation_depth": .int(Int64(depth)), "action": .object(inner)]
            if let b = risk["blastRadius"] { cctx["blast_radius"] = b }
            if let rc = resolveReversibilityClass(actionCtx, plan: planNodes, nodeId: p["plan"]?.get("node_id")?.asString) { cctx["reversibility_class"] = .string(rc) }
            if let t = ctx.recentActionTimes { cctx["recent_action_times"] = .array(t.map { .double($0) }) }
            var args: JSONValue = .object([:])
            if case .object? = inner["params"] { args = inner["params"] ?? args }
            let call = ToolCall(tool: action["verb"]?.asString ?? "", args: args, toolSignatureDigest: p["tool_binding"]?.asString)
            let cv = evaluateAgentCaveats(.array(extra.filter { !isK1Caveat($0) } + (k1r?.plain ?? [])), .object(cctx), actionCtx, call, SafeRegex.Budget())
            if cv.ok && (k1r?.ok ?? true) {
                mark("delegated_caveats", .pass)
            } else {
                var why = "delegation caveat(s) not satisfied: \((cv.failed + (k1r?.failed ?? [])).joined(separator: ", "))"
                if let kr = k1r, !kr.ok { why += " (\(kr.reasons.joined(separator: "; ")))" }
                fail("delegated_caveats", why)
            }
        }

        // policy: the check mirrors the Policy VM's release decision; its reasons are kept in order
        mark("policy", release ? .pass : .fail)
        for x in d.get("reasons")?.asArray ?? [] { reasons.append("policy: \(x.asString ?? "")") }

        // threshold: t above 1 needs an ENFORCED threshold hook that reported at least the SERVER-derived t (F-1)
        let hookTInt: Double? = hookT.flatMap { $0.isNaN ? nil : max(-9007199254740991, min(9007199254740991, $0.rounded(.down))) }
        if tReq > 1 && release {
            let th = checks["threshold"]
            if th == .pass {
                if !(hookTInt != nil && hookTInt! >= Double(tReq)) {
                    fail("threshold", "threshold hook enforced t=\(hookT.map { PD.numStr($0) } ?? "unreported") but the server requires t=\(tReq) (below the server-derived threshold; derive t from server-held data)")
                }
            } else if th == .fail {
                fail("threshold", "t=\(tReq) required and the threshold proof was rejected")
            } else {
                fail("threshold", "t=\(tReq) (\(reqThreshold.proof)) required but no threshold verifier is enforced")
            }
        }

        let required = o.require ?? VERDICT_REQUIRED_CHECKS
        let wantAssurance = o.assurance || o.requireAssurance != nil
        func report(_ cs: [String: CheckStatus], _ order: [String]) -> AssuranceReport {
            var src = AssuranceSources(checks: order.map { NamedStatus(name: $0, status: cs[$0]?.rawValue ?? "fail") }, pcactn: pIn,
                                       hooks: AssuranceHooks(attestation: o.attestation.map { $0 as Any }, zk: o.zk.map { $0 as Any },
                                                             threshold: o.threshold.map { $0 as Any }, revocation: o.revocation.map { $0 as Any }),
                                       attestationHook: (o.enforce.attestation?.verifier ?? o.attestation).map { $0 as Any }, thresholdT: hookT)
            if v2d?.legacy == true { src.degraded = ["tighten": LEGACY_POLARITY_DEGRADED] }
            return buildAssuranceReport(src)
        }
        if let req = o.requireAssurance {
            if let unmet = unmetAssurance(report(checks, names), req) {
                fail("assurance", String(unmet.unicodeScalars.dropFirst("assurance: ".unicodeScalars.count)))
            } else {
                mark("assurance", .pass)
            }
        }

        let allow = !checks.values.contains(.fail) && release && coreAllow
        var finalChecks = checks
        for n in unsupported where finalChecks[n] == .notEnforced { finalChecks[n] = .unsupported }
        // a feature the PCActn carries but this verifier does not implement is never a pass, and denies unless allowed
        let refused = unsupported.filter { n in !o.allowUnsupported.contains(n) }
        if !refused.isEmpty {
            var out = PcaVerdict(allow: false, r: dr, requiredThreshold: reqThreshold, checkNames: names, checks: finalChecks,
                                 reasons: reasons + refused.map { "\($0): unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)" })
            verdictEnforce(&out, required)
            if wantAssurance { out.assurance = refreshAssurance(report(finalChecks, names), out.checkNames.map { (name: $0, status: out.checks[$0]?.rawValue ?? "fail") }) }
            return out
        }
        var out = PcaVerdict(allow: allow, r: dr, requiredThreshold: reqThreshold, checkNames: names, checks: finalChecks, reasons: reasons)
        if allow && hasBudget { out.budget = d.get("budget") }
        if let kb = k1Bound, kb.contains(where: { k1IsMaxUses($0.caveat) }) { out.k1Bound = kb }
        verdictEnforce(&out, required)
        // an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
        if !out.allow && hasBudget {
            var st: [String: String] = [:]
            for (n, c) in out.checks { st[n] = c.rawValue }
            if decisionOf(allow: false, checks: st, reasons: out.reasons) == "escalate" { out.budget = d.get("budget") }
        }
        if !out.allow && out.reasons.isEmpty { out.reasons = ["denied"] }
        if wantAssurance { out.assurance = refreshAssurance(report(finalChecks, names), out.checkNames.map { (name: $0, status: out.checks[$0]?.rawValue ?? "fail") }) }
        return out
    }

    /// `hashCanonical` of a value (the strict profile); a value outside it is a verifier fault (fail closed).
    private static func verdictHash(_ v: JSONValue) throws -> String {
        guard let h = IV.strictHash(v) else { throw InternalError(what: "canonicalize: value outside the strict JSON profile") }
        return h
    }

    private static func verdictK1JSON(_ k: K1Input, actionDigest: String?) -> JSONValue {
        var o: JObject = [:]
        o["pins"] = .array(k.pins.map { p in
            var m: JObject = ["label": .string(p.label), "class": .string(p.issuerClass), "pk": .string(p.pk)]
            if let x = p.pqPk { m["pq_pk"] = .string(x) }
            if let x = p.spiffeId { m["spiffe_id"] = .string(x) }
            return .object(m)
        })
        o["discharges"] = .array(k.discharges)
        if let a = actionDigest { o["action_digest"] = .string(a) }
        if let r = k.revokedDischarges { o["revoked_discharges"] = .array(r.map { .string($0) }) }
        if let s = k.spiffeId { o["spiffe_id"] = .string(s) }
        if let h = k.history { o["history"] = .array(h) }
        return .object(o)
    }

    private static func errMessageOf(_ e: Error) -> String { (e as? PCAProducerError)?.description ?? (e as? JSError)?.message ?? "\(e)" }
}
