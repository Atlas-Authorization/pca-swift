import Foundation

/// The deterministic Policy VM (the reference's `decide` and `deriveDecideInput`): whether the guardian share may be released for an
/// action, the threshold and proof it then needs, the risk, the budget admission and the budget afterwards. Inputs and results are the
/// reference's objects as JSON trees. `decide` is total: any fault is a denial carrying a reason (fail closed). It throws nothing.
/// `deriveDecideInput` throws where the reference throws (no stored grant in the context).
///
/// Input members of `decide`: grant, pqPins?, trustedRoot?, chain?, action ({action: {verb, resource, params, reversibility_class},
/// subject?, env?, toolBinding?}), plan?, risk, budget ({B, tau, asOf?}), now, nodeId?, goalNodeId?, caveatContext?
/// (recentActionTimes, reversibilityClass, blastRadius, delegationDepth), ageHorizonMs?, rFloor?, chainVerified?, k1? (the caveat-language
/// input: pins, discharges, narrow, action_digest, revoked_discharges, spiffe_id, history).
/// Result members: releaseGuardianShare, requiredThreshold {t, proof, optimisticAllowed}, r, admit, needStepUp, reasons, budget, k1Bound?.
///
/// A budget whose B or tau is not a finite number is refused (the reference computes with NaN and still releases: native stricter).
public enum PCAPolicyVm {
    /// A reference TypeError (caught by `decide` and turned into a denial).
    private struct Fault: Error { let message: String }

    /// Classes recognised as non-irreversible (so the optimistic fast path may be offered); anything else is treated as irreversible.
    private static let FAST_PATH: Set<String> = ["reversible", "rate_limited", "costly"]

    private static func num(_ d: Double) -> JSONValue { d == d.rounded() && abs(d) <= Double(Canonical.MAX_SAFE) ? .int(Int64(d)) : .double(d) }

    private static func denied(_ reason: String, _ budget: JSONValue?) -> JSONValue {
        var o: JObject = [
            "releaseGuardianShare": .bool(false),
            "requiredThreshold": .object(["t": .int(3), "proof": .string("strong"), "optimisticAllowed": .bool(false)]),
            "r": .int(1), "admit": .bool(false), "needStepUp": .bool(true), "reasons": .array([.string(reason)]),
        ]
        if let b = budget { o["budget"] = b }
        return .object(o)
    }

    /// `x.toFixed(3)` for r in [0, 1]: JavaScript rounds an exact tie up, printf rounds it to even.
    private static func toFixed3(_ r: Double) -> String {
        let p = r * 1000
        if p.truncatingRemainder(dividingBy: 1) == 0.5 && fma(r, 1000, -p) == 0 {
            let q = Int64(p + 0.5)
            let frac = String(q % 1000)
            return "\(q / 1000)." + String(repeating: "0", count: 3 - frac.count) + frac
        }
        return String(format: "%.3f", r)
    }

    private static func withoutK1(_ cs: [JSONValue]) -> [JSONValue] { cs.filter { !PCA.isK1Caveat($0) } }

    /// The class an action is bound to: its own, else the class of the plan node it names (nodeId), else unknown.
    private static func resolveReversibility(_ inner: JSONValue?, _ plan: JSONValue?, _ nodeId: JSONValue?) throws -> JSONValue? {
        if let own = inner?.get("reversibility_class"), !own.isNull { return own }
        guard case let .string(nid)? = nodeId else { return nil }
        guard let p = plan, !p.isNull else { return nil }
        guard case let .array(ns) = p else { throw Fault(message: "plan.find is not a function") }
        for n in ns {
            if n.isNull { throw Fault(message: "cannot read properties of null (reading 'id')") }
            if IV.same(n.get("id")?.asString, nid) { return n.get("reversibility_class") }
        }
        return nil
    }

    private static func k1Input(_ v: JSONValue?) -> K1Input? {
        guard case let .object(o)? = v else { return nil }
        return K1Input(pins: (o["pins"]?.asArray ?? []).compactMap { DischargePin.fromJSON($0) },
                       discharges: o["discharges"]?.asArray ?? [],
                       narrow: o["narrow"],
                       actionDigest: o["action_digest"]?.asString,
                       revokedDischarges: o["revoked_discharges"]?.asArray?.compactMap { $0.asString },
                       spiffeId: o["spiffe_id"]?.asString,
                       history: o["history"]?.asArray)
    }

    /// Decides `input`. Never throws.
    public static func decide(_ input: JSONValue) throws -> JSONValue {
        var fallback: JSONValue = .object(["B": .int(0), "tau": .int(0)])
        if let b = input.get("budget"), !b.isNull { fallback = b }
        do {
            return try decideInner(input)
        } catch let e as Fault {
            return denied("policy evaluation error (fail closed): \(e.message)", fallback)
        } catch let e as JSError {
            return denied("policy evaluation error (fail closed): \(e.message)", fallback)
        } catch {
            return denied("policy evaluation error (fail closed): unknown", fallback)
        }
    }

    private static func decideInner(_ input: JSONValue) throws -> JSONValue {
        let budgetIn = input.get("budget")
        let grant = input.get("grant") ?? .null
        guard let envV = PCA.readEnvelope(grant), case let .object(env) = envV else { return denied("grant carries no valid envelope", budgetIn) }
        guard let nowV = input.get("now"), let now = ToolSchema.fin(nowV) else { return denied("invalid decision time", budgetIn) }
        let chainV = input.get("chain")

        // an unverified capability chain is DENIED here: unless the caller vouches it was verified, decide re-verifies it
        if input.get("chainVerified") != .bool(true) {
            var toVerify: [JSONValue] = [grant]
            if case let .array(c)? = chainV, !c.isEmpty { toVerify = c }
            var pins: [String: String]?
            if case let .object(po)? = input.get("pqPins") {
                var m: [String: String] = [:]
                for (k, v) in po { m[k.s] = v.asString ?? "" } // a pin that is not a string never equals a key: it refuses
                pins = m
            }
            var trusted: JSONValue?
            if case .object? = input.get("trustedRoot") { trusted = input.get("trustedRoot") }
            if let why = Capability.verifyChain(toVerify, expectedRootIssuer: grant.get("issuer")?.asString, pqPins: pins, trustedRoot: trusted) {
                return denied("capability chain unverified: \(why)", budgetIn)
            }
        }

        var reasons: [String] = []
        let action = input.get("action")
        let actionCtx: JSONValue = action ?? .null
        let innerAction = action?.get("action")
        let regex = SafeRegex.Budget() // ONE regex work budget for the whole decision

        // 1. semantic predicates (default deny)
        let predicatesWhy = PCA.envelopePredicatesError(env["predicates"], actionCtx, regex)
        let prOk = predicatesWhy == nil
        if let w = predicatesWhy { reasons.append(w) }

        // 2. envelope caveats
        let riskObj = input.get("risk")?.asObject
        let nodeId = input.get("nodeId")
        var cctx: JObject = ["now": nowV]
        if let b = riskObj?["blastRadius"] { cctx["blast_radius"] = b }
        if let rc = try resolveReversibility(innerAction, input.get("plan"), nodeId) { cctx["reversibility_class"] = rc }
        if let over = input.get("caveatContext")?.asObject {
            for (camel, snake) in [("now", "now"), ("blastRadius", "blast_radius"), ("reversibilityClass", "reversibility_class"),
                                   ("delegationDepth", "delegation_depth"), ("recentActionTimes", "recent_action_times")] {
                if let v = over[JKey(camel)] { cctx[JKey(snake)] = v }
            }
        }
        if let ia = innerAction { cctx["action"] = ia }
        let tool = innerAction?.get("verb")?.asString ?? ""
        var args: JSONValue = .object([:])
        if case .object? = innerAction?.get("params") { args = innerAction?.get("params") ?? args }
        let call = PCA.ToolCall(tool: tool, args: args, toolSignatureDigest: action?.get("toolBinding")?.asString)

        var chainOk = true
        var extra: [JSONValue] = []
        var leafHop: JSONValue = grant
        if let cv = chainV {
            if case let .array(c) = cv, let last = c.last {
                cctx["delegation_depth"] = .int(Int64(c.count - 1))
                guard case let .array(lc)? = last.get("caveats") else { throw Fault(message: "cannot read properties of undefined (reading 'slice')") }
                extra = Array(lc.dropFirst(grant.get("caveats")?.asArray?.count ?? 0))
                leafHop = last
            } else {
                chainOk = false
                reasons.append("delegation chain is empty or malformed")
            }
        }
        let ctx = JSONValue.object(cctx)
        let ecv = PCA.evaluateAgentCaveats(env["caveats"], ctx, actionCtx, call, regex)
        if !ecv.ok { reasons.append("caveat(s) not satisfied: \(ecv.failed.joined(separator: ", "))") }

        // root caveats outside the envelope are signed authority too; the caveat-language (K1) types are evaluated over the whole chain
        let k1v = input.get("k1")
        var useK1 = k1v?.get("narrow") != nil
        if case let .array(lcs)? = leafHop.get("caveats"), lcs.contains(where: { PCA.isK1Caveat($0) }) { useK1 = true }
        var k1: K1Result?
        if useK1 {
            k1 = PCA.evaluateK1(grant: grant, chain: chainV, k1: k1Input(k1v), now: IV.int(nowV) ?? Int64.max, action: innerAction)
        }
        var rootList = PCA.rootCaveats(grant)
        if case let .array(l)? = rootList { rootList = .array(withoutK1(l)) }
        let rcv = PCA.evaluateAgentCaveats(rootList, ctx, actionCtx, call, regex)
        if !rcv.ok { reasons.append("root caveat(s) not satisfied: \(rcv.failed.joined(separator: ", "))") }
        let cvOk = ecv.ok && rcv.ok
        let dcv = PCA.evaluateAgentCaveats(.array(withoutK1(extra) + (k1?.plain ?? [])), ctx, actionCtx, call, regex)
        var dcvOk = dcv.ok
        if !dcv.ok { reasons.append("delegated caveat(s) not satisfied: \(dcv.failed.joined(separator: ", "))") }
        if let k = k1, !k.ok {
            dcvOk = false
            for (i, r) in k.reasons.enumerated() { reasons.append("caveat language: \(k.failed[i]): \(r)") }
        }

        // 3. risk
        guard let budget = Risk.Budget(json: budgetIn) else { throw Fault(message: "budget is not a trust budget") }
        guard let pol = env["risk_policy"]?.asObject, let th1 = ToolSchema.fin(pol["theta1"]), let th2 = ToolSchema.fin(pol["theta2"]),
              let kappa = ToolSchema.fin(pol["kappa"]), let lambda = ToolSchema.fin(pol["lambda"]) else { throw Fault(message: "risk_policy is not valid") }
        let leaked = Risk.leak(budget, now: now, lambda: lambda)
        var inputs = Risk.WORST
        var missing: [String] = []
        for (i, k) in Risk.KEYS.enumerated() {
            let v = ToolSchema.fin(riskObj?[JKey(k)])
            if let v = v { inputs[i] = v }
            if k != "age" && v == nil { missing.append(k) }
        }
        let plan = input.get("plan")
        if JS.truthy(plan) && riskObj?["semanticDistance"] == nil {
            var goal = input.get("goalNodeId")
            if goal == nil || goal!.isNull {
                if case let .array(pa)? = plan { goal = pa.last?.get("id") } else { goal = nil }
            }
            if let nid = nodeId, let g = goal {
                guard case let .array(pa)? = plan else { throw Fault(message: "plan is not iterable") }
                if case let .string(a) = nid, case let .string(b) = g { inputs[0] = Risk.planGeodesic(pa, from: a, to: b) } else { inputs[0] = 1 }
            } else {
                inputs[0] = 1
            }
            missing.removeAll { $0 == "semanticDistance" }
        }
        if riskObj?["age"] == nil {
            let hv = input.get("ageHorizonMs")
            let horizon: Double = hv == nil ? 3_600_000 : (IV.num(hv) ?? .nan)
            inputs[5] = Risk.ageSinceTouch(leaked, now: now, horizonMs: horizon)
        }
        if !missing.isEmpty { reasons.append("risk input(s) missing, assumed worst case: \(missing.joined(separator: ", "))") }
        var rFloor = 0.0
        if let rf = ToolSchema.fin(input.get("rFloor")) { rFloor = min(1, max(0, rf)) }
        let r = max(Risk.riskScore(inputs.map { Optional($0) }, weights: pol["weights"]?.asObject ?? [:]), rFloor)

        // Reversibility fails CLOSED for the optimistic fast path: only a recognised non-irreversible class is eligible.
        let irreversible: Bool
        if case let .string(c)? = cctx["reversibility_class"] { irreversible = !FAST_PATH.contains(c) } else { irreversible = true }
        let rt = Risk.requiredThreshold(r, theta1: th1, theta2: th2, irreversible: irreversible)

        // 4. budget admission
        let cost = Risk.cost(r, kappa: kappa)
        let adm = Risk.admit(t: Risk.requiredThreshold(r, theta1: th1, theta2: th2, irreversible: false).t, covers: Risk.covers(leaked.b, cost))
        if adm.needStepUp {
            reasons.append(rt.t < 3 && adm.t == 3 ? "trust budget depleted: human recharge required"
                : "risk \(toFixed3(r)) exceeds auto threshold: step-up to t=\(adm.t)")
        }

        // 5. guardian release: policy AND caveats AND a well-formed chain; the human / step-up path stays available otherwise
        let release = prOk && cvOk && dcvOk && chainOk
        let thr = Risk.escalate(rt, minT: adm.t)
        let out = release && adm.metered ? Risk.debit(leaked, cost) : leaked
        var res: JObject = [
            "releaseGuardianShare": .bool(release),
            "requiredThreshold": .object(["t": .int(Int64(thr.t)), "proof": .string(thr.proof), "optimisticAllowed": .bool(thr.optimisticAllowed)]),
            "r": num(r),
            "admit": .bool(release && adm.admit),
            "needStepUp": .bool(release ? adm.needStepUp : true),
            "reasons": .array(reasons.map { .string($0) }),
            "budget": .object(["B": num(out.b), "tau": num(out.tau), "asOf": num(out.asOf ?? out.tau)]),
        ]
        if let k = k1 {
            res["k1Bound"] = .array(k.bound.map { .object(["caveat": $0.caveat, "hop": .int(Int64($0.hop)), "cap_hash": .string($0.capHash)]) })
        }
        return .object(res)
    }

    /// Assembles a `decide` input from a PCActn plus the resource server's context, so caller and verifier derive the action, node id and
    /// chain identically. `ctx`: grant (REQUIRED: the verifier's OWN stored grant, never the artifact's chain root; it is also the chain's
    /// trusted root), plan?, params?, risk, budget, chain?, now, pqPins?, goalNodeId?, subject?, env?, caveatContext?, ageHorizonMs?.
    public static func deriveDecideInput(_ pcactn: JSONValue, _ ctx: JSONValue) throws -> JSONValue {
        // an array is an object to the reference: it passes here and `decide` then denies it
        guard ctx.get("grant")?.isObject == true || ctx.get("grant")?.isArray == true else {
            throw JSError("deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant", code: "grant_required")
        }
        if pcactn.isNull { throw JSError("Cannot read properties of null (reading 'cap_chain')") }
        func nn(_ v: JSONValue?) -> JSONValue? { v?.isNull == true ? nil : v }
        let act = pcactn.get("action")
        var inner: JObject = [:]
        for k in ["verb", "resource"] { if let v = act?.get(k) { inner[JKey(k)] = v } }
        inner["params"] = nn(ctx.get("params")) ?? .object([:])
        if let v = act?.get("reversibility_class") { inner["reversibility_class"] = v }
        var actionCtx: JObject = ["action": .object(inner)]
        if JS.truthy(ctx.get("subject")), let v = ctx.get("subject") { actionCtx["subject"] = v }
        if JS.truthy(ctx.get("env")), let v = ctx.get("env") { actionCtx["env"] = v }
        var out: JObject = ["grant": ctx.get("grant") ?? .null, "trustedRoot": ctx.get("grant") ?? .null]
        if let v = ctx.get("pqPins") { out["pqPins"] = v }
        if let v = nn(ctx.get("chain")) ?? nn(pcactn.get("cap_chain")) { out["chain"] = v }
        out["action"] = .object(actionCtx)
        // `p.plan.node_id`: an artifact without a plan member has no node to read (the reference throws)
        guard let planRef = pcactn.get("plan"), !planRef.isNull else { throw JSError("Cannot read properties of undefined (reading 'node_id')") }
        if let v = planRef.get("node_id") { out["nodeId"] = v }
        for k in ["plan", "goalNodeId", "risk", "budget", "now", "caveatContext", "ageHorizonMs"] { if let v = ctx.get(k) { out[JKey(k)] = v } }
        return .object(out)
    }
}
