import Foundation

/// The agent-facing half of the approval model: review an intended action against a facade agent (auto / deny / step-up with its goal
/// lineage and canonical approval render), batch review, and standing "approve this class of action for N hours" grants that downgrade a
/// matching step-up to auto. Nothing here authorizes anything and nothing is signed: the resource server's verifier stays the authority.
/// A review is the JSON the approval inbox renders: `{kind: "auto"}`, `{kind: "deny", reason}` or `{kind: "step_up", request}`.
public enum PCAApprovals {
    /// Builds the canonical approval render of an action (what the approver must be shown); a throw makes the review a deny.
    public typealias Renderer = (_ verb: String, _ resource: String, _ params: JSONValue?) throws -> JSONValue

    /// Options of `reviewAction`; every member is optional.
    public struct ReviewOptions {
        /// The clock (epoch ms); the wall clock when nil.
        public var now: Int64?
        /// Plaintext goal carried on a step-up request (shown to the approver).
        public var goal: String?
        /// Standing class approvals that can downgrade a step-up to auto.
        public var standing: [JSONValue]?
        /// Without a renderer (and without `insecureUnboundApproval`) a step-up is a deny: what the approver sees is what is signed.
        public var renderer: Renderer?
        /// The documented INSECURE opt-out: keep the behaviour of an unbound request (no render).
        public var insecureUnboundApproval: Bool
        public init(now: Int64? = nil, goal: String? = nil, standing: [JSONValue]? = nil, renderer: Renderer? = nil, insecureUnboundApproval: Bool = false) {
            self.now = now
            self.goal = goal
            self.standing = standing
            self.renderer = renderer
            self.insecureUnboundApproval = insecureUnboundApproval
        }
    }

    // ---- standing class approvals ----

    /// A standing approval `{id, verbs, resource?, grantedAt, ttlMs, by}` for the listed verbs, optionally narrowed to a resource pattern
    /// (`*` suffix = prefix match), valid from `now` for `ttlMs`.
    public static func approveClass(_ verbs: [String], ttlMs: Double, by: String, now: Int64? = nil, resource: String? = nil) -> JSONValue {
        let grantedAt = now ?? Int64(Date().timeIntervalSince1970 * 1000)
        let sorted = verbs.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        let id = Canonical.hashCanonical(.object(["d": .string("atlas-pca/class-approval/v1"), "verbs": .array(sorted.map { .string($0) }),
                                                  "resource": resource.map { .string($0) } ?? .null, "grantedAt": .int(grantedAt), "by": .string(by)]))
        var m: JObject = ["id": .string(id), "verbs": .array(verbs.map { .string($0) }), "grantedAt": .int(grantedAt), "ttlMs": PCAFacade.jsNum(ttlMs), "by": .string(by)]
        if let r = resource { m["resource"] = .string(r) }
        return .object(m)
    }

    private static func resourceMatches(_ pattern: String?, _ resource: String) -> Bool {
        guard let p = pattern, p != "*" else { return true }
        if p.hasSuffix("*") { return resource.hasPrefix(String(p.dropLast())) }
        return p == resource
    }

    /// True while the approval is in force (`grantedAt <= now < grantedAt + ttlMs`) and covers the verb and the resource. A malformed
    /// approval covers nothing.
    public static func classApprovalCovers(_ a: JSONValue, verb: String, resource: String, now: Double) -> Bool {
        let granted = PCAFacade.jsToNumber(a.get("grantedAt")), ttl = PCAFacade.jsToNumber(a.get("ttlMs"))
        if !(now.isFinite && granted.isFinite && ttl.isFinite && now >= granted && now < granted + ttl) { return false }
        guard let verbs = a.get("verbs")?.asArray, verbs.contains(.string(verb)) else { return false }
        return resourceMatches(a.get("resource")?.asString, resource)
    }

    /// Is (verb, resource) covered by ANY active standing approval?
    public static func coveredByAny(_ approvals: [JSONValue], verb: String, resource: String, now: Double) -> Bool {
        approvals.contains { classApprovalCovers($0, verb: verb, resource: resource, now: now) }
    }

    // ---- goal lineage ----

    private static func formatLimit(_ limit: PCAParsedLimit) -> String {
        let base = limit.unit == "usd" ? "$" + PCAFacade.jsNumberText(limit.amount) : PCAFacade.jsNumberText(limit.amount)
        guard let ms = limit.periodMs else { return base }
        let hours = Double(ms) / 3_600_000
        let period: String
        if hours.truncatingRemainder(dividingBy: 24) == 0 && hours >= 24 { period = PCAFacade.jsNumberText(hours / 24) + "d" }
        else if hours >= 1 { period = PCAFacade.jsNumberText(hours) + "h" }
        else { period = PCAFacade.jsNumberText((Double(ms) / 60_000 + 0.5).rounded(.down)) + "m" }
        return base + "/" + period
    }

    // shortcut: a parsed object has no insertion order, so the first four members are taken in the JS integer-keys-then-code-unit order, not
    // the producer's order; only the display line differs, when a params object has more than four members
    private static func summarizeParams(_ params: JSONValue?, _ amountField: String?) -> String? {
        guard let p = params, p.isObject else { return nil }
        if let f = amountField, let v = p.get(f) { return "\(f)=\(JS.toString(v))" }
        let keys = JSLoose.keys(p)
        if keys.isEmpty { return nil }
        return keys.prefix(4).map { k -> String in
            let v = p.get(k)
            switch v {
            case .object?, .array?, .null?: return "\(k)=\(JS.stringify(v ?? .null))"
            default: return "\(k)=\(JS.toString(v))"
            }
        }.joined(separator: ", ")
    }

    private static func node(_ kind: String, _ label: String, _ detail: String?) -> JSONValue {
        var n: JObject = ["kind": .string(kind), "label": .string(label)]
        if let d = detail { n["detail"] = .string(d) }
        return .object(n)
    }

    /// The goal lineage of one intended action ("you approved X because you asked to Y"): the grant's goal commitment, threaded through the
    /// delegated authority that admits the verb, down to the action. `goal` (plaintext) is checked against the commitment with the agent's
    /// salt: `goalVerified` says whether it opens it, so an inbox shows "unverified" rather than lie. Signs nothing.
    public static func buildGoalLineage(_ agent: PCAFacadeAgent, verb: String, resource: String, params: JSONValue?, goal: String?) -> JSONValue {
        let goalCommit = PCA.readEnvelope(agent.grant)?.get("goal_commit")?.asString ?? ""
        let verified: Bool
        if let g = goal, !goalCommit.isEmpty, !agent.goalSalt.isEmpty, let c = try? PCAIssue.goalCommit(goal: g, salt: agent.goalSalt) { verified = c == goalCommit } else { verified = false }
        let spec = agent.policy.actions.first { $0.verb == verb }
        let limit = agent.policy.limits.first { $0.verb == verb }?.limit

        let goalLabel = goal.map { "Pursue the goal: \u{201C}\($0)\u{201D}" } ?? "Pursue the grant\u{2019}s committed goal"
        let goalDetail: String? = goal != nil
            ? (verified ? "verified: this goal opens the signed grant commitment" : "unverified: the revealed goal does not open the grant commitment")
            : (!goalCommit.isEmpty ? "committed as \(goalCommit)" : nil)
        let authorityLabel = "Delegated authority to \(verb)" + (limit.map { " (up to \(formatLimit($0)))" } ?? "")
        let actionDetail = summarizeParams(params, spec?.amountField)
        let chain: [JSONValue] = [
            node("goal", goalLabel, goalDetail),
            node("authority", authorityLabel, (spec?.description).flatMap { $0.isEmpty ? nil : $0 }),
            node("action", "\(verb) \(resource)", actionDetail),
        ]
        let because = goal.map { "Approving \(verb) on \(resource) because you asked to \u{201C}\($0)\u{201D}." }
            ?? "Approving \(verb) on \(resource), authorized under the grant\u{2019}s committed goal."
        var out: JObject = ["goalCommit": .string(goalCommit), "goalVerified": .bool(verified), "chain": .array(chain), "because": .string(because)]
        if let g = goal { out["goal"] = .string(g) }
        return .object(out)
    }

    // ---- review ----

    private static func riskForReview(_ agent: PCAFacadeAgent, _ verb: String, _ params: JSONValue?) -> Double {
        let spec = agent.policy.actions.first { $0.verb == verb }
        if agent.policy.budgetModel == "dollars", let f = spec?.amountField {
            let amt = PCAFacade.jsToNumber(params?.get(f))
            if let kappa = IV.num(agent.policy.riskPolicy["kappa"]), amt.isFinite, kappa > 0 { return max(0, min(1, amt / kappa)) }
        }
        return max(0, min(1, spec?.blastRadius ?? 0.8))
    }

    private static func review(_ kind: String, _ reason: String? = nil) -> JSONValue {
        var m: JObject = ["kind": .string(kind)]
        if let r = reason { m["reason"] = .string(r) }
        return .object(m)
    }

    /// Review an intended action against the agent's grant. `{kind: auto}`: no human needed; `{kind: deny, reason}`: the grant's predicates or
    /// caveats forbid it, or no complete approval render could be made (fail closed); `{kind: step_up, request}`: admissible but needs a tier-2/3
    /// co-sign, unless a standing class approval covers it. A step-up carries the canonical render and its digest (without a renderer it is a
    /// deny unless `insecureUnboundApproval` is set).
    public static func reviewAction(_ agent: PCAFacadeAgent, verb: String, resource: String, params: JSONValue? = nil, _ opts: ReviewOptions = ReviewOptions()) -> JSONValue {
        do { return try reviewActionThrowing(agent, verb: verb, resource: resource, params: params, opts) }
        catch { return review("deny", "approval request cannot be made (fail closed): \((error as? JSError)?.message ?? "\(error)")") }
    }

    /// `reviewAction` as the reference runs it: a request whose parameters are outside the canonical profile (a number past 2^53) throws instead of being reviewed.
    public static func reviewActionThrowing(_ agent: PCAFacadeAgent, verb: String, resource: String, params: JSONValue? = nil, _ opts: ReviewOptions = ReviewOptions()) throws -> JSONValue {
        let now = opts.now ?? Int64(Date().timeIntervalSince1970 * 1000)
        let dr = agent.dryRun(verb: verb, resource: resource, params: params, now: now)
        if !dr.allowed { return review("deny", dr.reason ?? "denied by policy") }
        guard let tier = dr.t, tier != 1 else { return review("auto") }
        if let s = opts.standing, coveredByAny(s, verb: verb, resource: resource, now: Double(now)) { return review("auto") }
        var render: JSONValue?
        var renderDigest: String?
        if opts.renderer == nil && !opts.insecureUnboundApproval {
            return review("deny", "approval render required: pass a renderer (renderersFromDefs from the pinned action definitions), or insecureUnboundApproval: true")
        }
        if let r = opts.renderer {
            do {
                let rendered = try r(verb, resource, params)
                guard let digest = Approval.renderDigest(rendered) else {
                    return review("deny", "approval render failed (fail closed): approvalRenderDigest: \(Approval.renderShapeError(rendered) ?? "unknown")")
                }
                render = rendered
                renderDigest = digest
            } catch {
                return review("deny", "approval render failed (fail closed): \(error)")
            }
        }
        let goalCommit = PCA.readEnvelope(agent.grant)?.get("goal_commit")?.asString ?? ""
        let lineage = buildGoalLineage(agent, verb: verb, resource: resource, params: params, goal: opts.goal)
        let id = Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(.object(["d": .string("atlas-pca/stepup/v1"), "verb": .string(verb), "resource": .string(resource), "params": params ?? .null, "at": .int(now)]))))
        var request: JObject = ["id": .string(id), "verb": .string(verb), "resource": .string(resource), "tier": .int(Int64(tier)),
                                "reason": .string(dr.reason ?? "requires tier \(tier) co-sign"), "goalCommit": .string(goalCommit), "lineage": lineage,
                                "r": PCAFacade.jsNum(riskForReview(agent, verb, params)), "requestedAt": .int(now)]
        if let p = params { request["params"] = p }
        if let g = opts.goal { request["goal"] = .string(g) }
        if let r = render, let d = renderDigest { request["render"] = r; request["renderDigest"] = .string(d) }
        return .object(["kind": .string("step_up"), "request": .object(request)])
    }

    /// Flatten a lineage to plain text lines (for log-free text surfaces): `label — detail` for a hop with a detail, else its label (null when
    /// a hop has none). Throws when the lineage has no chain list.
    public static func describeGoalLineage(_ lineage: JSONValue?) throws -> [JSONValue] {
        guard let l = lineage, l.isObject else { throw JSError("describeGoalLineage: lineage required") }
        guard let chain = l.get("chain")?.asArray else { throw JSError("describeGoalLineage: chain must be a list") }
        return try chain.map { hop in
            if hop == .null { throw JSError("describeGoalLineage: a hop must not be null") }
            guard hop.isObject else { return .null } // a primitive has no label or detail
            if JS.truthy(hop.get("detail")) { return .string("\(JS.toString(hop.get("label"))) \u{2014} \(JS.toString(hop.get("detail")))") }
            return hop.get("label") ?? .null
        }
    }

    /// Narrow a capability to expire `ttlMs` after `now` by appending an `expires` caveat signed by the holder: caveats are conjunctive and
    /// append-only, so this can only RESTRICT. Throws when the expiry is not finite.
    public static func timeBox(_ parent: JSONValue, holder: PCASuiteKey, ttlMs: Double, now: Double) throws -> JSONValue {
        let at = now + ttlMs
        guard at.isFinite else { throw JSError("timeBox: the expiry must be a finite number") }
        return try PCAIssue.attenuate(parent: parent, added: [.object(["type": .string("expires"), "at": PCAFacade.jsNum(at)])], signer: holder)
    }

    /// Record a human's decision on a request (pure data for the audit trail): `{requestId, decision, by, at}`.
    public static func recordDecision(_ request: JSONValue, decision: String, by: String, at: Double? = nil) -> JSONValue {
        .object(["requestId": request.get("id") ?? .null, "decision": .string(decision), "by": .string(by),
                 "at": PCAFacade.jsNum(at ?? Double(Int64(Date().timeIntervalSince1970 * 1000)))])
    }

    /// Apply a human co-sign to the trust budget `{B, tau, asOf?}`: a partial recharge (`B <- min(bMax, B + rho)`) by default, or a recharge to `bMax`
    /// with `full`; `tau` and `asOf` become `now`. The only thing that raises the budget, so the safety bound holds between two co-signs.
    public static func applyCosign(_ budget: JSONValue, policy: JSONValue, now: Double, full: Bool = false) -> JSONValue {
        let nz = Risk.nz
        let bMax = nz(JS.toNumber(policy.get("bMax"))), rho = nz(JS.toNumber(policy.get("rho")))
        let b = full ? bMax : PCARiskBudgets.jsMin(bMax, JS.toNumber(budget.get("B")) + rho)
        return .object(["B": PCARiskBudgets.num(b), "tau": PCARiskBudgets.num(now), "asOf": PCARiskBudgets.num(now)])
    }

    /// One intended call of `batchReview`.
    public struct IntendedCall {
        public var verb: String
        public var resource: String
        public var params: JSONValue?
        public init(verb: String, resource: String, params: JSONValue? = nil) {
            self.verb = verb
            self.resource = resource
            self.params = params
        }
    }

    /// Review a batch of intended actions: the inbox's "N actions waiting".
    public static func batchReview(_ agent: PCAFacadeAgent, _ calls: [IntendedCall], _ opts: ReviewOptions = ReviewOptions()) -> [JSONValue] {
        calls.map { reviewAction(agent, verb: $0.verb, resource: $0.resource, params: $0.params, opts) }
    }

    /// The step-up requests among a batch of reviews (what the approver actually sees).
    public static func pendingRequests(_ reviews: [JSONValue]) -> [JSONValue] {
        reviews.compactMap { $0.get("kind") == .string("step_up") ? $0.get("request") : nil }
    }
}
