import Foundation

// `PCA.authorize`: the full authorization pipeline for a Swift resource server or tool guard (0.5, additive).
//
// `PCA.verify` answers "is this a validly signed PCActn for this audience". `authorize` answers "may THIS operation run
// now", in the same order as the TypeScript `authorize()`:
//
//   1. configuration: `audience`, `resolveGrant`, `stateStore` and `isRevoked` are REQUIRED, and the call names the
//      `operation` it will execute (verb, resource, params). A missing one denies with its name.
//   2. the core checks (`PCA.verify`), then `revocation` (`isRevoked`), then `zk_compliance` (a carried proof cannot be
//      verified here: fail closed).
//   3. `operation`: the signed `action.verb` / `action.resource` equal the operation's, and the signed
//      `action.params_digest` opens to exactly the operation's params. Those params are what the predicates and caveats
//      read.
//   4. `grant_ref`, `params_digest`, `plan_root_authorized`, `attestation` (a grant whose `agent_binding` pins the agent
//      needs an attestation verifier this SDK does not have: fail closed), `reversibility`.
//   5. policy: the envelope predicates (default deny), the envelope caveats and the root caveats outside the envelope
//      (`policy`), and the caveats delegation hops appended (`delegated_caveats`). Unknown caveat types fail closed.
//   6. replay: only when everything above passes, the counter is consumed through `stateStore.claim(key:counter:)`.
//
// Not ported from the TypeScript policy VM: the risk score, trust budget, threshold co-signature, revocation epochs and
// liveness beacons. Never throws or traps on its inputs: an internal error is a denial.

/// The replay store: ONE atomic operation per action.
///
/// `claim(key:counter:)` must, atomically: if a counter is stored for `key` and `counter` is not strictly greater, return
/// `ClaimResult(ok: false, lastCounter: stored)`; otherwise store `counter` and return `ClaimResult(ok: true)`. A claim
/// that cannot decide must return `ok: false` or throw (`authorize` then denies).
public protocol PCAStateStore {
    func claim(key: String, counter: Int64) throws -> ClaimResult
    /// TTL'd consume-once (K1 `max_uses` slots): true iff `key` has no live record (one whose `retainUntil >= now`); the store
    /// then remembers it at least until `retainUntil` (the maximum of the horizons it has seen). Throws for an empty key or
    /// `retainUntil < now` (never true) and leaves nothing behind. The default falls back to `claim(key:counter: 1)`, which
    /// never forgets (correct, but the slot does not expire); a durable store should override it with an atomic
    /// insert-or-update-if-expired and prune expired rows.
    func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool
}

/// Thrown by `consumeOnce` for an empty key or a retention horizon before `now`.
public struct PCAStoreArgumentError: Error, Equatable, Sendable {}

extension PCAStateStore {
    public func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool {
        if key.isEmpty || retainUntil < now { throw PCAStoreArgumentError() }
        return try claim(key: key, counter: 1).ok
    }
}

/// What `PCAStateStore.claim` returns. `ok` is true only when THIS call consumed the counter.
public struct ClaimResult: Equatable, Sendable {
    public let ok: Bool
    public let lastCounter: Int64?
    public init(ok: Bool, lastCounter: Int64? = nil) {
        self.ok = ok
        self.lastCounter = lastCounter
    }
}

/// A replay store that can also report a holder's highest admitted counter (the head of its history). Required to admit an
/// escalation answer: the answer is bound to that head (`PCA.escalationHistoryHead`).
public protocol PCALastStore: PCAStateStore {
    func last(key: String) throws -> Int64?
}

/// In-process replay store (one lock). Correct for ONE process only; several processes or hosts need a shared store with
/// an atomic conditional write (see the README).
public final class MemoryStateStore: PCALastStore, @unchecked Sendable {
    private var heads: [String: Int64] = [:]
    private var once: [String: Int64] = [:] // key -> retain_until
    private let lock = NSLock()

    public init() {}

    public func last(key: String) -> Int64? {
        lock.lock()
        defer { lock.unlock() }
        return heads[key]
    }

    public func claim(key: String, counter: Int64) -> ClaimResult {
        lock.lock()
        defer { lock.unlock() }
        if let l = heads[key], !(counter > l) { return ClaimResult(ok: false, lastCounter: l) }
        heads[key] = counter
        return ClaimResult(ok: true)
    }

    public func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool {
        if key.isEmpty || retainUntil < now { throw PCAStoreArgumentError() }
        lock.lock()
        defer { lock.unlock() }
        once = once.filter { $0.value >= now } // prune the expired
        if let u = once[key] {
            once[key] = max(u, retainUntil)
            return false
        }
        once[key] = retainUntil
        return true
    }
}

extension PCA {
    /// The `plan` mode that accepts a one-node plan whose node is exactly the operation.
    public static let SINGLE_STEP = "single-step"

    /// The checks that must be `pass` (not merely "not failed"). `require` can add names, never remove these.
    public static let DEFAULT_REQUIRED_CHECKS = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound",
                                                 "operation", "params_digest", "policy"]

    /// A failing one of these is an authentication failure (401); anything else is insufficient authority (403).
    static let AUTHN_CHECKS = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature", "malformed", "grant_ref"]

    /// The order the core verifier evaluates its checks in (the decisive reason follows it).
    static let CORE_CHECK_ORDER = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature",
                                   "counter_format", "intent", "schema", "intent_session", "layers", "accumulators", "map", "facts", "provenance", "classes"]

    /// The operation the handler or tool WILL execute, from the server's own routing and parsed input, never from the
    /// PCActn. `params` must be a JSON object.
    public struct Operation: Equatable, Sendable {
        public var verb: String
        public var resource: String
        public var params: JSONValue
        public init(verb: String, resource: String, params: JSONValue) {
            self.verb = verb
            self.resource = resource
            self.params = params
        }
        var isValid: Bool { !verb.isEmpty && !resource.isEmpty && params.isObject }
    }

    /// The operation an allowing decision is bound to. `id` is the digest of the presented PCActn.
    public struct AuthorizedOperation: Equatable, Sendable {
        public let verb: String
        public let resource: String
        public let paramsDigest: String
        public let id: String
        public init(verb: String, resource: String, paramsDigest: String, id: String) {
            self.verb = verb
            self.resource = resource
            self.paramsDigest = paramsDigest
            self.id = id
        }
    }

    /// `pass`, `fail` or `not-enforced`.
    public enum CheckStatus: String, Sendable {
        case pass
        case fail
        case notEnforced = "not-enforced"
    }

    /// A tool call as a `tool_schema` caveat judges it: the tool name, its arguments (a JSON object) and, optionally, the
    /// tool signature digest the PCActn signed (`tool_binding`).
    public struct ToolCall: Sendable {
        public var tool: String
        public var args: JSONValue
        public var toolSignatureDigest: String?
        public init(tool: String, args: JSONValue, toolSignatureDigest: String? = nil) {
            self.tool = tool
            self.args = args
            self.toolSignatureDigest = toolSignatureDigest
        }
    }

    /// What the resource server knows about the request beyond the operation (all optional).
    public struct AuthorizeContext {
        /// The principal-authorized plan (plan nodes `{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}`).
        public var plan: [JSONValue]?
        /// Must be true for `plan` to authorize the PCActn's plan root.
        public var planAuthorized: Bool
        /// The predicate context's `subject` and `env`.
        public var subject: JSONValue?
        public var env: JSONValue?
        /// Read by `max_blast_radius` and `rate` caveats.
        public var blastRadius: Double?
        public var recentActionTimes: [Double]?
        /// The server's authoritative reversibility class: the agent may declare a stricter one, never a weaker one.
        public var reversibilityClass: String?
        public init(plan: [JSONValue]? = nil, planAuthorized: Bool = false, subject: JSONValue? = nil, env: JSONValue? = nil,
                    blastRadius: Double? = nil, recentActionTimes: [Double]? = nil, reversibilityClass: String? = nil) {
            self.plan = plan
            self.planAuthorized = planAuthorized
            self.subject = subject
            self.env = env
            self.blastRadius = blastRadius
            self.recentActionTimes = recentActionTimes
            self.reversibilityClass = reversibilityClass
        }
    }

    /// The Intent Layer v2 verifier context: a fixed value, or computed per PCActn.
    public enum IntentV2Source {
        case context(IntentV2Context)
        case provider((JSONValue) throws -> IntentV2Context?)
    }

    /// K5 workflow admission (C-308), the verifier-pinned half: `principal` signs the workflow commitment, `rsSigner` signs the step
    /// receipts (a key named inside either is never trusted). With `required`, a call that carries no `workflowStep` is refused.
    public struct WorkflowGate: Sendable {
        public var principal: String
        public var rsSigner: String
        public var required: Bool
        public init(principal: String, rsSigner: String, required: Bool = false) {
            self.principal = principal
            self.rsSigner = rsSigner
            self.required = required
        }
    }

    /// The workflow step a call is: the signed commitment, the receipts so far (a JSON array), the step id.
    public struct WorkflowCall: Sendable {
        public var commitment: JSONValue
        public var receipts: JSONValue
        public var step: String
        public var units: [String: String]
        public var goalDigest: String?
        public init(commitment: JSONValue, receipts: JSONValue, step: String, units: [String: String] = [:], goalDigest: String? = nil) {
            self.commitment = commitment
            self.receipts = receipts
            self.step = step
            self.units = units
            self.goalDigest = goalDigest
        }
    }

    /// The inputs of `authorize`. `operation`, `audience`, `resolveGrant`, `stateStore` and `isRevoked` are required; they
    /// are optional here only so that a missing one is refused with its name instead of being a build error.
    public struct AuthorizeInput {
        /// What the handler WILL execute.
        public var operation: Operation?
        /// This resource server's id; the PCActn's signed `aud` must equal it.
        public var audience: String?
        /// `grant_ref -> grant` from your own store (nil = unknown grant; throwing denies).
        public var resolveGrant: ((String) throws -> JSONValue?)?
        /// The replay store.
        public var stateStore: (any PCAStateStore)?
        /// `(pcactn, grant) -> revoked?`. Only `false` passes; `true`, `nil` or a thrown error denies.
        public var isRevoked: ((JSONValue, JSONValue) throws -> Bool?)?
        /// Epoch milliseconds (default: the wall clock).
        public var now: Int64?
        /// `PCA.SINGLE_STEP` accepts a one-node plan whose node is exactly the operation. Otherwise `context` must return
        /// the principal-authorized `plan` with `planAuthorized: true`.
        public var plan: String?
        /// `(pcactn) -> context` (throwing denies).
        public var context: ((JSONValue) throws -> AuthorizeContext?)?
        /// Forwarded to the core verifier.
        public var intentPolicy: IntentPolicy?
        /// Forwarded to the core verifier; its `params` default to the operation's.
        public var intentV2: IntentV2Source?
        public var allowedSuites: [String]?
        /// Extra check names that must pass (the defaults always apply).
        public var require: [String]
        /// The pinned keys whose `EscalationAnswer`s count (empty: every `escalate` is refused). Needs a `PCALastStore`.
        public var escalationPrincipals: [PinnedSigner]
        /// The principal's signed answer for THIS action (parsed JSON; header `PCA-Escalation-Answer` via
        /// `PCA.escalationAnswer(fromHeader:)`, or the body member `escalation_answer`).
        public var escalationAnswer: JSONValue?
        /// K7: recompute H(R), the canonical approval render digest, from the executed params and the verifier's own definition
        /// (`Approval.render` + `Approval.renderDigest`); nil = none could be derived. By default an answer is admitted only over a
        /// recomputed render and must be signed over exactly it.
        public var escalationRender: ((JSONValue) -> String?)? = nil
        /// The documented INSECURE opt-out: accept escalation answers with no recomputed render (an answer that carries a render is
        /// still refused when none was recomputed).
        public var insecureUnboundApproval: Bool = false
        /// Revocation staleness (T9; off when nil or empty): caps how old the revocation state may be by the action's effective
        /// reversibility class (the stricter of `context.reversibilityClass` and the signed class; missing or unknown counts as
        /// irreversible). It needs `revocationState` (the state source) and, for a signed epoch, `guardianPublic` (plus
        /// `guardianPins` for a post-quantum guardian). The result is the required `freshness` check; `isRevoked` stays the
        /// revocation answer and works unchanged.
        public var revocationStaleness: RevocationStalenessPolicy?
        /// `(pcactn, grant) -> state` (throwing denies the `freshness` check).
        public var revocationState: ((JSONValue, JSONValue) throws -> RevocationState?)?
        /// The pinned Ed25519 identity (b64u) of the epoch guardian.
        public var guardianPublic: String?
        /// Which capability ids need a non-membership proof when staleness is on (default: every `id` in the PCActn's `cap_chain`).
        public var revocationIds: ((JSONValue) -> [String])?
        /// `(pcactn, id) -> proof` `{size, lo?, hi?}` against the epoch's root. Missing (no source, or nil) denies the `freshness` check.
        public var revocationProof: ((JSONValue, String) -> JSONValue?)?
        /// `{Ed25519 b64u: ML-DSA public key b64u}` for a post-quantum or hybrid guardian.
        public var guardianPins: [String: String]?
        /// Plan lifecycle (T10): the plan registry. When the context names no plan, the plan the PCActn commits to (`plan.root`) is looked
        /// up for this grant: its nodes and whether it is executable now feed `plan_root_authorized`, and a plan that is not executable
        /// (unknown, not yet authorized, expired, revoked) also fails `plan_state` with the registry's reason.
        public var plans: PlanRegistry?
        /// A high-assurance policy (T8): when the evidence behind the passing checks is weaker, missing, unlabelled, awaiting-audit, degraded or
        /// unsupported, the `assurance` check fails and the request is denied before any replay state is written. `assuranceHooks` carries
        /// the labels of the verifier's hooks (the report never trusts presented evidence). Every result carries the `assurance` report
        /// whether or not a requirement is set.
        public var requireAssurance: AssuranceRequirement?
        public var assuranceHooks: AssuranceHooks
        /// Caveat language v2 (K1; off unless set): the verifier's discharge-issuer pins and the discharges / narrow block /
        /// SPIFFE ID / history it was given (`K1Input`). `actionDigest` is ignored: the verifier computes it from the PCActn.
        /// Without it a chain carrying a K1 caveat is refused ("the caveat language is not configured (no k1 input)").
        public var k1: K1Input?
        /// Where `max_uses` is spent (an atomic first-use claim per slot; share and persist it across processes). A chain that
        /// carries a `max_uses` caveat is refused when this is nil.
        public var usesStore: (any PCAStateStore)?
        /// Forwarded to the core verifier (`fresh_at` consistency token). nil: no policy (a PCActn carrying the member then fails closed).
        public var freshAt: FreshAtPolicy?
        /// The raw `pca-fresh-at` request header (the pre-member, side-carried token). Read only with a `freshAt` policy, when the
        /// PCActn has no `fresh_at` member and the policy carries no `sideCarried`; unparseable JSON is a null token (`bad_token`).
        public var freshAtHeader: String?
        /// K5 workflow admission (C-308; off when nil): decides `workflowStep` with `Workflow.admitStep` BEFORE the replay store is touched, so a
        /// refusal never consumes the PCActn's counter. The PCActn's `plan.root` must equal the workflow's committed plan root.
        public var workflow: WorkflowGate?
        /// The workflow step this call is (read only when `workflow` is set).
        public var workflowStep: WorkflowCall?

        public init(operation: Operation? = nil, audience: String? = nil, resolveGrant: ((String) throws -> JSONValue?)? = nil,
                    stateStore: (any PCAStateStore)? = nil, isRevoked: ((JSONValue, JSONValue) throws -> Bool?)? = nil, now: Int64? = nil,
                    plan: String? = nil, context: ((JSONValue) throws -> AuthorizeContext?)? = nil, intentPolicy: IntentPolicy? = nil,
                    intentV2: IntentV2Source? = nil, allowedSuites: [String]? = nil, require: [String] = [],
                    escalationPrincipals: [PinnedSigner] = [], escalationAnswer: JSONValue? = nil,
                    revocationStaleness: RevocationStalenessPolicy? = nil, revocationState: ((JSONValue, JSONValue) throws -> RevocationState?)? = nil,
                    guardianPublic: String? = nil, guardianPins: [String: String]? = nil, plans: PlanRegistry? = nil,
                    requireAssurance: AssuranceRequirement? = nil, assuranceHooks: AssuranceHooks = AssuranceHooks(),
                    k1: K1Input? = nil, usesStore: (any PCAStateStore)? = nil,
                    freshAt: FreshAtPolicy? = nil, freshAtHeader: String? = nil,
                    workflow: WorkflowGate? = nil, workflowStep: WorkflowCall? = nil) {
            self.operation = operation
            self.audience = audience
            self.resolveGrant = resolveGrant
            self.stateStore = stateStore
            self.isRevoked = isRevoked
            self.now = now
            self.plan = plan
            self.context = context
            self.intentPolicy = intentPolicy
            self.intentV2 = intentV2
            self.allowedSuites = allowedSuites
            self.require = require
            self.escalationPrincipals = escalationPrincipals
            self.escalationAnswer = escalationAnswer
            self.revocationStaleness = revocationStaleness
            self.revocationState = revocationState
            self.guardianPublic = guardianPublic
            self.guardianPins = guardianPins
            self.plans = plans
            self.requireAssurance = requireAssurance
            self.assuranceHooks = assuranceHooks
            self.k1 = k1
            self.usesStore = usesStore
            self.freshAt = freshAt
            self.freshAtHeader = freshAtHeader
            self.workflow = workflow
            self.workflowStep = workflowStep
        }
    }

    /// The outcome of `authorize`. `allow` is the one thing a caller must branch on.
    ///
    /// `status` is 200, 401 (no, undecodable or unauthenticated proof) or 403. `checks` maps each check to its status
    /// (`checkNames` lists them in evaluation order); `reason` is the decisive one (an `operation` failure first). `missing`
    /// names configuration components that were absent (the call was refused before any verification).
    public struct AuthorizeResult {
        public let allow: Bool
        public let status: Int
        public let checks: [String: CheckStatus]
        public let checkNames: [String]
        public let reasons: [String]
        public let reason: String?
        public let operation: AuthorizedOperation?
        public let pcactn: JSONValue?
        public let verdict: Verdict?
        public let missing: [String]?
        /// `allow` (and `allow` is true), `escalate` (refused, 403: `escalation` is the request to put to the principal) or `deny`.
        /// `allow` is exactly `decision == "allow"`: an `escalate` is never `allow: true`.
        public var decision: String = "deny"
        /// `escalate`: the request (`pca-escalation-request`) for the principal. An allow admitted by an answer: `{answered_by}`.
        public var escalation: JSONValue? = nil
        /// Names the passing checks that rest on a compatibility mode (check name -> why): `tighten` under rule 21's `model_polarity`
        /// "legacy". A caller with a high-assurance policy must not accept a degraded pass.
        public var degraded: [String: String] = [:]
        /// The per-check report: what each passing check rests on (see `PCA.buildAssuranceReport`). The capability chain check is reported as
        /// `cap_chain`.
        public var assurance = AssuranceReport()

        /// The names of the failing checks, sorted.
        public var failedChecks: [String] { checks.filter { $0.value == .fail }.map { $0.key }.sorted() }
    }

    /// Insertion-ordered check statuses (the decisive reason follows evaluation order).
    struct CheckList {
        var order: [String] = []
        var map: [String: CheckStatus] = [:]
        mutating func set(_ name: String, _ s: CheckStatus) {
            if map[name] == nil { order.append(name) }
            map[name] = s
        }
        subscript(_ name: String) -> CheckStatus? { map[name] }
        var anyFail: Bool { map.values.contains(.fail) }
    }

    static func refuse(_ status: Int, _ check: String, _ reason: String, missing: [String]? = nil, pcactn: JSONValue? = nil) -> AuthorizeResult {
        AuthorizeResult(allow: false, status: status, checks: [check: .fail], checkNames: [check], reasons: [reason], reason: reason,
                        operation: nil, pcactn: pcactn, verdict: nil, missing: missing)
    }

    /// Names of the required components `input` lacks (empty = complete): `audience`, `resolveGrant`, `stateStore`,
    /// `isRevoked`, in that order.
    public static func missingAuthorizeComponents(_ input: AuthorizeInput) -> [String] {
        var missing: [String] = []
        if (input.audience ?? "").isEmpty { missing.append("audience") }
        if input.resolveGrant == nil { missing.append("resolveGrant") }
        if input.stateStore == nil { missing.append("stateStore") }
        if input.isRevoked == nil { missing.append("isRevoked") }
        if let sp = input.revocationStaleness, sp.isOn {
            if input.revocationState == nil { missing.append("revocationState (required by revocationStaleness)") }
            if let why = sp.validate() { missing.append("revocationStaleness (invalid: \(why))") }
        }
        // an answer is bound to the holder's history head: a store that cannot report it cannot admit one (refused up front)
        if !input.escalationPrincipals.isEmpty && !(input.stateStore is PCALastStore) { missing.append("stateStore.last (needed with escalationPrincipals)") }
        return missing
    }

    /// The store key of a holder's counter stream (`<grant id>:<leaf holder>`).
    public static func stateKey(grantId: String, leafHolder: String) -> String { "\(grantId):\(leafHolder)" }

    // ---- the envelope ----

    static func validateRiskPolicy(_ p: JSONValue?) -> String? {
        guard case let .object(o)? = p else { return "risk_policy must be an object" }
        guard case let .object(w)? = o["weights"] else { return "risk_policy.weights missing" }
        for k in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
            guard let v = ToolSchema.fin(w[JKey(k)]), v >= 0 else { return "risk_policy.weights.\(k) must be finite and >= 0" }
        }
        var vals: [String: Double] = [:]
        for k in ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"] {
            guard let v = ToolSchema.fin(o[JKey(k)]) else { return "risk_policy.\(k) must be finite" }
            vals[k] = v
        }
        let t1 = vals["theta1"] ?? 0, t2 = vals["theta2"] ?? 0
        if t1 < 0 || t2 < t1 { return "risk_policy requires 0 <= theta1 <= theta2" }
        if (vals["kappa"] ?? 0) <= 0 { return "risk_policy.kappa must be > 0" }
        if (vals["lambda"] ?? 0) < 0 || (vals["rho"] ?? 0) < 0 || (vals["bMax"] ?? 0) < 0 { return "risk_policy lambda/rho/bMax must be >= 0" }
        return nil
    }

    /// The grant's policy envelope: its FIRST `envelope` caveat without `type`, or nil when absent or malformed.
    public static func readEnvelope(_ grant: JSONValue) -> JSONValue? {
        guard case let .array(cs)? = grant.get("caveats"),
              let cv = cs.first(where: { ToolSchema.eqs($0.get("type"), ENVELOPE_CAVEAT) }), case var .object(e) = cv else { return nil }
        e["type"] = nil
        guard case .string? = e["goal_commit"], case .array? = e["predicates"], case .array? = e["caveats"] else { return nil }
        switch e["agent_binding"] {
        case .object?, .array?: break
        default: return nil
        }
        if validateRiskPolicy(e["risk_policy"]) != nil { return nil }
        return .object(e)
    }

    /// Every root caveat except the first `envelope` one; a `caveats` that is not an array is returned as is.
    public static func rootCaveats(_ grant: JSONValue) -> JSONValue? {
        guard let csv = grant.get("caveats") else { return nil }
        guard case var .array(cs) = csv else { return csv }
        if let i = cs.firstIndex(where: { ToolSchema.eqs($0.get("type"), ENVELOPE_CAVEAT) }) { cs.remove(at: i) }
        return .array(cs)
    }

    /// Any agent pin in `agent_binding` requires a bound attestation.
    static func requiresAttestation(_ binding: JSONValue?) -> Bool {
        let b = binding?.asObject ?? [:]
        func nonEmpty(_ k: String) -> Bool { if case let .array(a)? = b[JKey(k)] { return !a.isEmpty }; return false }
        let hasMin: Bool = { guard let m = b["min_measurement"] else { return false }; return !ToolSchema.eqs(m, "") }()
        let hasOperator: Bool = { if case let .string(s)? = b["operator"] { return !s.isEmpty }; return false }()
        return nonEmpty("model_allowlist") || hasMin || hasOperator || nonEmpty("weights_allowlist") || nonEmpty("system_prompt_allowlist")
            || nonEmpty("tool_manifest_allowlist") || b["require_hardware"] == .bool(true) || b["require_measured_weights"] == .bool(true)
    }

    // ---- the agent-native caveat evaluator ----

    /// Evaluate a tool call against a `tool_schema` caveat: `(ok, reason)`. Never throws.
    public static func evaluateToolSchema(_ caveat: JSONValue?, call: ToolCall?) -> (ok: Bool, reason: String?) {
        ToolSchema.evaluate(caveat, call)
    }

    static func agentCaveatSatisfied(_ cv: JSONValue, _ ctx: JSONValue, _ actx: JSONValue, _ call: ToolCall?, _ budget: SafeRegex.Budget) -> Bool {
        guard case let .object(c) = cv, ctx.isObject else { return false }
        if ToolSchema.eqs(c["type"], "tool_schema") { return ToolSchema.evaluate(cv, call).ok }
        if ToolSchema.eqs(c["type"], "predicates") {
            guard actx.isObject, case let .array(allow)? = c["allow"] else { return false }
            return allow.contains { Predicates.predicateMatches($0, actx, budget) }
        }
        // max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
        return evaluateCaveats(.array([cv]), context: ctx).ok
    }

    static func evaluateAgentCaveats(_ caveats: JSONValue?, _ ctx: JSONValue, _ actx: JSONValue?, _ call: ToolCall?, _ budget: SafeRegex.Budget) -> (ok: Bool, failed: [String]) {
        guard case let .array(list)? = caveats else { return (false, ["<malformed caveats>"]) }
        if !list.isEmpty && !ctx.isObject { return (false, ["<evaluation error>"]) }
        var failed: [String] = []
        for cv in list where !agentCaveatSatisfied(cv, ctx, actx ?? .object([:]), call, budget) {
            failed.append(cv.get("type")?.asString ?? "<malformed>")
        }
        return (failed.isEmpty, failed)
    }

    /// The agent-native caveat evaluator: the stock types of `evaluateCaveats`, plus `predicates` (`allow`: the action must
    /// match one predicate; needs `actionContext` = `{"action": {...}, "subject"?, "env"?}`) and `tool_schema` (needs
    /// `toolCall`). `context` is the stock context (`now`, `action`, `blast_radius`, ...). Unknown types fail closed.
    /// Returns `(ok, failed types)`. One regex work budget per call.
    public static func evaluateAgentCaveats(_ caveats: JSONValue?, context: JSONValue, actionContext: JSONValue? = nil,
                                            toolCall: ToolCall? = nil) -> (ok: Bool, failed: [String]) {
        evaluateAgentCaveats(caveats, context, actionContext, toolCall, SafeRegex.Budget())
    }

    /// `evaluatePredicates`: nil when some predicate permits the action, else the reason.
    static func envelopePredicatesError(_ preds: JSONValue?, _ actx: JSONValue, _ budget: SafeRegex.Budget) -> String? {
        guard case let .array(ps)? = preds, !ps.isEmpty else { return "envelope grants no predicates" }
        if ps.contains(where: { Predicates.predicateMatches($0, actx, budget) }) { return nil }
        let a = actx.get("action")
        let at = "\(IntentWB.jsOpt(a?.get("verb"))) on \(IntentWB.jsOpt(a?.get("resource")))"
        if let limit = Predicates.firstUnmetLimit(preds, actx, budget) { return "\(limit) not satisfied for \(at)" }
        return "no predicate permits \(at)"
    }

    // ---- authorize ----

    static let CLASS_RANK: [String: Int] = ["reversible": 0, "rate_limited": 1, "costly": 1, "irreversible": 2]

    static func classRank(_ c: JSONValue?) -> Int {
        guard case let .string(s)? = c, s.unicodeScalars.allSatisfy({ $0.isASCII }) else { return 2 }
        return CLASS_RANK[s] ?? 2
    }

    static func decisive(_ checks: CheckList, _ reasons: [String]) -> String {
        let names = checks.order.filter { $0 == "operation" } + checks.order.filter { $0 != "operation" }
        for n in names where checks[n] == .fail {
            if let hit = reasons.first(where: { IV.startsWith($0, n + ":") }) { return hit }
        }
        return reasons.first ?? "denied"
    }

    /// Authorize ONE operation for a parsed PCActn (nil = none presented). See the README for the pipeline.
    public static func authorize(pcactn: JSONValue?, _ input: AuthorizeInput) -> AuthorizeResult {
        guard let v = pcactn else { return run(nil, "absent", input) }
        return run(v.isObject ? v : nil, v.isObject ? nil : "undecodable", input)
    }

    /// Authorize ONE operation for a PCActn as received (JSON text, strict profile; nil = none presented).
    public static func authorize(json text: String?, _ input: AuthorizeInput) -> AuthorizeResult {
        guard let t = text else { return run(nil, "absent", input) }
        if t.utf8.count > MAX_ARTIFACT_BYTES { return run(nil, "undecodable", input) }
        guard let v = try? StrictJSON.parse(t), v.isObject else { return run(nil, "undecodable", input) }
        return run(v, nil, input)
    }

    struct InternalError: Error { let what: String }

    static func run(_ p: JSONValue?, _ parseErr: String?, _ input: AuthorizeInput) -> AuthorizeResult {
        do {
            return try authorizeSteps(p, parseErr, input)
        } catch {
            let what = (error as? InternalError)?.what ?? "\(type(of: error))"
            return refuse(403, "authorize", "authorize: error (fail closed): \(what)")
        }
    }

    static func authorizeSteps(_ pIn: JSONValue?, _ parseErr: String?, _ input: AuthorizeInput) throws -> AuthorizeResult {
        var missing = missingAuthorizeComponents(input)
        if let pl = input.plan, !IV.same(pl, SINGLE_STEP) { missing.append("plan (only '\(SINGLE_STEP)' or nil)") }
        guard missing.isEmpty, let audience = input.audience, let resolveGrant = input.resolveGrant,
              let store = input.stateStore, let isRevoked = input.isRevoked else {
            return refuse(403, "authorize_config", "authorize_config: missing required component(s): \(missing.joined(separator: ", ")) (fail closed)",
                          missing: missing)
        }
        guard let opIn = input.operation, opIn.isValid else {
            return refuse(403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)")
        }
        // a private copy in the strict profile: the params that are verified are exactly what was digested
        guard let canon = IV.strictCanon(opIn.params), let opParams = try? StrictJSON.parse(canon), let opDigest = IV.strictHash(opParams) else {
            throw InternalError(what: "the operation params are outside the strict JSON profile")
        }
        let op = Operation(verb: opIn.verb, resource: opIn.resource, params: opParams)

        let now = input.now ?? Int64(Date().timeIntervalSince1970 * 1000)

        // K5 workflow admission, before the PCActn is verified and before any replay state is written. A required gate with no step refuses
        // first (it needs no PCActn); an unreadable or absent PCActn is not judged by the gate (the wire refusal below answers it); the plan
        // root is read from the presented (unverified) PCActn.
        if let wg = input.workflow {
            if let wc = input.workflowStep, pIn != nil {
                var units: JObject = [:]
                for (k, u) in wc.units { units[JKey(k)] = .string(u) }
                var root: JSONValue = .null
                if let rs = pIn?.get("plan")?.get("root")?.asString { root = .string(rs) }
                let req: JSONValue = .object(["step": .string(wc.step), "verb": .string(op.verb), "resource": .string(op.resource), "params": op.params,
                                              "units": .object(units), "goal_digest": wc.goalDigest.map { JSONValue.string($0) } ?? .null, "plan_root": root])
                let d = Workflow.admitStep(workflow: wc.commitment, principal: wg.principal, rsSigner: wg.rsSigner, receipts: wc.receipts, now: now, request: req)
                if d.decision != "allow" {
                    var r = refuse(403, "workflow", "workflow: \(d.code ?? "refused")" + (d.step.map { " (step \($0))" } ?? ""))
                    if d.decision == "escalate" { r.decision = "escalate" }
                    return r
                }
            } else if input.workflowStep == nil, wg.required {
                return refuse(403, "workflow", "workflow: this call carries no workflow step (fail closed)")
            }
        }

        guard let pv = pIn, case let .object(p) = pv else {
            return parseErr == "absent" ? refuse(401, "wire", "wire: no PCActn presented")
                                        : refuse(401, "pcactn", "undecodable PCActn: not a strict-JSON object")
        }
        guard case let .string(grantRef)? = p["grant_ref"] else {
            return refuse(401, "malformed", "malformed: grant_ref is not a string", pcactn: pv)
        }
        let grantOpt: JSONValue?
        do { grantOpt = try resolveGrant(grantRef) } catch {
            return refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", pcactn: pv)
        }
        guard let grant = grantOpt, case let .object(g) = grant else {
            return refuse(401, "grant_ref", "grant_ref: does not resolve to a known grant", pcactn: pv)
        }

        var ctx = AuthorizeContext()
        if let cb = input.context {
            do { ctx = try cb(pv) ?? AuthorizeContext() } catch {
                return refuse(403, "context", "context: the context callback failed (fail closed)", pcactn: pv)
            }
        }

        var planStatus: PlanStatus?
        if let reg = input.plans, ctx.plan == nil {
            let root = p["plan"]?.get("root")?.asString ?? ""
            if let pc = reg.context(grantRef: grantRef, root: root, now: now) {
                ctx.plan = pc.plan
                ctx.planAuthorized = pc.planAuthorized
                planStatus = pc.status
            } else if !(input.plan.map { IV.same($0, SINGLE_STEP) } ?? false) {
                planStatus = PlanStatus(state: .unknown, executable: false, reason: "plan \(root) is unknown to the plan registry")
            }
        }

        var v2: IntentV2Context?
        switch input.intentV2 {
        case let .context(c)?: v2 = c
        case let .provider(f)?:
            do { v2 = try f(pv) } catch {
                return refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", pcactn: pv)
            }
        case nil: v2 = nil
        }
        // Rules 20 / 21 read the signed envelope of the stored grant: when it carries units / tighten / model_polarity or a grant-side
        // where reads a model-derived path, the v2 pipeline needs the plaintext params and the host env even without a v2 context.
        if v2 == nil && needsModelRules(grant) { v2 = IntentV2Context(.object([:])) }
        if let c = v2, case var .object(o) = c.value {
            if o["params"] == nil || o["params"] == .null { o["params"] = op.params }
            if o["env"] == nil || o["env"] == .null { // `intentV2.env ?? ctx.env`: a null env is the authorize context's
                o["env"] = nil
                if let he = ctx.env, !he.isNull { o["env"] = he }
            }
            v2 = IntentV2Context(.object(o))
        }

        // ---- 1. the core checks
        var freshAt = input.freshAt
        if var fp = freshAt, pv.get("fresh_at") == nil, fp.sideCarried == nil, let h = input.freshAtHeader {
            fp.sideCarried = (try? StrictJSON.parse(h)) ?? .null
            freshAt = fp
        }
        let core = verify(pcactn: pv, grant: grant, now: now, audience: .id(audience), allowedSuites: input.allowedSuites,
                          intentPolicy: input.intentPolicy, intentV2: v2, freshAt: freshAt)
        if core.checks["wire"] == false {
            let r = core.reason.isEmpty ? "wire: malformed PCActn" : core.reason
            return AuthorizeResult(allow: false, status: 401, checks: ["wire": .fail, "malformed": .fail], checkNames: ["wire", "malformed"],
                                   reasons: [r], reason: r, operation: nil, pcactn: pv, verdict: core, missing: nil)
        }
        var checks = CheckList()
        let coreNames = CORE_CHECK_ORDER.filter { core.checks[$0] != nil } + core.checks.keys.filter { !CORE_CHECK_ORDER.contains($0) }.sorted()
        for n in coreNames { checks.set(n, core.checks[n] == true ? .pass : .fail) }
        var reasons: [String] = core.allow ? [] : core.reasons
        func fail(_ name: String, _ why: String) {
            checks.set(name, .fail)
            reasons.append("\(name): \(why)")
        }

        // ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
        let revoked: Bool?
        do { revoked = try isRevoked(pv, grant) } catch { revoked = nil }
        if revoked == false {
            checks.set("revocation", .pass)
        } else {
            fail("revocation", revoked == true ? "the grant is revoked" : "the revocation check failed (fail closed)")
        }
        if let sp = input.revocationStaleness, sp.isOn, let source = input.revocationState {
            var st: RevocationState?
            var failed = false
            do { st = try source(pv, grant) } catch { failed = true }
            if failed {
                fail("freshness", "the revocation state source failed (fail closed)")
            } else if let why = revocationFreshness(input, ctx, p, st, now) {
                fail("freshness", why)
            } else {
                checks.set("freshness", .pass)
            }
        }
        if p["zk_compliance"] != nil {
            fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)")
        }

        let action = p["action"]?.asObject ?? [:]
        let signedDigest = action["params_digest"]

        // ---- 3. the operation binding
        if !ToolSchema.eqs(action["verb"], op.verb) || !ToolSchema.eqs(action["resource"], op.resource) {
            fail("operation", "the proof is for \(IntentWB.jsOpt(action["verb"])) on \(IntentWB.jsOpt(action["resource"])), but this operation is \(op.verb) on \(op.resource)")
        } else if !ToolSchema.eqs(signedDigest, opDigest) {
            fail("operation", "the proof's params_digest does not match the params of this \(op.verb) operation")
        } else {
            checks.set("operation", .pass)
        }

        // ---- 4. grant_ref, params, plan, attestation, reversibility
        if ToolSchema.eqs(g["id"], grantRef) {
            checks.set("grant_ref", .pass)
        } else {
            fail("grant_ref", "does not reference the supplied grant")
        }
        if ToolSchema.eqs(signedDigest, opDigest) {
            checks.set("params_digest", .pass)
        } else {
            fail("params_digest", "supplied params do not hash to action.params_digest")
        }

        let pl = p["plan"]?.asObject ?? [:]
        let nodeId = pl["node_id"]
        var planNodes: [JSONValue]? = ctx.plan
        var planAuthorized = ctx.planAuthorized
        if let mode = input.plan, IV.same(mode, SINGLE_STEP), planNodes == nil {
            var node: JObject = ["id": .string(IntentWB.jsOpt(nodeId)), "verb": .string(op.verb), "resource": .string(op.resource),
                                 "params_digest": .string(opDigest)]
            if let rc = action["reversibility_class"] { node["reversibility_class"] = rc }
            planNodes = [.object(node)]
            planAuthorized = true
        }
        if let nodes = planNodes {
            let known = knownPlanRoot(nodes)
            if known == nil || !ToolSchema.eqs(pl["root"], known ?? "") {
                fail("plan_root_authorized", "known plan does not match plan.root")
            } else if !planAuthorized {
                fail("plan_root_authorized", "the plan root has not been authorized by the principal")
            } else {
                checks.set("plan_root_authorized", .pass)
            }
        } else {
            // K5 default-deny: no plan source configured fails (there is deliberately NO insecureSkipPlanRootCheck on authorize)
            fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)")
        }

        if let ps = planStatus {
            if ps.executable {
                checks.set("plan_state", .pass)
            } else {
                fail("plan_state", (ps.reason ?? "").isEmpty ? "plan is \(ps.state.rawValue)" : ps.reason!)
            }
        }

        let env = readEnvelope(grant)
        if requiresAttestation(env?.get("agent_binding")) {
            fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED (no attestation verifier in this SDK: fail closed)")
        }

        let declared = action["reversibility_class"]
        var effective = declared
        if let serverClass = ctx.reversibilityClass {
            let dr = classRank(declared), sr = classRank(.string(serverClass))
            if dr < sr {
                fail("reversibility", "declared class '\(IntentWB.jsOpt(declared))' is less restrictive than the authoritative '\(serverClass)'")
            } else {
                checks.set("reversibility", .pass)
            }
            effective = dr > sr ? declared : .string(serverClass)
        }

        // ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
        let chain = p["cap_chain"]?.asArray ?? []
        let depth = max(0, chain.count - 1)
        var inner: JObject = ["params": op.params]
        if let x = action["verb"] { inner["verb"] = x }
        if let x = action["resource"] { inner["resource"] = x }
        if let e = effective { inner["reversibility_class"] = e }
        var actx: JObject = ["action": .object(inner)]
        if let s = ctx.subject { actx["subject"] = s }
        if let e = v2Env(p, grant, v2, now, ctx.env) { actx["env"] = e }
        let actionCtx = JSONValue.object(actx)
        let toolCall = ToolCall(tool: action["verb"]?.asString ?? "", args: op.params, toolSignatureDigest: p["tool_binding"]?.asString)
        var revClass = effective
        if revClass == nil, case let .string(nid)? = nodeId, let nodes = planNodes {
            revClass = nodes.first(where: { $0.isObject && ToolSchema.eqs($0.get("id"), nid) })?.get("reversibility_class")
        }
        var cctx: JObject = ["now": .int(now), "action": .object(inner), "delegation_depth": .int(Int64(depth))]
        if let b = ctx.blastRadius { cctx["blast_radius"] = .double(b) }
        if let r = revClass { cctx["reversibility_class"] = r }
        if let t = ctx.recentActionTimes { cctx["recent_action_times"] = .array(t.map { .double($0) }) }
        let caveatCtx = JSONValue.object(cctx)

        var k1Bound: [BoundCaveat]?
        if !chain.isEmpty {
            let leaf = chain[chain.count - 1].asObject ?? [:]
            let gcs = g["caveats"]?.asArray ?? []
            var extra: JSONValue?
            if case let .array(lc)? = leaf["caveats"] { extra = .array(lc.count > gcs.count ? Array(lc[gcs.count...]) : []) }
            // K1 caveat types (and the caveats of a verified narrow block) are evaluated over the whole chain; the stock evaluator
            // would refuse them. Without `k1` nothing changes.
            var k1r: K1Result?
            var stockExtra = extra
            var k = input.k1
            k?.actionDigest = dischargeActionDigest(pcactn: pv)
            // Without `k1` a K1 caveat is refused by evaluateK1 itself (no k1 input), never left to the stock evaluator.
            let carriesK1 = (leaf["caveats"]?.asArray ?? []).contains(where: { isK1Caveat($0) })
            if carriesK1 || k?.narrow != nil {
                let kr = evaluateK1(grant: grant, chain: p["cap_chain"], k1: k, now: now, action: .object(inner))
                k1r = kr
                k1Bound = kr.bound
            }
            if case let .array(list)? = extra { stockExtra = .array(list.filter { !isK1Caveat($0) } + (k1r?.plain ?? [])) }
            let r = evaluateAgentCaveats(stockExtra, caveatCtx, actionCtx, toolCall, SafeRegex.Budget())
            if r.ok && (k1r?.ok ?? true) {
                checks.set("delegated_caveats", .pass)
            } else {
                var why = "delegation caveat(s) not satisfied: \((r.failed + (k1r?.failed ?? [])).joined(separator: ", "))"
                if let kr = k1r, !kr.ok { why += " (\(kr.reasons.joined(separator: "; ")))" }
                fail("delegated_caveats", why)
            }
        }

        var policyWhy: [String] = []
        if let e = env {
            let budget = SafeRegex.Budget() // one document scope for the whole policy step
            if let why = envelopePredicatesError(e.get("predicates"), actionCtx, budget) { policyWhy.append(why) }
            let ec = evaluateAgentCaveats(e.get("caveats"), caveatCtx, actionCtx, toolCall, budget)
            if !ec.ok { policyWhy.append("caveat(s) not satisfied: \(ec.failed.joined(separator: ", "))") }
            var rootList = rootCaveats(grant)
            var rootK1: K1Result?
            // the root's own K1 caveats, judged with the root grant alone (no narrow block: it is bound to the chain's leaf)
            var rk = input.k1
            rk?.actionDigest = dischargeActionDigest(pcactn: pv)
            rk?.narrow = nil
            if (g["caveats"]?.asArray ?? []).contains(where: { isK1Caveat($0) }) || rk != nil {
                rootK1 = evaluateK1(grant: grant, chain: nil, k1: rk, now: now, action: .object(inner))
            }
            if case let .array(list)? = rootList { rootList = .array(list.filter { !isK1Caveat($0) }) }
            let rc = evaluateAgentCaveats(rootList, caveatCtx, actionCtx, toolCall, budget)
            if !rc.ok || !(rootK1?.ok ?? true) {
                policyWhy.append("root caveat(s) not satisfied: \((rc.failed + (rootK1?.failed ?? [])).joined(separator: ", "))")
            }
        } else {
            policyWhy = ["grant carries no valid envelope"]
        }
        if policyWhy.isEmpty {
            checks.set("policy", .pass)
        } else {
            checks.set("policy", .fail)
            reasons += policyWhy.map { "policy: \($0)" }
        }

        // ---- required checks (default-deny), then the replay counter
        // `replay` is decided by the claim below: tentatively pass (as the TypeScript guard does), flipped to fail on a refusal.
        checks.set("replay", .pass)
        func assuranceReport() -> AssuranceReport {
            var src = AssuranceSources(pcactn: pv, hooks: input.assuranceHooks)
            for n in checks.order { src.checks.append(NamedStatus(name: n == "chain" ? "cap_chain" : n, status: checks.map[n]?.rawValue ?? "fail")) }
            if core.legacyModelPolarity && checks["tighten"] == .pass { src.degraded = ["tighten": PCA.LEGACY_POLARITY_DEGRADED] }
            return PCA.buildAssuranceReport(src)
        }
        if let req = input.requireAssurance, let why = PCA.unmetAssurance(assuranceReport(), req) {
            checks.set("assurance", .fail)
            reasons.append(why)
        }
        // `counter` in a require list is the documented alias of `replay` (it always meant the stateful check here).
        let freshnessRequired = (input.revocationStaleness?.isOn ?? false) ? ["freshness"] : []
        for name in DEFAULT_REQUIRED_CHECKS + freshnessRequired + input.require.map({ $0 == "counter" ? "replay" : $0 }) {
            let st = checks[name]
            if st != .pass && st != .fail {
                checks.set(name, .fail)
                reasons.append("\(name): required check is \(st?.rawValue ?? "absent") (default-deny: not enforced by this resource server)")
            }
        }

        var escalation: JSONValue?
        var answeredBy: String?
        func deny() -> AuthorizeResult {
            let status = AUTHN_CHECKS.contains(where: { checks[$0] == .fail }) ? 401 : 403
            var r = AuthorizeResult(allow: false, status: status, checks: checks.map, checkNames: checks.order, reasons: reasons,
                                    reason: decisive(checks, reasons), operation: nil, pcactn: pv, verdict: core, missing: nil)
            r.decision = escalation != nil ? "escalate" : "deny"
            r.escalation = escalation
            r.assurance = assuranceReport()
            return r
        }
        let holder = chain.last?.get("holder")?.asString
        let gidOpt = g["id"]?.asString
        if checks.anyFail {
            // Ternary decision: every failing check is escalate-class (over the FULL per-check result set) -> escalate; never
            // admitted by itself. A hard failure anywhere stays deny, and an answer never upgrades it.
            var st: [String: String] = [:]
            for (n, c) in checks.map { st[n] = c.rawValue }
            guard let h = holder, let gid = gidOpt,
                  PCA.decisionOf(allow: false, checks: st, reasons: reasons) == "escalate" else { return deny() }
            var last: Int64?
            var headKnown = false
            if let ls = store as? PCALastStore {
                do {
                    last = try ls.last(key: stateKey(grantId: gid, leafHolder: h))
                    headKnown = true
                } catch {}
            }
            let renderDigest: String? = input.escalationRender?(pv)
            guard let req = PCA.buildEscalationRequest(aud: audience, grant: grant, pcactn: pv, lastCounter: last, reasons: reasons, now: now, renderDigest: renderDigest) else { return deny() }
            escalation = req
            if !input.escalationPrincipals.isEmpty, input.escalationAnswer != nil, !input.insecureUnboundApproval, renderDigest == nil {
                // K7 default: an answer is admitted only over a render the verifier recomputed
                reasons.append("escalation: an approval render is required and none could be recomputed (set escalationRender, or insecureUnboundApproval)")
            } else if !input.escalationPrincipals.isEmpty, let ans = input.escalationAnswer, headKnown,
               let pd = PCA.escalationPolicyDigest(grant: grant), let ad = PCA.escalationActionDigest(pcactn: pv), let hh = PCA.escalationHistoryHead(lastCounter: last) {
                let v = PCA.verifyEscalationAnswer(ans, principals: input.escalationPrincipals,
                                                   bind: EscalationBinding(policyDigest: pd, actionDigest: ad, historyHead: hh, renderDigest: renderDigest), now: now)
                if v.ok && v.decision == "allow" {
                    // the answer upgrades ONLY the escalate-class failures; the replay claim below spends it
                    for n in checks.order where checks[n] == .fail { checks.set(n, .pass) }
                    checks.set("escalation", .pass)
                    reasons.append("escalation: answered allow by principal \(String(v.principal.prefix(8)))")
                    answeredBy = v.principal
                    escalation = nil
                } else {
                    reasons.append("escalation: \(v.ok ? "the principal answered deny" : v.reason)")
                }
            }
            if escalation != nil { return deny() }
        }

        guard let h = holder, let gid = gidOpt, let counter = p["counter"]?.safeInt else {
            fail("replay", "no counter stream for this proof (fail closed)")
            return deny()
        }
        guard let id = IV.strictHash(pv) else { throw InternalError(what: "the PCActn is outside the strict JSON profile") }
        let claimed: ClaimResult?
        do { claimed = try store.claim(key: stateKey(grantId: gid, leafHolder: h), counter: counter) } catch { claimed = nil }
        guard let c = claimed, c.ok else {
            if claimed == nil {
                fail("replay", "the replay store failed (fail closed)")
            } else if let last = claimed?.lastCounter {
                fail("replay", "\(counter) is not greater than last seen \(last) (replay)")
            } else {
                fail("replay", "\(counter) was already claimed (replay)")
            }
            return deny()
        }
        // K1 `max_uses` is spent only for an action that is otherwise admitted, after the counter above accepted it
        if let bound = k1Bound, bound.contains(where: { PCA.k1IsMaxUses($0.caveat) }) {
            let why: String
            if let us = input.usesStore {
                let r = reserveMaxUses(store: us, bound: bound, now: now)
                why = r.ok ? "" : r.reason
            } else {
                why = "the chain carries a max_uses caveat and this guard has no usesStore (fail closed)"
            }
            if !why.isEmpty {
                fail("max_uses", why)
                return deny()
            }
        }
        var ok = AuthorizeResult(allow: true, status: 200, checks: checks.map, checkNames: checks.order, reasons: reasons, reason: nil,
                                 operation: AuthorizedOperation(verb: op.verb, resource: op.resource, paramsDigest: opDigest, id: id),
                                 pcactn: pv, verdict: core, missing: nil)
        ok.decision = "allow"
        ok.assurance = assuranceReport()
        if core.legacyModelPolarity && checks["tighten"] == .pass { ok.degraded = ["tighten": PCA.LEGACY_POLARITY_DEGRADED] }
        if let by = answeredBy { ok.escalation = .object(["answered_by": .string(by)]) }
        return ok
    }

    public static let LEGACY_POLARITY_DEGRADED = "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)"

    /// The grant's envelope carries units / tighten / model_polarity, or a grant-side where reads a model-derived path.
    static func needsModelRules(_ grant: JSONValue) -> Bool {
        guard let env = readEnvelope(grant) else { return false }
        if ["units", "tighten", "model_polarity"].contains(where: { env.get($0) != nil }) { return true }
        return !modelPathsRead([env.get("predicates") ?? .null]).isEmpty
    }

    /// The Merkle root of a known plan (each node's leaf with its own pre / post conditions), or nil when a node is
    /// malformed.
    static func knownPlanRoot(_ nodes: [JSONValue]) -> String? {
        var leaves: [JSONValue] = []
        for n in nodes {
            guard case let .object(o) = n, o["verb"] != nil, o["resource"] != nil else { return nil }
            guard let cond = IV.strictHash(.object(["pre": o["pre"] ?? .null, "post": o["post"] ?? .null])),
                  let leaf = Merkle.planLeaf(o["id"], o, cond), IV.strictCanon(leaf) != nil else { return nil }
            leaves.append(leaf)
        }
        return Merkle.merkleRoot(leaves)
    }

    /// The predicate `env`: the host's, with the verifier-computed Intent Layer v2 members.
    static func v2Env(_ p: JObject, _ grant: JSONValue, _ v2: IntentV2Context?, _ now: Int64, _ env: JSONValue?) -> JSONValue? {
        if p["intent_session"] == nil { return env }
        var rest = env?.asObject ?? [:]
        for k in ["acc", "mon", "canon", "world", "prov", "class"] { rest[JKey(k)] = nil }
        if case let .object(d)? = IntentV2.decide(p, grant: grant, ctx: v2, now: now).env?.json {
            for (k, v) in d { rest[k] = v }
        }
        return .object(rest)
    }

    /// True only if `result` allowed exactly this operation (verb, resource, params digest). Call it where the side effect
    /// runs, with the values it is about to use.
    public static func isAuthorized(_ result: AuthorizeResult, for operation: Operation?) -> Bool {
        guard result.allow, let b = result.operation, let op = operation, op.isValid, let d = IV.strictHash(op.params) else { return false }
        return IV.same(b.verb, op.verb) && IV.same(b.resource, op.resource) && b.paramsDigest == d
    }
}

extension JSONValue {
    /// The canonical JSON text of the value (sorted keys, no whitespace, the numbers as ECMAScript prints them): what the stores keep.
    public var canonicalText: String { Canonical.canonicalize(self) }

    /// Parse JSON text (RFC 8259) the way `JSON.parse` reads it: for a request body or a grant from your store. nil when
    /// the text is not JSON. (A presented PCActn goes to `PCA.authorize(json:_:)`, which applies the strict profile.)
    public static func parse(_ text: String) -> JSONValue? {
        guard let v = try? StrictJSON.parseLenient(text) else { return nil }
        return IV.normalized(v)
    }
}
