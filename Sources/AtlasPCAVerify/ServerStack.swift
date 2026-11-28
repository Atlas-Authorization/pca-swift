import Foundation

// The server stack of core pca: the required-check profiles and their default-deny fold, the build-once authorizer and request guard, the replay /
// budget state stores (in memory and over an atomic key/value store) and the small guard helpers.
extension PCA {
    /// The profile a STATEFUL resource server demands: the stateless profile plus `replay`, the strictly-increasing-counter check against stored state
    /// (it is not enforced without a store, so the request is denied).
    public static let STATEFUL_REQUIRED_CHECKS = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]

    /// The checks a full-policy execution decision must pass: the stateful profile plus the params digest and the policy itself.
    public static let EXECUTION_REQUIRED_CHECKS = STATEFUL_REQUIRED_CHECKS + ["params_digest", "policy"]

    /// The required components a full-policy execution configuration lacks (empty = complete).
    public static func missingExecutionComponents(audience: String?, grant: JSONValue?, resolveGrant: ((String) throws -> JSONValue?)?, state: (any PCAStateStore)?,
                                                  isRevoked: ((JSONValue, JSONValue) throws -> Bool?)?) -> [String] {
        var missing: [String] = []
        if (audience ?? "").isEmpty { missing.append("audience") }
        if grant == nil && resolveGrant == nil { missing.append("grant or resolveGrant") }
        if state == nil { missing.append("state") }
        if isRevoked == nil { missing.append("isRevoked") }
        return missing
    }

    /// Default-deny: turn every required check that is not `pass` into a failure. The verdict is `{allow, checks: {name: pass|fail|not-enforced|unsupported},
    /// reasons: [..]}`. A check that is not `fail` is recorded as `fail` with the reason `<name>: required check is <status|absent> (default-deny: not
    /// enforced by this resource server)`; one already `fail` keeps its reason. `counter` is the old name of `replay` (or `counter_format` when no replay
    /// check ran). A non-required `unsupported` check stays `unsupported`. Reasons only grow and the result never allows more than the input.
    public static func enforceRequired(_ verdict: JSONValue, _ required: [String]) -> JSONValue {
        var allow = verdict.get("allow") == .bool(true)
        var order: [String] = []
        var checks: [String: String] = [:]
        for k in JS.keyOrder(verdict.get("checks")?.asObject ?? [:]) {
            order.append(k.s)
            checks[k.s] = verdict.get("checks")?.get(k.s)?.asString ?? ""
        }
        let original = checks
        var reasons = (verdict.get("reasons")?.asArray ?? [])
        for raw in required {
            let name = raw == "counter" && original["counter"] == nil ? (original["replay"] != nil ? "replay" : "counter_format") : raw
            let was = checks[name]
            if was == "pass" { continue }
            allow = false
            if was == "fail" { continue }
            let shown = original[name] == "unsupported" ? "unsupported" : (was == "unsupported" ? "not-enforced" : (was ?? "absent"))
            reasons.append(.string("\(name): required check is \(shown) (default-deny: not enforced by this resource server)"))
            if was == nil { order.append(name) }
            checks[name] = "fail"
        }
        var out = verdict.asObject ?? [:]
        out["allow"] = .bool(allow)
        out["checks"] = .object(order.reduce(into: JObject()) { $0[JKey($1, ord: Int32($0.count + 1))] = .string(checks[$1] ?? "") })
        out["reasons"] = .array(reasons)
        return .object(out)
    }

    /// Build an authorizer once (the configuration is validated here) and call it per operation: `(pcactn, operation) -> AuthorizeResult`. An incomplete
    /// configuration answers a 403 `authorize_config` refusal naming the missing components on every call (fail closed).
    public static func createAuthorizer(_ base: AuthorizeInput) -> (_ pcactn: JSONValue?, _ operation: Operation?) -> AuthorizeResult {
        let missing = missingAuthorizeComponents(base)
        if !missing.isEmpty {
            let reason = "authorize: missing required component(s): \(missing.joined(separator: ", ")) (fail closed)"
            return { _, _ in refuse(403, "authorize_config", reason, missing: missing) }
        }
        return { pcactn, op in
            var input = base
            input.operation = op
            return authorize(pcactn: pcactn, input)
        }
    }

    /// A request guard over `authorize` (the `requireAuthorized` of the reference): the guard answers allow with the bound operation, or a 401 / 403
    /// denial. Configure the operation mapping in `PcaAuthorizeConfig.operation` (from the server's routing, never from the PCActn; a nil mapping denies).
    public static func requireAuthorized(_ config: PcaGuardConfig) throws -> PcaGuard { try PcaGuard(config) }

    /// The reference's `requireAuthorized` result shape of a guard decision: an allow is `{ok: true, decision: "allow", verdict, pcactn, operation, escalation?}`, a refusal
    /// `{ok: false, decision, status, verdict?, wwwAuthenticate, escalation?}`. `verdict` is `{allow, checks, reason}`.
    public static func guardResult(_ d: PcaGuardDecision) -> JSONValue {
        func verdict(_ v: PCA.Verdict?) -> JSONValue? {
            guard let v = v else { return nil }
            var checks: JObject = [:]
            for (k, ok) in v.checks { checks[JKey(k)] = .bool(ok) }
            return .object(["allow": .bool(v.allow), "checks": .object(checks), "reason": .string(v.reason)])
        }
        switch d {
        case let .allow(a):
            var o: JObject = ["ok": .bool(true), "decision": .string("allow"), "pcactn": a.pcactn]
            if let v = verdict(a.verdict) { o["verdict"] = v }
            if let op = a.operation {
                o["operation"] = .object(["verb": .string(op.verb), "resource": .string(op.resource), "params_digest": .string(op.paramsDigest), "id": .string(op.id)])
            }
            if let e = a.authorization?.escalation { o["escalation"] = e }
            return .object(o)
        case let .deny(x):
            var o: JObject = ["ok": .bool(false), "decision": .string(x.decision), "status": .int(Int64(x.status)), "wwwAuthenticate": .string(x.wwwAuthenticate)]
            if let v = verdict(x.authorization?.verdict) { o["verdict"] = v }
            if let e = x.escalation { o["escalation"] = e }
            return .object(o)
        }
    }

    /// The ternary decision of a guard result (a refusal without `decision` is `deny`).
    public static func decisionOfResult(ok: Bool, decision: String? = nil) -> String { ok ? "allow" : (decision == "escalate" ? "escalate" : "deny") }

    /// Default escalation-answer extraction: header `PCA-Escalation-Answer` (strict base64url JSON), else body `escalation_answer`. nil when absent or malformed.
    public static func defaultEscalationAnswer(_ req: PcaGuardRequest) -> JSONValue? {
        if let h = req.header(PcaGuard.ESCALATION_HEADER), !h.isEmpty {
            guard let text = PcaGuard.decodeHeader(h) else { return nil }
            return JSONValue.parse(text)
        }
        guard let text = String(data: Data(req.body), encoding: .utf8), let body = JSONValue.parse(text) else { return nil }
        return body.get("escalation_answer")
    }

    /// In-memory replay / budget store for ONE process (tests, a single node): its state dies with the process, so it declares `scope: process`.
    public static func memoryPcaStore() -> MemoryStateStore { MemoryStateStore() }
    /// In-memory store with atomic claims (the reference for ONE process); every `MemoryStateStore` claim is atomic.
    public static func atomicMemoryPcaStore() -> MemoryStateStore { MemoryStateStore() }

    /// True iff the store claims atomically with budgets and raises pins (the shape `requirePCA` needs for `atomic-claim` mode).
    public static func isAtomicPcaStateStore(_ s: Any?) -> Bool { s is PCABudgetStore && s is PCAPinStore }

    /// `PCAStateStore` over any atomic key/value store (see `PCAKVStateStore`): crash-safe and multi-process-safe when the backing store is.
    public static func durablePcaStateStore(_ kv: AtomicKV, prefix: String = "pca-state:", scope: PCAStoreScope = .shared) -> PCAKVStateStore {
        PCAKVStateStore(kv, prefix: prefix, scope: scope)
    }
}

/// The replay / budget / pin state store over an `AtomicKV`: every claim is ONE atomic `update` of the holder's state object
/// `{lastCounter?, budget?: {B, tau, asOf?}, lastEpoch?, lastBeaconSeq?}` under `<prefix><key>` (the wire shape of the reference `durablePcaStateStore`),
/// so of N concurrent presentations of one PCActn at most one claim succeeds. With `openDurableState` as the backing store it is crash-safe on one host.
public final class PCAKVStateStore: PCALastStore, PCAPinStore, PCABudgetStore, @unchecked Sendable {
    private let kv: AtomicKV
    private let prefix: String
    public let scope: PCAStoreScope

    public init(_ kv: AtomicKV, prefix: String = "pca-state:", scope: PCAStoreScope = .shared) {
        self.kv = kv
        self.prefix = prefix
        self.scope = scope
    }

    private func read(_ k: String) throws -> JObject? { try kv.get(prefix + k)?.asObject }

    public func last(key: String) throws -> Int64? { try read(key)?[JKey("lastCounter")]?.safeInt }
    public func budget(key: String) throws -> Risk.Budget? { Risk.Budget(json: try read(key)?[JKey("budget")]) }
    public func pin(key: String) throws -> Double? { try read(key)?[JKey("lastEpoch")].flatMap { IV.num($0) } }

    public func claim(key: String, counter: Int64) throws -> ClaimResult { try claim(key: key, counter: counter, budgetBefore: nil, budgetAfter: nil, ignoreBudget: true) }

    public func claim(key: String, counter: Int64, budgetBefore: Risk.Budget?, budgetAfter: Risk.Budget?) throws -> ClaimResult {
        try claim(key: key, counter: counter, budgetBefore: budgetBefore, budgetAfter: budgetAfter, ignoreBudget: false)
    }

    private func claim(key: String, counter: Int64, budgetBefore: Risk.Budget?, budgetAfter: Risk.Budget?, ignoreBudget: Bool) throws -> ClaimResult {
        var result = ClaimResult(ok: false, conflict: true)
        try kv.update(prefix + key) { prev in
            var cur = prev?.asObject ?? [:]
            if let l = cur[JKey("lastCounter")]?.safeInt, !(counter > l) { result = ClaimResult(ok: false, lastCounter: l); return nil }
            if !ignoreBudget, Risk.Budget(json: cur[JKey("budget")].map { $0 }) != budgetBefore { result = ClaimResult(ok: false, conflict: true); return nil }
            if let a = budgetAfter, !ignoreBudget { cur[JKey("budget")] = a.json }
            cur[JKey("lastCounter")] = .int(counter)
            result = ClaimResult(ok: true)
            return .object(cur)
        }
        return result
    }

    public func raisePin(key: String, value: Double) throws {
        try kv.update(prefix + key) { prev in
            var cur = prev?.asObject ?? [:]
            if let p = cur[JKey("lastEpoch")].flatMap({ IV.num($0) }), p >= value { return nil }
            cur[JKey("lastEpoch")] = PCAFacade.jsNum(value)
            return .object(cur)
        }
    }

    public func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool {
        if key.isEmpty || retainUntil < now { throw PCAStoreArgumentError() }
        var taken = false
        try kv.update(prefix + "once:" + key) { prev in
            if let u = prev?.get("retainUntil")?.safeInt, u >= now { return nil }
            taken = true
            return .object(["retainUntil": .int(Swift.max(retainUntil, prev?.get("retainUntil")?.safeInt ?? 0))])
        }
        return taken
    }
}
