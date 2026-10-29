import Foundation

// Executor: `authorize` + `executeAuthorized` in one call, with retries answered from the record. A second presentation of the same
// PCActn is refused by `authorize` as a replay; if that replay is the ONLY failing check (the proof, binding, policy and revocation
// all still pass now) and a record exists for its operation id and this operation, the record's outcome is returned (`replayed`)
// instead of the bare denial. No record means the first attempt never reached execution: the denial stands (the authorization was
// consumed; the agent signs a fresh PCActn).

/// `PCAExecutor` options.
public struct ExecutorOptions {
    /// REQUIRED: the operation record store.
    public var operations: OperationStore?
    /// The `authorize` configuration (audience, resolveGrant, stateStore, isRevoked, plans, ...). Its `operation` is set per call.
    /// Before an irreversible operation the executor re-runs `isRevoked` against the grant, checks the PCActn's expiry, and with
    /// `plans` that the registered plan is still executable for the node.
    public var authorize: PCA.AuthorizeInput
    /// An extra re-check before an irreversible operation (for example a step-up approval still stands).
    public var recheck: ((ExecutionHandle) async throws -> RecheckResult)?
    /// nil or "irreversible" (default), or "always".
    public var recheckFor: String?
    /// The server's reversibility class for an operation (catalog); nil: the signed class only.
    public var reversibilityClassOf: ((PCA.Operation) -> String?)?
    /// An open record older than this is settled (0: `PCA.OPERATION_PENDING_TIMEOUT_MS`).
    public var pendingTimeoutMs: Int64
    /// The clock in epoch ms (nil: the wall clock; `authorize.now`, when set, wins for the authorization).
    public var now: (() -> Int64)?

    public init(operations: OperationStore?, authorize: PCA.AuthorizeInput, recheck: ((ExecutionHandle) async throws -> RecheckResult)? = nil,
                recheckFor: String? = nil, reversibilityClassOf: ((PCA.Operation) -> String?)? = nil, pendingTimeoutMs: Int64 = 0, now: (() -> Int64)? = nil) {
        self.operations = operations
        self.authorize = authorize
        self.recheck = recheck
        self.recheckFor = recheckFor
        self.reversibilityClassOf = reversibilityClassOf
        self.pendingTimeoutMs = pendingTimeoutMs
        self.now = now
    }
}

/// The executor's answer: the execution outcome, or (`status` `denied`) the authorization denial with nothing run.
public struct ExecutorOutcome {
    public let execution: ExecuteOutcome
    /// The `authorize` result of a denial (nil otherwise).
    public let authorization: PCA.AuthorizeResult?
}

/// Runs authorized operations at most once. Safe for concurrent use when its stores are.
public final class PCAExecutor: @unchecked Sendable {
    private let o: ExecutorOptions

    public init(_ options: ExecutorOptions) { o = options }

    private var clock: () -> Int64 { o.now ?? { Int64(Date().timeIntervalSince1970 * 1000) } }
    private var timeout: Int64 { o.pendingTimeoutMs != 0 ? o.pendingTimeoutMs : PCA.OPERATION_PENDING_TIMEOUT_MS }

    /// The executor's own re-check: the grant is still known and not revoked, a registered plan is still executable, then the caller's
    /// extra re-check.
    private func recheck(_ now: @escaping () -> Int64) -> (ExecutionHandle) async throws -> RecheckResult {
        let input = o.authorize
        let extra = o.recheck
        return { h in
            let ref = h.pcactn.get("grant_ref")?.asString ?? ""
            var grant: JSONValue?
            do { if let f = input.resolveGrant { grant = try f(ref) } } catch { grant = nil }
            guard let g = grant else { return .refuse("the grant is no longer known") }
            var revoked: Bool?
            var failed = false
            do { if let f = input.isRevoked { revoked = try f(h.pcactn, g) } } catch { failed = true }
            if failed || revoked == nil { return .refuse("revocation could not be checked") }
            if revoked == true { return .refuse("the grant has been revoked") }
            // a registered plan must still be executable: not revoked, the principal's approval not expired
            if let reg = input.plans, let pl = h.pcactn.get("plan"), let root = pl.get("root")?.asString, ((try? reg.get(grantRef: ref, root: root)) ?? nil) != nil {
                let ps = reg.check(grantRef: ref, root: root, PlanCheckOptions(nodeId: pl.get("node_id")?.asString, now: now()))
                if !ps.executable { return .refuse((ps.reason ?? "").isEmpty ? "plan is \(ps.state.rawValue)" : ps.reason!) }
            }
            if let e = extra { return try await e(h) }
            return .pass
        }
    }

    /// Authorizes `pcactn` (parsed JSON; nil = none presented) for `operation` and, when allowed, executes `fn` at most once. A missing
    /// record store is a refusal.
    public func run(pcactn: JSONValue?, operation: PCA.Operation?, _ fn: (ExecutionHandle) async throws -> JSONValue?) async -> ExecutorOutcome {
        guard o.operations != nil else { return refusedMissingStore }
        var input = o.authorize
        input.operation = operation
        if input.now == nil { input.now = clock() }
        return await decide(PCA.authorize(pcactn: pcactn, input), operation, fn)
    }

    /// `run` for a PCActn as received (JSON text, strict profile).
    public func run(json: String?, operation: PCA.Operation?, _ fn: (ExecutionHandle) async throws -> JSONValue?) async -> ExecutorOutcome {
        guard o.operations != nil else { return refusedMissingStore }
        var input = o.authorize
        input.operation = operation
        if input.now == nil { input.now = clock() }
        return await decide(PCA.authorize(json: json, input), operation, fn)
    }

    private var refusedMissingStore: ExecutorOutcome {
        ExecutorOutcome(execution: .refused("PCAExecutor: missing required component: operations (fail closed)"), authorization: nil)
    }

    private func decide(_ r: PCA.AuthorizeResult, _ op: PCA.Operation?, _ fn: (ExecutionHandle) async throws -> JSONValue?) async -> ExecutorOutcome {
        guard let store = o.operations else { return refusedMissingStore }
        let now = clock
        let cls = op.flatMap { o.reversibilityClassOf?($0) }
        if r.allow {
            let opts = ExecuteOptions(store: store, operation: op, recheck: recheck(now), recheckFor: o.recheckFor, reversibilityClass: cls,
                                      pendingTimeoutMs: timeout, now: now)
            return ExecutorOutcome(execution: await PCA.executeAuthorized(r, options: opts, fn), authorization: nil)
        }
        let denied = ExecutorOutcome(execution: ExecuteOutcome(.denied), authorization: r)
        let failed = r.checks.filter { $0.value == .fail }.map { $0.key }
        guard r.status == 403, failed.count == 1, failed[0] == "replay", let want = op, want.isValid, let pcactn = r.pcactn else { return denied }
        // a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
        guard let id = IV.strictHash(pcactn), let digest = IV.strictHash(want.params), let rec = (try? store.get(id)) ?? nil,
              IV.same(rec.verb, want.verb), IV.same(rec.resource, want.resource), rec.paramsDigest == digest else { return denied }
        return ExecutorOutcome(execution: PCA.fromRecord(store, rec, now(), timeout), authorization: nil)
    }
}
