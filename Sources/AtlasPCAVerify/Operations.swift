import Foundation

// Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.
//
// `PCA.authorize` decides and consumes the PCActn's replay counter. Between that decision and the end of the side effect the
// process can crash, the client can time out and retry, or two workers can pick up the same authorization. A record per
// operation id (`AuthorizedOperation.id`, the digest of the presented PCActn) closes that gap:
//
//  1. `executeAuthorized` creates the record in state `pending` BEFORE anything runs (one atomic create-if-absent: of N
//     concurrent executions of one authorization exactly one gets to run `fn`);
//  2. for an irreversible operation it re-checks revocation, expiry and approval immediately before `fn` (`recheck` is
//     required, fail closed); a failed re-check records `aborted` and `fn` never runs;
//  3. it moves the record to `executing` and only then calls `fn`, with the operation id as the idempotency key;
//  4. the record becomes `committed` (with `fn`'s result) or `failed` (with its error) afterwards.
//
// A second execution of the same id never runs `fn` again: it is answered from the record. Once `pendingTimeoutMs` has passed, a
// record still `pending` is settled `aborted` (the side effect never started) and one still `executing` `uncertain` (it may or may
// not have happened: reconcile it with `resolveOperation` using the idempotency key). Mirrors the reference operation-record
// module; the shared operation-vectors.json corpus pins the state machine and every message.

/// Where an operation is in its execution.
public enum OperationState: String, Sendable {
    /// Claimed for execution, `fn` not started yet (re-check running), or the process crashed before starting it.
    case pending
    /// `fn` has been started: the side effect is running, or the process crashed during or after it.
    case executing
    /// The side effect completed; `result` is what `fn` returned.
    case committed
    /// `fn` threw; not re-run.
    case failed
    /// The pre-execution re-check refused (revoked, expired, approval withdrawn); `fn` never ran.
    case aborted
    /// Found `executing` after `pendingTimeoutMs`: the outcome is unknown and must be reconciled, never re-run.
    case uncertain
}

/// The durable record of one operation. Times are epoch milliseconds.
public struct OperationRecord: Equatable, Sendable {
    public var id: String
    public var state: OperationState
    public var verb: String
    public var resource: String
    public var paramsDigest: String
    /// The effective reversibility class the execution ran under.
    public var reversibility: String
    public var startedAt: Int64
    public var executingAt: Int64?
    public var finishedAt: Int64?
    /// `committed`: what `fn` returned (keep it JSON-serialisable for a durable store).
    public var result: JSONValue?
    /// `failed` / `aborted` / `uncertain`: why.
    public var error: String?

    public init(id: String, state: OperationState, verb: String, resource: String, paramsDigest: String, reversibility: String, startedAt: Int64,
                executingAt: Int64? = nil, finishedAt: Int64? = nil, result: JSONValue? = nil, error: String? = nil) {
        self.id = id
        self.state = state
        self.verb = verb
        self.resource = resource
        self.paramsDigest = paramsDigest
        self.reversibility = reversibility
        self.startedAt = startedAt
        self.executingAt = executingAt
        self.finishedAt = finishedAt
        self.result = result
        self.error = error
    }

    /// The record as the shared corpus writes it (`params_digest`, `startedAt`, `executingAt`, ...; absent members are left out).
    public var json: JSONValue {
        var o: JObject = ["id": .string(id), "state": .string(state.rawValue), "verb": .string(verb), "resource": .string(resource),
                          "params_digest": .string(paramsDigest), "reversibility": .string(reversibility), "startedAt": .int(startedAt)]
        if let x = executingAt { o["executingAt"] = .int(x) }
        if let x = finishedAt { o["finishedAt"] = .int(x) }
        if let x = result { o["result"] = x }
        if let x = error { o["error"] = .string(x) }
        return .object(o)
    }

    /// nil unless `v` is an object with a string `id`, a known `state` and the other string members.
    public init?(json v: JSONValue) {
        guard case let .object(o) = v, case let .string(id)? = o["id"], !id.isEmpty, case let .string(st)? = o["state"], let state = OperationState(rawValue: st),
              case let .string(verb)? = o["verb"], case let .string(res)? = o["resource"], case let .string(pd)? = o["params_digest"],
              case let .string(rev)? = o["reversibility"], let started = o["startedAt"]?.safeInt else { return nil }
        self.init(id: id, state: state, verb: verb, resource: res, paramsDigest: pd, reversibility: rev, startedAt: started,
                  executingAt: o["executingAt"]?.safeInt, finishedAt: o["finishedAt"]?.safeInt, result: o["result"], error: o["error"]?.asString)
    }
}

/// What `OperationStore.create` answers: this call created the record, or the record that already existed.
public enum OperationCreate: Sendable {
    case created
    case existing(OperationRecord)
}

/// Durable, shared storage of operation records. `create` and `transition` MUST be atomic across every process and node that
/// shares the store (a unique-key insert and a conditional `UPDATE ... WHERE state = ?`). A call that cannot decide MUST throw:
/// the executor then refuses.
public protocol OperationStore: Sendable {
    /// Atomically inserts `record` if no record with its id exists; otherwise returns the existing one unchanged.
    func create(_ record: OperationRecord) throws -> OperationCreate
    func get(_ id: String) throws -> OperationRecord?
    /// Atomically replaces the record with `next` only if its current state is `from`. Returns whether it did.
    func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool
}

/// The optional `OperationStore` capability `PCA.recoverOperations` needs: the records still `pending` or `executing`.
public protocol OperationLister: OperationStore {
    func listOpen() throws -> [OperationRecord]
}

/// In-process `OperationStore` for ONE process (tests, a single worker). Its records die with the process.
public final class MemoryOperationStore: OperationLister, @unchecked Sendable {
    private var records: [String: OperationRecord] = [:]
    private let lock = NSLock()

    public init() {}

    public func create(_ record: OperationRecord) -> OperationCreate {
        lock.lock()
        defer { lock.unlock() }
        if let cur = records[record.id] { return .existing(cur) }
        records[record.id] = record
        return .created
    }

    public func get(_ id: String) -> OperationRecord? {
        lock.lock()
        defer { lock.unlock() }
        return records[id]
    }

    public func transition(_ id: String, from: OperationState, to next: OperationRecord) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let cur = records[id], cur.state == from else { return false }
        var n = next
        n.id = id
        records[id] = n
        return true
    }

    /// The open records, ordered by id.
    public func listOpen() -> [OperationRecord] {
        lock.lock()
        defer { lock.unlock() }
        return records.values.filter { $0.state == .pending || $0.state == .executing }.sorted { IV.utf8Less($0.id, $1.id) }
    }
}

/// What a pre-execution re-check answered.
public struct RecheckResult: Equatable, Sendable {
    public let ok: Bool
    public let reason: String?
    public init(ok: Bool, reason: String? = nil) {
        self.ok = ok
        self.reason = reason
    }
    public static let pass = RecheckResult(ok: true)
    public static func refuse(_ reason: String) -> RecheckResult { RecheckResult(ok: false, reason: reason) }
}

/// What the executed function receives.
public struct ExecutionHandle: Sendable {
    /// The operation id: pass it as the idempotency key of the downstream call (e.g. `Idempotency-Key`).
    public let idempotencyKey: String
    public let operation: PCA.AuthorizedOperation
    public let pcactn: JSONValue
    public init(idempotencyKey: String, operation: PCA.AuthorizedOperation, pcactn: JSONValue) {
        self.idempotencyKey = idempotencyKey
        self.operation = operation
        self.pcactn = pcactn
    }
}

/// A throwable whose message is recorded verbatim (`failed` / recheck errors). Any other error is recorded by its description.
public struct PCAFailure: Error, LocalizedError, CustomStringConvertible, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
    public var errorDescription: String? { message }
}

func errorMessage(_ e: Error) -> String {
    if let f = e as? PCAFailure { return f.message }
    if let l = e as? LocalizedError, let d = l.errorDescription { return d }
    return String(describing: e)
}

/// `ExecuteOutcome.status`.
public enum ExecuteStatus: String, Sendable {
    case committed, failed, aborted, pending, uncertain, refused
    /// Only from `PCAExecutor`: the authorization was denied, nothing ran.
    case denied
}

/// The outcome of an execution attempt. `replayed` means it was answered from an existing record.
///
/// `committed` (`result`; `recorded` false means `fn` ran but the record could not be written: it stays `executing` and settles
/// `uncertain`), `failed` (`error`), `aborted` (`reason`), `pending` (another execution of this id is in flight; `fn` did not
/// run here), `uncertain` (`reason`: the earlier outcome is unknown; `fn` did not run here), or `refused` (`reason`: nothing ran and
/// nothing was recorded).
public struct ExecuteOutcome: Equatable, Sendable {
    public let status: ExecuteStatus
    public let operationId: String?
    public let result: JSONValue?
    public let error: String?
    public let reason: String?
    public let replayed: Bool
    public let recorded: Bool

    init(_ status: ExecuteStatus, id: String? = nil, result: JSONValue? = nil, error: String? = nil, reason: String? = nil, replayed: Bool = false, recorded: Bool = false) {
        self.status = status
        self.operationId = id
        self.result = result
        self.error = error
        self.reason = reason
        self.replayed = replayed
        self.recorded = recorded
    }

    static func refused(_ reason: String) -> ExecuteOutcome { ExecuteOutcome(.refused, reason: reason) }

    /// The outcome as the shared corpus writes it.
    public var json: JSONValue {
        var o: JObject = ["status": .string(status.rawValue)]
        switch status {
        case .committed:
            o["operationId"] = operationId.map { .string($0) } ?? .null
            o["replayed"] = .bool(replayed)
            o["recorded"] = .bool(recorded)
            if let r = result { o["result"] = r }
        case .failed:
            o["operationId"] = operationId.map { .string($0) } ?? .null
            o["error"] = .string(error ?? "")
            o["replayed"] = .bool(replayed)
        case .aborted, .uncertain:
            o["operationId"] = operationId.map { .string($0) } ?? .null
            o["reason"] = .string(reason ?? "")
            o["replayed"] = .bool(replayed)
        case .pending:
            o["operationId"] = operationId.map { .string($0) } ?? .null
            o["replayed"] = .bool(replayed)
        case .refused:
            o["reason"] = .string(reason ?? "")
        case .denied:
            break
        }
        return .object(o)
    }
}

/// `PCA.executeAuthorized` options.
public struct ExecuteOptions {
    /// REQUIRED (shared and durable in production).
    public var store: OperationStore?
    /// When set, the operation about to execute: the authorization must be for exactly it.
    public var operation: PCA.Operation?
    /// Re-checks, immediately before `fn`, that the authorization still stands (grant not revoked, approval not expired or
    /// withdrawn). REQUIRED for an irreversible operation (fail closed), and for the others with `recheckFor` "always". The
    /// PCActn's own expiry (`exp`) is always checked with it. A throw is a refusal.
    public var recheck: ((ExecutionHandle) async throws -> RecheckResult)?
    /// nil or "irreversible" (default), or "always".
    public var recheckFor: String?
    /// The server's authoritative class; the stricter of it and the signed class applies (missing or unknown = irreversible).
    public var reversibilityClass: String?
    /// An open record older than this is settled (0: `PCA.OPERATION_PENDING_TIMEOUT_MS`).
    public var pendingTimeoutMs: Int64
    /// The clock in epoch ms (nil: the wall clock).
    public var now: (() -> Int64)?

    public init(store: OperationStore? = nil, operation: PCA.Operation? = nil, recheck: ((ExecutionHandle) async throws -> RecheckResult)? = nil,
                recheckFor: String? = nil, reversibilityClass: String? = nil, pendingTimeoutMs: Int64 = 0, now: (() -> Int64)? = nil) {
        self.store = store
        self.operation = operation
        self.recheck = recheck
        self.recheckFor = recheckFor
        self.reversibilityClass = reversibilityClass
        self.pendingTimeoutMs = pendingTimeoutMs
        self.now = now
    }

    var clock: () -> Int64 { now ?? { Int64(Date().timeIntervalSince1970 * 1000) } }
    var timeout: Int64 { pendingTimeoutMs != 0 ? pendingTimeoutMs : PCA.OPERATION_PENDING_TIMEOUT_MS }
}

/// The reconciled outcome of an `uncertain` operation.
public enum OperationResolution: Sendable {
    /// The downstream system reports it applied (with its result).
    case committed(result: JSONValue?)
    /// It never applied.
    case failed(error: String)
}

extension PCA {
    /// The default age after which an open record is settled.
    public static let OPERATION_PENDING_TIMEOUT_MS: Int64 = 5 * 60_000

    static func storeFailed(_ e: Error) -> ExecuteOutcome {
        .refused("executeAuthorized: the operation store failed (fail closed): \(errorMessage(e))")
    }

    /// Settles an open record older than `timeoutMs`: `pending` -> `aborted`, `executing` -> `uncertain`.
    static func settleStale(_ store: OperationStore, _ rec: OperationRecord, _ now: Int64, _ timeoutMs: Int64) throws -> OperationRecord {
        guard rec.state == .pending || rec.state == .executing else { return rec }
        // executing is aged from the moment fn was started (a slow re-check does not count against it)
        var start = rec.startedAt
        if rec.state == .executing, let e = rec.executingAt, e != 0 { start = e }
        if !(now - start > timeoutMs) { return rec }
        var next = rec
        next.finishedAt = now
        if rec.state == .pending {
            next.state = .aborted
            next.error = "not started within \(timeoutMs) ms of the claim: the side effect never ran"
        } else {
            next.state = .uncertain
            next.error = "no outcome recorded within \(timeoutMs) ms of the start: the side effect may or may not have happened"
        }
        _ = try store.transition(rec.id, from: rec.state, to: next)
        // whatever is stored now (the original execution may have finished in between)
        return try store.get(rec.id) ?? next
    }

    /// Answers an execution attempt from an existing record (never runs anything).
    static func fromRecord(_ store: OperationStore, _ rec0: OperationRecord, _ now: Int64, _ timeoutMs: Int64) -> ExecuteOutcome {
        let rec: OperationRecord
        do { rec = try settleStale(store, rec0, now, timeoutMs) } catch { return storeFailed(error) }
        func orDefault(_ s: String?, _ d: String) -> String { (s ?? "").isEmpty ? d : s! }
        switch rec.state {
        case .committed: return ExecuteOutcome(.committed, id: rec.id, result: rec.result, replayed: true, recorded: true)
        case .failed: return ExecuteOutcome(.failed, id: rec.id, error: orDefault(rec.error, "failed"), replayed: true)
        case .aborted: return ExecuteOutcome(.aborted, id: rec.id, reason: orDefault(rec.error, "aborted"), replayed: true)
        case .uncertain: return ExecuteOutcome(.uncertain, id: rec.id, reason: orDefault(rec.error, "outcome unknown"), replayed: true)
        case .pending, .executing: return ExecuteOutcome(.pending, id: rec.id, replayed: true)
        }
    }

    /// Leaves `executing` (or `uncertain`, when recovery settled a slow execution) for the final state.
    static func finishRecord(_ store: OperationStore, _ rec: OperationRecord, _ mutate: (inout OperationRecord) -> Void) throws -> Bool {
        var out = rec
        mutate(&out)
        if try store.transition(rec.id, from: rec.state, to: out) { return true }
        if rec.state == .executing { return try store.transition(rec.id, from: .uncertain, to: out) }
        return false
    }

    /// Answers from the record as it is stored now (a concurrent recovery or execution changed it).
    static func answerCurrent(_ store: OperationStore, _ id: String, _ now: Int64, _ timeoutMs: Int64) -> ExecuteOutcome {
        do {
            guard let cur = try store.get(id) else { return ExecuteOutcome(.uncertain, id: id, reason: "the operation record disappeared", replayed: true) }
            return fromRecord(store, cur, now, timeoutMs)
        } catch {
            return storeFailed(error)
        }
    }

    /// Executes an allowed `authorize` result at most once, with a durable record (see the file comment). `fn` runs only if this
    /// call created the `pending` record and the re-check (when required) passed; every other outcome is answered from the record.
    /// A throw from `fn` is recorded as `failed` and returned, not re-thrown. Never throws.
    public static func executeAuthorized(_ az: AuthorizeResult, options opts: ExecuteOptions,
                                         _ fn: (ExecutionHandle) async throws -> JSONValue?) async -> ExecuteOutcome {
        guard let store = opts.store else { return .refused("executeAuthorized: missing required component: store (fail closed)") }
        guard az.allow, let op = az.operation, !op.id.isEmpty, let pcactn = az.pcactn else {
            return .refused("executeAuthorized: the authorization did not allow an operation")
        }
        if let want = opts.operation {
            guard want.isValid, let d = IV.strictHash(want.params), IV.same(want.verb, op.verb), IV.same(want.resource, op.resource), d == op.paramsDigest else {
                return .refused("executeAuthorized: the authorization is not for this operation (verb, resource or params differ)")
            }
        }
        let now = opts.clock
        let timeoutMs = opts.timeout
        let reversibility = effectiveReversibility(serverClass: opts.reversibilityClass, signedClass: pcactn.get("action")?.get("reversibility_class"))
        let mustRecheck = reversibility == "irreversible" || opts.recheckFor == "always"
        if mustRecheck && opts.recheck == nil {
            return .refused("executeAuthorized: a \(reversibility) operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)")
        }

        let handle = ExecutionHandle(idempotencyKey: op.id, operation: op, pcactn: pcactn)
        let rec = OperationRecord(id: op.id, state: .pending, verb: op.verb, resource: op.resource, paramsDigest: op.paramsDigest,
                                  reversibility: reversibility, startedAt: now())
        do {
            if case let .existing(cur) = try store.create(rec) { return fromRecord(store, cur, now(), timeoutMs) }
        } catch {
            return storeFailed(error)
        }

        if mustRecheck {
            var rc: RecheckResult
            if let exp = IV.num(pcactn.get("exp")), Double(now()) > exp {
                rc = .refuse("the PCActn expired at \(msStr(exp))")
            } else if let check = opts.recheck {
                do { rc = try await check(handle) } catch { rc = .refuse("recheck error (fail closed): \(errorMessage(error))") }
            } else {
                rc = .refuse("refused")
            }
            if !rc.ok {
                let why = (rc.reason ?? "").isEmpty ? "refused" : rc.reason!
                let reason = "recheck: \(why)"
                do {
                    let t = now()
                    if try finishRecord(store, rec, { $0.state = .aborted; $0.error = reason; $0.finishedAt = t }) {
                        return ExecuteOutcome(.aborted, id: rec.id, reason: reason)
                    }
                } catch {
                    return storeFailed(error)
                }
                return answerCurrent(store, rec.id, now(), timeoutMs)
            }
        }

        // the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
        var running = rec
        running.state = .executing
        running.executingAt = now()
        do {
            if !(try store.transition(rec.id, from: .pending, to: running)) { return answerCurrent(store, rec.id, now(), timeoutMs) }
        } catch {
            return storeFailed(error)
        }

        let result: JSONValue?
        do {
            result = try await fn(handle)
        } catch {
            let msg = errorMessage(error)
            let t = now()
            _ = try? finishRecord(store, running) { $0.state = .failed; $0.error = msg; $0.finishedAt = t }
            return ExecuteOutcome(.failed, id: rec.id, error: msg)
        }
        let t = now()
        let recorded = (try? finishRecord(store, running) { $0.state = .committed; $0.result = result; $0.finishedAt = t }) ?? false
        return ExecuteOutcome(.committed, id: rec.id, result: result, recorded: recorded)
    }

    /// Settles every open record older than `olderThanMs` (0: the default; run it at startup and periodically): `pending` ->
    /// `aborted` (the side effect never started), `executing` -> `uncertain`. Returns the records it settled and needs a store
    /// that is an `OperationLister`. Nothing is re-run: reconcile each `uncertain` one with `resolveOperation`.
    public static func recoverOperations(_ store: OperationStore, olderThanMs: Int64 = 0, now: (() -> Int64)? = nil) throws -> [OperationRecord] {
        guard let lister = store as? OperationLister else {
            throw PCAFailure("recoverOperations: the store has no listOpen (recover by id with recoverOperation)")
        }
        var out: [OperationRecord] = []
        for r in try lister.listOpen() {
            if let u = try recoverOperation(store, id: r.id, olderThanMs: olderThanMs, now: now), u.state != r.state { out.append(u) }
        }
        return out
    }

    /// `recoverOperations` for one id. Returns the record as it now stands (nil: no record, the operation never started).
    public static func recoverOperation(_ store: OperationStore, id: String, olderThanMs: Int64 = 0, now: (() -> Int64)? = nil) throws -> OperationRecord? {
        guard let r = try store.get(id) else { return nil }
        let t = now?() ?? Int64(Date().timeIntervalSince1970 * 1000)
        return try settleStale(store, r, t, olderThanMs != 0 ? olderThanMs : OPERATION_PENDING_TIMEOUT_MS)
    }

    /// Settles an `uncertain` record after reconciling with the downstream system (look the idempotency key up there). Returns false
    /// when the record is not `uncertain` (or unknown).
    public static func resolveOperation(_ store: OperationStore, id: String, outcome: OperationResolution, now: (() -> Int64)? = nil) throws -> Bool {
        guard let r = try store.get(id), r.state == .uncertain else { return false }
        var next = r
        next.finishedAt = now?() ?? Int64(Date().timeIntervalSince1970 * 1000)
        switch outcome {
        case let .committed(result):
            next.state = .committed
            next.result = result
        case let .failed(error):
            next.state = .failed
            next.error = error
        }
        return try store.transition(id, from: .uncertain, to: next)
    }
}
