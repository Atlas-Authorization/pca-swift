import Foundation

// The undo-window coordinator: admission, the durable ledger, the human surface and the real rollback.
//
//     admit      ELIGIBILITY. An action gets a veto window only when the policy does not turn windows off, its signed reversibility class is `reversible`, the
//                `engine` (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating action is AUTHORIZED under the original grant (the
//                policy VM releases it over the original PCActn's verified chain).
//     open       writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the `opened` receipt, mints the one-click undo
//                token and notifies the principal. A window nobody was told about is no window: a failed notification aborts the record and raises an alert.
//     veto       a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves `open -> vetoed` exactly once and starts the compensation.
//     compensate re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt through the `operations` store
//                and the `compensate` executor. Success: `compensated` and the budget reservation released. Anything else: `compensation_failed`, the reservation
//                kept and an alert raised (never silent).
//     finalizeDue closes the windows whose time is up (`open -> finalized`) and commits their budget reservations.
//
// Synchronous. Records, plans, notices and alerts are the reference's objects as JSON trees. A budget release carries NO evidence unless the caller supplies it
// through `PCAUndoBudget.evidence` (for example a release signed with `PCABudgetLedger.signRelease`).

/// A bond ledger the coordinator can slash through (`StoreBondLedger` or your own): answers the settlement record.
public protocol UndoBondLedger: AnyObject {
    func slashBond(_ params: JSONValue) throws -> JSONValue
}

extension StoreBondLedger: UndoBondLedger {}

/// Aggregate budgets held during the window: committed on finalize, released on compensation or abort. `evidence(reservation, reason)` supplies the release
/// evidence (`reason` is `rollback` or `effect_not_run`); nil (the default) releases with none.
public struct PCAUndoBudget {
    public var ledger: BudgetLedger
    public var evidence: ((_ reservation: JSONValue, _ reason: String) throws -> JSONValue?)?
    public init(ledger: BudgetLedger, evidence: ((_ reservation: JSONValue, _ reason: String) throws -> JSONValue?)? = nil) { self.ledger = ledger; self.evidence = evidence }
}

/// Everything `PCAUndoCoordinator.create` needs. Required: `store`, `engine`, `signerSecret` (32 bytes), `audience`, `resolveGrant`, `compensate`, `operations`,
/// `notifier`, `alert`.
public struct PCAUndoOptions {
    /// The durable undo ledger (`durable == true`).
    public var store: UndoStore
    /// Confirmed reversibility and compensations: `plan(operation, operationId)` answers a plan `{def_digest, compensation: {verb, params, def_digest, target_param?}, render?,
    /// render_digest?}` or nil.
    public var engine: (_ operation: JSONValue, _ operationId: String) throws -> JSONValue?
    public var signerSecret: [UInt8]
    public var audience: String
    /// The grant by reference, from YOUR store.
    public var resolveGrant: (_ grantRef: String?, _ pcactn: JSONValue) throws -> JSONValue?
    /// Runs a compensating action (your connector); throw on failure. The call is `{operation, idempotencyKey, undoOf, record, originalResult?}`.
    public var compensate: (_ call: JSONValue) throws -> JSONValue?
    /// At-most-once records for compensation attempts.
    public var operations: OperationStore
    /// The principal's channels (`PCAUndoServer.undoNotifierFromDispatcher`): answers `{delivered, reason?}`.
    public var notifier: (_ notice: JSONValue) throws -> JSONValue
    /// Where a failure that needs a human goes (pager, SIEM). Never silent.
    public var alert: (_ alert: JSONValue) throws -> Void
    /// `{mode?: always | escalations | off, windowMs?, onRevocation?: keep | veto}` for (operation, grant).
    public var policy: ((_ operation: JSONValue, _ grant: JSONValue) throws -> JSONValue?)?
    public var windowMinMs: Double?
    public var windowMaxMs: Double?
    public var windowDefaultMs: Double?
    /// The value of the compensating action's target parameter. Default: `effect.result.id` when it is a non-empty string.
    public var resolveTarget: ((_ record: JSONValue) throws -> String?)?
    public var budget: PCAUndoBudget?
    /// Verifier-side PQ pins forwarded to the compensation decision.
    public var pqPins: JSONValue?
    /// A vetoed record whose effect was never reported is compensated anyway after this long (ms). Default 5 minutes.
    public var effectTimeoutMs: Int64 = 5 * 60_000
    public var now: (() -> Double)?
    /// Vetoes received somewhere else (the hosted veto endpoint; `PCAUndoServer.hostedUndoVetoRelay`): read before every finalize sweep. A relay that cannot be read
    /// finalizes NOTHING.
    public var relay: (() throws -> [PCAUndoServer.RelayedVeto])?
    /// TESTS ONLY: accept a store whose `durable` is false (every open window is lost on restart).
    public var insecureVolatileStore = false
    /// A bond ledger for `rollbackOnSlash`.
    public var bonds: UndoBondLedger?

    public init(store: UndoStore, engine: @escaping (JSONValue, String) throws -> JSONValue?, signerSecret: [UInt8], audience: String,
                resolveGrant: @escaping (String?, JSONValue) throws -> JSONValue?, compensate: @escaping (JSONValue) throws -> JSONValue?, operations: OperationStore,
                notifier: @escaping (JSONValue) throws -> JSONValue, alert: @escaping (JSONValue) throws -> Void) {
        self.store = store; self.engine = engine; self.signerSecret = signerSecret; self.audience = audience; self.resolveGrant = resolveGrant
        self.compensate = compensate; self.operations = operations; self.notifier = notifier; self.alert = alert
    }
}

public final class PCAUndoCoordinator: PCAUndoServer.EffectSink {
    static let MAX_CAS = 64

    private let o: PCAUndoOptions
    private let key: PCAEdKey
    private var bonds: UndoBondLedger?
    /// The undo service key's public half: verifies tokens and receipts elsewhere.
    public let signerPublic: String

    private enum Applied {
        case refused(code: String, reason: String)
        case done(record: JSONValue, applied: Bool)
    }

    private init(_ o: PCAUndoOptions) throws {
        self.o = o
        self.key = try PCAEdKey(seed: o.signerSecret)
        self.signerPublic = key.id
        self.bonds = o.bonds
    }

    /// Build the coordinator. Throws `config` for a missing component and `not_durable` for a volatile store (fail closed).
    public static func create(_ opts: PCAUndoOptions) throws -> PCAUndoCoordinator {
        let missing = PCAUndoServer.missingUndoComponents(store: opts.store, hasEngine: true, signerSecret: opts.signerSecret, audience: opts.audience, hasResolveGrant: true,
                                                          hasCompensate: true, hasOperations: true, hasNotifier: true, hasAlert: true)
        if !missing.isEmpty { throw UndoError("config", "undo coordinator: missing required component(s): \(missing.joined(separator: ", "))") }
        if !opts.store.durable && !opts.insecureVolatileStore { throw UndoError("not_durable", "an undo ledger must be durable: a restart would lose every open window and its compensation") }
        // a negative timeout would make compensation skip the wait for the effect report
        if !(opts.effectTimeoutMs >= 0) { throw UndoError("config", "undo coordinator: effectTimeoutMs must be a non-negative number") }
        return try PCAUndoCoordinator(opts)
    }

    // ---- plumbing ----

    private func now() throws -> Int64 {
        let t = (o.now ?? { Date().timeIntervalSince1970 * 1000 })()
        guard t.isFinite, abs(t.rounded(.down)) <= Double(Canonical.MAX_SAFE) else { throw UndoError("invalid", "the clock returned a non-finite time") }
        return Int64(t.rounded(.down))
    }

    private func alert(_ a: JSONValue) {
        do { try o.alert(a) } catch { // an alert sink that throws is itself a failure the operator must see
            FileHandle.standardError.write(Data("pca undo alert (\(JS.toString(a.get("code")))) for \(JS.toString(a.get("record"))): \(JS.toString(a.get("reason")))\n".utf8))
        }
    }

    private func alertOf(_ level: String, _ code: String, _ record: String, _ reason: String) -> JSONValue {
        .object(["level": .string(level), "code": .string(code), "record": .string(record), "reason": .string(reason)])
    }

    @discardableResult
    private func notify(_ n: JSONValue) -> (delivered: Bool, reason: String?) {
        do {
            let r = try o.notifier(n)
            if r.get("delivered") == .bool(true) { return (true, nil) }
            let why = r.get("reason")?.asString
            return (false, (why?.isEmpty ?? true) ? "no channel delivered the notice" : why)
        } catch { return (false, PCAStoreError.text(error).isEmpty ? "notifier error" : PCAStoreError.text(error)) }
    }

    private static func strip(_ r: JSONValue) -> JSONValue {
        var m = r.asObject ?? [:]
        m["pcactn"] = nil
        m["receipts"] = nil
        return .object(m)
    }

    private static func with(_ r: JSONValue, _ f: (inout JObject) -> Void) -> JSONValue {
        var m = r.asObject ?? [:]
        f(&m)
        return .object(m)
    }

    private func apply(_ id: String, _ ev: JSONValue, checkAt: Int64? = nil) throws -> Applied {
        for _ in 0..<PCAUndoCoordinator.MAX_CAS {
            guard let cur = try o.store.get(id) else { return .refused(code: "unknown", reason: "no undo record \(id)") }
            let t = try now()
            let tr = Undo.transition(cur, ev, now: Double(checkAt ?? t)) // a relayed veto is judged as of when the principal made it
            if tr.outcome == "refused" { return .refused(code: tr.code ?? "invalid", reason: tr.reason ?? "") }
            if tr.outcome == "replayed" { return .done(record: tr.record ?? cur, applied: false) }
            let next = try Undo.withReceipt(tr.record ?? cur, event: tr.event ?? "", note: tr.note ?? "", at: t, key: key)
            let ver = cur.get("ver")?.safeInt ?? 0
            if try o.store.replace(id, expectedVer: ver, next: next) { return .done(record: next, applied: true) }
        }
        throw UndoError("conflict_exhausted", "undo record \(id) kept changing")
    }

    private func must(_ id: String, _ ev: JSONValue) throws -> (record: JSONValue, applied: Bool) {
        switch try apply(id, ev) {
        case let .refused(code, reason): throw UndoError("invalid", "\(code): \(reason)")
        case let .done(record, applied): return (record, applied)
        }
    }

    private func settleBudget(_ rec: JSONValue, _ how: String) {
        guard let b = o.budget, let list = rec.get("budget")?.asArray, !list.isEmpty else { return }
        let id = rec.get("id")?.asString ?? ""
        for r in list {
            let k = r.get("key")?.asString ?? "", rid = r.get("id")?.asString ?? ""
            do {
                let out: JSONValue
                if how == "commit" { out = try b.ledger.commit(k, rid) } else {
                    let ev = try b.evidence?(r, how) // no evidence unless the caller supplies it
                    out = try b.ledger.release(k, rid, ev)
                }
                let outcome = out.get("outcome")?.asString
                if outcome != "settled" && outcome != "replayed" { alert(alertOf("warning", "budget_settle_failed", id, "\(how) of \(k)/\(rid): \(outcome ?? "undefined")")) }
            } catch {
                let t = PCAStoreError.text(error)
                alert(alertOf("warning", "budget_settle_failed", id, "\(how) of \(k)/\(rid): \(t.isEmpty ? "error" : t)"))
            }
        }
    }

    private func policyOf(_ op: JSONValue, _ grant: JSONValue) throws -> JSONValue {
        guard let p = o.policy else { return .object([:]) }
        return try p(op, grant) ?? .object([:])
    }

    private func decodePcactn(_ v: JSONValue?) throws -> JSONValue {
        guard let text = v?.asString else { throw JSError("decodePCActn: not text") }
        if text.utf8.count > PCA.MAX_ARTIFACT_BYTES { throw JSError(PCA.ARTIFACT_SIZE_REASON) }
        let p = try StrictJSON.parse(text)
        guard p.isObject else { throw JSError("decodePCActn: not an object") }
        return p
    }

    /// The policy VM on the compensating action under the original chain, at `at` (the admission time).
    private func compensationAllowed(_ pc: JSONValue, _ grant: JSONValue, _ op: JSONValue, _ at: Int64) throws -> (ok: Bool, reason: String) {
        var input: JObject = ["grant": grant, "trustedRoot": grant,
                              "action": .object(["action": .object(["verb": op.get("verb") ?? .null, "resource": op.get("resource") ?? .null, "params": op.get("params") ?? .object([:])])]),
                              "risk": .object([:]), "budget": .object(["B": .int(0), "tau": .int(at)]), "now": .int(at)]
        if let c = pc.get("cap_chain"), !c.isNull { input["chain"] = c }
        if let p = o.pqPins { input["pqPins"] = p }
        let d = try PCAPolicyVm.decide(.object(input))
        if d.get("releaseGuardianShare") == .bool(true) { return (true, "") }
        let why = (d.get("reasons")?.asArray ?? []).compactMap { $0.asString }.first { !IV.startsWith($0, "risk input") }
        return (false, why ?? "the grant does not authorize the compensating action")
    }

    // ---- the API ----

    /// ELIGIBILITY: an admission object, or `{refused: reason}`. Never throws.
    public func admit(pcactn pc: JSONValue, operation op: JSONValue, converted: Bool, grant: JSONValue? = nil) -> JSONValue {
        func refused(_ r: String) -> JSONValue { .object(["refused": .string(r)]) }
        do {
            guard pc.isObject, op.isObject, let verb = op.get("verb")?.asString, let resource = op.get("resource")?.asString else { return refused("no operation") }
            var g = grant
            if g == nil || g?.isNull == true { g = try o.resolveGrant(pc.get("grant_ref")?.asString, pc) }
            guard let gr = g, !gr.isNull else { return refused("unknown grant") }
            let pol = try policyOf(op, gr)
            let mode = StoreJ.nonEmpty(pol.get("mode")) ?? "always"
            if mode == "off" { return refused("policy: undo windows are off") }
            if mode == "escalations" && !converted { return refused("policy: windows only replace approvals") }
            let cls = pc.get("action")?.get("reversibility_class")
            if PCA.classRank(cls) != 0 { return refused("the signed class is \(cls.map { JS.toString($0) } ?? "undefined")") } // the stricter of the signed class and the definition applies
            let id = Canonical.hashCanonical(pc)
            guard let plan = try o.engine(op, id), plan.isObject, let pcomp = plan.get("compensation"), pcomp.isObject else { return refused("not confirmed reversible, or no confirmed compensating action") }
            var comp: JObject = ["verb": pcomp.get("verb") ?? .null, "resource": .string(resource), "params": pcomp.get("params") ?? .null, "undo_of": .string(id),
                                 "def_digest": pcomp.get("def_digest") ?? .null]
            if let tp = pcomp.get("target_param"), !tp.isNull { comp["target_param"] = tp }
            let t = try now()
            let allowed = try compensationAllowed(pc, gr, .object(["verb": comp["verb"] ?? .null, "resource": .string(resource), "params": comp["params"] ?? .null]), t)
            if !allowed.ok { return refused("the compensating action is not authorized under the grant: \(allowed.reason)") }
            let pw = pol.get("windowMs").flatMap { IV.num($0) }
            let windowMs = Undo.resolveWindow(pw, minMs: o.windowMinMs, maxMs: o.windowMaxMs, defaultMs: o.windowDefaultMs)
            return .object(["id": .string(id), "opened_at": .int(t), "window_end": .int(t + windowMs), "converted": .bool(converted), "plan": plan, "compensation": .object(comp),
                            "pcactn": pc, "grant": gr, "operation": .object(["verb": .string(verb), "resource": .string(resource), "params": op.get("params") ?? .object([:])])])
        } catch {
            let t = PCAStoreError.text(error)
            return refused("undo admission error (fail closed): \(t.isEmpty ? "unknown" : t)")
        }
    }

    private func infoOf(_ rec: JSONValue) throws -> JSONValue {
        guard let tok = Undo.encodeToken(try Undo.signToken(record: rec, key: key)) else { throw UndoError("invalid", "the undo token is outside the strict JSON profile") }
        let end = rec.get("window_end") ?? .null
        return .object(["id": rec.get("id") ?? .null, "window_end": end, "converted": rec.get("converted") ?? .null,
                        "compensation": .object(["verb": rec.get("compensation")?.get("verb") ?? .null, "resource": rec.get("compensation")?.get("resource") ?? .null]),
                        "token": .string(tok),
                        "obligation": .object(["kind": .string("undo_window"), "params": .object(["id": rec.get("id") ?? .null, "window_end": end]), "due": end])])
    }

    /// Write the record durably, sign the `opened` receipt, mint the one-click token and tell the principal. `bond` is `{ref, challengeEndsAt}`.
    public func open(_ adm: JSONValue, bond: (ref: String, challengeEndsAt: Double)? = nil) throws -> JSONValue {
        guard let pcactn = adm.get("pcactn"), let chain = pcactn.get("cap_chain")?.asArray, let last = chain.last, let comp = adm.get("compensation"),
              let grant = adm.get("grant"), let id = adm.get("id")?.asString, let openedAt = adm.get("opened_at")?.safeInt, let admEnd = adm.get("window_end")?.safeInt else {
            throw UndoError("invalid", "open: malformed admission")
        }
        let windowEnd = bond.map { Swift.max(admEnd, Int64($0.challengeEndsAt.rounded(.down))) } ?? admEnd
        guard let cdig = Undo.compensationDigest(comp) else { throw UndoError("invalid", "open: the compensation is outside the strict JSON profile") }
        let plan = adm.get("plan") ?? .null
        var base: JObject = ["v": .int(1), "id": .string(id), "aud": .string(o.audience), "grant_ref": pcactn.get("grant_ref") ?? .null, "holder": last.get("holder") ?? .null,
                             "principal": grant.get("issuer") ?? .null,
                             "action": .object(["verb": adm.get("operation")?.get("verb") ?? .null, "resource": adm.get("operation")?.get("resource") ?? .null,
                                                "params_digest": pcactn.get("action")?.get("params_digest") ?? .null, "def_digest": plan.get("def_digest") ?? .null]),
                             "compensation": comp, "compensation_digest": .string(cdig)]
        if let rd = plan.get("render_digest"), !rd.isNull { base["render_digest"] = rd }
        let converted = adm.get("converted") == .bool(true)
        base["opened_at"] = .int(openedAt)
        base["window_end"] = .int(windowEnd)
        base["converted"] = .bool(converted)
        base["state"] = .string("open")
        base["ver"] = .int(0)
        base["pcactn"] = .string(Canonical.canonicalize(pcactn))
        if let b = bond { base["bond_ref"] = .string(b.ref) }
        base["attempt"] = .int(0)
        base["receipts"] = .array([])
        let rec = try Undo.withReceipt(.object(base), event: "opened", note: converted ? "converted" : "", at: openedAt, key: key)
        let c = try o.store.create(rec)
        if !c.created {
            // a retry of the same admission returns the same window; anything else is a different action under the same id
            let ex = c.record ?? .null
            if ex.get("compensation_digest")?.asString != cdig || ex.get("state")?.asString != "open" {
                throw UndoError("invalid", "undo record \(id) already exists with other terms or state \(ex.get("state").map { JS.toString($0) } ?? "undefined")")
            }
            return try infoOf(ex)
        }
        let info = try infoOf(rec)
        var notice: JObject = ["kind": .string("opened"), "record": PCAUndoCoordinator.strip(rec), "token": info.get("token") ?? .null]
        if let r = plan.get("render"), !r.isNull { notice["render"] = r }
        let n = notify(.object(notice))
        if !n.delivered {
            _ = try apply(id, .object(["kind": .string("abort"), "reason": .string("notify_failed")]))
            alert(alertOf("critical", "notify_failed", id, "the principal could not be told about the undo window: \(n.reason ?? "not delivered")"))
            throw UndoError("invalid", "notify_failed: the undo window could not be announced (\(n.reason ?? "not delivered"))")
        }
        return info
    }

    public func get(_ id: String) throws -> JSONValue? { try o.store.get(id) }

    /// Hold aggregate budget reservations `[{key, id}]` until the window closes.
    public func holdBudget(_ id: String, _ reservations: [JSONValue]) throws -> JSONValue {
        for _ in 0..<PCAUndoCoordinator.MAX_CAS {
            guard let cur = try o.store.get(id) else { throw UndoError("invalid", "no undo record \(id)") }
            let st = cur.get("state")?.asString ?? ""
            if st != "open" && st != "vetoed" { throw UndoError("invalid", "a \(st) record holds no budget") }
            let ver = cur.get("ver")?.safeInt ?? 0
            let nxt = PCAUndoCoordinator.with(cur) {
                $0["budget"] = .array((cur.get("budget")?.asArray ?? []) + reservations.map { .object(["key": $0.get("key") ?? .null, "id": $0.get("id") ?? .null]) })
                $0["ver"] = .int(ver + 1)
            }
            if try o.store.replace(id, expectedVer: ver, next: nxt) { return nxt }
        }
        throw UndoError("conflict_exhausted", "undo record \(id) kept changing")
    }

    /// Report the original effect (its result names the compensation target). A veto that arrived while it ran is acted on now.
    public func recordEffect(_ id: String, result: JSONValue? = nil) throws -> JSONValue {
        var ev: JObject = ["kind": .string("effect")]
        if let r = result { ev["result"] = r }
        let r = try must(id, .object(ev))
        return r.record.get("state")?.asString == "vetoed" ? try runCompensation(r.record) : r.record
    }

    public func abort(_ id: String, reason: String) throws -> JSONValue {
        let r = try must(id, .object(["kind": .string("abort"), "reason": .string(reason)]))
        if r.applied { settleBudget(r.record, "effect_not_run") }
        return r.record
    }

    private func finishCompensated(_ rec: JSONValue) -> JSONValue {
        if rec.get("state")?.asString == "compensated" {
            settleBudget(rec, "rollback")
            notify(.object(["kind": .string("compensated"), "record": PCAUndoCoordinator.strip(rec)]))
        }
        return rec
    }

    private func runCompensation(_ rec0: JSONValue) throws -> JSONValue {
        let rec = rec0
        if rec.get("state")?.asString != "vetoed" { return rec }
        let recId = rec.get("id")?.asString ?? ""
        let t = try now()
        let effectNil = rec.get("effect") == nil || rec.get("effect")?.isNull == true
        let vetoAt = rec.get("veto")?.get("at")?.safeInt ?? t
        if effectNil && t - vetoAt < o.effectTimeoutMs { return rec } // wait for the effect report (recordEffect resumes)
        let pc = try decodePcactn(rec.get("pcactn"))
        let grant = try o.resolveGrant(rec.get("grant_ref")?.asString, pc)

        func fail(_ reason: String, _ code: String = "compensation_failed") throws -> JSONValue {
            let r = try apply(recId, .object(["kind": .string("compensation_failed"), "reason": .string(reason)]))
            switch r {
            case .refused: return try o.store.get(recId) ?? rec
            case let .done(out, applied):
                if applied {
                    alert(alertOf("critical", code, recId, reason))
                    notify(.object(["kind": .string("compensation_failed"), "record": PCAUndoCoordinator.strip(out)]))
                }
                return out
            }
        }

        guard let g = grant, !g.isNull else { return try fail("the grant is no longer known: the compensation cannot be authorized", "compensation_denied") }
        var params = rec.get("compensation")?.get("params")?.asObject ?? [:]
        if let tp = rec.get("compensation")?.get("target_param")?.asString {
            var target: String?
            if let rt = o.resolveTarget { target = try rt(rec) } else if let res = rec.get("effect")?.get("result"), let i = res.get("id")?.asString, !i.isEmpty { target = i }
            guard let tg = target else { return try fail("the target '\(tp)' of the compensation is unknown (no effect result names it)") }
            params[JKey(tp)] = .string(tg)
        }
        let op: JSONValue = .object(["verb": rec.get("compensation")?.get("verb") ?? .null, "resource": rec.get("compensation")?.get("resource") ?? .null, "params": .object(params)])
        let dec = try compensationAllowed(pc, g, op, rec.get("opened_at")?.safeInt ?? 0)
        if !dec.ok { return try fail("the compensating action is not authorized under the grant: \(dec.reason)", "compensation_denied") }
        let attempt = rec.get("attempt")?.safeInt ?? 0
        // at most once per attempt: the operation record is created before the compensator runs
        let opId = Canonical.hashCanonical(.object(["d": .string("atlas-pca/undo-compensation-op/v1"), "record": .string(recId), "attempt": .int(attempt)]))
        let orec = OperationRecord(id: opId, state: .pending, verb: op.get("verb")?.asString ?? "", resource: op.get("resource")?.asString ?? "",
                                   paramsDigest: Canonical.hashCanonical(.object(params)), reversibility: "irreversible", startedAt: t)
        let ops = o.operations
        if case let .existing(prev) = try ops.create(orec) {
            switch prev.state {
            case .committed:
                var ev: JObject = ["kind": .string("compensated")]
                if let r = prev.result { ev["result"] = r }
                let r = try apply(recId, .object(ev))
                if case let .done(rr, _) = r { return finishCompensated(rr) }
                return finishCompensated(rec)
            case .failed, .uncertain:
                return try fail("compensation attempt \(attempt) \(prev.state.rawValue): \(prev.error ?? "")")
            case .aborted:
                let r = try apply(recId, .object(["kind": .string("compensation_failed"), "reason": .string("attempt never started")]))
                guard case let .done(rr, _) = r else { return rec }
                let again = try apply(recId, .object(["kind": .string("retry")]))
                if case let .done(next, _) = again { return try runCompensation(next) }
                return rr
            case .pending, .executing:
                // another worker holds it, or a crash; stale ones are settled here
                if t - (prev.executingAt ?? prev.startedAt) > o.effectTimeoutMs {
                    var settled = prev
                    settled.finishedAt = t
                    if prev.state == .pending { settled.state = .aborted; settled.error = "never started" } else {
                        settled.state = .uncertain
                        settled.error = "no outcome recorded: the compensation may or may not have run"
                    }
                    _ = try ops.transition(prev.id, from: prev.state, to: settled)
                    return try runCompensation(try o.store.get(recId) ?? rec)
                }
                return rec
            }
        }
        // re-read under the record: a concurrent retry or resolution wins
        let cur = try o.store.get(recId)
        if cur == nil || cur?.get("state")?.asString != "vetoed" || cur?.get("attempt")?.safeInt != rec.get("attempt")?.safeInt {
            var aborted = orec
            aborted.state = .aborted
            aborted.error = "the undo record moved on"
            aborted.finishedAt = try now()
            _ = try ops.transition(opId, from: .pending, to: aborted)
            return cur ?? rec
        }
        var running = orec
        running.state = .executing
        running.executingAt = try now()
        if !(try ops.transition(opId, from: .pending, to: running)) { return try o.store.get(recId) ?? rec }
        var call: JObject = ["operation": op, "idempotencyKey": .string(opId), "undoOf": .string(recId), "record": PCAUndoCoordinator.with(cur ?? rec) { $0["pcactn"] = nil }]
        if let orig = rec.get("effect")?.get("result"), !orig.isNull { call["originalResult"] = orig }
        let result: JSONValue?
        do { result = try o.compensate(.object(call)) } catch {
            let text = PCAStoreError.text(error)
            var failed = running
            failed.state = .failed
            failed.error = text
            failed.finishedAt = try? now()
            _ = try? ops.transition(opId, from: .executing, to: failed)
            return try fail("the compensating action failed: \(text)")
        }
        var committed = running
        committed.state = .committed
        committed.result = result
        committed.finishedAt = try? now()
        _ = try? ops.transition(opId, from: .executing, to: committed)
        var ev: JObject = ["kind": .string("compensated")]
        if let r = result, !r.isNull { ev["result"] = r }
        let r = try apply(recId, .object(ev))
        guard case let .done(rr, _) = r else { return try o.store.get(recId) ?? rec }
        return finishCompensated(rr)
    }

    /// Veto with the one-click `token` (the principal; `at` is the relayed veto time), as an authenticated `operator` of this server, or with a prepared `veto`
    /// (revocation, fraud proof). `{ok: true, record, replayed}` or `{ok: false, code, reason}`.
    public func veto(_ id: String, token: JSONValue? = nil, at: Int64? = nil, operator op: String? = nil, veto prepared: JSONValue? = nil) -> JSONValue {
        func no(_ code: String, _ reason: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(code), "reason": .string(reason)]) }
        do {
            guard let cur = try o.store.get(id) else { return no("unknown", "no undo record \(id)") }
            var t = try now()
            var checkAt: Int64?
            var v: JObject
            if let token = token, !token.isNull {
                if let a = at {
                    if a > t || a < (cur.get("opened_at")?.safeInt ?? 0) { return no("malformed", "a relayed veto time must lie between the opening of the window and now") }
                    t = a
                    checkAt = a
                }
                let tok: JSONValue? = token.asString.map { Undo.decodeToken($0) ?? .null } ?? token
                let chk = Undo.tokenCheck(tok, expectedSigner: signerPublic, record: cur, now: Double(t))
                if chk != "ok" { return no(chk, "the undo token was refused (\(chk))") }
                v = ["at": .int(t), "via": .string("token"), "by": cur.get("principal") ?? .null, "evidence": .string(tok.flatMap { Undo.tokenDigest($0) } ?? "")]
            } else if let operatorName = op {
                if operatorName.isEmpty { return no("malformed", "an operator veto names the operator") }
                v = ["at": .int(t), "via": .string("operator"), "by": .string(operatorName)]
            } else {
                v = prepared?.asObject ?? [:]
                v["at"] = .int(t)
            }
            switch try apply(id, .object(["kind": .string("veto"), "veto": .object(v)]), checkAt: checkAt) {
            case let .refused(code, reason): return no(code, reason)
            case let .done(record, applied):
                if applied { notify(.object(["kind": .string("vetoed"), "record": PCAUndoCoordinator.strip(record)])) }
                let done = try runCompensation(record)
                return .object(["ok": .bool(true), "record": done, "replayed": .bool(!applied)])
            }
        } catch {
            let t = PCAStoreError.text(error)
            return no("malformed", "veto error (fail closed): \(t.isEmpty ? "unknown" : t)")
        }
    }

    /// Apply the relay's pending vetoes now (also done by every `finalizeDue`). Throws when the relay cannot be read.
    @discardableResult
    public func syncRelay() throws -> [JSONValue] {
        guard let relay = o.relay else { return [] }
        return try relay().map { veto($0.id, token: .string($0.token), at: $0.at) }
    }

    public func compensate(_ id: String) throws -> JSONValue {
        guard let cur = try o.store.get(id) else { throw UndoError("invalid", "no undo record \(id)") }
        return try runCompensation(cur)
    }

    public func retry(_ id: String) throws -> JSONValue { try runCompensation(try must(id, .object(["kind": .string("retry")])).record) }

    /// Close the windows whose time is up (`open -> finalized`) and commit their budget reservations.
    public func finalizeDue() throws -> [String] {
        var out: [String] = []
        do { try syncRelay() } catch {
            // a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
            let t = PCAStoreError.text(error)
            alert(alertOf("critical", "veto_relay_failed", "*", "the veto relay could not be read; no window was finalized: \(t.isEmpty ? "error" : t)"))
            return out
        }
        let endedBy = try now() - 1 - (o.relay != nil ? PCAUndoServer.UNDO_RELAY_GRACE_MS : 0)
        for rec in try o.store.list(UndoQuery(state: "open", windowEndedBy: endedBy)) {
            let id = rec.get("id")?.asString ?? ""
            guard case let .done(r, applied) = try apply(id, .object(["kind": .string("finalize")])), applied else { continue }
            out.append(id)
            if r.get("effect") == nil || r.get("effect")?.isNull == true {
                alert(alertOf("warning", "effect_unknown", id, "the window closed without an effect report: reconcile the original operation"))
            }
            settleBudget(r, "commit")
            notify(.object(["kind": .string("finalized"), "record": PCAUndoCoordinator.strip(r)]))
        }
        return out
    }

    /// After a restart: resume every vetoed record's compensation, then finalize what is due.
    public func recover() throws -> [String] {
        var out: [String] = []
        for rec in try o.store.list(UndoQuery(state: "vetoed")) {
            let r = try runCompensation(rec)
            if r.get("state")?.asString != "vetoed" { out.append(rec.get("id")?.asString ?? "") }
        }
        return out + (try finalizeDue())
    }

    /// A grant was revoked: veto its open windows when the policy says so, else alert and tell the principal.
    public func onRevocation(_ grantRef: String) throws -> [String] {
        var out: [String] = []
        for rec in try o.store.list(UndoQuery(state: "open", grantRef: grantRef)) {
            let id = rec.get("id")?.asString ?? ""
            let pc = try decodePcactn(rec.get("pcactn"))
            let grant = try o.resolveGrant(rec.get("grant_ref")?.asString, pc)
            var pol: JSONValue = .object([:])
            if let g = grant, !g.isNull { pol = try policyOf(.object(["verb": rec.get("action")?.get("verb") ?? .null, "resource": rec.get("action")?.get("resource") ?? .null]), g) }
            if (StoreJ.nonEmpty(pol.get("onRevocation")) ?? "keep") == "veto" {
                if veto(id, veto: .object(["at": .int(0), "via": .string("revocation"), "by": .string(grantRef)])).get("ok") == .bool(true) { out.append(id) }
            } else {
                alert(alertOf("warning", "revoked_open_window", id, "grant \(grantRef) was revoked while this window is open; the principal can still undo it"))
                notify(.object(["kind": .string("revoked"), "record": PCAUndoCoordinator.strip(rec)]))
            }
        }
        return out
    }

    /// Slash a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window), then undo the record. `{settlement, veto}`.
    public func rollbackOnSlash(_ params: JSONValue, bonds override: UndoBondLedger? = nil) throws -> JSONValue {
        guard let b = override ?? bonds else { throw UndoError("config", "rollbackOnSlash needs a bond ledger (pass bonds in the options or to this call)") }
        let claimId = params.get("claimId")?.asString ?? ""
        let settlement = try b.slashBond(params)
        let evidence = Canonical.hashCanonical(.object(["d": .string("atlas-pca/undo-slash-ref/v1"), "settlement": settlement]))
        let recs = try o.store.list(UndoQuery(state: "open", bondRef: claimId))
        guard let target = try recs.first ?? o.store.get(claimId) else {
            return .object(["settlement": settlement, "veto": .object(["ok": .bool(false), "code": .string("unknown"), "reason": .string("no undo record for bond \(claimId)")])])
        }
        let tid = target.get("id")?.asString ?? ""
        let v = veto(tid, veto: .object(["at": .int(0), "via": .string("fraud_proof"), "by": .string(claimId), "evidence": .string(evidence)]))
        if v.get("ok") != .bool(true) {
            alert(alertOf("critical", "slash_after_window", tid, "the bond was slashed but the effect could not be rolled back: \(v.get("reason").map { JS.toString($0) } ?? "undefined")"))
        }
        return .object(["settlement": settlement, "veto": v])
    }
}
