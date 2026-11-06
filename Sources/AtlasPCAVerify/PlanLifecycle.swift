import Foundation

// Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and the
// principal's plan authorization.
//
//   draft ──validate──▶ validated ──commit──▶ committed ──authorize──▶ authorized
//     └─────────────────────┴──────────────────────┴───────────revoke──────┴──▶ revoked
//
//   - draft: the nodes are recorded; the root is computed from them (never taken from the caller).
//   - validated: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the server's own
//     validator (for example every node inside the grant's predicates).
//   - committed: the root is fixed. A committed plan is NOT executable: it still needs the principal.
//   - authorized: the principal approved this root for this grant, optionally until `expiresAt`.
//   - revoked: terminal; every later action against the root is denied.
//
// "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is authorized, the approval has not
// expired, and its stored nodes still hash to the root. `check` adds the per-action staleness rules a server applies immediately
// before execution: the node exists and the operation's verb, resource and params still match what the principal approved. The
// registry only feeds the plan into `authorize` (`AuthorizeInput.plans`) and names the state on a denial; the wire formats are
// unchanged. Mirrors the reference plan registry; plan-vectors.json pins it.

/// A plan's lifecycle state. `unknown` is reported for a root this grant does not have (never stored).
public enum PlanState: String, Sendable {
    case draft, validated, committed, authorized, revoked, unknown
}

/// The principal's approval of a plan.
public struct PlanApproval: Equatable, Sendable {
    /// Who approved (the principal's key or account id, for the record).
    public var by: String
    /// The approval lapses at this time (epoch ms); nil: until revoked. It must be finite.
    public var expiresAt: Double?
    public init(by: String, expiresAt: Double? = nil) {
        self.by = by
        self.expiresAt = expiresAt
    }

    var json: JSONValue {
        var o: JObject = ["by": .string(by)]
        if let e = expiresAt {
            let whole = e.isFinite && e.rounded() == e && abs(e) <= IV.MAX_SAFE
            o["expiresAt"] = whole ? JSONValue.int(Int64(e)) : JSONValue.double(e)
        }
        return .object(o)
    }
}

/// The stored plan. `nodes` are the plan nodes (`{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}`); `root` is
/// their Merkle root, computed by the registry.
public struct PlanRecord: Equatable, Sendable {
    public var grantRef: String
    public var root: String
    public var nodes: [JSONValue]
    public var state: PlanState
    public var createdAt: Int64
    public var validatedAt: Int64?
    public var committedAt: Int64?
    public var authorizedAt: Int64?
    public var approval: PlanApproval?
    public var revokedAt: Int64?
    public var revokedReason: String?

    public init(grantRef: String, root: String, nodes: [JSONValue], state: PlanState, createdAt: Int64) {
        self.grantRef = grantRef
        self.root = root
        self.nodes = nodes
        self.state = state
        self.createdAt = createdAt
    }

    /// The record as the shared corpus writes it.
    public var json: JSONValue {
        var o: JObject = ["grantRef": .string(grantRef), "root": .string(root), "nodes": .array(nodes), "state": .string(state.rawValue), "createdAt": .int(createdAt)]
        if let x = validatedAt { o["validatedAt"] = .int(x) }
        if let x = committedAt { o["committedAt"] = .int(x) }
        if let x = authorizedAt { o["authorizedAt"] = .int(x) }
        if let a = approval { o["approval"] = a.json }
        if let x = revokedAt { o["revokedAt"] = .int(x) }
        if let x = revokedReason { o["revokedReason"] = .string(x) }
        return .object(o)
    }

    /// nil unless `v` is an object with a string `grantRef` and `root`, an array `nodes`, a stored `state` and an integer `createdAt`.
    public init?(json v: JSONValue) {
        guard case let .object(o) = v, case let .string(g)? = o["grantRef"], case let .string(r)? = o["root"], case let .array(ns)? = o["nodes"],
              case let .string(st)? = o["state"], let state = PlanState(rawValue: st), state != .unknown, let created = o["createdAt"]?.safeInt else { return nil }
        self.init(grantRef: g, root: r, nodes: ns, state: state, createdAt: created)
        validatedAt = o["validatedAt"]?.safeInt
        committedAt = o["committedAt"]?.safeInt
        authorizedAt = o["authorizedAt"]?.safeInt
        revokedAt = o["revokedAt"]?.safeInt
        revokedReason = o["revokedReason"]?.asString
        if case let .object(a)? = o["approval"], case let .string(by)? = a["by"] {
            approval = PlanApproval(by: by, expiresAt: a["expiresAt"].flatMap { IV.num($0) })
        }
    }
}

/// The result of a lifecycle transition: `ok` with the new `record`, or the `state` the plan is in and the `reason` it refused.
public struct PlanTransition: Equatable, Sendable {
    public let ok: Bool
    public let record: PlanRecord?
    public let state: PlanState
    public let reason: String?

    static func good(_ r: PlanRecord) -> PlanTransition { PlanTransition(ok: true, record: r, state: r.state, reason: nil) }
    static func refused(_ state: PlanState, _ reason: String) -> PlanTransition { PlanTransition(ok: false, record: nil, state: state, reason: reason) }

    /// The result as the shared corpus writes it.
    public var json: JSONValue {
        if ok, let r = record { return .object(["ok": .bool(true), "record": r.json]) }
        return .object(["ok": .bool(false), "state": .string(state.rawValue), "reason": .string(reason ?? "")])
    }
}

/// A plan's state at the moment of use.
public struct PlanStatus: Equatable, Sendable {
    public var state: PlanState
    public var executable: Bool
    /// Why it is not executable.
    public var reason: String?
    public var record: PlanRecord?

    public init(state: PlanState, executable: Bool, reason: String? = nil, record: PlanRecord? = nil) {
        self.state = state
        self.executable = executable
        self.reason = reason
        self.record = record
    }

    public var json: JSONValue {
        var o: JObject = ["state": .string(state.rawValue), "executable": .bool(executable)]
        if let r = reason { o["reason"] = .string(r) }
        if let r = record { o["record"] = r.json }
        return .object(o)
    }
}

/// The verifier context for an action against a root: the stored plan and whether it is executable now.
public struct PlanContext: Equatable, Sendable {
    public let plan: [JSONValue]
    public let planAuthorized: Bool
    public let status: PlanStatus

    public var json: JSONValue { .object(["plan": .array(plan), "planAuthorized": .bool(planAuthorized), "status": status.json]) }
}

/// A validator's answer.
public struct PlanValidation: Sendable {
    public let ok: Bool
    public let reason: String?
    public init(ok: Bool, reason: String? = nil) {
        self.ok = ok
        self.reason = reason
    }
    public static let accept = PlanValidation(ok: true)
    public static func refuse(_ reason: String) -> PlanValidation { PlanValidation(ok: false, reason: reason) }
}

/// `PlanRegistry.check` options.
public struct PlanCheckOptions {
    /// The plan node the action executes (the PCActn's `plan.node_id`); nil = not named.
    public var nodeId: String?
    /// The operation about to execute: it must match the node (verb, resource, params digest).
    public var operation: PCA.Operation?
    /// The time of the check in epoch ms (nil: the registry clock).
    public var now: Int64?
    public init(nodeId: String? = nil, operation: PCA.Operation? = nil, now: Int64? = nil) {
        self.nodeId = nodeId
        self.operation = operation
        self.now = now
    }
}

/// The plan lifecycle store. Safe for concurrent use when its `AtomicKV` is: every transition is one atomic update, so of N concurrent
/// claims of one transition exactly one succeeds.
public final class PlanRegistry: @unchecked Sendable {
    private let kv: AtomicKV
    private let prefix: String
    private let clock: () -> Int64
    private let validator: ((PlanRecord) throws -> PlanValidation)?

    /// `kv`: where the records live (default: in memory, one process). `validator`: the server's validation, run by `validate` after the
    /// structural checks (for example each node is within the grant's predicates); a throw refuses.
    public init(kv: AtomicKV = MemoryAtomicKV(), prefix: String = "pca-plan:", now: (() -> Int64)? = nil,
                validator: ((PlanRecord) throws -> PlanValidation)? = nil) {
        self.kv = kv
        self.prefix = prefix
        self.clock = now ?? { Int64(Date().timeIntervalSince1970 * 1000) }
        self.validator = validator
    }

    /// `encodeURIComponent` of the grant ref (the reference's key layout, so stores can be shared).
    private static let KEY_SAFE = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()")

    private func key(_ grantRef: String, _ root: String) -> String {
        prefix + (grantRef.addingPercentEncoding(withAllowedCharacters: PlanRegistry.KEY_SAFE) ?? grantRef) + ":" + root
    }

    /// The stored plan (nil: none for this grant).
    public func get(grantRef: String, root: String) throws -> PlanRecord? {
        guard let v = try kv.get(key(grantRef, root)) else { return nil }
        return PlanRecord(json: v)
    }

    private func unknownPlan(_ root: String) -> PlanTransition { .refused(.unknown, "plan \(root) is unknown for this grant") }
    private func storeRefusal(_ e: Error) -> PlanTransition { .refused(.unknown, "the plan store failed (fail closed): \(errorMessage(e))") }

    /// The Merkle root of the plan-node leaves, or the reason it has none.
    static func rootOf(_ nodes: [JSONValue]) -> (root: String?, why: String) {
        if nodes.isEmpty { return (nil, "merkleRoot: empty leaf set") }
        guard let r = PCA.knownPlanRoot(nodes) else { return (nil, "a plan node cannot be hashed") }
        return (r, "")
    }

    /// The reason a plan's nodes are not well-formed (nil when valid).
    static func structuralProblem(_ nodes: [JSONValue]) -> String? {
        if nodes.isEmpty { return "a plan needs at least one node" }
        var ids: [String] = []
        for n in nodes {
            guard case let .object(o) = n, case let .string(id)? = o["id"], !id.isEmpty else { return "every node needs an id" }
            if IV.contains(ids, id) { return "duplicate node id '\(id)'" }
            ids.append(id)
            guard case let .string(v)? = o["verb"], !v.isEmpty, case let .string(r)? = o["resource"], !r.isEmpty else {
                return "node '\(id)' needs a verb and a resource"
            }
            if let rc = o["reversibility_class"] {
                guard case let .string(s) = rc, PCA.CLASS_RANK[s] != nil, s.unicodeScalars.allSatisfy({ $0.isASCII }) else {
                    return "node '\(id)' has an unknown reversibility class '\(IntentWB.jsOpt(rc))'"
                }
            }
        }
        return nil
    }

    /// Atomically moves a plan from one of `from` to the state named `to` (`next` computes the new record from the current one).
    private func move(_ grantRef: String, _ root: String, from: [PlanState], to: String, _ next: (PlanRecord) -> PlanRecord) -> PlanTransition {
        var out = unknownPlan(root)
        do {
            try kv.update(key(grantRef, root)) { prev in
                guard let p = prev, let cur = PlanRecord(json: p) else {
                    out = unknownPlan(root)
                    return nil
                }
                if !from.contains(cur.state) {
                    out = .refused(cur.state, "plan \(root) is \(cur.state.rawValue): cannot \(to)")
                    return nil
                }
                let rec = next(cur)
                out = .good(rec)
                return rec.json
            }
        } catch {
            return storeRefusal(error)
        }
        return out
    }

    /// Records a draft plan for a grant. The root is computed from `nodes`. Re-drafting an existing root is refused.
    public func draft(grantRef: String, nodes: JSONValue) -> PlanTransition {
        if grantRef.isEmpty { return .refused(.unknown, "a plan needs a grant") }
        // structural problems are reported by `validate` (a draft can be inspected first); an unhashable plan has no root
        guard case let .array(ns) = nodes else { return .refused(.unknown, "the plan cannot be committed: the nodes are not an array") }
        let r = PlanRegistry.rootOf(ns)
        guard let root = r.root else { return .refused(.unknown, "the plan cannot be committed: \(r.why)") }
        let rec = PlanRecord(grantRef: grantRef, root: root, nodes: ns, state: .draft, createdAt: clock())
        var out = PlanTransition.good(rec)
        do {
            try kv.update(key(grantRef, root)) { prev in
                if let p = prev, let cur = PlanRecord(json: p) {
                    out = .refused(cur.state, "plan \(root) already exists (\(cur.state.rawValue))")
                    return nil
                }
                out = .good(rec)
                return rec.json
            }
        } catch {
            return storeRefusal(error)
        }
        return out
    }

    /// draft -> validated (structural checks, then the server's validator).
    public func validate(grantRef: String, root: String) -> PlanTransition {
        let cur: PlanRecord?
        do { cur = try get(grantRef: grantRef, root: root) } catch { return storeRefusal(error) }
        guard let rec = cur else { return unknownPlan(root) }
        if rec.state != .draft { return .refused(rec.state, "plan \(root) is \(rec.state.rawValue): cannot validate") }
        var problem = PlanRegistry.structuralProblem(rec.nodes)
        if problem == nil, !IV.same(PlanRegistry.rootOf(rec.nodes).root, root) { problem = "the stored nodes no longer hash to the root" }
        if let p = problem { return .refused(rec.state, "plan \(root) is invalid: \(p)") }
        if let v = validator {
            let verdict: PlanValidation
            do { verdict = try v(rec) } catch { verdict = .refuse("validator error (fail closed): \(errorMessage(error))") }
            if !verdict.ok {
                let why = (verdict.reason ?? "").isEmpty ? "refused by the validator" : verdict.reason!
                return .refused(rec.state, "plan \(root) is invalid: \(why)")
            }
        }
        let t = clock()
        return move(grantRef, root, from: [.draft], to: "validate") { var p = $0; p.state = .validated; p.validatedAt = t; return p }
    }

    /// validated -> committed: the root is fixed; it still needs the principal's authorization to execute.
    public func commit(grantRef: String, root: String) -> PlanTransition {
        let t = clock()
        return move(grantRef, root, from: [.validated], to: "commit") { var p = $0; p.state = .committed; p.committedAt = t; return p }
    }

    /// committed -> authorized with the principal's approval (call it only after verifying the principal's consent). A nil approval,
    /// an empty `by` or a non-finite `expiresAt` is refused.
    public func authorize(grantRef: String, root: String, approval: PlanApproval?) -> PlanTransition {
        func stateNow() -> PlanState { (try? get(grantRef: grantRef, root: root))?.state ?? .unknown }
        guard let ap = approval, !ap.by.isEmpty else { return .refused(stateNow(), "an approval names who approved (`by`)") }
        if let e = ap.expiresAt, !e.isFinite { return .refused(stateNow(), "approval.expiresAt must be a time (epoch ms)") }
        let t = clock()
        return move(grantRef, root, from: [.committed], to: "authorize") { var p = $0; p.state = .authorized; p.authorizedAt = t; p.approval = ap; return p }
    }

    /// Any state except revoked -> revoked (terminal).
    public func revoke(grantRef: String, root: String, reason: String) -> PlanTransition {
        let t = clock()
        return move(grantRef, root, from: [.draft, .validated, .committed, .authorized], to: "revoke") {
            var p = $0
            p.state = .revoked
            p.revokedAt = t
            p.revokedReason = reason
            return p
        }
    }

    /// The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root). `now` nil is
    /// the registry clock. A store error is reported as not executable.
    public func status(grantRef: String, root: String, now: Int64? = nil) -> PlanStatus {
        let at = now ?? clock()
        let found: PlanRecord?
        do { found = try get(grantRef: grantRef, root: root) } catch {
            return PlanStatus(state: .unknown, executable: false, reason: "the plan store failed (fail closed): \(errorMessage(error))")
        }
        guard let rec = found else { return PlanStatus(state: .unknown, executable: false, reason: "plan \(root) is unknown for this grant") }
        if rec.state != .authorized {
            var why = "\(rec.state.rawValue), not authorized"
            if rec.state == .committed {
                why = "committed but not authorized by the principal"
            } else if rec.state == .revoked {
                why = "revoked (\((rec.revokedReason ?? "").isEmpty ? "no reason given" : rec.revokedReason!))"
            }
            return PlanStatus(state: rec.state, executable: false, reason: "plan \(root) is \(why)", record: rec)
        }
        if let e = rec.approval?.expiresAt, !(Double(at) < e) {
            return PlanStatus(state: rec.state, executable: false, reason: "plan \(root): the principal's approval expired at \(PCA.msStr(e))", record: rec)
        }
        if !IV.same(PlanRegistry.rootOf(rec.nodes).root, root) {
            return PlanStatus(state: rec.state, executable: false, reason: "plan \(root): the stored nodes no longer hash to the root", record: rec)
        }
        return PlanStatus(state: rec.state, executable: true, record: rec)
    }

    /// `status` plus the per-action staleness rules (the node exists, the operation matches it). Run it immediately before execution.
    public func check(grantRef: String, root: String, _ o: PlanCheckOptions = PlanCheckOptions()) -> PlanStatus {
        var s = status(grantRef: grantRef, root: root, now: o.now)
        guard s.executable, let rec = s.record, o.nodeId != nil || o.operation != nil else { return s }
        var node: JSONValue?
        if let nid = o.nodeId {
            node = rec.nodes.first { IV.same($0.get("id")?.asString, nid) }
            if node == nil {
                s.executable = false
                s.reason = "plan \(root) has no node '\(nid)'"
                return s
            }
        }
        if let op = o.operation {
            let candidates = node.map { [$0] } ?? rec.nodes
            let digest = Merkle.paramsDigest(op.params)
            let empty = Merkle.paramsDigest(nil)
            let same = candidates.contains { n in
                let nd: String
                if case let .string(x)? = n.get("params_digest") { nd = x } else if n.get("params_digest") == nil || n.get("params_digest") == .null { nd = empty } else { return false }
                return IV.same(n.get("verb")?.asString, op.verb) && IV.same(n.get("resource")?.asString, op.resource) && nd == digest
            }
            if !same {
                s.executable = false
                s.reason = "plan \(root): the operation (\(op.verb) on \(op.resource) with these params) is not what the principal approved"
            }
        }
        return s
    }

    /// True only when the plan is executable now (fail closed on any error).
    public func isPlanAuthorized(grantRef: String, planRoot: String) -> Bool {
        status(grantRef: grantRef, root: planRoot).executable
    }

    /// The verifier context for an action against `root`: the stored plan, and `planAuthorized` = executable. nil: the root is unknown
    /// for this grant.
    public func context(grantRef: String, root: String, now: Int64? = nil) -> PlanContext? {
        let s = status(grantRef: grantRef, root: root, now: now)
        guard let rec = s.record else { return nil }
        return PlanContext(plan: rec.nodes, planAuthorized: s.executable, status: s)
    }
}
