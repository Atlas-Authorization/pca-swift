import Foundation

// Durable enforcement of a signed behavioural contract: a port of `contract-enforcer.ts`.
//
// `Contracts.advanceContract` is a pure function of (state, action, contract). A deployment also needs the state to live where two processes
// cannot both advance it, to survive a restart, and to stay refused once the agent has broken the contract. The monitor state is one document in
// an `AtomicKV`, and the whole read-check-advance runs inside the kv's atomic `update`, so concurrent callers are serialised (one wins each sequence
// number, the others see the advanced state) and a stale or rolled-back state can never be advanced.
//
// Guarantees: only a contract signed by the PINNED principal is loaded; the state document is bound to the contract id; every malformed, corrupt or
// unreadable state or store error DENIES; a real contract violation LATCHES the enforcer (default) so every later action is denied until the
// principal signs a reset. Not guaranteed: liveness, and anything for actions that never pass through `check`. Contracts are safety properties.

/// `open` / `state` refused.
public struct ContractEnforcerError: Error, CustomStringConvertible, Equatable {
    public let description: String
    init(_ m: String) { description = "ContractEnforcer: \(m)" }
}

/// The outcome of `check` / `peek`.
public struct EnforceResult: Equatable, Sendable {
    public let allow: Bool
    /// `ok`, `violated`, `latched`, `permission`, `state-error` or `store-error`.
    public let reason: String
    /// Violated clause / invariant ids (empty unless `reason` is `violated` or `latched`).
    public let violated: [String]
    public let reasons: [String]
    /// Admitted-action count after this call.
    public let seq: Int
    public var json: JSONValue {
        .object(["allow": .bool(allow), "reason": .string(reason), "violated": PD.strs(violated), "reasons": PD.strs(reasons), "seq": .int(Int64(seq))])
    }
}

public final class ContractEnforcer: @unchecked Sendable {
    public static let CONTRACT_RESET_DOMAIN = "atlas-pca/contract-reset/v1\u{0}"
    static let DOC_VERSION = 1
    static let CORRUPT = "<state>: stored state is corrupt or belongs to another contract"

    private let kv: AtomicKV
    private let contract: JSONValue
    private let contractId: String
    private let principal: String
    private let key: String
    private let now: () -> Double
    private let latch: Bool

    private init(kv: AtomicKV, contract: JSONValue, id: String, principal: String, key: String, now: @escaping () -> Double, latch: Bool) {
        self.kv = kv
        self.contract = contract
        self.contractId = id
        self.principal = principal
        self.key = key
        self.now = now
        self.latch = latch
    }

    /// Throws `ContractEnforcerError` unless the contract verifies under the pinned principal (there is no trust-on-first-use). `key` is the state
    /// document's key (default `contract/<contract id>`); `now` the wall clock in epoch ms (the state clock never goes back: the later of this and
    /// the stored `now` is used); `latchOnViolation` (default true): with false a violating action is just denied.
    public static func open(kv: AtomicKV, contract: JSONValue, principal: String, key: String? = nil, now: (() -> Double)? = nil,
                            latchOnViolation: Bool = true) throws -> ContractEnforcer {
        if principal.isEmpty { throw ContractEnforcerError("a pinned principal is required") }
        let v = Contracts.verifyContract(contract, expectedPrincipal: principal)
        if !v.ok { throw ContractEnforcerError("contract refused: \(v.reason ?? "undefined")") }
        guard let id = contract.get("id")?.asString else { throw ContractEnforcerError("contract refused: id does not match content") }
        return ContractEnforcer(kv: kv, contract: contract, id: id, principal: principal, key: key ?? "contract/\(id)",
                                now: now ?? { (Date().timeIntervalSince1970 * 1000).rounded(.down) }, latch: latchOnViolation)
    }

    static func resetMessage(_ id: String, _ seq: Int) -> [UInt8] {
        Canonical.utf8(CONTRACT_RESET_DOMAIN) + Canonical.sha256(Canonical.utf8("\(id):\(seq)"))
    }

    /// The principal's authorisation to un-latch `contractId` at sequence `seq` (binds both, so it cannot be replayed later).
    public static func signContractReset(principal: PCAEdKey, contractId: String, seq: Int) throws -> String {
        Base64URLStrict.encode(try principal.sign(resetMessage(contractId, seq)))
    }

    enum DocCheck { case ok, bad, throwsError }

    /// `isDoc`: a stored state document of THIS contract. A `latched` member that is JSON null makes the reference throw (a TypeError).
    static func isDoc(_ d: JSONValue?, _ id: String) -> DocCheck {
        guard case let .object(o)? = d else { return .bad }
        if IV.num(o["v"]) != Double(DOC_VERSION) || !IV.same(o["contract_id"]?.asString, id) || Prohibitions.stateProblem(o["state"]) != nil { return .bad }
        guard let l = o["latched"] else { return .ok }
        if l.isNull { return .throwsError }
        guard case let .object(lo) = l, PD.isInteger(lo["seq"]), !PD.negZero(lo["seq"]), case let .array(v)? = lo["violated"] else { return .bad }
        return v.allSatisfy { PD.isStr($0) } ? .ok : .bad
    }

    static func res(_ allow: Bool, _ reason: String, _ violated: [String], _ reasons: [String], _ seq: Int) -> EnforceResult {
        EnforceResult(allow: allow, reason: reason, violated: violated, reasons: reasons, seq: seq)
    }

    static func seqOf(_ doc: JObject) -> Int { Int(IV.num(doc["state"]?.get("seq")) ?? 0) }

    static func latchedResult(_ doc: JObject) -> EnforceResult {
        let l = doc["latched"]
        let violated = (l?.get("violated")?.asArray ?? []).compactMap { $0.asString }
        return res(false, "latched", violated, ["<latched>: contract violated at seq \(PD.js(l?.get("seq")))"], seqOf(doc))
    }

    /// Check one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never throws.
    public func check(_ action: JSONValue?, permitted: Bool = true) -> EnforceResult {
        let id = contractId
        var out = ContractEnforcer.res(false, "store-error", [], ["store unavailable"], 0)
        var threw = false
        do {
            let wall = now()
            try kv.update(key) { prev in
                if let p = prev {
                    switch ContractEnforcer.isDoc(p, id) {
                    case .bad:
                        out = ContractEnforcer.res(false, "state-error", [], [ContractEnforcer.CORRUPT], 0)
                        return nil
                    case .throwsError:
                        threw = true
                        return nil
                    case .ok: break
                    }
                    if !wall.isFinite {
                        out = ContractEnforcer.res(false, "state-error", [], ["<state>: clock is not finite"], ContractEnforcer.seqOf(p.asObject ?? [:]))
                        return nil
                    }
                }
                let doc: JObject = prev?.asObject ?? ["v": .int(Int64(ContractEnforcer.DOC_VERSION)), "contract_id": .string(id), "state": Prohibitions.emptyState(wall.isFinite ? wall : 0)]
                if doc["latched"] != nil {
                    out = ContractEnforcer.latchedResult(doc)
                    return nil
                }
                let stateNow = PD.fin(doc["state"]?.get("now")) ?? 0
                let r = Contracts.checkAndAdvanceContract(permitted: permitted, doc["state"], action, self.contract, now: PD.jsMax(wall, stateNow), expectedSeq: IV.num(doc["state"]?.get("seq")))
                if r.allow {
                    out = ContractEnforcer.res(true, "ok", [], [], Int(IV.num(r.next.get("seq")) ?? 0))
                    var d = doc
                    d["state"] = r.next
                    return .object(d)
                }
                let structural = r.decidedBy == "state"
                let real = !structural && !r.violated.isEmpty
                out = ContractEnforcer.res(false, structural ? "state-error" : (real ? "violated" : "permission"), real ? r.violated : [], r.reasons, ContractEnforcer.seqOf(doc))
                if real && self.latch {
                    var d = doc
                    d["latched"] = .object(["seq": doc["state"]?.get("seq") ?? .int(0), "violated": PD.strs(r.violated)])
                    return .object(d)
                }
                return nil
            }
            if threw { out = ContractEnforcer.res(false, "store-error", [], ["store error (fail closed)"], 0) }
        } catch {
            out = ContractEnforcer.res(false, "store-error", [], ["store error (fail closed)"], 0)
        }
        return out
    }

    /// Read-only evaluation of `action` against the stored state: nothing is advanced or latched. Used to refuse BEFORE a replay counter is
    /// spent; `check` then commits once the action is actually admitted. Never throws.
    public func peek(_ action: JSONValue?) -> EnforceResult {
        do {
            let prev = try kv.get(key)
            if let p = prev {
                switch ContractEnforcer.isDoc(p, contractId) {
                case .bad: return ContractEnforcer.res(false, "state-error", [], [ContractEnforcer.CORRUPT], 0)
                case .throwsError: return ContractEnforcer.res(false, "store-error", [], ["store error (fail closed)"], 0)
                case .ok: break
                }
                if p.get("latched") != nil { return ContractEnforcer.latchedResult(p.asObject ?? [:]) }
            }
            let wall = now()
            let r = Contracts.checkContract(action, contract, prev?.get("state") ?? Prohibitions.emptyState(wall.isFinite ? wall : 0))
            let seq = prev.map { ContractEnforcer.seqOf($0.asObject ?? [:]) } ?? 0
            if r.ok { return ContractEnforcer.res(true, "ok", [], [], seq) }
            return ContractEnforcer.res(false, "violated", r.violated, r.reasons, seq)
        } catch {
            return ContractEnforcer.res(false, "store-error", [], ["store error (fail closed)"], 0)
        }
    }

    /// The current stored state and whether it is latched, or nil when nothing was admitted yet. Throws `ContractEnforcerError` on a corrupt document.
    public func state() throws -> (state: JSONValue, latched: Bool)? {
        guard let d = try kv.get(key) else { return nil }
        if ContractEnforcer.isDoc(d, contractId) != .ok { throw ContractEnforcerError("stored state is corrupt or belongs to another contract") }
        return (d.get("state") ?? .null, d.get("latched") != nil)
    }

    /// Un-latch with the principal's signature (see `signContractReset`) at the latched sequence. Returns whether it cleared.
    public func reset(_ sig: String) -> Bool {
        var cleared = false
        do {
            try kv.update(key) { prev in
                guard ContractEnforcer.isDoc(prev, contractId) == .ok, case var .object(o)? = prev, let l = o["latched"] else { return nil }
                let seq = Int(IV.num(l.get("seq")) ?? 0)
                guard Ed25519Strict.verifyB64u(principal, ContractEnforcer.resetMessage(contractId, seq), sig) else { return nil }
                cleared = true
                o["latched"] = nil
                return .object(o)
            }
        } catch {
            return false
        }
        return cleared
    }
}
