import Foundation

// Durable bond settlement: exact micro-unit money arithmetic, the slash split, bond sizing, the evidence digests a signed settlement record commits to,
// `PCABondSettlementPlanner` (the pure half: validates a transition against a read view, re-derives every slash verdict ITSELF, computes the balance
// movements and signs the record) and `StoreBondLedger` (commits the plans to a bond store atomically, fails closed, and stamps every time from a clock the
// claimant cannot touch). INTERNAL ACCOUNTING ONLY: nothing here moves money.
//
// THE CHALLENGE-WINDOW CLOCK: the window opens at the ledger's own `registeredAt` (its clock at `openClaim`), lasts the claim's `challenge_window_ms` and is
// never derived from the claim's `issued_at`. The ledger's "now" is `max(clock(), highest time the store has ever recorded)`, so a clock that steps backwards
// cannot reopen a closed window or release early.

public enum PCABondSettlement {
    public static let ESCROW_ACCOUNT = "escrow"
    public static let COMPENSATION_POOL_ACCOUNT = "pca:pool:compensation"
    public static let SETTLEMENT_LEAF_DOMAIN = "atlas-pca/settlement-leaf/v1"
    public static let DEFAULT_MIN_CHALLENGE_WINDOW_MS: Double = 30_000
    static let MIN_SHARE_QUANTUM = pow(2.0, -30.0)

    /// The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder.
    public static func defaultSlashSplitPolicy() -> JSONValue { .object(["challengerBps": .int(5000), "victimBps": .int(4000)]) }

    private static func assertSplitPolicy(_ p: JSONValue) throws {
        var total = 0.0
        for k in ["challengerBps", "victimBps"] {
            guard let v = StoreJ.fin(p.get(k)), v == v.rounded(.down), v >= 0, v <= 10_000 else { throw JSError("slash split: \(k) must be an integer in [0,10000]") }
            total += v
        }
        if total > 10_000 { throw JSError("slash split: challengerBps + victimBps must not exceed 10000") }
    }

    private static func shareQuantum(_ amount: Double) -> Double {
        let u = amount.ulp
        return amount == amount.rounded(.down) ? Swift.max(1, u) : Swift.max(MIN_SHARE_QUANTUM, u)
    }

    /// The challenger / victim / treasury division of a slashed `amount`: exact (treasury = amount - challenger - victim). `dest` has `challengerAccount` (a
    /// string, or an explicit null for an anonymous challenge, which pays the whole bond to the treasury), `victimAccount` and `treasuryAccount`.
    public static func computeSlashSplit(_ amount: Double, policy: JSONValue, dest: JObject) throws -> JSONValue {
        guard amount.isFinite, amount > 0 else { throw JSError("computeSlashSplit: amount must be a positive finite number") }
        try assertSplitPolicy(policy)
        guard let victim = dest["victimAccount"]?.asString, !victim.isEmpty else { throw JSError("computeSlashSplit: victimAccount is required") }
        guard let treasury = dest["treasuryAccount"]?.asString, !treasury.isEmpty else { throw JSError("computeSlashSplit: treasuryAccount is required") }
        let has = dest["challengerAccount"] != nil
        let ch = dest["challengerAccount"] ?? .null
        func out(_ c: Double, _ v: Double, _ t: Double, _ amt: Double) -> JSONValue {
            var r: JObject = ["amount": StoreJ.num(amt), "challengerReward": StoreJ.num(c), "victimCompensation": StoreJ.num(v), "treasuryRemainder": StoreJ.num(t)]
            if has { r["challengerAccount"] = ch }
            r["victimAccount"] = .string(victim)
            r["treasuryAccount"] = .string(treasury)
            return .object(r)
        }
        if has && ch.isNull { return out(0, 0, amount, amount) }
        let cbps = IV.num(policy.get("challengerBps")) ?? 0, vbps = IV.num(policy.get("victimBps")) ?? 0
        let micros: Int64? = amount == amount.rounded(.down) ? nil : PCABondMath.toMicros(amount) // integer bonds keep whole-unit shares
        if let m = micros {
            let c = m * Int64(cbps) / 10_000, v = m * Int64(vbps) / 10_000
            let t = m - c - v
            return out(PCABondMath.fromMicros(c), PCABondMath.fromMicros(v), PCABondMath.fromMicros(t), PCABondMath.fromMicros(m))
        }
        let q = shareQuantum(amount)
        func share(_ bps: Double) -> Double { ((amount * bps) / 10_000 / q).rounded(.down) * q }
        let challenger = Swift.min(share(cbps), amount)
        let victimComp = Swift.min(share(vbps), amount - challenger)
        return out(challenger, victimComp, amount - challenger - victimComp, amount)
    }

    /// `max(floor, curve(k, exposure))` snapped up onto the micro grid; no curve = linear. A non-finite or non-positive exposure gives the floor.
    public static func bondAmount(_ policy: PCAIntentBond.BondPolicy, _ exposure: Double) throws -> Double { try PCAIntentBond.bondAmount(policy, exposure) }

    public static func quantizeUp(_ x: Double) -> Double { PCAIntentBond.quantizeUp(x) }

    static func lenient(_ o: JObject) -> String { Canonical.hashCanonical(.object(o)) }

    private static func identity(_ claim: JSONValue) -> JObject {
        var o: JObject = [:]
        if let d = claim.get("pcactn_digest") { o["claimDigest"] = d }
        if let b = claim.get("bond_ref") { o["bond_ref"] = b }
        return o
    }

    /// Binds a slash to the server-derived fraud verdict.
    public static func settlementEvidenceDigest(_ claim: JSONValue, _ fraudVerdict: JSONValue) -> String {
        var o = identity(claim)
        for k in ["fraudulent", "slashBondRef", "reason"] { if let v = fraudVerdict.get(k) { o[JKey(k)] = v } }
        return lenient(o)
    }

    public static func revocationEvidenceDigest(_ claim: JSONValue, _ revokedCapId: String) -> String {
        var o = identity(claim)
        o["kind"] = .string("revocation")
        o["revokedCapId"] = .string(revokedCapId)
        return lenient(o)
    }

    /// Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion.
    public static func disputeEvidenceDigest(_ claim: JSONValue, _ verdict: JSONValue) -> String {
        var o = identity(claim)
        o["kind"] = .string("dispute")
        for k in ["outcome", "input", "agentValue", "oracleValue", "slashBondRef", "reason"] {
            if let v = verdict.get(k), !((k == "agentValue" || k == "oracleValue") && v.isNull) { o[JKey(k)] = v }
        }
        return lenient(o)
    }

    /// Verify a settlement record's signature under the guardian public key; suite-agile.
    public static func verifySettlement(_ record: JSONValue?, guardianPublic: String, pins: [String: String]? = nil) -> Bool {
        Optimistic.settlementWireCheck(record, guardianPublic: guardianPublic, pins: pins) == "ok"
    }

    public static func settlementRecordDigest(_ record: JSONValue) -> String { lenient(["t": .string(SETTLEMENT_LEAF_DOMAIN), "record": record]) }

    /// The salted commitment of a settlement record (the opaque transparency-log leaf).
    public static func settlementCommit(salt: String, _ record: JSONValue) throws -> String {
        if salt.isEmpty { throw JSError("settlementCommit: salt must be a non-empty string") }
        return lenient(["salt": .string(salt), "settlement_digest": .string(settlementRecordDigest(record))])
    }

    static func jsNum(_ d: Double) -> String { JS.number(d) }
}

/// What a planner reads of the books.
public struct PCABondView {
    public var bond: (String) -> JSONValue?
    public var balanceOf: (String) -> Double
    public var openTotals: (String) -> (count: Double, sum: Double)
    public init(bond: @escaping (String) -> JSONValue?, balanceOf: @escaping (String) -> Double, openTotals: @escaping (String) -> (count: Double, sum: Double)) {
        self.bond = bond; self.balanceOf = balanceOf; self.openTotals = openTotals
    }
}

/// The pure half of bond settlement. A plan is `{claimId, expect, next, open?, moves, record}` (see `KvBondStore`).
public final class PCABondSettlementPlanner {
    public let guardianPublicKey: String
    public let escrow: String
    public let bondPolicy: PCAIntentBond.BondPolicy
    public let slashSplitPolicy: JSONValue
    private let key: PCASuiteKey
    private let epoch: Int64?

    public init(guardian: PCASuiteKey, guardianEpoch: Int64? = nil, escrowAccount: String? = nil, bondPolicy: PCAIntentBond.BondPolicy? = nil, slashSplitPolicy: JSONValue? = nil) throws {
        guard let pub = guardian.id else { throw JSError("BondLedger: guardian must be a key with an Ed25519 identity") }
        if let e = guardianEpoch, e < 0 || e > Canonical.MAX_SAFE { throw JSError("BondLedger: guardianEpoch must be a non-negative safe integer") }
        self.key = guardian; self.epoch = guardianEpoch; self.guardianPublicKey = pub
        self.escrow = (escrowAccount?.isEmpty ?? true) ? PCABondSettlement.ESCROW_ACCOUNT : escrowAccount!
        self.bondPolicy = bondPolicy ?? PCAIntentBond.BondPolicy()
        self.slashSplitPolicy = slashSplitPolicy ?? PCABondSettlement.defaultSlashSplitPolicy()
    }

    private func sign(_ base: JObject) throws -> JSONValue {
        var body = base
        if let e = epoch { body["guardian_epoch"] = .int(e) }
        if key.alg != "ed25519" {
            body["alg"] = .string(key.alg)
            body["pq_pk"] = key.pqPk.map { JSONValue.string($0) } ?? .null
        }
        let sg = try key.sign(Canonical.utf8(Optimistic.SETTLEMENT_DOMAIN) + Canonical.utf8(Canonical.canonicalize(.object(body))))
        body["sig"] = .string(sg.sig)
        if let q = sg.pqSig { body["pq_sig"] = .string(q) }
        return .object(body)
    }

    private static func move(_ account: String, _ op: String, _ amount: Double) -> JSONValue { .object(["account": .string(account), "op": .string(op), "amount": StoreJ.num(amount)]) }

    private static func base(_ claimId: String, _ action: String, _ amount: Double, _ from: String, _ to: String, _ at: Double, _ evidence: String) -> JObject {
        ["claimId": .string(claimId), "action": .string(action), "amount": StoreJ.num(amount), "from": .string(from), "to": .string(to), "at": StoreJ.num(at), "evidenceDigest": .string(evidence)]
    }

    private static func plan(_ claimId: String, _ expect: String, _ next: String, _ moves: [JSONValue], _ record: JSONValue) -> JObject {
        ["claimId": .string(claimId), "expect": .string(expect), "next": .string(next), "moves": .array(moves), "record": record]
    }

    private static func openBond(_ view: PCABondView, _ who: String, _ claimId: String?) throws -> JSONValue {
        guard let id = claimId, let bond = view.bond(id) else { throw JSError("\(who): no bond for \(claimId ?? "undefined")") }
        let st = bond.get("status")?.asString ?? ""
        if st != "open" { throw JSError("\(who): bond \(id) is already \(st) (double-settle refused)") }
        return bond
    }

    private static func needTreasury(_ p: JSONValue, _ who: String) throws {
        guard let t = p.get("treasury")?.asString, !t.isEmpty else { throw JSError("\(who): treasury is required") }
    }

    private func slashPlan(_ bond: JSONValue, _ claimId: String, _ now: Double, _ evidence: String, _ p: JSONValue) throws -> JSONValue {
        let treasury = p.get("treasury")?.asString ?? "", amount = IV.num(bond.get("amount")) ?? 0
        let policy = p.get("splitPolicy")?.isObject == true ? (p.get("splitPolicy") ?? slashSplitPolicy) : slashSplitPolicy
        let comp = p.get("compensationAccount")?.asString
        let dest: JObject = ["challengerAccount": p.get("challengerAccount") ?? .null, "victimAccount": .string((comp?.isEmpty ?? true) ? PCABondSettlement.COMPENSATION_POOL_ACCOUNT : comp!),
                             "treasuryAccount": .string(treasury)]
        let split = try PCABondSettlement.computeSlashSplit(amount, policy: policy, dest: dest)
        var moves = [PCABondSettlementPlanner.move(escrow, "debit", amount)] // the full bond leaves escrow
        if let ca = split.get("challengerAccount")?.asString, !ca.isEmpty, (IV.num(split.get("challengerReward")) ?? 0) > 0 { moves.append(PCABondSettlementPlanner.move(ca, "credit", IV.num(split.get("challengerReward")) ?? 0)) }
        if (IV.num(split.get("victimCompensation")) ?? 0) > 0 { moves.append(PCABondSettlementPlanner.move(split.get("victimAccount")?.asString ?? "", "credit", IV.num(split.get("victimCompensation")) ?? 0)) }
        if (IV.num(split.get("treasuryRemainder")) ?? 0) > 0 { moves.append(PCABondSettlementPlanner.move(split.get("treasuryAccount")?.asString ?? "", "credit", IV.num(split.get("treasuryRemainder")) ?? 0)) }
        var b = PCABondSettlementPlanner.base(claimId, "slash", amount, escrow, treasury, now, evidence)
        b["split"] = split
        return .object(PCABondSettlementPlanner.plan(claimId, "open", "slashed", moves, try sign(b)))
    }

    /// Open (lock) a bond: refuses an unaffordable bond, one below `bondAmount(policy, exposure)`, one that breaches the depositor's caps and a double-open. The
    /// bond moves from the depositor into escrow.
    public func planOpen(_ view: PCABondView, claimId: String, amount: Double, depositor: String, exposure: Double?, now: Double, window: JSONValue? = nil) throws -> JSONValue {
        if claimId.isEmpty { throw JSError("openBond: claimId is required") }
        guard amount.isFinite, amount > 0 else { throw JSError("openBond: amount must be a positive finite number") }
        if depositor.isEmpty { throw JSError("openBond: depositor is required") }
        if view.bond(claimId) != nil { throw JSError("openBond: bond \(claimId) already exists (double-open refused)") }
        let required = try PCABondSettlement.bondAmount(bondPolicy, exposure ?? 0)
        if !(amount >= required) { throw JSError("openBond: amount \(JS.number(amount)) is below the required bond \(JS.number(required))") }
        let t = view.openTotals(depositor)
        if !(Double(t.count).isFinite && Double(t.count) + 1 <= bondPolicy.maxOpenClaims) { throw JSError("openBond: depositor open-claim cap reached") }
        if !((t.sum + amount).isFinite && t.sum + amount <= bondPolicy.maxOpenAmount) { throw JSError("openBond: depositor aggregate open-bond cap exceeded") }
        if !(view.balanceOf(depositor).isFinite && view.balanceOf(depositor) >= amount) { throw JSError("openBond: insufficient balance for the bond") }
        let record = try sign(PCABondSettlementPlanner.base(claimId, "open", amount, depositor, escrow, now, ""))
        var open: JObject = ["amount": StoreJ.num(amount), "depositor": .string(depositor), "maxOpenClaims": StoreJ.num(bondPolicy.maxOpenClaims), "maxOpenAmount": StoreJ.num(bondPolicy.maxOpenAmount)]
        if let w = window { open["window"] = w }
        var p = PCABondSettlementPlanner.plan(claimId, "none", "open", [PCABondSettlementPlanner.move(depositor, "debit", amount), PCABondSettlementPlanner.move(escrow, "credit", amount)], record)
        p["open"] = .object(open)
        return .object(p)
    }

    /// Release a bond back to its depositor after an unchallenged window; refuses a missing or already settled bond.
    public func planRelease(_ view: PCABondView, claimId: String, now: Double) throws -> JSONValue {
        guard let bond = view.bond(claimId) else { throw JSError("releaseBond: no bond for \(claimId)") }
        let st = bond.get("status")?.asString ?? ""
        if st != "open" { throw JSError("releaseBond: bond \(claimId) is already \(st) (double-settle refused)") }
        let amount = IV.num(bond.get("amount")) ?? 0, depositor = bond.get("depositor")?.asString ?? ""
        return .object(PCABondSettlementPlanner.plan(claimId, "open", "released", [PCABondSettlementPlanner.move(escrow, "debit", amount), PCABondSettlementPlanner.move(depositor, "credit", amount)],
                                                     try sign(PCABondSettlementPlanner.base(claimId, "release", amount, escrow, depositor, now, ""))))
    }

    /// Slash against a VERIFIED fraud verdict; re-runs the policy VM itself. `p`: claimId, claim, fraudProof, grant, openSnapshot, treasury, and optionally
    /// challengerAccount, compensationAccount, splitPolicy.
    public func planSlash(_ view: PCABondView, _ p: JSONValue, now: Double) throws -> JSONValue {
        let claimId = p.get("claimId")?.asString, claim = p.get("claim") ?? .null
        let bond = try PCABondSettlementPlanner.openBond(view, "slashBond", claimId)
        try PCABondSettlementPlanner.needTreasury(p, "slashBond")
        if !StoreJ.same(claim.get("bond_ref"), claimId.map { JSONValue.string($0) }) { throw JSError("slashBond: claim.bond_ref does not match claimId") }
        let verdict = PCAOptimisticAdjudication.verifyFraudProof(claim, p.get("fraudProof"), p.get("grant"), p.get("openSnapshot"))
        if verdict.get("fraudulent") != .bool(true) || !StoreJ.same(verdict.get("slashBondRef"), claimId.map { JSONValue.string($0) }) {
            throw JSError("slashBond: refused \u{2014} no verified fraud verdict slashing \(claimId ?? "undefined") (\(verdict.get("reason").map { JS.toString($0) } ?? "undefined"))")
        }
        return try slashPlan(bond, claimId ?? "", now, PCABondSettlement.settlementEvidenceDigest(claim, verdict), p)
    }

    /// Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). `p` adds revokedCapId.
    public func planSlashOnRevocation(_ view: PCABondView, _ p: JSONValue, now: Double) throws -> JSONValue {
        let claimId = p.get("claimId")?.asString, claim = p.get("claim") ?? .null
        let bond = try PCABondSettlementPlanner.openBond(view, "slashBondOnRevocation", claimId)
        try PCABondSettlementPlanner.needTreasury(p, "slashBondOnRevocation")
        if !StoreJ.same(claim.get("bond_ref"), claimId.map { JSONValue.string($0) }) { throw JSError("slashBondOnRevocation: claim.bond_ref does not match claimId") }
        guard let revoked = p.get("revokedCapId")?.asString, !revoked.isEmpty else { throw JSError("slashBondOnRevocation: revokedCapId is required") }
        return try slashPlan(bond, claimId ?? "", now, PCABondSettlement.revocationEvidenceDigest(claim, revoked), p)
    }

    /// Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. `p` adds dispute, oracle, rMargin?.
    public func planSlashOnDispute(_ view: PCABondView, _ p: JSONValue, oracle: PCADisputeOracle?, now: Double) throws -> JSONValue {
        let claimId = p.get("claimId")?.asString, claim = p.get("claim") ?? .null
        let bond = try PCABondSettlementPlanner.openBond(view, "slashBondOnDispute", claimId)
        try PCABondSettlementPlanner.needTreasury(p, "slashBondOnDispute")
        if !StoreJ.same(claim.get("bond_ref"), claimId.map { JSONValue.string($0) }) { throw JSError("slashBondOnDispute: claim.bond_ref does not match claimId") }
        let v = PCAOptimisticAdjudication.adjudicateDispute(claim, p.get("dispute"), p.get("grant"), p.get("openSnapshot"), oracle, rMargin: p.get("rMargin"))
        if v.get("outcome")?.asString != "agent-fraud" || v.get("fraudulent") != .bool(true) || !StoreJ.same(v.get("slashBondRef"), claimId.map { JSONValue.string($0) }) {
            throw JSError("slashBondOnDispute: refused \u{2014} no verified agent-fraud verdict slashing \(claimId ?? "undefined") (\(v.get("outcome").map { JS.toString($0) } ?? "undefined"): \(v.get("reason").map { JS.toString($0) } ?? "undefined"))")
        }
        return try slashPlan(bond, claimId ?? "", now, PCABondSettlement.disputeEvidenceDigest(claim, v), p)
    }

    /// Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing); an anonymous slash, 100% to the treasury.
    public func planSlashCounterBond(_ view: PCABondView, _ p: JSONValue, oracle: PCADisputeOracle?, now: Double) throws -> JSONValue {
        let cid = p.get("counterBondId")?.asString, claim = p.get("claim") ?? .null
        guard let id = cid, let bond = view.bond(id) else { throw JSError("slashCounterBond: no counter-bond for \(cid ?? "undefined")") }
        let st = bond.get("status")?.asString ?? ""
        if st != "open" { throw JSError("slashCounterBond: counter-bond \(id) is already \(st) (double-settle refused)") }
        try PCABondSettlementPlanner.needTreasury(p, "slashCounterBond")
        let v = PCAOptimisticAdjudication.adjudicateDispute(claim, p.get("dispute"), p.get("grant"), p.get("openSnapshot"), oracle, rMargin: p.get("rMargin"))
        if v.get("outcome")?.asString != "claim-upheld" || v.get("slashCounterBond") != .bool(true) {
            throw JSError("slashCounterBond: refused \u{2014} the dispute is not frivolous (\(v.get("outcome").map { JS.toString($0) } ?? "undefined"): \(v.get("reason").map { JS.toString($0) } ?? "undefined"))")
        }
        var q: JObject = ["treasury": p.get("treasury") ?? .null, "challengerAccount": .null]
        if let c = p.get("compensationAccount") { q["compensationAccount"] = c }
        if let s = p.get("splitPolicy") { q["splitPolicy"] = s }
        return try slashPlan(bond, id, now, PCABondSettlement.disputeEvidenceDigest(claim, v), .object(q))
    }
}

/// Durable, restart-safe bond settlement over a bond store (`KvBondStore` or your own). Every method is idempotent under retry: repeating a transition that
/// already committed returns the stored record and moves nothing, while a conflicting transition (a release after a slash, a second slash with different
/// evidence) throws. Every store failure is a `PCAStoreError`: `store_missing`, `guardian_key_missing`, `clock_invalid`, `store_unavailable`, `store_corrupt`,
/// `invalid_claim`, `window_open`, `window_closed`, `unregistered`, `claim_mismatch` or `conflict`. Planner failures keep their own message (a `JSError`).
public final class StoreBondLedger {
    private let store: BondStore
    private let planner: PCABondSettlementPlanner
    private let clock: () -> Double
    private let windowPolicy: Optimistic.ChallengeWindowPolicy
    private let oracle: PCADisputeOracle?

    public init(store: BondStore, guardian: PCASuiteKey, clock: (() -> Double)? = nil, windowPolicy: Optimistic.ChallengeWindowPolicy = .default, guardianEpoch: Int64? = nil,
                escrowAccount: String? = nil, bondPolicy: PCAIntentBond.BondPolicy? = nil, slashSplitPolicy: JSONValue? = nil, oracle: PCADisputeOracle? = nil) throws {
        guard guardian.id != nil else { throw PCAStoreError("guardian_key_missing", "a guardian secret key is required") }
        self.store = store
        self.planner = try PCABondSettlementPlanner(guardian: guardian, guardianEpoch: guardianEpoch, escrowAccount: escrowAccount, bondPolicy: bondPolicy, slashSplitPolicy: slashSplitPolicy)
        self.clock = clock ?? { Date().timeIntervalSince1970 * 1000 }
        self.windowPolicy = windowPolicy
        self.oracle = oracle
    }

    public var guardianPublicKey: String { planner.guardianPublicKey }

    private func guarded<T>(_ f: () throws -> T) throws -> T {
        do { return try f() } catch let e as PCAStoreError where e.code != "RangeError" { throw e } catch {
            let t = PCAStoreError.text(error)
            throw PCAStoreError("store_unavailable", t.isEmpty ? "store failed" : t)
        }
    }

    private func load(_ claimId: String, _ depositor: String? = nil) throws -> (snap: JSONValue, view: PCABondView, now: Double) {
        let snap = try guarded { try store.read(claimId, depositor) }
        let t = clock()
        if !t.isFinite { throw PCAStoreError("clock_invalid", "the clock returned a non-finite time") }
        let bond = snap.get("bond")
        var bal: [String: Double] = [:]
        for e in snap.get("balances")?.asArray ?? [] { if let a = e.asArray, a.count == 2, let k = a[0].asString { bal[k] = IV.num(a[1]) ?? 0 } }
        let totals = (count: IV.num(snap.get("openTotals")?.get("count")) ?? 0, sum: IV.num(snap.get("openTotals")?.get("sum")) ?? 0)
        let view = PCABondView(bond: { cid in (bond != nil && bond?.get("claimId")?.asString == cid) ? bond : nil }, balanceOf: { bal[$0] ?? 0 }, openTotals: { _ in totals })
        return (snap, view, Swift.max(t, IV.num(snap.get("highWater")) ?? 0))
    }

    private func submit(_ plan: JSONValue, _ now: Double) throws -> JSONValue {
        let out = try guarded { try store.commit(plan, StoreJ.num(now)) }
        if out.get("outcome")?.asString == "conflict" { throw PCAStoreError("conflict", out.get("reason")?.asString ?? "conflict") }
        return out.get("record") ?? .null
    }

    private func settle(_ claimId: String, _ plan: (PCABondView, Double) throws -> JSONValue, gate: ((JSONValue, Double) throws -> Void)? = nil) throws -> JSONValue {
        let l = try load(claimId)
        if let bond = l.snap.get("bond") {
            if bond.get("status")?.asString != "open" {
                let last = bond.get("records")?.asArray?.last
                var asOpenBond = bond.asObject ?? [:]
                asOpenBond["status"] = .string("open")
                var asOpen = l.view
                asOpen.bond = { _ in .object(asOpenBond) }
                let again = try plan(asOpen, l.now) // throws if the evidence no longer holds
                if let lst = last, PCABondMath.sameSettlement(lst, again.get("record") ?? .null) { return lst }
                return try plan(l.view, l.now).get("record") ?? .null // throws the standard double-settle refusal
            }
            if let g = gate { try g(bond, l.now) }
        }
        return try submit(try plan(l.view, l.now), l.now)
    }

    /// Top up an account of the internal books (a positive finite amount).
    public func deposit(_ account: String, _ amount: Double) throws -> Double { try guarded { try store.deposit(.string(account), StoreJ.num(amount)) } }

    public func balanceOf(_ account: String) throws -> Double {
        let snap = try guarded { try store.read("", account) }
        return IV.num(snap.get("balances")?.asArray?.first?.asArray?.last) ?? 0
    }

    public func bondStatus(_ claimId: String) throws -> String { try guarded { try store.read(claimId, nil) }.get("bond")?.get("status")?.asString ?? "none" }

    public func getBond(_ claimId: String) throws -> JSONValue? { try guarded { try store.read(claimId, nil) }.get("bond") }

    /// Where the claim's challenge window stands on the ledger's clock; throws `unregistered` for a bond with no claim. `{phase, endsAt, now}`.
    public func challengeStatus(_ claimId: String) throws -> JSONValue {
        let l = try load(claimId)
        guard let w = l.snap.get("bond")?.get("window"), w.isObject else { throw PCAStoreError("unregistered", "bond \(claimId) has no registered claim") }
        let ends = (IV.num(w.get("registeredAt")) ?? 0) + (IV.num(w.get("windowMs")) ?? 0)
        // never report finalized (it opens settlement) on a clock or window end that is not finite
        if !(l.now.isFinite && ends.isFinite) { throw PCAStoreError("clock_invalid", "the clock returned a non-finite time") }
        return .object(["phase": .string(l.now <= ends ? "open" : "finalized"), "endsAt": StoreJ.num(ends), "now": StoreJ.num(l.now)])
    }

    private func replayOpen(_ prior: JSONValue, _ depositor: String, _ amount: Double, _ window: JSONValue?) throws -> JSONValue {
        let same = prior.get("depositor")?.asString == depositor && IV.num(prior.get("amount")) == amount
            && StoreJ.same(prior.get("window")?.get("claimDigest"), window?.get("claimDigest"))
        if same, let r = prior.get("records")?.asArray?.first { return r }
        throw PCAStoreError("conflict", "openBond: bond \(prior.get("claimId")?.asString ?? "") already exists (double-open refused)")
    }

    /// Register an optimistic claim and lock its bond in one atomic commit. The claim must pass the claim check against the ledger's clock and its window must
    /// be at least the realistic floor; the window then runs from the ledger's own `registeredAt`.
    public func openClaim(_ claim: JSONValue, pcactn: JSONValue, signerPublic: String, amount: Double, depositor: String, exposure: Double? = nil) throws -> JSONValue {
        let l = try load(claim.get("bond_ref")?.asString ?? "None", depositor)
        let check = Optimistic.claimCheck(claim, expectedPcactnDigest: Canonical.hashCanonical(pcactn), signerPublic: signerPublic, serverNow: l.now, policy: windowPolicy)
        if check != "ok" {
            var reason: String? = ["malformed": "malformed claim", "irreversible": "irreversible action is ineligible for the optimistic path", "digest": "claim does not cover this PCActn",
                                   "claimed_r": "claimed_r is not finite", "signature": "claim signature does not verify"][check]
            if check == "window" { reason = Optimistic.validateWindow(issuedAt: IV.num(claim.get("issued_at")) ?? .nan, windowMs: IV.num(claim.get("challenge_window_ms")) ?? .nan, serverNow: l.now, policy: windowPolicy) }
            throw PCAStoreError("invalid_claim", reason ?? check)
        }
        let floor = Swift.max(windowPolicy.minWindowMs, PCABondSettlement.DEFAULT_MIN_CHALLENGE_WINDOW_MS)
        let windowMs = IV.num(claim.get("challenge_window_ms")) ?? .nan
        if !(windowMs.isFinite && windowMs >= floor) { throw PCAStoreError("invalid_claim", "challenge window \(JS.number(windowMs)) ms is below the \(JS.number(floor)) ms floor") }
        guard let ref = claim.get("bond_ref")?.asString, !ref.isEmpty else { throw PCAStoreError("invalid_claim", "claim has no bond_ref") }
        let window: JSONValue = .object(["registeredAt": StoreJ.num(l.now), "windowMs": StoreJ.num(windowMs), "claimDigest": .string(Canonical.hashCanonical(claim))])
        if let b = l.snap.get("bond") { return try replayOpen(b, depositor, amount, window) }
        return try submit(try planner.planOpen(l.view, claimId: ref, amount: amount, depositor: depositor, exposure: exposure, now: l.now, window: window), l.now)
    }

    /// Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with `slashCounterBond` or `releaseUnregistered`.
    public func openBond(_ claimId: String, amount: Double, depositor: String, exposure: Double? = nil) throws -> JSONValue {
        let l = try load(claimId, depositor)
        if let b = l.snap.get("bond") { return try replayOpen(b, depositor, amount, nil) }
        return try submit(try planner.planOpen(l.view, claimId: claimId, amount: amount, depositor: depositor, exposure: exposure, now: l.now, window: nil), l.now)
    }

    /// Release a registered claim's bond once its challenge window has closed on the ledger's clock.
    public func release(_ claimId: String) throws -> JSONValue {
        try settle(claimId, { try planner.planRelease($0, claimId: claimId, now: $1) }, gate: { bond, now in
            guard let w = bond.get("window"), w.isObject else { throw PCAStoreError("unregistered", "bond \(claimId) has no registered claim; use releaseUnregistered for a counter-bond") }
            let ends = (IV.num(w.get("registeredAt")) ?? 0) + (IV.num(w.get("windowMs")) ?? 0)
            if !(now.isFinite && now > ends) { throw PCAStoreError("window_open", "the challenge window of \(claimId) closes at \(JS.number(ends))") }
        })
    }

    /// Release a bond that backs no claim (a counter-bond).
    public func releaseUnregistered(_ claimId: String) throws -> JSONValue {
        try settle(claimId, { try planner.planRelease($0, claimId: claimId, now: $1) }, gate: { bond, _ in
            if let w = bond.get("window"), w.isObject { throw PCAStoreError("conflict", "bond \(claimId) backs a registered claim; use release") }
        })
    }

    private func challengeGate(_ claim: JSONValue) -> (JSONValue, Double) throws -> Void {
        { bond, now in
            let id = bond.get("claimId")?.asString ?? ""
            guard let w = bond.get("window"), w.isObject else { throw PCAStoreError("unregistered", "bond \(id) has no registered claim") }
            if !StoreJ.same(w.get("claimDigest"), .string(Canonical.hashCanonical(claim))) { throw PCAStoreError("claim_mismatch", "the claim is not the one registered for \(id)") }
            let ends = (IV.num(w.get("registeredAt")) ?? 0) + (IV.num(w.get("windowMs")) ?? 0)
            if !(now.isFinite && now <= ends) { throw PCAStoreError("window_closed", "the challenge window of \(id) closed at \(JS.number(ends))") }
        }
    }

    /// Slash on a fraud proof the ledger re-verifies itself, inside the challenge window. `params`: claimId, claim, fraudProof, grant, openSnapshot, treasury,
    /// and optionally challengerAccount, compensationAccount, splitPolicy.
    public func slashBond(_ params: JSONValue) throws -> JSONValue {
        try settle(params.get("claimId")?.asString ?? "", { try planner.planSlash($0, params, now: $1) }, gate: challengeGate(params.get("claim") ?? .null))
    }

    /// Slash on a dispute the ledger re-adjudicates itself (with the oracle given at construction), inside the challenge window.
    public func slashBondOnDispute(_ params: JSONValue) throws -> JSONValue {
        try settle(params.get("claimId")?.asString ?? "", { try planner.planSlashOnDispute($0, params, oracle: oracle, now: $1) }, gate: challengeGate(params.get("claim") ?? .null))
    }

    /// Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated).
    public func slashBondOnRevocation(_ params: JSONValue) throws -> JSONValue {
        try settle(params.get("claimId")?.asString ?? "", { try planner.planSlashOnRevocation($0, params, now: $1) }, gate: { bond, _ in
            if let w = bond.get("window"), w.isObject, !StoreJ.same(w.get("claimDigest"), .string(Canonical.hashCanonical(params.get("claim") ?? .null))) {
                throw PCAStoreError("claim_mismatch", "the claim is not the one registered for \(bond.get("claimId")?.asString ?? "")")
            }
        })
    }

    /// Slash a challenger's counter-bond after a frivolous dispute.
    public func slashCounterBond(_ params: JSONValue) throws -> JSONValue {
        try settle(params.get("counterBondId")?.asString ?? "", { try planner.planSlashCounterBond($0, params, oracle: oracle, now: $1) })
    }
}
