import Foundation

// Durable bond settlement, the store half: the `BondStore` contract (`read`, `commit`, `deposit`), the exact micro-unit arithmetic every store shares, the pure
// transition function and `KvBondStore`, one document in any atomic key-value store. INTERNAL ACCOUNTING ONLY: nothing here moves money.
//
// A plan is `{claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?}, moves: [{account, op, amount}], record}`. `commit` applies
// it ALL OR NOTHING: the compare-and-swap on the bond's phase, every balance movement, the new phase and the signed record become visible together; committing
// the same transition twice is a replay (the stored record, nothing moved).

/// The micro-unit arithmetic of the bond books.
public enum PCABondMath {
    static let MICROS: Double = 1_000_000
    static let MAX_SAFE_MICROS: Double = 1e15

    /// Integer micro-units of `x` when it is a micro-grid amount below 1e15 micros, else nil.
    public static func toMicros(_ x: Double) -> Int64? {
        guard x.isFinite, x >= 0 else { return nil }
        let scaled = x * MICROS
        if scaled > MAX_SAFE_MICROS { return nil }
        let r = (scaled + 0.5).rounded(.down)
        if r / MICROS != x && abs(scaled - r) > 1e-3 { return nil } // genuinely sub-micro: not a micro-grid amount
        return Int64(r)
    }

    public static func fromMicros(_ m: Int64) -> Double { Double(m) / MICROS }

    /// a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain floating point otherwise.
    public static func exactAdd(_ a: Double, _ b: Double, sign: Int) -> Double {
        guard let ma = toMicros(a), let mb = toMicros(b) else { return a + Double(sign) * b }
        return fromMicros(sign == 1 ? ma + mb : ma - mb)
    }

    /// Apply moves in order over a balance reader; throws (applying nothing) on an invalid amount or an overdraft. The result lists the touched accounts in
    /// first-touched order.
    public static func applyBondMoves(_ balanceOf: (String) -> Double, _ moves: [JSONValue]) throws -> [(String, Double)] {
        var out: [(String, Double)] = []
        func bal(_ a: String) -> Double { out.first { $0.0 == a }?.1 ?? balanceOf(a) }
        for m in moves {
            let op = m.get("op")?.asString ?? "None"
            guard let amount = StoreJ.fin(m.get("amount")), amount >= 0 else { throw JSError("\(op): invalid amount") }
            guard let account = m.get("account")?.asString else { throw JSError("move: account is required") }
            if !bal(account).isFinite { throw JSError("\(op): balance of \(account) is not finite") }
            if op == "debit" && !(bal(account) >= amount) { throw JSError("debit: insufficient balance for \(account)") }
            let next = exactAdd(bal(account), amount, sign: op == "debit" ? -1 : 1)
            if let i = out.firstIndex(where: { $0.0 == account }) { out[i].1 = next } else { out.append((account, next)) }
        }
        return out
    }

    /// Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored).
    public static func sameSettlement(_ a: JSONValue, _ b: JSONValue) -> Bool {
        StoreJ.same(a.get("claimId"), b.get("claimId")) && StoreJ.same(a.get("action"), b.get("action")) && IV.num(a.get("amount")) == IV.num(b.get("amount"))
            && StoreJ.same(a.get("from"), b.get("from")) && StoreJ.same(a.get("to"), b.get("to")) && StoreJ.same(a.get("evidenceDigest"), b.get("evidenceDigest"))
            && StoreJ.same(a.get("split") ?? .null, b.get("split") ?? .null)
    }
}

/// The persistence contract of the bond books.
public protocol BondStore: AnyObject {
    /// What a planner may read: `{bond?, balances: [[account, balance]], openTotals: {count, sum}, highWater}`.
    func read(_ claimId: String, _ depositor: String?) throws -> JSONValue
    /// Apply a plan all or nothing: `{outcome: committed | replayed, record}` or `{outcome: conflict, reason, current}`.
    func commit(_ plan: JSONValue, _ observedAt: JSONValue) throws -> JSONValue
    /// Atomically credit `account` with `amount` (a positive finite number); the new balance.
    func deposit(_ account: JSONValue, _ amount: JSONValue) throws -> Double
}

public extension BondStore {
    func deposit(_ account: String, _ amount: Double) throws -> Double { try deposit(.string(account), StoreJ.num(amount)) }
}

/// The reference bond store: the whole book is one document in an atomic key-value store, so every transition is a single atomic read-modify-write.
/// LIMIT: one document, rewritten on every commit; a production deployment implements the store over a database transaction.
public final class KvBondStore: BondStore, @unchecked Sendable {
    public static let DOC_KEY = "pca-bond-store/v1"
    private let kv: AtomicKV
    private let key: String

    public init(kv: AtomicKV, key: String = KvBondStore.DOC_KEY) { self.kv = kv; self.key = key }

    struct Doc {
        var balances: [(String, Double)] = []
        var bonds: [JSONValue] = [] // rows in insertion order
        var highWater: Double = 0
        func balance(_ a: String) -> Double { balances.first { $0.0 == a }?.1 ?? 0 }
        func bond(_ id: String) -> JSONValue? { bonds.first { $0.get("claimId")?.asString == id } }
        mutating func setBalance(_ a: String, _ v: Double) { if let i = balances.firstIndex(where: { $0.0 == a }) { balances[i].1 = v } else { balances.append((a, v)) } }
        mutating func setBond(_ row: JSONValue) {
            if let i = bonds.firstIndex(where: { $0.get("claimId")?.asString == row.get("claimId")?.asString }) { bonds[i] = row } else { bonds.append(row) }
        }
    }

    static let PHASES = ["open", "released", "slashed"]

    static func bad(_ why: String) -> PCAStoreError { PCAStoreError("store_corrupt", why) }

    static func decode(_ raw: JSONValue?) throws -> Doc {
        guard let r = raw, !r.isNull else { return Doc() }
        guard r.isObject, IV.num(r.get("v")) == 1, case .array(let bals)? = r.get("balances"), case .array(let bonds)? = r.get("bonds"),
              r.get("highWater")?.isNumber == true else { throw bad("bond document has the wrong shape") }
        var doc = Doc()
        guard let hw = StoreJ.fin(r.get("highWater")), hw >= 0 else { throw bad("highWater is not a non-negative number") }
        doc.highWater = hw
        for e in bals {
            guard case .array(let p) = e, p.count == 2, let a = p[0].asString, let v = StoreJ.fin(p[1]), v >= 0 else { throw bad("malformed balance entry") }
            doc.setBalance(a, v)
        }
        for b in bonds {
            guard b.isObject, let id = b.get("claimId")?.asString, b.get("depositor")?.asString != nil, StoreJ.fin(b.get("amount")) != nil,
                  let st = b.get("status")?.asString, PHASES.contains(st), let recs = b.get("records")?.asArray, !recs.isEmpty else { throw bad("malformed bond row") }
            if doc.bond(id) != nil { throw bad("duplicate bond row") }
            doc.bonds.append(b)
        }
        return doc
    }

    static func encode(_ d: Doc) -> JSONValue {
        .object(["v": .int(1), "balances": .array(d.balances.map { .array([.string($0.0), StoreJ.num($0.1)]) }), "bonds": .array(d.bonds), "highWater": StoreJ.num(d.highWater)])
    }

    private static func conflict(_ reason: String, _ current: String) -> JSONValue {
        .object(["outcome": .string("conflict"), "reason": .string(reason), "current": .string(current)])
    }

    private static func sameWindow(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        let an = a == nil || a == .null, bn = b == nil || b == .null
        if an || bn { return an && bn }
        return IV.num(a?.get("windowMs")) == IV.num(b?.get("windowMs")) && StoreJ.same(a?.get("claimDigest"), b?.get("claimDigest")) // registeredAt is the first call's
    }

    /// Apply `plan` to `doc` following the BondStore.commit rules. Mutates `doc` ONLY on `committed` (the moves are checked on an overlay first).
    static func commitPlan(_ doc: inout Doc, _ plan: JSONValue, _ observedAt: JSONValue) throws -> JSONValue {
        guard let claimId = plan.get("claimId")?.asString else { throw JSError("commit: claimId is required") }
        let bond = doc.bond(claimId)
        let cur = bond?.get("status")?.asString ?? "none"
        var o = plan.get("open")
        if let x = o, x.isNull || x.asObject?.isEmpty == true { o = nil }
        let expect = plan.get("expect")?.asString, next = plan.get("next")?.asString
        let record = plan.get("record") ?? .null
        if expect == "none" {
            guard let op = o, next == "open" else { return conflict("malformed open plan", cur) }
            if let b = bond {
                let recs = b.get("records")?.asArray ?? []
                let same = StoreJ.same(b.get("depositor"), op.get("depositor")) && IV.num(b.get("amount")) == IV.num(op.get("amount")) && sameWindow(b.get("window"), op.get("window"))
                    && !recs.isEmpty && PCABondMath.sameSettlement(recs[0], record)
                return same ? .object(["outcome": .string("replayed"), "record": recs[0]]) : conflict("bond \(claimId) already exists", b.get("status")?.asString ?? "none")
            }
            var count = 0.0, total = 0.0
            for b in doc.bonds where b.get("status")?.asString == "open" && StoreJ.same(b.get("depositor"), op.get("depositor")) {
                count += 1
                total += IV.num(b.get("amount")) ?? 0
            }
            guard let maxClaims = IV.num(op.get("maxOpenClaims")), let maxAmount = IV.num(op.get("maxOpenAmount")), let amount = IV.num(op.get("amount")) else {
                throw JSError("commit: malformed open caps")
            }
            if !(count.isFinite && count + 1 <= maxClaims) { return conflict("depositor open-claim cap reached", "none") }
            if !((total + amount).isFinite && total + amount <= maxAmount) { return conflict("depositor aggregate open-bond cap exceeded", "none") }
        } else if let b = bond {
            if b.get("status")?.asString != expect {
                let last = b.get("records")?.asArray?.last
                if b.get("status")?.asString == next, let l = last, PCABondMath.sameSettlement(l, record) { return .object(["outcome": .string("replayed"), "record": l]) }
                return conflict("bond \(claimId) is already \(b.get("status")?.asString ?? "none")", b.get("status")?.asString ?? "none")
            }
        } else {
            return conflict("no bond for \(claimId)", "none")
        }
        let moved: [(String, Double)]
        do { moved = try PCABondMath.applyBondMoves({ doc.balance($0) }, plan.get("moves")?.asArray ?? []) } catch let e as JSError { return conflict(e.message, cur) }
        for (a, v) in moved { doc.setBalance(a, v) }
        if let op = o {
            var row: JObject = ["claimId": .string(claimId), "amount": op.get("amount") ?? .null, "depositor": op.get("depositor") ?? .null, "status": .string("open")]
            if let w = op.get("window"), !w.isNull { row["window"] = w }
            row["records"] = .array([record])
            doc.setBond(.object(row))
        } else if var b = bond?.asObject {
            b["status"] = plan.get("next") ?? .null
            b["records"] = .array((b["records"]?.asArray ?? []) + [record])
            doc.setBond(.object(b))
        }
        let obs = StoreJ.fin(observedAt) ?? 0
        doc.highWater = Swift.max(doc.highWater, obs)
        return .object(["outcome": .string("committed"), "record": record])
    }

    /// What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark.
    static func snapshot(_ doc: Doc, _ claimId: String, _ depositor: String?) -> JSONValue {
        var count = 0.0, total = 0.0
        var balances: [JSONValue] = []
        if let d = depositor {
            for b in doc.bonds where b.get("status")?.asString == "open" && b.get("depositor")?.asString == d {
                count += 1
                total += IV.num(b.get("amount")) ?? 0
            }
            balances.append(.array([.string(d), StoreJ.num(doc.balance(d))]))
        }
        var out: JObject = [:]
        if let b = doc.bond(claimId) { out["bond"] = b }
        out["balances"] = .array(balances)
        out["openTotals"] = .object(["count": StoreJ.num(count), "sum": StoreJ.num(total)])
        out["highWater"] = StoreJ.num(doc.highWater)
        return .object(out)
    }

    public func read(_ claimId: String, _ depositor: String?) throws -> JSONValue { KvBondStore.snapshot(try KvBondStore.decode(try kv.get(key)), claimId, depositor) }

    public func commit(_ plan: JSONValue, _ observedAt: JSONValue) throws -> JSONValue {
        var out: JSONValue?
        var failure: Error?
        try kv.update(key) { prev in
            do {
                var d = try KvBondStore.decode(prev)
                let r = try KvBondStore.commitPlan(&d, plan, observedAt)
                out = r
                return r.get("outcome")?.asString == "committed" ? KvBondStore.encode(d) : nil // nil: leave the key untouched
            } catch { failure = error; return nil }
        }
        if let f = failure { throw f }
        return out ?? .null
    }

    /// Atomically credit `account` with `amount` (a positive finite number). Returns the new balance.
    public func deposit(_ account: JSONValue, _ amount: JSONValue) throws -> Double {
        guard let a = StoreJ.nonEmpty(account) else { throw PCAStoreError.range("deposit: account is required") }
        guard let n = StoreJ.fin(amount), n > 0 else { throw PCAStoreError.range("deposit: amount must be a positive finite number") }
        var res: Double = 0
        var failure: Error?
        try kv.update(key) { prev in
            do {
                var d = try KvBondStore.decode(prev)
                let moved = try PCABondMath.applyBondMoves({ d.balance($0) }, [.object(["account": .string(a), "op": .string("credit"), "amount": amount])])
                res = moved.first { $0.0 == a }?.1 ?? 0
                d.setBalance(a, res)
                return KvBondStore.encode(d)
            } catch { failure = error; return nil }
        }
        if let f = failure { throw f }
        return res
    }
}
