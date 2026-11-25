import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the durable stores of core pca against the TypeScript reference (ref-core-stores-java): the ledger store, the stored ledger with its checkpoint
/// verification, the bond store and the budget ledger with signed releases and aggregate admission. Every failure is compared by its stable code
/// (`RangeError` for an argument error); each case is a script of operations whose results are compared as one array.
final class RefCoreStoresTests: XCTestCase {
    static let file = "ref-core-stores-java.json.gz"

    static func edKey(_ label: String) throws -> PCAEdKey {
        try PCAEdKey(seed: Canonical.sha256(Array("atlas-pca-conformance/\(label)".utf8)))
    }

    static func script(_ ops: [JSONValue], _ f: (_ op: [JSONValue]) throws -> JSONValue) -> JSONValue {
        .array(ops.map { o in
            do { return try f(o.asArray ?? []) } catch { return .object(["$err": .string(PCAStoreError.codeOf(error))]) }
        })
    }

    static func arg(_ op: [JSONValue], _ i: Int) -> JSONValue { i < op.count ? op[i] : .null }

    static func ledgerStore(_ ops: [JSONValue]) -> JSONValue {
        let kv = MemoryAtomicKV()
        let s = KvLedgerStore(kv: kv)
        return script(ops) { op in
            switch op[0].asString ?? "" {
            case "size": return .int(Int64(try s.size()))
            case "read": return .array(try s.read(arg(op, 1), arg(op, 2)).map { .string($0) })
            case "append": return try s.append(arg(op, 1), arg(op, 2))
            case "cpCount": return .int(Int64(try s.checkpointCount()))
            case "cps": return .array(try s.checkpoints(arg(op, 1)))
            case "appendCp": return try s.appendCheckpoint(arg(op, 1), arg(op, 2))
            case "kvSet": try kv.update(KvLedgerStore.DOC_KEY) { _ in arg(op, 1) }; return .null
            default: throw JSError("op")
            }
        }
    }

    static func storedLedger(_ ops: [JSONValue]) throws -> JSONValue {
        let kv = MemoryAtomicKV()
        let store = KvLedgerStore(kv: kv)
        var handles: [String: StoredLedger] = [:]
        var calls = 0.0
        let gkey = PCASuiteKey.ed25519(try edKey("stored-ledger-guardian"))
        let other = PCASuiteKey.ed25519(try edKey("other"))
        let clock: () -> Double = { defer { calls += 1 }; return 1_800_000_000_000 + 1000 * calls }
        return script(ops) { op in
            let head = op[0].asString ?? ""
            if head == "open" {
                let g = op.count > 2 && op[2].asString == "other-key" ? other : gkey
                let inst = op.count > 3 && !op[3].isNull ? (op[3].asString ?? "inst") : "inst"
                let h = try StoredLedger.open(store: store, guardian: g, instanceId: inst, principal: "pr", clock: clock)
                handles[op[1].asString ?? ""] = h
                return .object(["size": .int(Int64(h.size)), "guardian": .string(h.guardian)])
            }
            if head == "kvSet" { try kv.update(KvLedgerStore.DOC_KEY) { _ in arg(op, 1) }; return .null }
            if head == "kvGet" { return try kv.get(KvLedgerStore.DOC_KEY) ?? .null }
            guard let h = handles[head] else { throw JSError("handle") }
            switch op[1].asString ?? "" {
            case "append": return try h.append(arg(op, 2))
            case "checkpoint": return try h.checkpoint()
            case "catchUp": try h.catchUp(); return .null
            case "head": return h.head()
            case "size": return .int(Int64(h.size))
            case "incl": return try h.inclusionProof(arg(op, 2))
            case "consFrom": return try h.consistencyProofFrom(arg(op, 2))
            case "commits": return .array(h.commits().map { .string($0) })
            case "latest": return h.latestCheckpoint() ?? .null
            case "chain": return .array(h.checkpointChain())
            case "guardian": return .string(h.guardian)
            default: throw JSError("op")
            }
        }
    }

    static func bondStore(_ ops: [JSONValue]) -> JSONValue {
        let kv = MemoryAtomicKV()
        let s = KvBondStore(kv: kv)
        return script(ops) { op in
            switch op[0].asString ?? "" {
            case "read": return try s.read(arg(op, 1).asString ?? "", arg(op, 2).asString)
            case "commit": return try s.commit(arg(op, 1), arg(op, 2))
            case "deposit": return StoreJ.num(try s.deposit(arg(op, 1), arg(op, 2)))
            case "kvSet": try kv.update(KvBondStore.DOC_KEY) { _ in arg(op, 1) }; return .null
            case "kvGet": return try kv.get(KvBondStore.DOC_KEY) ?? .null
            default: throw JSError("op")
            }
        }
    }

    static func budgetLedger(_ ops: [JSONValue]) throws -> JSONValue {
        let rkey = try edKey("release-signer")
        let kv = MemoryAtomicKV()
        var ledger: KvBudgetLedger?
        let log = KvLedgerStore(kv: MemoryAtomicKV())
        func l() throws -> KvBudgetLedger { guard let x = ledger else { throw JSError("no ledger") }; return x }
        return script(ops) { op in
            let str = { (i: Int) in arg(op, i).asString ?? "" }
            switch op[0].asString ?? "" {
            case "new":
                guard case .bool(let d) = arg(op, 1) else { throw PCAStoreError("invalid", "say whether the kv is durable (True or False)") }
                ledger = KvBudgetLedger(kv: kv, durable: d)
                return .bool(d)
            case "snapshot": return try l().snapshot(str(1))
            case "reserve": return try l().reserve(str(1), arg(op, 2))
            case "start": return try l().start(str(1), str(2))
            case "commit": return try l().commit(str(1), str(2))
            case "release": return try l().release(str(1), str(2), arg(op, 3).isNull ? nil : arg(op, 3))
            case "expire": return try l().expire(str(1), arg(op, 2))
            case "signRelease": return try PCABudgetLedger.signRelease(key: str(1), id: str(2), reason: str(3), at: arg(op, 4), secret: rkey)
            case "verifyRelease":
                let who: JSONValue = arg(op, 2).asString == "signer" ? .string(rkey.id) : arg(op, 2)
                return .bool(PCABudgetLedger.verifyRelease(arg(op, 1), expectedSigner: who))
            case "releaseCommit": return .array([.string(PCABudgetLedger.releaseDigest(arg(op, 1))), .string(PCABudgetLedger.releaseCommit(arg(op, 1)))])
            case "anchor":
                let i = try PCABudgetLedger.anchorRelease(log, arg(op, 1))
                return .array([.int(Int64(i)), .int(Int64(try log.size()))])
            case "scopeKey": return .string(try PCABudgetLedger.scopeKey(str(1), str(2)))
            case "kvSet": try kv.update(str(1)) { _ in arg(op, 2) }; return .null
            case "admit":
                let ad = arg(op, 1)
                let allow = ad.get("allow") ?? .bool(false)
                return try PCABudgetLedger.admitAggregateAction(try l(), ids: ad.get("ids"), accumulators: ad.get("accumulators")?.asArray ?? [], event: ad.get("event") ?? .null,
                                                                verify: { state in .object(["allow": allow, "state": state]) }, expiresAt: ad.get("expiresAt"),
                                                                maxAttempts: ad.get("maxAttempts").flatMap { $0.safeInt }.map { Int($0) })
            case "startAgg": return .bool(try PCABudgetLedger.startAggregate(try l(), arg(op, 1).asArray ?? []))
            case "settleAgg": return .array(try PCABudgetLedger.settleAggregate(try l(), arg(op, 1).asArray ?? [], status: str(2)))
            default: throw JSError("op")
            }
        }
    }

    func replay(_ fn: String, minimum: Int, _ run: ([JSONValue]) throws -> JSONValue) throws {
        let d = Base.Diffs()
        let n = try Base.each(Self.file, [fn]) { c in
            let got = Base.run { try run(c.arg(0)?.asArray ?? []) }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThanOrEqual(n, minimum, fn)
        d.finish(minimum)
    }

    func testLedgerStoreAgainstTheReference() throws { try replay("ledgerStore", minimum: 60) { Self.ledgerStore($0) } }
    func testStoredLedgerAgainstTheReference() throws { try replay("storedLedger", minimum: 28) { try Self.storedLedger($0) } }
    func testBondStoreAgainstTheReference() throws { try replay("bondStore", minimum: 55) { Self.bondStore($0) } }
    func testBudgetLedgerAgainstTheReference() throws { try replay("budgetLedger", minimum: 58) { try Self.budgetLedger($0) } }
}
