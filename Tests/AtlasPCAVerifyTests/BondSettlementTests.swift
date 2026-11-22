import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Bond settlement over the durable bond store: exact micro-unit arithmetic, the slash split, the signed records, the fail-closed refusals and the retry
/// semantics. Hand-written; the store itself is replayed against the reference in `RefCoreStoresTests`.
final class BondSettlementTests: XCTestCase {
    final class Clock { var t: Double; init(_ t: Double) { self.t = t } }

    func guardian() throws -> PCASuiteKey { .ed25519(try PCAEdKey(seed: [UInt8](repeating: 4, count: 32))) }

    func ledger(_ clock: Clock) throws -> StoreBondLedger {
        try StoreBondLedger(store: KvBondStore(kv: MemoryAtomicKV()), guardian: try guardian(), clock: { clock.t })
    }

    func codeOf(_ f: () throws -> Any) -> String? {
        do { _ = try f(); return nil } catch { return (error as? PCAStoreError)?.code ?? "Error" }
    }

    func testMicroUnitArithmeticIsExact() throws {
        XCTAssertEqual(PCABondMath.exactAdd(0.1, 0.2, sign: 1), 0.3)
        XCTAssertEqual(PCABondMath.exactAdd(1, 0.000001, sign: -1), 0.999999)
        let moved = try PCABondMath.applyBondMoves({ _ in 5 }, [.object(["account": .string("a"), "op": .string("debit"), "amount": .double(2.5)])])
        XCTAssertEqual(moved.map { $0.0 }, ["a"])
        XCTAssertEqual(moved.map { $0.1 }, [2.5])
        // an overdraft applies nothing
        XCTAssertThrowsError(try PCABondMath.applyBondMoves({ _ in 1 }, [.object(["account": .string("a"), "op": .string("debit"), "amount": .int(2)])]))
        XCTAssertEqual(try PCABondSettlement.bondAmount(PCAIntentBond.BondPolicy(), 0), 1)
        var p = PCAIntentBond.BondPolicy()
        p.k = 2
        XCTAssertEqual(try PCABondSettlement.bondAmount(p, 3.3), 6.6)
    }

    func testTheSlashSplitSumsExactly() throws {
        let pol = PCABondSettlement.defaultSlashSplitPolicy()
        let s = try PCABondSettlement.computeSlashSplit(100, policy: pol, dest: ["challengerAccount": .string("ch"), "victimAccount": .string("v"), "treasuryAccount": .string("t")])
        XCTAssertEqual([s.get("challengerReward"), s.get("victimCompensation"), s.get("treasuryRemainder")].map { IV.num($0) }, [50, 40, 10])
        let anon = try PCABondSettlement.computeSlashSplit(7.25, policy: pol, dest: ["challengerAccount": .null, "victimAccount": .string("v"), "treasuryAccount": .string("t")])
        XCTAssertEqual(IV.num(anon.get("treasuryRemainder")), 7.25)
        XCTAssertEqual(IV.num(anon.get("challengerReward")), 0)
        let third: JSONValue = .object(["challengerBps": .int(3333), "victimBps": .int(3333)])
        let f = try PCABondSettlement.computeSlashSplit(10.333333, policy: third, dest: ["challengerAccount": .string("c"), "victimAccount": .string("v"), "treasuryAccount": .string("t")])
        let sum = PCABondMath.exactAdd(PCABondMath.exactAdd(IV.num(f.get("challengerReward")) ?? 0, IV.num(f.get("victimCompensation")) ?? 0, sign: 1), IV.num(f.get("treasuryRemainder")) ?? 0, sign: 1)
        XCTAssertEqual(sum, 10.333333)
        XCTAssertThrowsError(try PCABondSettlement.computeSlashSplit(1, policy: .object(["challengerBps": .int(9000), "victimBps": .int(2000)]),
                                                                     dest: ["victimAccount": .string("v"), "treasuryAccount": .string("t")]))
    }

    func testOpenReleaseAndRetrySemantics() throws {
        let clock = Clock(1_000)
        let b = try ledger(clock)
        let pub = try guardian().id ?? ""
        XCTAssertEqual(try b.deposit("alice", 100), 100)
        XCTAssertEqual(try b.bondStatus("c1"), "none")
        let rec = try b.openBond("c1", amount: 40, depositor: "alice")
        XCTAssertTrue(PCABondSettlement.verifySettlement(rec, guardianPublic: pub))
        XCTAssertEqual(try b.balanceOf("alice"), 60)
        XCTAssertEqual(try b.bondStatus("c1"), "open")
        XCTAssertEqual(try b.openBond("c1", amount: 40, depositor: "alice"), rec) // a retried open returns the original record
        XCTAssertEqual(codeOf { try b.openBond("c1", amount: 41, depositor: "alice") }, "conflict")
        let out = try b.releaseUnregistered("c1")
        XCTAssertEqual(out.get("action")?.asString, "release")
        XCTAssertTrue(PCABondSettlement.verifySettlement(out, guardianPublic: pub))
        XCTAssertEqual(try b.balanceOf("alice"), 100)
        XCTAssertEqual(try b.releaseUnregistered("c1"), out) // idempotent under retry
        XCTAssertEqual(try b.bondStatus("c1"), "released")
    }

    func testRefusalsFailClosed() throws {
        let clock = Clock(1_000)
        let b = try ledger(clock)
        _ = try b.deposit("alice", 10)
        XCTAssertThrowsError(try b.openBond("big", amount: 50, depositor: "alice")) // insufficient balance
        XCTAssertThrowsError(try b.releaseUnregistered("nothing"))
        let bad = try StoreBondLedger(store: KvBondStore(kv: MemoryAtomicKV()), guardian: try guardian(), clock: { .nan })
        XCTAssertEqual(codeOf { try bad.openBond("x", amount: 1, depositor: "alice") }, "clock_invalid")
        let code = codeOf { try b.challengeStatus("c9") }
        XCTAssertTrue(code == "unregistered" || code == "store_unavailable")
    }

    func testAClockThatStepsBackCannotReleaseEarly() throws {
        let clock = Clock(5_000)
        let b = try ledger(clock)
        _ = try b.deposit("alice", 10)
        _ = try b.openBond("c", amount: 5, depositor: "alice")
        clock.t = 1 // the store's high-water mark keeps "now" from going backwards
        _ = try b.releaseUnregistered("c")
        XCTAssertGreaterThanOrEqual(try b.getBond("c")?.get("records")?.asArray?.last?.get("at")?.safeInt ?? 0, 5_000)
    }

    func testTheLedgerStoreAndTheStoredLedgerRoundTrip() throws {
        let kv = MemoryAtomicKV()
        let store = KvLedgerStore(kv: kv)
        let key = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 5, count: 32)))
        var t = 1_800_000_000_000.0
        let a = try StoredLedger.open(store: store, guardian: key, instanceId: "i", principal: "p", clock: { t += 1; return t })
        for c in ["a", "b", "c"] { _ = try a.append(c) }
        let first = try a.checkpoint()
        XCTAssertEqual(first.get("size")?.safeInt, 3)
        _ = try a.append("d")
        _ = try a.checkpoint()
        // a reopened handle verifies the whole chain; a tampered entry fails closed
        let b = try StoredLedger.open(store: store, guardian: key, instanceId: "i", principal: "p")
        XCTAssertEqual(b.size, 4)
        try kv.update(KvLedgerStore.DOC_KEY) { prev in
            guard var o = prev?.asObject, var cs = o["commits"]?.asArray else { return nil }
            cs[0] = .string("evil")
            o["commits"] = .array(cs)
            return .object(o)
        }
        XCTAssertThrowsError(try StoredLedger.open(store: store, guardian: key, instanceId: "i", principal: "p")) { XCTAssertEqual(($0 as? PCAStoreError)?.code, "tamper") }
    }
}
