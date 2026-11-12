import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Every locking method of the in-process stores takes its lock once and releases it (see S2LK.check).
final class S2LKStoreLockTests: XCTestCase {
    typealias J = JSONValue

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    private func rec(_ id: String, _ st: OperationState) -> OperationRecord {
        OperationRecord(id: id, state: st, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: 1)
    }

    // Operations.swift: MemoryOperationStore (lines 120, 128, 134, 145)
    func testMemoryOperationStore() {
        let s = MemoryOperationStore()
        _ = S2LK.check(s.lock, "create") { s.create(rec("a", .pending)) }
        _ = S2LK.check(s.lock, "create (existing)") { s.create(rec("a", .pending)) }
        XCTAssertEqual(S2LK.check(s.lock, "get") { s.get("a") }?.id, "a")
        XCTAssertTrue(S2LK.check(s.lock, "transition") { s.transition("a", from: .pending, to: rec("a", .executing)) })
        XCTAssertFalse(S2LK.check(s.lock, "transition (refused)") { s.transition("a", from: .pending, to: rec("a", .committed)) })
        XCTAssertEqual(S2LK.check(s.lock, "listOpen") { s.listOpen() }.count, 1)
    }

    // AtomicKV.swift: MemoryAtomicKV (lines 20, 26)
    func testMemoryAtomicKV() {
        let kv = MemoryAtomicKV()
        S2LK.check(kv.lock, "update") { kv.update("k") { _ in J.int(1) } }
        XCTAssertEqual(S2LK.check(kv.lock, "get") { kv.get("k") }, J.int(1))
        S2LK.check(kv.lock, "update (leave unchanged)") { kv.update("k") { _ in nil } }
    }

    // ReadVault.swift: MemoryVault (lines 28, 33)
    func testMemoryVault() {
        let v = MemoryVault()
        S2LK.check(v.lock, "put") { v.put("t", VaultEntry(cls: "c", value: J.int(1), grant: "g", exp: 5)) }
        XCTAssertEqual(S2LK.check(v.lock, "get") { v.get("t") }?.cls, "c")
        XCTAssertNil(S2LK.check(v.lock, "get (absent)") { v.get("zz") })
    }

    // Authorize.swift: MemoryStateStore (lines 74, 80, 89)
    func testMemoryStateStore() throws {
        let s = MemoryStateStore()
        XCTAssertNil(S2LK.check(s.lock, "last") { s.last(key: "k") })
        XCTAssertTrue(S2LK.check(s.lock, "claim") { s.claim(key: "k", counter: 1) }.ok)
        XCTAssertFalse(S2LK.check(s.lock, "claim (replay)") { s.claim(key: "k", counter: 1) }.ok)
        XCTAssertEqual(S2LK.check(s.lock, "last (after claim)") { s.last(key: "k") }, 1)
        XCTAssertTrue(try S2LK.check(s.lock, "consumeOnce") { try s.consumeOnce(key: "o", retainUntil: 10, now: 5) })
        XCTAssertFalse(try S2LK.check(s.lock, "consumeOnce (again)") { try s.consumeOnce(key: "o", retainUntil: 10, now: 5) })
    }

    // StoreConformance.swift: ConformanceCounter (53, 58) and LossyStateStore (76, 79)
    func testConformanceCounter() {
        let c = ConformanceCounter()
        S2LK.check(c.lock, "add") { c.add(2) }
        S2LK.check(c.lock, "add (default)") { c.add() }
        XCTAssertEqual(S2LK.check(c.lock, "value") { c.value }, 3)
    }

    func testLossyStateStore() {
        let l = LossyStateStore(MemoryStateStore())
        let lost: Bool = S2LK.check(l.lock, "first claim (the answer is lost)") { (try? l.claim(key: "k", counter: 1)) == nil }
        XCTAssertTrue(lost, "the first claim loses its answer and throws")
        XCTAssertTrue(S2LK.check(l.lock, "second claim") { try? l.claim(key: "k", counter: 2) }?.ok ?? false)
    }
}
