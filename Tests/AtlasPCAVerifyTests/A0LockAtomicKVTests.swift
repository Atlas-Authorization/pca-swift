import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Lock kills (see S2LK) for AtomicKV.swift line 26 (get) and Operations.swift line 145 (listOpen), plus update; the stem is in the class
/// name so the mutation tool runs these first.
final class A0LockAtomicKVTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testMemoryAtomicKVTakesItsLockOncePerCall() {
        let kv = MemoryAtomicKV()
        S2LK.check(kv.lock, "update") { kv.update("k") { _ in JSONValue.string("v") } }
        XCTAssertEqual(S2LK.check(kv.lock, "get") { kv.get("k") }, JSONValue.string("v"))
        XCTAssertNil(S2LK.check(kv.lock, "get missing") { kv.get("zz") })
    }
}

final class A0LockOperationsListOpenTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testListOpenTakesItsLockAndOrdersById() {
        let s = MemoryOperationStore()
        func rec(_ id: String, _ st: OperationState) -> OperationRecord {
            OperationRecord(id: id, state: st, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: 1)
        }
        _ = s.create(rec("b", .pending))
        _ = s.create(rec("a", .executing))
        _ = s.create(rec("c", .pending))
        _ = s.transition("c", from: .pending, to: rec("c", .executing))
        let open = S2LK.check(s.lock, "listOpen") { s.listOpen() }
        XCTAssertEqual(open.map { $0.id }, ["a", "b", "c"])
    }
}
