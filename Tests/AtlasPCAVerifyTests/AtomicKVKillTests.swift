import XCTest
@testable import AtlasPCAVerify

/// `KVOperationStore.transition`: a compare-and-set on the state (reference operation-record module). Wrong `from` or a missing
/// record: false and nothing written; matching `from`: true and the new record stored under the id.
final class AtomicKVKillTests: XCTestCase {
    private func rec(_ id: String, _ st: OperationState) -> OperationRecord {
        OperationRecord(id: id, state: st, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: 1)
    }

    func testTransitionIsACompareAndSetOnState() throws {
        let s = KVOperationStore(kv: MemoryAtomicKV())
        XCTAssertFalse(try s.transition("missing", from: .pending, to: rec("x", .executing)))
        XCTAssertNil(try s.get("missing"))
        _ = try s.create(rec("a", .pending))
        XCTAssertFalse(try s.transition("a", from: .executing, to: rec("a", .committed)))
        XCTAssertEqual(try s.get("a")?.state, .pending)
        XCTAssertTrue(try s.transition("a", from: .pending, to: rec("ignored", .executing)))
        XCTAssertEqual(try s.get("a"), rec("a", .executing)) // stored under the transition id, not the record's
        XCTAssertFalse(try s.transition("a", from: .pending, to: rec("a", .committed)))
        XCTAssertEqual(try s.get("a")?.state, .executing)
    }
}
