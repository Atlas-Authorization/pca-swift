import XCTest
@testable import AtlasPCAVerify

/// `KVOperationStore.create` is create-if-absent: the second call answers with the stored record and writes nothing.
final class S2G4AtomicKVKillTests: XCTestCase {
    private func rec(_ id: String, _ st: OperationState) -> OperationRecord {
        OperationRecord(id: id, state: st, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: 1)
    }

    func testCreateAnswersWithTheExistingRecord() throws {
        let s = KVOperationStore(kv: MemoryAtomicKV())
        let first = rec("a", .pending)
        if case .created = try s.create(first) {} else { XCTFail("the first create creates") }
        if case let .existing(cur) = try s.create(rec("a", .executing)) {
            XCTAssertEqual(cur, first)
        } else { XCTFail("the second create answers with the stored record") }
        XCTAssertEqual(try s.get("a"), first, "the second create wrote nothing")
    }
}
