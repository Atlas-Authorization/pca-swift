import XCTest
import Foundation
import AtlasPCAVerify
@testable import AtlasPCASQLite

/// `SQLiteOperationStore.transition` stores the record under the id it was asked to transition, whatever id the record carries.
final class S2G7SQLiteStoresKillTests: XCTestCase {
    var path = ""
    override func setUp() {
        super.setUp()
        path = FileManager.default.temporaryDirectory.appendingPathComponent("pca-s2g7-\(UUID().uuidString).sqlite").path
    }
    override func tearDown() {
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
        super.tearDown()
    }

    private func rec(_ id: String, _ st: OperationState) -> OperationRecord {
        OperationRecord(id: id, state: st, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: 1)
    }

    func testTransitionKeepsTheRowId() throws {
        let s = try SQLiteOperationStore(path: path)
        _ = try s.create(rec("a", .pending))
        XCTAssertTrue(try s.transition("a", from: .pending, to: rec("zzz", .executing)))
        let got = try XCTUnwrap(try s.get("a"))
        XCTAssertEqual(got.id, "a", "the stored record carries the row id, not the one passed in")
        XCTAssertEqual(got.state, .executing)
        XCTAssertNil(try s.get("zzz"))
        XCTAssertEqual(try s.listOpen().map { $0.id }, ["a"])
    }
}
