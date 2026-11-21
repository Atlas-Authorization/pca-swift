import XCTest
@testable import AtlasPCAVerify

/// packages/pca/src/intent-history.ts: only an event stamped AFTER t short-circuits `inWindow` (63); an empty pre-state is all zero (82).
final class IntentHistoryK05Tests: XCTestCase {
    func testAnEventStampedExactlyAtTGoesThroughTheWindowRules() {
        let sliding0: JSONValue = .object(["kind": .string("sliding"), "ms": .int(0)])
        XCTAssertFalse(IntentHistory.inWindow(sliding0, .int(5), .int(5))) // 5 > 5 - 0 is false
        XCTAssertTrue(IntentHistory.inWindow(sliding0, .int(6), .int(5)))  // stamped after t: always counts
        XCTAssertFalse(IntentHistory.inWindow(sliding0, .int(4), .int(5)))
    }

    func testEmptyPreStates() {
        XCTAssertEqual(IntentHistory.emptyPre("sum"), .object(["sum": .int(0)]))
        XCTAssertEqual(IntentHistory.emptyPre("count"), .object(["count": .int(0)]))
        XCTAssertEqual(IntentHistory.emptyPre("max"), .object(["max": .int(0)]))
        XCTAssertEqual(IntentHistory.emptyPre("distinct"), .object(["values": .array([])]))
    }
}
