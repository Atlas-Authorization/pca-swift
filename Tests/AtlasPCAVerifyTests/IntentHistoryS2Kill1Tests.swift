import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the IntentHistory.swift survivor of group 2: a monitor with no predicate never matches (fail closed), it is not "matches everything".
final class S2G2IntentHistoryKillTests: XCTestCase {
    private let event: JObject = ["status": .string("committed"), "verb": .string("a.b")]

    func testAMonitorWithoutAPredicateMatchesNothing() {
        XCTAssertEqual(IntentHistory.monitorStep(["kind": .string("never")], "clean", event), "clean", "line 110")
        XCTAssertEqual(IntentHistory.monitorStep(["kind": .string("requires_prior")], "unmet", event), "unmet", "line 110")
        XCTAssertEqual(IntentHistory.monitorStep(["kind": .string("precedes")], "unmet", event), "unmet", "line 110")
        XCTAssertEqual(IntentHistory.monitorStep(["kind": .string("always")], "ok", event), "broken", "line 110")
    }
}
