import XCTest
import Foundation
@testable import AtlasPCAStepUp

/// The step-up expiry parses with or without fractional seconds.
final class S2G3PendingStepUpKillTests: XCTestCase {
    func testFractionalSecondsAreKept() throws {
        let d = try XCTUnwrap(ISO8601.parse("2024-01-01T00:00:00.500Z"))
        XCTAssertEqual(d.timeIntervalSince1970, 1_704_067_200.5, accuracy: 0.001)
    }

    func testWholeSecondsParseToo() throws {
        let d = try XCTUnwrap(ISO8601.parse("2024-01-01T00:00:00Z"))
        XCTAssertEqual(d.timeIntervalSince1970, 1_704_067_200, accuracy: 0.001)
        XCTAssertNil(ISO8601.parse("not a date"))
    }
}
