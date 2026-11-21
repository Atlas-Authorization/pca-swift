import XCTest

final class S2DeadlineTests: XCTestCase {
    func testAFastCallReturnsItsResult() {
        XCTAssertEqual(S2Deadline.within(5, "fast") { 41 + 1 }, 42)
    }
}
