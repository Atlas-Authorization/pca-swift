import XCTest
@testable import AtlasPCAVerify

/// The replay clock is the corpus header's clockMs; a header without it (an older corpus) gives the fallback.
final class BaseClockTests: XCTestCase {
    func testHeaderClockIsRead() {
        XCTAssertEqual(Base.clockOfHeader(#"{"about":"a","generator":"g.mts","count":3,"clockMs":1700000000000,"cases":["#), 1_700_000_000_000)
    }

    func testMissingHeaderClockFallsBack() {
        XCTAssertEqual(Base.clockOfHeader(#"{"about":"a","generator":"g.mts","count":3,"cases":["#), Base.fallbackClockMs)
    }
}
