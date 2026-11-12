import XCTest
@testable import AtlasPCAVerify

/// Date.parse of the PCS documents' ISO forms (attest-intel-collateral.ts:262): the seconds field counts.
final class S2G3IntelCollateralKillTests: XCTestCase {
    private typealias C = IntelCollateral
    private let t: Int64 = 1_767_225_600_000 // 2026-01-01T00:00:00Z

    func testSecondsAreReadFromTheTimeOfDay() {
        XCTAssertEqual(C.jsDateParse("2026-01-01T00:00:45Z"), t + 45_000)
        XCTAssertEqual(C.jsDateParse("2026-01-01T00:01:07Z"), t + 67_000)
        XCTAssertEqual(C.jsDateParse("2026-01-01T00:00:45.25Z"), t + 45_250)
        XCTAssertEqual(C.jsDateParse("2026-01-01T01:00:30+01:00"), t + 30_000)
        XCTAssertEqual(C.jsDateParse("2026-01-01T00:00:30-01:00"), t + 3_630_000)
    }
}
