import XCTest
@testable import AtlasPCAVerify

/// `IntelCollateral.jsDateParse` zone offsets, as JS Date.parse: hour 00..23, minute 00..59, anything else is NaN (attest-intel-collateral.ts:260).
final class AttestIntelCollateralDateTests: XCTestCase {
    func testZoneOffsetRange() {
        let t: Int64 = 1_767_225_600_000 // 2026-01-01T00:00:00Z
        XCTAssertEqual(IntelCollateral.jsDateParse("2026-01-01T00:00:00Z"), t)
        XCTAssertEqual(IntelCollateral.jsDateParse("2026-01-01T00:00:00+23:59"), t - 86_340_000)
        XCTAssertEqual(IntelCollateral.jsDateParse("2026-01-01T00:00:00-23:59"), t + 86_340_000)
        XCTAssertEqual(IntelCollateral.jsDateParse("2026-01-01T00:00:00+00:00"), t)
        for bad in ["+24:00", "-24:00", "+00:60", "-00:60", "+99:99"] { XCTAssertNil(IntelCollateral.jsDateParse("2026-01-01T00:00:00" + bad), bad) }
    }
}
