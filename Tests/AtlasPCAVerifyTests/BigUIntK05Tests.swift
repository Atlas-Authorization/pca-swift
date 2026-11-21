import XCTest
@testable import AtlasPCAVerify

/// The decimal constructor's digit gate (a non-digit traps in the constructor, so the gate is pinned on its own).
final class BigUIntK05Tests: XCTestCase {
    func testDecimalDigit() {
        XCTAssertNil(BigUInt.decimalDigit(":"))
        XCTAssertNil(BigUInt.decimalDigit("a"))
        XCTAssertNil(BigUInt.decimalDigit("/"))
        XCTAssertEqual(BigUInt.decimalDigit("0"), 0)
        XCTAssertEqual(BigUInt.decimalDigit("5"), 5)
        XCTAssertEqual(BigUInt.decimalDigit("9"), 9)
    }
}
