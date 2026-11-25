import XCTest
@testable import AtlasPCAVerify

final class RiskSafetyBoundTests: XCTestCase {
    func testTheBoundIsTheBudgetCapOverKappa() {
        XCTAssertEqual(Risk.safetyBound(bMax: 1, kappa: 2), 0.5)
        XCTAssertEqual(Risk.safetyBound(bMax: 10, kappa: 0.5), 20)
        XCTAssertEqual(Risk.safetyBound(bMax: -3, kappa: 2), 0)
        XCTAssertEqual(Risk.safetyBound(bMax: 5, kappa: 0), 0)
        XCTAssertEqual(Risk.safetyBound(bMax: 5, kappa: -1), 0)
        XCTAssertEqual(Risk.safetyBound(.object(["bMax": .int(3), "kappa": .int(4)])), 0.75)
        XCTAssertTrue(Risk.safetyBound(.object(["bMax": .string("x"), "kappa": .int(4)])).isNaN)
        XCTAssertEqual(Risk.safetyBound(nil), 0, "a policy without a positive kappa has no bound")
    }
}
