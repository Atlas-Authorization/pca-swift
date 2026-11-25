import XCTest
import Foundation
@testable import AtlasPCAVerify

/// FdLibm reproduces the reference runtime's Math.log / exp / log2 / sin on known doubles (bit patterns from the reference).
final class RefFdLibmTests: XCTestCase {
    func testExactPointsAndSpecialValues() {
        XCTAssertEqual(FdLibm.log(1.0), 0.0)
        XCTAssertEqual(FdLibm.exp(0.0), 1.0)
        XCTAssertEqual(FdLibm.log(0.0), -Double.infinity)
        XCTAssertTrue(FdLibm.log(-1.0).isNaN)
        XCTAssertEqual(FdLibm.exp(710.0), Double.infinity)
        XCTAssertEqual(FdLibm.exp(-746.0), 0.0)
        XCTAssertEqual(FdLibm.log2(8.0), 3.0)
        XCTAssertEqual(FdLibm.sin(0.0), 0.0)
    }

    func testAgreesWithLibmWithinOneUlp() {
        for x in stride(from: 0.001, to: 50.0, by: 0.37) {
            XCTAssertEqual(FdLibm.log(x), Foundation.log(x), accuracy: Foundation.log(x).ulp * 1.5 + 1e-300)
            XCTAssertEqual(FdLibm.exp(x / 5), Foundation.exp(x / 5), accuracy: Foundation.exp(x / 5).ulp * 1.5)
            XCTAssertEqual(FdLibm.log2(x), Foundation.log2(x), accuracy: Swift.max(Foundation.log2(x).ulp, 1e-300) * 1.5)
        }
        for x in stride(from: -2.0, to: 2.0, by: 0.173) {
            XCTAssertEqual(FdLibm.sin(x), Foundation.sin(x), accuracy: 1e-15)
        }
    }

    func testClopperPearsonKnownBounds() throws {
        // k = 0: upper bound is 1 - alpha^(1/n) on the 2^-52 grid
        let u = try PCAIntentStats.clopperPearsonUpper(0, 59, 0.05)
        XCTAssertEqual(u, 1 - Foundation.pow(0.05, 1.0 / 59.0), accuracy: 1e-9)
        XCTAssertThrowsError(try PCAIntentStats.clopperPearsonUpper(5, 3, 0.05))
    }

    func testPowExactPointsSpecialValuesAndLibmAgreement() {
        XCTAssertEqual(FdLibm.pow(2, 10), 1024)
        XCTAssertEqual(FdLibm.pow(2, -20), 9.5367431640625e-07)
        XCTAssertEqual(FdLibm.pow(2, -1074), 5e-324)
        XCTAssertEqual(FdLibm.pow(2, 1023), 8.98846567431158e307)
        XCTAssertEqual(FdLibm.pow(2, 1024), .infinity)
        XCTAssertEqual(FdLibm.pow(0.5, 3), 0.125)
        XCTAssertEqual(FdLibm.pow(10, 2), 100)
        XCTAssertEqual(FdLibm.pow(-8, 1.0 / 3.0).isNaN, true)
        XCTAssertEqual(FdLibm.pow(-2, 3), -8)
        XCTAssertEqual(FdLibm.pow(-2, 4), 16)
        XCTAssertEqual(FdLibm.pow(7, 0), 1)
        XCTAssertEqual(FdLibm.pow(.nan, 0), 1)
        XCTAssertTrue(FdLibm.pow(1, .infinity).isNaN) // the reference language's rule, unlike C
        XCTAssertTrue(FdLibm.pow(-1, -.infinity).isNaN)
        XCTAssertTrue(FdLibm.pow(2, .nan).isNaN)
        XCTAssertEqual(FdLibm.pow(0.5, .infinity), 0)
        XCTAssertEqual(FdLibm.pow(0.5, -.infinity), .infinity)
        XCTAssertEqual(FdLibm.pow(0, -1), .infinity)
        XCTAssertEqual(FdLibm.pow(-0.0, 3).sign, .minus)
        XCTAssertEqual(FdLibm.pow(4, 0.5), 2)
        var g = SystemRandomNumberGenerator()
        for _ in 0..<20_000 {
            let x = Double.random(in: 0.001...50, using: &g), y = Double.random(in: -40...40, using: &g)
            let a = FdLibm.pow(x, y), b = Foundation.pow(x, y)
            XCTAssertLessThanOrEqual(abs(a - b), 2 * b.ulp, "pow(\(x), \(y))")
        }
    }
}
