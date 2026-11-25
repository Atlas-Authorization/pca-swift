import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The exact entropy cutoff and the deterministic math (integer fixed point, no libm).
final class DetMathTests: XCTestCase {
    typealias E = PCAEntropy

    func testBigDivisionIdentity() {
        let a = BigUInt(decimal: "123456789012345678901234567890123456789012345678901234567890")
        let one = BigUInt(1)
        let pairs: [(BigUInt, BigUInt)] = [
            (a, BigUInt(decimal: "98765432109876543210987654321")),
            ((one << 200) - one, (one << 100) + one),
            ((one << 192), (one << 96) - one),
            (a, BigUInt(7)),
            (BigUInt(5), a),
            ((one << 128) - one, (one << 64) - one),
        ]
        for (x, y) in pairs {
            let (q, r) = x.divMod(y)
            XCTAssertTrue(r < y)
            XCTAssertEqual(q * y + r, x)
        }
        XCTAssertEqual((one << 130) >> 129, BigUInt(2))
    }

    func testProportionCutoffExact() throws {
        XCTAssertEqual(try E.proportionCutoff(1, 2000), 1107) // the old float recurrence underflowed here and returned 2001, which disabled the test
        XCTAssertEqual(try E.proportionCutoff(8, 512), 13)
        XCTAssertEqual(try E.proportionCutoff(0.5, 512), 410)
    }

    func testProportionCutoffRefusesNeverRounds() {
        for h in [1.1, 0.0, 0.1, 64.125, -1, Double.nan, Double.infinity] { XCTAssertThrowsError(try E.proportionCutoff(h, 512), "h \(h)") }
        for w in [1.0, 0, 2.5, 65537, -2, Double.nan, Double.infinity] { XCTAssertThrowsError(try E.proportionCutoff(1, w), "w \(w)") }
    }

    func testHealthTestBytesBadHFails() {
        let bytes = (0..<600).map { UInt8($0 % 251) }
        XCTAssertEqual(E.healthTestBytes(bytes, E.HealthTestOptions(h: 1.1, window: 512)), E.HealthVerdict(ok: false, test: "repetition-count"))
        XCTAssertTrue(E.healthTestBytes(bytes, E.HealthTestOptions(h: 8, window: 512)).ok)
        // a one-byte window skips the proportion test
        XCTAssertTrue(E.healthTestBytes([7], E.HealthTestOptions(h: 8, window: 512)).ok)
    }

    func testDetMathValues() {
        XCTAssertEqual(DetMath.detLn(1), 0)
        XCTAssertEqual(DetMath.detLog2(1024), 10)
        XCTAssertEqual(DetMath.detLog2(0.25), -2)
        XCTAssertEqual(DetMath.detLog2(1), 0)
        XCTAssertEqual(DetMath.detExp(0), 1)
        XCTAssertEqual(DetMath.detLn(0), -Double.infinity)
        XCTAssertEqual(DetMath.detLn(-0.0), -Double.infinity)
        XCTAssertEqual(DetMath.detLog2(0), -Double.infinity)
        XCTAssertEqual(DetMath.detLog2(-0.0), -Double.infinity)
        XCTAssertTrue(DetMath.detLog2(-1).isNaN)
        XCTAssertTrue(DetMath.detLn(Double.nan).isNaN)
        XCTAssertEqual(DetMath.detExp(-Double.infinity), 0)
        XCTAssertEqual(DetMath.detExp(DetMath.detLn(0)), 0) // a prior-mix cell with q = 0 or 1 weighs 0
        XCTAssertTrue(DetMath.detLn(-1).isNaN)
        XCTAssertEqual(DetMath.detLn(Double.infinity), Double.infinity)
        XCTAssertEqual(DetMath.detLn(2), 0.6931471805599453, accuracy: 1e-15)
        XCTAssertEqual(DetMath.detLn(0.5), -0.6931471805599453, accuracy: 1e-15)
        XCTAssertEqual(DetMath.detLn(100), 4.605170185988092, accuracy: 1e-14)
        XCTAssertEqual(DetMath.detExp(1), 2.718281828459045, accuracy: 1e-15)
        XCTAssertEqual(DetMath.detExp(-1), 0.36787944117144233, accuracy: 1e-16)
        XCTAssertEqual(DetMath.detExp(710), Double.infinity)
        XCTAssertEqual(DetMath.detExp(-746), 0)
        XCTAssertTrue(DetMath.detExp(Double.nan).isNaN)
        XCTAssertEqual(DetMath.detPowInt(0.5, 3), 0.125)
        XCTAssertEqual(DetMath.detPowInt(7, 0), 1)
        // exp and ln invert each other to the last bits
        XCTAssertEqual(DetMath.detLn(DetMath.detExp(3.25)), 3.25, accuracy: 1e-14)
    }

    func testBetaUpperExactIsClopperPearson() throws {
        XCTAssertEqual(try WalletStats.betaUpperExact(0.05, 1, 9), 1 - pow(0.05, 1.0 / 9), accuracy: 1e-3)
        XCTAssertEqual(try WalletStats.betaUpperExact(0.05, 3, 7), try PCAIntentStats.clopperPearsonUpper(2, 9, 0.05))
        for (a, b) in [(0.5, 9.0), (1.0, 0.0), (Double.nan, 9)] { XCTAssertThrowsError(try WalletStats.betaUpperExact(0.05, a, b)) }
    }
}
