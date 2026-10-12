import XCTest
@testable import AtlasPCAVerify

/// BigUInt carries the two curve constants and the S < L / y < p gates; pin its arithmetic directly (multi-limb carries,
/// shifts across limb boundaries, normalisation), not only through the handful of constants the verifier builds.
final class BigUIntTests: XCTestCase {
    private func le(_ b: [UInt8]) -> BigUInt { BigUInt(bytesLE: b) }

    func testConstructionAndNormalisation() {
        XCTAssertTrue(BigUInt(UInt64.max) == le([UInt8](repeating: 0xff, count: 8)))
        XCTAssertTrue(BigUInt(0x1_0000_0001) == le([1, 0, 0, 0, 1]))
        XCTAssertTrue(le([5, 0, 0, 0, 0, 0, 0, 0, 0]) == BigUInt(5))
        XCTAssertTrue(le([0, 1]) == BigUInt(256))
        XCTAssertTrue(le([0, 0, 0, 0, 1]) == (BigUInt(1) << 32))
        XCTAssertTrue(le([]).isZero && BigUInt(0).isZero && le([0, 0, 0]).isZero)
        XCTAssertEqual(le([1, 2, 3, 4, 5]).bitLength, 35)
        XCTAssertEqual(BigUInt(0).bitLength, 0)
        XCTAssertTrue(BigUInt(decimal: "18446744073709551616") == (BigUInt(1) << 64))
    }

    func testShift() {
        XCTAssertTrue((BigUInt(1) << 1) == BigUInt(2))
        XCTAssertTrue((BigUInt(0xffff_ffff) << 4) == BigUInt(0xf_ffff_fff0))
        XCTAssertTrue((BigUInt(0x8000_0001) << 33) == le([0, 0, 0, 0, 2, 0, 0, 0, 1]))
        XCTAssertTrue((BigUInt(3) << 64) == le([0, 0, 0, 0, 0, 0, 0, 0, 3]))
        XCTAssertTrue((BigUInt(5) << 0) == BigUInt(5))
        XCTAssertTrue((BigUInt(0) << 7).isZero)
    }

    func testAddSubMul() {
        XCTAssertTrue(BigUInt(UInt64.max) + BigUInt(1) == (BigUInt(1) << 64))
        XCTAssertTrue((BigUInt(1) << 64) - BigUInt(1) == BigUInt(UInt64.max))
        XCTAssertTrue(le([0, 0, 0, 0, 1]) - BigUInt(1) == BigUInt(0xffff_ffff))
        XCTAssertTrue((BigUInt(1) << 40) * (BigUInt(1) << 40) == (BigUInt(1) << 80))
        // (2^64 - 1)^2 = 2^128 - 2^65 + 1
        XCTAssertTrue(BigUInt(UInt64.max) * BigUInt(UInt64.max) == le([1, 0, 0, 0, 0, 0, 0, 0, 0xfe] + [UInt8](repeating: 0xff, count: 7)))
        XCTAssertTrue((BigUInt(0) * BigUInt(9)).isZero && (BigUInt(9) * BigUInt(0)).isZero)
    }

    func testOrderAndBits() {
        XCTAssertTrue((BigUInt(1) << 64) < (BigUInt(1) << 65))
        XCTAssertFalse((BigUInt(1) << 65) < (BigUInt(1) << 64))
        XCTAssertTrue(le([1, 0, 0, 0, 2]) < le([2, 0, 0, 0, 2]))
        XCTAssertTrue(le([9, 0, 0, 0, 1]) < le([0, 0, 0, 0, 2]))
        XCTAssertFalse(le([1, 0, 0, 0, 2]) < le([1, 0, 0, 0, 2]))
        XCTAssertTrue(BigUInt(0xffff_ffff) < (BigUInt(1) << 32))
        let x = BigUInt(1) << 40
        XCTAssertEqual(x.bit(40), 1); XCTAssertEqual(x.bit(39), 0); XCTAssertEqual(x.bit(41), 0); XCTAssertEqual(x.bit(1000), 0)
        XCTAssertEqual(BigUInt(5).bit(0), 1); XCTAssertEqual(BigUInt(5).bit(1), 0); XCTAssertEqual(BigUInt(5).bit(2), 1)
    }

    func testCurveConstants() {
        XCTAssertEqual(Ed25519Strict.L.bitLength, 253)
        XCTAssertEqual(Ed25519Strict.P.bitLength, 255)
        XCTAssertTrue(Ed25519Strict.L == le([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14] + [UInt8](repeating: 0, count: 15) + [0x10]))
        XCTAssertTrue(Ed25519Strict.P == le([0xed] + [UInt8](repeating: 0xff, count: 30) + [0x7f]))
    }
}
