import XCTest
import Foundation
@testable import AtlasPCAVerify

/// BigUInt.swift 18 (limb split loop; a wrong test grows an array without end, so 2 s), 32 (byte shifts), 74 (compare walk).
final class A0DeadlineBigUIntTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testA1ConstructionFromAnIntegerEndsAtItsTopLimb() {
        let got: [[UInt32]]? = S2Deadline.within(2, "BigUInt(UInt64)") {
            [BigUInt(0).limbs, BigUInt(1).limbs, BigUInt(1 << 40).limbs, BigUInt(0xffff_ffff_ffff_ffff).limbs]
        }
        XCTAssertEqual(got, [[], [1], [0, 256], [0xffff_ffff, 0xffff_ffff]], "line 18")
    }

    func testA2LittleEndianBytesLandInTheirOwnShifts() {
        XCTAssertEqual(BigUInt(bytesLE: [1]).limbs, [1], "line 32: byte 0 sits at shift 0")
        XCTAssertEqual(BigUInt(bytesLE: [1, 2]).limbs, [0x0201], "line 32: byte 1 sits at shift 8")
        XCTAssertEqual(BigUInt(bytesLE: [1, 2, 3, 4, 5]).limbs, [0x0403_0201, 5], "line 32: byte 4 starts the next limb")
    }

    func testA3LessThanWalksDownToTheFirstDifferingLimb() {
        let lo = BigUInt(0x1_0000_0001), hi = BigUInt(0x1_0000_0002)
        let got: [Bool]? = S2Deadline.within(10, "BigUInt <") { [lo < hi, hi < lo, lo < lo, BigUInt(5) < BigUInt(5), BigUInt(0) < BigUInt(0)] }
        XCTAssertEqual(got, [true, false, false, false, false], "line 74")
    }
}
