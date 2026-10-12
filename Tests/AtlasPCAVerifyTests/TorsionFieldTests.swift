import XCTest
@testable import AtlasPCAVerify

/// The mod-p field layer under the prime-order (torsion) test, pinned on the carry / borrow / fold paths that random field
/// values almost never take (a limb exactly at 2^64-1 with a carry in, a borrow rippling into the top limb, ...).
final class TorsionFieldTests: XCTestCase {
    typealias T = Ed25519Torsion
    typealias Fe = Ed25519Torsion.Fe
    let max = UInt64.max

    func testGeP() {
        let P = T.P
        XCTAssertTrue(T.geP(P))
        XCTAssertFalse(T.geP(Fe(P.a0 - 1, max, max, P.a3)))
        XCTAssertTrue(T.geP(Fe(P.a0 + 1, max, max, P.a3)))
        XCTAssertFalse(T.geP(Fe(0, max, 0, P.a3)))          // limb 2 decides
        XCTAssertFalse(T.geP(Fe(max, 0, max, P.a3)))        // limb 1 decides
        XCTAssertTrue(T.geP(Fe(0, 0, 0, P.a3 + 1)))
        XCTAssertTrue(T.geP(Fe(max, max, max, max)))
        XCTAssertFalse(T.geP(T.zero))
        XCTAssertEqual(T.canon(Fe(P.a0 + 5, max, max, P.a3)), Fe(5))
    }

    func testAddCarry() {
        let (r, c) = T.addCarry(Fe(max, max, 0, 0), Fe(1))   // limb 1: max + 0 + carry-in overflows on the carry alone
        XCTAssertEqual(r, Fe(0, 0, 1, 0)); XCTAssertEqual(c, 0)
        let (r2, c2) = T.addCarry(Fe(max, max, max, max), Fe(1))
        XCTAssertEqual(r2, T.zero); XCTAssertEqual(c2, 1)
        let (r3, c3) = T.addCarry(Fe(max, 5, 0, 0), Fe(max, 0, 0, 0))
        XCTAssertEqual(r3, Fe(max - 1, 6, 0, 0)); XCTAssertEqual(c3, 0)
    }

    func testNegSubBorrowChain() {
        let x = Fe(0xFFFF_FFFF_FFFF_FFF0, max, max, 0)          // borrows ripple from limb 0 into limb 3
        XCTAssertEqual(T.negSub(x), Fe(0xFFFF_FFFF_FFFF_FFFD, max, max, 0x7FFF_FFFF_FFFF_FFFE))
        XCTAssertEqual(T.fadd(x, T.negSub(x)), T.zero)
        XCTAssertEqual(T.negSub(T.one), Fe(T.P.a0 - 1, max, max, T.P.a3))
        XCTAssertEqual(T.fsub(T.zero, T.one), Fe(T.P.a0 - 1, max, max, T.P.a3))
    }

    func testReduceWideCarries() {
        // 2^63 * 2^256 + (2^64 - 6) * 2^64 = 19 * 2^64 + (2^64 - 6) * 2^64 (mod p) = 2^128 + 13 * 2^64: the carry comes from s1 + c
        XCTAssertEqual(T.reduceWide([0, max - 5, 0, 0, 1 << 63, 0, 0, 0]), Fe(0, 13, 1, 0))
        // 1 * 2^256 + (2^64 - 1) = 38 + 2^64 - 1 = 2^64 + 37: the carry comes from lo + t
        XCTAssertEqual(T.reduceWide([max, 0, 0, 0, 1, 0, 0, 0]), Fe(37, 1, 0, 0))
        XCTAssertEqual(T.reduceWide([5, 0, 0, 0, 0, 0, 0, 0]), Fe(5))
    }

    func testFieldMul() {
        let pm1 = Fe(T.P.a0 - 1, max, max, T.P.a3)                 // -1
        XCTAssertEqual(T.fmul(pm1, pm1), T.one)
        XCTAssertEqual(T.fmul(pm1, T.one), pm1)
        XCTAssertEqual(T.fmul(Fe(0, 1, 0, 0), Fe(0, 0, 0, 1)), Fe(38))   // 2^64 * 2^192 = 2^256 = 38
        XCTAssertEqual(T.fmul(Fe(1 << 32), Fe(1 << 32)), Fe(0, 1, 0, 0))
    }

    func testPrimeOrderEdges() {
        XCTAssertFalse(T.isPrimeOrder([1] + [UInt8](repeating: 0, count: 31)))         // identity
        XCTAssertTrue(T.isPrimeOrder([0x58] + [UInt8](repeating: 0x66, count: 31)))     // base point
        XCTAssertFalse(T.isPrimeOrder([0x58] + [UInt8](repeating: 0x66, count: 30)))    // wrong length
    }

    func testBigUIntNotEqualAndSelfSubtraction() {
        XCTAssertFalse(BigUInt(1) != BigUInt(1))
        XCTAssertTrue(BigUInt(1) != BigUInt(2))
        XCTAssertTrue((BigUInt(7) - BigUInt(7)).isZero)
        XCTAssertTrue(((BigUInt(1) << 64) - (BigUInt(1) << 64)).isZero)
    }
}
