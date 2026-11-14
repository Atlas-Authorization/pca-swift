import XCTest
import Foundation
@testable import AtlasPCAVerify

/// BigNat construction, comparison, byte output and the Montgomery power, against plain arithmetic.
final class AttestCryptoK05BigNatTests: XCTestCase {
    func testConstructorsTrimOnlyZeroTopLimbs() {
        XCTAssertEqual(BigNat(limbs: [5, 1]).limbs, [5, 1])
        XCTAssertEqual(BigNat(limbs: [5, 0, 0]).limbs, [5])
        XCTAssertEqual(BigNat(limbs: [0, 0]).limbs, [])
        XCTAssertEqual(BigNat(bytes: [1, 2, 3, 4, 5]).limbs, [0x0203_0405, 1])
        XCTAssertEqual(BigNat(bytes: [1, 2, 3, 4]).limbs, [0x0102_0304])
        XCTAssertEqual(BigNat(bytes: []).limbs, [])
    }

    func testParityAndBitLength() {
        XCTAssertTrue(BigNat(bytes: [2]).isEven)
        XCTAssertFalse(BigNat(bytes: [3]).isEven)
        XCTAssertTrue(BigNat(limbs: [0, 1]).isEven)
        XCTAssertTrue(BigNat(bytes: []).isEven)
        XCTAssertEqual(BigNat(bytes: []).bitLength, 0)
        XCTAssertEqual(BigNat(bytes: [1]).bitLength, 1)
        XCTAssertEqual(BigNat(bytes: [1, 0, 0, 0, 0]).bitLength, 33)
    }

    func testBytesPadAndRefuseOverflow() {
        XCTAssertEqual(BigNat(bytes: [1]).bytes(length: 6), [0, 0, 0, 0, 0, 1], "padding is zero")
        XCTAssertEqual(BigNat(bytes: [0xab, 1]).bytes(length: 2), [0xab, 1])
        XCTAssertEqual(BigNat(bytes: [1]).bytes(length: 1), [1], "zero bytes past the length are fine")
        XCTAssertEqual(BigNat(bytes: [1, 0, 0, 0, 0]).bytes(length: 5), [1, 0, 0, 0, 0])
        XCTAssertNil(BigNat(bytes: [1, 0]).bytes(length: 1))
        XCTAssertNil(BigNat(bytes: [2, 0]).bytes(length: 1))
        XCTAssertNil(BigNat(bytes: [1, 0, 0, 0, 0]).bytes(length: 4))
    }

    func testOrdering() {
        let table: [([UInt32], [UInt32], Bool)] = [
            ([1], [2], true), ([2], [1], false), ([1], [1], false),
            ([5], [0, 1], true), ([0, 1], [5], false),
            ([9, 5], [2, 6], true), ([2, 6], [9, 5], false),
            ([1, 5], [2, 5], true), ([2, 5], [1, 5], false), ([2, 5], [2, 5], false),
            ([], [1], true), ([1], [], false), ([], [], false),
        ]
        for (a, b, less) in table {
            XCTAssertEqual(BigNat(limbs: a) < BigNat(limbs: b), less, "\(a) < \(b)")
        }
    }

    func testSubLimbsBorrow() {
        var a: [UInt32] = [5, 7, 9]
        BigNat.subLimbs(&a, [5, 7, 1])
        XCTAssertEqual(a, [0, 0, 8], "equal limbs do not borrow")
        var b: [UInt32] = [0, 1, 5]
        BigNat.subLimbs(&b, [1, 0, 0])
        XCTAssertEqual(b, [0xffff_ffff, 0, 5], "a borrow moves one limb")
        var c: [UInt32] = [0, 0, 5]
        BigNat.subLimbs(&c, [1, 0, 0])
        XCTAssertEqual(c, [0xffff_ffff, 0xffff_ffff, 4], "a borrow passes through a zero limb")
    }

    static func powMod(_ base: UInt64, _ exp: UInt64, _ mod: UInt64) -> UInt64 { // mod < 2^32
        var r: UInt64 = 1 % mod, x = base % mod, e = exp
        while e > 0 {
            if e & 1 == 1 { r = r * x % mod }
            x = x * x % mod
            e >>= 1
        }
        return r
    }

    /// A two-limb exponent first: it fails an assertion for a wrong limb or bit index before the 32-bit case could index out of range.
    func testExponentBitsAcrossLimbs() {
        let cases: [(UInt64, UInt64, UInt64)] = [
            (2, 0x0000_0005_8000_0002, 1_000_003), (3, 0x0000_0005_8000_0002, 4_294_967_291),
            (2, 0x0000_0003_c000_0004, 1_000_003), (3, 0x0000_0003_c000_0004, 4_294_967_291),
            (7, 65537, 1_000_003), (7, 3, 4_294_967_291),
        ]
        for (b, e, m) in cases {
            let exp = BigNat(limbs: [UInt32(truncatingIfNeeded: e), UInt32(truncatingIfNeeded: e >> 32)])
            let mod = BigNat(limbs: [UInt32(truncatingIfNeeded: m)])
            let want = BigNat(limbs: [UInt32(truncatingIfNeeded: Self.powMod(b, e, m))])
            XCTAssertEqual(BigNat.modPowOdd(base: BigNat(limbs: [UInt32(truncatingIfNeeded: b)]), exp: exp, mod: mod), want, "\(b)^\(e) mod \(m)")
        }
        // exactly 32 bits is the largest exponent rsaPublic takes
        let n = [UInt8](repeating: 0xff, count: 64), s = [UInt8](repeating: 0, count: 63) + [1]
        XCTAssertEqual(ACrypto.rsaPublic(n: n, e: [0x80, 0, 0, 0x01], sig: s), s)
    }

    /// n = 2^64 - 1, (n - 1)^2: the sum reaches t[k + 1] in the second Montgomery round, and (n - 1)^2 mod n is 1.
    func testCarryIntoTheExtraLimb() {
        let n = BigNat(limbs: [0xffff_ffff, 0xffff_ffff]), base = BigNat(limbs: [0xffff_fffe, 0xffff_ffff])
        XCTAssertEqual(BigNat.modPowOdd(base: base, exp: BigNat(limbs: [2]), mod: n), BigNat(limbs: [1]))
    }

    func testSmallestModulus() {
        XCTAssertEqual(BigNat.modPowOdd(base: BigNat(limbs: []), exp: BigNat(limbs: [1]), mod: BigNat(limbs: [1])), BigNat(limbs: []))
    }
}
