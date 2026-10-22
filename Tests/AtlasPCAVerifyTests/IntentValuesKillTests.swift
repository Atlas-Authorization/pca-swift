import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mutation-kill tests for IntentValues.swift (IV): ASCII class boundaries, equality, sentinel scan, normalisation.
final class IntentValuesKillTests: XCTestCase {
    static let SENT = String(Canonical.LONE_SURROGATE_SENTINEL)

    func testEndsWithEqualLength() {
        XCTAssertTrue(IV.endsWith("ab", "ab"))
        XCTAssertTrue(IV.endsWith("xab", "ab"))
        XCTAssertFalse(IV.endsWith("b", "ab"))
        XCTAssertFalse(IV.endsWith("ac", "ab"))
        XCTAssertTrue(IV.endsWith("", ""))
    }

    func testIsIdAlnumBoundaries() {
        for s in ["0", "9", "A", "Z", "a", "z", "_", "aZ09_"] { XCTAssertTrue(IV.isId(s), s) }
        for s in ["/", ":", "@", "[", "`", "{", "-", ".", "", "a b"] { XCTAssertFalse(IV.isId(s), s) }
        XCTAssertTrue(IV.isId(String(repeating: "a", count: 64)))
        XCTAssertFalse(IV.isId(String(repeating: "a", count: 65)))
    }

    func testIsPathSegment() {
        for s in ["a_b", "a-b", "-", "_", "Z", "A", "0", "9", "z"] { XCTAssertTrue(IV.isPathSegment(s), s) }
        for s in ["a.b", "a b", "@", "[", "", "__proto__", "constructor", "prototype"] { XCTAssertFalse(IV.isPathSegment(s), s) }
        XCTAssertTrue(IV.isPathSegment("__proto__x"))
    }

    func testLowerDigitUnderscoreViaUnitId() {
        for s in ["a", "z", "0", "9", "_", "a.b", "a0_.z9"] { XCTAssertTrue(IV.isUnitId(s), s) }
        for s in ["A", "Z", "/", ":", "`", "{", "-", "", "a..b", ".a", "a.", "."] { XCTAssertFalse(IV.isUnitId(s), s) }
    }

    func testIsName() {
        for s in ["a", "z", "m", "a0", "z_9"] { XCTAssertTrue(IV.isName(s), s) }
        for s in ["", "0", "_", "A", "`", "{", "aA", "a-"] { XCTAssertFalse(IV.isName(s), s) }
        XCTAssertTrue(IV.isName(String(repeating: "a", count: 64)))
        XCTAssertFalse(IV.isName(String(repeating: "a", count: 65)))
    }

    func testIsDataClass() {
        for s in ["a", "z", "a.b", "z.0_", "a_1.b2"] { XCTAssertTrue(IV.isDataClass(s), s) }
        for s in ["", "0", "_", "A", "`", "{", "a.", "a..b", ".a", "aB"] { XCTAssertFalse(IV.isDataClass(s), s) }
    }

    func testStrictEq() {
        XCTAssertTrue(IV.strictEq(nil, nil))
        XCTAssertFalse(IV.strictEq(nil, .null))
        XCTAssertFalse(IV.strictEq(.null, nil))
        XCTAssertTrue(IV.strictEq(.null, .null))
        XCTAssertTrue(IV.strictEq(.bool(true), .bool(true)))
        XCTAssertTrue(IV.strictEq(.bool(false), .bool(false)))
        XCTAssertFalse(IV.strictEq(.bool(true), .bool(false)))
        XCTAssertTrue(IV.strictEq(.string("a"), .string("a")))
        XCTAssertFalse(IV.strictEq(.string("a"), .string("b")))
        XCTAssertTrue(IV.strictEq(.int(1), .double(1.0)))
        XCTAssertTrue(IV.strictEq(.int(1), .int(1)))
        XCTAssertFalse(IV.strictEq(.int(1), .int(2)))
        XCTAssertFalse(IV.strictEq(.int(1), .string("1")))
        XCTAssertFalse(IV.strictEq(.bool(true), .int(1)))
        XCTAssertFalse(IV.strictEq(.array([]), .array([])))
        XCTAssertFalse(IV.strictEq(.null, .bool(false)))
    }

    func testScalarEq() {
        XCTAssertTrue(IV.scalarEq(.bool(true), .bool(true)))
        XCTAssertFalse(IV.scalarEq(.bool(true), .bool(false)))
        XCTAssertTrue(IV.scalarEq(.int(3), .int(3)))
        XCTAssertFalse(IV.scalarEq(.int(3), .int(4)))
        XCTAssertFalse(IV.scalarEq(.int(1), .string("1")))
        XCTAssertFalse(IV.scalarEq(nil, nil))
    }

    func testHasSentinelObject() {
        let S = Self.SENT
        XCTAssertTrue(IV.hasSentinel(.string("a" + S)))
        XCTAssertFalse(IV.hasSentinel(.string("a")))
        XCTAssertTrue(IV.hasSentinel(.array([.int(1), .string(S)])))
        XCTAssertTrue(IV.hasSentinel(.object([JKey(S): .int(1)])))
        XCTAssertTrue(IV.hasSentinel(.object([JKey("k"): .string(S)])))
        XCTAssertTrue(IV.hasSentinel(.object([JKey("k"): .object([JKey("j"): .array([.string(S)])])])))
        XCTAssertFalse(IV.hasSentinel(.object([JKey("k"): .string("v")])))
        XCTAssertFalse(IV.hasSentinel(.null))
    }

    func testNormalizedSafeBoundary() {
        let m = Canonical.MAX_SAFE
        XCTAssertEqual(IV.normalized(.int(m)), .int(m))
        XCTAssertEqual(IV.normalized(.int(-m)), .int(-m))
        XCTAssertEqual(IV.normalized(.int(0)), .int(0))
        XCTAssertEqual(IV.normalized(.int(m + 1)), .double(Double(m + 1)))
        XCTAssertEqual(IV.normalized(.int(-m - 1)), .double(Double(-m - 1)))
        XCTAssertEqual(IV.normalized(.array([.int(m + 1)])), .array([.double(Double(m + 1))]))
        XCTAssertEqual(IV.normalized(.object([JKey("k"): .int(m + 1)])), .object([JKey("k"): .double(Double(m + 1))]))
    }

    func testVerifyEdMissingSig() {
        XCTAssertFalse(IV.verifyEd("AAAA", [1, 2, 3], nil))
        XCTAssertFalse(IV.verifyEd("AAAA", [1, 2, 3], .int(1)))
    }
}
