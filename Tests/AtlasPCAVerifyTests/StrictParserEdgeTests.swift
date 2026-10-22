import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Canonical number spelling and the strict / lenient JSON parser pinned edge by edge. The number vectors are the
/// ECMAScript `String(x)` of each double (computed with Node), restricted to the plain-decimal range Swift prints (no exponent).
final class StrictParserEdgeTests: XCTestCase {
    private static let numbers: [(Double, String)] = [
        (0.5, "0.5"),
        (-0.5, "-0.5"),
        (0.25, "0.25"),
        (-0.25, "-0.25"),
        (0.125, "0.125"),
        (-0.125, "-0.125"),
        (0.05, "0.05"),
        (-0.05, "-0.05"),
        (0.005, "0.005"),
        (-0.005, "-0.005"),
        (0.0005, "0.0005"),
        (-0.0005, "-0.0005"),
        (0.000005, "0.000005"),
        (-0.000005, "-0.000005"),
        (0.00001, "0.00001"),
        (-0.00001, "-0.00001"),
        (0.000123, "0.000123"),
        (-0.000123, "-0.000123"),
        (1.5, "1.5"),
        (-1.5, "-1.5"),
        (12.5, "12.5"),
        (-12.5, "-12.5"),
        (123.456, "123.456"),
        (-123.456, "-123.456"),
        (1234.5678, "1234.5678"),
        (-1234.5678, "-1234.5678"),
        (100.0, "100"),
        (-100.0, "-100"),
        (1000.0, "1000"),
        (-1000.0, "-1000"),
        (1200.0, "1200"),
        (-1200.0, "-1200"),
        (120000.0, "120000"),
        (-120000.0, "-120000"),
        (100000.0, "100000"),
        (-100000.0, "-100000"),
        (1000000.0, "1000000"),
        (-1000000.0, "-1000000"),
        (10000000000.0, "10000000000"),
        (-10000000000.0, "-10000000000"),
        (1000000000000000.0, "1000000000000000"),
        (-1000000000000000.0, "-1000000000000000"),
        (1200000000000000.0, "1200000000000000"),
        (-1200000000000000.0, "-1200000000000000"),
        (123456789012345.0, "123456789012345"),
        (-123456789012345.0, "-123456789012345"),
        (10000000000000000.0, "10000000000000000"),
        (-10000000000000000.0, "-10000000000000000"),
        (15000000000000000.0, "15000000000000000"),
        (-15000000000000000.0, "-15000000000000000"),
        (100000000000000000.0, "100000000000000000"),
        (-100000000000000000.0, "-100000000000000000"),
        (100000000000000000000.0, "100000000000000000000"),
        (-100000000000000000000.0, "-100000000000000000000"),
        (123000000000000000000.0, "123000000000000000000"),
        (-123000000000000000000.0, "-123000000000000000000"),
        (0.000025, "0.000025"),
        (-0.000025, "-0.000025"),
        (0.0000999, "0.0000999"),
        (-0.0000999, "-0.0000999"),
        (0.1, "0.1"),
        (-0.1, "-0.1"),
        (0.2, "0.2"),
        (-0.2, "-0.2"),
        (0.3, "0.3"),
        (-0.3, "-0.3"),
        (0.7, "0.7"),
        (-0.7, "-0.7"),
        (0.3333333333333333, "0.3333333333333333"),
        (-0.3333333333333333, "-0.3333333333333333"),
        (0.6666666666666666, "0.6666666666666666"),
        (-0.6666666666666666, "-0.6666666666666666"),
        (3.3333333333333335, "3.3333333333333335"),
        (-3.3333333333333335, "-3.3333333333333335"),
        (33.333333333333336, "33.333333333333336"),
        (-33.333333333333336, "-33.333333333333336"),
        (1000000000000000000.0, "1000000000000000000"),
        (-1000000000000000000.0, "-1000000000000000000"),
        (0.000001, "0.000001"),
        (-0.000001, "-0.000001"),
        (0.0000011, "0.0000011"),
        (-0.0000011, "-0.0000011"),
        (4.35, "4.35"),
        (-4.35, "-4.35"),
        (0.0000123456789, "0.0000123456789"),
        (-0.0000123456789, "-0.0000123456789"),
        (98765.4321, "98765.4321"),
        (-98765.4321, "-98765.4321"),
        (3.14159, "3.14159"),
        (-3.14159, "-3.14159"),
        (2.718281828459045, "2.718281828459045"),
        (-2.718281828459045, "-2.718281828459045"),
        (179769313486231568384.0, "179769313486231570000"),
        (-179769313486231568384.0, "-179769313486231570000"),
        (12345678901234567168.0, "12345678901234567000"),
        (-12345678901234567168.0, "-12345678901234567000"),
        (0.8999999999999999, "0.8999999999999999"),
        (-0.8999999999999999, "-0.8999999999999999"),
        (1.2100000000000002, "1.2100000000000002"),
        (-1.2100000000000002, "-1.2100000000000002"),
        (4503599627370497.0, "4503599627370497"),
        (-4503599627370497.0, "-4503599627370497"),
        (4503599627370495.5, "4503599627370495.5"),
        (-4503599627370495.5, "-4503599627370495.5"),
        (9007199254740992.0, "9007199254740992"),
        (-9007199254740992.0, "-9007199254740992"),
        (18014398509481984.0, "18014398509481984"),
        (-18014398509481984.0, "-18014398509481984"),
        (500000000000000000.0, "500000000000000000"),
        (-500000000000000000.0, "-500000000000000000"),
        (7500000000000000000.0, "7500000000000000000"),
        (-7500000000000000000.0, "-7500000000000000000"),
        (123456788999999995904.0, "123456789000000000000"),
        (-123456788999999995904.0, "-123456789000000000000"),
        (0.00000123, "0.00000123"),
        (-0.00000123, "-0.00000123"),
        (0.000003, "0.000003"),
        (-0.000003, "-0.000003"),
        (0.0000085, "0.0000085"),
        (-0.0000085, "-0.0000085"),
        (10.0, "10"),
        (-10.0, "-10"),
        (120.0, "120"),
        (-120.0, "-120"),
        (0.01, "0.01"),
        (-0.01, "-0.01"),
        (0.015, "0.015"),
        (-0.015, "-0.015"),
        (10.5, "10.5"),
        (-10.5, "-10.5"),
        (0.001, "0.001"),
        (-0.001, "-0.001"),
        (0.0015, "0.0015"),
        (-0.0015, "-0.0015"),
        (100.5, "100.5"),
        (-100.5, "-100.5"),
        (12000.0, "12000"),
        (-12000.0, "-12000"),
        (0.0001, "0.0001"),
        (-0.0001, "-0.0001"),
        (0.00015, "0.00015"),
        (-0.00015, "-0.00015"),
        (1000.5, "1000.5"),
        (-1000.5, "-1000.5"),
        (10000.0, "10000"),
        (-10000.0, "-10000"),
        (0.000015, "0.000015"),
        (-0.000015, "-0.000015"),
        (10000.5, "10000.5"),
        (-10000.5, "-10000.5"),
        (1200000.0, "1200000"),
        (-1200000.0, "-1200000"),
        (0.0000015, "0.0000015"),
        (-0.0000015, "-0.0000015"),
        (100000.5, "100000.5"),
        (-100000.5, "-100000.5"),
        (12000000.0, "12000000"),
        (-12000000.0, "-12000000"),
        (1000000.5, "1000000.5"),
        (-1000000.5, "-1000000.5"),
        (10000000.0, "10000000"),
        (-10000000.0, "-10000000"),
        (120000000.0, "120000000"),
        (-120000000.0, "-120000000"),
        (10000000.5, "10000000.5"),
        (-10000000.5, "-10000000.5"),
        (100000000.0, "100000000"),
        (-100000000.0, "-100000000"),
        (1200000000.0, "1200000000"),
        (-1200000000.0, "-1200000000"),
        (100000000.5, "100000000.5"),
        (-100000000.5, "-100000000.5"),
        (1000000000.0, "1000000000"),
        (-1000000000.0, "-1000000000"),
        (12000000000.0, "12000000000"),
        (-12000000000.0, "-12000000000"),
        (1000000000.5, "1000000000.5"),
        (-1000000000.5, "-1000000000.5"),
        (120000000000.0, "120000000000"),
        (-120000000000.0, "-120000000000"),
        (10000000000.5, "10000000000.5"),
        (-10000000000.5, "-10000000000.5"),
        (100000000000.0, "100000000000"),
        (-100000000000.0, "-100000000000"),
        (1200000000000.0, "1200000000000"),
        (-1200000000000.0, "-1200000000000"),
        (100000000000.5, "100000000000.5"),
        (-100000000000.5, "-100000000000.5"),
        (1000000000000.0, "1000000000000"),
        (-1000000000000.0, "-1000000000000"),
        (12000000000000.0, "12000000000000"),
        (-12000000000000.0, "-12000000000000"),
        (1000000000000.5, "1000000000000.5"),
        (-1000000000000.5, "-1000000000000.5"),
        (10000000000000.0, "10000000000000"),
        (-10000000000000.0, "-10000000000000"),
        (120000000000000.0, "120000000000000"),
        (-120000000000000.0, "-120000000000000"),
        (10000000000000.5, "10000000000000.5"),
        (-10000000000000.5, "-10000000000000.5"),
        (100000000000000.0, "100000000000000"),
        (-100000000000000.0, "-100000000000000"),
        (100000000000000.5, "100000000000000.5"),
        (-100000000000000.5, "-100000000000000.5"),
        (12000000000000000.0, "12000000000000000"),
        (-12000000000000000.0, "-12000000000000000"),
        (1000000000000000.5, "1000000000000000.5"),
        (-1000000000000000.5, "-1000000000000000.5"),
        (120000000000000000.0, "120000000000000000"),
        (-120000000000000000.0, "-120000000000000000"),
        (1200000000000000000.0, "1200000000000000000"),
        (-1200000000000000000.0, "-1200000000000000000"),
        (12000000000000000000.0, "12000000000000000000"),
        (-12000000000000000000.0, "-12000000000000000000"),
        (10000000000000000000.0, "10000000000000000000"),
        (-10000000000000000000.0, "-10000000000000000000"),
        (120000000000000000000.0, "120000000000000000000"),
        (-120000000000000000000.0, "-120000000000000000000"),
    ]

    func testNumberStringMatchesEcmaScript() {
        XCTAssertGreaterThan(Self.numbers.count, 200)
        for (d, s) in Self.numbers {
            XCTAssertEqual(Canonical.numberString(d), s, "numberString(\(d))")
            XCTAssertEqual(Canonical.canonicalize(.double(d)), s, "canonicalize(\(d))")
        }
        XCTAssertEqual(Canonical.numberString(0.0), "0")
        XCTAssertEqual(Canonical.numberString(-0.0), "0")
    }

    private func err(_ text: String, lenient: Bool = false) -> String? {
        do { _ = lenient ? try StrictJSON.parseLenient(text) : try StrictJSON.parse(text); return nil } catch let e as StrictJSON.ParseError { return e.message } catch { return "\(error)" }
    }
    private func ok(_ text: String, lenient: Bool = false) -> JSONValue? { lenient ? try? StrictJSON.parseLenient(text) : try? StrictJSON.parse(text) }

    // ---- hex digits of \u escapes ----

    func testEveryHexDigitOfAnEscape() {
        let digits = Array("0123456789abcdefABCDEF")
        for (i, c) in digits.enumerated() {
            let v = i < 10 ? i : (i < 16 ? i : i - 6)
            // "\u00X0" -> the scalar X0 (a hex digit in the third position) and "\u000X" -> X in the last position
            let a = ok("\"\\u00\(c)0\"")
            XCTAssertEqual(a, .string(String(Unicode.Scalar(UInt32(v * 16))!)), "third digit \(c)")
            let b = ok("\"\\u000\(c)\"")
            XCTAssertEqual(b, .string(String(Unicode.Scalar(UInt32(v))!)), "last digit \(c)")
            let c2 = ok("\"\\u0\(c)00\"")
            XCTAssertEqual(c2, .string(String(Unicode.Scalar(UInt32(v * 256))!)), "second digit \(c)")
        }
        XCTAssertEqual(ok("\"\\u00fA\""), .string("\u{fa}"))
        XCTAssertEqual(ok("\"\\u00Af\""), .string("\u{af}"))
        for bad in ["g", "G", "/", ":", "@", "`", " ", "-", "x"] {
            XCTAssertEqual(err("\"\\u000\(bad)\""), "strict JSON: bad \\u escape (at offset 2)", "digit \(bad)")
            XCTAssertEqual(err("\"\\u0\(bad)00\""), "strict JSON: bad \\u escape (at offset 2)", "digit \(bad)")
        }
    }

    func testEscapeBoundariesAndSurrogates() {
        XCTAssertEqual(err("\"\\u004"), "strict JSON: bad \\u escape (at offset 2)")
        XCTAssertEqual(err("\"\\u00"), "strict JSON: bad \\u escape (at offset 2)")
        XCTAssertEqual(err("\"\\u"), "strict JSON: bad \\u escape (at offset 2)")
        XCTAssertEqual(err("\"\\u0041"), "strict JSON: unterminated string (at offset 7)")
        XCTAssertEqual(ok("\"\\u0041\""), .string("A"))
        // surrogate pairs and the exact lone-surrogate boundaries
        XCTAssertEqual(ok("\"\\ud83d\\ude00\""), .string("\u{1F600}"))
        XCTAssertEqual(ok("\"\\ud800\\udc00\""), .string("\u{10000}"))
        XCTAssertEqual(ok("\"\\udbff\\udfff\""), .string("\u{10FFFF}"))
        XCTAssertEqual(ok("\"\\uD83D\\uDE00\""), .string("\u{1F600}"))
        XCTAssertEqual(ok("\"\\ud801\\udc37\""), .string("\u{10437}"))
        XCTAssertEqual(err("\"\\ud800\""), "strict JSON: lone surrogate in string (at offset 6)")
        XCTAssertEqual(err("\"\\ud800"), "strict JSON: lone surrogate in string (at offset 6)")
        XCTAssertEqual(err("\"\\ud800\\"), "strict JSON: lone surrogate in string (at offset 6)")
        XCTAssertEqual(err("\"\\ud800\\u"), "strict JSON: bad \\u escape (at offset 8)")
        XCTAssertEqual(err("\"\\ud800\\u0041\""), "strict JSON: lone surrogate in string (at offset 12)")
        XCTAssertEqual(err("\"\\ud800\\ud800\""), "strict JSON: lone surrogate in string (at offset 12)")
        XCTAssertEqual(err("\"\\ud800x\""), "strict JSON: lone surrogate in string (at offset 6)")
        XCTAssertEqual(err("\"\\udc00\""), "strict JSON: lone surrogate in string (at offset 6)")
        XCTAssertEqual(err("\"\\udfff\\ud800\""), "strict JSON: lone surrogate in string (at offset 6)")
        // the simple escapes
        XCTAssertEqual(ok("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\""), .string("\"\\/\u{8}\u{c}\n\r\t"))
        XCTAssertEqual(err("\"\\q\""), "strict JSON: unknown escape (at offset 2)")
        XCTAssertEqual(err("\"\\"), "strict JSON: unterminated string (at offset 2)")
        XCTAssertEqual(err("\"abc"), "strict JSON: unterminated string (at offset 4)")
        XCTAssertEqual(err("\"\u{1f}\""), "strict JSON: raw control character in string (at offset 1)")
        XCTAssertNotNil(ok("\"\u{20}\""))
    }

    // ---- literals, whitespace, end of input ----

    func testLiteralsAdvanceExactly() {
        for lenient in [false, true] {
            XCTAssertEqual(ok("[true]", lenient: lenient), .array([.bool(true)]))
            XCTAssertEqual(ok("[false]", lenient: lenient), .array([.bool(false)]))
            XCTAssertEqual(ok("[null]", lenient: lenient), .array([.null]))
            XCTAssertEqual(ok("[true,false,null]", lenient: lenient), .array([.bool(true), .bool(false), .null]))
            XCTAssertEqual(ok("{\"a\":false,\"b\":true}", lenient: lenient), .object([JKey("a"): .bool(false), JKey("b"): .bool(true)]))
            XCTAssertEqual(err("fals", lenient: lenient), "strict JSON: unexpected token (at offset 0)")
            XCTAssertEqual(err("tru", lenient: lenient), "strict JSON: unexpected token (at offset 0)")
            XCTAssertEqual(err("nul", lenient: lenient), "strict JSON: unexpected token (at offset 0)")
            XCTAssertEqual(err("falsey", lenient: lenient), "strict JSON: trailing characters after the JSON value (at offset 5)")
            XCTAssertEqual(err("truee", lenient: lenient), "strict JSON: trailing characters after the JSON value (at offset 4)")
            XCTAssertEqual(err("nulll", lenient: lenient), "strict JSON: trailing characters after the JSON value (at offset 4)")
            XCTAssertEqual(ok("false", lenient: lenient), .bool(false))
            XCTAssertEqual(ok("true", lenient: lenient), .bool(true))
            XCTAssertEqual(ok("null", lenient: lenient), .null)
            XCTAssertEqual(err("", lenient: lenient), "strict JSON: unexpected end of input (at offset 0)")
            XCTAssertEqual(err("   ", lenient: lenient), "strict JSON: unexpected end of input (at offset 3)")
            XCTAssertEqual(err("[", lenient: lenient), "strict JSON: unexpected end of input (at offset 1)")
            XCTAssertEqual(err("[1", lenient: lenient), "strict JSON: expected \",\" or \"]\" (at offset 2)")
            XCTAssertEqual(err("{", lenient: lenient), "strict JSON: expected a string key (at offset 1)")
            XCTAssertEqual(err("{\"a\"", lenient: lenient), "strict JSON: expected \":\" (at offset 4)")
            XCTAssertEqual(err("{\"a\":1", lenient: lenient), "strict JSON: expected \",\" or \"}\" (at offset 6)")
            XCTAssertEqual(err("{\"a\":1,\"a\":2}", lenient: lenient), "strict JSON: duplicate key (at offset 10)")
        }
    }

    func testWhitespaceIsExactlyTheJsonFour() {
        for lenient in [false, true] {
            for w in [" ", "\t", "\n", "\r", "  ", "   ", " \t\n\r", "\t\t\t"] {
                XCTAssertEqual(ok("\(w)[\(w)1\(w),\(w)2\(w)]\(w)", lenient: lenient), .array([.int(1), .int(2)]), "ws \(w.debugDescription)")
                XCTAssertEqual(ok("\(w){\(w)\"a\"\(w):\(w)1\(w)}\(w)", lenient: lenient), .object([JKey("a"): .int(1)]), "ws \(w.debugDescription)")
            }
            for w in ["\u{b}", "\u{c}", "\u{a0}", "\u{feff}", "\u{2028}"] {
                XCTAssertNotNil(err("\(w)1", lenient: lenient), "must refuse \(w.debugDescription)")
                XCTAssertNotNil(err("1\(w)", lenient: lenient), "must refuse trailing \(w.debugDescription)")
            }
        }
    }

    // ---- depth ----

    func testDepthBounds() {
        func nest(_ n: Int) -> String { String(repeating: "[", count: n) + String(repeating: "]", count: n) }
        func nestObj(_ n: Int) -> String { String(repeating: "{\"a\":", count: n - 1) + "{}" + String(repeating: "}", count: n - 1) }
        XCTAssertEqual(Canonical.MAX_JSON_DEPTH, 32)
        XCTAssertNil(err(nest(32)))
        XCTAssertEqual(err(nest(33)), "strict JSON: nesting too deep (at offset 32)")
        XCTAssertNil(err(nestObj(32)))
        XCTAssertNotNil(err(nestObj(33)))
        XCTAssertEqual(err(nest(40)), "strict JSON: nesting too deep (at offset 32)")
        XCTAssertNil(err(nest(1024), lenient: true))
        XCTAssertEqual(err(nest(1025), lenient: true), "strict JSON: nesting too deep (at offset 1024)")
        XCTAssertNil(err(nestObj(1024), lenient: true))
        XCTAssertNotNil(err(nestObj(1025), lenient: true))
    }

    // ---- numbers ----

    func testStrictNumbers() {
        XCTAssertEqual(ok("0"), .int(0))
        XCTAssertEqual(ok("-5"), .int(-5))
        XCTAssertEqual(ok("9007199254740991"), .int(9_007_199_254_740_991))
        XCTAssertEqual(ok("-9007199254740991"), .int(-9_007_199_254_740_991))
        XCTAssertEqual(err("9007199254740992"), "strict JSON: integer outside the safe range (at offset 16)")
        XCTAssertEqual(err("12345678901234567"), "strict JSON: integer outside the safe range (at offset 17)")
        XCTAssertEqual(err("123456789012345678901"), "strict JSON: integer outside the safe range (at offset 21)")
        XCTAssertEqual(ok("1.5"), .double(1.5))
        XCTAssertEqual(ok("-1.5"), .double(-1.5))
        XCTAssertEqual(ok("0.5"), .double(0.5))
        XCTAssertEqual(ok("0.000001"), .double(0.000001))
        XCTAssertEqual(ok("123456789012.345"), .double(123456789012.345))
        XCTAssertEqual(err("-0"), "strict JSON: negative zero is not allowed (at offset 2)")
        XCTAssertEqual(err("1.50"), "strict JSON: trailing fractional zero is not canonical (at offset 4)")
        XCTAssertEqual(err("1.0"), "strict JSON: trailing fractional zero is not canonical (at offset 3)")
        XCTAssertEqual(err("0.0000001"), "strict JSON: non-integer magnitude below 1e-6 is not allowed (at offset 9)")
        XCTAssertEqual(err("1.234567890123456"), "strict JSON: more than 15 significant digits (at offset 17)")
        XCTAssertNil(err("1.2345678901234"))
        XCTAssertNil(err("0.0123456789012345"))
        XCTAssertEqual(err("1e5"), "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 1)")
        XCTAssertEqual(err("1E5"), "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 1)")
        XCTAssertEqual(err("1.5e3"), "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 3)")
        XCTAssertEqual(err("01"), "strict JSON: trailing characters after the JSON value (at offset 1)")
        XCTAssertEqual(err("-"), "strict JSON: bad number (at offset 1)")
        XCTAssertEqual(err("-a"), "strict JSON: bad number (at offset 1)")
        XCTAssertEqual(err("1."), "strict JSON: bad number (at offset 2)")
        XCTAssertEqual(err("1.x"), "strict JSON: bad number (at offset 2)")
        XCTAssertEqual(ok("[0,1]"), .array([.int(0), .int(1)]))
    }

    func testLenientNumbers() {
        XCTAssertEqual(ok("5", lenient: true), .int(5))
        XCTAssertEqual(ok("-5", lenient: true), .int(-5))
        XCTAssertEqual(ok("0", lenient: true), .int(0))
        XCTAssertEqual(ok("123456", lenient: true), .int(123_456))
        XCTAssertEqual(ok("9223372036854775807", lenient: true), .int(Int64.max))
        XCTAssertEqual(ok("9223372036854775808", lenient: true), .double(9_223_372_036_854_775_808.0))
        if case let .double(d)? = ok("-0", lenient: true) { XCTAssertTrue(d == 0 && d.sign == .minus) } else { XCTFail("-0 must stay a double with its sign") }
        XCTAssertEqual(ok("1.5", lenient: true), .double(1.5))
        XCTAssertEqual(ok("-1.5", lenient: true), .double(-1.5))
        XCTAssertEqual(ok("12.75", lenient: true), .double(12.75))
        XCTAssertEqual(ok("1e5", lenient: true), .double(100_000))
        XCTAssertEqual(ok("1E5", lenient: true), .double(100_000))
        XCTAssertEqual(ok("1e+5", lenient: true), .double(100_000))
        XCTAssertEqual(ok("1e-5", lenient: true), .double(0.00001))
        XCTAssertEqual(ok("-1.5e+2", lenient: true), .double(-150))
        XCTAssertEqual(ok("1.25e10", lenient: true), .double(12_500_000_000))
        XCTAssertEqual(ok("1e123", lenient: true), .double(1e123))
        XCTAssertEqual(ok("[1,2.5,-3,4e2]", lenient: true), .array([.int(1), .double(2.5), .int(-3), .double(400)]))
        XCTAssertNotNil(err("1e", lenient: true))
        XCTAssertNotNil(err("1e+", lenient: true))
        XCTAssertNotNil(err("-", lenient: true))
    }
}
