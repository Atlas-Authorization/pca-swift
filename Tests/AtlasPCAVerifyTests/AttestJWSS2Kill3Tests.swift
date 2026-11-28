import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The wording of V8's JSON.parse failures (JsonParser::ReportUnexpectedToken, kMaxContextCharacters = 10, kMinOriginalSourceLengthForContext = 21)
/// and the JWK curve name. Every expected string is written from the V8 rules, not read back from the code under test.
final class S2G3JwsKillTests: XCTestCase {
    func err(_ s: String) -> String { V8JSON.error(s) }

    func at(_ s: String, _ pos: Int) -> String { " in JSON at position \(pos) (line 1 column \(pos + 1))" }

    func sub(_ s: String, _ a: Int, _ b: Int) -> String { String(Array(s)[a..<b]) }

    // ---- the context window of an unexpected token ----

    func doc(_ pos: Int, _ n: Int) -> String { String(repeating: " ", count: pos) + "x" + String(repeating: "y", count: n - pos - 1) }

    func testUnexpectedTokenContextWindow() {
        let head = "Unexpected token 'x', "
        // (pos, n, kind): below 21 characters the whole text, then the three windows
        let cases: [(Int, Int, String)] = [
            (0, 19, "whole"), (0, 20, "whole"), (0, 21, "head"), (0, 22, "head"), (9, 30, "head"), (10, 30, "mid"), (19, 30, "mid"),
            (11, 21, "tail"), (20, 30, "tail"), (29, 30, "tail"),
        ]
        for (pos, n, kind) in cases {
            let d = doc(pos, n)
            let want: String
            switch kind {
            case "whole": want = head + "\"" + d + "\" is not valid JSON"
            case "head": want = head + "\"" + sub(d, 0, pos + 10) + "\"... is not valid JSON"
            case "mid": want = head + "...\"" + sub(d, pos - 10, pos + 10) + "\"... is not valid JSON"
            default: want = head + "...\"" + sub(d, pos - 10, n) + "\" is not valid JSON"
            }
            XCTAssertEqual(err(d), want, "pos \(pos) of \(n) (\(kind))")
        }
    }

    func testWholeTextSpecialCases() {
        for w in ["NaN", "Infinity", "undefined", "[object Object]"] { XCTAssertEqual(err(w), "\"\(w)\" is not valid JSON", w) }
    }

    func testNulIsAnUnexpectedTokenNotTheEnd() {
        XCTAssertEqual(err("\u{0}"), "Unexpected token '\u{0}', \"\u{0}\" is not valid JSON")
        XCTAssertEqual(err("\"\u{0}\""), "Bad control character in string literal" + at("", 1))
    }

    // ---- numbers ----

    func testValidNumbers() {
        for d in ["0", "9", "10", "90", "-0", "1.5", "1.55", "[1.5]", "[1.55]", "1e5", "1E5", "1e+5", "1e-5", "1.5e3", "[1e5]", "[1e+5]", "[1e55]", "[0,9]"] {
            XCTAssertEqual(err(d), "", d)
        }
    }

    func testNumberFailures() {
        XCTAssertEqual(err("01"), "Unexpected number" + at("", 1))
        XCTAssertEqual(err("1."), "Unterminated fractional number" + at("", 2))
        XCTAssertEqual(err("1e"), "Exponent part is missing a number" + at("", 2))
        XCTAssertEqual(err("1e+"), "Exponent part is missing a number" + at("", 3))
    }

    // ---- literals ----

    func testTruncatedLiteralsEndTheInput() {
        for d in ["tru", "fals", "nul", "t"] { XCTAssertEqual(err(d), "Unexpected end of JSON input", d) }
    }

    // ---- strings ----

    func testValidStrings() {
        for d in ["\"\"", "\" \"", "[\"a\"]", "\"\\\"\"", "\"\\n\"", "\"\\\\\"", "[\"\\n\"]"] { XCTAssertEqual(err(d), "", d) }
    }

    func testUnterminatedStrings() {
        XCTAssertEqual(err("\"abc"), "Unterminated string" + at("", 4))
        XCTAssertEqual(err("\"\\"), "Unterminated string" + at("", 2))
    }

    func testBadEscape() {
        XCTAssertEqual(err("\"\\x\""), "Bad escaped character" + at("", 2))
    }

    func testUnicodeEscapes() {
        for h in ["0", "9", "a", "f", "A", "F"] { XCTAssertEqual(err("\"\\u000" + h + "\""), "", h) }
        XCTAssertEqual(err("\"\\uaFAf\""), "")
        XCTAssertEqual(err("\"\\u0041\""), "")
        for bad in ["g", "G", "`", "@", "/", ":", "x"] { XCTAssertEqual(err("\"\\u000" + bad + "\""), "Bad Unicode escape" + at("", 6), bad) }
        XCTAssertEqual(err("\"\\u0ggg\""), "Bad Unicode escape" + at("", 4))
        XCTAssertEqual(err("\"\\u004g\""), "Bad Unicode escape" + at("", 6))
    }

    // ---- objects and arrays ----

    func testWhitespaceInsideContainers() {
        for d in ["{}", "[{},1]", "{\"a\":1 }", "{\"a\":1, \"b\":2}", "[ ]", "[1 ]", "[1 ,2]", "[ 1]"] { XCTAssertEqual(err(d), "", d) }
    }

    func testMissingSeparators() {
        XCTAssertEqual(err("{\"a\":1x}"), "Expected ',' or '}' after property value" + at("", 6))
        XCTAssertEqual(err("{\"a\":1 x}"), "Expected ',' or '}' after property value" + at("", 7))
        XCTAssertEqual(err("[1 x]"), "Expected ',' or ']' after array element" + at("", 3))
    }

    // ---- the JWK curve name ----

    func testEcJwkCarriesTheOpenSSLCurveName() throws {
        typealias C = AttestFailClosedTests
        let pt = C.h(C.P256_PT)
        let k = try JWS.jwkECKey("P-256", Base64URLStrict.encode(Array(pt[1..<33])), Base64URLStrict.encode(Array(pt[33..<65])))
        XCTAssertEqual(k.curve, "prime256v1")
        XCTAssertEqual(k.ecName, "P-256")
        let x = C.h("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66")
        let y = C.h("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")
        XCTAssertEqual(try JWS.jwkECKey("P-521", Base64URLStrict.encode(x), Base64URLStrict.encode(y)).curve, "secp521r1")
    }
}
