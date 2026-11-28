import XCTest
@testable import AtlasPCAVerify

/// `IV.jsNumber` pinned to JS `Number(string)` (ECMA-262 StringNumericLiteral), and every caller of it.
final class IntentValuesJsNumberTests: XCTestCase {
    func testFormsJSRefuse() {
        for s in ["+-Infinity", "-+Infinity", "+0x1", "-0x1", "0x+1", "0x-1", "0x1_0", "0x 1", "0x", "0b2", "0o8", "1_000", "\u{661}", "\u{FF11}",
                  "infinity", "INFINITY", "nan", "NaN", "1e", ".", "+", "1f", "1d", "1L",
                  // what a bare Double(String) takes or a sloppy scan would
                  "inf", "Inf", "-inf", "nan(1)", "0x1p3", "0x1.8", "+0x1p0", "0X", "0o", "0O", "0b", "0B", "+0b1", "-0o7", "+Infinityx", "Infinity1", "-",
                  "e1", ".e1", "+.", "1e+", "1e-", "1e1.5", "1.5.5", "1 2", "1\u{0}", "\u{85}1", "\u{180E}1", "/", ":", "0x/", "0x:", "0xg", "0xG", "0o/", "0b/", "0o:"] {
            XCTAssertTrue(IV.jsNumber(s).isNaN, s)
        }
    }

    func testFormsJSParse() {
        let table: [(String, Double)] = [
            ("", 0), (" ", 0), ("\t\n\u{0B}\u{0C}\r ", 0), ("\u{FEFF}", 0), ("\u{A0}", 0), (" 12 ", 12), ("\u{FEFF}12\u{A0}", 12), ("\u{2003}1\u{3000}", 1),
            ("Infinity", .infinity), ("+Infinity", .infinity), ("-Infinity", -.infinity), (" Infinity ", .infinity),
            ("0x10", 16), ("0X1f", 31), ("0XAF", 175), ("0xaf", 175), ("0o7", 7), ("0O17", 15), ("0b1", 1), ("0B101", 5), ("0x0", 0), ("0b0", 0), ("0o0", 0), ("0b1000", 8), ("0x00ff", 255),
            ("1.", 1), (".5", 0.5), ("1e3", 1000), ("1E3", 1000), ("1e+3", 1000), ("1e-3", 0.001), ("+1.5", 1.5), ("-1.5", -1.5), ("0", 0), ("09", 9), ("0.5", 0.5), (".5e1", 5), ("1.e1", 10),
            ("1e400", .infinity), ("-1e400", -.infinity), ("1e-400", 0),
            ("0x" + String(repeating: "f", count: 300), .infinity), ("0b" + String(repeating: "1", count: 1100), .infinity),
            // above 2^53: rounded, not accumulated (2^53 + 1 is a tie to even, 2^53 + 3 rounds up)
            ("0x20000000000001", 9_007_199_254_740_992), ("0x20000000000003", 9_007_199_254_740_996),
            ("0o400000000000000001", 9_007_199_254_740_992), ("0b1" + String(repeating: "0", count: 52) + "1", 9_007_199_254_740_992),
        ]
        for (s, want) in table { XCTAssertEqual(IV.jsNumber(s), want, s) }
        XCTAssertEqual(IV.jsNumber("-0"), 0)
        XCTAssertEqual(IV.jsNumber("-0").sign, .minus)
        XCTAssertEqual(IV.jsNumber("0").sign, .plus)
    }

    func testNvidiaNumberFollowsJS() {
        for s in ["+0x1", "0x1p3", "nan", "inf", "x"] {
            XCTAssertFalse(Nvidia.jsNumberFromString(s).1, s)
            XCTAssertEqual(Nvidia.jsNumberFromString(s).0, 0, s)
        }
        let table: [(String, Double)] = [("0b1", 1), ("0o7", 7), ("0x10", 16), ("", 0), (" 3 ", 3), ("Infinity", .infinity)]
        for (s, want) in table {
            XCTAssertTrue(Nvidia.jsNumberFromString(s).1, s)
            XCTAssertEqual(Nvidia.jsNumberFromString(s).0, want, s)
        }
    }

    func testPendingStateFollowsJS() {
        let m: JObject = ["kind": .string("responds_within"), "within": .int(2), "p": .object(["verb": .string("a"), "resource": .string("*")]),
                          "q": .object(["verb": .string("b"), "resource": .string("*")])]
        let ev: JObject = ["verb": .string("x"), "resource": .string("r"), "params": .object([:]), "status": .string("committed")]
        XCTAssertEqual(IntentHistory.monitorStep(m, "pending:", ev), "missed") // Number("") === 0
        XCTAssertEqual(IntentHistory.monitorStep(m, "pending:0x3", ev), "pending:2")
    }

    func testCompareVersionFollowsJS() {
        XCTAssertEqual(K3.compareVersion("0x10", "16"), 0)
        XCTAssertEqual(K3.compareVersion("1e1", "10"), 0)
        XCTAssertEqual(K3.compareVersion("", "0"), 0)
    }

    /// The verb-floor forgery of the Python sweep: a floor that is a string never satisfies the order here (no coercion at all).
    func testStringFloorsNeverSatisfyLeq() throws {
        func q(_ risk: JSONValue) -> JSONValue {
            .object(["risk": risk, "rev": .string("irreversible"), "blast_ppm": .int(0), "esc": .int(0), "caveats": .array([]), "context": .array([]), "prules": .array([])])
        }
        XCTAssertTrue(try Actions.jsLeq(Profile(), q(.int(0))))
        for s in ["+-Infinity", "-+Infinity", "0x1", "Infinity", "1", ""] { XCTAssertFalse(try Actions.jsLeq(Profile(), q(.string(s))), s) }
    }
}
