import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Exact-behaviour tests for the strict / lenient JSON layers (canonical numbers, size and depth caps, truncated
/// escapes, the lenient corpus loader). Each one pins a branch that the shared corpus does not decide on its own.
final class StrictJSONKillTests: XCTestCase {
    private func nestArrays(_ n: Int) -> JSONValue {
        var v = JSONValue.array([])
        for _ in 1..<n { v = .array([v]) }
        return v
    }
    private func nestObjects(_ n: Int) -> JSONValue {
        var v = JSONValue.object([:])
        for _ in 1..<n { v = .object([JKey("a"): v]) }
        return v
    }
    private func parseError(_ text: String, lenient: Bool = false) -> String? {
        do { _ = lenient ? try StrictJSON.parseLenient(text) : try StrictJSON.parse(text); return nil } catch let e as StrictJSON.ParseError { return e.message } catch { return "\(error)" }
    }
    private func strictError(_ v: JSONValue) -> String? {
        do { _ = try Canonical.canonicalizeStrict(v); return nil } catch let e as Canonical.CanonicalError { return e.message } catch { return "\(error)" }
    }

    // ---- size cap: exactly 2^20 UTF-8 bytes parse, one more is refused before parsing ----
    func testStrictParseSizeCapBoundary() {
        XCTAssertEqual(Canonical.MAX_JSON_BYTES, 1_048_576)
        let lit = { (n: Int) in "\"" + String(repeating: "a", count: n - 2) + "\"" }
        XCTAssertNil(parseError(lit(1_048_576)))
        XCTAssertEqual(parseError(lit(1_048_577)), "strict JSON: input too large")
    }

    // ---- strict number profile ----
    func testStrictCanonicalNumbers() {
        XCTAssertEqual(strictError(.double(-0.0)), "canonicalize: negative zero")
        XCTAssertEqual(try Canonical.canonicalizeStrict(.double(-1.5)), "-1.5")
        XCTAssertEqual(try Canonical.canonicalizeStrict(.double(9_007_199_254_740_991.0)), "9007199254740991")
        XCTAssertEqual(strictError(.double(9_007_199_254_740_992.0)), "canonicalize: integer outside the safe range")
        XCTAssertEqual(strictError(.double(-9_007_199_254_740_992.0)), "canonicalize: integer outside the safe range")
        XCTAssertEqual(strictError(.int(Int64.max)), "canonicalize: integer outside the safe range")
    }

    /// Lenient canonical numbers equal ECMAScript `String(x)` (shortest round-trip, plain decimal) for |x| < 1e21.
    func testLenientNumberStrings() {
        let cases: [(Double, String)] = [
            (0.0, "0"), (1.0, "1"), (-1.0, "-1"), (0.5, "0.5"), (-0.5, "-0.5"), (0.05, "0.05"), (2.5e-5, "0.000025"),
            (123456789012.5, "123456789012.5"),
            (9_007_199_254_740_992.0, "9007199254740992"), (9_007_199_254_740_994.0, "9007199254740994"),
            (-9_007_199_254_740_994.0, "-9007199254740994"),
            (18_014_398_509_481_984.0, "18014398509481984"), (36_028_797_018_963_968.0, "36028797018963970"),
            (1e16, "10000000000000000"), (1.5e20, "150000000000000000000"), (1152921504606846976.0, "1152921504606847000"),
        ]
        for (d, s) in cases {
            XCTAssertEqual(Canonical.canonicalize(.double(d)), s, "\(d)")
            XCTAssertEqual(Canonical.numberString(d), s, "\(d)")
        }
        // the lenient form does not apply the strict profile
        XCTAssertEqual(Canonical.canonicalize(.int(Int64.max)), "9223372036854775807")
        XCTAssertEqual(Canonical.canonicalize(.array([.double(0.1 + 0.2)])), "[0.30000000000000004]")
        // out-of-profile lenient input is "" (never a shared truncated prefix)
        XCTAssertEqual(Canonical.canonicalize(.array([.int(1), .double(.nan)])), "")
        XCTAssertEqual(Canonical.canonicalize(.array([.int(1), .double(.infinity)])), "")
    }

    // ---- depth caps (TS MAX_JSON_DEPTH = 32 on every strict path; 1024 on the lenient ones) ----
    func testStrictCanonicalDepthCap() {
        for (n, ok) in [(31, true), (32, true), (33, false)] {
            XCTAssertEqual(strictError(nestArrays(n)) == nil, ok, "arrays \(n)")
            XCTAssertEqual(strictError(nestObjects(n)) == nil, ok, "objects \(n)")
        }
        XCTAssertEqual(strictError(nestObjects(33)), "canonicalize: nesting too deep")
        XCTAssertEqual(strictError(nestArrays(33)), "canonicalize: nesting too deep")
    }

    func testLenientCanonicalDepthCap() {
        XCTAssertEqual(Canonical.MAX_LENIENT_DEPTH, 1024)
        for (n, ok) in [(1023, true), (1024, true), (1025, false)] {
            let a = Canonical.canonicalize(nestArrays(n))
            XCTAssertEqual(a == String(repeating: "[", count: n) + String(repeating: "]", count: n), ok, "arrays \(n)")
            XCTAssertEqual(a.isEmpty, !ok, "arrays \(n)")
            let o = Canonical.canonicalize(nestObjects(n))
            XCTAssertEqual(o == String(repeating: "{\"a\":", count: n - 1) + "{}" + String(repeating: "}", count: n - 1), ok, "objects \(n)")
            XCTAssertEqual(o.isEmpty, !ok, "objects \(n)")
        }
    }

    func testStrictParseDepthCap() {
        let arr = { (n: Int) in String(repeating: "[", count: n) + String(repeating: "]", count: n) }
        let obj = { (n: Int) in String(repeating: "{\"a\":", count: n) + "1" + String(repeating: "}", count: n) }
        for (n, ok) in [(31, true), (32, true), (33, false), (100_000, false)] {
            let ea = parseError(arr(n)), eo = parseError(obj(n))
            XCTAssertEqual(ea == nil, ok, "arrays \(n)")
            XCTAssertEqual(eo == nil, ok, "objects \(n)")
            if !ok {
                XCTAssertTrue(ea?.hasPrefix("strict JSON: nesting too deep") ?? false, ea ?? "")
                XCTAssertTrue(eo?.hasPrefix("strict JSON: nesting too deep") ?? false, eo ?? "")
            }
        }
        // the public entry point: a 100000-deep document is a clean wire deny (no stack overflow)
        let v = PCA.verify(json: arr(100_000), grant: .object([:]), now: 0, audience: "a")
        XCTAssertFalse(v.allow)
        XCTAssertEqual(v.checks, ["wire": false])
        XCTAssertTrue(v.reason.contains("nesting too deep"), v.reason)
    }

    func testLenientParseDepthCap() {
        let arr = { (n: Int) in String(repeating: "[", count: n) + String(repeating: "]", count: n) }
        for (n, ok) in [(1023, true), (1024, true), (1025, false), (100_000, false)] {
            let e = parseError(arr(n), lenient: true)
            XCTAssertEqual(e == nil, ok, "\(n)")
            if !ok { XCTAssertTrue(e?.hasPrefix("strict JSON: nesting too deep") ?? false, e ?? "") }
        }
    }

    // ---- truncated \u escapes at the very end of the input: clean errors, never an out-of-range read ----
    func testTruncatedUnicodeEscapes() {
        XCTAssertTrue(parseError("\"\\u004")?.hasPrefix("strict JSON: bad \\u escape") ?? false)
        XCTAssertTrue(parseError("\"\\u0041")?.hasPrefix("strict JSON: unterminated string") ?? false)
        XCTAssertTrue(parseError("\"\\uD83D")?.hasPrefix("strict JSON: lone surrogate in string") ?? false)
        XCTAssertTrue(parseError("\"\\uD83D\\")?.hasPrefix("strict JSON: lone surrogate in string") ?? false)
        XCTAssertTrue(parseError("\"\\uD83D\\u")?.hasPrefix("strict JSON: bad \\u escape") ?? false)
        XCTAssertTrue(parseError("\"\\uD83D\\uDE0")?.hasPrefix("strict JSON: bad \\u escape") ?? false)
        XCTAssertEqual(try StrictJSON.parse("\"\\uD83D\\uDE00\""), .string("\u{1F600}"))
        XCTAssertEqual(try StrictJSON.parse("\"\\u0041\""), .string("A"))
    }

    func testExponentRefusedWithItsOwnReason() {
        for t in ["1e5", "1E5", "[1.5e1]", "[2E-3]"] {
            XCTAssertTrue(parseError(t)?.hasPrefix("strict JSON: exponent form is not allowed") ?? false, t)
        }
    }

    /// The lenient corpus loader keeps integer lexemes as .int and everything with a fraction / exponent as .double.
    func testLenientNumberClassification() throws {
        XCTAssertEqual(try StrictJSON.parseLenient("[5,-12,0,1.5,-1.5,1e5,-2E-3,2.0,9223372036854775807]"),
                       .array([.int(5), .int(-12), .int(0), .double(1.5), .double(-1.5), .double(1e5), .double(-0.002), .double(2.0), .int(Int64.max)]))
        XCTAssertEqual(try StrictJSON.parseLenient("9223372036854775808"), .double(9_223_372_036_854_775_808.0))
    }
}
