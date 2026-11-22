import XCTest
import Foundation
@testable import AtlasPCAVerify

private func a0Show(_ r: JSONValue?) -> String {
    switch r {
    case .int(let n)?: return "int \(n)"
    case .double(let d)?: return "double \(d)"
    case .string(let s)?: return "string \(s)"
    default: return "other"
    }
}

/// StrictParser.swift mutants that loop or allocate without bound. Each call runs under a deadline; the originals finish in
/// milliseconds. The string loop appends forever under its mutant, so it uses 1 s (before the memory watchdog).
final class A0DeadlineStrictParserTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testA1StringBodyAdvances() {
        let got: String? = S2Deadline.within(1, "strict string ab") { a0Show(try? StrictJSON.parse("\"ab\"")) }
        XCTAssertEqual(got, "string ab", "StrictParser.swift:115")
    }

    func testA2WhitespaceAdvances() {
        let got: String? = S2Deadline.within(10, "strict ws then 1") { a0Show(try? StrictJSON.parse(" \t\n\r1 ")) }
        XCTAssertEqual(got, "int 1", "StrictParser.swift:45")
    }

    func testA3StrictNumberDigitLoopsAdvance() {
        let integer: String? = S2Deadline.within(10, "strict 12") { a0Show(try? StrictJSON.parse("12")) }
        XCTAssertEqual(integer, "int 12", "StrictParser.swift:154")
        let frac: String? = S2Deadline.within(10, "strict 0.5") { a0Show(try? StrictJSON.parse("0.5")) }
        XCTAssertEqual(frac, "double 0.5", "StrictParser.swift:162 (leading 0 skips the line 154 loop)")
        let both: String? = S2Deadline.within(10, "strict 1.5") { a0Show(try? StrictJSON.parse("1.5")) }
        XCTAssertEqual(both, "double 1.5", "StrictParser.swift:154,162")
    }

    func testA4LenientNumberDigitLoopsAdvance() {
        let a: String? = S2Deadline.within(10, "lenient 12.5e+3") { a0Show(try? StrictJSON.parseLenient("12.5e+3")) }
        XCTAssertEqual(a, "double 12500.0", "StrictParser.swift:129,133,138")
        let b: String? = S2Deadline.within(10, "lenient .5") { a0Show(try? StrictJSON.parseLenient("0.5")) }
        XCTAssertEqual(b, "double 0.5", "StrictParser.swift:133 (the line 129 loop sees only the 0)")
        let c: String? = S2Deadline.within(10, "lenient 0e3") { a0Show(try? StrictJSON.parseLenient("0e3")) }
        XCTAssertEqual(c, "double 0.0", "StrictParser.swift:138")
    }
}
