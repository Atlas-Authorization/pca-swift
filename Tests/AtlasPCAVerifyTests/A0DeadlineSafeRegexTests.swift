import XCTest
import Foundation
@testable import AtlasPCAVerify

private func a0Match(_ src: String, _ subject: String) -> String {
    guard let re = SafeRegex.compile(Array(src.utf16)) else { return "nil-compile" }
    guard let r = SafeRegex.run(re, Array(subject.utf16)) else { return "nil-run" }
    return r ? "true" : "false"
}

/// SafeRegex.swift mutants that loop or allocate without bound. Every call that reaches a mutated line runs under a deadline; the
/// originals finish in milliseconds. Mutants that append forever use 1 s so the deadline fires before the memory watchdog.
final class A0DeadlineSafeRegexTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testA1AlternationConsumesTheBarAndEachBranch() {
        // line 99 (== -> !=): "a|b" leaves the loop at once, the parser stops on '|' and compile returns nil; line 100 (i += 0) never leaves the bar
        let got: String? = S2Deadline.within(1, "compile a|b and run on b") { a0Match("a|b", "b") }
        XCTAssertEqual(got, "true", "SafeRegex.swift:99,100")
        let two: String? = S2Deadline.within(1, "compile a|b|c and run on c") { a0Match("a|b|c", "c") }
        XCTAssertEqual(two, "true", "SafeRegex.swift:99,100 two bars")
    }

    func testA2AtomsAlwaysAdvance() {
        let dot: String? = S2Deadline.within(1, "compile . and run on x") { a0Match(".", "x") }
        XCTAssertEqual(dot, "true", "SafeRegex.swift:172 dot")
        let dotNl: String? = S2Deadline.within(1, "dot on newline") { a0Match(".", "\n") }
        XCTAssertEqual(dotNl, "false", "SafeRegex.swift:172 dot excludes a line terminator")
        let bol: String? = S2Deadline.within(1, "compile ^a and run on a") { a0Match("^a", "a") }
        XCTAssertEqual(bol, "true", "SafeRegex.swift:173 bol")
        let eol: String? = S2Deadline.within(1, "compile a$ and run on a") { a0Match("a$", "a") }
        XCTAssertEqual(eol, "true", "SafeRegex.swift:174 eol")
        let lit: String? = S2Deadline.within(1, "compile a and run on a") { a0Match("a", "a") }
        XCTAssertEqual(lit, "true", "SafeRegex.swift:177 literal")
    }

    func testA3ClassAtomAlwaysAdvances() {
        let got: String? = S2Deadline.within(1, "compile [ab] and run on b") { a0Match("[ab]", "b") }
        XCTAssertEqual(got, "true", "SafeRegex.swift:237")
    }

    func testA4CharSetBinarySearchTerminates() {
        let hit: String? = S2Deadline.within(10, "\\w on a") { a0Match("\\w", "a") }
        XCTAssertEqual(hit, "true", "SafeRegex.swift:37,39 lo = mid + 1 and the midpoint")
        let below: String? = S2Deadline.within(10, "\\w on -") { a0Match("\\w", "-") }
        XCTAssertEqual(below, "false", "SafeRegex.swift:39 hi = mid - 1")
        let above: String? = S2Deadline.within(10, "\\w on {") { a0Match("\\w", "{") }
        XCTAssertEqual(above, "false", "SafeRegex.swift:39 above the last range")
    }

    func testA5BraceDigitLoopsAdvance() {
        let got: String? = S2Deadline.within(10, "compile a{2,3} and run on aa") { a0Match("a{2,3}", "aa") }
        XCTAssertEqual(got, "true", "SafeRegex.swift:116,124")
    }

    func testA6RepeatEmitsExactlyMinCopies() {
        let got: Int? = S2Deadline.within(10, "a{3} program length") { SafeRegex.compile(Array("a{3}".utf16))?.prog.count ?? -1 }
        XCTAssertEqual(got, 4, "SafeRegex.swift:306: three sets and the match")
    }

    func testA7EpsilonCycleIsMarked() {
        let a: String? = S2Deadline.within(2, "(?:a*)* on a") { a0Match("(?:a*)*", "a") }
        XCTAssertEqual(a, "true", "SafeRegex.swift:358 mark[pc] = epoch")
        let b: String? = S2Deadline.within(2, "(?:a*)* on b") { a0Match("(?:a*)*", "b") }
        XCTAssertEqual(b, "false", "SafeRegex.swift:358")
    }

    func testA8IsSafeSourceScansAdvance() {
        let empty: Bool? = S2Deadline.within(10, "isSafeSource []") { SafeRegex.isSafeSource(Array("[]".utf16)) }
        XCTAssertEqual(empty, true, "SafeRegex.swift:415 i = j + 1 (an empty class)")
        let cls: Bool? = S2Deadline.within(10, "isSafeSource [a]") { SafeRegex.isSafeSource(Array("[a]".utf16)) }
        XCTAssertEqual(cls, true, "SafeRegex.swift:412 j += 1")
        let esc: Bool? = S2Deadline.within(10, "isSafeSource [^a\\]b]x") { SafeRegex.isSafeSource(Array("[^a\\]b]x".utf16)) }
        XCTAssertEqual(esc, true, "SafeRegex.swift:411,412 escape in a class")
        let grp: Bool? = S2Deadline.within(10, "isSafeSource (a)") { SafeRegex.isSafeSource(Array("(a)".utf16)) }
        XCTAssertEqual(grp, true, "SafeRegex.swift:424 plain group open")
        let bounded: Bool? = S2Deadline.within(10, "isSafeSource a{2,3}") { SafeRegex.isSafeSource(Array("a{2,3}".utf16)) }
        XCTAssertEqual(bounded, true, "SafeRegex.swift:464,471 brace digits")
        let plain: Bool? = S2Deadline.within(10, "isSafeSource ab") { SafeRegex.isSafeSource(Array("ab".utf16)) }
        XCTAssertEqual(plain, true, "SafeRegex.swift:499 plain atom")
    }
}
