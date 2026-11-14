import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for SafeRegex.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1SafeRegexHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testCharSetBinarySearchTerminates() {
        XCTAssertEqual(dl("\\w on a") { "\(String(describing: SafeRegex.compile(Array("\\w".utf16)).flatMap { SafeRegex.run($0, [0x61]) }))" }, "Optional(true)", "SafeRegex.swift:37,39 has()")
        XCTAssertEqual(dl("\\w on -") { "\(String(describing: SafeRegex.compile(Array("\\w".utf16)).flatMap { SafeRegex.run($0, [0x2d]) }))" }, "Optional(false)", "SafeRegex.swift:39 has() below the first range")
        XCTAssertEqual(dl("\\w on {") { "\(String(describing: SafeRegex.compile(Array("\\w".utf16)).flatMap { SafeRegex.run($0, [0x7b]) }))" }, "Optional(false)", "SafeRegex.swift:39 has() above the last range")
    }

    func testParserAlwaysAdvances() {
        for (src, subject, want) in [("a|b", "b", true), ("a{2,3}", "aa", true), (".", "x", true), ("^a$", "a", true), ("a", "a", true), ("[ab]", "b", true)] as [(String, String, Bool)] {
            let got = dl("compile and run \(src)") { "\(String(describing: SafeRegex.compile(Array(src.utf16)).flatMap { SafeRegex.run($0, Array(subject.utf16)) }))" }
            XCTAssertEqual(got, "Optional(\(want))", "SafeRegex.swift parser advance: \(src)")
        }
    }

    func testRepeatEmitsExactlyMinCopies() {
        let got = dl("a{3} program length") { "\(SafeRegex.compile(Array("a{3}".utf16))?.prog.count ?? -1)" }
        XCTAssertEqual(got, "4", "SafeRegex.swift:306: three sets and the match")
    }

    func testEpsilonCycleIsMarked() {
        for (subject, want) in [("a", true), ("", true), ("b", false)] as [(String, Bool)] {
            let got = dl("(?:a*)* on \(subject)") { "\(String(describing: SafeRegex.compile(Array("(?:a*)*".utf16)).flatMap { SafeRegex.run($0, Array(subject.utf16)) }))" }
            XCTAssertEqual(got, "Optional(\(want))", "SafeRegex.swift:358 mark[pc] = epoch, subject '\(subject)'")
        }
    }

    func testIsSafeSourceScanTerminates() {
        for src in ["[a]", "[]", "[^a\\]b]x", "(a)", "(?:a)", "a{2}", "a{2,3}", "a{2,}", "ab"] {
            let got = dl("isSafeSource \(src)") { "\(SafeRegex.isSafeSource(Array(src.utf16)))" }
            XCTAssertEqual(got, "true", "SafeRegex.swift isSafeSource scan: \(src)")
        }
        XCTAssertEqual(dl("isSafeSource [a") { "\(SafeRegex.isSafeSource(Array("[a".utf16)))" }, "false", "SafeRegex.swift:414 unterminated class")
    }
}
