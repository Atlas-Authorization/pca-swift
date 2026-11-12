import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for StrictParser.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1StrictParserHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testStrictParserAdvances() {
        XCTAssertEqual(dl("strict ws") { if case .int(1)? = try? StrictJSON.parse(" \t\n\r1 ") { return "ok" }; return "bad" }, "ok", "StrictParser.swift:45")
        XCTAssertEqual(dl("strict string") { if case .string("ab")? = try? StrictJSON.parse("\"ab\"") { return "ok" }; return "bad" }, "ok", "StrictParser.swift:115")
        XCTAssertEqual(dl("strict int") { if case .int(12)? = try? StrictJSON.parse("12") { return "ok" }; return "bad" }, "ok", "StrictParser.swift:154")
        XCTAssertEqual(dl("strict frac") { if case .double(1.5)? = try? StrictJSON.parse("1.5") { return "ok" }; return "bad" }, "ok", "StrictParser.swift:162")
        XCTAssertEqual(dl("lenient number") { if case .double(12500)? = try? StrictJSON.parseLenient("12.5e+3") { return "ok" }; return "bad" }, "ok", "StrictParser.swift:129,133,138")
    }
}
