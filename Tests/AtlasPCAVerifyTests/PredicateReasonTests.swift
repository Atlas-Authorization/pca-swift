import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The limit-naming denial reasons (0.5): every expected reason in test-data/predicate-reasons.json was produced by the
/// TypeScript `evaluatePredicates`, so the text must match byte for byte.
final class PredicateReasonTests: XCTestCase {
    static let CASES: [JSONValue] = ((try? K042.json("predicate-reasons.json"))?.get("cases")?.asArray) ?? []

    func testReasonsMatchTypeScript() {
        XCTAssertEqual(Self.CASES.count, 70)
        var bad: [String] = []
        for c in Self.CASES {
            let name = c.get("name")?.asString ?? "?"
            let want = c.get("reason")?.asString
            let got = PCA.envelopePredicatesError(c.get("predicates"), c.get("ctx") ?? .null, SafeRegex.Budget())
            if got != want { bad.append("\(name): \(got ?? "nil") != \(want ?? "nil")") }
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }
}
