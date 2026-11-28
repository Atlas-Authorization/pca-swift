import XCTest
import Foundation
@testable import AtlasPCAVerify

/// F10: budget_alloc monotonicity over packages/pca/conformance/budget-alloc-vectors.json (widen, malformed, equal ...).
final class A0F10BudgetAllocVectorsTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testBudgetAllocVectors() throws {
        let doc = try ConformanceTests.load("budget-alloc-vectors.json")
        let cases = try XCTUnwrap(doc.get("budget_alloc")?.asArray)
        XCTAssertEqual(cases.count, 24)
        var failures: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            // the row `caveats-not-an-array` (an object) is replayed as given: the reference answers `malformed caveats`
            let caveats = c.get("caveats")
            let got: String?? = S2Deadline.within(10, "allocationsMonotoneError \(name)") { Capability.allocationsMonotoneError(caveats) }
            let expect = c.get("expect")
            if expect?.get("ok") == .bool(true) {
                if got != .some(nil) { failures.append("\(name): want ok, got \(String(describing: got))") }
            } else if got != .some(expect?.get("reason")?.asString) {
                failures.append("\(name): want \(expect?.get("reason")?.asString ?? "?"), got \(String(describing: got))")
            }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }
}
