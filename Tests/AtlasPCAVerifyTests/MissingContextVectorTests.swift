import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED typed-missing-context vectors (packages/pca/conformance/missing-context-vectors.json). A missing file fails.
final class MissingContextVectorTests: XCTestCase {
    private func strs(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    func testDecide() throws {
        let doc = try ConformanceTests.load("missing-context-vectors.json")
        let cases = doc.get("decide")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 20)
        var f: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let e = c.get("expect")
            let got = MissingContext.decideWithMissing(where: c.get("where"), bound: c.get("bound"), supplied: c.get("supplied"), suppliers: c.get("suppliers"))
            let want = (e?.get("missing")?.asArray ?? []).map { MissingContext.Missing(path: $0.get("path")?.asString ?? "", supplier: $0.get("supplier")?.asString ?? "") }
            if got.decision != e?.get("decision")?.asString || got.reason != e?.get("reason")?.asString || got.missing != want { f.append("\(name): \(got)") }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }

    func testBind() throws {
        let doc = try ConformanceTests.load("missing-context-vectors.json")
        let cases = doc.get("bind")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 8)
        var f: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let e = c.get("expect")
            guard let got = MissingContext.bindContext(c.get("bound") ?? .null, supplied: c.get("supplied"), table: c.get("suppliers")?.asObject ?? [:]) else {
                f.append("\(name): threw")
                continue
            }
            if got.context != e?.get("context") || got.conflicts != strs(e?.get("conflicts")) || got.dropped != strs(e?.get("dropped")) { f.append("\(name): \(got)") }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }
}
