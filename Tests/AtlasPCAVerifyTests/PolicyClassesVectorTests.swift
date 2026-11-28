import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED policy-class vectors (packages/pca/conformance/policy-classes-vectors.json). A missing file fails.
final class PolicyClassesVectorTests: XCTestCase {
    private func strs(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    func testValidate() throws {
        let doc = try ConformanceTests.load("policy-classes-vectors.json")
        let cases = doc.get("validate")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 10)
        var f: [String] = []
        for c in cases {
            let ok = PolicyClasses.classVerdictsError(c.get("input")) == nil
            if ok != (c.get("expect")?.get("ok") == .bool(true)) { f.append(c.get("name")?.asString ?? "?") }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }

    func testDecide() throws {
        let doc = try ConformanceTests.load("policy-classes-vectors.json")
        let cases = doc.get("decide")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 9)
        var f: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let e = c.get("expect")
            let got = PolicyClasses.decideClasses(c.get("input"))
            var ok = got.decision == e?.get("decision")?.asString && got.reason == e?.get("reason")?.asString
                && got.deniedBy == strs(e?.get("denied_by")) && got.escalatedBy == strs(e?.get("escalated_by"))
            let want = e?.get("classes")?.asArray ?? []
            ok = ok && want.count == got.classes.count
            if ok {
                for (i, w) in want.enumerated() {
                    let g = got.classes[i]
                    if g.cls != w.get("class")?.asString || g.revision != w.get("revision")?.safeInt || g.digest != w.get("digest")?.asString || g.decision != w.get("decision")?.asString { ok = false }
                }
            }
            if !ok { f.append("\(name): \(got)") }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }
}
