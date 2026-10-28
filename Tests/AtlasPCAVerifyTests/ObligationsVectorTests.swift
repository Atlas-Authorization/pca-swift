import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED decision-obligations vectors (packages/pca/conformance/obligations-vectors.json). A missing file fails.
final class ObligationsVectorTests: XCTestCase {
    private func strs(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    func testObligationsVectors() throws {
        let doc = try ConformanceTests.load("obligations-vectors.json")
        var f: [String] = []
        let validate = doc.get("validate")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(validate.count, 15)
        for c in validate {
            let ok = Obligations.obligationsError(c.get("input")) == nil
            if ok != (c.get("expect")?.get("ok") == .bool(true)) { f.append("validate \(c.get("name")?.asString ?? "?")") }
        }
        let merge = doc.get("merge")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(merge.count, 5)
        for c in merge {
            let name = c.get("name")?.asString ?? "?"
            let got = Obligations.mergeObligations(c.get("inputs")?.asArray ?? [])
            let e = c.get("expect")
            if got.ok != (e?.get("ok") == .bool(true)) { f.append("merge \(name): ok"); continue }
            if got.ok && JSONValue.array(got.obligations) != e?.get("obligations") { f.append("merge \(name): obligations") }
        }
        let gate = doc.get("gate")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(gate.count, 10)
        for c in gate {
            let name = c.get("name")?.asString ?? "?"
            let got = Obligations.pepObligationGate(decision: c.get("decision")?.asString ?? "", answered: c.get("answered") == .bool(true),
                                                    obligations: c.get("obligations"), supported: c.get("supported"))
            let e = c.get("expect")
            if got.decision != e?.get("decision")?.asString { f.append("gate \(name): decision \(got.decision)") }
            if JSONValue.array(got.perform) != e?.get("perform") { f.append("gate \(name): perform") }
            if got.unsupported != strs(e?.get("unsupported")) { f.append("gate \(name): unsupported") }
        }
        let outcome = doc.get("outcome")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(outcome.count, 8)
        for c in outcome {
            let name = c.get("name")?.asString ?? "?"
            let got = Obligations.obligationOutcome(obligations: c.get("obligations"), fulfilled: c.get("fulfilled"), now: c.get("now"))
            let e = c.get("expect")
            if got.outcome != e?.get("outcome")?.asString { f.append("outcome \(name): \(got.outcome)") }
            if got.overdue.map({ Int64($0) }) != (e?.get("overdue")?.asArray ?? []).compactMap({ $0.safeInt }) { f.append("outcome \(name): overdue") }
            if got.status != e?.get("status")?.asString { f.append("outcome \(name): status") }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }
}
