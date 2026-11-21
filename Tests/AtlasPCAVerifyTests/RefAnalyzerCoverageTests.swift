import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the policy coverage, schema validation and policy test runner of the analyzer against the reference
/// (@atlasauth/pca-analyzer). Numbers that are not finite are {"$num": ...}; a key is "$key:LABEL".
final class RefAnalyzerCoverageTests: XCTestCase {
    typealias A = PCAAnalyzer
    static let fns: Set<String> = ["witnessOf", "coverage", "coverageGate", "verbShapesFromActionDefs", "verbShapes", "validatePolicyAgainstSchema",
                                   "policyTestsDoc", "runPolicyTests", "generateBoundaryTests", "decideAll", "signPolicyTests", "verifyPolicyTests"]

    func testCoverageValidateTestRunner() throws {
        try K042.requireCovers(["Analyzer", "JSInterop", "JSLoose", "Predicates"])
        let d = Base.Diffs()
        var seen = Set<String>()
        try Base.each(RefAnalyzer.file, Self.fns) { c in
            let a0 = RefAnalyzer.arg(c, 0), a1 = RefAnalyzer.arg(c, 1), a2 = RefAnalyzer.arg(c, 2)
            seen.insert(c.fn)
            let got: BaseGot
            switch c.fn {
            case "witnessOf": got = RefAnalyzer.run { try A.witnessOf(try A.toModel(a0), a1) }
            case "coverage": got = RefAnalyzer.run { try A.coverage(a0, a1, a2) }
            case "coverageGate": got = RefAnalyzer.run { try A.coverageGate(a0, a1 == .null ? nil : a1) }
            case "verbShapesFromActionDefs": got = RefAnalyzer.run { try A.verbShapesFromActionDefs(a0) }
            case "verbShapes": got = RefAnalyzer.run { try A.verbShapes(a0) }
            case "validatePolicyAgainstSchema": got = RefAnalyzer.run { try A.validatePolicyAgainstSchema(a0, a1, a2) }
            case "policyTestsDoc": got = RefAnalyzer.run { try A.policyTestsDoc(a0, a1) }
            case "runPolicyTests": got = RefAnalyzer.run { try A.runPolicyTests(a0, a1, a2) }
            case "generateBoundaryTests": got = RefAnalyzer.run { try A.generateBoundaryTests(a0, a1) }
            case "decideAll": got = RefAnalyzer.run { try A.decideAll(a0, a1) }
            case "signPolicyTests":
                guard let doc = a0, let label = a1?.asString else { d.skip("signPolicyTests: malformed arguments"); return }
                got = RefAnalyzer.run { try A.signPolicyTests(doc, try RefAnalyzer.key(label)) }
            case "verifyPolicyTests": got = .value(.bool(A.verifyPolicyTests(a0, a1.map { RefAnalyzer.keyed($0) })))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen, Self.fns)
        d.finish(500)
    }
}
