import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the quantitative policy-analyzer queries (thresholds, max exposure, escalation surface, delegation envelope,
/// policy diff and its gate, the solver-answer check), the workflow DAG exposure and the minimal-flip counterfactual search against the
/// reference (@atlasauth/pca-analyzer). A reference throw requires a native refusal.
final class RefAnalyzerExposureTests: XCTestCase {
    typealias A = PCAAnalyzer

    func testAnalyzerExposure() throws {
        try K042.requireCovers(["Analyzer"])
        let fns: Set<String> = ["thresholdsOf", "maxExposure", "escalationSurface", "delegationEnvelope", "diffPolicies", "diffGate", "findWithBackend", "dagExposure", "minimalFlip"]
        let d = Base.Diffs()
        try Base.each(RefAnalyzer.file, fns) { c in
            let a0 = RefAnalyzer.arg(c, 0), a1 = RefAnalyzer.arg(c, 1), a2 = RefAnalyzer.arg(c, 2)
            let got: BaseGot
            switch c.fn {
            case "thresholdsOf":
                got = RefAnalyzer.run {
                    guard let path = a1?.asString else { throw JSError("path is not a string") }
                    return .array(try A.thresholdsOf(try A.toModel(a0), path).map { A.num($0) })
                }
            case "maxExposure": got = RefAnalyzer.run { try A.maxExposure(a0, a1) }
            case "escalationSurface": got = RefAnalyzer.run { try A.escalationSurface(a0, a1) }
            case "delegationEnvelope": got = RefAnalyzer.run { try A.delegationEnvelope(a0, a1) }
            case "diffPolicies": got = RefAnalyzer.run { try A.diffPolicies(a0, a1, a2) }
            case "diffGate":
                // a null `allow` is the reference's omitted argument
                got = RefAnalyzer.run { try A.diffGate(a0, a1 == .null ? nil : a1) }
            case "findWithBackend":
                got = RefAnalyzer.run { try A.findWithBackend(a0, name: a1?.get("name"), result: a1?.get("result")) }
            case "dagExposure": got = RefAnalyzer.run { try A.dagExposure(a0) }
            case "minimalFlip": got = RefAnalyzer.run { try A.minimalFlip(a0, a1, a2) }
            default: return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(780)
    }
}
