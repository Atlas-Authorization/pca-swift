import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the residual / "what may I do" / data-filter / narrowing / access-request surface of the policy analyzer against
/// the reference (@atlasauth/pca-analyzer). Policies, residuals and filters are plain JSON; a non-finite number is {"$num": "Infinity"}, a key
/// is a label ("$key:LABEL") and signing is deterministic (RFC 8032), so signatures compare byte for byte.
final class RefAnalyzerResidualTests: XCTestCase {
    typealias A = PCAAnalyzer
    static let fns: Set<String> = ["residual", "residualPolicy", "evaluateResidual", "whatMayIDo", "toFilter", "evalFilter", "toUcast", "evalUcast",
                                   "suggestNarrowing", "signAccessRequest", "verifyAccessRequest"]

    func testAnalyzerResidual() throws {
        try K042.requireCovers(["Analyzer", "Predicates", "JSLoose", "JSInterop"])
        let d = Base.Diffs()
        var seen = Set<String>()
        try Base.each(RefAnalyzer.file, Self.fns) { c in
            let a0 = RefAnalyzer.arg(c, 0), a1 = RefAnalyzer.arg(c, 1), a2 = RefAnalyzer.arg(c, 2), a3 = RefAnalyzer.arg(c, 3)
            seen.insert(c.fn)
            let got: BaseGot
            switch c.fn {
            case "residual": got = RefAnalyzer.run { try A.residual(a0, a1, a2) }
            case "residualPolicy": got = RefAnalyzer.run { try A.residualPolicy(a0) }
            case "evaluateResidual": got = RefAnalyzer.run { .string(try A.evaluateResidual(a0, a1)) }
            case "whatMayIDo": got = RefAnalyzer.run { try A.whatMayIDo(a0, a1, a2, a3) }
            case "toFilter": got = RefAnalyzer.run { A.toFilter(try A.residual(a0, a1, a2), a3) }
            case "evalFilter": got = RefAnalyzer.run { try A.evalFilter(a0, a1) }
            case "toUcast": got = RefAnalyzer.run { try A.toUcast(a0) }
            case "evalUcast": got = RefAnalyzer.run { .bool(try A.evalUcast(a0, a1)) }
            case "suggestNarrowing": got = RefAnalyzer.run { try A.suggestNarrowing(a0, a1, a2) }
            case "signAccessRequest":
                got = RefAnalyzer.run {
                    guard let r = a0, let label = a1?.asString else { throw JSError("malformed case") }
                    return try A.signAccessRequest(r, key: try RefAnalyzer.key(label))
                }
            case "verifyAccessRequest":
                // a null expected signer is the omitted argument
                got = .value(.bool(A.verifyAccessRequest(a0, a1 == .null ? nil : a1.map { RefAnalyzer.keyed($0) })))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen, Self.fns)
        d.finish(1800)
    }
}
