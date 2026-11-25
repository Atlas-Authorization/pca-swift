import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the policy debugger (explainRisk, explainDecision, applyDelta, counterfactual, auditPCActn) against the reference:
/// every case of the shared corpus. Non-finite numbers travel as {"$num"}; results are compared as canonical JSON.
final class RefPolicyDebugTests: XCTestCase {
    func testReplay() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-policy-debug.json.gz") { c in
            seen[c.fn, default: 0] += 1
            let a = c.args.map { RefAnalyzer.revive($0) }
            func arg(_ i: Int) -> JSONValue { i < a.count ? a[i] : .null }
            let got = Base.run({ ($0 as? JSError)?.code }) { () -> JSONValue in
                switch c.fn {
                case "explainRisk": return PCAPolicyDebug.explainRisk(arg(0), arg(1), a.count > 2 && arg(2) != .null ? arg(2) : nil)
                case "explainDecision": return try PCAPolicyDebug.explainDecision(arg(0))
                case "applyDelta": return PCAPolicyDebug.applyDelta(arg(0), arg(1))
                case "counterfactual": return try PCAPolicyDebug.counterfactual(arg(0), arg(1))
                case "auditPCActn": return try PCAPolicyDebug.auditPCActn(arg(0), arg(1), arg(2))
                default: XCTFail("unhandled fn \(c.fn)"); return .null
                }
            }
            if case let .value(v) = got { d.add(c, Base.diff(c, .value(RefAnalyzer.out(v)))) } else { d.add(c, Base.diff(c, got)) }
        }
        XCTAssertEqual(n, 553)
        XCTAssertEqual(seen, ["explainRisk": 315, "explainDecision": 140, "applyDelta": 63, "counterfactual": 26, "auditPCActn": 9])
        d.finish(553)
    }
}
