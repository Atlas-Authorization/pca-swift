import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the frontier signals (semanticSignal, progressSignal, objectiveSignal, tightenRiskInputs) against the reference: every case.
final class RefFrontierSignalsTests: XCTestCase {
    /// The four functions over one case (also replayed from the shared sweep corpus).
    static func run(_ c: BaseCase) throws -> JSONValue? {
        let a = c.args.map { RefAnalyzer.revive($0) }
        func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
        switch c.fn {
        case "semanticSignal": return .string(PCAFrontierSignals.semanticSignal(arg(0)))
        case "progressSignal": return .string(PCAFrontierSignals.progressSignal(arg(0)))
        case "objectiveSignal": return .string(PCAFrontierSignals.objectiveSignal(arg(0)))
        case "tightenRiskInputs": return RefAnalyzer.out(try PCAFrontierSignals.tightenRiskInputs(arg(0), arg(1)))
        default: return nil
        }
    }

    func testReplay() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-frontier-signals.json.gz") { c in
            seen[c.fn, default: 0] += 1
            d.add(c, Base.diff(c, Base.run { try Self.run(c) ?? { XCTFail("unhandled fn \(c.fn)"); return .null }() }))
        }
        XCTAssertEqual(n, 690)
        XCTAssertEqual(seen, ["tightenRiskInputs": 340, "objectiveSignal": 182, "progressSignal": 129, "semanticSignal": 39])
        d.finish(690)
    }
}
