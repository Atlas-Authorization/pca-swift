import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the goal N-version meet, the panel check and the active disambiguation against the reference. A reference throw
/// requires a native refusal.
final class RefGoalNVersionTests: XCTestCase {
    static let file = "ref-goal-nversion.json.gz"

    private static func arr(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return a
    }

    private static func need(_ v: JSONValue?) throws -> JSONValue {
        guard let x = v else { throw JSError("missing argument") }
        return x
    }

    private static func call(_ c: BaseCase) throws -> JSONValue? {
        switch c.fn {
        case "meet": return try PCAGoalNVersion.meet(try arr(c.arg(0)))
        case "meetGrants": return .array(try PCAGoalNVersion.meetGrants(try arr(c.arg(0)), try arr(c.arg(1))))
        case "checkPanel": return .array(PCAGoalNVersion.checkPanel(try arr(c.arg(0))))
        case "disagreementMass": return .double(try PCAGoalDisambiguate.disagreementMass(try arr(c.arg(0)), try need(c.arg(1))))
        case "questions": return .array(try PCAGoalDisambiguate.questions(try arr(c.arg(0)), PCAGoalDisambiguate.Opts(try need(c.arg(1)))))
        case "nVersion":
            var threshold: Double? = nil
            if let t = c.arg(2), t != .null { threshold = IV.num(t) }
            return try PCAGoalNVersion.nVersion(try arr(c.arg(0)), PCAGoalDisambiguate.Opts(try need(c.arg(1))), threshold)
        case "allowsWitness": return .bool(try PCAGoalDisambiguate.allowsWitness(try need(c.arg(0)), try need(c.arg(1)), try need(c.arg(2))))
        case "disambiguate":
            let readings = try arr(c.arg(0))
            let ont = try need(c.arg(1))
            let mode = c.arg(2)?.asString ?? ""
            let opts = PCAGoalDisambiguate.Opts(ont)
            if let b = c.arg(3), b != .null {
                guard let n = IV.int(b) else { throw JSError("budget expected") }
                opts.budget = Int(n)
            }
            return try PCAGoalDisambiguate.disambiguate(readings, { (q: JSONValue) throws -> String in
                if mode == "allow" { return "allow" }
                if mode == "deny" { return "deny" }
                // "reading<i>": the answer of reading i
                guard let i = Int(String(mode.dropFirst(6))), i >= 0, i < readings.count else { throw JSError("bad mode") }
                return try PCAGoalDisambiguate.allowsWitness(try need(readings[i].get("goal")), ont, q) ? "allow" : "deny"
            }, opts)
        default: return nil
        }
    }

    func testReplayAgainstReference() throws {
        let d = Base.Diffs()
        var unknown = 0
        try Base.each(Self.file) { c in
            var known = true
            let got: BaseGot = Base.run { () throws -> JSONValue in
                guard let v = try Self.call(c) else { known = false; return .null }
                return v
            }
            if !known { unknown += 1; d.skip("function not replayed: \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(unknown, 0, "every function of the corpus is replayed")
        d.finish(60)
    }
}
