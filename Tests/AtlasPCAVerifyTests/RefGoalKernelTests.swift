import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the goal kernel over the kernel tape corpus (the reference's compiled kernel on the goal conformance vectors): every
/// op's output tape must be identical, as harness text. A case whose tape text carries a lone surrogate is counted and skipped
/// (a Swift String cannot hold one).
final class RefGoalKernelTests: XCTestCase {
    static let file = "ref-goal-kernel.json.gz"

    private func text(_ ops: String, _ g: JSONValue, _ o: JSONValue?, _ a: JSONValue?, _ h: JSONValue?) throws -> JSONValue {
        return .string(try PCAGoalKernel.tapeToText(try PCAGoalKernel.call(ops, g, o, a, h)))
    }

    func testTapeText() throws {
        XCTAssertEqual("k5 i-3 s s68.1f600", try PCAGoalKernel.tapeToText(try PCAGoalKernel.tapeFromText("k5 i-3 s s68.1f600")))
        XCTAssertEqual(try PCAGoalKernel.tapeFromText("s68.1f600").asArray?[0].asArray?[1].asString, "h\u{1F600}")
        XCTAssertThrowsError(try PCAGoalKernel.tapeFromText("sd800"))
        XCTAssertThrowsError(try PCAGoalKernel.tapeFromText("x1"))
    }

    func testKernelTapes() throws {
        let d = Base.Diffs()
        try Base.each(Self.file, ["kernel"]) { c in
            guard let g0 = c.arg(0)?.asString, let o0 = c.arg(1)?.asString else { d.add(c, "\(c.name): bad args"); return }
            let g: JSONValue
            let o: JSONValue
            var probes: [(JSONValue, JSONValue)] = []
            do {
                g = try PCAGoalKernel.tapeFromText(g0)
                o = try PCAGoalKernel.tapeFromText(o0)
                for p in c.arg(2)?.asArray ?? [] {
                    let pp = p.asArray ?? []
                    probes.append((try PCAGoalKernel.tapeFromText(pp[0].asString ?? ""), try PCAGoalKernel.tapeFromText(pp[1].asString ?? "")))
                }
            } catch {
                d.skip("tape text with a lone surrogate (a Swift String cannot hold one)")
                return
            }
            let got = Base.run { () throws -> JSONValue in
                var out = JObject()
                for op in ["typecheck", "compile", "render"] { out[JKey(op)] = try self.text(op, g, o, nil, nil) }
                var ps: [JSONValue] = []
                for (act, hist) in probes {
                    ps.append(.array([try self.text("decideg", g, o, act, hist), try self.text("decidep", g, o, act, hist)]))
                }
                out[JKey("probes")] = .array(ps)
                return .object(out)
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(150)
    }

    /// A string token of a million characters crosses the kernel without a stack overflow.
    func testHugeStringDoesNotOverflow() throws {
        let big: JSONValue = .array([.array([.string("s"), .string(String(repeating: "a", count: 1 << 20))])])
        for op in ["typecheck", "compile", "render"] {
            let r = try PCAGoalKernel.call(op, big, .array([]), nil, nil)
            XCTAssertEqual(r.asArray?[0].asArray?[0].asString, "i", op)
        }
    }

    private func nested(_ n: Int) throws -> JSONValue {
        let head = "k480 i1 s s s i0 i1 k380 s s k373 s "
        let tail = " i0 i0 k460 i0 i0 i0 k461 i0 i1 i0 i0 i0 i0"
        return try PCAGoalKernel.tapeFromText(head + String(repeating: "k364 ", count: n) + "k360" + tail)
    }

    /// A deeply nested condition is decoded (or refused past the depth cap), never a stack overflow.
    func testDeepNestingRefusedNotCrashed() throws {
        let ok = try PCAGoalKernel.call("render", try nested(5000), nil, nil, nil)
        XCTAssertEqual(String(try PCAGoalKernel.tapeToText(ok).prefix(2)), "i0")
        XCTAssertThrowsError(try PCAGoalKernel.call("render", try nested(100_050), nil, nil, nil))
    }

    func testMalformedIsRefused() throws {
        XCTAssertTrue(PCAGoalKernel.available())
        let bad = try PCAGoalKernel.tapeFromText("i7")
        XCTAssertEqual(try PCAGoalKernel.tapeToText(try PCAGoalKernel.call("typecheck", bad, .array([]), nil, nil)), "i9")
        XCTAssertThrowsError(try PCAGoalKernel.call("nope", bad, bad, nil, nil))
        XCTAssertThrowsError(try PCAGoalKernel.call("typecheck", try PCAGoalKernel.tapeFromText("k9007199254740992"), bad, nil, nil))
    }
}
