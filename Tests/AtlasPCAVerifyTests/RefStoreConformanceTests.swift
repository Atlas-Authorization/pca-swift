import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the pca-store-conformance history checker (step, overlappingTrues, prune, fastCheck, the budgeted search, decideKey, deletion,
/// minimize, checkKey, checkHistory, formatOps) against the TypeScript reference. A reference throw requires a native refusal.
final class RefStoreConformanceTests: XCTestCase {
    typealias S = PCAStoreConformance
    static let file = "ref-store-conformance.json.gz"

    static func ops(_ v: JSONValue?) throws -> [S.Op] {
        guard let a = v?.asArray else { throw JSError("history expected") }
        return try a.map { try S.op(from: $0) }
    }

    static func opts(_ v: JSONValue?) -> (budget: Int, minimize: Bool, limit: Int) {
        let o = v?.asObject ?? [:]
        return (IV.safe(o["budget"]).map { Int($0) } ?? S.DEFAULT_SEARCH_BUDGET, o["minimize"] != .bool(false), IV.safe(o["minimizeLimit"]).map { Int($0) } ?? 200)
    }

    func testCheckerAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["step", "overlappingTrues", "prune", "fastCheck", "search", "decideKey", "deletion", "minimize", "checkKey", "checkHistory", "formatOps"]
        let n = try Base.each(Self.file, fns) { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "step":
                    guard let s = S.numOf(c.arg(0)) else { throw JSError("state") }
                    return .array(S.step(s, try S.op(from: c.arg(1))).map { S.numValue($0) })
                case "overlappingTrues":
                    guard let p = S.overlappingTrues(try Self.ops(c.arg(0))) else { return .null }
                    return .array([S.json(p.0), S.json(p.1)])
                case "prune": return .array(S.prune(try Self.ops(c.arg(0))).map { S.json($0) })
                case "fastCheck": return S.fastCheck(try Self.ops(c.arg(0))).map { .bool($0) } ?? .null
                case "search":
                    let b = IV.safe(c.arg(1)).map { Int($0) } ?? S.DEFAULT_SEARCH_BUDGET
                    return .string(S.searchLinearizable(try Self.ops(c.arg(0)), b))
                case "decideKey":
                    let b = IV.safe(c.arg(1)).map { Int($0) } ?? S.DEFAULT_SEARCH_BUDGET
                    let r = S.decideKey(try Self.ops(c.arg(0)), b)
                    return .object(["verdict": .string(r.verdict), "method": .string(r.method), "kept": .array(r.kept.map { S.json($0) })])
                case "deletion":
                    let o = try Self.ops(c.arg(0))
                    guard let i = IV.safe(c.arg(1)), Int(i) >= 0, Int(i) < o.count else { throw JSError("index") }
                    return .array(S.deletion(o, Int(i)).map { S.json($0) })
                case "minimize":
                    let b = IV.safe(c.arg(1)).map { Int($0) } ?? S.DEFAULT_SEARCH_BUDGET
                    return .array(S.minimize(try Self.ops(c.arg(0)), b).map { S.json($0) })
                case "checkKey":
                    let o = Self.opts(c.arg(1))
                    let h = try Self.ops(c.arg(0))
                    if h.isEmpty { throw JSError("empty") }
                    return S.json(S.checkKey(h, budget: o.budget, minimize: o.minimize, minimizeLimit: o.limit))
                case "checkHistory":
                    let o = Self.opts(c.arg(1))
                    return S.json(S.checkHistory(try Self.ops(c.arg(0)), budget: o.budget, minimize: o.minimize, minimizeLimit: o.limit))
                case "formatOps": return .array(S.formatOps(try Self.ops(c.arg(0))).map { .string($0) })
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 1500)
        d.finish(1500)
    }
}
