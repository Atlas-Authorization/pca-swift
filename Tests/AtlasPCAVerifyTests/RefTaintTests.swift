import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the taint module (lattice, registry, classifyRef, computeTaint) against the reference: every case of the shared corpus.
final class RefTaintTests: XCTestCase {
    private struct ThrowingRegistry: PCATaint.Registry {
        func lookup(_ digest: String) throws -> JSONValue? { throw JSError("registry boom") }
    }
    private struct FixedRegistry: PCATaint.Registry {
        let fixed: JSONValue?
        func lookup(_ digest: String) throws -> JSONValue? { fixed }
    }

    /// The registry a corpus spec describes (nil: the context carries none).
    private func registry(_ rs: JSONValue?) -> PCATaint.Registry? {
        guard let rs = JS.present(rs) else { return nil }
        switch rs.get("mode")?.asString {
        case "throws": return ThrowingRegistry()
        case "fixed": return FixedRegistry(fixed: JS.present(rs.get("fixed")))
        default:
            let r = PCATaint.InMemoryRegistry()
            for rec in rs.get("records")?.asArray ?? [] { if let p = rec.asArray, p.count == 2 { r.record(p[0], p[1]) } }
            return r
        }
    }

    private func graph(_ gs: JSONValue?) -> ((String) throws -> Bool)? {
        guard let g = JS.present(gs) else { return nil }
        let nodes = (g.get("nodes")?.asArray ?? []).compactMap { $0.asString }.map { Array($0.utf16) }
        let boom = g.get("throws") == .bool(true)
        return { id in
            if boom { throw JSError("graph boom") }
            return nodes.contains(Array(id.utf16))
        }
    }

    private func runRegistry(_ ops: [JSONValue]) -> JSONValue {
        let r = PCATaint.InMemoryRegistry()
        var out: [JSONValue] = []
        for op in ops {
            let a = op.asArray ?? []
            func s(_ i: Int) -> String { i < a.count ? (a[i].asString ?? "") : "" }
            switch a.first?.asString {
            case "lookup": out.append(a.count > 1 ? (a[1].asString.flatMap { r.lookup($0) } ?? .null) : .null)
            case "size": out.append(.int(Int64(r.size)))
            case "emptyLookup": out.append((try? PCATaint.EmptyRegistry().lookup(s(1))) ?? .null)
            case "record": r.record(a.count > 1 ? a[1] : nil, a.count > 2 ? a[2] : nil); out.append(.null)
            case "recordTrusted": r.recordTrusted(s(1)); out.append(.null)
            case "recordFirstParty": r.recordFirstParty(s(1)); out.append(.null)
            case "recordTool": r.recordTool(s(1), id: s(2)); out.append(.null)
            case "recordWeb": r.recordWeb(s(1)); out.append(.null)
            default: XCTFail("unhandled registry op"); out.append(.null)
            }
        }
        return .array(out)
    }

    func testReplay() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-taint.json.gz") { c in
            seen[c.fn, default: 0] += 1
            let a = c.args.map { RefAnalyzer.revive($0) }
            func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
            let got = Base.run({ ($0 as? JSError)?.code }) { () -> JSONValue in
                switch c.fn {
                case "constants": return .object(["TAINT_LEVELS": .array(PCATaint.TAINT_LEVELS.map { .string($0) }), "BOTTOM": PCATaint.BOTTOM, "TOP": PCATaint.TOP])
                case "isTaintLevel": return .bool(PCATaint.isTaintLevel(arg(0)))
                case "labelRank": return .int(Int64(PCATaint.labelRank(arg(0))))
                case "taintValue": return .double(PCATaint.taintValue(arg(0)))
                case "joinLabel": return try PCATaint.joinLabel(arg(0), arg(1))
                case "joinLabels": return try PCATaint.joinLabels(arg(0)?.asArray ?? [])
                case "registry": return runRegistry(arg(0)?.asArray ?? [])
                case "classifyRef": return try PCATaint.classifyRef(arg(0), registry: registry(arg(1)?.get("registry")), node: graph(arg(1)?.get("graph")))
                case "computeTaint": return PCATaint.computeTaint(arg(0), registry: registry(arg(1)?.get("registry")), node: graph(arg(1)?.get("graph")))
                default: XCTFail("unhandled fn \(c.fn)"); return .null
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 2344)
        XCTAssertEqual(seen, ["computeTaint": 990, "classifyRef": 841, "joinLabel": 400, "labelRank": 27, "taintValue": 27, "joinLabels": 25, "isTaintLevel": 24, "registry": 9, "constants": 1])
        d.finish(2344)
    }
}
