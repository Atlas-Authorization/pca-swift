import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the policy bridge (Cedar / OPA-Rego / OpenFGA / strict-CEL translators and the deny-overrides-permit decision)
/// against the reference (@atlasauth/pca-policy-bridge). A parsed object has no member order, but the reference reports an OpenFGA
/// model's relations (and orders a CEL schema's variables) in the order they were written, so the member order of each case line is
/// scanned from the corpus text and handed to the translator as its KeyOrder (looked up by member set within the one case).
///
/// Skipped: only cases that carry a lone surrogate (a Swift String cannot hold one). Nothing is stricter natively in this corpus.
final class RefPolicyBridgeTests: XCTestCase {
    static let file = "ref-policy-bridge.json.gz"
    typealias PB = PCAPolicyBridge

    /// Per function, the member orders of each of its case lines in file order.
    static func lineOrders(_ fns: Set<String>) throws -> [String: [[String: [String]]]] {
        let bs = [UInt8](try K042.bytes(file))
        let prefix = Array(#"{"fn":""#.utf8)
        var out: [String: [[String: [String]]]] = [:]
        var at = 0
        while at < bs.count {
            let nl = bs[at...].firstIndex(of: 0x0A) ?? bs.count
            let line = Array(bs[at..<nl])
            at = nl + 1
            guard line.starts(with: prefix) else { continue }
            var e = prefix.count
            while e < line.count && line[e] != 0x22 { e += 1 }
            var fn = String(decoding: line[prefix.count..<e], as: UTF8.self)
            if fn.hasSuffix("@suspect") { fn = String(fn.dropLast("@suspect".count)) }
            if fns.contains(fn) { out[fn, default: []].append(RefComplianceTests.scanOrders(line)) }
        }
        return out
    }

    static func hook(_ orders: [String: [String]]) -> PB.KeyOrder {
        { o in orders[RefComplianceTests.sig(o.keys.map { $0.s })] ?? [] }
    }

    func testPolicyBridge() throws {
        try K042.requireCovers(["PolicyBridge", "Predicates", "JSInterop", "JSLoose"])
        let ordered: Set<String> = ["openfgaToPca", "celToCondition", "celToPredicate", "celConditionsToPca"]
        let orders = try Self.lineOrders(ordered)
        var next: [String: Int] = [:]
        let d = Base.Diffs()
        var seen = Set<String>()
        try Base.each(Self.file, seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            seen.insert(c.fn)
            var order: PB.KeyOrder?
            if ordered.contains(c.fn) {
                let i = next[c.fn, default: 0]
                next[c.fn] = i + 1
                if let all = orders[c.fn], i < all.count { order = Self.hook(all[i]) }
            }
            let got: BaseGot
            switch c.fn {
            case "cedarToPca":
                guard let t = a0?.asString else { d.skip("non-string policy text"); return }
                got = .value(PB.cedarToPca(t))
            case "translateCedar":
                guard let t = a0?.asString else { d.skip("non-string policy text"); return }
                got = .value(PB.translateCedar(t, errorGuards: a1 == .bool(true)))
            case "regoToPca":
                guard let t = a0?.asString else { d.skip("non-string module text"); return }
                got = Ref.v { try PB.regoToPca(t) }
            case "openfgaToPca": got = .value(PB.openfgaToPca(a0, a1, order: order))
            case "decide": got = Ref.v { try PB.decide(a0, a1) }
            case "parseCel": got = .value(PB.parseCel(a0))
            case "celToCondition": got = .value(PB.celToCondition(a0, a1, order: order))
            case "celToPredicate": got = Ref.v { try PB.celToPredicate(a0, a1, scope: a2, order: order) }
            case "celConditionsToPca": got = Ref.v { try PB.celConditionsToPca(a0, a1, order: order) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen.count, 9)
        d.finish(4000)
    }
}
