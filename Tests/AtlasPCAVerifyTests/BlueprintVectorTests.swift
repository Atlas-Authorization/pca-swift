import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED agent-blueprint vectors (packages/pca/conformance/blueprint-vectors.json).
final class BlueprintVectorTests: XCTestCase {
    func testBlueprintVectors() throws {
        let doc = try ConformanceTests.load("blueprint-vectors.json")
        let recs = doc.get("records")?.asArray ?? []
        XCTAssertEqual(recs.count, 26)
        XCTAssertFalse(Blueprint.verify(recs[8]), "record 8 (a tampered record)")
        let op = doc.get("operator")?.asString ?? ""
        var failures: [String] = []
        for s in doc.get("scenarios")?.asArray ?? [] {
            let name = s.get("name")?.asString ?? "?"
            let reg = Blueprint.Registry(operators: [op], store: Blueprint.MemoryStore())
            for st in s.get("steps")?.asArray ?? [] {
                let exp = st.get("expect")
                if st.get("op")?.asString == "accept" {
                    let got = reg.accept(recs[Int(st.get("record")?.safeInt ?? 0)])
                    let ok = got.ok == (exp?.get("ok") == .bool(true)) && (got.ok ? got.replaced == (exp?.get("replaced") == .bool(true)) : got.code == exp?.get("code")?.asString)
                    if !ok { failures.append("\(name): accept \(got)") }
                } else {
                    let o = st.get("opts")
                    // `opts.admitted` is data: 'all' (the hook returns true), 'none' (false), or a list of instance keys; absent: no hook
                    var hook: ((String, JObject) throws -> Bool)?
                    switch o?.get("admitted") {
                    case .some(.string("all")): hook = { _, _ in true }
                    case .some(.string("none")): hook = { _, _ in false }
                    case let .some(.array(keys)): let ok = keys.compactMap { $0.asString }; hook = { holder, _ in ok.contains(holder) }
                    default: break
                    }
                    let got = Blueprint.check(chain: st.get("chain"), registry: reg, now: o?.get("now"), mode: o?.get("mode")?.asString ?? "", minEpoch: o?.get("minEpoch")?.safeInt, admitted: hook)
                    var ok = got.decision == exp?.get("decision")?.asString
                    if let c = exp?.get("code")?.asString { ok = ok && got.code == c }
                    if let b = exp?.get("blueprint")?.asString { ok = ok && got.blueprint == b }
                    if let g = exp?.get("governed")?.asArray { ok = ok && got.governed == g.compactMap { $0.asString } }
                    if exp?.get("decision")?.asString == "escalate" { ok = ok && got.have == exp?.get("have")?.safeInt && got.need == exp?.get("need")?.safeInt }
                    if !ok { failures.append("\(name): check \(got)") }
                }
            }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }
}
