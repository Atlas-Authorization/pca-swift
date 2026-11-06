import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED `pca_grant` authorization-details vectors (packages/pca/conformance/pca-grant-vectors.json).
final class PcaGrantVectorTests: XCTestCase {
    func testPcaGrantVectors() throws {
        let doc = try ConformanceTests.load("pca-grant-vectors.json")
        var failures: [String] = []
        for v in doc.get("digest")?.asArray ?? [] {
            let ids = (v.get("ids")?.asArray ?? []).compactMap { $0.asString }
            if PcaGrant.chainDigest(ids) != v.get("digest")?.asString { failures.append("digest \(ids)") }
        }
        let details = doc.get("detail")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(details.count, 40)
        for v in details {
            let name = v.get("name")?.asString ?? "?"
            let code = PcaGrant.validate(v.get("input"))
            let exp = v.get("expect")
            if (code == nil) != (exp?.get("ok") == .bool(true)) || (code != nil && code != exp?.get("code")?.asString) { failures.append("detail \(name): \(code ?? "ok")") }
        }
        for v in doc.get("array")?.asArray ?? [] {
            let name = v.get("name")?.asString ?? "?"
            let r = PcaGrant.parse(v.get("input"))
            let exp = v.get("expect")
            let ok = (r.code == nil) == (exp?.get("ok") == .bool(true))
                && (r.code == nil ? Int64(r.details.count) == exp?.get("count")?.safeInt : r.code == exp?.get("code")?.asString)
            if !ok { failures.append("array \(name): \(r.code ?? "ok")") }
        }
        for v in doc.get("presentation")?.asArray ?? [] {
            let name = v.get("name")?.asString ?? "?"
            let p = v.get("presented")
            let r = PcaGrant.check(details: v.get("details")?.asArray ?? [], resource: p?.get("resource")?.asString ?? "",
                                   chainIds: (p?.get("chain_ids")?.asArray ?? []).compactMap { $0.asString }, proofVerified: p?.get("proof_verified") == .bool(true))
            let exp = v.get("expect")
            let ok = (r.code == nil) == (exp?.get("allow") == .bool(true))
                && (r.code == nil ? r.index.map { Int64($0) } == exp?.get("index")?.safeInt : r.code == exp?.get("code")?.asString)
            if !ok { failures.append("presentation \(name): \(r.code ?? "allow \(r.index ?? -1)")") }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }
}
