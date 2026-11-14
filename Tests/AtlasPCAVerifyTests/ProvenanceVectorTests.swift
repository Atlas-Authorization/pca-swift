import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED build-provenance vectors (packages/pca/conformance/provenance-vectors.json, track K9).
final class ProvenanceVectorTests: XCTestCase {
    private func table(_ name: String) throws -> [JSONValue] {
        try ConformanceTests.load("provenance-vectors.json").get("primitives")?.get(name)?.asArray ?? []
    }

    private func unhex(_ v: JSONValue?) -> [UInt8] {
        let u = Array((v?.asString ?? "").utf8)
        return stride(from: 0, to: u.count - 1, by: 2).map { UInt8(String(decoding: u[$0...$0 + 1], as: UTF8.self), radix: 16) ?? 0 }
    }

    func testMerkleInclusion() throws {
        let rows = try table("merkle_inclusion")
        XCTAssertEqual(rows.count, 44)
        for v in rows {
            let i = v.get("input")
            let ok = PCA.verifyRfc9162Inclusion(
                leafHash: PCA.rfc9162LeafHash(unhex(i?.get("leaf_hex"))),
                index: i?.get("index")?.safeInt ?? -1,
                size: i?.get("size")?.safeInt ?? -1,
                proof: (i?.get("proof_hex")?.asArray ?? []).map { unhex($0) },
                root: unhex(i?.get("root_hex")))
            XCTAssertEqual(JSONValue.object(["ok": .bool(ok)]), v.get("expect"), v.get("name")?.asString ?? "?")
        }
    }

    func testGate() throws {
        let rows = try table("gate")
        XCTAssertEqual(rows.count, 45)
        for v in rows {
            let r = PCA.provenanceGate(v.get("input"))
            let got: JSONValue = r.ok
                ? .object(["ok": .bool(true), "level": .int(r.level), "claims": .object(r.claims)])
                : .object(["ok": .bool(false), "code": .string(r.code)])
            XCTAssertEqual(got, v.get("expect"), v.get("name")?.asString ?? "?")
        }
    }

    func testModelPath() throws {
        let rows = try table("model_path")
        XCTAssertEqual(rows.count, 7)
        for v in rows {
            let model = PCA.isModelDerivedPath(v.get("input")?.get("path")?.asString ?? "", [])
            XCTAssertEqual(JSONValue.object(["model": .bool(model)]), v.get("expect"), v.get("name")?.asString ?? "?")
        }
    }

    func testCaveatDefaultsAndOrder() throws {
        let c = PCA.provenanceCaveat(ProvenanceCaveatOptions(issuer: "slsa", minLevel: 3, sourceRepo: "r"))
        let want = try ConformanceTests.loadText(#"{"type":"needs_discharge","id":"provenance","issuer":"slsa","issuer_class":"artifact","bind":"action","ttl_ms":300000,"require":[{"claim":"slsa_level","op":"gte","value":3},{"claim":"source_repo","op":"eq","value":"r"},{"claim":"runtime_bound","op":"eq","value":true}]}"#)
        XCTAssertEqual(c, want)
        XCTAssertNil(PCA.needsDischargeError(c))
        let all = PCA.provenanceCaveat(ProvenanceCaveatOptions(issuer: "slsa", minLevel: 2, id: "prov", builderIds: ["b"], oidcIssuer: "i", requireRuntime: false, bind: "chain_hop", ttlMs: 1000))
        let req = try ConformanceTests.loadText(#"[{"claim":"slsa_level","op":"gte","value":2},{"claim":"builder_id","op":"in","value":["b"]},{"claim":"oidc_issuer","op":"eq","value":"i"}]"#)
        XCTAssertEqual(all.get("require"), req)
        XCTAssertEqual([all.get("id"), all.get("bind"), all.get("ttl_ms")], [.string("prov"), .string("chain_hop"), .int(1000)])
    }
}
