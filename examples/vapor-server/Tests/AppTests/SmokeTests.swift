import XCTest
import XCTVapor
import Foundation
import AtlasPCAVerify
import App

/// A real signed PCActn from the library's shared authorize fixtures (a $50 payment under a $100 envelope), read with Foundation only.
final class SmokeTests: XCTestCase {
    struct Fixture {
        let now: Int64, audience: String, grant: JSONValue, header: String, verb: String, resource: String, paramsText: String
    }

    func load() throws -> Fixture {
        // …/examples/vapor-server/Tests/AppTests/<file> -> the library's test-data
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        url.appendPathComponent("test-data/authorize-fixtures.json")
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let c = try XCTUnwrap((root["cases"] as? [[String: Any]])?.first)
        let s = try XCTUnwrap((c["steps"] as? [[String: Any]])?.first)
        let op = try XCTUnwrap(s["operation"] as? [String: Any])
        func text(_ v: Any?) throws -> String {
            let d = try JSONSerialization.data(withJSONObject: try XCTUnwrap(v), options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed])
            // re-print canonically: Foundation prints some doubles with 17+ digits, which the strict wire profile refuses
            return try XCTUnwrap(JSONValue.parse(String(decoding: d, as: UTF8.self))).canonicalText
        }
        let header = Data(try text(s["pcactn"]).utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return Fixture(now: (try XCTUnwrap(root["now"] as? NSNumber)).int64Value, audience: try XCTUnwrap(root["audience"] as? String),
                       grant: try XCTUnwrap(JSONValue.parse(try text(c["grant"]))), header: header,
                       verb: try XCTUnwrap(op["verb"] as? String), resource: try XCTUnwrap(op["resource"] as? String), paramsText: try text(op["params"]))
    }

    func testAllowsTheSignedRefundAndRefusesAReplayWithADocLink() throws {
        let f = try load()
        let app = Application(.testing)
        defer { app.shutdown() }
        let now = f.now
        // the provenance the agent harness presents: the refund came straight from the principal (harness pin: seed 32 x 0x01)
        let recorder = try ProvenanceRecorder(mediator: "conformance-harness", kid: "k1", secretKey: [UInt8](repeating: 1, count: 32))
        let params = try XCTUnwrap(JSONValue.parse(f.paramsText))
        let prov = ProvenanceRecorder.header(try PCA.principalDirectProvenance(recorder, PCA.Operation(verb: f.verb, resource: f.resource, params: params)))
        try configure(app, audience: f.audience, grants: [f.grant], verb: f.verb, resource: f.resource, mediators: [recorder.pin], now: { now })

        // without the provenance bundle: an escalation, never an allow
        try app.test(.POST, "refunds", headers: ["PCA-Action": f.header], body: ByteBuffer(string: f.paramsText)) { res in
            XCTAssertEqual(res.status, .forbidden)
            XCTAssertTrue(res.body.string.contains("provenance_flow"), res.body.string)
        }
        try app.test(.POST, "refunds", headers: ["PCA-Action": f.header, "PCA-Provenance": prov], body: ByteBuffer(string: f.paramsText)) { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(res.body.string, "refunded:\(f.verb)")
        }
        // the same proof again: refused, with the reason and a link to its explanation
        try app.test(.POST, "refunds", headers: ["PCA-Action": f.header, "PCA-Provenance": prov], body: ByteBuffer(string: f.paramsText)) { res in
            XCTAssertEqual(res.status, .forbidden)
            guard case let .object(o)? = JSONValue.parse(res.body.string), case let .string(doc)? = o[JKey("doc")] else {
                return XCTFail("no doc member in \(res.body.string)")
            }
            XCTAssertEqual(doc, "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay")
        }
    }
}
