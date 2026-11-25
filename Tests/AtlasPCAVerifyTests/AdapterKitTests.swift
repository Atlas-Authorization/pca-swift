import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The structural tool wrapper and the MCP client transport wrapper: a verifiable PCActn per call, a fast-fail on the local dry run, metadata kept,
/// results recorded as untrusted, and everything that is not a mapped `tools/call` passing through untouched.
final class AdapterKitTests: XCTestCase {
    static let AUD = "ins_test"

    func agent() throws -> PCAFacadeAgent {
        try PCAAgent.fromPrincipal(PCAAgentOptions(principal: .ed25519(try PCAEdKey.generate()), goal: "refunds", permissions: [("stripe", ["refund"])],
                                                   limits: ["refund": "$500/day"], aud: Self.AUD))
    }

    final class Box: @unchecked Sendable {
        var ran: JSONValue?
        var proof: PCAActResult?
    }

    func refundTool(_ box: Box) -> PCATool {
        PCATool(metadata: .object(["name": .string("refund"), "description": .string("Refund a charge"), "parameters": .object(["type": .string("object")])])) { args in
            box.ran = args
            return .object(["ok": .bool(true)])
        }
    }

    func testWithPCAEmitsAProofThenRunsTheCall() async throws {
        let a = try agent()
        let box = Box()
        let spec = PCAAdapters.ToolSpec(verb: "stripe.refund", resource: { "charge:\($0.get("charge")?.asString ?? "")" }, onProof: { p, _ in box.proof = p })
        let tool = PCAAdapters.withPCA(a, spec, refundTool(box))
        let args: JSONValue = .object(["amount": .int(20), "currency": .string("usd"), "charge": .string("ch_1")])
        let out = try await tool.call(args)
        XCTAssertEqual(out, .object(["ok": .bool(true)]))
        XCTAssertEqual(box.ran, args)
        let p = try XCTUnwrap(box.proof)
        XCTAssertEqual(p.pcactn.get("aud")?.asString, Self.AUD)
        XCTAssertEqual(p.pcactn.get("action")?.get("resource")?.asString, "charge:ch_1")
        XCTAssertEqual(p.headers["PCA-Action"], PCAIssue.header(p.pcactn))
        XCTAssertTrue(p.dryRun.allowed)
    }

    func testFastFailsAnOverCapCallWithoutRunningIt() async throws {
        let a = try agent()
        let box = Box()
        let tool = PCAAdapters.withPCA(a, PCAAdapters.ToolSpec(verb: "stripe.refund", resource: "charge:ch_1"), refundTool(box))
        do {
            _ = try await tool.call(.object(["amount": .int(9999), "currency": .string("usd"), "charge": .string("ch_1")]))
            XCTFail("an over-cap call must be refused")
        } catch is PCADenied {}
        XCTAssertNil(box.ran)
    }

    func testMetadataIsPreserved() throws {
        let box = Box()
        let tool = PCAAdapters.withPCA(try agent(), PCAAdapters.ToolSpec(verb: "stripe.refund", resource: "charge:ch_1"), refundTool(box))
        XCTAssertEqual(tool.metadata.get("name")?.asString, "refund")
        XCTAssertEqual(tool.metadata.get("description")?.asString, "Refund a charge")
        XCTAssertEqual(tool.metadata.get("parameters"), .object(["type": .string("object")]))
    }

    static func rpc(_ method: String, _ params: JSONValue) -> String {
        Canonical.canonicalize(.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string(method), "params": params]))
    }

    func testPcaFetchAttachesAFreshProofToEveryToolsCall() async throws {
        let a = try agent()
        var seen: [PCAMcp.FetchRequest] = []
        let f = PCAMcp.pcaFetch(a, { c in c.name == "refund" ? (verb: "stripe.refund", resource: "charge:\(c.arguments["chargeId"]?.asString ?? "")") : nil }) { r in
            seen.append(r)
            return PCAMcp.FetchResponse(status: 200, headers: ["content-type": "application/json"], body: "{\"result\":{}}")
        }
        let call = Self.rpc("tools/call", .object(["name": .string("refund"), "arguments": .object(["chargeId": .string("c1"), "amount": .int(5)])]))
        _ = try await f(PCAMcp.FetchRequest(url: "http://x", method: "POST", headers: ["Pca-Action": "stale"], body: call))
        _ = try await f(PCAMcp.FetchRequest(url: "http://x", method: "POST", body: call))
        XCTAssertEqual(seen.count, 2)
        let counters = try seen.map { r -> Int64? in
            let h = try XCTUnwrap(r.headers["PCA-Action"])
            XCTAssertNil(r.headers["Pca-Action"])
            let text = String(decoding: try XCTUnwrap(Base64URLStrict.decode(h)), as: UTF8.self)
            let p = try XCTUnwrap(JSONValue.parse(text))
            XCTAssertEqual(p.get("action")?.get("verb")?.asString, "stripe.refund")
            XCTAssertNotNil(r.headers["PCA-Provenance"])
            return p.get("counter")?.safeInt
        }
        XCTAssertEqual(counters, [1, 2])
    }

    func testPcaFetchPassesEverythingElseThrough() async throws {
        let a = try agent()
        var seen: [PCAMcp.FetchRequest] = []
        let f = PCAMcp.pcaFetch(a, { _ in nil }) { r in seen.append(r); return PCAMcp.FetchResponse(status: 200) }
        let listing = PCAMcp.FetchRequest(url: "http://x", method: "POST", body: Self.rpc("tools/list", .object([:])))
        let unmapped = PCAMcp.FetchRequest(url: "http://x", method: "POST", body: Self.rpc("tools/call", .object(["name": .string("other")])))
        let notJson = PCAMcp.FetchRequest(url: "http://x", method: "POST", body: "not json")
        let get = PCAMcp.FetchRequest(url: "http://x")
        for r in [listing, unmapped, notJson, get] { _ = try await f(r) }
        XCTAssertEqual(seen.count, 4)
        XCTAssertTrue(seen.allSatisfy { $0.headers.isEmpty })
    }

    func testPcaFetchHonoursAnAudienceOverride() async throws {
        let a = try agent()
        var seen: [PCAMcp.FetchRequest] = []
        let f = PCAMcp.pcaFetch(a, { _ in (verb: "stripe.refund", resource: "charge:c") }, aud: "other_server") { r in seen.append(r); return PCAMcp.FetchResponse(status: 200, body: "ok") }
        _ = try await f(PCAMcp.FetchRequest(url: "http://x", method: "POST", body: Self.rpc("tools/call", .object(["name": .string("refund"), "arguments": .object(["chargeId": .string("c")])]))))
        let h = try XCTUnwrap(seen.first?.headers["PCA-Action"])
        let p = try XCTUnwrap(JSONValue.parse(String(decoding: try XCTUnwrap(Base64URLStrict.decode(h)), as: UTF8.self)))
        XCTAssertEqual(p.get("aud")?.asString, "other_server")
    }
}
