import XCTest
@testable import AtlasPCAVerify

final class SurfaceAliases4Tests: XCTestCase {
    func testTheDefaultRegistryHelpers() throws {
        let ids = PCAConnectors.listProviders().map { $0.id }
        XCTAssertTrue(ids.contains("github"))
        XCTAssertEqual(ids, ids.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) })
        XCTAssertEqual(PCAConnectors.getProvider("github")?.id, "github")
        XCTAssertNil(PCAConnectors.getProvider("no-such-provider"))
        // a registered id is never swapped silently
        let github = PCAConnectors.Providers.github.json
        XCTAssertThrowsError(try PCAConnectors.registerProvider(github))
        XCTAssertNoThrow(try PCAConnectors.registerProvider(github, replace: true))
        XCTAssertThrowsError(try PCAConnectors.registerProvider(github, replace: true, expectedDigest: "sha256:nope"))
        XCTAssertThrowsError(try PCAConnectors.registerProvider(.object([:])))
    }

    func testThePassportRegistryKeepsFirstPositionAndLastValue() {
        let r = PassportRegistry([["id": .string("a"), "v": .int(1)], ["id": .string("b")], ["id": .string("a"), "v": .int(2)]])
        XCTAssertEqual(r.all().map { JS.toString($0["id"]) }, ["a", "b"])
        XCTAssertEqual(r.get("a")?["v"], .int(2))
        XCTAssertTrue(r.has("b"))
        XCTAssertFalse(r.has("c"))
        XCTAssertNil(r.get("c"))
    }

    func testPushShapesAndPostsThePayload() throws {
        var seen: (String, [String: String], String)?
        let target = PCAScim.PushTarget(endpoint: "https://dir.example/Users", token: "t0k", fetch: { u, h, b in seen = (u, h, b); return (201, "{\"id\":\"x\"}") })
        let agent: JObject = ["id": .string("agent-1"), "displayName": .string("Agent"), "active": .bool(true)]
        let r = try PCAScim.pushToEntra(agent, target)
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.status, 201)
        XCTAssertEqual(r.body.get("id"), .string("x"))
        XCTAssertEqual(seen?.0, "https://dir.example/Users")
        XCTAssertEqual(seen?.1["authorization"], "Bearer t0k")
        XCTAssertEqual(seen?.1["content-type"], "application/scim+json")
        XCTAssertEqual(seen?.2, JS.stringify(PCAScim.toEntraAgentPayload(agent)))
        let bad = PCAScim.PushTarget(endpoint: "u", token: "t", fetch: { _, _, _ in (500, "not json") })
        let rb = try PCAScim.pushToOkta(agent, bad)
        XCTAssertFalse(rb.ok)
        XCTAssertEqual(rb.body, .null)
    }
}
