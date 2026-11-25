import XCTest
@testable import AtlasPCAVerify

final class RagFilterTests: XCTestCase {
    static let policy: JSONValue = (try? StrictJSON.parseLenient("""
    {"openfga":{"model":{"schema_version":"1.1","type_definitions":[{"type":"user"},{"type":"document","relations":{"viewer":{"this":{}},"can_view":{"computedUserset":{"relation":"viewer"}}}}]},
    "tuples":[{"user":"user:alice","relation":"viewer","object":"document:readme"}]}}
    """)) ?? .null

    static func doc(_ id: String, _ object: String) -> JSONValue { .object(["id": .string(id), "acl": .object(["relation": .string("can_view"), "object": .string(object)])]) }

    func testOnlyWhatThePrincipalMaySeeIsReleasedAndTheDecisionIsKept() throws {
        let docs = [Self.doc("readme", "document:readme"), Self.doc("secret", "document:secret")]
        var asked: [(String, Int?)] = []
        let rec = try ProvenanceRecorder(mediator: "rag", kid: "k1", signer: .ed25519(try PCAEdKey.generate()))
        let r = try PCARag.withPcaFilter({ q, k in asked.append((q, k)); return docs }, principal: .string("user:alice"), policy: Self.policy, recorder: rec)
        XCTAssertNil(r.lastDecision())
        let out = try r.retrieve("what is in the readme", 5)
        XCTAssertEqual(out.map { $0.get("id")?.asString }, ["readme"])
        XCTAssertEqual(asked.count, 1)
        XCTAssertEqual(asked[0].1, 5)
        XCTAssertEqual(r.lastDecision()?.get("allowedIds"), .array([.string("readme")]))
        XCTAssertEqual(r.lastDecision()?.get("droppedIds"), .array([.string("secret")]))
    }

    func testAnUnusablePolicyDropsEverythingAndAMalformedOneThrowsEarly() throws {
        let r = try PCARag.withPcaFilter({ _, _ in [Self.doc("a", "document:readme")] }, principal: .string("user:alice"), policy: .null)
        XCTAssertEqual(try r.retrieve("q").count, 0)
        XCTAssertEqual(r.lastDecision()?.get("policyIncomplete"), .bool(true))
        XCTAssertThrowsError(try PCARag.withPcaFilter({ _, _ in [] }, principal: .string("u"), policy: .object(["predicates": .array([]), "report": .object([:])])))
        let failing = try PCARag.withPcaFilter({ _, _ in throw JSError("retriever down") }, principal: .string("u"), policy: Self.policy)
        XCTAssertThrowsError(try failing.retrieve("q"))
    }
}
