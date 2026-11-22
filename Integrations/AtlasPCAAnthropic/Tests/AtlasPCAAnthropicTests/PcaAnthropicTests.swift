import XCTest
import SwiftAnthropic
import AtlasPCAVerify
@testable import AtlasPCAAnthropic

final class PcaAnthropicTests: XCTestCase {
    func agent() throws -> PCAFacadeAgent {
        try PCAAgent.fromPrincipal(PCAAgentOptions(principal: .ed25519(try PCAEdKey.generate()), goal: "refunds", permissions: [("stripe", ["refund"])],
                                                   limits: ["refund": "$500/day"], aud: "ins_test"))
    }

    /// A ToolUse as the API delivers it: decoded from JSON (its memberwise initializer is not public).
    func use(_ id: String, _ name: String, _ input: [String: Any] = ["amount": 20, "currency": "usd"]) throws -> PCAAnthropic.ToolUse {
        try JSONDecoder().decode(PCAAnthropic.ToolUse.self, from: try JSONSerialization.data(withJSONObject: ["id": id, "name": name, "input": input], options: []))
    }

    let map: PCAAdapters.ToolMapping = { c in c.name == "refund" ? (verb: "stripe.refund", resource: "charge:ch_1") : nil }

    func testHandleToolUseReturnsAToolResult() async throws {
        let u = try use("toolu_1", "refund")
        let handlers: [String: PCAAnthropic.Handler] = ["refund": { _, _ in .object(["ok": .bool(true)]) }]
        let r = try await PCAAnthropic.handleToolUse(try agent(), u, map: map, handlers: handlers)
        guard case let .toolResult(id, content, isError, _) = r else { return XCTFail("a tool_result is expected") }
        XCTAssertEqual(id, "toolu_1")
        XCTAssertNil(isError)
        guard case let .text(text)? = content.first else { return XCTFail("text content is expected") }
        XCTAssertEqual(text, "{\"ok\":true}")
    }

    func testUnmappedAndHandlerlessToolsAreErrorsAndNeverRun() async throws {
        let a = try agent()
        let other = try use("t2", "other")
        let r1 = try await PCAAnthropic.handleToolUse(a, other, map: map, handlers: ["other": { _, _ in .null }])
        guard case let .toolResult(_, _, e1, _) = r1 else { return XCTFail("a tool_result is expected") }
        XCTAssertEqual(e1, true)
        let r2 = try await PCAAnthropic.handleToolUse(a, try use("t3", "refund"), map: map, handlers: [:])
        guard case let .toolResult(_, _, e2, _) = r2 else { return XCTFail("a tool_result is expected") }
        XCTAssertEqual(e2, true)
    }

    func testAThrowingHandlerIsAnErrorResult() async throws {
        struct Boom: Error, CustomStringConvertible { var description: String { "boom" } }
        let r = try await PCAAnthropic.handleToolUse(try agent(), try use("t4", "refund"), map: map, handlers: ["refund": { _, _ in throw Boom() }])
        guard case let .toolResult(_, content, isError, _) = r, case let .text(t)? = content.first else { return XCTFail("a tool_result is expected") }
        XCTAssertEqual(isError, true)
        XCTAssertEqual(t, "boom")
    }

    func testInputConversion() {
        let v = PCAAnthropic.jsonObject(["a": .integer(1), "b": .array([.string("x"), .null, .bool(true)]), "c": .dictionary(["d": .double(1.5)])])
        XCTAssertEqual(v.canonicalText, "{\"a\":1,\"b\":[\"x\",null,true],\"c\":{\"d\":1.5}}")
    }
}
