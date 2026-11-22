import XCTest
import OpenAI
import AtlasPCAVerify
@testable import AtlasPCAOpenAI

final class PcaOpenAITests: XCTestCase {
    func agent() throws -> PCAFacadeAgent {
        try PCAAgent.fromPrincipal(PCAAgentOptions(principal: .ed25519(try PCAEdKey.generate()), goal: "refunds", permissions: [("stripe", ["refund"])],
                                                   limits: ["refund": "$500/day"], aud: "ins_test"))
    }

    func call(_ id: String, _ name: String, _ args: String) -> PCAOpenAI.ToolCall {
        .init(id: id, function: .init(arguments: args, name: name))
    }

    let map: PCAAdapters.ToolMapping = { c in c.name == "refund" ? (verb: "stripe.refund", resource: "charge:ch_1") : nil }

    func testDispatchRunsTheHandlerWithTheProofAndReturnsAToolMessage() async throws {
        final class Box: @unchecked Sendable { var proof: PCAActResult?; var args: JSONValue? }
        let box = Box()
        let handlers: [String: PCAOpenAI.Handler] = ["refund": { args, proof in box.proof = proof; box.args = args; return .object(["ok": .bool(true)]) }]
        let msg = try await PCAOpenAI.dispatchToolCall(try agent(), call("call_1", "refund", "{\"amount\":20,\"currency\":\"usd\"}"), map: map, handlers: handlers)
        guard case let .tool(t) = msg else { return XCTFail("a tool message is expected") }
        XCTAssertEqual(t.toolCallId, "call_1")
        XCTAssertEqual(t.content, .textContent("{\"ok\":true}"))
        XCTAssertEqual(box.args?.member("amount"), .int(20))
        XCTAssertEqual(box.proof?.pcactn.member("action")?.member("verb"), .string("stripe.refund"))
        XCTAssertEqual(box.proof?.headers["PCA-Action"], PCAIssue.header(try XCTUnwrap(box.proof).pcactn))
    }

    func testAnUnmappedToolIsNeverRun() async throws {
        do {
            _ = try await PCAOpenAI.dispatchToolCall(try agent(), call("c", "other", "{}"), map: map, handlers: ["other": { _, _ in .null }])
            XCTFail("an unmapped tool must be refused")
        } catch is PCAOpenAI.DispatchError {}
    }

    func testBadArgumentsAreRefused() async throws {
        for raw in ["[1]", "not json", "3"] {
            do {
                _ = try await PCAOpenAI.dispatchToolCall(try agent(), call("c", "refund", raw), map: map, handlers: [:])
                XCTFail("\(raw) must be refused")
            } catch is PCAOpenAI.DispatchError {}
        }
        let empty = try await PCAOpenAI.dispatchToolCall(try agent(), call("c", "refund", "  "), map: map, handlers: [:])
        guard case let .tool(t) = empty, case let .textContent(text) = t.content else { return XCTFail("a tool message is expected") }
        XCTAssertTrue(text.hasPrefix("{\"pca\":\""), text) // no handler: the encoded proof comes back
    }

    func testCountersIncrementPerCall() async throws {
        var seen: [Int64] = []
        let handlers: [String: PCAOpenAI.Handler] = ["refund": { _, p in seen.append(p.pcactn.member("counter").flatMap { if case let .int(i) = $0 { return i } else { return nil } } ?? -1); return nil }]
        _ = try await PCAOpenAI.dispatchToolCalls(try agent(), [call("a", "refund", "{}"), call("b", "refund", "{}")], map: map, handlers: handlers, counter: 5)
        XCTAssertEqual(seen, [5, 6])
    }

    func testConversationRecordsEachMessageOnce() throws {
        let a = try agent()
        let conv = PCAOpenAI.Conversation(a)
        let msgs: [PCAOpenAI.Message] = [.user(.init(content: .string("refund ch_1"))), .tool(.init(content: .textContent("{}"), toolCallId: "c1"))]
        try conv.record(msgs)
        try conv.record(msgs) // nothing new
        try conv.record(msgs + [.user(.init(content: .string("thanks")))])
    }
}

extension JSONValue {
    func member(_ key: String) -> JSONValue? { if case let .object(o) = self { return o[JKey(key)] } else { return nil } }
}
