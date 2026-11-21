import XCTest
@testable import AtlasPCAVerify

final class SurfaceAliases5Tests: XCTestCase {
    func testTheDispatcherSkipsDisabledChannels() {
        var sent: [String] = []
        let on = PCAWalletDelivery.questionTextChannel(kind: "email", siteName: .string("Shop"), send: { _ in sent.append("email") })
        let off = PCAWalletDelivery.questionTextChannel(kind: "sms", siteName: .string("Shop"), send: nil)
        let d = PCAWalletDelivery.createQuestionDispatcher([on, off])
        XCTAssertEqual(d.channels.count, 2)
        let out = d.notifyAll(PCAWalletDelivery.clarificationNotice(session: .string("s1"), questionId: .string("q1")))
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].get("kind"), .string("email"))
        XCTAssertEqual(out[0].get("delivered"), .bool(true))
        XCTAssertEqual(sent, ["email"])
    }

    func testImportActionDefsFromMcpReturnsUnreviewedDefsAndTheSource() throws {
        let tools: JSONValue = .array([.object(["name": .string("files_read"), "description": .string("Read a file"),
                                                 "inputSchema": .object(["type": .string("object"), "properties": .object(["path": .object(["type": .string("string")])])])])])
        let r = try PCAMcp.importActionDefsFromMcp(tools, ns: "demo", suggest: "none")
        XCTAssertEqual(r[JKey("defs")]?.asArray?.count, 1)
        XCTAssertNotNil(r[JKey("todo")]?.asArray)
        XCTAssertNotNil(r[JKey("source")])
        let withRules = try PCAMcp.importActionDefsFromMcp(.object(["tools": tools.asArray.map { .array($0) } ?? .null]), ns: "demo")
        XCTAssertEqual(withRules[JKey("defs")]?.asArray?.count, 1)
        XCTAssertThrowsError(try PCAMcp.importActionDefsFromMcp(.string("nope"), ns: "demo"))
    }

    func testATestAgentBuildsPCActnsThatVerifyAndTheCounterAdvances() throws {
        let a = try PCATesting.testAgent()
        let first = try PCATesting.makePCActn(a, "stripe.refund", "stripe:charge/ch_1", params: .object(["amount": .int(100)]), now: 1_800_000_000_000)
        let second = try PCATesting.makePCActn(a, "stripe.refund", "stripe:charge/ch_2", params: .object(["amount": .int(100)]), now: 1_800_000_000_000)
        XCTAssertEqual(first.pcactn.get("counter"), .int(1))
        XCTAssertEqual(second.pcactn.get("counter"), .int(2))
        XCTAssertFalse(first.encoded.isEmpty)
        XCTAssertTrue(try PCATesting.expectVerifies(first.pcactn, PCATesting.FakeVerifyOptions(now: 1_800_000_000_000)).allow)
        let fixed = try PCATesting.makePCActn(a, "stripe.refund", "stripe:charge/ch_3", counter: 40, now: 1_800_000_000_000)
        XCTAssertEqual(fixed.pcactn.get("counter"), .int(40))
        XCTAssertEqual(first.pcactn.get("aud"), .string("ins_test"))
    }
}
