import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The CIBA relying-party client over a scripted provider (no network): hints, ping tokens, poll discipline, slow_down, terminal answers cached.
final class CibaClientTests: XCTestCase {
    typealias C = PCACiba

    final class Script: @unchecked Sendable {
        var calls: [(url: String, headers: [String: String], body: String)] = []
        var replies: [(Int, String)] = []
        var clock = 1_000_000.0
        var slept: [Double] = []
        func fetch(_ url: String, _ h: [String: String], _ b: String, _ t: Double) throws -> (status: Int, body: String) {
            calls.append((url, h, b))
            guard !replies.isEmpty else { throw JSError("no scripted reply") }
            let r = replies.removeFirst()
            return (r.0, r.1)
        }
    }

    static let stepUp: JSONValue = .object(["id": .string("su-1"), "verb": .string("payments.send"), "resource": .string("acct:approve"), "tier": .int(2), "reason": .string("risk"), "goalCommit": .string("abcdefghijklmnop")])

    func client(_ s: Script) throws -> C.Client {
        try C.createCibaClient(C.ClientConfig(backchannelAuthenticationEndpoint: "https://op.example/bc", tokenEndpoint: "https://op.example/token", clientId: "cid x", clientSecret: "sec/ret",
                                              fetch: { try s.fetch($0, $1, $2, $3) }, sleep: { s.slept.append($0); s.clock += $0 }, now: { s.clock }))
    }

    func testEndpointsMustBeHttpsAndTheHintIsExactlyOne() throws {
        let s = Script()
        XCTAssertThrowsError(try C.createCibaClient(C.ClientConfig(backchannelAuthenticationEndpoint: "http://op.example/bc", tokenEndpoint: "https://op.example/t", clientId: "a", clientSecret: "b")))
        XCTAssertNoThrow(try C.createCibaClient(C.ClientConfig(backchannelAuthenticationEndpoint: "http://op.example/bc", tokenEndpoint: "http://op.example/t", clientId: "a", clientSecret: "b",
                                                               allowInsecureHttp: true)))
        XCTAssertThrowsError(try C.createCibaClient(C.ClientConfig(backchannelAuthenticationEndpoint: "nope", tokenEndpoint: "https://op.example/t", clientId: "a", clientSecret: "b")))
        let c = try client(s)
        XCTAssertThrowsError(try c.initiate(Self.stepUp, C.InitiateOptions()))
        XCTAssertThrowsError(try c.initiate(Self.stepUp, C.InitiateOptions(loginHint: "a", idTokenHint: "b")))
        XCTAssertThrowsError(try c.initiate(Self.stepUp, C.InitiateOptions(loginHint: "a", delivery: "ping", clientNotificationToken: "short")))
        XCTAssertTrue(s.calls.isEmpty)
    }

    func testInitiateSendsBasicAuthAndTheFormAndReadsTheReply() throws {
        let s = Script()
        s.replies = [(200, "{\"auth_req_id\":\"ar1\",\"expires_in\":120}")]
        let flow = try client(s).initiate(Self.stepUp, C.InitiateOptions(loginHint: "alice@example.com", delivery: "ping"))
        XCTAssertEqual(flow.authReqId, "ar1")
        XCTAssertEqual(flow.intervalSec, 5)
        XCTAssertEqual(flow.expiresInSec, 120)
        XCTAssertNotNil(flow.clientNotificationToken)
        let call = s.calls[0]
        XCTAssertEqual(call.url, "https://op.example/bc")
        XCTAssertEqual(call.headers["authorization"], "Basic " + Data("cid%20x:sec%2Fret".utf8).base64EncodedString())
        XCTAssertEqual(call.headers["content-type"], "application/x-www-form-urlencoded")
        XCTAssertTrue(call.body.contains("login_hint=alice%40example.com"))
        XCTAssertTrue(call.body.contains("client_notification_token="))
        XCTAssertTrue(call.body.hasPrefix("scope="))
        s.replies = [(400, "{\"error\":\"invalid_request\",\"error_description\":\"bad\"}")]
        XCTAssertThrowsError(try client(s).initiate(Self.stepUp, C.InitiateOptions(loginHint: "a"))) { XCTAssertEqual(($0 as? C.ProviderError)?.error, "invalid_request") }
        s.replies = [(200, "{\"auth_req_id\":\"\",\"expires_in\":120}")]
        XCTAssertThrowsError(try client(s).initiate(Self.stepUp, C.InitiateOptions(loginHint: "a")))
        s.replies = [(200, "not json")]
        XCTAssertThrowsError(try client(s).initiate(Self.stepUp, C.InitiateOptions(loginHint: "a"))) { XCTAssertEqual(($0 as? C.ProviderError)?.retryable, true) }
    }

    func testThePollerKeepsTheIntervalSlowsDownAndCachesTheTerminalAnswer() throws {
        let s = Script()
        s.replies = [(200, "{\"auth_req_id\":\"ar1\",\"expires_in\":600,\"interval\":2}")]
        let c = try client(s)
        let flow = try c.initiate(Self.stepUp, C.InitiateOptions(loginHint: "a"))
        let p = c.poller(flow)
        s.replies = [(400, "{\"error\":\"authorization_pending\"}"), (400, "{\"error\":\"slow_down\"}"), (200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}")]
        XCTAssertEqual(try p.poll(), .pending(intervalSec: 2))
        XCTAssertEqual(s.slept.first ?? 0, 2000, accuracy: 1) // never faster than the OP's interval
        XCTAssertEqual(try p.poll(), .pending(intervalSec: 7)) // slow_down adds 5 s
        let done = try p.wait()
        guard case let .approved(tokens) = done else { return XCTFail("\(done)") }
        XCTAssertEqual(tokens.get("access_token"), .string("at"))
        let before = s.calls.count
        XCTAssertEqual(try p.poll(), done) // a settled flow is never re-sent
        XCTAssertEqual(s.calls.count, before)
        XCTAssertTrue(s.calls.last!.body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Aciba") || s.calls.last!.body.contains("urn%3Aopenid%3Aparams%3Agrant-type%3Aciba"))
    }

    func testDeniedExpiredAndTheDeadline() throws {
        let s = Script()
        s.replies = [(200, "{\"auth_req_id\":\"ar1\",\"expires_in\":10,\"interval\":1}")]
        let c = try client(s)
        let flow = try c.initiate(Self.stepUp, C.InitiateOptions(loginHint: "a"))
        s.replies = [(400, "{\"error\":\"access_denied\"}")]
        XCTAssertEqual(try c.poller(flow).wait(), .denied(error: "access_denied"))
        s.replies = [(400, "{\"error\":\"expired_token\"}")]
        XCTAssertEqual(try c.poller(flow).poll(), .expired)
        s.clock += 60_000
        s.replies = []
        XCTAssertEqual(try c.poller(flow).poll(), .expired) // past expires_in nothing is sent
        s.replies = [(400, "{\"error\":\"invalid_client\"}")]
        s.clock = flow.startedAt
        XCTAssertThrowsError(try c.poller(flow).poll()) { XCTAssertEqual(($0 as? C.ProviderError)?.error, "invalid_client") }
    }

    func testServerErrorsAreRetriedByWaitThenGiveUp() throws {
        let s = Script()
        s.replies = [(200, "{\"auth_req_id\":\"ar1\",\"expires_in\":6000,\"interval\":1}")]
        let c = try client(s)
        let flow = try c.initiate(Self.stepUp, C.InitiateOptions(loginHint: "a"))
        s.replies = [(503, "x"), (503, "x"), (400, "{\"error\":\"access_denied\"}")]
        XCTAssertEqual(try c.poller(flow).wait(), .denied(error: "access_denied"))
        s.replies = Array(repeating: (503, "x"), count: 6)
        XCTAssertThrowsError(try c.poller(flow).wait()) { XCTAssertEqual(($0 as? C.ProviderError)?.status, 503) }
    }

    func testAnAbortedWaitStops() throws {
        let s = Script()
        s.replies = [(200, "{\"auth_req_id\":\"ar1\",\"expires_in\":600}")]
        let c = try client(s)
        let p = c.poller(try c.initiate(Self.stepUp, C.InitiateOptions(loginHint: "a")))
        let sig = C.AbortSignal()
        sig.abort()
        XCTAssertThrowsError(try p.wait(sig))
    }
}
