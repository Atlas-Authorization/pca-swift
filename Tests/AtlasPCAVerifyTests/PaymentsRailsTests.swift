import XCTest
import Foundation
@testable import AtlasPCAVerify

final class PaymentsRailsTests: XCTestCase {
    typealias Pay = PCAPayments

    final class Wire: @unchecked Sendable {
        var posts: [(String, JSONValue)] = []
        var tokenRef = "tok_0123456789abcdef"
        lazy var transport = Pay.PartnerTransport(post: { [unowned self] path, body in
            self.posts.append((path, body))
            return .object(["token_ref": .string(self.tokenRef)])
        })
    }

    static let limits: JSONValue = .object(["currency": .string("USD"), "perAuthorizationMax": .int(500), "totalMax": .int(2000), "categories": .array([.string("5734")]),
                                            "merchants": .array([.string("m1")]), "expiresAt": .int(1_900_000_000_000)])
    static let grant: JSONValue = .object(["issuer": .string("i"), "holder": .string("h"), "caveats": .array([])])

    func testIssueBindsTheTokenAndTheControlsAreACopyOfTheLimits() throws {
        let wire = Wire()
        let key = try PCAEdKey(seed: [UInt8](repeating: 5, count: 32))
        let provider = Pay.visaIntelligentCommerceAdapter(wire.transport)
        XCTAssertEqual(provider.id, "visa_ic")
        let out = try Pay.issueBoundNetworkToken(provider: provider, limits: Self.limits, grant: Self.grant, agentId: "agent-1", holder: key, holderPublic: key.pub,
                                                 issuerNonce: "nonce-0123456789abcdef")
        XCTAssertEqual(wire.posts[0].0, "/tokens")
        let scope = wire.posts[0].1.get("instructions")
        XCTAssertEqual(scope?.get("per_authorization_max"), .int(500))
        XCTAssertEqual(scope?.get("merchant_categories"), .array([.string("5734")]))
        XCTAssertEqual(scope?.get("expires_at"), .int(1_900_000_000_000))
        XCTAssertEqual(wire.posts[0].1.get("agent_id"), .string("agent-1"))
        let binding = out.get("binding") ?? .null
        XCTAssertNil(Pay.verifyNetworkTokenBinding(binding, .object(["grant": Self.grant, "holder": .string(key.id), "issuerNonce": .string("nonce-0123456789abcdef"), "provider": .string("visa_ic")])))
        XCTAssertEqual(out.get("controls")?.get("totalMax"), .int(2000))

        let mc = Pay.mastercardAgentPayAdapter(wire.transport)
        XCTAssertEqual(mc.id, "mastercard_agent_pay")
        _ = try Pay.issueBoundNetworkToken(provider: mc, limits: Self.limits, grant: Self.grant, agentId: "a", holder: key, holderPublic: key.pub, issuerNonce: "nonce-0123456789abcdef")
        XCTAssertNotNil(wire.posts[1].1.get("session_scope"))

        try Pay.suspendOnRevoke(provider, binding)
        XCTAssertEqual(wire.posts.last?.0, "/tokens/tok_0123456789abcdef/suspend".replacingOccurrences(of: ":", with: ":"))
        XCTAssertEqual(wire.posts.last?.1.get("reason"), .string("grant_revoked"))
    }

    func testAPanShapedOrMalformedProviderReferenceIsRefused() throws {
        let key = try PCAEdKey(seed: [UInt8](repeating: 5, count: 32))
        for bad in ["4111111111111111", "short"] {
            let wire = Wire()
            wire.tokenRef = bad
            XCTAssertThrowsError(try Pay.issueBoundNetworkToken(provider: Pay.visaIntelligentCommerceAdapter(wire.transport), limits: Self.limits, grant: Self.grant, agentId: "a",
                                                                 holder: key, holderPublic: key.pub, issuerNonce: "nonce-0123456789abcdef"))
        }
    }

    func testTheRailAuthorizerDeclinesEveryUnknown() throws {
        let store = Pay.memoryChargeBudgetStore()
        let authorize = try Pay.createRailAuthorizer(Pay.RailAuthorizerOptions(instruments: { _ in nil }, store: store))
        func reasons(_ a: JSONValue) -> [JSONValue] { authorize(a).get("reasons")?.asArray ?? [] }
        XCTAssertEqual(authorize(.null).get("approved"), .bool(false))
        XCTAssertEqual(reasons(.null), [.string("malformed_authorization")])
        let base: JObject = ["id": .string("a1"), "instrumentId": .string("c1"), "amount": .int(100), "currency": .string("usd"), "merchantId": .string("m1")]
        XCTAssertEqual(reasons(.object(base)), [.string("instrument_unknown")])
        var o = base; o["amount"] = .int(0)
        XCTAssertEqual(reasons(.object(o)), [.string("amount_not_positive_minor_units")])
        o = base; o["currency"] = .string("")
        XCTAssertEqual(reasons(.object(o)), [.string("currency_missing")])
        o = base; o["merchantId"] = nil
        XCTAssertEqual(reasons(.object(o)), [.string("merchant_unknown")])
        XCTAssertThrowsError(try Pay.createRailAuthorizer(Pay.RailAuthorizerOptions(instruments: { _ in nil }, store: store, latencyBudgetMs: 0)))
    }

    func testASlowLookupIsDeclinedWithinTheBudget() throws {
        let slow = try Pay.createRailAuthorizer(Pay.RailAuthorizerOptions(instruments: { _ in Thread.sleep(forTimeInterval: 0.4); return nil }, store: Pay.memoryChargeBudgetStore(),
                                                                          latencyBudgetMs: 50))
        let v = slow(.object(["id": .string("a1"), "instrumentId": .string("c1"), "amount": .int(100), "currency": .string("usd"), "merchantId": .string("m1")]))
        XCTAssertEqual(v.get("reasons"), .array([.string("latency_budget_exceeded")]))
    }

    func testTheMemoryBudgetStoreIsACompareAndSet() throws {
        let s = Pay.memoryChargeBudgetStore()
        XCTAssertNil(try s.get("k"))
        XCTAssertFalse(try s.compareAndSet("k", 3, .object(["B": .int(1)])))
        XCTAssertTrue(try s.compareAndSet("k", nil, .object(["B": .int(1)])))
        XCTAssertFalse(try s.compareAndSet("k", nil, .object(["B": .int(2)])))
        XCTAssertEqual(try s.get("k")?.get("version"), .int(1))
        XCTAssertTrue(try s.compareAndSet("k", 1, .object(["B": .int(2)])))
        XCTAssertEqual(try s.get("k")?.get("budget"), .object(["B": .int(2)]))
        XCTAssertEqual(Pay.MCC_TRAIT_RE, "^mcc\\.c(\\d{4})$")
    }
}
