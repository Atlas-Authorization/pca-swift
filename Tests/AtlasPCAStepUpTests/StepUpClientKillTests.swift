import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import AtlasPCAStepUp

/// Answers every request with a plain (non-HTTP) URLResponse.
final class NonHTTPProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        client?.urlProtocol(self, didReceive: URLResponse(url: request.url!, mimeType: nil, expectedContentLength: 0, textEncodingName: nil), cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data())
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class StepUpClientKillTests: XCTestCase {
    static let su = PendingStepUp(id: "s", grantRef: "g", actionVerb: "v", actionResource: "r", requiredT: 3, thresholdMessageB64u: "AAEC", expiresAt: Date().addingTimeInterval(60))

    func client(dashboard: URL = URL(string: "https://api.example")!, proto: AnyClass = MockProtocol.self) throws -> StepUpClient {
        let key = PrincipalDeviceKey(store: InMemorySecretStore()); _ = try key.generate()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [proto]
        MockProtocol.seen = []
        return StepUpClient(dashboardURL: dashboard, instanceURL: URL(string: "https://inst.example")!,
                            accountId: "acc", instanceId: "ins", token: { "dsk_x" }, key: key, session: URLSession(configuration: cfg))
    }

    func wire(_ exp: String) throws -> WireStepUp {
        try JSONDecoder().decode(WireStepUp.self, from: Data(#"{"id":"x","grant_ref":"g","action":{"verb":"v","resource":"r"},"required_t":2,"threshold_message":"AA","expires_at":"\#(exp)"}"#.utf8))
    }

    func testAnEntryExpiringExactlyNowHasExpired() throws {
        let now = ISO8601.parse("2030-01-01T00:00:00Z")!
        XCTAssertEqual(StepUpClient.unexpired([try wire("2030-01-01T00:00:00Z")], now: now), [])
        XCTAssertEqual(StepUpClient.unexpired([try wire("2030-01-01T00:00:01Z")], now: now).map(\.id), ["x"])
    }

    func testRelativeDashboardURLKeepsItsBase() async throws {
        let dash = URL(string: "api/", relativeTo: URL(string: "https://dash.example/")!)!
        MockProtocol.handler = { _ in (200, #"{"stepups":[]}"#) }
        let items = try await client(dashboard: dash).pending()
        XCTAssertEqual(items, [])
        XCTAssertEqual(MockProtocol.seen.last?.0.url?.host, "dash.example")
        XCTAssertEqual(MockProtocol.seen.last?.0.url?.path, "/api/v1/dashboard/accounts/acc/instances/ins/pca/stepups")
    }

    func testApproveWithoutAllowIsNotAnchored() async throws {
        MockProtocol.handler = { _ in (202, #"{"status":"pending"}"#) }
        let r = try await client().approve(Self.su)
        XCTAssertEqual(r, ApproveResult(status: "pending", anchored: false, httpStatus: 202))
        XCTAssertFalse(r.anchored)
    }

    func testStatusRangeEdges() async throws {
        MockProtocol.handler = { _ in (299, "{}") }
        try await client().deny(Self.su)
        MockProtocol.handler = { _ in (200, "{}") }
        try await client().deny(Self.su)
        MockProtocol.handler = { _ in (300, "{}") }
        do { try await client().deny(Self.su); XCTFail("300 must throw") }
        catch let e as StepUpError { XCTAssertEqual(e, .api(status: 300, message: "The request failed.")) }
    }

    func testANonHTTPResponseIsStatusZero() async throws {
        do { try await client(proto: NonHTTPProtocol.self).deny(Self.su); XCTFail("must throw") }
        catch let e as StepUpError { XCTAssertEqual(e, .api(status: 0, message: "The request failed.")) }
    }
}
