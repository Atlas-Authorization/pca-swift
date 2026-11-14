import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import AtlasPCAStepUp

/// Kills the StepUpClient.swift survivors of group 2: the list query, the list status check, and the request headers of approve / deny.
final class S2G2StepUpClientKillTests: XCTestCase {
    static let su = PendingStepUp(id: "s", grantRef: "g", actionVerb: "v", actionResource: "r", requiredT: 3, thresholdMessageB64u: "AAEC", expiresAt: Date().addingTimeInterval(60))

    private func client() throws -> StepUpClient {
        let key = PrincipalDeviceKey(store: InMemorySecretStore())
        _ = try key.generate()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [MockProtocol.self]
        MockProtocol.seen = []
        return StepUpClient(dashboardURL: URL(string: "https://api.example")!, instanceURL: URL(string: "https://inst.example")!,
                            accountId: "acc", instanceId: "ins", token: { "dsk_x" }, key: key, session: URLSession(configuration: cfg))
    }

    func testPendingAsksForPendingEntries() async throws {
        MockProtocol.handler = { _ in (200, #"{"stepups":[]}"#) }
        let items = try await client().pending()
        XCTAssertEqual(items, [])
        XCTAssertEqual(MockProtocol.seen.last?.0.url?.query, "status=pending", "line 53")
    }

    func testPendingChecksTheStatus() async throws {
        MockProtocol.handler = { _ in (500, #"{"stepups":[]}"#) }
        do {
            _ = try await client().pending()
            XCTFail("a 500 must throw even when the body parses (line 57)")
        } catch let e as StepUpError {
            XCTAssertEqual(e, .api(status: 500, message: "The request failed."))
        }
    }

    func testApproveSendsJSON() async throws {
        MockProtocol.handler = { _ in (200, #"{"status":"anchored","allow":true}"#) }
        let r = try await client().approve(Self.su)
        XCTAssertTrue(r.anchored)
        let req = try XCTUnwrap(MockProtocol.seen.last?.0)
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Type"), "application/json", "line 82")
    }

    func testDenySendsAnAuthenticatedJSONPost() async throws {
        MockProtocol.handler = { _ in (200, "{}") }
        try await client().deny(Self.su)
        let req = try XCTUnwrap(MockProtocol.seen.last?.0)
        XCTAssertEqual(req.httpMethod, "POST", "line 94")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Type"), "application/json", "line 95")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer dsk_x", "line 96")
        XCTAssertEqual(req.url?.path, "/v1/dashboard/accounts/acc/instances/ins/pca/stepups/s/deny")
    }
}
