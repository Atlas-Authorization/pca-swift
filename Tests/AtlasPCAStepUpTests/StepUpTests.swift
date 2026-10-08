import XCTest
import CryptoKit
@testable import AtlasPCAStepUp

final class MockProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (Int, String))?
    nonisolated(unsafe) static var seen: [(URLRequest, Data?)] = []
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        var body: Data? = request.httpBody
        if body == nil, let s = request.httpBodyStream {
            s.open(); var d = Data(); var buf = [UInt8](repeating: 0, count: 4096)
            while s.hasBytesAvailable { let n = s.read(&buf, maxLength: 4096); if n <= 0 { break }; d.append(buf, count: n) }
            body = d
        }
        Self.seen.append((request, body))
        let (code, text) = Self.handler!(request)
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(text.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class StepUpTests: XCTestCase {
    func client(_ key: PrincipalDeviceKey) -> StepUpClient {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [MockProtocol.self]
        MockProtocol.seen = []
        return StepUpClient(dashboardURL: URL(string: "https://api.example")!, instanceURL: URL(string: "https://inst.example")!,
                            accountId: "acc", instanceId: "ins", token: { "dsk_x" }, key: key, session: URLSession(configuration: cfg))
    }

    func testBase64URLRoundTrip() {
        for n in 0..<40 {
            let d = Data((0..<n).map { UInt8(($0 * 37 + 250) & 0xff) })
            XCTAssertEqual(Base64URL.decode(Base64URL.encode(d)), d)
        }
        XCTAssertNil(Base64URL.decode("a"))
    }

    func testKeyGenerateExportImportSign() throws {
        let k = PrincipalDeviceKey(store: InMemorySecretStore())
        XCTAssertFalse(k.exists)
        let pub = try k.generate()
        let k2 = PrincipalDeviceKey(store: InMemorySecretStore())
        XCTAssertEqual(try k2.importSecret(try k.exportSecret()), pub)
        let msg = Data("hello".utf8)
        let sig = Base64URL.decode(try k2.sign(msg))!
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: Base64URL.decode(pub)!)
        XCTAssertTrue(pk.isValidSignature(sig, for: msg))
        XCTAssertThrowsError(try k2.importSecret("AAAA"))
        XCTAssertThrowsError(try PrincipalDeviceKey(store: InMemorySecretStore()).sign(msg))
    }

    func testListApproveDeny() async throws {
        let key = PrincipalDeviceKey(store: InMemorySecretStore()); let pub = try key.generate()
        let msg = Data([1, 2, 3, 250, 251])
        let exp = ISO8601DateFormatter().string(from: Date().addingTimeInterval(600))
        let list = #"{"stepups":[{"id":"su_1","grant_ref":"g1","action":{"verb":"pay","resource":"order/1"},"required_t":3,"threshold_message":"\#(Base64URL.encode(msg))","created_at":"x","expires_at":"\#(exp)","status":"pending"},{"id":"su_old","grant_ref":"g1","action":{"verb":"v","resource":"r"},"required_t":3,"threshold_message":"AA","created_at":"x","expires_at":"2001-01-01T00:00:00Z","status":"pending"}]}"#
        MockProtocol.handler = { req in
            let p = req.url!.path
            if req.httpMethod == "GET" { return (200, list) }
            if p.hasSuffix("/cosign") { return (200, #"{"status":"approved","allow":true}"#) }
            return (200, "{}")
        }
        let c = client(key)
        let items = try await c.pending()
        XCTAssertEqual(items.map(\.id), ["su_1"])
        XCTAssertEqual(items[0].actionVerb, "pay")
        XCTAssertEqual(MockProtocol.seen[0].0.value(forHTTPHeaderField: "Authorization"), "Bearer dsk_x")

        let r = try await c.approve(items[0])
        XCTAssertTrue(r.anchored)
        let body = try JSONSerialization.jsonObject(with: MockProtocol.seen.last!.1!) as! [String: String]
        XCTAssertEqual(body["role"], "principal"); XCTAssertEqual(body["publicKey"], pub)
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: Base64URL.decode(pub)!)
        XCTAssertTrue(pk.isValidSignature(Base64URL.decode(body["sig"]!)!, for: msg))
        XCTAssertEqual(MockProtocol.seen.last!.0.url!.host, "inst.example")

        try await c.deny(items[0], reason: "no")
        XCTAssertTrue(MockProtocol.seen.last!.0.url!.path.hasSuffix("/su_1/deny"))
    }

    func testPrincipalMismatchSurfacesGuidance() async throws {
        let key = PrincipalDeviceKey(store: InMemorySecretStore()); _ = try key.generate()
        MockProtocol.handler = { _ in (403, #"{"errors":[{"code":"forbidden","message":"The share is not from this grant's principal key."}]}"#) }
        let su = PendingStepUp(id: "s", grantRef: "g", actionVerb: "v", actionResource: "r", requiredT: 3, thresholdMessageB64u: "AAEC", expiresAt: Date().addingTimeInterval(60))
        do { _ = try await client(key).approve(su); XCTFail() }
        catch let StepUpError.principalMismatch(m) { XCTAssertTrue(m.contains("principal key")) }
    }
}
