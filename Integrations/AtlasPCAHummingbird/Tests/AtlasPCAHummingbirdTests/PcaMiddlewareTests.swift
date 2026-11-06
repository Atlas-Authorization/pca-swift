import XCTest
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import NIOCore
import Foundation
import AtlasPCAVerify
import AtlasPCAHummingbird

/// A real signed PCActn from the shared authorize fixtures (the first case: a $50 payment under a $100 envelope), read with Foundation only.
struct Fixture {
    let now: Int64
    let audience: String
    let grant: JSONValue
    let pcactnText: String
    let verb: String
    let resource: String
    let paramsText: String

    static func load() throws -> Fixture {
        // …/Integrations/AtlasPCAHummingbird/Tests/AtlasPCAHummingbirdTests/<file> -> the core package's test-data
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        url.appendPathComponent("test-data/authorize-fixtures.json")
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let c = try XCTUnwrap((root["cases"] as? [[String: Any]])?.first)
        let s = try XCTUnwrap((c["steps"] as? [[String: Any]])?.first)
        let op = try XCTUnwrap(s["operation"] as? [String: Any])
        func text(_ v: Any?) throws -> String {
            let d = try JSONSerialization.data(withJSONObject: try XCTUnwrap(v), options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed])
            // Foundation prints some doubles with 17+ digits (0.8 -> 0.8000000000000000444), which the strict wire profile refuses: re-print canonically.
            return try XCTUnwrap(JSONValue.parse(String(decoding: d, as: UTF8.self))).canonicalText
        }
        func int64(_ v: Any?) -> Int64? {
            if let i = v as? Int64 { return i }
            if let i = v as? Int { return Int64(i) }
            return (v as? NSNumber)?.int64Value
        }
        return Fixture(now: try XCTUnwrap(int64(root["now"])), audience: try XCTUnwrap(root["audience"] as? String),
                       grant: try XCTUnwrap(JSONValue.parse(try text(c["grant"]))), pcactnText: try text(s["pcactn"]),
                       verb: try XCTUnwrap(op["verb"] as? String), resource: try XCTUnwrap(op["resource"] as? String), paramsText: try text(op["params"]))
    }

    var header: String {
        Data(pcactnText.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    /// Provenance by default: the harness recorder (Ed25519 seed = 32 bytes of 0x01, mediator `conformance-harness`, kid `k1`), whose
    /// pin the guard trusts; every request here comes straight from the principal.
    static func provRecorder() throws -> ProvenanceRecorder {
        try ProvenanceRecorder(mediator: "conformance-harness", kid: "k1", secretKey: [UInt8](repeating: 1, count: 32))
    }

    static let provPin: JSONValue = (try? provRecorder().pin) ?? .null

    /// The principal-direct bundle of the operation the mapper derives from `body` (nil when the body is not JSON).
    func provBundle(_ body: String) -> JSONValue? {
        guard let params = JSONValue.parse(body), let r = try? Fixture.provRecorder() else { return nil }
        return try? PCA.principalDirectProvenance(r, PCA.Operation(verb: verb, resource: resource, params: params))
    }

    /// The `PCA-Provenance` header value for `body`.
    func provHeader(_ body: String) -> String? { provBundle(body).map(ProvenanceRecorder.header) }

    func config(store: PCAStateStore = MemoryStateStore(), signatureOnly: Bool = false, revoked: Bool = false, executor: PcaGuardExecutorConfig? = nil) -> PcaGuardConfig {
        let g = grant
        let verb = verb, resource = resource
        let mapper: (PcaGuardRequest) throws -> PCA.Operation? = { req in
            guard let params = JSONValue.parse(String(decoding: req.body, as: UTF8.self)) else { return nil }
            return PCA.Operation(verb: verb, resource: resource, params: params)
        }
        var az = PcaAuthorizeConfig(stateStore: store, isRevoked: { _, _ in revoked }, operation: mapper)
        az.argProvenance.mediators = [Fixture.provPin]
        return PcaGuardConfig(audience: audience, resolveGrant: { _ in g }, now: { self.now }, signatureOnly: signatureOnly,
                              authorize: signatureOnly ? nil : az, executor: executor)
    }
}

struct TestContext: PcaRequestContext {
    var coreContext: CoreRequestContextStorage
    var pca: PcaGuardAllow?
    init(source: Source) {
        coreContext = .init(source: source)
        pca = nil
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func bump() { lock.lock(); n += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
}

final class PcaMiddlewareTests: XCTestCase {
    static let pcaHeader = HTTPField.Name("PCA-Action")!

    func makeApp(_ config: PcaGuardConfig, extra: (Router<TestContext>) -> Void = { _ in }) throws -> some ApplicationProtocol {
        let router = Router(context: TestContext.self)
        router.middlewares.add(try PcaMiddleware<TestContext>(config))
        router.post("payments") { _, context -> String in
            guard let pca = context.pca else { return "no pca" }
            return "paid:\(pca.operation?.verb ?? "-")"
        }
        extra(router)
        return Application(router: router)
    }

    static let provHeader = HTTPField.Name(PCA.PROV_HEADER)!

    /// Sends with the principal-direct `PCA-Provenance` header of the body's operation unless the caller set one.
    func post(_ client: some TestClientProtocol, _ headers: HTTPFields, _ body: String, _ check: @escaping (TestResponse) throws -> Void) async throws {
        var h = headers
        if h[Self.provHeader] == nil, let p = try Fixture.load().provHeader(body) { h[Self.provHeader] = p }
        try await client.execute(uri: "/payments", method: .post, headers: h, body: ByteBuffer(string: body)) { response in try check(response) }
    }

    func testWithoutProvenanceASensitiveCallEscalates() async throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        let other = try ProvenanceRecorder(mediator: "someone-else", kid: "k1", secretKey: [UInt8](repeating: 9, count: 32))
        let params = try XCTUnwrap(JSONValue.parse(f.paramsText))
        let foreign = ProvenanceRecorder.header(try PCA.principalDirectProvenance(other, PCA.Operation(verb: f.verb, resource: f.resource, params: params)))
        try await app.test(.router) { client in
            // an unreadable header is refused; an untrusted mediator's bundle vouches for nothing
            try await self.post(client, [Self.pcaHeader: f.header, Self.provHeader: "not base64url!"], f.paramsText) { res in
                XCTAssertEqual(res.status, .forbidden)
                XCTAssertTrue(String(buffer: res.body).contains("provenance_flow"), String(buffer: res.body))
            }
            try await self.post(client, [Self.pcaHeader: f.header, Self.provHeader: foreign], f.paramsText) { res in
                XCTAssertEqual(res.status, .forbidden)
                XCTAssertTrue(String(buffer: res.body).contains("escalate"), String(buffer: res.body))
            }
            // the refusals consumed nothing: the trusted bundle is admitted
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { XCTAssertEqual($0.status, .ok) }
        }
    }

    func testAllowedRequestReachesTheHandlerWithTheBoundOperation() async throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        try await app.test(.router) { client in
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { res in
                XCTAssertEqual(res.status, .ok)
                XCTAssertEqual(String(buffer: res.body), "paid:\(f.verb)")
            }
        }
    }

    func testReplayIsRefused() async throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        try await app.test(.router) { client in
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { XCTAssertEqual($0.status, .ok) }
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { res in
                XCTAssertEqual(res.status, .forbidden)
                XCTAssertTrue(String(buffer: res.body).contains("replay"), String(buffer: res.body))
                XCTAssertEqual(res.headers[.wwwAuthenticate], "PCA realm=\"pca\", error=\"insufficient_authority\"")
            }
        }
    }

    func testNoProofIs401WithAChallenge() async throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        try await app.test(.router) { client in
            try await self.post(client, [:], f.paramsText) { res in
                XCTAssertEqual(res.status, .unauthorized)
                XCTAssertTrue(res.headers[.wwwAuthenticate]?.hasPrefix("PCA realm=\"pca\", error=\"invalid_request\"") ?? false)
                XCTAssertEqual(res.headers[.contentType], "application/json")
            }
            try await self.post(client, [Self.pcaHeader: "not base64url!"], f.paramsText) { XCTAssertEqual($0.status, .unauthorized) }
        }
    }

    func testAProofForAnotherOperationIsRefusedAndConsumesNothing() async throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        try await app.test(.router) { client in
            // the handler would pay 400; the proof is for 50
            try await self.post(client, [Self.pcaHeader: f.header], #"{"amount":400,"currency":"usd"}"#) { res in
                XCTAssertEqual(res.status, .forbidden)
                XCTAssertTrue(String(buffer: res.body).contains("operation"), String(buffer: res.body))
            }
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { XCTAssertEqual($0.status, .ok) }
        }
    }

    func testARevokedGrantIsRefused() async throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config(revoked: true))
        try await app.test(.router) { client in
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { res in
                XCTAssertEqual(res.status, .forbidden)
                XCTAssertTrue(String(buffer: res.body).contains("revocation"), String(buffer: res.body))
            }
        }
    }

    func testMissingConfigurationIsAuthorizeConfig403() async throws {
        let f = try Fixture.load()
        let app = try makeApp(PcaGuardConfig(audience: f.audience, resolveGrant: { _ in f.grant }, now: { f.now }))
        try await app.test(.router) { client in
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { res in
                XCTAssertEqual(res.status, .forbidden)
                XCTAssertTrue(String(buffer: res.body).contains("authorize_config"), String(buffer: res.body))
            }
        }
    }

    func testSignatureOnlyIsAnExplicitOptIn() async throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config(signatureOnly: true))
        try await app.test(.router) { client in
            try await self.post(client, [Self.pcaHeader: f.header], f.paramsText) { res in
                XCTAssertEqual(res.status, .ok)
                XCTAssertEqual(String(buffer: res.body), "paid:-", "signature-only binds no operation")
            }
        }
        XCTAssertThrowsError(try PcaMiddleware<TestContext>(PcaGuardConfig(audience: "a", signatureOnly: true, authorize: PcaAuthorizeConfig())))
    }

    func testBodyTransportAndTheHandlerStillReadsTheBody() async throws {
        let f = try Fixture.load()
        let verb = f.verb, resource = f.resource, paramsText = f.paramsText
        var az = PcaAuthorizeConfig(stateStore: MemoryStateStore(), isRevoked: { _, _ in false },
                                    operation: { _ in PCA.Operation(verb: verb, resource: resource, params: JSONValue.parse(paramsText) ?? .null) })
        az.argProvenance.mediators = [Fixture.provPin]
        let config = PcaGuardConfig(audience: f.audience, resolveGrant: { _ in f.grant }, now: { f.now }, authorize: az)
        let router = Router(context: TestContext.self)
        router.middlewares.add(try PcaMiddleware<TestContext>(config))
        router.post("echo") { request, _ -> String in
            String(buffer: try await request.body.collect(upTo: 1 << 20))
        }
        let app = Application(router: router)
        // the proof and the provenance bundle both in the body (`pcactn`, `pca_provenance`)
        let body = #"{"pca_provenance":"# + (try XCTUnwrap(f.provBundle(paramsText)).canonicalText) + #","pcactn":"# + f.pcactnText + "}"
        try await app.test(.router) { client in
            try await client.execute(uri: "/echo", method: .post, body: ByteBuffer(string: body)) { res in
                XCTAssertEqual(res.status, .ok)
                XCTAssertEqual(String(buffer: res.body), body, "the middleware must leave the body readable")
            }
        }
    }

    func testExecuteRunsTheSideEffectOnce() async throws {
        let f = try Fixture.load()
        let store = MemoryOperationStore()
        let counter = Counter()
        let app = try makeApp(f.config()) { router in
            router.post("pay") { _, context -> Response in
                await context.pcaExecute(options: ExecuteOptions(store: store, recheck: { _ in .pass }, now: { f.now })) { h in
                    counter.bump()
                    return .string("sent:" + String(h.idempotencyKey.prefix(4)))
                }
            }
        }
        try await app.test(.router) { client in
            try await client.execute(uri: "/pay", method: .post, headers: [Self.pcaHeader: f.header, Self.provHeader: try XCTUnwrap(f.provHeader(f.paramsText))], body: ByteBuffer(string: f.paramsText)) { res in
                XCTAssertEqual(res.status, .ok)
                XCTAssertTrue(String(buffer: res.body).contains("\"replayed\":false"), String(buffer: res.body))
            }
        }
        XCTAssertEqual(counter.value, 1)
    }

    func testExecutorRunsTheRouteOnceAndAnswersARetryFromTheRecord() async throws {
        let f = try Fixture.load()
        let counter = Counter()
        let app = try makeApp(f.config(executor: PcaGuardExecutorConfig(operations: MemoryOperationStore()))) { router in
            router.post("pay") { _, _ -> Response in
                counter.bump()
                var headers = HTTPFields()
                headers[HTTPField.Name("X-Receipt")!] = "r1"
                return Response(status: .created, headers: headers, body: ResponseBody(byteBuffer: ByteBuffer(string: "sent")))
            }
        }
        try await app.test(.router) { client in
            try await client.execute(uri: "/pay", method: .post, headers: [Self.pcaHeader: f.header, Self.provHeader: try XCTUnwrap(f.provHeader(f.paramsText))], body: ByteBuffer(string: f.paramsText)) { res in
                XCTAssertEqual(res.status, .created)
                XCTAssertEqual(String(buffer: res.body), "sent")
                XCTAssertNil(res.headers[HTTPField.Name("PCA-Replayed")!])
            }
            try await client.execute(uri: "/pay", method: .post, headers: [Self.pcaHeader: f.header, Self.provHeader: try XCTUnwrap(f.provHeader(f.paramsText))], body: ByteBuffer(string: f.paramsText)) { res in
                XCTAssertEqual(res.status, .created)
                XCTAssertEqual(String(buffer: res.body), "sent")
                XCTAssertEqual(res.headers[HTTPField.Name("X-Receipt")!], "r1")
                XCTAssertEqual(res.headers[HTTPField.Name("PCA-Replayed")!], "true")
            }
        }
        XCTAssertEqual(counter.value, 1)
    }

    func testExecutorRouteFailureIs500WithoutTheErrorText() async throws {
        let f = try Fixture.load()
        struct Boom: Error, CustomStringConvertible { var description: String { "secret-detail-7731" } }
        let app = try makeApp(f.config(executor: PcaGuardExecutorConfig(operations: MemoryOperationStore()))) { router in
            router.post("pay") { _, _ -> Response in throw Boom() }
        }
        try await app.test(.router) { client in
            try await client.execute(uri: "/pay", method: .post, headers: [Self.pcaHeader: f.header, Self.provHeader: try XCTUnwrap(f.provHeader(f.paramsText))], body: ByteBuffer(string: f.paramsText)) { res in
                XCTAssertEqual(res.status, .internalServerError)
                XCTAssertTrue(String(buffer: res.body).contains("operation_failed"), String(buffer: res.body))
                XCTAssertFalse(String(buffer: res.body).contains("secret-detail-7731"))
            }
        }
    }
}
