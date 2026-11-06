import XCTest
import XCTVapor
import Foundation
import AtlasPCAVerify
import AtlasPCAVapor

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
        // …/Integrations/AtlasPCAVapor/Tests/AtlasPCAVaporTests/<file> -> the core package's test-data
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

final class PcaMiddlewareTests: XCTestCase {
    func makeApp(_ config: PcaGuardConfig) throws -> Application {
        let app = Application(.testing)
        app.middleware.use(try PcaMiddleware(config))
        app.post("payments") { req -> String in
            guard let pca = req.pca else { return "no pca" }
            return "paid:\(pca.operation?.verb ?? "-")"
        }
        return app
    }

    /// Sends with the principal-direct `PCA-Provenance` header of the body's operation unless the caller set one.
    func post(_ app: Application, headers: HTTPHeaders, body: String, _ check: (XCTHTTPResponse) throws -> Void) throws {
        var h = headers
        if h.first(name: PCA.PROV_HEADER) == nil, let p = try Fixture.load().provHeader(body) { h.add(name: PCA.PROV_HEADER, value: p) }
        try app.test(.POST, "payments", headers: h, body: ByteBuffer(string: body)) { res in try check(res) }
    }

    func testWithoutProvenanceASensitiveCallEscalates() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        defer { app.shutdown() }
        // an unreadable header is refused; an untrusted mediator's bundle vouches for nothing
        try post(app, headers: ["PCA-Action": f.header, "PCA-Provenance": "not base64url!"], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .forbidden)
            XCTAssertTrue(res.body.string.contains("provenance_flow"), res.body.string)
        }
        let other = try ProvenanceRecorder(mediator: "someone-else", kid: "k1", secretKey: [UInt8](repeating: 9, count: 32))
        let params = try XCTUnwrap(JSONValue.parse(f.paramsText))
        let foreign = ProvenanceRecorder.header(try PCA.principalDirectProvenance(other, PCA.Operation(verb: f.verb, resource: f.resource, params: params)))
        try post(app, headers: ["PCA-Action": f.header, "PCA-Provenance": foreign], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .forbidden)
            XCTAssertTrue(res.body.string.contains("escalate"), res.body.string)
        }
        // the refusals consumed nothing: the trusted bundle is admitted
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { XCTAssertEqual($0.status, .ok) }
    }

    func testAllowedRequestReachesTheHandlerWithTheBoundOperation() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        defer { app.shutdown() }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(res.body.string, "paid:\(f.verb)")
        }
    }

    /// A string member of a JSON object (the core's accessors are internal).
    func member(_ v: JSONValue?, _ key: String) -> String? {
        guard case let .object(o)? = v, case let .string(s)? = o[JKey(key)] else { return nil }
        return s
    }

    func testRefusalBodyCarriesADocLinkAndTheReasonIsUnchanged() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        defer { app.shutdown() }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { XCTAssertEqual($0.status, .ok) }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .forbidden)
            let body = JSONValue.parse(res.body.string)
            XCTAssertTrue(member(body, "reason")?.hasPrefix("replay") ?? false, res.body.string)
            XCTAssertEqual(member(body, "doc"), "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay")
        }
    }

    func testProtectMiddlewareAllowsOnceAndRevokes() throws {
        let f = try Fixture.load()
        let g = f.grant
        let verb = f.verb, resource = f.resource
        let p = protect(audience: f.audience, operation: { req in
            guard let params = JSONValue.parse(String(decoding: req.body, as: UTF8.self)) else { return nil }
            return PCA.Operation(verb: verb, resource: resource, params: params)
        }, grants: [g], now: { f.now }, configure: { $0.authorize?.argProvenance.mediators = [Fixture.provPin] })
        let app = Application(.testing)
        defer { app.shutdown() }
        app.middleware.use(try p.middleware())
        app.post("payments") { _ in "ok" }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { XCTAssertEqual($0.status, .ok) }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { XCTAssertEqual($0.status, .forbidden) }
        p.revoke(try XCTUnwrap(member(g, "id")))
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .forbidden)
        }
    }

    func testReplayIsRefused() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        defer { app.shutdown() }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { XCTAssertEqual($0.status, .ok) }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .forbidden)
            XCTAssertTrue(res.body.string.contains("replay"), res.body.string)
            XCTAssertEqual(res.headers.first(name: "WWW-Authenticate"), "PCA realm=\"pca\", error=\"insufficient_authority\"")
        }
    }

    func testNoProofIs401WithAChallenge() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        defer { app.shutdown() }
        try post(app, headers: [:], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .unauthorized)
            XCTAssertTrue(res.headers.first(name: "WWW-Authenticate")?.hasPrefix("PCA realm=\"pca\", error=\"invalid_request\"") ?? false)
            XCTAssertEqual(res.headers.first(name: "Content-Type"), "application/json")
        }
        try post(app, headers: ["PCA-Action": "not base64url!"], body: f.paramsText) { XCTAssertEqual($0.status, .unauthorized) }
    }

    func testAProofForAnotherOperationIsRefusedAndConsumesNothing() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config())
        defer { app.shutdown() }
        // the handler would pay 400; the proof is for 50
        try post(app, headers: ["PCA-Action": f.header], body: #"{"amount":400,"currency":"usd"}"#) { res in
            XCTAssertEqual(res.status, .forbidden)
            XCTAssertTrue(res.body.string.contains("operation"), res.body.string)
        }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { XCTAssertEqual($0.status, .ok) }
    }

    func testARevokedGrantIsRefused() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config(revoked: true))
        defer { app.shutdown() }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .forbidden)
            XCTAssertTrue(res.body.string.contains("revocation"), res.body.string)
        }
    }

    func testMissingConfigurationIsAuthorizeConfig403() throws {
        let f = try Fixture.load()
        let app = try makeApp(PcaGuardConfig(audience: f.audience, resolveGrant: { _ in f.grant }, now: { f.now }))
        defer { app.shutdown() }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .forbidden)
            XCTAssertTrue(res.body.string.contains("authorize_config"), res.body.string)
        }
    }

    func testSignatureOnlyIsAnExplicitOptIn() throws {
        let f = try Fixture.load()
        let app = try makeApp(f.config(signatureOnly: true))
        defer { app.shutdown() }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(res.body.string, "paid:-", "signature-only binds no operation")
        }
        XCTAssertThrowsError(try PcaMiddleware(PcaGuardConfig(audience: "a", signatureOnly: true, authorize: PcaAuthorizeConfig())))
    }

    func testBodyTransport() throws {
        let f = try Fixture.load()
        let app = try makeApp(PcaGuardConfig(audience: f.audience, resolveGrant: { _ in f.grant }, now: { f.now }, authorize: {
            let verb = f.verb, resource = f.resource, paramsText = f.paramsText
            var az = PcaAuthorizeConfig(stateStore: MemoryStateStore(), isRevoked: { _, _ in false },
                                        operation: { _ in PCA.Operation(verb: verb, resource: resource, params: JSONValue.parse(paramsText) ?? .null) })
            az.argProvenance.mediators = [Fixture.provPin]
            return az
        }()))
        defer { app.shutdown() }
        // the proof and the provenance bundle both in the body (`pcactn`, `pca_provenance`)
        let bundle = try XCTUnwrap(f.provBundle(f.paramsText)).canonicalText
        try app.test(.POST, "payments", body: ByteBuffer(string: #"{"pca_provenance":"# + bundle + #","pcactn":"# + f.pcactnText + "}")) { res in
            XCTAssertEqual(res.status, .ok)
        }
    }

    func testExecuteRunsTheSideEffectOnce() throws {
        let f = try Fixture.load()
        let store = MemoryOperationStore()
        let counter = Counter()
        let app = Application(.testing)
        defer { app.shutdown() }
        app.middleware.use(try PcaMiddleware(f.config()))
        app.post("payments") { req async -> Response in
            await req.pcaExecute(options: ExecuteOptions(store: store, recheck: { _ in .pass }, now: { f.now })) { h in
                counter.bump()
                return .string("sent:" + String(h.idempotencyKey.prefix(4)))
            }
        }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertTrue(res.body.string.contains("\"replayed\":false"), res.body.string)
        }
        XCTAssertEqual(counter.value, 1)
    }

    func testExecutorRunsTheRouteOnceAndAnswersARetryFromTheRecord() throws {
        let f = try Fixture.load()
        let counter = Counter()
        let app = Application(.testing)
        defer { app.shutdown() }
        app.middleware.use(try PcaMiddleware(f.config(executor: PcaGuardExecutorConfig(operations: MemoryOperationStore()))))
        app.post("payments") { req -> Response in
            counter.bump()
            let res = Response(status: .created, body: .init(string: "sent"))
            res.headers.replaceOrAdd(name: "X-Receipt", value: "r1")
            return res
        }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .created)
            XCTAssertEqual(res.body.string, "sent")
            XCTAssertNil(res.headers.first(name: "PCA-Replayed"))
        }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .created)
            XCTAssertEqual(res.body.string, "sent")
            XCTAssertEqual(res.headers.first(name: "X-Receipt"), "r1")
            XCTAssertEqual(res.headers.first(name: "PCA-Replayed"), "true")
        }
        XCTAssertEqual(counter.value, 1)
    }

    func testExecutorRouteFailureIs500WithoutTheErrorText() throws {
        let f = try Fixture.load()
        struct Boom: Error, CustomStringConvertible { var description: String { "secret-detail-7731" } }
        let app = Application(.testing)
        defer { app.shutdown() }
        app.middleware.use(try PcaMiddleware(f.config(executor: PcaGuardExecutorConfig(operations: MemoryOperationStore()))))
        app.post("payments") { _ -> Response in throw Boom() }
        try post(app, headers: ["PCA-Action": f.header], body: f.paramsText) { res in
            XCTAssertEqual(res.status, .internalServerError)
            XCTAssertTrue(res.body.string.contains("operation_failed"), res.body.string)
            XCTAssertFalse(res.body.string.contains("secret-detail-7731"))
        }
    }

    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func bump() { lock.lock(); n += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    }
}
