import Foundation
import Vapor
import AtlasPCAVerify

/// The request storage key `PcaMiddleware` fills on an allowed request.
public struct PcaAllowKey: StorageKey {
    public typealias Value = PcaGuardAllow
}

extension Request {
    /// What a passing request carries to the handler: the verified PCActn, the core verdict and (default mode) the authorization bound to
    /// the operation the middleware mapped from this request. nil outside `PcaMiddleware`.
    public var pca: PcaGuardAllow? {
        get { storage[PcaAllowKey.self] }
        set { storage[PcaAllowKey.self] = newValue }
    }

    /// Runs the side effect of an authorized request at most once, with a durable record (`PCA.executeAuthorized`), and answers with the
    /// outcome: 200 for a commit (also when answered from the record), 500 for a failed function, 409 for an in-flight or uncertain
    /// operation, 403 for a refusal or an abort. The function gets the operation id as its idempotency key (`ExecutionHandle`).
    public func pcaExecute(options: ExecuteOptions, _ fn: (ExecutionHandle) async throws -> JSONValue?) async -> Response {
        guard let authorization = pca?.authorization else {
            return pcaResponse(status: 403, body: Array(#"{"status":"refused"}"#.utf8), challenge: nil)
        }
        let outcome = await PCA.executeAuthorized(authorization, options: options, fn)
        return pcaResponse(status: PcaGuard.operationStatus(outcome), body: Array(PcaGuard.operationBody(outcome).utf8), challenge: nil)
    }
}

func pcaResponse(status: Int, body: [UInt8], challenge: String?) -> Response {
    var headers = HTTPHeaders()
    if let c = challenge { headers.replaceOrAdd(name: "WWW-Authenticate", value: c) }
    headers.replaceOrAdd(name: "Content-Type", value: "application/json")
    return Response(status: HTTPResponseStatus(statusCode: status), headers: headers, body: .init(data: Data(body)))
}

/// The route's response could not be recorded (a streamed body): the operation is recorded failed and answered 500 `operation_failed`.
struct PcaUnrecordableResponse: Error {}

func pcaResponse(_ reply: PcaGuardReply) -> Response {
    var headers = HTTPHeaders()
    for (name, values) in reply.headers { for v in values { headers.add(name: name, value: v) } }
    return Response(status: HTTPResponseStatus(statusCode: reply.status), headers: headers, body: .init(data: Data(reply.body)))
}

/// Proof-Carrying Authority for Vapor. Every request it guards must present a PCActn (header `PCA-Action`, or a JSON body
/// `{"pcactn": {...}}`); the default is the full `PCA.authorize` path, so the PCActn must authorize exactly the operation your
/// `PcaAuthorizeConfig.operation` maps from the request, the grant's predicates and caveats are enforced against it, revocation must answer
/// `false` and the replay counter is claimed atomically. A missing component is a 403 `authorize_config`; verifying the signature only is
/// the explicit opt-in `PcaGuardConfig.signatureOnly`. 401 for no, undecodable or unauthenticated proofs, 403 otherwise, with a
/// `WWW-Authenticate: PCA` challenge and a JSON body; an `escalate` decision is a 403 that carries the request for the principal.
///
///     app.middleware.use(try PcaMiddleware(PcaGuardConfig(audience: "payments-rs", resolveGrant: { ref in grants[ref] },
///                                                          authorize: PcaAuthorizeConfig(stateStore: store, isRevoked: { _, g in revoked(g) },
///                                                                                        operation: { req in PCA.Operation(...) }))))
///
/// On allow the request's `pca` is set and the chain continues. With `PcaGuardConfig.executor` the rest of the chain runs inside the
/// executor instead: at most once per PCActn, its response (an in-memory body) recorded, a retry of the same PCActn answered from the
/// record with `PCA-Replayed: true`, a thrown error recorded as a failure (500 `operation_failed`, no error text), an execution in flight
/// 409 `operation_in_progress`, an unknown outcome 409 `operation_uncertain`, a refused re-check 403 `operation_aborted`.
public struct PcaMiddleware: AsyncMiddleware {
    private let pcaGuard: PcaGuard

    /// Throws `PcaGuardConfigError` for a configuration the guard refuses (signature-only together with authorize options, escalation
    /// principals with a store that cannot report the history head).
    public init(_ config: PcaGuardConfig) throws {
        pcaGuard = try PcaGuard(config)
    }

    public init(guard g: PcaGuard) {
        pcaGuard = g
    }

    public func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        var headers: [String: String] = [:]
        for (name, value) in request.headers where headers[name.lowercased()] == nil { headers[name.lowercased()] = value }
        var body: [UInt8] = []
        var complete = true
        do {
            if let buffer = try await request.body.collect(max: PcaGuard.MAX_BODY_BYTES).get() { body = Array(buffer.readableBytesView) }
        } catch {
            complete = false // larger than the limit (or unreadable): the guard never gives the operation mapper a partial body
        }
        let pcaRequest = PcaGuardRequest(method: request.method.rawValue, path: request.url.path, headers: headers, body: body, bodyComplete: complete)
        if pcaGuard.executes {
            let reply = await pcaGuard.handle(pcaRequest) { allowed in
                request.pca = allowed
                let response = try await next.respond(to: request)
                guard let data = response.body.data else { throw PcaUnrecordableResponse() }
                var headers: [String: [String]] = [:]
                for (name, value) in response.headers { headers[name, default: []].append(value) }
                return PcaRecordedResponse(status: Int(response.status.code), headers: headers, body: [UInt8](data))
            }
            return pcaResponse(reply)
        }
        switch pcaGuard.handle(pcaRequest) {
        case let .allow(allowed):
            request.pca = allowed
            return try await next.respond(to: request)
        case let .deny(denied):
            return pcaResponse(status: denied.status, body: denied.body, challenge: denied.wwwAuthenticate)
        }
    }
}
