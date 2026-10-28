import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import AtlasPCAVerify

/// A request context that can carry what `PcaMiddleware` found. Add the member to your context:
///
///     struct AppContext: RequestContext, PcaRequestContext {
///         var coreContext: CoreRequestContextStorage
///         var pca: PcaGuardAllow?
///         init(source: Source) { coreContext = .init(source: source); pca = nil }
///     }
public protocol PcaRequestContext: RequestContext {
    /// What a passing request carries to the handler: the verified PCActn, the core verdict and (default mode) the authorization bound to
    /// the operation the middleware mapped from this request. nil outside `PcaMiddleware`.
    var pca: PcaGuardAllow? { get set }
}

func pcaResponse(status: Int, body: [UInt8], challenge: String?) -> Response {
    var headers = HTTPFields()
    if let c = challenge { headers[.wwwAuthenticate] = c }
    headers[.contentType] = "application/json"
    return Response(status: HTTPResponse.Status(code: status), headers: headers, body: ResponseBody(byteBuffer: ByteBuffer(bytes: body)))
}

extension PcaRequestContext {
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

func pcaResponse(_ reply: PcaGuardReply) -> Response {
    var headers = HTTPFields()
    for (name, values) in reply.headers {
        guard let field = HTTPField.Name(name) else { continue }
        for v in values { headers.append(HTTPField(name: field, value: v)) }
    }
    return Response(status: HTTPResponse.Status(code: reply.status), headers: headers, body: ResponseBody(byteBuffer: ByteBuffer(bytes: reply.body)))
}

/// Collects a response body (the executor records the route's response).
final class PcaBodyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: [UInt8] = []
    func append(_ buffer: ByteBuffer) { lock.lock(); bytes.append(contentsOf: buffer.readableBytesView); lock.unlock() }
    var value: [UInt8] { lock.lock(); defer { lock.unlock() }; return bytes }
}

struct PcaBodyCollector: ResponseBodyWriter {
    let box: PcaBodyBox
    mutating func write(_ buffer: ByteBuffer) async throws { box.append(buffer) }
    consuming func finish(_ trailingHeaders: HTTPFields?) async throws {}
}

/// Proof-Carrying Authority for Hummingbird 2. Every request it guards must present a PCActn (header `PCA-Action`, or a JSON body
/// `{"pcactn": {...}}`); the default is the full `PCA.authorize` path, so the PCActn must authorize exactly the operation your
/// `PcaAuthorizeConfig.operation` maps from the request, the grant's predicates and caveats are enforced against it, revocation must answer
/// `false` and the replay counter is claimed atomically. A missing component is a 403 `authorize_config`; verifying the signature only is
/// the explicit opt-in `PcaGuardConfig.signatureOnly`. 401 for no, undecodable or unauthenticated proofs, 403 otherwise, with a
/// `WWW-Authenticate: PCA` challenge and a JSON body; an `escalate` decision is a 403 that carries the request for the principal.
///
///     router.middlewares.add(try PcaMiddleware<AppContext>(PcaGuardConfig(audience: "payments-rs", resolveGrant: { ref in grants[ref] },
///                                                                         authorize: PcaAuthorizeConfig(stateStore: store, ...))))
///
/// On allow the context's `pca` is set and the chain continues. With `PcaGuardConfig.executor` the rest of the chain runs inside the
/// executor instead: at most once per PCActn, its response recorded, a retry of the same PCActn answered from the record with
/// `PCA-Replayed: true`, a thrown error recorded as a failure (500 `operation_failed`, no error text), an execution in flight 409
/// `operation_in_progress`, an unknown outcome 409 `operation_uncertain`, a refused re-check 403 `operation_aborted`.
public struct PcaMiddleware<Context: PcaRequestContext>: RouterMiddleware {
    private let pcaGuard: PcaGuard

    /// Throws `PcaGuardConfigError` for a configuration the guard refuses (signature-only together with authorize options, escalation
    /// principals with a store that cannot report the history head).
    public init(_ config: PcaGuardConfig) throws {
        pcaGuard = try PcaGuard(config)
    }

    public init(guard g: PcaGuard) {
        pcaGuard = g
    }

    public func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        var forwarded = request
        var headers: [String: String] = [:]
        for field in request.headers where headers[field.name.rawName.lowercased()] == nil { headers[field.name.rawName.lowercased()] = field.value }
        var body: [UInt8] = []
        var complete = true
        do {
            let buffer = try await request.body.collect(upTo: PcaGuard.MAX_BODY_BYTES)
            body = Array(buffer.readableBytesView)
            forwarded.body = RequestBody(buffer: buffer) // the handler still reads the body
        } catch {
            complete = false // larger than the limit (or unreadable): the guard never gives the operation mapper a partial body
        }
        let pcaRequest = PcaGuardRequest(method: request.method.rawValue, path: request.uri.path, headers: headers, body: body, bodyComplete: complete)
        if pcaGuard.executes {
            let reply = await pcaGuard.handle(pcaRequest) { allowed in
                var ctx = context
                ctx.pca = allowed
                let response = try await next(forwarded, ctx)
                let box = PcaBodyBox()
                try await response.body.write(PcaBodyCollector(box: box))
                var headers: [String: [String]] = [:]
                for field in response.headers { headers[field.name.rawName, default: []].append(field.value) }
                return PcaRecordedResponse(status: Int(response.status.code), headers: headers, body: box.value)
            }
            return pcaResponse(reply)
        }
        switch pcaGuard.handle(pcaRequest) {
        case let .allow(allowed):
            var ctx = context
            ctx.pca = allowed
            return try await next(forwarded, ctx)
        case let .deny(denied):
            return pcaResponse(status: denied.status, body: denied.body, challenge: denied.wwwAuthenticate)
        }
    }
}
