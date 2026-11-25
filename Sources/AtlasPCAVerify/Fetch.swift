import Foundation

/// The runtime-neutral request guard of the reference (@atlasauth/pca-fetch): a `Request -> Response` wrapper over the framework-free
/// `PcaGuard` that verifies the inbound PCActn (default-deny) and, on success, calls the handler with the verdict; otherwise it answers
/// 401 / 403 with a `WWW-Authenticate` challenge and a JSON body `{error, verdict, decision}`. The client sends the PCActn as
/// `PCA-Action: <base64url>` or as a JSON body `{"pcactn": {...}}`. Nothing here authorizes on its own: the verifier decides.
public enum PCAFetch {
    /// A web request as the guard reads it.
    public struct Request {
        public var method: String
        /// The request URL (absolute or origin-relative); only its path reaches the operation mapper.
        public var url: String
        public var headers: [String: String]
        public var body: [UInt8]
        public init(method: String = "GET", url: String, headers: [String: String] = [:], body: [UInt8] = []) {
            self.method = method; self.url = url; self.headers = headers; self.body = body
        }
    }

    public struct Response {
        public var status: Int
        public var headers: [String: String]
        public var body: [UInt8]
        public init(status: Int, headers: [String: String] = [:], body: [UInt8] = []) { self.status = status; self.headers = headers; self.body = body }

        public func header(_ name: String) -> String? { headers.first { $0.key.lowercased() == name.lowercased() }?.value }
    }

    public struct Options {
        public var config: PcaGuardConfig
        /// The explicit opt-in to verify signature, chain and freshness only (no operation binding); needed when `config` has no operation mapper.
        public var insecureAllowUnboundOperation: Bool
        /// Shapes the 401 / 403 body (default `{error, verdict, decision[, escalation]}`).
        public var denyBody: ((PcaGuardDenial) -> JSONValue)?
        public init(config: PcaGuardConfig, insecureAllowUnboundOperation: Bool = false, denyBody: ((PcaGuardDenial) -> JSONValue)? = nil) {
            self.config = config; self.insecureAllowUnboundOperation = insecureAllowUnboundOperation; self.denyBody = denyBody
        }
    }

    /// The guard's answer: the verified request, or the response to send.
    public enum Decision {
        case allow(PcaGuardAllow)
        case deny(Response)
    }

    /// What a guarded request carries to the handler.
    public typealias Handler = (Request, PcaGuardAllow) async throws -> Response

    /// The audience is required, and a guard without an operation mapper (the authorize path) or the explicit unbound opt-in is a
    /// configuration error: a proof must be bound to the operation the request will execute.
    static func validate(_ o: Options) throws {
        if o.config.audience.isEmpty { throw JSError("requirePCA: `audience` (this resource server's id) is required") }
        let bound = o.config.authorize?.operation != nil
        if !bound && !(o.insecureAllowUnboundOperation || o.config.signatureOnly) {
            throw JSError("requirePCA: `operation` is required: map each request to the operation it will execute so the proof is bound to it, or use `authorize`; set insecureAllowUnboundOperation only to migrate")
        }
    }

    static func path(_ url: String) -> String {
        guard let u = WhatwgURL.parse(url) ?? WhatwgURL.parse("http://adapter.invalid" + (url.hasPrefix("/") ? "" : "/") + url) else { return "/" }
        return u.pathname
    }

    /// The 401 / 403 answer: `{error, verdict, decision[, escalation]}` and the challenge when the guard has one.
    static func deny(_ d: PcaGuardDenial, challenge: Bool, denyBody: ((PcaGuardDenial) -> JSONValue)?) -> Response {
        let reason: String
        if case let .object(o)? = try? StrictJSON.parse(d.bodyText) { reason = o[JKey("reason")]?.asString ?? o[JKey("error_description")]?.asString ?? d.code } else { reason = d.code }
        var body: JObject = ["error": .string(reason), "decision": .string(d.decision),
                             "verdict": .object(["allow": .bool(false), "checks": .object([:]), "reason": .string(reason), "reasons": .array([.string(reason)])])]
        if let e = d.escalation { body["escalation"] = e }
        let json = denyBody?(d) ?? .object(body)
        var headers = ["content-type": "application/json"]
        if challenge { headers["WWW-Authenticate"] = d.wwwAuthenticate }
        return Response(status: d.status, headers: headers, body: Array(Canonical.canonicalize(json).utf8))
    }

    /// A guard over a request: the full decision, to compose inside an existing router. `resolveGrant` that throws is a 403 (no challenge),
    /// an unknown grant a 401.
    public static func createGuard(_ options: Options) throws -> (Request) -> Decision {
        try validate(options)
        let box = ThrowFlag()
        var config = options.config
        if let resolve = config.resolveGrant {
            config.resolveGrant = { ref in
                do { return try resolve(ref) } catch { box.threw = true; return nil }
            }
        }
        let g = try PcaGuard(config)
        return { req in
            box.threw = false
            var headers: [String: String] = [:]
            for (k, v) in req.headers where headers[k.lowercased()] == nil { headers[k.lowercased()] = v }
            let r = PcaGuardRequest(method: req.method, path: path(req.url), headers: headers, body: req.body, bodyComplete: true)
            switch g.handle(r) {
            case let .allow(a): return Decision.allow(a)
            case let .deny(d):
                // a resolver that throws is a verification failure (403, no challenge), not an unknown grant
                if box.threw && d.code == "unknown_grant" {
                    let refused = PcaGuardDenial(status: 403, code: "verification_error", wwwAuthenticate: "", body: Array(#"{"reason":"grant resolution failed"}"#.utf8),
                                                 decision: "deny", escalation: nil, authorization: nil)
                    return Decision.deny(Self.deny(refused, challenge: false, denyBody: options.denyBody))
                }
                return Decision.deny(Self.deny(d, challenge: d.status == 401, denyBody: options.denyBody))
            }
        }
    }

    final class ThrowFlag { var threw = false }

    /// Wraps a handler so the inbound PCActn is verified first; on success the handler runs with the allow decision.
    public static func withPCA(_ options: Options, _ handler: @escaping Handler) throws -> (Request) async throws -> Response {
        let g = try createGuard(options)
        return { req in
            switch g(req) {
            case let .allow(a): return try await handler(req, a)
            case let .deny(r): return r
            }
        }
    }
}
