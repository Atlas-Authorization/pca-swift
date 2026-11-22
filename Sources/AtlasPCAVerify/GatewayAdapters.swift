import Foundation

/// Edge adapters over the gateway: Envoy ext_authz (HTTP and gRPC shapes) and AWS Lambda authorizers (REST request authorizer and the
/// HTTP API simple response). They are functions over decoded events; the transport is yours. A client-supplied `x-pca-*` header is never
/// trusted: an allow sets the injected headers itself (empty when there is nothing to inject).
extension PCAGateway {
    // MARK: Envoy

    public struct EnvoyHttpCheckRequest {
        public var method: String?
        /// The request target, query and fragment included.
        public var path: String?
        public var authority: String?
        public var headers: [String: String]
        public var body: String?
        public init(method: String? = nil, path: String? = nil, authority: String? = nil, headers: [String: String] = [:], body: String? = nil) {
            self.method = method
            self.path = path
            self.authority = authority
            self.headers = headers
            self.body = body
        }
    }

    public struct EnvoyHttpCheckResponse {
        public var status: Int
        public var headers: [String: String]
        public var body: String
    }

    /// The query of a request target (from the first `?`, up to a `#` that follows it).
    private static func queryOfTarget(_ target: String) -> String {
        guard let q = target.firstIndex(of: "?") else { return "" }
        let rest = target[target.index(after: q)...]
        return rest.firstIndex(of: "#").map { String(rest[..<$0]) } ?? String(rest)
    }

    private static func headerMap(_ h: [String: String]) -> HeaderMap { h.keys.sorted().map { ($0, HeaderValue.one(h[$0]!)) } }

    static func envoyRequest(_ c: EnvoyHttpCheckRequest) -> GatewayRequest {
        let method = c.method ?? c.headers[":method"] ?? "*"
        let target = c.path ?? c.headers[":path"] ?? "/"
        let mark = target.firstIndex(where: { $0 == "?" || $0 == "#" })
        let rawPath = mark.map { String(target[..<$0]) } ?? target
        return GatewayRequest(method: method, path: rawPath.isEmpty ? "/" : rawPath, query: queryOfTarget(target), authority: c.authority ?? c.headers[":authority"], body: c.body, headers: headerMap(c.headers))
    }

    private static func errorBody(_ d: Decision) -> String { JS.stringify(.object(["error": .string(d.code.rawValue), "reason": .string(d.reason)]), order: ["error", "reason"]) }

    /// Envoy `ext_authz` over HTTP: 200 with the injected `x-pca-*` headers, or the decision's status with a JSON body.
    public static func envoyExtAuthz(_ o: GatewayOptions) throws -> (EnvoyHttpCheckRequest) throws -> EnvoyHttpCheckResponse {
        let gateway = try createGateway(o)
        return { check in
            let d = try gateway(envoyRequest(check))
            if d.allow {
                var h: [String: String] = [:]
                for n in PCA_INJECTED_HEADERS { h[n] = "" }
                for (k, v) in d.headers { h[k] = v }
                return EnvoyHttpCheckResponse(status: 200, headers: h, body: "")
            }
            var h = ["content-type": "application/json"]
            for (k, v) in d.headers { h[k] = v }
            return EnvoyHttpCheckResponse(status: d.status, headers: h, body: errorBody(d))
        }
    }

    public struct EnvoyGrpcHttp {
        public var method: String?
        public var path: String?
        public var host: String?
        public var headers: [String: String]
        public var body: String?
        public init(method: String? = nil, path: String? = nil, host: String? = nil, headers: [String: String] = [:], body: String? = nil) {
            self.method = method
            self.path = path
            self.host = host
            self.headers = headers
            self.body = body
        }
    }

    public struct EnvoyGrpcHeaderValueOption {
        public var key: String
        public var value: String
        /// OVERWRITE_IF_EXISTS_OR_ADD.
        public var appendAction = 2
    }

    public struct EnvoyGrpcCheckResponse {
        public var code: Int
        public var message: String
        public var okHeaders: [EnvoyGrpcHeaderValueOption]?
        public var okHeadersToRemove: [String]?
        public var deniedStatus: Int?
        public var deniedHeaders: [EnvoyGrpcHeaderValueOption]?
        public var deniedBody: String?
    }

    private static func headerOptions(_ h: [(String, String)]) -> [EnvoyGrpcHeaderValueOption] { h.map { EnvoyGrpcHeaderValueOption(key: $0.0, value: $0.1) } }

    /// Envoy `ext_authz` over gRPC (the `CheckResponse` shape): OK (0) with headers to set and to remove, UNAUTHENTICATED (16) for a 401,
    /// UNAVAILABLE (14) for a 503, PERMISSION_DENIED (7) otherwise. A check without HTTP attributes is denied.
    public static func envoyGrpcExtAuthz(_ o: GatewayOptions) throws -> (EnvoyGrpcHttp?) throws -> EnvoyGrpcCheckResponse {
        let gateway = try createGateway(o)
        return { http in
            guard let http = http else {
                return EnvoyGrpcCheckResponse(code: 7, message: "no http request attributes", deniedStatus: 403, deniedHeaders: [],
                                              deniedBody: JS.stringify(.object(["error": .string("invalid-request"), "reason": .string("CheckRequest carried no HTTP attributes")]), order: ["error", "reason"]))
            }
            let req = EnvoyHttpCheckRequest(method: http.method ?? http.headers[":method"], path: http.path ?? http.headers[":path"], authority: http.host ?? http.headers[":authority"], headers: http.headers, body: http.body)
            let d = try gateway(envoyRequest(req))
            if d.allow {
                return EnvoyGrpcCheckResponse(code: 0, message: "", okHeaders: headerOptions(d.headers), okHeadersToRemove: PCA_INJECTED_HEADERS.filter { n in !d.headers.contains { $0.0 == n } })
            }
            return EnvoyGrpcCheckResponse(code: d.status == 401 ? 16 : d.status == 503 ? 14 : 7, message: d.reason, deniedStatus: d.status,
                                          deniedHeaders: headerOptions([("content-type", "application/json")] + d.headers), deniedBody: errorBody(d))
        }
    }

    // MARK: AWS Lambda

    /// A Lambda request-authorizer event (REST payload v1, HTTP API payload v2). Query parameters are the event's JSON members.
    public struct LambdaEvent {
        public var headers: HeaderMap = []
        public var methodArn: String?
        public var routeArn: String?
        public var httpMethod: String?
        public var path: String?
        public var rawPath: String?
        public var contextHttpMethod: String?
        public var contextHttpPath: String?
        public var rawQueryString: String?
        public var queryStringParameters: JSONValue?
        public var multiValueQueryStringParameters: JSONValue?
        public init() {}
    }

    public struct LambdaAuthResponse {
        public var principalId: JSONValue
        public var effect: String
        public var resource: String
        public var context: [String: String]
    }

    public struct LambdaSimpleAuthResponse {
        public var isAuthorized: Bool
        public var context: [String: String]
    }

    private static func lambdaMethodPath(_ e: LambdaEvent) -> (method: String, path: String) {
        let method = e.contextHttpMethod ?? e.httpMethod
        let path = e.rawPath ?? e.path ?? e.contextHttpPath
        if let m = method, let p = path { return (m, p) }
        if let arn = e.methodArn ?? e.routeArn {
            // arn.split(':').slice(5).join(':') then '/'-parts: [stage, ?, "METHOD path", ...]
            let tail = arn.split(separator: ":", omittingEmptySubsequences: false).dropFirst(5).joined(separator: ":")
            let parts = tail.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            let arnMethod = parts.count > 2 ? parts[2].split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) : nil
            return (method ?? arnMethod ?? "*", path ?? "/" + parts.dropFirst(3).joined(separator: "/"))
        }
        return (method ?? "*", path ?? "/")
    }

    private static func lambdaQuery(_ e: LambdaEvent) -> String {
        if let r = e.rawQueryString { return r }
        func enc(_ v: JSONValue) -> String { JS.encodeURIComponent(JS.toString(v)) }
        var pairs: [String] = []
        if let multi = e.multiValueQueryStringParameters?.asObject {
            for k in multi.keys.sorted(by: { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }) {
                for v in multi[k]?.asArray ?? [] { pairs.append("\(JS.encodeURIComponent(k.s))=\(enc(v))") }
            }
        } else if let single = e.queryStringParameters?.asObject {
            for k in single.keys.sorted(by: { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }) { pairs.append("\(JS.encodeURIComponent(k.s))=\(enc(single[k]!))") }
        }
        return pairs.joined(separator: "&")
    }

    private static func lambdaRequest(_ e: LambdaEvent) -> GatewayRequest {
        let mp = lambdaMethodPath(e)
        return GatewayRequest(method: mp.method, path: mp.path, query: lambdaQuery(e), headers: e.headers)
    }

    private static func lambdaContext(_ d: Decision) -> [String: String] {
        if d.allow { return d.verdict.map { ["pcaVerdict": JS.stringify($0.json, order: ["allow", "checks", "reason"])] } ?? [:] }
        return ["pcaDenied": "true", "pcaCode": d.code.rawValue, "pcaReason": d.reason, "pcaStatus": String(d.status)]
    }

    /// AWS REST API Lambda request authorizer: an IAM policy allowing or denying `execute-api:Invoke` on the invoked ARN, with the grant as principal.
    public static func lambdaAuthorizer(_ o: GatewayOptions) throws -> (LambdaEvent) throws -> LambdaAuthResponse {
        let gateway = try createGateway(o)
        return { e in
            let d = try gateway(lambdaRequest(e))
            return LambdaAuthResponse(principalId: d.pcactn?.get("grant_ref").flatMap { $0.isNull ? nil : $0 } ?? .string("anonymous"), effect: d.allow ? "Allow" : "Deny",
                                      resource: e.methodArn ?? e.routeArn ?? "*", context: lambdaContext(d))
        }
    }

    /// AWS HTTP API Lambda authorizer with the simple response format.
    public static func lambdaSimpleAuthorizer(_ o: GatewayOptions) throws -> (LambdaEvent) throws -> LambdaSimpleAuthResponse {
        let gateway = try createGateway(o)
        return { e in
            let d = try gateway(lambdaRequest(e))
            return LambdaSimpleAuthResponse(isAuthorized: d.allow, context: lambdaContext(d))
        }
    }
}
