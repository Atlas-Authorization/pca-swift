import Foundation

/// The runtime-free core of the Cloudflare Worker adapter: a function over a request value that verifies the inbound PCActn at the edge.
/// On allow it calls `next` with every inbound `x-pca-*` header removed (a client cannot forge the headers the gateway owns); on deny it
/// returns `respond(jsonBody, status, headers)` and never reaches `next`. The runtime types (a Workers `Request` / `Response`) are the
/// caller's: it maps them to `WorkerRequest` and back.
extension PCAGateway {
    public struct WorkerRequest {
        public var method: String
        /// The absolute request URL.
        public var url: String
        /// Header names are matched case-insensitively.
        public var headers: [String: String]
        /// Read only by a full-policy gateway whose params are the body.
        public var body: String?
        public init(method: String, url: String, headers: [String: String] = [:], body: String? = nil) {
            self.method = method
            self.url = url
            self.headers = headers
            self.body = body
        }

        /// The value of a header by lower-case name (names in sorted order, so a duplicate spelling resolves the same way every time).
        func header(_ lowerName: String) -> String? {
            for k in headers.keys.sorted() where k.lowercased() == lowerName { return headers[k] }
            return nil
        }
    }

    public enum WorkerRewrite {
        /// The request without the inbound `x-pca-*` headers.
        case standard
        /// No rewrite: a request that carries an `x-pca-*` header is refused with 400 instead of forwarded.
        case none
        /// Your own rewrite of the request given the lower-case names to drop; nil means it could not clean it (400).
        case custom((WorkerRequest, [String]) -> WorkerRequest?)
    }

    /// Path, authority and query of an absolute request URL, without a URL parser (the reference splits the string the same way).
    static func workerLocation(_ url: String) -> (path: String, authority: String, query: String) {
        var rest = Array(url.unicodeScalars)
        var authority = ""
        let sep = Array("://".unicodeScalars)
        if let i = (0..<max(0, rest.count - 2)).first(where: { Array(rest[$0..<$0 + 3]) == sep }) {
            rest = Array(rest[(i + 3)...])
            if let slash = rest.firstIndex(of: "/") {
                authority = scalars(rest[..<slash])
                rest = Array(rest[slash...])
            } else {
                authority = scalars(rest[...])
                rest = ["/"]
            }
        }
        let mark = rest.firstIndex(where: { $0 == "?" || $0 == "#" })
        let path = scalars(mark.map { rest[..<$0] } ?? rest[...])
        var query = ""
        if let q = rest.firstIndex(of: "?") {
            let after = rest[(q + 1)...]
            query = scalars(after.firstIndex(of: "#").map { after[..<$0] } ?? after)
        }
        return (path.isEmpty ? "/" : path, authority, query)
    }

    private static func scalars(_ s: ArraySlice<Unicode.Scalar>) -> String {
        var v = String.UnicodeScalarView()
        v.append(contentsOf: s)
        return String(v)
    }

    /// Lower-case names of the inbound `x-pca-*` headers: every such header in sorted order (a Fetch `Headers` iterates sorted), then the injected names.
    static func workerInboundPcaHeaders(_ r: WorkerRequest) -> [String] {
        var found: [String] = []
        for n in r.headers.keys.map({ $0.lowercased() }).sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) where n.hasPrefix("x-pca-") && !found.contains(n) { found.append(n) }
        for n in PCA_INJECTED_HEADERS where r.header(n) != nil && !found.contains(n) { found.append(n) }
        return found
    }

    public static func cloudflareWorker<Res>(_ o: GatewayOptions, next: @escaping (WorkerRequest) throws -> Res,
                                             respond: @escaping (_ body: String, _ status: Int, _ headers: [String: String]) -> Res,
                                             rewrite: WorkerRewrite = .standard) throws -> (WorkerRequest) throws -> Res {
        let gateway = try createGateway(o)
        return { request in
            let loc = workerLocation(request.url)
            var headers: HeaderMap = []
            for n in [PCA_HEADER.lowercased(), "pca-discharges", "pca-narrow"] { if let v = request.header(n) { headers.append((n, .one(v))) } }
            var body: String? = nil
            if case let .full(fp)? = o.policy, case .body = fp.params { body = request.body }
            let d = try gateway(GatewayRequest(method: request.method, path: loc.path, query: loc.query, authority: loc.authority, body: body, headers: headers))
            if d.allow {
                let forged = workerInboundPcaHeaders(request)
                if forged.isEmpty { return try next(request) }
                var clean: WorkerRequest?
                switch rewrite {
                case .standard:
                    var c = request
                    c.headers = request.headers.filter { !forged.contains($0.key.lowercased()) }
                    clean = c
                case .none: clean = nil
                case let .custom(f): clean = f(request, forged)
                }
                if let c = clean { return try next(c) }
                return respond(JS.stringify(.object(["error": .string("forged-pca-header"), "reason": .string("inbound x-pca-* header cannot be removed")]), order: ["error", "reason"]),
                               400, ["content-type": "application/json"])
            }
            var h = ["content-type": "application/json"]
            for (k, v) in d.headers { h[k] = v }
            return respond(JS.stringify(.object(["error": .string(d.code.rawValue), "reason": .string(d.reason)]), order: ["error", "reason"]), d.status, h)
        }
    }
}
