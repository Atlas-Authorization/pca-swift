import Foundation

/// The gateway: an HTTP-edge authorizer that admits a request only with a verified PCActn bound to that exact request (method, path,
/// canonical query, authority, body hash), over a route table of required capabilities, with single-use replay protection. Deny by
/// default. Signature-only mode verifies the proof with the core verifier; full-policy mode delegates the grant's limits, caveats,
/// revocation and replay counter to `PCA.authorize` with a caller-supplied template, joining in the gateway's own provenance log (untrusted
/// content it relayed to each agent session) and the discharge / narrow artifacts a request presents. The attestation, threshold and zk hooks
/// and the taint / freshness / attestation enforcement gates run in the core verification step of both modes.
public enum PCAGateway {
    public static let PCA_HEADER = "PCA-Action"
    public static let PCA_INJECTED_HEADERS = ["x-pca-verdict", "x-pca-verb", "x-pca-grant"]

    /// A refusal or failure with the reference's message.
    public struct GatewayError: Error, CustomStringConvertible {
        public let message: String
        public var description: String { message }
        init(_ m: String) { message = m }
    }

    static func errMessage(_ e: Error) -> String { (e as? GatewayError)?.message ?? (e as? JSError)?.message ?? "\(e)" }

    // MARK: request model

    public enum HeaderValue {
        case one(String)
        case many([String])
    }
    /// Header members in the order given; a lookup is case-insensitive and the first match wins (an array reads as its first element).
    public typealias HeaderMap = [(String, HeaderValue)]

    public struct GatewayRequest {
        public var method: String
        public var path: String
        public var query: String?
        public var authority: String?
        public var bodySha256: String?
        public var body: String?
        public var headers: HeaderMap
        public init(method: String, path: String, query: String? = nil, authority: String? = nil, bodySha256: String? = nil, body: String? = nil, headers: HeaderMap = []) {
            self.method = method
            self.path = path
            self.query = query
            self.authority = authority
            self.bodySha256 = bodySha256
            self.body = body
            self.headers = headers
        }
    }

    public struct RequiredCapability: Equatable {
        public var verb: String
        public var resource: String?
        public init(verb: String, resource: String? = nil) {
            self.verb = verb
            self.resource = resource
        }
        var json: JSONValue {
            var o: JObject = ["verb": .string(verb)]
            if let r = resource { o["resource"] = .string(r) }
            return .object(o)
        }
    }

    public struct RouteRule {
        /// nil, "*" or "ANY" match every method.
        public var method: String?
        /// Exact, `prefix/*` (the prefix itself or anything below it), `prefix*`, or `*` / `/*`.
        public var path: String
        public var capability: RequiredCapability
        public init(method: String? = nil, path: String, capability: RequiredCapability) {
            self.method = method
            self.path = path
            self.capability = capability
        }
    }

    static func getHeader(_ headers: HeaderMap, _ name: String) -> String? {
        let lower = name.lowercased()
        for (k, v) in headers where k.lowercased() == lower {
            switch v {
            case let .one(s): return s
            case let .many(a): return a.first
            }
        }
        return nil
    }

    // MARK: request binding

    public enum BodyBinding {
        /// Bind the body hash when the request carries one.
        case auto
        case on
        case off
    }

    public struct BindRequestOptions {
        /// Bind the (lower-cased) authority.
        public var authority: Bool
        public var body: BodyBinding
        public init(authority: Bool = false, body: BodyBinding = .auto) {
            self.authority = authority
            self.body = body
        }
    }

    /// The request attributes an agent signs into its params (`binding`) so a proof cannot be replayed against another request.
    public static func requestBinding(_ req: GatewayRequest, _ opts: BindRequestOptions = BindRequestOptions()) throws -> JObject {
        var b: JObject = ["v": .int(2), "method": .string(req.method.uppercased()), "path": .string(req.path), "query": .string(try canonicalQuery(req.query))]
        if opts.authority { b["authority"] = .string((req.authority ?? "").lowercased()) }
        if opts.body == .on || (opts.body == .auto && req.bodySha256 != nil) { b["body_sha256"] = .string((req.bodySha256 ?? "").lowercased()) }
        return b
    }

    /// The query with its parameters sorted. Refused when parsers could disagree on it: a `;` separator, a malformed percent escape in a
    /// name, or a name (decoded, `+` as space, lower-cased) that appears twice.
    public static func canonicalQuery(_ query: String?) throws -> String {
        guard let query = query else { return "" }
        let q = query.hasPrefix("?") ? String(query.dropFirst()) : query
        if q.contains(";") { throw GatewayError("query contains ';' (parsers disagree on it as a separator)") }
        let pairs = q.split(separator: "&", omittingEmptySubsequences: true).map(String.init)
        var seen: [String] = []
        for pair in pairs {
            let rawKey = pair.firstIndex(of: "=").map { String(pair[..<$0]) } ?? pair
            guard let dec = PCAConnect.decodeURIComponent(rawKey.replacingOccurrences(of: "+", with: " ")) else { throw GatewayError("query parameter name has a malformed percent escape") }
            let key = dec.lowercased()
            if IV.contains(seen, key) { throw GatewayError("duplicate query parameter '\(key)'") }
            seen.append(key)
        }
        return pairs.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.joined(separator: "&")
    }

    /// `{...params, binding}`; refused when the params already carry a `binding` member.
    public static func bindParams(_ params: JObject, _ binding: JObject?) throws -> JObject {
        guard let b = binding else { return params }
        if params[JKey("binding")] != nil { throw GatewayError("params already have a 'binding' member") }
        var out = params
        out[JKey("binding")] = .object(b)
        return out
    }

    /// Why a path is ambiguous (parsers could disagree on it), or nil when it is canonical.
    public static func ambiguousPathReason(_ path: String) -> String? {
        let s = Array(path.unicodeScalars)
        if s.contains(where: { $0.value <= 0x1F || $0.value == 0x7F || $0 == "\\" }) { return "control character or backslash in path" }
        if path.contains("//") { return "repeated slash in path" }
        if s.contains(";") { return "path parameter (;) in path" }
        if path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) { return "dot segment in path" }
        func hex(_ c: Unicode.Scalar) -> UInt32? { c.isASCII ? WhatwgURL.hexVal(UInt8(c.value)).map { UInt32($0) } : nil }
        var i = 0
        while i < s.count {
            if s[i] == "%", i + 2 < s.count, let h = hex(s[i + 1]), let l = hex(s[i + 2]) {
                let code = h << 4 | l, ch = Unicode.Scalar(code)!
                if code < 0x20 || code == 0x7F { return "percent-encoded control character in path" }
                if ch == "/" || ch == "\\" { return "percent-encoded slash in path" }
                if ch == ";" { return "percent-encoded path parameter delimiter in path" }
                if (ch.value >= 0x30 && ch.value <= 0x39) || (ch.value >= 0x41 && ch.value <= 0x5A) || (ch.value >= 0x61 && ch.value <= 0x7A) || "-._~".unicodeScalars.contains(ch) { return "non-canonical percent-encoding in path" }
                i += 3
            } else { i += 1 }
        }
        for k in s.indices where s[k] == "%" {
            if !(k + 2 < s.count && hex(s[k + 1]) != nil && hex(s[k + 2]) != nil) { return "malformed percent-encoding in path" }
        }
        return nil
    }

    // MARK: replay guard, provenance log

    public protocol ReplayGuard {
        /// True the first time `key` is claimed (until `expiresAtMs`), false while it is live; throws when the store cannot decide.
        func claim(_ key: String, expiresAtMs: Double, nowMs: Double?) throws -> Bool
    }

    /// An in-memory guard bounded to `maxEntries` (expired entries are purged when full; still full throws, never evicts a live one).
    public final class MemoryReplayGuard: ReplayGuard {
        private var seen: [String: Double] = [:]
        private let maxEntries: Int
        private let now: () -> Double
        public init(maxEntries: Int = 100_000, now: (() -> Double)? = nil) {
            self.maxEntries = maxEntries
            self.now = now ?? { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
        }
        public func claim(_ key: String, expiresAtMs: Double, nowMs: Double? = nil) throws -> Bool {
            let t = nowMs ?? now()
            // a clock or expiry that is not finite cannot say whether a claim is still live: refuse
            if !t.isFinite || !expiresAtMs.isFinite { throw GatewayError("replay guard: the clock and the claim expiry must be finite numbers") }
            if seen.count >= maxEntries {
                seen = seen.filter { !($0.value < t) }
                if seen.count >= maxEntries { throw GatewayError("replay guard full") }
            }
            if let e = seen[key], e >= t { return false }
            seen[key] = expiresAtMs
            return true
        }
    }

    public static func memoryReplayGuard(_ maxEntries: Int = 100_000, now: (() -> Double)? = nil) -> MemoryReplayGuard { MemoryReplayGuard(maxEntries: maxEntries, now: now) }

    /// One provenance observation: where a value came from (`undefined` members are nil).
    public struct ProvObservation {
        public var origin: JSONValue?
        public var source: JSONValue?
        public init(origin: JSONValue? = nil, source: JSONValue? = nil) {
            self.origin = origin
            self.source = source
        }
        func same(_ o: ProvObservation) -> Bool { IV.strictEq(origin, o.origin) && IV.strictEq(source, o.source) }
        /// The `{origin, source}` object the provenance gate reads (an `undefined` member is left out).
        var json: JSONValue {
            var o: JObject = [:]
            if let x = origin { o["origin"] = x }
            if let x = source { o["source"] = x }
            return .object(o)
        }
    }

    /// The gateway's per-session record of what it let through: every allowed call is untrusted tool output reaching that session, and later calls
    /// of the session are decided with these observations joined in (raise only). A store that throws makes the request deny (fail closed).
    public protocol ProvenanceLog {
        func seen(_ session: String) throws -> [ProvObservation]
        func add(_ session: String, _ o: ProvObservation) throws
    }

    /// Per-session observations, bounded: at most 256 distinct per session and `maxSessions` sessions (the least recently added is dropped).
    public final class MemoryProvenanceLog: ProvenanceLog {
        private let lock = NSLock()
        private var order: [String] = []
        private var map: [String: [ProvObservation]] = [:]
        private let maxSessions: Int
        public init(maxSessions: Int = 10_000) { self.maxSessions = maxSessions }
        public func seen(_ session: String) -> [ProvObservation] { lock.lock(); defer { lock.unlock() }; return map[session] ?? [] }
        public func add(_ session: String, _ o: ProvObservation) {
            lock.lock(); defer { lock.unlock() }
            var cur = map[session] ?? []
            order.removeAll { $0 == session }
            if !cur.contains(where: { $0.same(o) }), cur.count < 256 { cur.append(ProvObservation(origin: o.origin, source: o.source)) }
            map[session] = cur
            order.append(session)
            while order.count > maxSessions { map[order.removeFirst()] = nil }
        }
    }

    // MARK: presented artifacts

    public enum Presented {
        /// Nothing presented (the reference's `undefined`).
        case absent
        /// Presented; JSON null = presented but unreadable (a gate refuses it).
        case value(JSONValue)
    }

    public enum ParamsSource {
        /// The agent signed the request body as its params.
        case body
        case fn((GatewayRequest) throws -> JObject?)
        var isFunction: Bool { if case .fn = self { return true } else { return false } }
    }

    private static func headerJSON(_ h: String) -> JSONValue? {
        guard let text = PcaGuard.decodeHeader(h) else { return nil }
        return try? StrictJSON.parse(text)
    }

    private static func bodyObject(_ req: GatewayRequest, _ source: ParamsSource) -> JObject? {
        guard source.isFunction, let b = req.body, !b.isEmpty, let v = try? StrictJSON.parse(b) else { return nil }
        return v.asObject
    }

    /// The provenance bundle presented with a request: the `PCA-Provenance` header, else (function params) the body member `pca_provenance`.
    public static func presentedProvenance(_ req: GatewayRequest, _ source: ParamsSource) -> Presented {
        if let h = getHeader(req.headers, "pca-provenance"), !h.isEmpty {
            return .value(headerJSON(h) ?? .null) // unreadable: presented but malformed, the gate denies it
        }
        if let b = bodyObject(req, source), let p = b[JKey("pca_provenance")] { return .value(p) }
        return .absent
    }

    /// The discharges (an array) and narrow block presented with a request: the `PCA-Discharges` / `PCA-Narrow` headers, else the body members.
    public static func presentedArtifacts(_ req: GatewayRequest, _ source: ParamsSource) -> (discharges: [JSONValue]?, narrow: JSONValue?) {
        var discharges: [JSONValue]?, narrow: JSONValue?
        if let d = getHeader(req.headers, "pca-discharges"), !d.isEmpty, let a = headerJSON(d)?.asArray { discharges = a }
        if let n = getHeader(req.headers, "pca-narrow"), !n.isEmpty, let v = headerJSON(n) { narrow = v }
        if let b = bodyObject(req, source) {
            if discharges == nil, let a = b[JKey("pca_discharges")]?.asArray { discharges = a }
            if narrow == nil, let n = b[JKey("pca_narrow")] { narrow = n }
        }
        return (discharges, narrow)
    }
}
