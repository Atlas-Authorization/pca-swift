import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Thin client for the grant management resource (pca-grants client.ts). It also carries the newest `pca-fresh-at` token it has seen: a token that
/// does not verify under `freshSigner` (when set) is ignored, and a token never replaces a fresher one. The transport is injected (default: a
/// blocking URLSession call; run it off the main thread).
public final class GrantClient: @unchecked Sendable {
    public struct ApiError: Error, CustomStringConvertible {
        public let status: Int
        public let code: String
        public let message: String
        public var description: String { message }
    }

    /// One HTTP exchange: method, absolute URL, request headers, body (nil: none) to (status, response headers (lower-case names), body text).
    public typealias Transport = (_ method: String, _ url: String, _ headers: [String: String], _ body: String?) throws -> (status: Int, headers: [String: String], body: String)

    private static let COUNTERS = ["revocation_epoch", "policy_revision", "ledger_tree_size", "budget_version"]

    private let baseUrl: String
    private let transport: Transport
    private let freshSigner: String?
    private let headers: (() -> [String: String])?
    private var latest: JObject?
    private let lock = PCALock()

    public init(baseUrl: String, freshSigner: String? = nil, headers: (() -> [String: String])? = nil, transport: Transport? = nil) {
        self.baseUrl = baseUrl.hasSuffix("/") ? String(baseUrl.dropLast()) : baseUrl
        self.freshSigner = freshSigner
        self.headers = headers
        self.transport = transport ?? GrantClient.urlSessionTransport
    }

    /// The default transport: a blocking exchange over URLSession.
    public static let urlSessionTransport: Transport = { method, url, headers, body in
        guard let u = URL(string: url) else { throw JSError("invalid url") }
        var req = URLRequest(url: u)
        req.httpMethod = method
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let b = body { req.httpBody = Data(b.utf8) }
        final class Box: @unchecked Sendable { var out: (Int, [String: String], String)?; var err: Error? }
        let box = Box(), sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { data, resp, err in
            if let h = resp as? HTTPURLResponse {
                var hs: [String: String] = [:]
                for (k, v) in h.allHeaderFields { hs[String(describing: k).lowercased()] = String(describing: v) }
                box.out = (h.statusCode, hs, String(decoding: data ?? Data(), as: UTF8.self))
            }
            box.err = err
            sem.signal()
        }.resume()
        sem.wait()
        if let e = box.err { throw e }
        guard let o = box.out else { throw JSError("no http response") }
        return (o.0, o.1, o.2)
    }

    /// The newest consistency token seen on any response (attach it to later requests for read-your-writes), or nil.
    public func freshAt() -> JObject? { lock.lock(); defer { lock.unlock() }; return latest }

    /// Fold the newest token into a local state; nil when none was seen.
    public func foldFreshAt(_ state: JObject) throws -> JSONValue? {
        guard let l = freshAt() else { return nil }
        return try PCAGrants.mergeFreshAt(l, state)
    }

    private func call(_ method: String, _ path: String, _ body: JSONValue?) throws -> JObject {
        var h: [String: String] = ["content-type": "application/json"]
        if let l = freshAt() { h["pca-fresh-at"] = Canonical.canonicalize(.object(l)) }
        for (k, v) in headers?() ?? [:] { h[k] = v }
        let res = try transport(method, baseUrl + path, h, body.map { Canonical.canonicalize($0) })
        if let t = res.headers["pca-fresh-at"] { fold(t) }
        let json = (try? StrictJSON.parseLenient(res.body))?.asObject ?? [:] // a non-JSON body is treated as an empty object
        if res.status < 200 || res.status > 299 {
            throw ApiError(status: res.status, code: json["error"]?.asString ?? "error", message: json["message"]?.asString ?? "HTTP \(res.status)")
        }
        return json
    }

    private func fold(_ tok: String) {
        // a malformed header is ignored: freshness is only ever tightened by a valid token
        guard let t = (try? StrictJSON.parseLenient(tok))?.asObject else { return }
        if let s = freshSigner, !FreshAt.verify(.object(t), signer: s) { return }
        var cs: [Int64] = []
        for k in Self.COUNTERS { guard let n = K3Sig.safeInt(t[JKey(k)]) else { return }; cs.append(n) }
        lock.lock(); defer { lock.unlock() }
        var newer = true
        if let cur = latest {
            for (i, k) in Self.COUNTERS.enumerated() { newer = newer && cs[i] >= (K3Sig.safeInt(cur[JKey(k)]) ?? 0) }
        }
        if newer { latest = t } // monotone fold: never replace a fresher token with an older one
    }

    /// JavaScript encodeURIComponent.
    static func enc(_ s: String) -> String { JS.encodeURIComponent(s) }

    public func list(_ q: [(String, String?)] = []) throws -> JObject {
        var parts: [String] = []
        for (k, v) in q { if let v = v { parts.append(Self.enc(k) + "=" + Self.enc(v)) } }
        return try call("GET", GrantHttp.GRANTS_PATH + (parts.isEmpty ? "" : "?" + parts.joined(separator: "&")), nil)
    }

    public func inspect(_ id: String) throws -> JObject { try call("GET", GrantHttp.GRANTS_PATH + "/" + Self.enc(id), nil) }

    public func amend(_ id: String, _ req: JObject) throws -> JObject { try call("POST", GrantHttp.GRANTS_PATH + "/" + Self.enc(id) + "/amend", .object(req)) }

    /// `scope` nil means grant; `sig` nil sends no body (an admin revoke).
    public func revoke(_ id: String, scope: String? = nil, sig: String? = nil) throws -> JObject {
        let body: JSONValue? = (sig ?? "").isEmpty ? nil : .object(["sig": .string(sig!)])
        return try call("DELETE", GrantHttp.GRANTS_PATH + "/" + Self.enc(id) + "?scope=" + (scope ?? "grant"), body)
    }

    public func requestNeeds(_ id: String, _ needs: [JSONValue]) throws -> JObject {
        try call("POST", GrantHttp.GRANTS_PATH + "/" + Self.enc(id) + "/needs", .object(["needs": .array(needs)]))
    }

    public func approveNeeds(_ needId: String, approved: [JSONValue], sig: String, stepUpRef: String? = nil) throws -> JObject {
        var body: JObject = ["approved": .array(approved), "sig": .string(sig)]
        if let r = stepUpRef, !r.isEmpty { body["step_up_ref"] = .string(r) }
        return try call("POST", GrantHttp.NEEDS_PATH + "/" + Self.enc(needId) + "/approve", .object(body))
    }

    public func denyNeeds(_ needId: String) throws -> JObject { try call("POST", GrantHttp.NEEDS_PATH + "/" + Self.enc(needId) + "/deny", nil) }
}

/// The TypeScript name of `GrantClient`'s factory (pca-grants client.ts `createGrantClient`) and error (`GrantApiError`).
public typealias GrantApiError = GrantClient.ApiError

public func createGrantClient(baseUrl: String, freshSigner: String? = nil, headers: (() -> [String: String])? = nil, transport: GrantClient.Transport? = nil) -> GrantClient {
    GrantClient(baseUrl: baseUrl, freshSigner: freshSigner, headers: headers, transport: transport)
}
