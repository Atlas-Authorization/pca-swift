import Foundation

/// OAuth token refresh over an injected transport.
extension PCAConnect {
    /// Per-provider OAuth token-endpoint configuration used to refresh an access token.
    public struct ProviderConfig {
        /// The provider's OAuth 2.0 token endpoint (RFC 6749 section 3.2).
        public var tokenEndpoint: String
        public var clientId: String
        /// nil for public clients / PKCE.
        public var clientSecret: String?
        /// When true, a narrowed `scope` is sent on refresh so the minted token carries only the requested scopes.
        public var supportsScopeNarrowing: Bool
        /// Extra static form parameters merged into every refresh request (in this order; a repeated name replaces the earlier value in place).
        public var extraParams: [(String, String)]
        public init(tokenEndpoint: String, clientId: String, clientSecret: String? = nil, supportsScopeNarrowing: Bool = false, extraParams: [(String, String)] = []) {
            self.tokenEndpoint = tokenEndpoint
            self.clientId = clientId
            self.clientSecret = clientSecret
            self.supportsScopeNarrowing = supportsScopeNarrowing
            self.extraParams = extraParams
        }
    }

    public struct VaultHttpRequest {
        public var method: String
        public var headers: [(String, String)]
        public var body: String
    }

    /// A structural view of an HTTP response; `json()` / `text()` throw when the body cannot be read.
    public struct VaultHttpResponse {
        public var ok: Bool
        public var status: Int
        public var json: () throws -> JSONValue
        public var text: () throws -> String
        public init(ok: Bool, status: Int, json: @escaping () throws -> JSONValue, text: @escaping () throws -> String) {
            self.ok = ok
            self.status = status
            self.json = json
            self.text = text
        }
    }

    /// The injectable transport (a throw is a transport error).
    public typealias VaultFetch = (String, VaultHttpRequest) throws -> VaultHttpResponse

    /// The fields to apply to a refreshed connection.
    public struct RefreshedFields: Equatable {
        public var accessToken: String
        public var refreshToken: String
        public var expiresAt: Double
        public var scopes: [String]
    }

    /// Every occurrence of `needle` in `text` replaced by `with` (code-unit exact, like `split(needle).join(with)`).
    static func replaceAll(_ text: String, _ needle: String, _ with: String) -> String {
        let t = Array(text.utf8), n = Array(needle.utf8)
        guard !n.isEmpty, t.count >= n.count else { return text }
        var out: [UInt8] = [], i = 0
        let w = Array(with.utf8)
        while i < t.count {
            if i + n.count <= t.count, t[i] == n[0], t[i..<(i + n.count)].elementsEqual(n) { out += w; i += n.count } else { out.append(t[i]); i += 1 }
        }
        return String(decoding: out, as: UTF8.self)
    }

    private static func errText(_ e: Error) -> String { (e as? JSError)?.message ?? "\(e)" }

    /// The epoch-ms expiry claimed by a JWT access token (a compact JWS with a JSON-object payload); nil for an opaque token.
    private static func jwtExpiryMs(_ token: String) -> Double? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let raw = Base64URLStrict.decode(String(parts[1])), let p = try? StrictJSON.parse(String(decoding: raw, as: UTF8.self)),
              let o = p.asObject, let e = IV.num(o[JKey("exp")]), e.isFinite else { return nil }
        return e * 1000
    }

    /// Refresh `connection`'s access token at its provider's token endpoint with the stored refresh token. `requested` is the
    /// least-privilege scope set the caller asked for; when the provider supports scope narrowing it is sent so the new token is minted no
    /// wider than requested. Throws `refresh_failed` on any transport / parse failure; its message never carries a secret.
    public static func refreshConnection(connection: StoredConnection, config: ProviderConfig?, refreshToken: String, requested: [String], fetch: VaultFetch?, now: Double,
                                         defaultTokenLifetimeMs: Double) throws -> RefreshedFields {
        let provider = connection.provider
        var secrets: [String?] = [refreshToken, connection.accessToken, config?.clientSecret]
        secrets += (config?.extraParams ?? []).map { $0.1 }
        func redact(_ text: String) -> String { secrets.reduce(text) { acc, s in s.map { replaceAll(acc, $0, "[redacted]") } ?? acc } }
        guard let config = config else { throw VaultError.refreshFailed(provider, "no provider token-endpoint config") }
        guard let fetch = fetch else { throw VaultError.refreshFailed(provider, "no fetch transport configured") }

        var params: [(String, String)] = [("grant_type", "refresh_token"), ("refresh_token", refreshToken), ("client_id", config.clientId)]
        func set(_ k: String, _ v: String) {
            if let i = params.firstIndex(where: { IV.same($0.0, k) }) { params[i].1 = v } else { params.append((k, v)) }
        }
        if let s = config.clientSecret { set("client_secret", s) }
        for (k, v) in config.extraParams { set(k, v) }
        if config.supportsScopeNarrowing && !requested.isEmpty { set("scope", requested.joined(separator: " ")) }
        let body = params.map { "\(JS.encodeURIComponent($0.0))=\(JS.encodeURIComponent($0.1))" }.joined(separator: "&")

        let res: VaultHttpResponse
        do {
            res = try fetch(config.tokenEndpoint, VaultHttpRequest(method: "POST", headers: [("content-type", "application/x-www-form-urlencoded"), ("accept", "application/json")], body: body))
        } catch {
            throw VaultError.refreshFailed(provider, "transport error: \(redact(errText(error)))")
        }
        if !res.ok {
            var detail: String
            do { detail = redact(String(decoding: Array((try res.text()).utf16.prefix(256)), as: UTF16.self)) } catch { detail = "<unreadable body>" }
            throw VaultError.refreshFailed(provider, "token endpoint \(res.status): \(detail)", status: res.status)
        }
        let json: JSONValue
        do { json = try res.json() } catch { throw VaultError.refreshFailed(provider, "unparseable JSON body") }

        guard let o = json.asObject else { throw VaultError.refreshFailed(provider, "token endpoint returned a non-object body") }
        guard let access = o[JKey("access_token")]?.asString, !access.isEmpty else { throw VaultError.refreshFailed(provider, "token endpoint response has no access_token") }
        var expiresIn: Double?
        if let e = IV.num(o[JKey("expires_in")]), e.isFinite, e > 0 { expiresIn = e }
        var newRefresh: String?
        if let r = o[JKey("refresh_token")]?.asString, !r.isEmpty { newRefresh = r }
        var scopes: [String]?
        if let sc = o[JKey("scope")]?.asString {
            let t = Attest.jsTrim(sc)
            if !t.isEmpty { scopes = t.unicodeScalars.split(whereSeparator: Attest.isJSSpace).map { String(String.UnicodeScalarView($0)) } }
        }
        let expiresAt = expiresIn.map { now + $0 * 1000 } ?? jwtExpiryMs(access) ?? (now + defaultTokenLifetimeMs)
        let finalScopes = scopes ?? (config.supportsScopeNarrowing && !requested.isEmpty ? requested : connection.scopes)
        return RefreshedFields(accessToken: access, refreshToken: newRefresh ?? refreshToken, expiresAt: expiresAt, scopes: finalScopes)
    }
}
