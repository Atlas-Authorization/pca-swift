import Foundation

/// Authorization-code exchange and refresh: the token request is built from the manifest, sent through the injected transport, and the
/// result is stored in the vault bound to a capability (so the stored token is only ever released by a verified PCActn).
extension PCAConnectors {
    /// Where the minted connection is stored, and which capability may use it.
    public struct ConnectionBinding {
        public var vault: PCAConnect.TokenVault
        public var agentId: String
        public var connectionId: String?
        /// The base64url key the capability chain must be rooted at.
        public var principal: String
        /// Scopes the capability must cover; defaults to the requested scopes.
        public var scopes: [String]?
        public var audience: String?
        public init(vault: PCAConnect.TokenVault, agentId: String, connectionId: String? = nil, principal: String, scopes: [String]? = nil, audience: String? = nil) {
            self.vault = vault
            self.agentId = agentId
            self.connectionId = connectionId
            self.principal = principal
            self.scopes = scopes
            self.audience = audience
        }
    }

    public struct ExchangeCodeArgs {
        public var providerId: String
        public var clientId: String
        public var clientSecret: String?
        public var code: String?
        public var redirectUri: String
        public var codeVerifier: String?
        public var scopes: [String]?
        public var fetch: PCAConnect.VaultFetch
        public var bind: ConnectionBinding
        /// Epoch ms; defaults to the system clock.
        public var now: Double?
        public var registry: ProviderRegistry?
        public var vars: JObject?
        public var extraParams: [(String, String)] = []
        public init(providerId: String, clientId: String, clientSecret: String? = nil, code: String?, redirectUri: String, codeVerifier: String? = nil, scopes: [String]? = nil,
                    fetch: @escaping PCAConnect.VaultFetch, bind: ConnectionBinding, now: Double? = nil, registry: ProviderRegistry? = nil, vars: JObject? = nil, extraParams: [(String, String)] = []) {
            self.providerId = providerId
            self.clientId = clientId
            self.clientSecret = clientSecret
            self.code = code
            self.redirectUri = redirectUri
            self.codeVerifier = codeVerifier
            self.scopes = scopes
            self.fetch = fetch
            self.bind = bind
            self.now = now
            self.registry = registry
            self.vars = vars
            self.extraParams = extraParams
        }
    }

    public struct RefreshArgs {
        public var providerId: String
        public var clientId: String
        public var clientSecret: String?
        public var refreshToken: String?
        public var scopes: [String]?
        public var fetch: PCAConnect.VaultFetch
        public var bind: ConnectionBinding
        public var now: Double?
        public var registry: ProviderRegistry?
        public var vars: JObject?
        public var extraParams: [(String, String)] = []
        public init(providerId: String, clientId: String, clientSecret: String? = nil, refreshToken: String?, scopes: [String]? = nil, fetch: @escaping PCAConnect.VaultFetch,
                    bind: ConnectionBinding, now: Double? = nil, registry: ProviderRegistry? = nil, vars: JObject? = nil, extraParams: [(String, String)] = []) {
            self.providerId = providerId
            self.clientId = clientId
            self.clientSecret = clientSecret
            self.refreshToken = refreshToken
            self.scopes = scopes
            self.fetch = fetch
            self.bind = bind
            self.now = now
            self.registry = registry
            self.vars = vars
            self.extraParams = extraParams
        }
    }

    private struct ParsedToken {
        var accessToken: String
        var refreshToken: String?
        var expiresInSecs: Double?
        var scopes: [String]?
    }

    private static let DEFAULT_TOKEN_LIFETIME_MS = 3_600_000.0

    private static func checkExtraParams(_ extra: [(String, String)], _ what: String) throws {
        for (k, _) in extra where RESERVED_TOKEN_PARAMS.contains(k) { throw ConnectorError("\(what): extraParams may not set '\(k)'") }
    }

    /// An ordered parameter list with JS object semantics: a repeated name replaces the earlier value in place.
    private struct Params {
        var items: [(String, String)] = []
        mutating func set(_ k: String, _ v: String) {
            if let i = items.firstIndex(where: { IV.same($0.0, k) }) { items[i].1 = v } else { items.append((k, v)) }
        }
        subscript(_ k: String) -> String? { items.first { IV.same($0.0, k) }?.1 }
        mutating func remove(_ k: String) { items.removeAll { IV.same($0.0, k) } }
    }

    private static func errText(_ e: Error) -> String { (e as? JSError)?.message ?? "\(e)" }

    private static func parseTokenResponse(_ body: JSONValue, _ provider: String) throws -> ParsedToken {
        guard let o = body.asObject else { throw ConnectorError("[\(provider)] token endpoint returned a non-object body") }
        guard let at = o[JKey("access_token")]?.asString, !at.isEmpty else { throw ConnectorError("[\(provider)] token endpoint response has no access_token") }
        var out = ParsedToken(accessToken: at)
        if let e = IV.num(o[JKey("expires_in")]), e.isFinite, e > 0 { out.expiresInSecs = e }
        if let r = o[JKey("refresh_token")]?.asString, !r.isEmpty { out.refreshToken = r }
        if let sc = o[JKey("scope")]?.asString {
            let t = Attest.jsTrim(sc)
            if !t.isEmpty { out.scopes = splitScopes(t) }
        }
        return out
    }

    /// `text.split(/[\s,]+/)`: runs of whitespace or commas separate; a leading or trailing separator leaves an empty piece.
    static func splitScopes(_ t: String) -> [String] {
        var out: [String] = [], cur = String.UnicodeScalarView(), inSep = false
        for c in t.unicodeScalars {
            if Attest.isJSSpace(c) || c == "," {
                if !inSep { out.append(String(cur)); cur = String.UnicodeScalarView(); inSep = true }
            } else { cur.append(c); inSep = false }
        }
        out.append(String(cur))
        return out
    }

    private static func postToken(_ m: ProviderManifest, _ tokenEndpoint: String, _ params: Params, _ clientSecret: String?, _ fetch: PCAConnect.VaultFetch) throws -> ParsedToken {
        var headers: [(String, String)] = [("content-type", "application/x-www-form-urlencoded"), ("accept", "application/json")]
        var body = params
        var authorization: String?
        if m.clientAuth == .basic {
            // Client credentials move to the Authorization header; they must not also appear in the body.
            guard let secret = clientSecret else { throw ConnectorError("[\(m.id)] clientAuth 'basic' requires a clientSecret") }
            guard let cid = body["client_id"] else { throw ConnectorError("[\(m.id)] missing client_id for basic auth") }
            authorization = "Basic " + Data(Array("\(cid):\(secret)".utf8)).base64EncodedString()
            headers.append(("authorization", authorization!))
            body.remove("client_id")
            body.remove("client_secret")
        }
        let secrets: [String?] = [clientSecret, params["code"], params["code_verifier"], params["refresh_token"], authorization]
        func redact(_ text: String) -> String { secrets.reduce(text) { acc, s in s.map { PCAConnect.replaceAll(acc, $0, "[redacted]") } ?? acc } }
        let res: PCAConnect.VaultHttpResponse
        do {
            res = try fetch(tokenEndpoint, PCAConnect.VaultHttpRequest(method: "POST", headers: headers, body: body.items.map { "\(JS.encodeURIComponent($0.0))=\(JS.encodeURIComponent($0.1))" }.joined(separator: "&")))
        } catch {
            throw ConnectorError("[\(m.id)] token transport error: \(redact(errText(error)))")
        }
        if !res.ok {
            var detail: String
            do { detail = redact(String(decoding: Array((try res.text()).utf16.prefix(256)), as: UTF16.self)) } catch { detail = "<unreadable body>" }
            throw ConnectorError("[\(m.id)] token endpoint \(res.status): \(detail)")
        }
        let json: JSONValue
        do { json = try res.json() } catch { throw ConnectorError("[\(m.id)] unparseable token JSON") } // the parser's message quotes the body, which may hold a token
        return try parseTokenResponse(json, m.id)
    }

    private static func storeConnection(_ m: ProviderManifest, _ p: ParsedToken, _ requested: [String], _ bind: ConnectionBinding, _ now: Double, _ prior: String? = nil) throws -> PCAConnect.StoredConnection {
        let expiresAt = p.expiresInSecs.map { now + $0 * 1000 } ?? (now + DEFAULT_TOKEN_LIFETIME_MS)
        return try bind.vault.putConnection(PCAConnect.PutConnectionArgs(
            agentId: bind.agentId, provider: m.id, connectionId: bind.connectionId, accessToken: p.accessToken, refreshToken: p.refreshToken ?? prior, expiresAt: expiresAt,
            scopes: p.scopes ?? requested, principal: bind.principal, authorityScopes: bind.scopes ?? requested, audience: bind.audience))
    }

    private static func nowMs() -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }

    /// Exchange an authorization code for tokens and store the connection in the vault, bound to `bind.principal`.
    public static func exchangeCode(_ a: ExchangeCodeArgs) throws -> PCAConnect.StoredConnection {
        let m = try (a.registry ?? defaultRegistry).require(a.providerId)
        let now = a.now ?? nowMs()
        let requested = a.scopes ?? m.defaultScopes
        guard let code = a.code, !code.isEmpty else { throw ConnectorError("[\(m.id)] an authorization code is required") }
        try checkExtraParams(a.extraParams, "[\(m.id)] exchangeCode")
        if m.pkce == true, a.codeVerifier == nil { throw ConnectorError("[\(m.id)] provider uses PKCE; a codeVerifier is required to exchange the code") }

        var params = Params()
        params.set("grant_type", "authorization_code")
        params.set("code", code)
        params.set("redirect_uri", a.redirectUri)
        params.set("client_id", a.clientId)
        if let s = a.clientSecret { params.set("client_secret", s) }
        if let v = a.codeVerifier { params.set("code_verifier", v) }
        for (k, v) in a.extraParams { params.set(k, v) }
        let endpoint = try substituteVars(m.tokenUrl, a.vars)
        let parsed = try postToken(m, endpoint, params, a.clientSecret, a.fetch)
        return try storeConnection(m, parsed, requested, a.bind, now)
    }

    /// Refresh the stored token with the refresh token and store the result (the prior refresh token is kept unless the provider rotated it).
    public static func refresh(_ a: RefreshArgs) throws -> PCAConnect.StoredConnection {
        let m = try (a.registry ?? defaultRegistry).require(a.providerId)
        if m.refresh.mode == .none { throw ConnectorError("[\(m.id)] provider does not support token refresh") }
        let now = a.now ?? nowMs()
        let requested = a.scopes ?? m.defaultScopes
        guard let rt = a.refreshToken, !rt.isEmpty else { throw ConnectorError("[\(m.id)] a refresh token is required") }
        try checkExtraParams(a.extraParams, "[\(m.id)] refresh")

        var params = Params()
        params.set("grant_type", "refresh_token")
        params.set("refresh_token", rt)
        params.set("client_id", a.clientId)
        if let s = a.clientSecret { params.set("client_secret", s) }
        for (k, v) in m.refresh.extraParams ?? [] { params.set(k, v) }
        for (k, v) in a.extraParams { params.set(k, v) }
        if m.refresh.supportsScopeNarrowing == true, !requested.isEmpty { params.set("scope", requested.joined(separator: m.scopeSeparator ?? " ")) }
        let endpoint = try substituteVars(m.refresh.tokenEndpoint ?? m.tokenUrl, a.vars)
        let parsed = try postToken(m, endpoint, params, a.clientSecret, a.fetch)
        return try storeConnection(m, parsed, requested, a.bind, now, rt)
    }

    public struct ProviderCredentials {
        public var clientId: String
        public var clientSecret: String?
        public var vars: JObject?
        public init(clientId: String, clientSecret: String? = nil, vars: JObject? = nil) {
            self.clientId = clientId
            self.clientSecret = clientSecret
            self.vars = vars
        }
    }

    /// The vault's token-endpoint config for a provider, with the optional members the manifest declared kept optional.
    public struct VaultProviderConfig {
        public var tokenEndpoint: String
        public var clientId: String
        public var clientSecret: String?
        public var supportsScopeNarrowing: Bool?
        public var extraParams: [(String, String)]?

        /// The `PCAConnect` form (an undeclared narrowing flag is false).
        public var vault: PCAConnect.ProviderConfig {
            PCAConnect.ProviderConfig(tokenEndpoint: tokenEndpoint, clientId: clientId, clientSecret: clientSecret, supportsScopeNarrowing: supportsScopeNarrowing == true, extraParams: extraParams ?? [])
        }

        public var json: JSONValue {
            var o: JObject = ["tokenEndpoint": .string(tokenEndpoint), "clientId": .string(clientId)]
            if let s = clientSecret { o["clientSecret"] = .string(s) }
            if let n = supportsScopeNarrowing { o["supportsScopeNarrowing"] = .bool(n) }
            if let e = extraParams {
                var p = JObject()
                for (k, v) in e { p[JKey(k)] = .string(v) }
                o["extraParams"] = .object(p)
            }
            return .object(o)
        }
    }

    /// The vault's provider config for a refreshable manifest (a provider whose tokens do not refresh has none).
    public static func manifestToProviderConfig(_ m: ProviderManifest, _ creds: ProviderCredentials) throws -> VaultProviderConfig {
        if m.refresh.mode == .none { throw ConnectorError("[\(m.id)] provider does not support token refresh; no ProviderConfig") }
        return VaultProviderConfig(tokenEndpoint: try substituteVars(m.refresh.tokenEndpoint ?? m.tokenUrl, creds.vars), clientId: creds.clientId, clientSecret: creds.clientSecret,
                                   supportsScopeNarrowing: m.refresh.supportsScopeNarrowing, extraParams: m.refresh.extraParams)
    }

    /// Provider configs for every refreshable provider named in `credsById`, for `TokenVault`'s `providers` option.
    public static func buildVaultProviders(_ credsById: [(String, ProviderCredentials)], registry: ProviderRegistry = defaultRegistry) throws -> [(String, VaultProviderConfig)] {
        var out: [(String, VaultProviderConfig)] = []
        for (id, creds) in credsById {
            let m = try registry.require(id)
            if m.refresh.mode == .none { continue }
            out.append((id, try manifestToProviderConfig(m, creds)))
        }
        return out
    }
}
