import Foundation

/// Authorization-request builders: `{var}` substitution, PKCE, the authorize URL, and how an access token is presented to the provider API.
extension PCAConnectors {
    public enum PkceOption {
        /// PKCE off even where the manifest asks for it.
        case off
        /// PKCE on with a random verifier.
        case on
        /// PKCE on with this verifier (43 to 128 unreserved characters) and method ("S256", or "plain" when `allowPlainPkce`).
        case params(verifier: String, method: String?)
    }

    public struct BuildAuthorizeUrlOptions {
        public var clientId: String?
        public var redirectUri: String
        public var scopes: [String]?
        public var state: String?
        public var pkce: PkceOption?
        public var vars: JObject?
        public var registry: ProviderRegistry?
        /// Extra authorize parameters, in this order.
        public var extraParams: [(String, String)]
        public var allowUnlistedScopes = false
        public var allowPlainPkce = false
        public init(clientId: String?, redirectUri: String, scopes: [String]? = nil, state: String? = nil, pkce: PkceOption? = nil, vars: JObject? = nil, registry: ProviderRegistry? = nil,
                    extraParams: [(String, String)] = []) {
            self.clientId = clientId
            self.redirectUri = redirectUri
            self.scopes = scopes
            self.state = state
            self.pkce = pkce
            self.vars = vars
            self.registry = registry
            self.extraParams = extraParams
        }
    }

    public struct PkceResult: Equatable {
        public var verifier: String
        public var challenge: String
        public var method: String
    }

    public struct AuthorizeUrl {
        public var url: String
        public var state: String
        public var pkce: PkceResult?
    }

    static func randomToken(_ bytes: Int = 32) -> String { Base64URLStrict.encode((0..<bytes).map { _ in UInt8.random(in: 0...255) }) }

    /// `S256` (the default, and for any method but "plain"): base64url(sha256(verifier)); "plain": the verifier itself.
    public static func pkceChallenge(_ verifier: String, _ method: String = "S256") -> String {
        method == "plain" ? verifier : Base64URLStrict.encode(Canonical.sha256(Array(verifier.utf8)))
    }

    /// Substitute `{var}` placeholders. A variable is a DNS label (a shop, an account): anything else could move the request to another host
    /// or path (`evil.com/x?` in `https://{shop}.myshopify.com/...` would send the authorization code to evil.com), so it is refused.
    public static func substituteVars(_ url: String, _ vars: JObject?) throws -> String {
        let s = Array(url.unicodeScalars)
        var out = String.UnicodeScalarView(), at = 0
        for p in placeholders(s) {
            out.append(contentsOf: s[at..<p.range.lowerBound])
            at = p.range.upperBound
            guard let v = vars?[JKey(p.name)] else { throw ConnectorError("missing URL variable '{\(p.name)}'") }
            let label = Array((v.asString ?? "\u{0}").unicodeScalars)
            guard v.asString != nil, (1...63).contains(label.count), label.allSatisfy({ isWord($0) && $0 != "_" || $0 == "-" }), label[0] != "-" else {
                throw ConnectorError("URL variable '{\(p.name)}' must be a single DNS label (letters, digits and hyphens)")
            }
            out.append(contentsOf: label)
        }
        out.append(contentsOf: s[at...])
        return String(out)
    }

    private static func encodeForm(_ params: [(String, String)]) -> String { params.map { "\(JS.encodeURIComponent($0.0))=\(JS.encodeURIComponent($0.1))" }.joined(separator: "&") }

    private static func isUnreserved(_ c: Unicode.Scalar) -> Bool { (isWord(c) && c != "_") || c == "_" || c == "." || c == "~" || c == "-" }

    public static func buildAuthorizeUrl(_ providerId: String, _ options: BuildAuthorizeUrlOptions) throws -> AuthorizeUrl {
        let manifest = try (options.registry ?? defaultRegistry).require(providerId)
        let scopes = options.scopes ?? manifest.defaultScopes
        let separator = manifest.scopeSeparator ?? " "
        let state = options.state ?? randomToken()

        guard let clientId = options.clientId, !clientId.isEmpty else { throw ConnectorError("buildAuthorizeUrl: clientId must be a non-empty string") }
        try checkRedirectUri(options.redirectUri)
        guard state.utf16.count >= 16 else { throw ConnectorError("buildAuthorizeUrl: state must be at least 16 characters (omit it to get a random one)") }
        try checkScopes(manifest, scopes, options.allowUnlistedScopes)
        for (k, _) in options.extraParams where RESERVED_AUTHORIZE_PARAMS.contains(k) { throw ConnectorError("buildAuthorizeUrl: extraParams may not set '\(k)'") }

        var params: [(String, String)] = [("response_type", "code"), ("client_id", clientId), ("redirect_uri", options.redirectUri)]
        if !scopes.isEmpty { params.append(("scope", scopes.joined(separator: separator))) }
        params.append(("state", state))

        // PKCE: on when requested, when a verifier is passed, or (unless disabled) when the manifest declares it.
        var wantPkce = manifest.pkce == true
        if let p = options.pkce { if case .off = p { wantPkce = false } else { wantPkce = true } }
        var pkce: PkceResult?
        if wantPkce {
            var verifier = randomToken(), method = "S256"
            if case let .params(v, m)? = options.pkce { verifier = v; method = m ?? "S256" }
            let vs = Array(verifier.unicodeScalars)
            guard (43...128).contains(vs.count), vs.allSatisfy(isUnreserved) else { throw ConnectorError("buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)") }
            guard method == "S256" || (method == "plain" && options.allowPlainPkce) else { throw ConnectorError("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')") }
            let challenge = pkceChallenge(verifier, method)
            params.append(("code_challenge", challenge))
            params.append(("code_challenge_method", method))
            pkce = PkceResult(verifier: verifier, challenge: challenge, method: method)
        }
        params += manifest.authParams ?? []
        params += options.extraParams

        let base = try substituteVars(manifest.authorizeUrl, options.vars)
        return AuthorizeUrl(url: "\(base)\(base.contains("?") ? "&" : "?")\(encodeForm(params))", state: state, pkce: pkce)
    }

    private static func checkRedirectUri(_ uri: String) throws {
        guard let u = WhatwgURL.parse(uri) else { throw ConnectorError("buildAuthorizeUrl: redirectUri must be an absolute URL") }
        let x = WhatwgURL.userinfoAndFragment(uri)
        if x.fragment { throw ConnectorError("buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)") }
        if x.userinfo { throw ConnectorError("buildAuthorizeUrl: redirectUri must not carry credentials") }
        let host = u.hostnameAndPort.hostname
        let local = host == "localhost" || host == "127.0.0.1" || host == "::1"
        if u.scheme != "https" && !(u.scheme == "http" && local) { throw ConnectorError("buildAuthorizeUrl: redirectUri must be https (http only for localhost)") }
    }

    private static func checkScopes(_ m: ProviderManifest, _ scopes: [String], _ allowUnlisted: Bool) throws {
        var seen: [String] = []
        let sep = m.scopeSeparator ?? " "
        for s in scopes {
            if s.isEmpty || s.unicodeScalars.contains(where: { Attest.isJSSpace($0) || $0 == "," }) || s.contains(sep) {
                throw ConnectorError("buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator")
            }
            if IV.contains(seen, s) { throw ConnectorError("buildAuthorizeUrl: scope '\(s)' is listed twice") }
            seen.append(s)
            if !allowUnlisted, !m.scopesAvailable.isEmpty, !IV.contains(m.scopesAvailable, s) {
                throw ConnectorError("buildAuthorizeUrl: scope '\(s)' is not offered by provider '\(m.id)'")
            }
        }
    }

    public struct AppliedToken: Equatable {
        /// "header" or "query".
        public var kind: String
        public var name: String
        public var value: String
    }

    /// How the access token goes on an outbound call. A control character or space in a token would end the header value (response
    /// splitting) or add a header, so only printable ASCII without spaces is accepted.
    public static func applyAccessToken(_ manifest: ProviderManifest, _ accessToken: String?) throws -> AppliedToken {
        guard let t = accessToken, !t.isEmpty, t.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value <= 0x7E }) else {
            throw ConnectorError("applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces")
        }
        switch manifest.tokenPlacement {
        case .bearer: return AppliedToken(kind: "header", name: "Authorization", value: "Bearer \(t)")
        case .header:
            guard let n = manifest.headerName else { throw ConnectorError("manifest '\(manifest.id)' is header-placed but has no headerName") }
            return AppliedToken(kind: "header", name: n, value: t)
        case .query:
            guard let n = manifest.queryParam else { throw ConnectorError("manifest '\(manifest.id)' is query-placed but has no queryParam") }
            return AppliedToken(kind: "query", name: n, value: t)
        }
    }
}
