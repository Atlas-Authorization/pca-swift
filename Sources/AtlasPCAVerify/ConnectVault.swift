import Foundation

extension PCAConnect {
    // MARK: replay guard

    /// One-time-use store for presented actions: `consumeOnce` is true only for the first use of a key within its retention horizon.
    public protocol ReplayStore {
        func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool
    }

    /// Correct only for a single process whose lifetime covers the action lifetime (state is lost on restart, not shared). When full of live
    /// entries it refuses (throws) rather than evict.
    public final class InMemoryReplayStore: ReplayStore {
        private var seen: [String: Int64] = [:]
        private let maxEntries: Int
        public init(maxEntries: Int = 100_000) { self.maxEntries = maxEntries }
        public var size: Int { seen.count }

        public func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool {
            if key.isEmpty || retainUntil < now { throw ConnectError("consumeOnce: invalid key or retention horizon") }
            let until = seen[key]
            if let u = until, u >= now { return false }
            if until == nil, seen.count >= maxEntries {
                seen = seen.filter { $0.value >= now }
                if seen.count >= maxEntries { throw ConnectError("replay store full of live entries") }
            }
            seen[key] = max(retainUntil, until ?? 0)
            return true
        }
    }

    /// `replayKey(namespace, ...parts)`: `namespace:` + base64url(sha256 of each part as a 4-byte big-endian length and its UTF-8 bytes).
    public static func replayKey(_ namespace: String, _ parts: [String]) -> String {
        var buf: [UInt8] = []
        for p in [namespace] + parts {
            let b = Array(p.utf8)
            let n = UInt32(b.count)
            buf += [UInt8(n >> 24 & 0xFF), UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)] + b
        }
        return "\(namespace):\(Base64URLStrict.encode(Canonical.sha256(buf)))"
    }

    /// The replay guard of a PCActn presented to the vault (nonce required, no counter stream): nil = admitted, else the refusal reason.
    /// Every pre-check runs before the store is touched; a store failure is a refusal.
    static func guardReplay(_ store: ReplayStore, _ p: JSONValue, aud: String?, now: Int64) -> String? {
        func nonNeg(_ v: JSONValue?) -> Int64? { IV.nonNeg(v) }
        guard now >= -Canonical.MAX_SAFE, now <= Canonical.MAX_SAFE else { return "verifier clock is not an integer epoch-ms" }
        guard let a = aud, !a.isEmpty, a.utf8.count <= 256 else { return "verifier audience is invalid" }
        guard p.isObject else { return "not a PCActn" }
        guard let pa = p.get("aud")?.asString, IV.same(pa, a) else { return "the PCActn is for another audience" }
        guard let iat = nonNeg(p.get("iat")), let exp = nonNeg(p.get("exp")), exp > iat, exp - iat <= PCA.MAX_LIFETIME_MS else { return "iat / exp are not a valid bounded window" }
        let skew = PCA.MAX_SKEW_MS
        if iat > now + skew { return "iat is in the future beyond the clock-skew allowance" }
        if now > exp { return "the PCActn has expired" }
        let chain = p.get("cap_chain")?.asArray
        guard let holder = chain?.last?.get("holder")?.asString, let ref = p.get("grant_ref")?.asString else { return "no leaf holder / grant" }
        guard [ref, holder].allSatisfy({ !$0.isEmpty && $0.utf8.count <= 512 }) else { return "grant / holder is not a bounded string" }
        guard nonNeg(p.get("counter")) != nil else { return "counter is not a non-negative safe integer" }
        guard let nonce = p.get("nonce")?.asString, !nonce.isEmpty, nonce.utf8.count <= 128 else { return p.get("nonce") != nil ? "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" : "a nonce is required" }
        guard exp + skew <= Canonical.MAX_SAFE else { return "exp + clock skew exceeds the safe-integer range (retention horizon not representable)" }
        do {
            if try !store.consumeOnce(key: replayKey("pca-nonce/v1", [a, ref, holder, nonce]), retainUntil: exp + skew, now: now) { return "nonce already consumed" }
        } catch {
            return "replay store failed closed"
        }
        return nil
    }

    // MARK: vault

    /// What the vault knows about one action, pinned by its operator from a reviewed action pack. The scopes a credential may carry come
    /// from HERE (`scopesMin`), never from the caller and never from the grant alone.
    public struct VaultAction {
        public var verb: String
        /// Digest of the definition this mapping was written for (informational pin).
        public var defDigest: String
        /// True iff the definition carries a valid signed confirmation. Unconfirmed: nothing is released.
        public var confirmed: Bool
        public var provider: String
        public var scopesMin: [String]
        /// Proxy mode: map the outbound request back to the action's parameters (`httpExtractor`).
        public var extract: ((ProxyRequest) throws -> JObject)?
        public init(verb: String, defDigest: String, confirmed: Bool, provider: String, scopesMin: [String], extract: ((ProxyRequest) throws -> JObject)? = nil) {
            self.verb = verb
            self.defDigest = defDigest
            self.confirmed = confirmed
            self.provider = provider
            self.scopesMin = scopesMin
            self.extract = extract
        }
    }

    public struct GetConnectionTokenArgs {
        public var provider: String
        public var connectionId: String?
        /// The scopes the tool call needs; defaults to the connection's bound authority scopes.
        public var scopes: [String]?
        public init(provider: String, connectionId: String? = nil, scopes: [String]? = nil) {
            self.provider = provider
            self.connectionId = connectionId
            self.scopes = scopes
        }
    }

    public struct ProxyCallArgs {
        public var provider: String
        public var connectionId: String?
        public init(provider: String, connectionId: String? = nil) {
            self.provider = provider
            self.connectionId = connectionId
        }
    }

    public struct PutConnectionArgs {
        public var agentId: String
        public var provider: String
        public var connectionId: String?
        public var accessToken: String
        public var refreshToken: String?
        public var expiresAt: Double
        public var scopes: [String]
        /// The base64url key the capability chain must be rooted at.
        public var principal: String
        /// Scopes the capability must cover for this connection; defaults to `scopes`.
        public var authorityScopes: [String]?
        /// When set, the PCActn's signed `aud` must equal this resource-server id.
        public var audience: String?
        public init(agentId: String, provider: String, connectionId: String? = nil, accessToken: String, refreshToken: String? = nil, expiresAt: Double, scopes: [String],
                    principal: String, authorityScopes: [String]? = nil, audience: String? = nil) {
            self.agentId = agentId
            self.provider = provider
            self.connectionId = connectionId
            self.accessToken = accessToken
            self.refreshToken = refreshToken
            self.expiresAt = expiresAt
            self.scopes = scopes
            self.principal = principal
            self.authorityScopes = authorityScopes
            self.audience = audience
        }
    }

    public struct ConnectionToken: Equatable {
        public var provider: String
        public var connectionId: String
        public var accessToken: String
        public var scopes: [String]
        public var expiresAt: Double
        /// True when the token was just refreshed at the provider.
        public var refreshed: Bool
        public var json: JSONValue {
            .object(["provider": .string(provider), "connectionId": .string(connectionId), "accessToken": .string(accessToken), "scopes": .array(scopes.map { .string($0) }),
                     "expiresAt": PCASandbox.num(expiresAt), "refreshed": .bool(refreshed)])
        }
    }

    public struct ProxyResult {
        public var response: ProxyResponse
        /// Present when the vault was constructed with `receipts`.
        public var receipt: JSONValue?
    }

    public struct VaultOptions {
        public var store: ConnectionStore?
        /// Per-provider token-endpoint config, used only when a refresh is required.
        public var providers: [String: ProviderConfig] = [:]
        /// Injectable transport for refreshes; required to refresh.
        public var fetch: VaultFetch?
        /// Clock, epoch ms.
        public var now: () -> Int64 = { Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) }
        /// This vault's resource-server id, compared to each PCActn's signed `aud`; nil opts out. A connection's own `authority.audience` overrides it.
        public var audience: String?
        /// Verifier-side `issuer -> pq_pk` pins (a non-ed25519 root verifies only under a pin for its issuer).
        public var pqPins: [String: String]?
        /// The plan roots the principal authorized. Required unless `insecureSkipPlanRootCheck`: a vault with neither refuses every release.
        public var authorizedPlanRoots: [String]?
        public var insecureSkipPlanRootCheck = false
        /// A token within this many ms of expiry is stale and refreshed.
        public var expiryLeewayMs: Double = 30_000
        public var defaultConnectionId = "default"
        /// When true (default), the PCActn's action must be a token-use action for the requested provider.
        public var requireActionBinding = true
        public var resourceFor: (String, String) -> String = { provider, _ in "oauth:\(provider)" }
        /// The `action.verb` a PCActn must carry; nil skips the verb check.
        public var useVerb: String? = "use_connection"
        public var defaultTokenLifetimeMs: Double = 300_000
        public var replay: ReplayStore?
        /// Revocation source: true refuses the action; a throw refuses it too (fail closed).
        public var isRevoked: ((JSONValue) throws -> Bool)?
        /// Production profile, ON unless false: the initializer throws unless the store encrypts at rest, `replay` and `isRevoked` are set and `audience` is non-empty.
        public var strict = true
        /// Resolve the pinned action for a PCActn's verb; with it set, every release derives its scopes from the action.
        public var actions: ((String) -> VaultAction?)?
        /// DOCUMENTED INSECURE opt-in: without it `getConnectionToken` throws `bearer_release_disabled`. Prefer `proxyCall`.
        public var insecureBearerRelease = false
        public var proxyFetch: ProxyFetch?
        public var proxyHeaders = DEFAULT_PROXY_HEADERS
        public var maxProxyResponseBytes = 4 * 1024 * 1024
        /// Sign a release receipt for every release / proxied call with this vault key (an Ed25519 seed) and hand it to `sink`.
        public var receiptKey: [UInt8]?
        public var receiptSink: ((JSONValue) throws -> Void)?
        public init() {}
    }

    private struct Authorized {
        var agentId: String
        var provider: String
        var connectionId: String
        var connection: StoredConnection
        var requested: [String]
        var now: Int64
        var action: VaultAction?
    }

    /// An outbound connection / token vault for PCA agents: it holds an agent's third-party OAuth tokens and releases a FRESH access token
    /// (or makes the call itself) only when a verified Proof-Carrying Action proves least-privilege authority over the provider and scopes.
    /// Concurrent callers that need the SAME stale connection refreshed share ONE refresh (in-flight de-duplication, keyed by agent, provider
    /// and connection: a rotating refresh token is spent once, and every waiter gets that refresh's result or its error). The store and the
    /// injected transports must themselves tolerate concurrent calls.
    public final class TokenVault {
        private let o: VaultOptions
        private let store: ConnectionStore
        private let proxyHeaders: [String]

        private let flights = SingleFlight<String, RefreshedFields>()

        public init(_ options: VaultOptions) throws {
            if options.strict {
                var missing: [String] = []
                if options.store?.encrypted != true { missing.append("an encrypting store") }
                if options.replay == nil { missing.append("replay") }
                if options.isRevoked == nil { missing.append("isRevoked") }
                if (options.audience ?? "").isEmpty { missing.append("audience") }
                if !missing.isEmpty { throw ConnectError("TokenVault strict mode requires \(missing.joined(separator: ", "))") }
            } else if options.store == nil {
                throw ConnectError("TokenVault requires a store")
            }
            o = options
            store = options.store!
            proxyHeaders = options.proxyHeaders.map { $0.lowercased() }
        }

        private func storeCall<T>(_ f: () throws -> T) throws -> T {
            do { return try f() } catch let e as VaultError { throw e } catch { throw VaultError.store() }
        }

        /// Store (or replace) an agent's connection. The authority descriptor binds which capability may use it.
        @discardableResult
        public func putConnection(_ a: PutConnectionArgs) throws -> StoredConnection {
            let connectionId = a.connectionId ?? o.defaultConnectionId
            for (k, v) in [("agentId", a.agentId), ("provider", a.provider), ("connectionId", connectionId), ("accessToken", a.accessToken), ("principal", a.principal)] where v.isEmpty {
                throw ConnectError("putConnection: \(k) must be a non-empty string")
            }
            guard a.expiresAt.isFinite else { throw ConnectError("putConnection: expiresAt must be a finite number") }
            if let r = a.refreshToken, r.isEmpty { throw ConnectError("putConnection: refreshToken must be a non-empty string when given") }
            let c = StoredConnection(agentId: a.agentId, provider: a.provider, connectionId: connectionId, accessToken: a.accessToken, refreshToken: a.refreshToken, expiresAt: a.expiresAt,
                                     scopes: a.scopes, authority: ConnectionAuthority(provider: a.provider, principal: a.principal, scopes: a.authorityScopes ?? a.scopes, audience: a.audience),
                                     createdAt: Double(o.now()), useCount: 0)
            try storeCall { try store.set(c) }
            return c
        }

        /// Resolve a FRESH access token iff `pcActn` verifies against the connection's bound principal and the capability chain's grant covers the
        /// requested provider and scopes (requested within granted). Refreshes a stale token when a refresh token is present.
        ///
        /// INSECURE BY NATURE: the caller receives a bearer credential. Disabled unless the vault was built with `insecureBearerRelease`.
        public func getConnectionToken(_ pcActn: JSONValue, _ args: GetConnectionTokenArgs) throws -> ConnectionToken {
            guard o.insecureBearerRelease else { throw VaultError.bearerDisabled() }
            let a = try authorize(pcActn, args.provider, args.connectionId, args.scopes, needAction: false, request: nil)
            let (token, refreshed) = try freshToken(a)
            let done = try recordUse(a, token)
            _ = try issueReceipt(pcActn, a, mode: "bearer", requestDigest: nil, httpStatus: nil, outcome: "released", scopes: done.scopes)
            var exp = done.expiresAt
            if a.action != nil, let pe = IV.num(pcActn.get("exp")), pe.isFinite { exp = min(exp, pe) }
            return ConnectionToken(provider: a.provider, connectionId: a.connectionId, accessToken: done.accessToken, scopes: done.scopes, expiresAt: exp, refreshed: refreshed)
        }

        /// Proxy mode: the vault makes the outbound call itself, so the agent never holds the credential. Verifies the PCActn and the pinned,
        /// CONFIRMED action; derives the scopes from the action; maps `request` back to the action's parameters with the action's extractor
        /// and requires their digest to equal the PCActn's signed `params_digest`; spends the action (replay guard); attaches the token; makes
        /// the call without following redirects; signs a receipt linking the release to the effect.
        public func proxyCall(_ pcActn: JSONValue, _ request: ProxyRequest, _ args: ProxyCallArgs) throws -> ProxyResult {
            guard o.actions != nil else { throw ConnectError("proxyCall requires the vault to be constructed with `actions`") }
            guard let fetch = o.proxyFetch else { throw ConnectError("proxyCall requires the vault to be constructed with `proxyFetch`") }
            let sendHeaders = try checkProxyHeaders(request.headers, proxyHeaders) // before anything is spent
            let a = try authorize(pcActn, args.provider, args.connectionId, nil, needAction: true, request: request)
            let (token, _) = try freshToken(a)
            let done = try recordUse(a, token)
            var headers = sendHeaders
            headers["authorization"] = "Bearer \(done.accessToken)"
            guard let reqDigest = outboundRequestDigest(method: request.method, url: request.url, headers: sendHeaders, body: request.body) else { throw ConnectError("request is not canonicalizable") }
            let response: ProxyResponse
            do {
                response = try fetch(ProxyFetchRequest(method: request.method, url: request.url, headers: headers, body: request.body))
            } catch {
                _ = try issueReceipt(pcActn, a, mode: "proxy", requestDigest: reqDigest, httpStatus: nil, outcome: "failed", scopes: done.scopes)
                throw VaultError.proxyFailed("the outbound call failed before a response")
            }
            let receipt = try issueReceipt(pcActn, a, mode: "proxy", requestDigest: reqDigest, httpStatus: response.status, outcome: "executed", scopes: done.scopes)
            if response.body.utf8.count > o.maxProxyResponseBytes { throw VaultError.proxyFailed("the response is larger than maxProxyResponseBytes (the call was made and the action is spent)") }
            let body = replaceAll(response.body, done.accessToken, "[redacted]")
            var rh: [(String, String)] = []
            for (k, v) in response.headers where k.lowercased() != "set-cookie" { rh.append((k, replaceAll(v, done.accessToken, "[redacted]"))) }
            return ProxyResult(response: ProxyResponse(status: response.status, headers: rh, body: body), receipt: receipt)
        }

        /// Remove a stored connection.
        public func deleteConnection(agentId: String, provider: String, connectionId: String? = nil) throws {
            try storeCall { try store.delete(ConnectionKey(agentId: agentId, provider: provider, connectionId: connectionId ?? o.defaultConnectionId)) }
        }

        /// Steps 1-5b of a release: resolve, anchor and verify, revoke, bind, derive scopes, least-privilege, spend. Shared by both modes.
        private func authorize(_ pcActn: JSONValue, _ provider: String, _ connectionIdArg: String?, _ scopesArg: [String]?, needAction: Bool, request: ProxyRequest?) throws -> Authorized {
            let connectionId = connectionIdArg ?? o.defaultConnectionId
            guard let chainV = pcActn.get("cap_chain"), let chain = chainV.asArray, !chain.isEmpty else { throw VaultError.notAuthorized("PCActn has no capability chain") }
            let leaf = chain[chain.count - 1], root = chain[0]
            if leaf.isNull || root.isNull { throw VaultError.notAuthorized("PCActn capability chain is malformed") }
            let agentId = JS.toString(leaf.get("holder"))

            guard let connection = try storeCall({ try store.get(ConnectionKey(agentId: agentId, provider: provider, connectionId: connectionId)) }) else {
                throw VaultError.unknownConnection(agentId, provider, connectionId)
            }
            guard IV.same(root.get("issuer")?.asString, connection.authority.principal) else { throw VaultError.notAuthorized("capability chain is not rooted at the connection's bound principal") }
            let now = o.now()
            let audience = connection.authority.audience ?? o.audience
            let verdict = PCA.verify(pcactn: pcActn, grant: root, now: now, audience: audience.map { PCA.Audience.id($0) } ?? PCA.Audience.any, authorizedPlanRoots: o.authorizedPlanRoots,
                                     insecureSkipPlanRootCheck: o.insecureSkipPlanRootCheck, pqPins: o.pqPins)
            if !verdict.allow { throw VaultError.notAuthorized("PCActn verification failed: \(verdict.reason.isEmpty ? "rejected" : verdict.reason)") }

            if let revoked = o.isRevoked {
                let r: Bool
                do { r = try revoked(pcActn) } catch { throw VaultError.notAuthorized("revocation source unavailable") }
                if r { throw VaultError.notAuthorized("the capability chain is revoked") }
            }

            let act = pcActn.get("action")
            let verb = act?.get("verb")?.asString
            var action: VaultAction?
            if let table = o.actions {
                guard let v = verb, let found = table(v), IV.same(found.verb, v) else { throw VaultError.unknownAction(JS.toString(act?.get("verb"))) }
                guard found.confirmed else { throw VaultError.unconfirmedAction(v) }
                if !IV.same(found.provider, provider) { throw VaultError.notAuthorized("the action '\(v)' is not for provider '\(provider)'") }
                if found.scopesMin.isEmpty { throw VaultError.notAuthorized("the action '\(v)' declares no upstream scopes (nothing to release)") }
                action = found
            } else if needAction {
                throw VaultError.unknownAction(JS.toString(act?.get("verb")))
            } else if o.requireActionBinding {
                let expected = o.resourceFor(provider, connectionId)
                if !IV.same(act?.get("resource")?.asString, expected) {
                    throw VaultError.notAuthorized("PCActn action resource '\(JS.toString(act?.get("resource")))' is not for this connection (expected '\(expected)')")
                }
                if let uv = o.useVerb, !IV.same(verb, uv) {
                    throw VaultError.notAuthorized("PCActn action verb '\(JS.toString(act?.get("verb")))' is not a connection-use verb (expected '\(uv)')")
                }
            }

            guard let granted = grantedOAuthScopes(chainV, provider) else { throw VaultError.notAuthorized("capability grants no authority for provider '\(provider)'") }

            var requested: [String]
            if let act = action {
                let min = act.scopesMin
                requested = scopesArg ?? min
                let beyond = requested.filter { !IV.contains(min, $0) }
                if !beyond.isEmpty { throw VaultError.scopeExceeded(provider, beyond) }
                let unheld = min.filter { !IV.contains(connection.scopes, $0) || !IV.contains(connection.authority.scopes, $0) }
                if !unheld.isEmpty { throw VaultError.scopeExceeded(provider, unheld) }
                if !needAction {
                    let extra = connection.scopes.filter { !IV.contains(min, $0) }
                    if !extra.isEmpty { throw VaultError.scopeExceeded(provider, extra) }
                }
                let ungranted = min.filter { !IV.contains(granted, $0) }
                if !ungranted.isEmpty { throw VaultError.scopeExceeded(provider, ungranted) }
            } else {
                requested = scopesArg ?? connection.authority.scopes
            }
            let missing = requested.filter { !IV.contains(granted, $0) }
            if !missing.isEmpty { throw VaultError.scopeExceeded(provider, missing) }

            if needAction, let act = action {
                guard let request = request, let extract = act.extract else { throw VaultError.requestMismatch("the action has no request extractor: proxy mode cannot bind the outbound request") }
                let params: JObject
                do { params = try extract(request) } catch let e as VaultError where e.code == "request_mismatch" { throw e } catch {
                    throw VaultError.requestMismatch("the outbound request could not be mapped to the action parameters")
                }
                guard let d = IV.strictHash(.object(params)) else { throw VaultError.requestMismatch("the outbound request parameters are not canonical") }
                if !IV.same(d, act0(pcActn)) { throw VaultError.requestMismatch("the outbound request does not carry the parameters the PCActn signed") }
            }

            if let replay = o.replay, let why = guardReplay(replay, pcActn, aud: pcActn.get("aud")?.asString, now: now) {
                throw VaultError.notAuthorized("replay guard refused the action: \(why)")
            }
            return Authorized(agentId: agentId, provider: provider, connectionId: connectionId, connection: connection, requested: requested, now: now, action: action)
        }

        private func act0(_ p: JSONValue) -> String? { p.get("action")?.get("params_digest")?.asString }

        /// Step 6: refresh a stale token, else use it as is. A token whose expiry is not a finite number can never be shown fresh.
        private func freshToken(_ a: Authorized) throws -> (StoredConnection, Bool) {
            let c = a.connection
            guard !c.expiresAt.isFinite || !o.expiryLeewayMs.isFinite || c.expiresAt - Double(a.now) <= o.expiryLeewayMs else { return (c, false) }
            guard let refresh = c.refreshToken else { throw VaultError.expiredNoRefresh(a.provider, a.connectionId) }
            let u = try flights.run([a.agentId, a.provider, a.connectionId].joined(separator: "\u{0}")) {
                try refreshConnection(connection: c, config: o.providers[a.provider], refreshToken: refresh, requested: a.requested, fetch: o.fetch, now: Double(a.now),
                                      defaultTokenLifetimeMs: o.defaultTokenLifetimeMs)
            }
            var t = c
            t.accessToken = u.accessToken
            t.refreshToken = u.refreshToken
            t.expiresAt = u.expiresAt
            t.scopes = u.scopes
            return (t, true)
        }

        /// Step 7: record usage and persist.
        private func recordUse(_ a: Authorized, _ token: StoredConnection) throws -> StoredConnection {
            var t = token
            t.lastUsedAt = Double(a.now)
            t.useCount += 1
            try storeCall { try store.set(t) }
            return t
        }

        private func issueReceipt(_ pcActn: JSONValue, _ a: Authorized, mode: String, requestDigest: String?, httpStatus: Int?, outcome: String, scopes: [String]) throws -> JSONValue? {
            guard let key = o.receiptKey else { return nil }
            guard let ad = receiptActionDigest(pcActn) else { throw ConnectError("PCActn is not canonicalizable") }
            let sorted = scopes.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            let r = try signReleaseReceipt(.object([
                "v": .int(1), "kind": .string("pca-release-receipt"), "action_digest": .string(ad), "provider": .string(a.provider), "connection_id": .string(a.connectionId),
                "mode": .string(mode), "scopes_released": .array(sorted.map { .string($0) }), "request_digest": requestDigest.map { .string($0) } ?? .null,
                "http_status": httpStatus.map { .int(Int64($0)) } ?? .null, "outcome": .string(outcome), "ts": .int(a.now),
            ]), seed: key)
            try? o.receiptSink?(r) // a failing sink never blocks the release
            return r
        }
    }
}
