import Foundation

/// The outbound connection / token vault: an agent's third-party OAuth tokens, released (or used on the agent's behalf) only when a
/// verified PCActn proves least-privilege authority over the provider and scopes. Network I/O (token refresh, the proxied call) goes
/// through injected synchronous closures.
public enum PCAConnect {
    // MARK: errors

    /// A typed refusal of the vault. `code` is the stable machine-readable reason.
    public struct VaultError: Error, CustomStringConvertible {
        public let name: String
        public let code: String
        public let message: String
        public var status: Int?
        public var missing: [String]?
        public var description: String { "\(name)[\(code)]: \(message)" }

        init(_ name: String, _ code: String, _ message: String, status: Int? = nil, missing: [String]? = nil) {
            self.name = name
            self.code = code
            self.message = message
            self.status = status
            self.missing = missing
        }

        static func notAuthorized(_ m: String) -> VaultError { VaultError("NotAuthorizedError", "not_authorized", m) }
        static func scopeExceeded(_ provider: String, _ missing: [String]) -> VaultError {
            VaultError("ScopeExceededError", "scope_exceeded", "requested scopes exceed the capability's grant for '\(provider)': not granted [\(missing.joined(separator: ", "))]", missing: missing)
        }
        static func expiredNoRefresh(_ provider: String, _ id: String) -> VaultError {
            VaultError("ExpiredNoRefreshError", "expired_no_refresh", "connection '\(provider)/\(id)' token is expired and has no refresh token")
        }
        static func refreshFailed(_ provider: String, _ detail: String, status: Int? = nil) -> VaultError {
            VaultError("RefreshFailedError", "refresh_failed", "refresh for '\(provider)' failed: \(detail)", status: status)
        }
        static func unknownConnection(_ agent: String, _ provider: String, _ id: String) -> VaultError {
            VaultError("UnknownConnectionError", "unknown_connection", "no connection for agent '\(agent)' provider '\(provider)' id '\(id)'")
        }
        static func store(_ m: String = "the connection store failed") -> VaultError { VaultError("StoreError", "store_error", m) }
        static func unknownAction(_ verb: String) -> VaultError {
            VaultError("UnknownActionError", "unknown_action", "no pinned action definition for verb '\(verb)': refusing to release a credential")
        }
        static func unconfirmedAction(_ verb: String) -> VaultError {
            VaultError("UnconfirmedActionError", "unconfirmed_action", "the definition of '\(verb)' has no valid signed confirmation: refusing to release a credential")
        }
        static func requestMismatch(_ m: String) -> VaultError { VaultError("RequestMismatchError", "request_mismatch", m) }
        static func bearerDisabled() -> VaultError {
            VaultError("BearerReleaseDisabledError", "bearer_release_disabled", "this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)")
        }
        static func proxyFailed(_ m: String) -> VaultError { VaultError("ProxyFailedError", "proxy_failed", m) }
    }

    /// A programming / configuration error (the reference's TypeError / Error), not a vault refusal.
    public struct ConnectError: Error, CustomStringConvertible {
        public let description: String
        init(_ d: String) { description = d }
    }

    // MARK: store

    public struct ConnectionAuthority: Equatable {
        public var provider: String
        /// The base64url public key the capability chain must be rooted at.
        public var principal: String
        public var scopes: [String]
        public var audience: String?
        public init(provider: String, principal: String, scopes: [String], audience: String? = nil) {
            self.provider = provider
            self.principal = principal
            self.scopes = scopes
            self.audience = audience
        }
    }

    public struct ConnectionKey: Equatable {
        public var agentId: String
        public var provider: String
        public var connectionId: String
        public init(agentId: String, provider: String, connectionId: String) {
            self.agentId = agentId
            self.provider = provider
            self.connectionId = connectionId
        }
        var storeKey: String { "\(agentId)\u{0}\(provider)\u{0}\(connectionId)" }
    }

    public struct StoredConnection: Equatable {
        public var agentId: String
        public var provider: String
        public var connectionId: String
        public var accessToken: String
        public var refreshToken: String?
        /// Epoch ms (a finite number; may be fractional).
        public var expiresAt: Double
        public var scopes: [String]
        public var authority: ConnectionAuthority
        public var createdAt: Double
        public var lastUsedAt: Double?
        public var useCount: Int
        public var key: ConnectionKey { ConnectionKey(agentId: agentId, provider: provider, connectionId: connectionId) }

        public init(agentId: String, provider: String, connectionId: String, accessToken: String, refreshToken: String? = nil, expiresAt: Double, scopes: [String],
                    authority: ConnectionAuthority, createdAt: Double, lastUsedAt: Double? = nil, useCount: Int = 0) {
            self.agentId = agentId
            self.provider = provider
            self.connectionId = connectionId
            self.accessToken = accessToken
            self.refreshToken = refreshToken
            self.expiresAt = expiresAt
            self.scopes = scopes
            self.authority = authority
            self.createdAt = createdAt
            self.lastUsedAt = lastUsedAt
            self.useCount = useCount
        }

        public var json: JSONValue {
            func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
            var auth: JObject = ["provider": .string(authority.provider), "principal": .string(authority.principal), "scopes": strs(authority.scopes)]
            if let a = authority.audience { auth["audience"] = .string(a) }
            var o: JObject = ["agentId": .string(agentId), "provider": .string(provider), "connectionId": .string(connectionId), "accessToken": .string(accessToken),
                              "expiresAt": PCASandbox.num(expiresAt), "scopes": strs(scopes), "authority": .object(auth), "createdAt": PCASandbox.num(createdAt),
                              "useCount": .int(Int64(useCount))]
            if let r = refreshToken { o["refreshToken"] = .string(r) }
            if let l = lastUsedAt { o["lastUsedAt"] = PCASandbox.num(l) }
            return .object(o)
        }
    }

    public protocol ConnectionStore {
        func get(_ key: ConnectionKey) throws -> StoredConnection?
        func set(_ connection: StoredConnection) throws
        func delete(_ key: ConnectionKey) throws
        /// True for a store that encrypts tokens at rest (`EncryptedConnectionStore`); a strict vault requires it.
        var encrypted: Bool { get }
    }

    /// A plaintext in-memory store (tests and local development only).
    public final class InMemoryConnectionStore: ConnectionStore {
        private var map: [String: StoredConnection] = [:]
        public init() {}
        public var encrypted: Bool { false }
        public func get(_ key: ConnectionKey) throws -> StoredConnection? { map[key.storeKey] }
        public func set(_ c: StoredConnection) throws { map[c.key.storeKey] = c }
        public func delete(_ key: ConnectionKey) throws { map[key.storeKey] = nil }
    }

    // MARK: oauth_scope caveats

    public static let OAUTH_SCOPE_CAVEAT = "oauth_scope"

    /// `{type: 'oauth_scope', provider, scopes}` with the scopes de-duplicated (first occurrence wins).
    public static func oauthScopeCaveat(_ provider: String, _ scopes: [String]) -> JSONValue {
        var seen = Set<JKey>(), out: [JSONValue] = []
        for s in scopes where seen.insert(JKey(s)).inserted { out.append(.string(s)) }
        return .object(["type": .string(OAUTH_SCOPE_CAVEAT), "provider": .string(provider), "scopes": .array(out)])
    }

    public static func isOAuthScopeCaveat(_ cv: JSONValue?) -> Bool {
        guard let o = cv?.asObject, o[JKey("type")]?.asString == OAUTH_SCOPE_CAVEAT, o[JKey("provider")]?.asString != nil, JS.isStringArray(o[JKey("scopes")]) else { return false }
        return true
    }

    /// The scopes the leaf capability grants for `provider`: the intersection of its oauth_scope caveats for that provider (code-point
    /// equality, first occurrence order), nil when it has none (or the chain is empty / malformed).
    public static func grantedOAuthScopes(_ chain: JSONValue?, _ provider: String) -> [String]? {
        guard let list = chain?.asArray, let leaf = list.last, let caveats = leaf.get("caveats")?.asArray else { return nil }
        var effective: [String]?
        for cv in caveats where isOAuthScopeCaveat(cv) && IV.same(cv.get("provider")?.asString, provider) {
            var here: [String] = []
            for s in (cv.get("scopes")?.asArray ?? []).compactMap({ $0.asString }) where !IV.contains(here, s) { here.append(s) }
            effective = effective.map { $0.filter { IV.contains(here, $0) } } ?? here
        }
        return effective
    }
}
