import Foundation
import CryptoKit
#if canImport(Security)
import Security
#endif

/// Where the 32-byte Ed25519 seed is persisted.
public protocol SecretStore: Sendable {
    func load() throws -> Data?
    func save(_ secret: Data) throws
    func delete() throws
}

/// The principal's Ed25519 device key.
///
/// HONEST CAVEAT: the iOS Secure Enclave supports only P-256, not Ed25519, and the
/// PCA principal key MUST be Ed25519. So this is a SOFTWARE key: the 32-byte seed is
/// stored in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: encrypted at
/// rest by the OS, never in iCloud/backups, unavailable while locked), but it is not
/// hardware-bound and the process can read it. Gate `approve` behind Face ID / Touch ID
/// (LocalAuthentication) in your app to get user-presence on every approval.
public struct PrincipalDeviceKey: Sendable {
    private let store: SecretStore

    public init(store: SecretStore = KeychainSecretStore()) { self.store = store }

    /// True when a key is stored.
    public var exists: Bool { ((try? store.load()) ?? nil) != nil }

    /// Generate a fresh key (replacing any existing one) and return its public key (base64url).
    /// The public key must be the grant's `principal` for approvals to be accepted.
    @discardableResult
    public func generate() throws -> String {
        let key = Curve25519.Signing.PrivateKey()
        try store.save(key.rawRepresentation)
        return Base64URL.encode(key.publicKey.rawRepresentation)
    }

    /// Import an existing principal secret (base64url 32-byte seed, as `@atlasauth/pca` encodes
    /// `secretKey`) — use this when the grant was minted elsewhere. Returns the public key.
    @discardableResult
    public func importSecret(_ secretB64u: String) throws -> String {
        guard let raw = Base64URL.decode(secretB64u), raw.count == 32,
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        else { throw StepUpError.invalidSecret }
        try store.save(key.rawRepresentation)
        return Base64URL.encode(key.publicKey.rawRepresentation)
    }

    /// Export the secret (base64url seed) for backup/migration. Treat it like a password.
    public func exportSecret() throws -> String {
        Base64URL.encode(try loadKey().rawRepresentation)
    }

    /// The public key (base64url), as registered on the grant.
    public func publicKey() throws -> String {
        Base64URL.encode(try loadKey().publicKey.rawRepresentation)
    }

    /// Ed25519-sign `message`; returns the signature as base64url.
    public func sign(_ message: Data) throws -> String {
        let sig = try loadKey().signature(for: message)
        return Base64URL.encode(sig)
    }

    /// Remove the key from secure storage.
    public func delete() throws { try store.delete() }

    private func loadKey() throws -> Curve25519.Signing.PrivateKey {
        guard let raw = try store.load() else { throw StepUpError.noDeviceKey }
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw) else { throw StepUpError.invalidSecret }
        return key
    }
}

/// In-memory store, for tests and previews only.
public final class InMemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var value: Data?
    public init() {}
    public func load() throws -> Data? { lock.lock(); defer { lock.unlock() }; return value }
    public func save(_ secret: Data) throws { lock.lock(); value = secret; lock.unlock() }
    public func delete() throws { lock.lock(); value = nil; lock.unlock() }
}

#if canImport(Security)
/// Keychain-backed store (generic password item).
public struct KeychainSecretStore: SecretStore {
    public let service: String
    public let account: String

    public init(service: String = "net.atlasauth.pca.stepup", account: String = "principal-ed25519") {
        self.service = service
        self.account = account
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    public func load() throws -> Data? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else { throw StepUpError.storage("SecItemCopyMatching \(status)") }
        return data
    }

    public func save(_ secret: Data) throws {
        SecItemDelete(query as CFDictionary)
        var q = query
        q[kSecValueData as String] = secret
        // Device-bound, not in backups/iCloud, readable only while unlocked.
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        q[kSecAttrSynchronizable as String] = false
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw StepUpError.storage("SecItemAdd \(status)") }
    }

    public func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw StepUpError.storage("SecItemDelete \(status)") }
    }
}
#endif
