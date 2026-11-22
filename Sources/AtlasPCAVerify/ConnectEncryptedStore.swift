import Foundation
import CryptoKit

/// Envelope encryption for stored OAuth tokens: every secret gets its own random data key; the data key is wrapped by a `KeyWrapper`
/// (a local key ring, or your KMS behind the same two methods). The additional authenticated data binds the wrapped key to the exact
/// connection and field, so a ciphertext copied to another connection or field fails to open.
extension PCAConnect {
    public protocol KeyWrapper {
        func wrap(_ dek: [UInt8], aad: [UInt8]) throws -> (keyId: String, wrapped: [UInt8])
        func unwrap(keyId: String, wrapped: [UInt8], aad: [UInt8]) throws -> [UInt8]
    }

    private static func aesSeal(_ key: [UInt8], _ aad: [UInt8], _ plain: [UInt8]) throws -> [UInt8] {
        let iv = (0..<12).map { _ in UInt8.random(in: 0...255) }
        let box = try AES.GCM.seal(Data(plain), using: SymmetricKey(data: Data(key)), nonce: try AES.GCM.Nonce(data: Data(iv)), authenticating: Data(aad))
        return iv + Array(box.ciphertext) + Array(box.tag)
    }

    private static func aesOpen(_ key: [UInt8], _ aad: [UInt8], _ sealed: [UInt8]) throws -> [UInt8] {
        guard sealed.count >= 12 + 16 else { throw ConnectError("short ciphertext") }
        let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: Data(sealed[0..<12])), ciphertext: Data(sealed[12..<(sealed.count - 16)]), tag: Data(sealed[(sealed.count - 16)...]))
        return Array(try AES.GCM.open(box, using: SymmetricKey(data: Data(key)), authenticating: Data(aad)))
    }

    /// A key ring held in process memory. Rotation: add the new key under a new id and make it active; records written under old ids still
    /// open until the old key is removed. For production keys implement `KeyWrapper` over a KMS.
    public final class LocalKeyWrapper: KeyWrapper {
        private var keys: [String: [UInt8]] = [:]
        private var active: String

        public init(keys: [String: [UInt8]], activeId: String) throws {
            active = activeId
            for (id, k) in keys { try addKey(id, k) }
            guard self.keys[activeId] != nil else { throw ConnectError("LocalKeyWrapper: the active key id is not in the key ring") }
        }

        public func addKey(_ id: String, _ key: [UInt8]) throws {
            guard !id.isEmpty else { throw ConnectError("LocalKeyWrapper: key id must not be empty") }
            guard key.count == 32 else { throw ConnectError("LocalKeyWrapper: keys must be 32 bytes") }
            keys[id] = key
        }

        public func setActive(_ id: String) throws {
            guard keys[id] != nil else { throw ConnectError("LocalKeyWrapper: the active key id is not in the key ring") }
            active = id
        }

        public func removeKey(_ id: String) throws {
            guard id != active else { throw ConnectError("LocalKeyWrapper: cannot remove the active key") }
            keys[id] = nil
        }

        public func wrap(_ dek: [UInt8], aad: [UInt8]) throws -> (keyId: String, wrapped: [UInt8]) {
            guard let k = keys[active] else { throw ConnectError("no active key") }
            return (active, try aesSeal(k, aad, dek))
        }

        public func unwrap(keyId: String, wrapped: [UInt8], aad: [UInt8]) throws -> [UInt8] {
            guard let k = keys[keyId] else { throw ConnectError("unknown key id") }
            return try aesOpen(k, aad, wrapped)
        }
    }

    private static let ENVELOPE_PREFIX = "pca1"

    private static func aad(_ key: ConnectionKey, _ field: String) -> [UInt8] {
        Array(["pca-connect/v1", field, key.agentId, key.provider, key.connectionId].map { "\($0.utf8.count):\($0)" }.joined(separator: "|").utf8)
    }

    private static func encryptField(_ w: KeyWrapper, _ key: ConnectionKey, _ field: String, _ plain: String) throws -> String {
        let a = aad(key, field)
        let dek = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let (keyId, wrapped) = try w.wrap(dek, aad: a)
        let sealed = try aesSeal(dek, a, Array(plain.utf8))
        return [ENVELOPE_PREFIX, Base64URLStrict.encode(Array(keyId.utf8)), Base64URLStrict.encode(wrapped), Base64URLStrict.encode(sealed)].joined(separator: ".")
    }

    private static func decryptField(_ w: KeyWrapper, _ key: ConnectionKey, _ field: String, _ value: String) throws -> String {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 4, parts[0] == ENVELOPE_PREFIX, let kid = Base64URLStrict.decode(parts[1]), let wrapped = Base64URLStrict.decode(parts[2]),
              let sealed = Base64URLStrict.decode(parts[3]) else { throw ConnectError("not an envelope") }
        let a = aad(key, field)
        let dek = try w.unwrap(keyId: String(decoding: kid, as: UTF8.self), wrapped: wrapped, aad: a)
        return String(decoding: try aesOpen(dek, a, sealed), as: UTF8.self)
    }

    /// Wraps any `ConnectionStore` so `accessToken` and `refreshToken` are encrypted before they reach it. Everything else in a record stays
    /// readable so the inner store can index and expire it. Fails closed: a stored token that is not an envelope (a plaintext record, a
    /// downgrade), fails authentication, or was sealed under an unknown key makes `get` throw a store error that carries no detail.
    public final class EncryptedConnectionStore: ConnectionStore {
        private let inner: ConnectionStore
        private let wrapper: KeyWrapper
        public var encrypted: Bool { true }

        public init(inner: ConnectionStore, wrapper: KeyWrapper) {
            self.inner = inner
            self.wrapper = wrapper
        }

        public func get(_ key: ConnectionKey) throws -> StoredConnection? {
            guard let raw = try inner.get(key) else { return nil }
            do {
                var out = raw
                let k = raw.key
                guard IV.same(k.agentId, key.agentId), IV.same(k.provider, key.provider), IV.same(k.connectionId, key.connectionId) else { throw ConnectError("record key mismatch") }
                out.accessToken = try decryptField(wrapper, k, "access", raw.accessToken)
                if let r = raw.refreshToken { out.refreshToken = try decryptField(wrapper, k, "refresh", r) }
                return out
            } catch {
                throw VaultError.store("a stored token could not be decrypted")
            }
        }

        public func set(_ connection: StoredConnection) throws {
            var sealed = connection
            do {
                sealed.accessToken = try encryptField(wrapper, connection.key, "access", connection.accessToken)
                if let r = connection.refreshToken { sealed.refreshToken = try encryptField(wrapper, connection.key, "refresh", r) }
            } catch {
                throw VaultError.store("a token could not be encrypted; nothing was stored")
            }
            try inner.set(sealed)
        }

        public func delete(_ key: ConnectionKey) throws { try inner.delete(key) }

        /// Re-encrypt one record under the wrapper's active key (run after rotating the key ring).
        public func reencrypt(_ key: ConnectionKey) throws -> Bool {
            guard let c = try get(key) else { return false }
            try set(c)
            return true
        }
    }
}
