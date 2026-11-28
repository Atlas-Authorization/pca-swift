import Foundation
import CLibcrypto

/// Ed448 (RFC 8032 section 5.2, pure, empty context) on libcrypto: 57-byte keys and seeds, 114-byte signatures.
extension PCAOpenSSL {
    static let ed448KeyBytes = 57
    static let ed448SigBytes = 114

    private static func ed448Key(seed: [UInt8]) -> OpaquePointer? {
        guard seed.count == ed448KeyBytes else { return nil }
        return EVP_PKEY_new_raw_private_key(NID_ED448, nil, seed, seed.count)
    }

    /// The 57-byte public key of a 57-byte seed; nil for any other seed length.
    static func ed448PublicKey(seed: [UInt8]) -> [UInt8]? {
        guard let pkey = ed448Key(seed: seed) else { return nil }
        defer { EVP_PKEY_free(pkey) }
        var pub = [UInt8](repeating: 0, count: ed448KeyBytes)
        var n = ed448KeyBytes
        guard EVP_PKEY_get_raw_public_key(pkey, &pub, &n) == 1, n == ed448KeyBytes else { return nil }
        return pub
    }

    static func ed448Sign(seed: [UInt8], message: [UInt8]) throws -> [UInt8] {
        guard let pkey = ed448Key(seed: seed) else { throw Failure("Invalid JWK OKP key") }
        defer { EVP_PKEY_free(pkey) }
        guard let ctx = EVP_MD_CTX_new() else { throw Failure("EVP_MD_CTX_new failed") }
        defer { EVP_MD_CTX_free(ctx) }
        guard EVP_DigestSignInit(ctx, nil, nil, nil, pkey) == 1 else { throw Failure("Ed448 sign init refused") }
        var sig = [UInt8](repeating: 0, count: ed448SigBytes)
        var n = ed448SigBytes
        guard EVP_DigestSign(ctx, &sig, &n, message, message.count) == 1, n == ed448SigBytes else { throw Failure("Ed448 sign failed") }
        return sig
    }

    /// True only for a valid signature under a 57-byte public key (OpenSSL checks the encodings: a malformed key or signature is false).
    static func ed448Verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
        guard publicKey.count == ed448KeyBytes, signature.count == ed448SigBytes,
              let pkey = EVP_PKEY_new_raw_public_key(NID_ED448, nil, publicKey, publicKey.count) else { return false }
        defer { EVP_PKEY_free(pkey) }
        guard let ctx = EVP_MD_CTX_new() else { return false }
        defer { EVP_MD_CTX_free(ctx) }
        guard EVP_DigestVerifyInit(ctx, nil, nil, nil, pkey) == 1 else { return false }
        return EVP_DigestVerify(ctx, signature, signature.count, message, message.count) == 1
    }
}
