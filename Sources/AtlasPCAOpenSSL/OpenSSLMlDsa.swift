import Foundation
import CLibcrypto
import AtlasPCAVerify

/// ML-DSA-65 / ML-DSA-87 (FIPS 204) signing keys on libcrypto 3.5+: the key is generated from the 32-byte FIPS 204 seed and signs with the DETERMINISTIC
/// variant (pure mode, empty context), so a seeded key reproduces the reference's signatures byte for byte. The platform signer hedges ML-DSA: its
/// signatures are equally valid but differ on every call. Opt-in: the key is an ordinary `PCAPQKey`, usable wherever a suite key takes one.
extension PCAOpenSSL {
    private static func mlDsaName(_ level: PCAMLDSALevel) -> String { level == .mlDsa65 ? "ML-DSA-65" : "ML-DSA-87" }

    /// True when the loaded libcrypto can build ML-DSA keys (3.5 or newer).
    public static func mlDsaAvailable() -> Bool {
        for name in ["ML-DSA-65", "ML-DSA-87"] {
            guard let ctx = EVP_PKEY_CTX_new_from_name(nil, name, nil) else { return false }
            EVP_PKEY_CTX_free(ctx)
        }
        return true
    }

    /// Owns one EVP_PKEY for as long as the key's signer closure lives.
    private final class MlDsaHandle: @unchecked Sendable {
        let key: OpaquePointer
        init(_ k: OpaquePointer) { key = k }
        deinit { EVP_PKEY_free(key) }
    }

    /// A one-byte buffer stands in for an empty message so the pointer is never nil.
    private static func withMessage<R>(_ b: [UInt8], _ body: (UnsafePointer<UInt8>, Int) -> R) -> R {
        if b.isEmpty { return [UInt8](repeating: 0, count: 1).withUnsafeBufferPointer { body($0.baseAddress!, 0) } }
        return b.withUnsafeBufferPointer { body($0.baseAddress!, b.count) }
    }

    /// The key pair the 32-byte seed derives, signing deterministically. Throws on a libcrypto without ML-DSA.
    public static func mlDsaKey(_ level: PCAMLDSALevel, seed: [UInt8]) throws -> PCAPQKey {
        let family = mlDsaName(level)
        guard seed.count == 32 else { throw Failure("\(family): seed must be 32 bytes") }
        guard let ctx = EVP_PKEY_CTX_new_from_name(nil, family, nil) else { throw Failure("\(family) is not available in this libcrypto") }
        defer { EVP_PKEY_CTX_free(ctx) }
        guard EVP_PKEY_keygen_init(ctx) == 1 else { throw Failure("\(family) keygen init refused") }
        var seedCopy = seed
        defer { for i in seedCopy.indices { seedCopy[i] = 0 } }
        let name = strdup("seed")! // the OSSL_PARAM keeps the pointer: it must outlive the construct call
        defer { free(name) }
        let rc: Int32 = seedCopy.withUnsafeMutableBytes { raw in
            var params = [OSSL_PARAM_construct_octet_string(name, raw.baseAddress, raw.count), OSSL_PARAM_construct_end()]
            return EVP_PKEY_CTX_set_params(ctx, &params)
        }
        guard rc == 1 else { throw Failure("\(family) refused the seed") }
        var pkey: OpaquePointer?
        guard EVP_PKEY_generate(ctx, &pkey) == 1, let key = pkey else { throw Failure("\(family) keygen failed") }
        let handle = MlDsaHandle(key)
        let pkLen = level == .mlDsa65 ? 1952 : 2592, sigLen = level == .mlDsa65 ? 3309 : 4627
        var pub = [UInt8](repeating: 0, count: pkLen)
        var n = pkLen
        guard EVP_PKEY_get_raw_public_key(key, &pub, &n) == 1, n == pkLen else { throw Failure("\(family) public key unavailable") }
        return try PCAPQKey(level: level, publicKey: pub) { msg in try mlDsaSign(handle, family, msg, sigLen) }
    }

    /// Deterministic pure-mode signature (empty context) under the key.
    private static func mlDsaSign(_ handle: MlDsaHandle, _ family: String, _ message: [UInt8], _ sigLen: Int) throws -> [UInt8] {
        guard let ctx = EVP_MD_CTX_new() else { throw Failure("EVP_MD_CTX_new failed") }
        defer { EVP_MD_CTX_free(ctx) }
        let name = strdup("deterministic")!
        defer { free(name) }
        var det: Int32 = 1
        let initRc: Int32 = withUnsafeMutablePointer(to: &det) { p in // the OSSL_PARAM keeps this pointer: build and use it inside the scope
            var params = [OSSL_PARAM_construct_int(name, p), OSSL_PARAM_construct_end()]
            return EVP_DigestSignInit_ex(ctx, nil, nil, nil, nil, handle.key, &params)
        }
        guard initRc == 1 else { throw Failure("\(family) sign init refused") }
        var sig = [UInt8](repeating: 0, count: sigLen)
        var n = sigLen
        let rc: Int32 = withMessage(message) { m, len in EVP_DigestSign(ctx, &sig, &n, m, len) }
        guard rc == 1, n == sigLen else { throw Failure("\(family) sign failed") }
        return sig
    }
}
