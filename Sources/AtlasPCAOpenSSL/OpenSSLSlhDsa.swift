import Foundation
import CLibcrypto
import AtlasPCAVerify

/// SLH-DSA (FIPS 205) SHA2-128f and SHA2-256s on libcrypto 3.5+: pure mode with an EMPTY context (OpenSSL's defaults for these key types, the same
/// bytes as the reference's @noble/post-quantum), keys generated from the FIPS 205 seed SK.seed || SK.prf || PK.seed, and DETERMINISTIC signing
/// (opt_rand = PK.seed) so a seeded key reproduces the reference's bytes. `registerSlhDsa()` is opt-in and registers nothing on a libcrypto that lacks
/// the algorithms (older than 3.5): the four SLH-DSA suites then stay refused as `unsupported_suite`.
extension PCAOpenSSL {
    /// True when the loaded libcrypto can build SLH-DSA keys (3.5 or newer).
    public static func slhDsaAvailable() -> Bool {
        for fam in PCASlhDsaHook.families {
            guard let ctx = EVP_PKEY_CTX_new_from_name(nil, fam, nil) else { return false }
            EVP_PKEY_CTX_free(ctx)
        }
        return true
    }

    /// Registers the SLH-DSA verify backend and signer into the core hook. Returns false (and registers nothing) when libcrypto lacks SLH-DSA.
    @discardableResult
    public static func registerSlhDsa() -> Bool {
        guard slhDsaAvailable() else { return false }
        PCASlhDsaHook.register { fam, vk, msg, sig in slhVerify(family: fam, publicKey: vk, message: msg, signature: sig) }
        PCASlhDsaHook.registerSigner(PCASlhDsaHook.Signer(
            keygen: { fam, seed in try slhKeygen(family: fam, seed: seed) },
            sign: { fam, sk, msg in try slhSign(family: fam, secretKey: sk, message: msg) }))
        return true
    }

    /// A one-byte buffer stands in for an empty message so the pointer is never nil.
    private static func withBytes<R>(_ b: [UInt8], _ body: (UnsafePointer<UInt8>, Int) -> R) -> R {
        if b.isEmpty { return [UInt8](repeating: 0, count: 1).withUnsafeBufferPointer { body($0.baseAddress!, 0) } }
        return b.withUnsafeBufferPointer { body($0.baseAddress!, b.count) }
    }

    /// True only for a valid signature of exactly the right lengths; never throws.
    static func slhVerify(family: String, publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
        guard publicKey.count == PCASlhDsaHook.pkBytes[family], signature.count == PCASlhDsaHook.sigBytes[family],
              let pkey = EVP_PKEY_new_raw_public_key_ex(nil, family, nil, publicKey, publicKey.count) else { return false }
        defer { EVP_PKEY_free(pkey) }
        guard let ctx = EVP_MD_CTX_new() else { return false }
        defer { EVP_MD_CTX_free(ctx) }
        guard EVP_DigestVerifyInit_ex(ctx, nil, nil, nil, nil, pkey, nil) == 1 else { return false }
        return withBytes(message) { m, n in EVP_DigestVerify(ctx, signature, signature.count, m, n) == 1 }
    }

    /// The raw secret key (4n bytes) and public key (2n bytes) of the key a 3n-byte seed derives.
    static func slhKeygen(family: String, seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8]) {
        guard let want = PCASlhDsaHook.seedBytes[family], seed.count == want else { throw Failure("\(family): seed must be \(PCASlhDsaHook.seedBytes[family] ?? 0) bytes") }
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
        defer { EVP_PKEY_free(key) }
        let pkLen = PCASlhDsaHook.pkBytes[family]!, skLen = PCASlhDsaHook.skBytes[family]!
        var pub = [UInt8](repeating: 0, count: pkLen)
        var n = pkLen
        guard EVP_PKEY_get_raw_public_key(key, &pub, &n) == 1, n == pkLen else { throw Failure("\(family) public key unavailable") }
        var priv = [UInt8](repeating: 0, count: skLen)
        var m = skLen
        guard EVP_PKEY_get_raw_private_key(key, &priv, &m) == 1, m == skLen else { throw Failure("\(family) secret key unavailable") }
        return (priv, pub)
    }

    /// Deterministic pure-mode signature (empty context) under the raw secret key.
    static func slhSign(family: String, secretKey: [UInt8], message: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == PCASlhDsaHook.skBytes[family], let sigLen = PCASlhDsaHook.sigBytes[family],
              let pkey = EVP_PKEY_new_raw_private_key_ex(nil, family, nil, secretKey, secretKey.count) else { throw Failure("\(family): invalid secret key") }
        defer { EVP_PKEY_free(pkey) }
        guard let ctx = EVP_MD_CTX_new() else { throw Failure("EVP_MD_CTX_new failed") }
        defer { EVP_MD_CTX_free(ctx) }
        let name = strdup("deterministic")!
        defer { free(name) }
        var det: Int32 = 1
        let initRc: Int32 = withUnsafeMutablePointer(to: &det) { p in // the OSSL_PARAM keeps this pointer: build and use it inside the scope
            var params = [OSSL_PARAM_construct_int(name, p), OSSL_PARAM_construct_end()]
            return EVP_DigestSignInit_ex(ctx, nil, nil, nil, nil, pkey, &params)
        }
        guard initRc == 1 else { throw Failure("\(family) sign init refused") }
        var sig = [UInt8](repeating: 0, count: sigLen)
        var n = sigLen
        let rc: Int32 = withBytes(message) { m, len in EVP_DigestSign(ctx, &sig, &n, m, len) }
        guard rc == 1, n == sigLen else { throw Failure("\(family) sign failed") }
        return sig
    }
}
