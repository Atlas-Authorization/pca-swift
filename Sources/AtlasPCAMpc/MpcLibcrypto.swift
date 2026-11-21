import Foundation
import CLibcrypto

/// The primitives of the MPC stack that are OpenSSL libcrypto's (3.x EVP): SHAKE256 here; AES-128-ECB and ML-KEM-768 below. Nothing is re-implemented;
/// a failing libcrypto call throws (fail closed).
enum Libcrypto {
    /// SHAKE256 (FIPS 202) of the concatenation of `chunks`, `outLen` bytes.
    static func shake256(_ chunks: [[UInt8]], outLen: Int) throws -> [UInt8] {
        guard outLen >= 1 else { throw PCAMpc.MpcError("SHAKE256 output length must be positive") }
        guard let md = EVP_MD_fetch(nil, "SHAKE256", nil) else { throw PCAMpc.MpcError("libcrypto has no SHAKE256") }
        defer { EVP_MD_free(md) }
        guard let ctx = EVP_MD_CTX_new() else { throw PCAMpc.MpcError("EVP_MD_CTX_new failed") }
        defer { EVP_MD_CTX_free(ctx) }
        guard EVP_DigestInit_ex(ctx, md, nil) == 1 else { throw PCAMpc.MpcError("SHAKE256 init failed") }
        for c in chunks where !c.isEmpty {
            guard c.withUnsafeBytes({ EVP_DigestUpdate(ctx, $0.baseAddress, c.count) }) == 1 else { throw PCAMpc.MpcError("SHAKE256 update failed") }
        }
        var out = [UInt8](repeating: 0, count: outLen)
        guard EVP_DigestFinalXOF(ctx, &out, outLen) == 1 else { throw PCAMpc.MpcError("SHAKE256 failed") }
        return out
    }

    /// AES-128-ECB encryption of whole blocks, no padding.
    static func aes128ecb(_ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, data.count % 16 == 0, data.count <= Int(Int32.max) else { throw PCAMpc.MpcError("aes: bad key or block length") }
        if data.isEmpty { return [] }
        guard let ctx = EVP_CIPHER_CTX_new() else { throw PCAMpc.MpcError("EVP_CIPHER_CTX_new failed") }
        defer { EVP_CIPHER_CTX_free(ctx) }
        guard EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nil, key, nil) == 1, EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 else { throw PCAMpc.MpcError("aes: init refused") }
        var out = [UInt8](repeating: 0, count: data.count)
        var n: Int32 = 0
        guard EVP_EncryptUpdate(ctx, &out, &n, data, Int32(data.count)) == 1, Int(n) == data.count else { throw PCAMpc.MpcError("aes: libcrypto refused") }
        var fin: Int32 = 0
        var tail = [UInt8](repeating: 0, count: 16)
        guard EVP_EncryptFinal_ex(ctx, &tail, &fin) == 1, fin == 0 else { throw PCAMpc.MpcError("aes: libcrypto refused") }
        return out
    }
}

/// ML-KEM-768 (FIPS 203) on OpenSSL >= 3.5: key generation from a 64-byte seed (d || z) and encapsulation from a 32-byte message (the "ikme" parameter),
/// so the OT transcripts are reproducible from a seeded stream.
extension Libcrypto {
    static let mlkemPublicKeyBytes = 1184
    static let mlkemCipherTextBytes = 1088
    static let mlkemSecretBytes = 32
    // OSSL_PARAM keeps the key-name pointer, so these must outlive every param built from them
    private static let seedKey = UnsafePointer<CChar>(strdup("seed")!)
    private static let ikmeKey = UnsafePointer<CChar>(strdup("ikme")!)

    /// True when the loaded libcrypto is 3.5 or later and a seeded key generation, deterministic encapsulation and decapsulation round-trip.
    static let mlkemAvailable: Bool = {
        guard OpenSSL_version_num() >= 0x3050_0000 else { return false }
        do {
            let seed = [UInt8](repeating: 1, count: 64)
            let pk = try mlkemPublicKey(seed)
            let e = try mlkemEncapsulate(pk, [UInt8](repeating: 2, count: 32))
            return try mlkemDecapsulate(e.cipherText, seed) == e.sharedSecret
        } catch { return false }
    }()

    private static func mlkemKey(_ seed: [UInt8]) throws -> OpaquePointer {
        guard seed.count == 64 else { throw PCAMpc.MpcError("ml-kem keygen: seed must be exactly 64 bytes") }
        guard let ctx = EVP_PKEY_CTX_new_from_name(nil, "ML-KEM-768", nil) else { throw PCAMpc.MpcError("ML-KEM-768 is not available (needs OpenSSL 3.5); KEM oblivious transfer refuses (fail closed)") }
        defer { EVP_PKEY_CTX_free(ctx) }
        guard EVP_PKEY_keygen_init(ctx) == 1 else { throw PCAMpc.MpcError("ML-KEM-768 keygen init refused") }
        var s = seed
        let key: OpaquePointer? = s.withUnsafeMutableBytes { buf in
            var params = [OSSL_PARAM_construct_octet_string(seedKey, buf.baseAddress, buf.count), OSSL_PARAM_construct_end()]
            guard EVP_PKEY_CTX_set_params(ctx, &params) == 1 else { return nil }
            var pkey: OpaquePointer?
            return EVP_PKEY_generate(ctx, &pkey) == 1 ? pkey : nil
        }
        guard let k = key else { throw PCAMpc.MpcError("ML-KEM-768 keygen refused the seed") }
        return k
    }

    /// The 1184-byte encapsulation key of the key pair generated from `seed`.
    static func mlkemPublicKey(_ seed: [UInt8]) throws -> [UInt8] {
        let pkey = try mlkemKey(seed)
        defer { EVP_PKEY_free(pkey) }
        var pub = [UInt8](repeating: 0, count: mlkemPublicKeyBytes)
        var n = mlkemPublicKeyBytes
        guard EVP_PKEY_get_raw_public_key(pkey, &pub, &n) == 1, n == mlkemPublicKeyBytes else { throw PCAMpc.MpcError("ML-KEM-768 public key export failed") }
        return pub
    }

    static func mlkemEncapsulate(_ publicKey: [UInt8], _ msg32: [UInt8]) throws -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
        guard msg32.count == 32 else { throw PCAMpc.MpcError("ml-kem encapsulate: message must be exactly 32 bytes") }
        guard publicKey.count == mlkemPublicKeyBytes else { throw PCAMpc.MpcError("ml-kem encapsulate: public key must be exactly \(mlkemPublicKeyBytes) bytes") }
        guard let pk = EVP_PKEY_new_raw_public_key_ex(nil, "ML-KEM-768", nil, publicKey, publicKey.count) else { throw PCAMpc.MpcError("ml-kem encapsulate: invalid public key") }
        defer { EVP_PKEY_free(pk) }
        guard let ctx = EVP_PKEY_CTX_new_from_pkey(nil, pk, nil) else { throw PCAMpc.MpcError("ml-kem encapsulate: no context") }
        defer { EVP_PKEY_CTX_free(ctx) }
        var m = msg32
        var ct = [UInt8](repeating: 0, count: mlkemCipherTextBytes), ss = [UInt8](repeating: 0, count: mlkemSecretBytes)
        var ctLen = mlkemCipherTextBytes, ssLen = mlkemSecretBytes
        let ok: Bool = m.withUnsafeMutableBytes { buf in
            var params = [OSSL_PARAM_construct_octet_string(ikmeKey, buf.baseAddress, buf.count), OSSL_PARAM_construct_end()]
            return EVP_PKEY_encapsulate_init(ctx, &params) == 1 && EVP_PKEY_encapsulate(ctx, &ct, &ctLen, &ss, &ssLen) == 1
        }
        guard ok, ctLen == mlkemCipherTextBytes, ssLen == mlkemSecretBytes else { throw PCAMpc.MpcError("ml-kem encapsulate failed") }
        return (ct, ss)
    }

    static func mlkemDecapsulate(_ cipherText: [UInt8], _ seed: [UInt8]) throws -> [UInt8] {
        guard cipherText.count == mlkemCipherTextBytes else { throw PCAMpc.MpcError("ml-kem decapsulate: ciphertext must be exactly \(mlkemCipherTextBytes) bytes") }
        let pkey = try mlkemKey(seed)
        defer { EVP_PKEY_free(pkey) }
        guard let ctx = EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil) else { throw PCAMpc.MpcError("ml-kem decapsulate: no context") }
        defer { EVP_PKEY_CTX_free(ctx) }
        var ss = [UInt8](repeating: 0, count: mlkemSecretBytes)
        var ssLen = mlkemSecretBytes
        guard EVP_PKEY_decapsulate_init(ctx, nil) == 1, EVP_PKEY_decapsulate(ctx, &ss, &ssLen, cipherText, cipherText.count) == 1, ssLen == mlkemSecretBytes else { throw PCAMpc.MpcError("ml-kem decapsulate failed") }
        return ss
    }
}
