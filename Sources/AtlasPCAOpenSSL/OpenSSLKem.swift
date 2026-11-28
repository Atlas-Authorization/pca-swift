import Foundation
import CLibcrypto
import AtlasPCAVerify

/// Hybrid key encapsulation on OpenSSL libcrypto 3.5+: X25519 + ML-KEM-768, X25519 + ML-KEM-1024 (each with its own HKDF-SHA256 combiner transcript) and
/// X-Wing (draft-connolly-cfrg-xwing-kem-09, SHA3-256 combiner, byte-compatible with other X-Wing implementations). Every one establishes a 32-byte
/// shared secret; no cipher is shipped. Every primitive (ML-KEM, X25519, HMAC-SHA256, SHA3-256, SHAKE256) is libcrypto's; a failing call throws.
///
/// Layouts. Hybrid: public key = X25519(32) || ek, ciphertext = ephemeral X25519(32) || ML-KEM ciphertext, secret key = X25519 secret(32) || the
/// expanded FIPS 203 decapsulation key. X-Wing: public key = ek(1184) || X25519(32), ciphertext = ML-KEM ciphertext(1088) || X25519(32), secret key =
/// the 32-byte seed.
public enum PCAKem {
    public struct KemError: Error, CustomStringConvertible {
        public let description: String
        init(_ d: String) { description = d }
    }

    public struct KeyPair: Equatable, Sendable {
        public let publicKey: [UInt8]
        public let secretKey: [UInt8]
    }

    public struct Encapsulation: Equatable, Sendable {
        public let ciphertext: [UInt8]
        public let sharedSecret: [UInt8]
    }

    public static let HYBRID_PUBLIC_KEY_LEN = 1216
    public static let HYBRID_CIPHERTEXT_LEN = 1120
    public static let HYBRID_SHARED_SECRET_LEN = 32
    public static let HYBRID_KEM_SUITE = "x25519-ml-kem-768"
    public static let XWING_SUITE = "xwing"
    public static let XWING_SEED_LEN = 32
    public static let XWING_SECRET_KEY_LEN = 32
    public static let XWING_PUBLIC_KEY_LEN = 1216
    public static let XWING_CIPHERTEXT_LEN = 1120
    public static let XWING_SHARED_SECRET_LEN = 32
    public static let XWING_ESEED_LEN = 64
    public static let XWING_LABEL: [UInt8] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]
    public static let HYBRID1024_PUBLIC_KEY_LEN = 1600
    public static let HYBRID1024_CIPHERTEXT_LEN = 1600
    public static let HYBRID1024_SHARED_SECRET_LEN = 32
    public static let HYBRID1024_KEM_SUITE = "x25519-ml-kem-1024"

    /// True when the loaded libcrypto has ML-KEM (3.5 or later).
    public static func available() -> Bool {
        guard OpenSSL_version_num() >= 0x3050_0000, let ctx = EVP_PKEY_CTX_new_from_name(nil, "ML-KEM-768", nil) else { return false }
        EVP_PKEY_CTX_free(ctx)
        return true
    }

    // MARK: parameter sets

    struct Level {
        let k: Int
        let name: String
        let domain: [UInt8]
        var ekLen: Int { 384 * k + 32 }
        var dkLen: Int { 768 * k + 96 }
        var ctLen: Int { k == 3 ? 1088 : 1568 }
    }

    static let L768 = Level(k: 3, name: "ML-KEM-768", domain: Array("atlas-pca/kem/x25519-ml-kem-768/v1".utf8) + [0])
    static let L1024 = Level(k: 4, name: "ML-KEM-1024", domain: Array("atlas-pca/kem/x25519-ml-kem-1024/v1".utf8) + [0])

    static func level(_ n: Int) throws -> Level {
        switch n {
        case 768: return L768
        case 1024: return L1024
        default: throw KemError("ML-KEM level must be 768 or 1024")
        }
    }

    // MARK: libcrypto primitives

    // an OSSL_PARAM keeps the key-name pointer, so these outlive every param built from them
    private static let seedKey = UnsafePointer<CChar>(strdup("seed")!)
    private static let ikmeKey = UnsafePointer<CChar>(strdup("ikme")!)
    private static let privKey = UnsafePointer<CChar>(strdup("priv")!)
    private static let pctKey = UnsafePointer<CChar>(strdup("ml-kem.import_pct_type")!)
    private static let pctNone = strdup("none")!

    /// A private library context whose default provider imports an explicit decapsulation key WITHOUT the pairwise consistency test: FIPS 203
    /// decapsulation with a damaged decryption half answers the implicit-rejection secret, it does not refuse. Nil when it cannot be built; the import
    /// then runs in the default context (with the test), which refuses such a key.
    private static let importLib: OpaquePointer? = {
        // the setter exists from libcrypto 3.5 on; it is looked up at run time so the product still builds and loads against older headers
        typealias AddConf = @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Int32
        guard let me = dlopen(nil, RTLD_NOW), let sym = dlsym(me, "OSSL_PROVIDER_add_conf_parameter"), let lib = OSSL_LIB_CTX_new() else { return nil }
        guard let prov = OSSL_PROVIDER_load(lib, "default"), unsafeBitCast(sym, to: AddConf.self)(prov, "ml-kem.import_pct_type", "none") == 1 else {
            OSSL_LIB_CTX_free(lib)
            return nil
        }
        return lib
    }()

    private static func random(_ n: Int) -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<n).map { _ in UInt8.random(in: .min ... .max, using: &g) }
    }

    private static func hmacSha256(_ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var n = 0
        guard EVP_Q_mac(nil, "HMAC", nil, "SHA256", nil, key, key.count, data, data.count, &out, 32, &n) != nil, n == 32 else { throw KemError("HMAC-SHA256 failed") }
        return out
    }

    /// HKDF-SHA256 (RFC 5869) with no salt and a 32-byte output: extract, then the first expand block.
    private static func hkdf32(_ ikm: [UInt8], info: [UInt8]) throws -> [UInt8] {
        try hmacSha256(try hmacSha256([UInt8](repeating: 0, count: 32), ikm), info + [1])
    }

    static func sha3_256(_ data: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var n = 0
        guard EVP_Q_digest(nil, "SHA3-256", nil, data, data.count, &out, &n) == 1, n == 32 else { throw KemError("SHA3-256 failed") }
        return out
    }

    private static func shake256(_ data: [UInt8], _ outLen: Int) throws -> [UInt8] {
        guard let md = EVP_MD_fetch(nil, "SHAKE256", nil) else { throw KemError("libcrypto has no SHAKE256") }
        defer { EVP_MD_free(md) }
        guard let ctx = EVP_MD_CTX_new() else { throw KemError("EVP_MD_CTX_new failed") }
        defer { EVP_MD_CTX_free(ctx) }
        var out = [UInt8](repeating: 0, count: outLen)
        guard EVP_DigestInit_ex(ctx, md, nil) == 1, EVP_DigestUpdate(ctx, data, data.count) == 1, EVP_DigestFinalXOF(ctx, &out, outLen) == 1 else { throw KemError("SHAKE256 failed") }
        return out
    }

    private static func x25519Key(_ secret: [UInt8]) throws -> OpaquePointer {
        guard secret.count == 32, let k = EVP_PKEY_new_raw_private_key_ex(nil, "X25519", nil, secret, 32) else { throw KemError("X25519: the secret must be 32 bytes") }
        return k
    }

    private static func x25519Public(_ secret: [UInt8]) throws -> [UInt8] {
        let k = try x25519Key(secret)
        defer { EVP_PKEY_free(k) }
        var out = [UInt8](repeating: 0, count: 32)
        var n = 32
        guard EVP_PKEY_get_raw_public_key(k, &out, &n) == 1, n == 32 else { throw KemError("X25519 public key export failed") }
        return out
    }

    /// The X25519 shared secret; a low-order peer point (an all-zero result) is refused.
    private static func x25519Shared(_ secret: [UInt8], _ peer: [UInt8]) throws -> [UInt8] {
        let k = try x25519Key(secret)
        defer { EVP_PKEY_free(k) }
        guard peer.count == 32, let p = EVP_PKEY_new_raw_public_key_ex(nil, "X25519", nil, peer, 32) else { throw KemError("X25519: the public key must be 32 bytes") }
        defer { EVP_PKEY_free(p) }
        guard let ctx = EVP_PKEY_CTX_new_from_pkey(nil, k, nil) else { throw KemError("X25519: no context") }
        defer { EVP_PKEY_CTX_free(ctx) }
        var out = [UInt8](repeating: 0, count: 32)
        var n = 32
        guard EVP_PKEY_derive_init(ctx) == 1, EVP_PKEY_derive_set_peer(ctx, p) == 1, EVP_PKEY_derive(ctx, &out, &n) == 1, n == 32 else { throw KemError("X25519 refused the public key") }
        var acc: UInt8 = 0
        for b in out { acc |= b }
        if acc == 0 { throw KemError("X25519: low-order public key") }
        return out
    }

    /// The encapsulation key and the expanded decapsulation key of the pair generated from the 64-byte seed d || z.
    static func mlKemKeygen(_ l: Level, _ seed: [UInt8]) throws -> (ek: [UInt8], dk: [UInt8]) {
        guard seed.count == 64 else { throw KemError("\(l.name) keygen: the seed must be 64 bytes") }
        guard let ctx = EVP_PKEY_CTX_new_from_name(nil, l.name, nil) else { throw KemError("\(l.name) is not available (needs OpenSSL 3.5)") }
        defer { EVP_PKEY_CTX_free(ctx) }
        guard EVP_PKEY_keygen_init(ctx) == 1 else { throw KemError("\(l.name) keygen init refused") }
        var s = seed
        defer { for i in s.indices { s[i] = 0 } }
        let key: OpaquePointer? = s.withUnsafeMutableBytes { buf in
            var params = [OSSL_PARAM_construct_octet_string(seedKey, buf.baseAddress, buf.count), OSSL_PARAM_construct_end()]
            guard EVP_PKEY_CTX_set_params(ctx, &params) == 1 else { return nil }
            var pkey: OpaquePointer?
            return EVP_PKEY_generate(ctx, &pkey) == 1 ? pkey : nil
        }
        guard let pkey = key else { throw KemError("\(l.name) keygen refused the seed") }
        defer { EVP_PKEY_free(pkey) }
        var ek = [UInt8](repeating: 0, count: l.ekLen), dk = [UInt8](repeating: 0, count: l.dkLen)
        var ekN = l.ekLen, dkN = 0
        guard EVP_PKEY_get_raw_public_key(pkey, &ek, &ekN) == 1, ekN == l.ekLen, EVP_PKEY_get_octet_string_param(pkey, privKey, &dk, l.dkLen, &dkN) == 1, dkN == l.dkLen else {
            throw KemError("\(l.name) key export failed")
        }
        return (ek, dk)
    }

    /// FIPS 203 encapsulation from the 32-byte message `m`. The caller has run the modulus check on `ek`.
    private static func mlKemEncapsulate(_ l: Level, _ ek: [UInt8], _ m: [UInt8]) throws -> (ct: [UInt8], ss: [UInt8]) {
        guard m.count == 32, ek.count == l.ekLen else { throw KemError("\(l.name) encapsulate: bad message or key length") }
        guard let pk = EVP_PKEY_new_raw_public_key_ex(nil, l.name, nil, ek, ek.count) else { throw KemError("\(l.name) encapsulate: invalid public key") }
        defer { EVP_PKEY_free(pk) }
        guard let ctx = EVP_PKEY_CTX_new_from_pkey(nil, pk, nil) else { throw KemError("\(l.name) encapsulate: no context") }
        defer { EVP_PKEY_CTX_free(ctx) }
        var msg = m
        defer { for i in msg.indices { msg[i] = 0 } }
        var ct = [UInt8](repeating: 0, count: l.ctLen), ss = [UInt8](repeating: 0, count: 32)
        var ctN = l.ctLen, ssN = 32
        let ok: Bool = msg.withUnsafeMutableBytes { buf in
            var params = [OSSL_PARAM_construct_octet_string(ikmeKey, buf.baseAddress, buf.count), OSSL_PARAM_construct_end()]
            return EVP_PKEY_encapsulate_init(ctx, &params) == 1 && EVP_PKEY_encapsulate(ctx, &ct, &ctN, &ss, &ssN) == 1
        }
        guard ok, ctN == l.ctLen, ssN == 32 else { throw KemError("\(l.name) encapsulate failed") }
        return (ct, ss)
    }

    /// FIPS 203 decapsulation with an expanded decapsulation key. A ciphertext that does not decrypt yields the implicit-rejection secret (no error).
    private static func mlKemDecapsulate(_ l: Level, _ ct: [UInt8], _ dk: [UInt8]) throws -> [UInt8] {
        guard ct.count == l.ctLen else { throw KemError("\(l.name) decapsulate: the ciphertext must be \(l.ctLen) bytes") }
        guard dk.count == l.dkLen else { throw KemError("\(l.name) decapsulate: the decapsulation key must be \(l.dkLen) bytes") }
        let lib = importLib
        guard let fctx = EVP_PKEY_CTX_new_from_name(lib, l.name, nil) else { throw KemError("\(l.name) is not available (needs OpenSSL 3.5)") }
        defer { EVP_PKEY_CTX_free(fctx) }
        guard EVP_PKEY_fromdata_init(fctx) == 1 else { throw KemError("\(l.name) key import init refused") }
        var d = dk
        defer { for i in d.indices { d[i] = 0 } }
        // FIPS 203 ByteDecode_12 reduces each 12-bit coefficient of the decryption half (the first 384 * k bytes) mod q = 3329, so a coefficient
        // >= q names the same key as its residue; OpenSSL range-checks on import instead, so re-encode that half reduced (the rest stays as it is)
        var i = 0
        while i + 2 < 384 * l.k {
            let c0 = (Int(d[i]) | ((Int(d[i + 1]) & 0x0f) << 8)) % 3329
            let c1 = ((Int(d[i + 1]) >> 4) | (Int(d[i + 2]) << 4)) % 3329
            d[i] = UInt8(c0 & 0xff)
            d[i + 1] = UInt8(((c0 >> 8) & 0x0f) | ((c1 & 0x0f) << 4))
            d[i + 2] = UInt8((c1 >> 4) & 0xff)
            i += 3
        }
        let key: OpaquePointer? = d.withUnsafeMutableBytes { buf in
            var params = [OSSL_PARAM_construct_octet_string(privKey, buf.baseAddress, buf.count), OSSL_PARAM_construct_utf8_string(pctKey, pctNone, 0), OSSL_PARAM_construct_end()]
            var pkey: OpaquePointer?
            // 0x87 = EVP_PKEY_KEYPAIR (the selection macro is not visible to Swift)
            return EVP_PKEY_fromdata(fctx, &pkey, 0x87, &params) == 1 ? pkey : nil
        }
        guard let pkey = key else { throw KemError("\(l.name) decapsulate: malformed decapsulation key") }
        defer { EVP_PKEY_free(pkey) }
        guard let ctx = EVP_PKEY_CTX_new_from_pkey(lib, pkey, nil) else { throw KemError("\(l.name) decapsulate: no context") }
        defer { EVP_PKEY_CTX_free(ctx) }
        var ss = [UInt8](repeating: 0, count: 32)
        var n = 32
        guard EVP_PKEY_decapsulate_init(ctx, nil) == 1, EVP_PKEY_decapsulate(ctx, &ss, &n, ct, ct.count) == 1, n == 32 else { throw KemError("\(l.name) decapsulate failed") }
        return ss
    }

    // MARK: FIPS 203 key checks

    /// Every 12-bit coefficient of the encoded vector is below the modulus 3329 (FIPS 203 section 7.2).
    private static func coefficientsReduced(_ ek: ArraySlice<UInt8>, _ k: Int) -> Bool {
        let e = Array(ek)
        var i = 0
        while i < 384 * k {
            if (Int(e[i]) | ((Int(e[i + 1]) & 0x0f) << 8)) >= 3329 { return false }
            if ((Int(e[i + 1]) >> 4) | (Int(e[i + 2]) << 4)) >= 3329 { return false }
            i += 3
        }
        return true
    }

    /// The encapsulation key input check (FIPS 203 section 7.2): the exact length and reduced coefficients. Throws for a level other than 768 / 1024.
    public static func mlKemEncapsulationKeyCheck(_ level: Int, _ ek: [UInt8]) throws -> Bool {
        let l = try self.level(level)
        return ek.count == l.ekLen && coefficientsReduced(ek[...], l.k)
    }

    /// The decapsulation key input check (FIPS 203 section 7.3): the exact length, the embedded hash equals SHA3-256 of the embedded encapsulation
    /// key, and that key passes its own check. The decryption half and z are not checked. Throws for a level other than 768 / 1024.
    public static func mlKemDecapsulationKeyCheck(_ level: Int, _ dk: [UInt8]) throws -> Bool {
        let l = try self.level(level)
        guard dk.count == l.dkLen else { return false }
        let ek = Array(dk[(384 * l.k)..<(768 * l.k + 32)])
        let want = try sha3_256(ek)
        var diff: UInt8 = 0
        for i in 0..<32 { diff |= want[i] ^ dk[768 * l.k + 32 + i] }
        return diff == 0 && coefficientsReduced(ek[...], l.k)
    }

    // MARK: hybrid X25519 + ML-KEM

    private static func combine(_ l: Level, _ ssM: [UInt8], _ ssX: [UInt8], _ ephPub: [UInt8], _ recipX: [UInt8]) throws -> [UInt8] {
        try hkdf32(ssM + ssX + ephPub + recipX, info: l.domain)
    }

    /// Key generation from the bytes the randomised call would draw: X25519 secret(32) || d(32) || z(32).
    static func hybridKeygenDerand(_ l: Level, _ rng: [UInt8]) throws -> KeyPair {
        guard rng.count == 96 else { throw KemError("hybrid keygen: 96 random bytes are needed") }
        let x = Array(rng[0..<32])
        let m = try mlKemKeygen(l, Array(rng[32..<96]))
        return KeyPair(publicKey: try x25519Public(x) + m.ek, secretKey: x + m.dk)
    }

    /// Encapsulation from the bytes the randomised call would draw: ephemeral X25519 secret(32) || ML-KEM message(32).
    static func hybridEncapsulateDerand(_ l: Level, _ publicKey: [UInt8], _ rng: [UInt8]) throws -> Encapsulation {
        guard publicKey.count == 32 + l.ekLen else { throw KemError("hybrid encapsulate: the public key must be \(32 + l.ekLen) bytes (got \(publicKey.count))") }
        guard rng.count == 64 else { throw KemError("hybrid encapsulate: 64 random bytes are needed") }
        let recipX = Array(publicKey[0..<32]), ek = Array(publicKey[32...]), eph = Array(rng[0..<32])
        let ephPub = try x25519Public(eph)
        let ssX = try x25519Shared(eph, recipX)
        guard coefficientsReduced(ek[...], l.k) else { throw KemError("hybrid encapsulate: the ML-KEM encapsulation key fails the FIPS 203 modulus check") }
        let e = try mlKemEncapsulate(l, ek, Array(rng[32..<64]))
        return Encapsulation(ciphertext: ephPub + e.ct, sharedSecret: try combine(l, e.ss, ssX, ephPub, recipX))
    }

    static func hybridDecapsulate(_ l: Level, _ ciphertext: [UInt8], _ secretKey: [UInt8]) throws -> [UInt8] {
        guard ciphertext.count == 32 + l.ctLen else { throw KemError("hybrid decapsulate: the ciphertext must be \(32 + l.ctLen) bytes (got \(ciphertext.count))") }
        guard secretKey.count == 32 + l.dkLen else { throw KemError("hybrid decapsulate: malformed secret key") }
        let ephPub = Array(ciphertext[0..<32]), x = Array(secretKey[0..<32])
        let ssX = try x25519Shared(x, ephPub)
        let ssM = try mlKemDecapsulate(l, Array(ciphertext[32...]), Array(secretKey[32...]))
        return try combine(l, ssM, ssX, ephPub, try x25519Public(x))
    }

    /// A fresh X25519 + ML-KEM-768 key pair (public key 1216 bytes, secret key 2432 bytes).
    public static func hybridKemKeygen() throws -> KeyPair { try hybridKeygenDerand(L768, random(96)) }
    /// Encapsulate to an X25519 + ML-KEM-768 public key: a 1120-byte ciphertext and the 32-byte shared secret.
    public static func hybridEncapsulate(_ recipientPublicKey: [UInt8]) throws -> Encapsulation { try hybridEncapsulateDerand(L768, recipientPublicKey, random(64)) }
    public static func hybridDecapsulate(_ ciphertext: [UInt8], _ secretKey: [UInt8]) throws -> [UInt8] { try hybridDecapsulate(L768, ciphertext, secretKey) }

    /// A fresh X25519 + ML-KEM-1024 key pair (public key 1600 bytes, secret key 3200 bytes).
    public static func hybridKem1024Keygen() throws -> KeyPair { try hybridKeygenDerand(L1024, random(96)) }
    public static func hybridEncapsulate1024(_ recipientPublicKey: [UInt8]) throws -> Encapsulation { try hybridEncapsulateDerand(L1024, recipientPublicKey, random(64)) }
    public static func hybridDecapsulate1024(_ ciphertext: [UInt8], _ secretKey: [UInt8]) throws -> [UInt8] { try hybridDecapsulate(L1024, ciphertext, secretKey) }

    // MARK: X-Wing

    private static func expandXWing(_ seed: [UInt8]) throws -> (dk: [UInt8], ek: [UInt8], xSecret: [UInt8], xPublic: [UInt8]) {
        guard seed.count == XWING_SEED_LEN else { throw KemError("X-Wing: the seed must be \(XWING_SEED_LEN) bytes (got \(seed.count))") }
        let ex = try shake256(seed, 96)
        let m = try mlKemKeygen(L768, Array(ex[0..<64]))
        let xs = Array(ex[64..<96])
        return (m.dk, m.ek, xs, try x25519Public(xs))
    }

    private static func xwingCombiner(_ ssM: [UInt8], _ ssX: [UInt8], _ ctX: [UInt8], _ pkX: [UInt8]) throws -> [UInt8] {
        try sha3_256(ssM + ssX + ctX + pkX + XWING_LABEL)
    }

    /// The X-Wing key pair of a 32-byte seed (a fresh random seed when none is given). The secret key is the seed.
    public static func xwingKeygen(_ seed: [UInt8]? = nil) throws -> KeyPair {
        let sk = seed ?? random(XWING_SEED_LEN)
        let ex = try expandXWing(sk)
        return KeyPair(publicKey: ex.ek + ex.xPublic, secretKey: sk)
    }

    /// Deterministic X-Wing encapsulation; `eseed` = ML-KEM message(32) || ephemeral X25519 secret(32).
    public static func xwingEncapsulateDerand(_ recipientPublicKey: [UInt8], _ eseed: [UInt8]) throws -> Encapsulation {
        guard recipientPublicKey.count == XWING_PUBLIC_KEY_LEN else { throw KemError("xwingEncapsulateDerand: the public key must be \(XWING_PUBLIC_KEY_LEN) bytes (got \(recipientPublicKey.count))") }
        guard eseed.count == XWING_ESEED_LEN else { throw KemError("xwingEncapsulateDerand: eseed must be \(XWING_ESEED_LEN) bytes (got \(eseed.count))") }
        let pkM = Array(recipientPublicKey[0..<1184]), pkX = Array(recipientPublicKey[1184...]), ekX = Array(eseed[32..<64])
        guard coefficientsReduced(pkM[...], 3) else { throw KemError("xwingEncapsulateDerand: the ML-KEM encapsulation key fails the FIPS 203 modulus check") }
        let e = try mlKemEncapsulate(L768, pkM, Array(eseed[0..<32]))
        let ctX = try x25519Public(ekX)
        let ssX = try x25519Shared(ekX, pkX)
        return Encapsulation(ciphertext: e.ct + ctX, sharedSecret: try xwingCombiner(e.ss, ssX, ctX, pkX))
    }

    public static func xwingEncapsulate(_ recipientPublicKey: [UInt8]) throws -> Encapsulation { try xwingEncapsulateDerand(recipientPublicKey, random(XWING_ESEED_LEN)) }

    public static func xwingDecapsulate(_ ciphertext: [UInt8], _ secretKey: [UInt8]) throws -> [UInt8] {
        guard ciphertext.count == XWING_CIPHERTEXT_LEN else { throw KemError("xwingDecapsulate: the ciphertext must be \(XWING_CIPHERTEXT_LEN) bytes (got \(ciphertext.count))") }
        let ex = try expandXWing(secretKey)
        let ctX = Array(ciphertext[1088...])
        let ssM = try mlKemDecapsulate(L768, Array(ciphertext[0..<1088]), ex.dk)
        let ssX = try x25519Shared(ex.xSecret, ctX)
        return try xwingCombiner(ssM, ssX, ctX, ex.xPublic)
    }

    // MARK: text forms (unpadded base64url; decoding is strict and does not check the decoded length)

    private static func decode(_ s: String) throws -> [UInt8] {
        guard let b = PCAWire.b64uDecode(s) else { throw KemError("not canonical unpadded base64url") }
        return b
    }

    public static func encodeHybridPublicKey(_ k: [UInt8]) -> String { PCAWire.b64uEncode(k) }
    public static func decodeHybridPublicKey(_ s: String) throws -> [UInt8] { try decode(s) }
    public static func encodeHybridCiphertext(_ c: [UInt8]) -> String { PCAWire.b64uEncode(c) }
    public static func decodeHybridCiphertext(_ s: String) throws -> [UInt8] { try decode(s) }
    public static func encodeXWingPublicKey(_ k: [UInt8]) -> String { PCAWire.b64uEncode(k) }
    public static func decodeXWingPublicKey(_ s: String) throws -> [UInt8] { try decode(s) }
    public static func encodeXWingCiphertext(_ c: [UInt8]) -> String { PCAWire.b64uEncode(c) }
    public static func decodeXWingCiphertext(_ s: String) throws -> [UInt8] { try decode(s) }
}
