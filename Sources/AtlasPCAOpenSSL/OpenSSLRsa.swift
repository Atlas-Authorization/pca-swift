import Foundation
import CLibcrypto
import AtlasPCAVerify

/// Signers and verifiers OpenSSL libcrypto provides to the verifier's registration seam (PCAExtraCrypto). Opt-in product: AtlasPCAVerify
/// itself never links OpenSSL.
public enum PCAOpenSSL {
    public struct Failure: Error, CustomStringConvertible {
        public let description: String
        init(_ d: String) { description = d }
    }

    /// Registers every algorithm this product provides.
    public static func register() {
        PCAExtraCrypto.rsaSign = { alg, parts, msg in try rsaSign(alg: alg, parts: parts, message: msg) }
        PCAExtraCrypto.ed448Verify = { pk, msg, sig in ed448Verify(publicKey: pk, message: msg, signature: sig) }
        PCAExtraCrypto.ed448Sign = { seed, msg in try ed448Sign(seed: seed, message: msg) }
        PCAExtraCrypto.ed448PublicKey = { seed in ed448PublicKey(seed: seed) }
    }

    // ---- RSA (RS / PS signing) ----

    private static func unsigned(_ b: [UInt8]) -> [UInt8] {
        var i = 0
        while i < b.count - 1 && b[i] == 0 { i += 1 }
        return b.isEmpty ? [0] : Array(b[i...])
    }

    private static func derLen(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var b: [UInt8] = []
        var v = n
        while v > 0 { b.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
        return [UInt8(0x80 | b.count)] + b
    }

    private static func derInt(_ b: [UInt8]) -> [UInt8] {
        var u = unsigned(b)
        if u[0] & 0x80 != 0 { u.insert(0, at: 0) }
        return [0x02] + derLen(u.count) + u
    }

    /// PKCS#1 RSAPrivateKey (RFC 8017 A.1.2) from the JWK members.
    static func rsaPrivateDer(_ parts: [String: [UInt8]]) throws -> (der: [UInt8], modulusBits: Int) {
        var ints: [[UInt8]] = []
        for m in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            guard let b = parts[m], !b.isEmpty else { throw Failure("Invalid JWK RSA key") }
            ints.append(b)
        }
        let n = unsigned(ints[0])
        let bits = (n.count - 1) * 8 + (8 - n[0].leadingZeroBitCount)
        let body = derInt([0]) + ints.flatMap { derInt($0) }
        return ([0x30] + derLen(body.count) + body, bits)
    }

    private static func mdFor(_ bits: Int) -> OpaquePointer {
        switch bits {
        case 256: return EVP_sha256()
        case 384: return EVP_sha384()
        default: return EVP_sha512()
        }
    }

    /// RS256/384/512 (PKCS#1 v1.5) and PS256/384/512 (PSS, MGF1 over the same hash, salt length = hash length, as jose).
    static func rsaSign(alg: String, parts: [String: [UInt8]], message: [UInt8]) throws -> [UInt8] {
        let pss = alg.hasPrefix("PS")
        guard pss || alg.hasPrefix("RS"), let bitsN = Int(alg.dropFirst(2)), [256, 384, 512].contains(bitsN) else { throw Failure("unsupported RSA alg \(alg)") }
        let (der, modBits) = try rsaPrivateDer(parts)
        if modBits < 2048 { throw Failure("\(alg) requires key modulusLength to be 2048 bits or larger") }
        let md = mdFor(bitsN)
        let saltLen = Int32(bitsN / 8)
        let key: OpaquePointer? = der.withUnsafeBufferPointer { buf in
            var p: UnsafePointer<UInt8>? = buf.baseAddress
            return d2i_PrivateKey(6, nil, &p, buf.count) // EVP_PKEY_RSA
        }
        guard let pkey = key else { throw Failure("Invalid JWK RSA key") }
        defer { EVP_PKEY_free(pkey) }
        guard let ctx = EVP_MD_CTX_new() else { throw Failure("EVP_MD_CTX_new failed") }
        defer { EVP_MD_CTX_free(ctx) }
        var pctx: OpaquePointer?
        guard EVP_DigestSignInit(ctx, &pctx, md, nil, pkey) == 1, let pc = pctx else { throw Failure("RSA sign init refused") }
        if pss {
            guard EVP_PKEY_CTX_set_rsa_padding(pc, 6) == 1, // RSA_PKCS1_PSS_PADDING
                  EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, saltLen) == 1,
                  EVP_PKEY_CTX_set_rsa_mgf1_md(pc, md) == 1 else { throw Failure("RSA-PSS parameters refused") }
        } else {
            guard EVP_PKEY_CTX_set_rsa_padding(pc, 1) == 1 else { throw Failure("RSA padding refused") } // RSA_PKCS1_PADDING
        }
        var sigLen = 0
        guard EVP_DigestSign(ctx, nil, &sigLen, message, message.count) == 1, sigLen > 0 else { throw Failure("RSA sign refused") }
        var sig = [UInt8](repeating: 0, count: sigLen)
        guard EVP_DigestSign(ctx, &sig, &sigLen, message, message.count) == 1 else { throw Failure("RSA sign failed") }
        return Array(sig[0..<sigLen])
    }
}
