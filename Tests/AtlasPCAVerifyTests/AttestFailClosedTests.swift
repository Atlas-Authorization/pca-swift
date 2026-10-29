import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Fail-closed tables and primitive self-checks of the attestation verifiers that need no vendor evidence: the RSA / ECDSA
/// primitives against signatures made by an independent library, the strict DER readers and the certificate engine over a small
/// generated chain, every constructor refusal, the answer for missing or garbage evidence, and the JSON.parse wording.
final class AttestFailClosedTests: XCTestCase {
    static let N = "b5fb2d04fa9c512806f148aa75e737ecd327980e8887790b585071657191fdc6d001ad7023c4e255986a7c261ef33237ce8c3b0e22f3c44ea64bd8ce08496ade22e3a97b165b7addd88e732454a8a5049d2b9f9f23004c61dbadeb4496f12f7d322e0d385a7e4bb2ebd20ea6b344a839746ff90d285eedffea9166ae957920f078b01494f8d1003564715ae5118b89e72c41e7bd5d0f7aae70ef84024d0524fd9f13836250c85dd152e8cb6bafb996ec4382fc35193bb93f9f39a1215d28a19d955931269cebde1fb12393741653f30a27930056f1f062ffe6cdc22a6fedbd6cce47d18d77cf2b11dd1875a806173c214e138dd888536c7fa7e33019b547f4cd"
    static let PKCS1 = "96bb7e7b24b5f801b3e32948a2f8c67248d9a0cd92635bdcf03b7bbd3f83f880090e75ee21854edea77165c9d2fa1549828a77202a22dae7d2102c5e917896de32bf428784125a29f0ec6432f6777e70d03f2cd6159394a904fcf5b7daca23b96d6d81736a6968017fa63193f492b38d93b1884f5b95a74a0aa0c84f7a5a78a9104189e030d8c3e9fc05476ca14f4df5541b212085380794317e7a676da6f22f79112058b49a85e311d4a40e2ee8253490b6ea612e9bddff167420ffb770a2866b729a62ab0b0875529d57ce5ef023fd7c832f2f2a34e16a9b96508ce81e6ff4cbc08cb5d0d35a3164730287389d73f9b50233e3d2bf0fb347afc729846b6bf0"
    static let PSS = "04912cfcd4544dc9f9c50b5b047dc828cdba4ee44c9606419c91f4fbf1009649cca72501532f42cd09972b310ba70487b8d3e3519628c713ba07d44b3e57a79416ce22268c43a2a492001534eec61fc99ea86b29805421aa0d45566b65bd673fca3f6735ba98abf5137ea481afea496d57f9a84f911061cb3d2453b039975e7cdfda810dce5ec74778c6623cac6fe543a8c99bbf54dfdccedc666723d70671e0aab28ac07b4db4accbdb2433ab97612a6599dcabc7c75c96be86214b02c347124148fa46bcbf45cc141a0717d9280cfdb6d5f0b0e1a9fab57226a69dbfcdbb280c8c29fad20920e236f07a757a0858e019f5c5facabfc47bfb0b6905e11d9e19"
    static let P384_PT = "04098b9ce9f0c40e7f6d9fb661f36520eeb1352872d7f8b7ad854800c3e25702dbf739e403b202d5596abe9bfb27791b1ef2c9b2fa87d8858d9c1f6386d41ca7255a3ebc5f31cc8621f804c7c3d0da673378f0134d57927b9fa044a93684de9a0c"
    static let P384_RAW = "001c4878a474c9fbc3d59d5b2437b958a96eca8d24454ee77c4586ed6d8621c476b809ec635f30c8790f5d8484b64df6ce94e9930350d778411e3405a7a1ef344775f1d2cfcfd0833b7b17527f28e85185ca2f8687c3b9b3bd98ecb8396c703c"
    static let P256_PT = "04a70af2d2a8ed8c8642cf94737e6136cd72838ab5e5f56a381e45068ddfb3d7f543e58d9a0ce2e71196c5759ac805b4498f78532f00394554089048fd74586b1c"
    static let P256_RAW = "d48357613eeb9d2e8a737dfd74e8ee523aed73514022260646b30c97503050bf764b56741222d5bb2b9ccf29d0a69c3d0802faf295d706ba7510a362ef9d38d7"
    static let P256_DER = "3045022100d48357613eeb9d2e8a737dfd74e8ee523aed73514022260646b30c97503050bf0220764b56741222d5bb2b9ccf29d0a69c3d0802faf295d706ba7510a362ef9d38d7"
    static let MSG = Array("atlas pca attestation self-check".utf8)

    static let ROOT = "MIIBczCB+qADAgECAgISNDAKBggqhkjOPQQDAzASMRAwDgYDVQQDDAdSb290IENBMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowEjEQMA4GA1UEAwwHUm9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIsh65EZT7Hkqh/5b4XizI6nb13zOdA/KkHrcOWmn0p1n0QBhQwOq/rqzHPgwbfCRJubaS8kx9hC+/SaPxZR7wFZo3j7DYcRcgXKSY9YakDLYcUZkefQee+nqlb8IcfQ2KMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQwCgYIKoZIzj0EAwMDaAAwZQIwOFK5NAPd9LpqvV9Nb4bJUgLe7voEF86Zp/zv9pLEj0RhJEfLL4KjGQY80ZzPhkqsAjEArmSCRctQIfKS5NjMHzzw+Ww2cPRoGDtKat9p6uWKKBUlto9kgTGUPXngxwNR7FLL"
    static let LEAF = "MIIBazCB8qADAgECAgIAqzAKBggqhkjOPQQDAzASMRAwDgYDVQQDDAdSb290IENBMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowHTEbMBkGA1UEAwwSTGVhZiwgd2l0aCtzcGVjaWFsMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJVkEuQBBG95r5T+E9MzFzQ3HfhYUq5ufQ6h9KlCN1dXOrB+Vt51jwaalF8fRRf4cLTfxjSt/N3KcADY2X6WkqP90B26Ko5pe4BkxPaaWW4Z1Bqul02RRu9HxLY1wLZKEoxAwDjAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMDA2gAMGUCMEvk/GPihzWGOxi1PdokR+v13fxCrPs6FKXk9V0md2p8OgGwTrJeHq9WnhEgg11uvAIxAJcRyb8oDZYr0SL6kHmyx/2OckiFj/7ZfznAi2rq0qHxNd80kqFU75gdSE/QxhSY6w=="
    static let RSA_CERT = "MIICszCCAZugAwIBAgIBBzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZSU0EgQ0EwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjARMQ8wDQYDVQQDDAZSU0EgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCe/iVsZupFLEP/alPJswFjOHT2YjtOpUBYRUuZ+DyRwADZC5YLrNidSdrjrqyBhhMkEAlC4QMDVMTiaYHD+QSb2xhlBa37NsPuCCvQgNba+JTjmEeUusVmcpaKMWK5qqji0XOXzisuAxIRmdtOzJ1YjdUh74ZnFTPz0HKPyNFXvebrnRousUh4Lrroj++FL//QeRN2GFZjMTlzPvOQ4rXn++TYs8+fiR9RfQpitIYI7pGOGnCSB0Zq6CZnmajJ5ddf4/z1g/2xsjkFC9W1NOfJ+BDVHBPcpNqafjecyrxZ6Tx2wgQb1JBR/XoqvCcN7/7faJG8fXhlW+dctiWz3tv7AgMBAAGjFjAUMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAFhWXrLJXDvCeqWQhx4YTvSjDnFqq0a5kWtikWBtC99EWLtHHP8Ujv34961yI70aoR3xiZuAZigCLFNdHdJgqnCQkG/A26f1lYrggzkAc5ZYG6VlfwV8g35OzPcCqsOjZgGT/oTiU+iK161fU65sojqf9Fo/ElsKQVNgWurd/Bd5h5+E7HrcpJPdF8DEao9QRaMMqMfWdYXB91AK7d4v4ZY36wsFCpOCoGXfcPuSjvxLX22qurguZt66wG30yd4rTcwVUpiXNBYDhWtPdbgyL7PoTmkBhxy/AInlC2PVlBHLh71wW9PNPw+T2OAXav1IAGdK1S1bMxQeTQrBasBTwqc="
    static let PSS_CERT = "MIIDGDCCAcygAwIBAgIBCDBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwETEPMA0GA1UEAwwGUFNTIENBMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowETEPMA0GA1UEAwwGUFNTIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnv4lbGbqRSxD/2pTybMBYzh09mI7TqVAWEVLmfg8kcAA2QuWC6zYnUna466sgYYTJBAJQuEDA1TE4mmBw/kEm9sYZQWt+zbD7ggr0IDW2viU45hHlLrFZnKWijFiuaqo4tFzl84rLgMSEZnbTsydWI3VIe+GZxUz89Byj8jRV73m650aLrFIeC666I/vhS//0HkTdhhWYzE5cz7zkOK15/vk2LPPn4kfUX0KYrSGCO6RjhpwkgdGaugmZ5moyeXXX+P89YP9sbI5BQvVtTTnyfgQ1RwT3KTamn43nMq8Wek8dsIEG9SQUf16KrwnDe/+32iRvH14ZVvnXLYls97b+wIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMAOCAQEATcUTOKYFh4LarjXbiU2A292RWXoKrJZNFtWw/exc5ckBxF/nO/A2MXxrIKijizEoa3IsezGE9paH6dIvXsPXq8RMNRlLvf4rA/9nmZT9C0DEpHtk4gIIswH4M6S9o8DoVx8WGVy70tqz5QL6XI5QFS6H2xlNgMypZYTJt2deikJ/CtDZwJZ2i/30wlPQ3qQl1ydcd5nODbPDamfznx3yp6lt3VFZHLaiXu9MPFGY5Cpff+0VwKF21CgTobITb4SfcVaW2q4pxLXxHtObjIprzOgHNWeIPRq8+Z7Lat76ubeMJvyirzqHFyXpP1DyGrS2ue5CYfOJGghNpNpRx7As9A=="
    static let ROOT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBczCB+qADAgECAgISNDAKBggqhkjOPQQDAzASMRAwDgYDVQQDDAdSb290IENB\nMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowEjEQMA4GA1UEAwwHUm9v\ndCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIsh65EZT7Hkqh/5b4XizI6nb13z\nOdA/KkHrcOWmn0p1n0QBhQwOq/rqzHPgwbfCRJubaS8kx9hC+/SaPxZR7wFZo3j7\nDYcRcgXKSY9YakDLYcUZkefQee+nqlb8IcfQ2KMjMCEwDwYDVR0TAQH/BAUwAwEB\n/zAOBgNVHQ8BAf8EBAMCAoQwCgYIKoZIzj0EAwMDaAAwZQIwOFK5NAPd9LpqvV9N\nb4bJUgLe7voEF86Zp/zv9pLEj0RhJEfLL4KjGQY80ZzPhkqsAjEArmSCRctQIfKS\n5NjMHzzw+Ww2cPRoGDtKat9p6uWKKBUlto9kgTGUPXngxwNR7FLL\n-----END CERTIFICATE-----\n"
    static let ROOT_SPKI_SHA256 = "d5351b5880bfb3c58c1352884a0f5044fd710c2f9e0a5f27b9396b367e64a841"

    static func h(_ s: String) -> [UInt8] { ACrypto.unhex(s)! }
    static func der(_ b64: String) -> [UInt8] { Attest.nodeB64(b64) }

    // ---- primitives ----

    func testBigNatMontgomeryModPow() {
        XCTAssertEqual(BigNat.modPowOdd(base: BigNat(bytes: [3]), exp: BigNat(bytes: [5]), mod: BigNat(bytes: [7])), BigNat(bytes: [5]))
        // 2^10 mod 1000003 = 1024
        XCTAssertEqual(BigNat.modPowOdd(base: BigNat(bytes: [2]), exp: BigNat(bytes: [10]), mod: BigNat(bytes: [0x0f, 0x42, 0x43])), BigNat(bytes: [0x04, 0x00]))
    }

    func testRsaPkcs1AndPss() {
        let n = Self.h(Self.N), e: [UInt8] = [0x01, 0x00, 0x01]
        XCTAssertTrue(ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha256, message: Self.MSG, sig: Self.h(Self.PKCS1)))
        XCTAssertFalse(ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha384, message: Self.MSG, sig: Self.h(Self.PKCS1)), "another hash")
        XCTAssertFalse(ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha256, message: Self.MSG + [0], sig: Self.h(Self.PKCS1)), "another message")
        var bad = Self.h(Self.PKCS1)
        bad[10] ^= 1
        XCTAssertFalse(ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha256, message: Self.MSG, sig: bad))
        XCTAssertFalse(ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha256, message: Self.MSG, sig: Array(Self.h(Self.PKCS1).dropFirst())), "short signature")
        XCTAssertTrue(ACrypto.rsaVerifyPSS(n: n, e: e, hash: .sha384, message: Self.MSG, sig: Self.h(Self.PSS), saltLength: 48))
        XCTAssertFalse(ACrypto.rsaVerifyPSS(n: n, e: e, hash: .sha384, message: Self.MSG, sig: Self.h(Self.PSS), saltLength: 20), "another salt length")
        XCTAssertFalse(ACrypto.rsaVerifyPSS(n: n, e: e, hash: .sha256, message: Self.MSG, sig: Self.h(Self.PSS), saltLength: 48), "another hash")
    }

    func testEcdsaRawAndDer() {
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-384", point: Self.h(Self.P384_PT), hash: .sha384, message: Self.MSG, raw: Self.h(Self.P384_RAW)))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-384", point: Self.h(Self.P384_PT), hash: .sha256, message: Self.MSG, raw: Self.h(Self.P384_RAW)))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-256", point: Self.h(Self.P384_PT), hash: .sha384, message: Self.MSG, raw: Self.h(Self.P384_RAW)), "a P-384 point is not a P-256 key")
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-256", point: Self.h(Self.P256_PT), hash: .sha256, message: Self.MSG, raw: Self.h(Self.P256_RAW)))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-256", point: Self.h(Self.P256_PT), hash: .sha256, message: Self.MSG, der: Self.h(Self.P256_DER)))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-256", point: Self.h(Self.P256_PT), hash: .sha256, message: Self.MSG + [1], der: Self.h(Self.P256_DER)))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-256", point: Self.h(Self.P256_PT), hash: .sha256, message: Self.MSG, raw: Array(Self.h(Self.P256_RAW).dropLast())), "a raw signature has the curve's exact size")
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-256", point: [4] + [UInt8](repeating: 1, count: 64)))
    }

    /// P-224 has no swift-crypto / CryptoKit type: pure-Swift ECDSA (AttestP224.swift). Signatures made by Node (OpenSSL) over a
    /// secp224r1 key, in raw and DER form, for each SHA-2 hash; reference verifiers accept the curve through OpenSSL.
    func testEcdsaP224() {
        let pt = Self.h("04d96a7f5a687c57f05382ccc7f1727c0e9bb389b0280aaed54c5a44f0d6e2fa9900149c8acc0860ff5d2d88a0b721cde3589218a8c0541921")
        let msg = Array("atlas pca p224 self-check".utf8)
        let raw256 = Self.h("1db8d960f60a77d39f04a98b77264129cdb2c97a4011d1f03f3c0364846d3b432ab87862c640d3a9c400696f1130dfff3b35d58596595233")
        let der256 = Self.h("303e021d00c6ba0c918d060308dac395c8b9ca6642a96184c781d56043c8daa431021d00dbdf2c218c40b97399363851c7f630fd6de94e21b2012980532bdfa3")
        let der384 = Self.h("303d021d00a44c3bf23a3f42539c9663871e9b91cc574afe8ef6b96bdb9ce1836c021c2a42cba17b001dbc6a55bd47218e48fda5043010f4db65a7acb37a1d")
        let raw384 = Self.h("d5155d3a6b7958af0f8d02eff23ebc217c7c8a69d857587e7da484ec239cea38765fce0888573d6f427ac4ecfb7e1d48080f2b65285dd2ab")
        let der512 = Self.h("303c021c6ca96fb721f13641c0a18ca1578315354b075cd2c6bc936dc6c45479021c36adf6c87b813ed00b3364bb92c0e8468cf71d57a508e1908ea111f5")
        let raw512 = Self.h("ee467c054e6e49d700e82ca0800ab0c1a91f7145b4a7b66576110e3ac86efda539c2792f10026b88a40ad42c8d28a5f4ef552ceca619bdbe")
        XCTAssertEqual(raw256.count, 56)
        XCTAssertEqual(raw384.count, 56)
        XCTAssertEqual(raw512.count, 56)
        XCTAssertTrue(ACrypto.ecPointValid(curve: "P-224", point: pt))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: raw256))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, der: der256))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha384, message: msg, raw: raw384))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha384, message: msg, der: der384))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha512, message: msg, raw: raw512))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha512, message: msg, der: der512))
        // wrong message / hash / key
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg + [0], raw: raw256))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha384, message: msg, raw: raw256))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: raw384))
        // a flipped bit in r or in s
        var bad = raw256
        bad[3] ^= 1
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: bad))
        bad = raw256
        bad[40] ^= 0x80
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: bad))
        // r = 0, s = 0, s = n, a short raw signature
        let zero = [UInt8](repeating: 0, count: 28)
        let n = Self.h("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: zero + Array(raw256[28...])))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: Array(raw256[..<28]) + zero))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: Array(raw256[..<28]) + n))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, raw: Array(raw256.dropLast())))
        // strict DER: trailing byte, non-minimal INTEGER (extra 0x00), wrong outer length, negative INTEGER
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, der: der256 + [0]))
        var nonMinimal = der256
        nonMinimal.replaceSubrange(2..<5, with: [0x02, 0x1e, 0x00, 0x00])
        nonMinimal[1] += 1
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, der: nonMinimal))
        var longer = der256
        longer[1] += 1
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, der: longer))
        // a bad public key: wrong prefix, off the curve, a coordinate not below p, wrong size
        var offCurve = pt
        offCurve[56] ^= 1
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-224", point: offCurve))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-224", point: offCurve, hash: .sha256, message: msg, raw: raw256))
        var compressedPrefix = pt
        compressedPrefix[0] = 0x02
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-224", point: compressedPrefix))
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-224", point: [0x04] + [UInt8](repeating: 0xff, count: 56)))
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-224", point: Array(pt.dropLast())))
        // the field and the order constants are the standard ones: G is on the curve, and a P-256 point is not a P-224 key
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-224", point: Self.h(Self.P256_PT)))
    }

    /// Wycheproof ecdsa_secp224r1 (SHA-256 and SHA-512 files; upstream has no SHA-384 one), signatures in DER. Policy: "valid" must verify,
    /// "invalid" must not (this verifier is strict DER, so BER variants are invalid; the files contain no "acceptable" case).
    func testEcdsaP224Wycheproof() throws {
        let doc = try JSONSerialization.jsonObject(with: K042.bytes("wycheproof-ecdsa-secp224r1.json.gz")) as! [String: Any]
        let groups = doc["groups"] as! [[String: Any]]
        var n = 0
        for g in groups {
            let sha = g["sha"] as! String
            let pt = Self.h(g["key"] as! String)
            for t in g["tests"] as! [[Any]] {
                let msg = Self.h(t[2] as! String), sig = Self.h(t[3] as! String)
                let ok = sha == "SHA-256"
                    ? ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha256, message: msg, der: sig)
                    : ACrypto.ecVerify(curve: "P-224", point: pt, hash: .sha512, message: msg, der: sig)
                XCTAssertEqual(ok, (t[4] as! String) == "valid", "\(sha) tcId \(t[0])")
                n += 1
            }
        }
        XCTAssertEqual(n, 1031)
    }

    // ---- DER readers and the certificate engine ----

    func testStrictDerReadersOverAGeneratedChain() throws {
        let root = Self.der(Self.ROOT), leaf = Self.der(Self.LEAF)
        let ri = try DER.readCertRoleInfo(root)
        XCTAssertTrue(ri.hasBasicConstraints && ri.ca && ri.hasKeyUsage && ri.keyCertSign)
        XCTAssertEqual(ri.pathLen, -1)
        let li = try DER.readCertRoleInfo(leaf)
        XCTAssertTrue(li.hasBasicConstraints && !li.ca && !li.hasKeyUsage)
        XCTAssertEqual(DER.checkChainRoles([leaf, root]), "")
        XCTAssertEqual(DER.checkChainRoles([root, leaf]), "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)")
        XCTAssertEqual(DER.checkChainRoles([leaf, leaf]), "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)")
        let ext = try DER.parseCertExtensions(root)
        XCTAssertEqual(ext.oids, ["2.5.29.19", "2.5.29.15"])
        XCTAssertTrue(ext.get("2.5.29.19")?.critical ?? false)
        XCTAssertNil(try DER.unrecognisedCriticalExtension(root))
        XCTAssertEqual(try DER.unrecognisedCriticalExtension(root, []), "2.5.29.19")
        let (from, to) = DER.derValidity(root)
        XCTAssertEqual(from, 1_735_689_600_000)
        XCTAssertEqual(to, 2_051_222_400_000)
        XCTAssertTrue(DER.derValidAt(root, 1_800_000_000_000, 0))
        XCTAssertFalse(DER.derValidAt(root, 1_735_689_599_999, 0))
        XCTAssertTrue(DER.derValidAt(root, 1_735_689_599_999, 1))
        XCTAssertFalse(DER.derValidAt(root, 2_051_222_400_001, 0))
        // a trailing byte, a truncation and a non-minimal length are each refused with the reference's message
        XCTAssertThrowsError(try DER.readCertRoleInfo(root + [0])) { XCTAssertEqual(($0 as? AttestError)?.message, "trailing bytes after the certificate") }
        XCTAssertThrowsError(try DER.readCertRoleInfo(Array(root.dropLast()))) { XCTAssertEqual(($0 as? AttestError)?.message, "DER: element overruns its parent") }
        XCTAssertThrowsError(try DER.readTlvStrict([0x30, 0x81, 0x05, 1, 2, 3, 4, 5], 0, 8)) { XCTAssertEqual(($0 as? AttestError)?.message, "DER: non-minimal length (long form below 128)") }
    }

    func testDerTimeIsStrict() {
        let t = { (tag: Int, s: String) in DER.parseDerTime(tag, Array(s.utf8)) }
        XCTAssertEqual(t(0x17, "250101000000Z"), 1_735_689_600_000)
        XCTAssertEqual(t(0x17, "500101000000Z"), -631_152_000_000, "YY >= 50 is 19YY")
        XCTAssertEqual(t(0x18, "20250101000000Z"), 1_735_689_600_000)
        XCTAssertNil(t(0x18, "20250230000000Z"), "no roll-over of Feb 30")
        XCTAssertNil(t(0x18, "20250101240000Z"))
        XCTAssertNil(t(0x17, "250101000000"), "no Z")
        XCTAssertNil(t(0x18, "2025010100000Z"), "wrong length")
        XCTAssertEqual(t(0x18, "20240229000000Z"), 1_709_164_800_000, "a leap day")
        XCTAssertNil(t(0x18, "20230229000000Z"))
    }

    func testCertificateParsingKeysAndSignatures() throws {
        let root = try Cert.parseDER(Self.der(Self.ROOT)), leaf = try Cert.parseDER(Self.der(Self.LEAF))
        XCTAssertTrue(Cert.selfIssued(root))
        XCTAssertFalse(Cert.selfIssued(leaf))
        XCTAssertEqual(Cert.serialHex(leaf), "ab")
        XCTAssertEqual(Cert.serialHex(root), "1234")
        XCTAssertEqual(Cert.nameText(root.rawSubject), "CN=Root CA")
        XCTAssertEqual(Cert.nameText(leaf.rawSubject), "CN=Leaf\\, with\\+special")
        let rk = try Cert.keyOf(root)
        XCTAssertEqual(rk.typ, "ec")
        XCTAssertEqual(rk.curve, "secp384r1")
        XCTAssertEqual(rk.spkiSHA256, Self.ROOT_SPKI_SHA256)
        XCTAssertTrue(Cert.sigOKBy(leaf, root))
        XCTAssertTrue(Cert.sigOKBy(root, root))
        XCTAssertFalse(Cert.sigOKBy(root, leaf))
        let fromPem = try Cert.fromPEM(Self.ROOT_PEM)
        XCTAssertEqual(fromPem.raw, Self.der(Self.ROOT))
        XCTAssertEqual(Cert.pemBlocks(Self.ROOT_PEM + Self.ROOT_PEM).count, 2)
        XCTAssertThrowsError(try Cert.fromPEM("nothing here")) { XCTAssertEqual(($0 as? AttestError)?.message, "error:0480006C:PEM routines::no start line") }
        let rsa = try Cert.parseDER(Self.der(Self.RSA_CERT)), pss = try Cert.parseDER(Self.der(Self.PSS_CERT))
        XCTAssertEqual(try Cert.keyOf(rsa).typ, "rsa")
        XCTAssertTrue(Cert.sigOKBy(rsa, rsa), "RSA PKCS#1 v1.5 / SHA-256")
        XCTAssertTrue(Cert.sigOKBy(pss, pss), "RSASSA-PSS / SHA-384, salt 48")
        XCTAssertFalse(Cert.sigOKBy(rsa, root))
        XCTAssertEqual(try DER.readCertRoleInfo(rsa.raw).pathLen, 1)
        // a tampered TBS no longer verifies
        var tampered = Self.der(Self.LEAF)
        tampered[60] ^= 1
        if let t = try? Cert.parseDER(tampered) { XCTAssertFalse(Cert.sigOKBy(t, root)) }
    }

    // ---- constructors refuse every unsafe configuration ----

    func refusal(_ vendor: String, _ cfg: JObject?) -> String? {
        do { _ = try VendorVerifier(vendor: vendor, config: cfg) } catch { return (error as? AttestationConfigError)?.message }
        return nil
    }

    func testConstructorRefusals() throws {
        XCTAssertEqual(refusal("tpm", [:]), "unknown attestation vendor \"tpm\"")
        let mHex = String(repeating: "ab", count: 48)
        XCTAssertEqual(refusal("amd-sev-snp", ["family": .string("rome"), "binding": .string("report-data")]), "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'")
        XCTAssertEqual(refusal("amd-sev-snp", ["family": .string("milan"), "binding": .string("x")]), "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'")
        XCTAssertEqual(refusal("amd-sev-snp", ["family": .string("milan"), "binding": .string("report-data"), "policy": .object(["measurements": .array([])])]),
                       "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
        XCTAssertEqual(refusal("amd-sev-snp", ["family": .string("milan"), "binding": .string("report-data"), "policy": .object(["measurements": .array([.string(mHex)]), "minReportedTcb": .null])]),
                       "Cannot convert null to a BigInt")
        XCTAssertNil(refusal("amd-sev-snp", ["family": .string("milan"), "binding": .string("report-data"), "policy": .object(["measurements": .array([.string(mHex)])])]))
        XCTAssertEqual(refusal("intel-tdx-dcap", ["binding": .string("report-data"), "policy": .object(["mrtds": .array([.string("ab")])])]), "createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)")
        XCTAssertEqual(refusal("intel-tdx-dcap", ["binding": .string("report-data")]), "createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)")
        XCTAssertEqual(refusal("azure-maa", [:]), "createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs")
        XCTAssertEqual(refusal("azure-maa", ["trustedIssuers": .array([.string("https://x")])]),
                       "createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted")
        XCTAssertEqual(refusal("azure-maa", ["trustedIssuers": .array([.string("https://x")]), "trustAnchors": .object(["rootSpkiSha256": .array([.string("ab")])])]),
                       "createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)")
        XCTAssertEqual(refusal("gcp-confidential-space", ["trustedIssuers": .array([.string("https://x")])]),
                       "createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted")
        XCTAssertEqual(refusal("gcp-confidential-space", ["trustedIssuers": .array([.string("https://x")]), "trustAnchors": .object(["trustedKeySpki": .array([.string("ab")])])]),
                       "createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)")
        XCTAssertEqual(refusal("nvidia-gpu-spdm", [:]), "createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")
        XCTAssertEqual(refusal("nvidia-gpu-spdm", ["rootSpkiSha256": .array([.string("ab")])]),
                       "createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)")
        XCTAssertEqual(refusal("nvidia-gpu-spdm", ["rootSpkiSha256": .array([.string("ab")]), "policy": .object(["measurements": .object(["300": .string("aa")])])]),
                       "createNvidiaSpdmVerifier: measurement index out of range")
    }

    // ---- missing and garbage evidence is refused with the reference's reason ----

    static let BIND = AttestationBinding(holderPub: "holder", grantRef: "grant", epoch: 1, nonce: "nonce")

    func verifier(_ vendor: String) throws -> VendorVerifier {
        let mHex = String(repeating: "ab", count: 48)
        let cfgs: [String: JObject] = [
            "amd-sev-snp": ["family": .string("milan"), "binding": .string("report-data"), "policy": .object(["measurements": .array([.string(mHex)])])],
            "intel-tdx-dcap": ["binding": .string("report-data"), "policy": .object(["mrtds": .array([.string(mHex)])])],
            "azure-maa": ["trustedIssuers": .array([.string("https://x")]), "trustAnchors": .object(["rootSpkiSha256": .array([.string("ab")])]),
                          "policy": .object(["sevSnpMeasurements": .array([.string("aa")])])],
            "gcp-confidential-space": ["trustedIssuers": .array([.string("https://x")]), "trustAnchors": .object(["trustedKeySpki": .array([.string("ab")])]),
                                       "policy": .object(["imageDigests": .array([.string("sha256:aa")])])],
            "nvidia-gpu-spdm": ["rootSpkiSha256": .array([.string("ab")]), "policy": .object(["measurements": .object(["0": .string("aa")])])],
        ]
        return try VendorVerifier(vendor: vendor, config: cfgs[vendor])
    }

    func testNoEvidenceIsRefused() throws {
        let reasons = ["amd-sev-snp": "no AMD SEV-SNP evidence for this action", "intel-tdx-dcap": "no Intel DCAP quote for this action",
                       "azure-maa": "no Azure MAA token for this action", "gcp-confidential-space": "no GCP Confidential Space token for this action",
                       "nvidia-gpu-spdm": "no NVIDIA GPU evidence for this action"]
        for (vendor, why) in reasons {
            let v = try verifier(vendor)
            for ev in [nil, JSONValue.null, .object([:]), .string("x"), .object(["token": .string("")])] as [JSONValue?] {
                let r = v.verify(evidence: ev, expected: Self.BIND, nowMs: 1_800_000_000_000)
                XCTAssertFalse(r.ok, vendor)
                XCTAssertEqual(r.reason, why, vendor)
            }
        }
    }

    func testGarbageEvidenceFailsClosedWithTheReferenceReason() throws {
        let now: Int64 = 1_800_000_000_000
        func ask(_ vendor: String, _ ev: JObject, _ b: AttestationBinding? = AttestFailClosedTests.BIND) throws -> String { try verifier(vendor).verify(evidence: .object(ev), expected: b, nowMs: now).reason }
        XCTAssertEqual(try ask("amd-sev-snp", ["report": .string("AA"), "vcekDer": .string("AA"), "askArkPem": .string("x")]),
                       "SEV-SNP report invalid: report parse failed: parseSevSnpReport: report too short (1 < 816)")
        XCTAssertEqual(try ask("amd-sev-snp", ["report": .string("AA"), "vcekDer": .string("AA"), "askArkPem": .string("x")], nil), "no expected attestation binding supplied")
        XCTAssertEqual(try ask("intel-tdx-dcap", ["quote": .string("AA")]), "DCAP quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length")
        XCTAssertEqual(try ask("intel-tdx-dcap", ["quote": .string("AA")], nil), "no expected attestation binding supplied")
        XCTAssertEqual(try ask("nvidia-gpu-spdm", ["evidence": .string("AA"), "certChainPem": .string("x")]), "device chain unparseable: parsePemChain: no certificates found")
        XCTAssertTrue(try ask("azure-maa", ["token": .string("not-a-jwt")]).hasPrefix("MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts"))
        XCTAssertEqual(try ask("azure-maa", ["token": .string("a.b.c")]), "MAA token parse failed: parseMaaJwt: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url (impossible length)")
        XCTAssertEqual(try ask("gcp-confidential-space", ["token": .string("a..c")]), "Confidential Space token parse failed: parseGcpCsJwt: empty JWS segment")
        // header {"alg":"none"} . payload {} . signature: an unsupported alg is refused before any key is looked at
        let hdr = Base64URLStrict.encode(Array(#"{"alg":"none"}"#.utf8)), pl = Base64URLStrict.encode(Array("{}".utf8)), sg = Base64URLStrict.encode([1, 2, 3])
        XCTAssertEqual(try ask("azure-maa", ["token": .string("\(hdr).\(pl).\(sg)")]), "unsupported JWS alg 'none' (MAA uses ES256 / RS256)")
        XCTAssertEqual(try ask("gcp-confidential-space", ["token": .string("\(hdr).\(pl).\(sg)")]), "unsupported JWS alg 'none' (Confidential Space uses RS256)")
        let rs = Base64URLStrict.encode(Array(#"{"alg":"RS256"}"#.utf8))
        XCTAssertEqual(try ask("azure-maa", ["token": .string("\(rs).\(pl).\(sg)")]), "no signing x5c available (no JWKS and no header x5c)")
        XCTAssertEqual(try ask("gcp-confidential-space", ["token": .string("\(rs).\(pl).\(sg)")]), "Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available")
    }

    func testIdentityOverridesAreMergedOverTheMeasuredIdentity() throws {
        // an override cannot turn a refusal into an accept: it applies to successful verifications only
        let v = try VendorVerifier(vendor: "nvidia-gpu-spdm", config: ["rootSpkiSha256": .array([.string("ab")]), "policy": .object(["measurements": .object(["0": .string("aa")])]),
                                                                       "identity_overrides": .object(["model_id": .string("m")])])
        XCTAssertFalse(v.verify(evidence: nil, expected: Self.BIND, nowMs: 0).ok)
    }

    // ---- the wording of JSON.parse failures ----

    func testV8JsonParseMessages() {
        XCTAssertEqual(V8JSON.error("{\"a\":1}"), "")
        XCTAssertEqual(V8JSON.error("{"), "Expected property name or '}' in JSON at position 1 (line 1 column 2)")
        XCTAssertEqual(V8JSON.error("nope"), "Unexpected token 'o', \"nope\" is not valid JSON")
        XCTAssertEqual(V8JSON.error(""), "Unexpected end of JSON input")
        XCTAssertEqual(V8JSON.error("[1,]"), "Unexpected token ']', \"[1,]\" is not valid JSON")
        XCTAssertEqual(V8JSON.error("{\"a\" 1}"), "Expected ':' after property name in JSON at position 5 (line 1 column 6)")
        XCTAssertEqual(V8JSON.error("1 2"), "Unexpected non-whitespace character after JSON at position 2 (line 1 column 3)")
        XCTAssertEqual(V8JSON.error("\"abc"), "Unterminated string in JSON at position 4 (line 1 column 5)")
        XCTAssertEqual(V8JSON.error("-"), "No number after minus sign in JSON at position 1 (line 1 column 2)")
        XCTAssertEqual(V8JSON.error("NaN"), "\"NaN\" is not valid JSON")
    }

    // ---- PCS collateral helpers ----

    func testDateParseAndBigIntFloors() throws {
        XCTAssertEqual(IntelCollateral.jsDateParse("2025-01-01T00:00:00Z"), 1_735_689_600_000)
        XCTAssertEqual(IntelCollateral.jsDateParse("2025-01-01T00:00:00.5Z"), 1_735_689_600_500)
        XCTAssertEqual(IntelCollateral.jsDateParse("2025-01-01T01:00:00+01:00"), 1_735_689_600_000)
        XCTAssertEqual(IntelCollateral.jsDateParse("2025-01-01"), 1_735_689_600_000)
        XCTAssertNil(IntelCollateral.jsDateParse("2025-13-01T00:00:00Z"))
        XCTAssertNil(IntelCollateral.jsDateParse("yesterday"))
        let a = try AmdVerifier.parseJSBigInt(.string("0x10"))
        XCTAssertEqual(a.value, 16)
        XCTAssertTrue(try AmdVerifier.parseJSBigInt(.string("99999999999999999999999")).huge)
        XCTAssertTrue(try AmdVerifier.parseJSBigInt(.string("18446744073709551615")).above(18_446_744_073_709_551_614))
        XCTAssertFalse(try AmdVerifier.parseJSBigInt(.string("5")).above(5))
        XCTAssertTrue(try AmdVerifier.parseJSBigInt(.string("5")).above(4))
        XCTAssertThrowsError(try AmdVerifier.parseJSBigInt(.double(1.5)))
        XCTAssertThrowsError(try AmdVerifier.parseJSBigInt(.string("12x")))
    }

    private func spdmReport(_ reqVer: UInt8, _ respVer: UInt8) -> SpdmReport {
        var b = [UInt8](repeating: 0, count: 37 + 8 + 32 + 2 + 96)
        b[0] = reqVer
        b[1] = 0xe0
        b[37] = respVer
        b[38] = 0x60
        return try! Nvidia.parseSpdm(b)
    }

    func testNvidiaSpdmVersionMustBeAtLeast11AndAgree() {
        XCTAssertNil(Nvidia.versionProblem(spdmReport(0x11, 0x11)))
        XCTAssertNil(Nvidia.versionProblem(spdmReport(0x12, 0x12)))
        XCTAssertEqual(Nvidia.versionProblem(spdmReport(0x10, 0x10)), "SPDM version 0x10/0x10 is not an accepted GET_MEASUREMENTS version")
        XCTAssertEqual(Nvidia.versionProblem(spdmReport(0x11, 0x12)), "SPDM version 0x11/0x12 is not an accepted GET_MEASUREMENTS version")
        XCTAssertEqual(Nvidia.versionProblem(spdmReport(0x12, 0x11)), "SPDM version 0x12/0x11 is not an accepted GET_MEASUREMENTS version")
    }
}
