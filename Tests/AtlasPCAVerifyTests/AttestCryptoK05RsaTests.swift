import XCTest
import Foundation
@testable import AtlasPCAVerify

/// RSA padding and key checks. With e = 1, s^e mod n is s, so a test chooses the encoded message itself and reaches every
/// modulus size and malformed padding without a private key. The encoders here follow RFC 8017 and use their own MGF1.
final class AttestCryptoK05RsaTests: XCTestCase {
    static let MSG = Array("atlas pca rsa padding".utf8)
    static let E1: [UInt8] = [1]

    /// The odd modulus 2^bits - 1.
    static func modulus(bits: Int) -> [UInt8] {
        var n = [UInt8](repeating: 0xff, count: (bits + 7) / 8)
        if bits % 8 != 0 { n[0] = UInt8((1 << (bits % 8)) - 1) }
        return n
    }

    static func mgf(_ seed: [UInt8], _ length: Int, _ hash: AHash) -> [UInt8] {
        var out: [UInt8] = []
        var c = 0
        while out.count < length {
            let counter: [UInt8] = [0, 0, UInt8(c >> 8), UInt8(c & 0xff)]
            out += hash.digest(seed + counter)
            c += 1
        }
        return Array(out.prefix(length))
    }

    static func salt(_ i: Int, _ length: Int) -> [UInt8] { mgf([UInt8(i)], length, .sha256) }

    /// EMSA-PSS-ENCODE over SHA-256; `delimiter` and `psFill` let a test break the DB.
    static func pssEM(emBits: Int, salt: [UInt8], delimiter: UInt8 = 0x01, psFill: UInt8 = 0) -> [UInt8] {
        let hash = AHash.sha256
        let emLen = (emBits + 7) / 8
        let eightZeros = [UInt8](repeating: 0, count: 8)
        let h = hash.digest(eightZeros + hash.digest(MSG) + salt)
        let ps = [UInt8](repeating: psFill, count: emLen - salt.count - hash.length - 2)
        let db: [UInt8] = ps + [delimiter] + salt
        let mask = mgf(h, db.count, hash)
        var masked = [UInt8](repeating: 0, count: db.count)
        for i in 0..<db.count { masked[i] = db[i] ^ mask[i] }
        masked[0] &= UInt8(0xff) >> (8 * emLen - emBits)
        let trailer: [UInt8] = [0xbc]
        return masked + h + trailer
    }

    /// Verify `em` (left-padded to |n|) under the modulus of nBits bits.
    func pss(_ em: [UInt8], nBits: Int, saltLength: Int) -> Bool {
        let n = Self.modulus(bits: nBits)
        let sig = [UInt8](repeating: 0, count: n.count - em.count) + em
        return ACrypto.rsaVerifyPSS(n: n, e: Self.E1, hash: .sha256, message: Self.MSG, sig: sig, saltLength: saltLength)
    }

    func testPssAcceptsEveryModulusBitOffsetAndSaltBoundary() {
        for nBits in 1024...1031 {
            let emBits = nBits - 1, emLen = (emBits + 7) / 8
            for i in 0..<8 {
                XCTAssertTrue(pss(Self.pssEM(emBits: emBits, salt: Self.salt(i, 32)), nBits: nBits, saltLength: 32), "bits \(nBits) salt \(i)")
            }
            XCTAssertTrue(pss(Self.pssEM(emBits: emBits, salt: []), nBits: nBits, saltLength: 0), "empty salt, bits \(nBits)")
            // the longest salt: no PS at all
            let longest = emLen - 32 - 2
            XCTAssertTrue(pss(Self.pssEM(emBits: emBits, salt: Self.salt(9, longest)), nBits: nBits, saltLength: longest), "longest salt, bits \(nBits)")
        }
    }

    func testPssRefusesSetBitsAboveEmBits() {
        var one = Self.pssEM(emBits: 1023, salt: Self.salt(1, 32))
        one[0] |= 0x80
        XCTAssertFalse(pss(one, nBits: 1024, saltLength: 32), "one top bit")
        var seven = Self.pssEM(emBits: 1025, salt: Self.salt(1, 32))
        seven[0] |= 0x02
        XCTAssertFalse(pss(seven, nBits: 1026, saltLength: 32), "seven top bits")
    }

    func testPssRefusesANonZeroByteBeforeAShorterEM() {
        let em = Self.pssEM(emBits: 1024, salt: Self.salt(1, 32))
        let sig: [UInt8] = [1] + em
        XCTAssertEqual(sig.count, Self.modulus(bits: 1025).count)
        XCTAssertFalse(ACrypto.rsaVerifyPSS(n: Self.modulus(bits: 1025), e: Self.E1, hash: .sha256, message: Self.MSG, sig: sig, saltLength: 32))
    }

    func testPssRefusesBadDbAndTrailer() {
        let good = Self.salt(1, 32)
        XCTAssertFalse(pss(Self.pssEM(emBits: 1023, salt: good, delimiter: 0x02), nBits: 1024, saltLength: 32), "delimiter")
        XCTAssertFalse(pss(Self.pssEM(emBits: 1023, salt: good, psFill: 0x01), nBits: 1024, saltLength: 32), "PS not zero")
        var trailer = Self.pssEM(emBits: 1023, salt: good)
        trailer[trailer.count - 1] ^= 1
        XCTAssertFalse(pss(trailer, nBits: 1024, saltLength: 32), "trailer")
    }

    func testPssRefusesBadSaltLengths() {
        let em = Self.pssEM(emBits: 1023, salt: Self.salt(1, 32))
        XCTAssertTrue(pss(em, nBits: 1024, saltLength: 32))
        XCTAssertFalse(pss(em, nBits: 1024, saltLength: -1), "negative")
        XCTAssertFalse(pss(em, nBits: 1024, saltLength: 33), "another length")
        XCTAssertFalse(pss(em, nBits: 1024, saltLength: em.count - 32 - 1), "one past the longest")
        XCTAssertFalse(pss(em, nBits: 1024, saltLength: em.count), "no room")
    }

    static func pkcs1EM(_ hash: AHash, k: Int) -> [UInt8] {
        let t = hash.digestInfoPrefix + hash.digest(MSG)
        let head: [UInt8] = [0x00, 0x01], separator: [UInt8] = [0x00]
        return head + [UInt8](repeating: 0xff, count: k - t.count - 3) + separator + t
    }

    func testPkcs1EightBytesOfPaddingIsTheMinimum() {
        // SHA-384: T is 67 bytes, so k = 78 leaves PS exactly 8 bytes (RFC 8017 9.2 emLen >= tLen + 11)
        XCTAssertTrue(ACrypto.rsaVerifyPKCS1(n: Self.modulus(bits: 78 * 8), e: Self.E1, hash: .sha384, message: Self.MSG, sig: Self.pkcs1EM(.sha384, k: 78)))
        XCTAssertFalse(ACrypto.rsaVerifyPKCS1(n: Self.modulus(bits: 77 * 8), e: Self.E1, hash: .sha384, message: Self.MSG, sig: Self.pkcs1EM(.sha384, k: 77)))
        // SHA-512 under a 64-byte modulus: T does not fit at all
        let one = [UInt8](repeating: 0, count: 63) + [1]
        XCTAssertFalse(ACrypto.rsaVerifyPKCS1(n: Self.modulus(bits: 512), e: Self.E1, hash: .sha512, message: Self.MSG, sig: one))
    }

    static func one(_ k: Int) -> [UInt8] { [UInt8](repeating: 0, count: k - 1) + [1] }

    func testRsaPublicModulusChecks() {
        XCTAssertEqual(ACrypto.rsaPublic(n: Self.modulus(bits: 512), e: Self.E1, sig: Self.one(64)), Self.one(64), "512 bits is the floor")
        XCTAssertEqual(ACrypto.rsaPublic(n: Self.modulus(bits: 513), e: Self.E1, sig: Self.one(65)), Self.one(65), "513 bits is 65 bytes")
        XCTAssertNil(ACrypto.rsaPublic(n: Self.modulus(bits: 511), e: Self.E1, sig: Self.one(64)), "below the floor")
        var even = Self.modulus(bits: 512)
        even[63] = 0xfe
        XCTAssertNil(ACrypto.rsaPublic(n: even, e: Self.E1, sig: Self.one(64)), "even modulus")
    }

    func testRsaPublicSignatureRange() {
        let n = Self.modulus(bits: 513)
        XCTAssertNil(ACrypto.rsaPublic(n: n, e: Self.E1, sig: Self.one(64)), "short")
        XCTAssertNil(ACrypto.rsaPublic(n: n, e: Self.E1, sig: Self.one(66)), "long")
        XCTAssertNil(ACrypto.rsaPublic(n: n, e: Self.E1, sig: n), "s == n")
        XCTAssertNil(ACrypto.rsaPublic(n: n, e: Self.E1, sig: [UInt8](repeating: 0xff, count: 65)), "s > n")
        var below = n
        below[64] = 0xfe
        XCTAssertEqual(ACrypto.rsaPublic(n: n, e: Self.E1, sig: below), below, "s == n - 1")
    }

    func testRsaPublicExponentChecks() {
        let n = Self.modulus(bits: 512), s = Self.one(64)
        XCTAssertNil(ACrypto.rsaPublic(n: n, e: [0], sig: s), "zero")
        XCTAssertNil(ACrypto.rsaPublic(n: n, e: [], sig: s), "empty")
        XCTAssertNil(ACrypto.rsaPublic(n: n, e: [0x01, 0, 0, 0, 0x01], sig: s), "33 bits")
        XCTAssertEqual(ACrypto.rsaPublic(n: n, e: [0x7f, 0xff, 0xff, 0xff], sig: s), s, "31 bits")
        XCTAssertEqual(ACrypto.rsaPublic(n: n, e: [0, 0, 0, 0, 0x01], sig: s), s, "leading zeros do not count")
    }
}
