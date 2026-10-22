import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Strict base64url pinned against independently computed encodings (Python base64): every length 0...13 with all-ones, random
/// and all-zero bytes, canonical decoding, the exact length gate, and every refusal (alphabet, padding, length mod 4, trailing bits).
final class Base64URLStrictVectorTests: XCTestCase {
    private func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var i = hex.startIndex
        while i < hex.endIndex { let j = hex.index(i, offsetBy: 2); out.append(UInt8(hex[i..<j], radix: 16)!); i = j }
        return out
    }
    private static let vectors: [(String, String)] = [
        ("", ""),
        ("", ""),
        ("", ""),
        ("ff", "_w"),
        ("a5", "pQ"),
        ("00", "AA"),
        ("ffff", "__8"),
        ("4dca", "Tco"),
        ("0000", "AAA"),
        ("ffffff", "____"),
        ("182530", "GCUw"),
        ("000000", "AAAA"),
        ("ffffffff", "_____w"),
        ("bb1d6d13", "ux1tEw"),
        ("00000000", "AAAAAA"),
        ("ffffffffff", "______8"),
        ("2cded6237b", "LN7WI3s"),
        ("0000000000", "AAAAAAA"),
        ("ffffffffffff", "________"),
        ("2ed91e3f721f", "LtkeP3If"),
        ("000000000000", "AAAAAAAA"),
        ("ffffffffffffff", "_________w"),
        ("cb1971174494d6", "yxlxF0SU1g"),
        ("00000000000000", "AAAAAAAAAA"),
        ("ffffffffffffffff", "__________8"),
        ("493c9d5c3460be31", "STydXDRgvjE"),
        ("0000000000000000", "AAAAAAAAAAA"),
        ("ffffffffffffffffff", "____________"),
        ("201e69fedaa0eee8b9", "IB5p_tqg7ui5"),
        ("000000000000000000", "AAAAAAAAAAAA"),
        ("ffffffffffffffffffff", "_____________w"),
        ("997f5c7c2999fdafe593", "mX9cfCmZ_a_lkw"),
        ("00000000000000000000", "AAAAAAAAAAAAAA"),
        ("ffffffffffffffffffffff", "______________8"),
        ("253cd654af4dfad71427a0", "JTzWVK9N-tcUJ6A"),
        ("0000000000000000000000", "AAAAAAAAAAAAAAA"),
        ("ffffffffffffffffffffffff", "________________"),
        ("aeb3fee9232f8af2211f9ee4", "rrP-6SMvivIhH57k"),
        ("000000000000000000000000", "AAAAAAAAAAAAAAAA"),
        ("ffffffffffffffffffffffffff", "_________________w"),
        ("91c5b10becb5563bfc1e6f9342", "kcWxC-y1Vjv8Hm-TQg"),
        ("00000000000000000000000000", "AAAAAAAAAAAAAAAAAA"),
    ]

    func testEncodeAndDecodeMatchTheReference() {
        for (h, e) in Self.vectors {
            let b = bytes(h)
            XCTAssertEqual(Base64URLStrict.encode(b), e, "encode \(h)")
            XCTAssertEqual(Base64URLStrict.decode(e) ?? [255], b, "decode \(e)")
            XCTAssertEqual(Base64URLStrict.decode(e, length: b.count) ?? [255], b, "decode \(e) with its length")
            XCTAssertNil(Base64URLStrict.decode(e, length: b.count + 1), "wrong length (+1) \(e)")
            if b.count > 0 { XCTAssertNil(Base64URLStrict.decode(e, length: b.count - 1), "wrong length (-1) \(e)") }
            XCTAssertEqual(Base64URLStrict.encodedLength(b.count), e.utf8.count, "encodedLength \(b.count)")
            XCTAssertTrue(Base64URLStrict.isValid(e))
            XCTAssertTrue(Base64URLStrict.isValid(e, length: b.count))
        }
    }

    func testRefusals() {
        let negatives: [String] = ["A", "AAAAA", "AB", "AC", "AD", "AAB", "AAC", "Zg=", "Zg==", "Zg ", "Zg\\n", "+/", "a+b", "a/b", "é", "AA\u{0}", "Zh", "Zi", "Zj", "Zx", "Zm9", "Zm9vYh", "Zm9vYi", "Zm9vYj", "AAAAB", "AAAAAAB"]
        for s in negatives { XCTAssertNil(Base64URLStrict.decode(s), "must refuse \(s.debugDescription)") }
        for s in ["Zg", "Zm8", "Zm9v", "AAAA"] { XCTAssertNotNil(Base64URLStrict.decode(s), s) }
        // every single character outside the alphabet is refused, wherever it sits
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        for u in 0..<128 {
            let ch = Character(Unicode.Scalar(UInt8(u)))
            if alphabet.contains(ch) { continue }
            XCTAssertNil(Base64URLStrict.decode("AAAA" + String(ch)), "char \(u) after")
            XCTAssertNil(Base64URLStrict.decode(String(ch) + "AAA"), "char \(u) before")
            XCTAssertNil(Base64URLStrict.decode("AA" + String(ch) + "A"), "char \(u) inside")
        }
        // the first alphabet-adjacent bytes
        for s in ["@AAA", "[AAA", "`AAA", "{AAA", "/AAA", ":AAA", "+AAA", ",AAA", ".AAA"] { XCTAssertNil(Base64URLStrict.decode(s), s) }
        // canonical trailing bits: 'Zg' ok, 'Zh'..'Zv' (nonzero low bits) refused; 3-char tails likewise
        XCTAssertNotNil(Base64URLStrict.decode("Zg"))
        for c in "BCDEFGHIJKLMNOPRSTUVWXYZabcdefhijklmnopqrstuvxyz0123456789-_" { XCTAssertNil(Base64URLStrict.decode("Z" + String(c)), "Z\(c)") }
        for c in "AQgw" { XCTAssertNotNil(Base64URLStrict.decode("Z" + String(c)), "Z\(c)") }
        XCTAssertNotNil(Base64URLStrict.decode("Zm8"))
        for c in "BCDFGHJKLNOPRSTVWXZabdefhijlmnpqrtuvxyz1235679-_" { XCTAssertNil(Base64URLStrict.decode("Zm" + String(c)), "Zm\(c)") }
        for c in "AEIMQUYcgkosw048" { XCTAssertNotNil(Base64URLStrict.decode("Zm" + String(c)), "Zm\(c)") }
        XCTAssertTrue(Base64URLStrict.isValid("Zm9v", length: 3))
        XCTAssertFalse(Base64URLStrict.isValid("Zm9v", length: 4))
        XCTAssertFalse(Base64URLStrict.isValid("Zm9v", length: 2))
        XCTAssertFalse(Base64URLStrict.isValid("Zm9v", length: 0))
        XCTAssertFalse(Base64URLStrict.isValid("", length: 1))
        XCTAssertTrue(Base64URLStrict.isValid("", length: 0))
        XCTAssertEqual(Base64URLStrict.encodedLength(0), 0)
        XCTAssertEqual(Base64URLStrict.encodedLength(1), 2)
        XCTAssertEqual(Base64URLStrict.encodedLength(2), 3)
        XCTAssertEqual(Base64URLStrict.encodedLength(3), 4)
        XCTAssertEqual(Base64URLStrict.encodedLength(32), 43)
        XCTAssertEqual(Base64URLStrict.encodedLength(64), 86)
    }
}
