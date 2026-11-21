import XCTest
@testable import AtlasPCAVerify

/// The structure checks of the certificate reader (OpenSSL's d2i_X509 and c2i_ASN1_INTEGER) and its small DER helpers.
final class AttestCertK05ParseTests: XCTestCase {
    private typealias F = StrictChainForge

    private static let alg = F.seq(F.oid([0x2a, 0x03]))
    private static let bits: [UInt8] = [0x03, 0x01, 0x00]
    private static let utc = DERB.tlv(0x17, Array("250101000000Z".utf8))
    private static let gen = DERB.tlv(0x18, Array("20250101000000Z".utf8))
    private static let notTime = DERB.tlv(0x02, [0x01])
    private static let oid123 = F.oid([0x2a, 0x03])
    private static let value = DERB.tlv(0x04, [0x01])

    private func why(_ der: [UInt8]) -> String {
        do { _ = try Cert.parseDER(der); return "ok" } catch { return (error as? AttestError)?.message ?? "?" }
    }

    private func cert(times: [UInt8]? = nil, tail: [UInt8] = []) -> [UInt8] {
        let name = F.seq([])
        let validity = F.seq(times ?? (Self.utc + Self.utc))
        let tbs: [UInt8] = DERB.tlv(0x02, [0x01]) + Self.alg + name + validity + name + F.seq(Self.alg + Self.bits) + tail
        return F.seq(F.seq(tbs) + Self.alg + Self.bits)
    }

    private func withExt(_ parts: [UInt8]) -> [UInt8] { cert(tail: DERB.tlv(0xa3, F.seq(F.seq(parts)))) }

    func testADefaultCertificateHasNoMatchingSignatureAlgorithms() {
        XCTAssertFalse(AttCert().sigAlgsMatch)
    }

    func testEmptyTbsIsNotEnoughData() {
        XCTAssertEqual(why(F.seq(F.seq([]) + Self.alg + Self.bits)), "error:0680007B:asn1 encoding routines::not enough data")
    }

    func testValidityTimeTags() {
        XCTAssertEqual(why(cert(times: Self.utc + Self.utc)), "ok")
        XCTAssertEqual(why(cert(times: Self.gen + Self.gen)), "ok")
        XCTAssertEqual(why(cert(times: Self.utc + Self.gen)), "ok")
        XCTAssertEqual(why(cert(times: Self.notTime + Self.gen)), OSSL.nested)
        XCTAssertEqual(why(cert(times: Self.notTime + Self.utc)), OSSL.nested)
        XCTAssertEqual(why(cert(times: Self.utc + Self.notTime)), OSSL.nested)
        XCTAssertEqual(why(cert(times: Self.utc)), OSSL.nested)
    }

    func testOptionalFieldsAfterTheKey() {
        let u1 = DERB.tlv(0x81, [0x00]), u2 = DERB.tlv(0x82, [0x00])
        let exts = DERB.tlv(0xa3, F.seq(F.seq(Self.oid123 + Self.value)))
        XCTAssertEqual(why(cert()), "ok")
        XCTAssertEqual(why(cert(tail: u1 + u2 + exts)), "ok")
        XCTAssertEqual(why(cert(tail: u2)), "ok")
        XCTAssertEqual(why(cert(tail: u2 + u1)), OSSL.nested)
        XCTAssertEqual(why(cert(tail: DERB.tlv(0x02, [0x01]))), OSSL.nested)
        XCTAssertEqual(why(cert(tail: exts + exts)), OSSL.nested)
    }

    func testExtensionShape() {
        let o = Self.oid123, v = Self.value
        XCTAssertEqual(why(withExt(o + v + v + v)), OSSL.nested)      // four parts
        XCTAssertEqual(why(withExt(o)), OSSL.nested)                  // one part
        XCTAssertEqual(why(withExt([])), OSSL.nested)                 // none
        XCTAssertEqual(why(withExt(F.oid([0x80, 0x01]) + v)), OSSL.nested)
        XCTAssertEqual(why(withExt(o + DERB.tlv(0x0c, [0x01]))), OSSL.wrongTag)
        XCTAssertEqual(why(withExt(o + [0x01, 0x01, 0xff] + DERB.tlv(0x0c, [0x01]))), OSSL.wrongTag)
        XCTAssertEqual(why(withExt(o + DERB.tlv(0x02, [0x01]) + v)), OSSL.nested)
        XCTAssertEqual(why(withExt(o + [0x01, 0x02, 0xff, 0xff] + v)), OSSL.nested)
        XCTAssertEqual(why(withExt(o + v)), "ok")
    }

    func testExtensionCriticalFlagAndValue() throws {
        let plain = try Cert.parseDER(withExt(Self.oid123 + Self.value))
        XCTAssertEqual(plain.exts.count, 1)
        XCTAssertEqual(plain.exts.first?.critical, false)
        XCTAssertEqual(plain.exts.first?.oid, "1.2.3")
        XCTAssertEqual(plain.exts.first?.value, [0x01])
        // the value byte differs from the flag so that reading the wrong element shows
        let rows: [(UInt8, Bool, UInt8)] = [(0x00, false, 0x01), (0x01, true, 0x00), (0xff, true, 0x00)]
        for (flag, want, valueByte) in rows {
            let c = try Cert.parseDER(withExt(Self.oid123 + DERB.tlv(0x01, [flag]) + DERB.tlv(0x04, [valueByte])))
            XCTAssertEqual(c.exts.first?.critical, want, "flag \(flag)")
            XCTAssertEqual(c.exts.first?.value, [valueByte], "flag \(flag)")
        }
    }

    func testLengthHeader() {
        let rows: [(Int, [UInt8])] = [
            (0, [0x30, 0x00]), (0x7f, [0x30, 0x7f]), (0x80, [0x30, 0x81, 0x80]), (0xff, [0x30, 0x81, 0xff]),
            (0x100, [0x30, 0x82, 0x01, 0x00]), (0x1234, [0x30, 0x82, 0x12, 0x34]), (0xffff, [0x30, 0x82, 0xff, 0xff]),
            (0x10000, [0x30, 0x83, 0x01, 0x00, 0x00]), (0x123456, [0x30, 0x83, 0x12, 0x34, 0x56]), (0xffffff, [0x30, 0x83, 0xff, 0xff, 0xff]),
            (0x1000000, [0x30, 0x84, 0x01, 0x00, 0x00, 0x00]), (0x12345678, [0x30, 0x84, 0x12, 0x34, 0x56, 0x78]), (0x7fffffff, [0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]),
        ]
        for (n, want) in rows { XCTAssertEqual(Cert.lengthHeader(0x30, n), want, "\(n)") }
    }

    /// A trailing byte keeps an empty element's start index inside the buffer.
    private func elem(_ tag: UInt8, _ c: [UInt8]) -> (b: [UInt8], e: CertElem) {
        ([tag, UInt8(c.count)] + c + [0x00], CertElem(tag: tag, hdr: 0, start: 2, end: 2 + c.count))
    }

    func testPositiveInteger() {
        func read(_ tag: UInt8, _ c: [UInt8]) -> [UInt8]? {
            let x = elem(tag, c)
            return Cert.positiveInteger(x.b, x.e)
        }
        XCTAssertNil(read(0x04, [0x01]))
        let accepted: [([UInt8], [UInt8])] = [
            ([0x01], [0x01]), ([0x7f], [0x7f]), ([0x00, 0x80], [0x80]), ([0x00, 0xff, 0x01], [0xff, 0x01]),
            ([0x01, 0x00], [0x01, 0x00]), ([0x01, 0xff], [0x01, 0xff]), ([0x7f, 0x80], [0x7f, 0x80]),
        ]
        for (c, want) in accepted { XCTAssertEqual(read(0x02, c), want, "\(c)") }
        let refused: [[UInt8]] = [[0x00, 0x01], [0x00, 0x7f], [0x00, 0x00], [0x00], [0x80], [0xff], [0xff, 0x80], [0xff, 0x01], []]
        for c in refused { XCTAssertNil(read(0x02, c), "\(c)") }
    }

    func testSmallInt() {
        func read(_ tag: UInt8, _ c: [UInt8]) -> Int? {
            let x = elem(tag, c)
            return Cert.smallInt(x.b, x.e)
        }
        let accepted: [([UInt8], Int)] = [
            ([0x00], 0), ([0x05], 5), ([0x7f], 127), ([0x00, 0x80], 128), ([0x01, 0x02], 258), ([0x01, 0x00, 0x00], 65536),
            ([0x7f, 0xff, 0xff], 0x7fffff), ([0x00, 0xff, 0xff, 0xff], 0xffffff),
        ]
        for (c, want) in accepted { XCTAssertEqual(read(0x02, c), want, "\(c)") }
        // c2i_ASN1_INTEGER refuses empty content and illegal padding; negative and over three octets are out of range here
        let refused: [[UInt8]] = [[], [0x00, 0x00], [0x00, 0x05], [0x80], [0xff], [0x01, 0x00, 0x00, 0x00], [0x00, 0x01, 0x00, 0x00, 0x00]]
        for c in refused { XCTAssertNil(read(0x02, c), "\(c)") }
        XCTAssertNil(read(0x04, [0x05]))
    }

    func testKeyOfSpkiBitString() throws {
        let rsaAlg = F.seq(F.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) + [0x05, 0x00])
        let edAlg = F.seq(F.oid([0x2b, 0x65, 0x70]))
        func keyWhy(_ spki: [UInt8]) -> String {
            do { _ = try Cert.keyOfSPKI(spki); return "ok" } catch { return (error as? AttestError)?.message ?? "?" }
        }
        let ed = [UInt8](repeating: 0x07, count: 32)
        XCTAssertEqual(keyWhy(F.seq(edAlg + DERB.tlv(0x04, [0x00] + ed))), OSSL.wrongTag)
        XCTAssertEqual(keyWhy(F.seq(rsaAlg + DERB.tlv(0x03, []))), OSSL.wrongTag)
        XCTAssertEqual(keyWhy(F.seq(rsaAlg + DERB.tlv(0x03, [0x00]))), OSSL.unsupported)
        let k = try Cert.keyOfSPKI(F.seq(edAlg + DERB.tlv(0x03, [0x00] + ed)))
        XCTAssertEqual(k.typ, "ed25519")
        XCTAssertEqual(k.ed, ed)
    }

    func testPemDecodeFirstIgnoresWhitespaceInTheBody() {
        let text = "-----BEGIN PUBLIC KEY-----\nQU JD\tRE\r\nVG\n-----END PUBLIC KEY-----\n"
        XCTAssertEqual(Cert.pemDecodeFirst(text), Array("ABCDEF".utf8))
        XCTAssertEqual(Cert.pemDecodeFirst("-----BEGIN X-----QUJD-----END X-----"), Array("ABC".utf8))
        XCTAssertNil(Cert.pemDecodeFirst("-----BEGIN X-----QU!D-----END X-----"))
        XCTAssertNil(Cert.pemDecodeFirst("QUJD"))
    }
}
