import XCTest
@testable import AtlasPCAVerify

/// The strict X.509 reader's DER pieces (the OpenSSL d2i_X509 checks the reference relies on through node:crypto): element
/// bounds, OBJECT IDENTIFIER content, AlgorithmIdentifier arity, BIT STRING unused bits, and an optional [0] version.
final class AttestCertKill2Tests: XCTestCase {
    private func why(_ f: () throws -> Void) -> String {
        do { try f(); return "ok" } catch { return (error as? AttestError)?.message ?? "?" }
    }
    private func tlv(_ t: UInt8, _ c: [UInt8]) -> [UInt8] { [t, UInt8(c.count)] + c }

    func testReadElemAtTheLimitIsNotEnoughData() {
        XCTAssertEqual(why { _ = try Cert.readElem([0x30, 0x00], 2, 2) }, "error:0680007B:asn1 encoding routines::not enough data")
        XCTAssertEqual(why { _ = try Cert.readElem([0x30, 0x00], 0, 2, 0x30) }, "ok")
    }

    func testValidOID() {
        func oid(_ content: [UInt8], trailing: [UInt8] = []) -> Bool {
            Cert.validOID([0x06, UInt8(content.count)] + content + trailing, CertElem(tag: 0x06, hdr: 0, start: 2, end: 2 + content.count))
        }
        XCTAssertTrue(oid([0x2a]))
        XCTAssertTrue(oid([0x81, 0x01]))
        XCTAssertTrue(oid([0x81, 0x80, 0x01]))           // 0x80 inside an arc
        XCTAssertFalse(oid([]))                            // empty content
        XCTAssertFalse(oid([0x81], trailing: [0x00]))      // dangling continuation (the next element's byte is not read)
        XCTAssertFalse(oid([0x80, 0x01]))                  // first arc starts with 0x80
        XCTAssertFalse(oid([0x01, 0x80, 0x01]))            // a later arc starts with 0x80
        XCTAssertFalse(Cert.validOID([0x04, 0x01, 0x2a], CertElem(tag: 0x04, hdr: 0, start: 2, end: 3)))
    }

    func testAlgIDArity() {
        func alg(_ kids: [UInt8]) -> String {
            let b = tlv(0x30, kids)
            do { return try Cert.algID(b, try Cert.readElem(b, 0, b.count, 0x30)).oid } catch { return (error as? AttestError)?.message ?? "?" }
        }
        let o: [UInt8] = [0x06, 0x03, 0x2a, 0x86, 0x48] // 1.2.840
        XCTAssertEqual(alg(o), "1.2.840")
        XCTAssertEqual(alg(o + [0x05, 0x00]), "1.2.840")
        XCTAssertEqual(alg(o + [0x05, 0x00, 0x05, 0x00]), OSSL.nested)
        XCTAssertEqual(alg([]), OSSL.nested)
        XCTAssertEqual(alg([0x06, 0x01, 0x80]), OSSL.nested) // an invalid OID is refused before its dotted conversion
    }

    func testBitStringUnusedBits() {
        func bits(_ b: [UInt8], end: Int? = nil, tag: UInt8 = 0x03) -> String {
            why { try Cert.checkBitString(b, CertElem(tag: tag, hdr: 0, start: 2, end: end ?? b.count)) }
        }
        XCTAssertEqual(bits([0x03, 0x01, 0x00]), "ok") // the empty bit string
        XCTAssertEqual(bits([0x03, 0x02, 0x07, 0x80]), "ok")
        XCTAssertEqual(bits([0x03, 0x02, 0x08, 0x00]), OSSL.bits)
        XCTAssertEqual(bits([0x03, 0x02, 0xff, 0x00]), OSSL.bits)
        XCTAssertEqual(bits([0x03, 0x00, 0x05], end: 2), OSSL.wrongTag) // no unused-bits octet: the following byte is not read
        XCTAssertEqual(bits([0x03, 0x00, 0x09], end: 2), OSSL.wrongTag)
        XCTAssertEqual(bits([0x04, 0x01, 0x00], tag: 0x04), OSSL.wrongTag)
    }

    func testVersionIsOptional() {
        let algSeq = tlv(0x30, [0x06, 0x03, 0x2a, 0x86, 0x48])
        let name = tlv(0x30, [])
        let time = tlv(0x17, Array("250101000000Z".utf8))
        let body = tlv(0x02, [0x01]) + algSeq + name + tlv(0x30, time + time) + name + tlv(0x30, algSeq + [0x03, 0x01, 0x00])
        func cert(_ tbs: [UInt8]) -> [UInt8] { tlv(0x30, tlv(0x30, tbs) + algSeq + [0x03, 0x01, 0x00]) }
        XCTAssertEqual(why { _ = try Cert.parseDER(cert(body)) }, "ok")                                   // v1: no [0] version
        XCTAssertEqual(why { _ = try Cert.parseDER(cert(tlv(0xa0, tlv(0x02, [0x02])) + body)) }, "ok")   // v3
        XCTAssertEqual(try Cert.parseDER(cert(body)).serial, [0x01])
    }
}
