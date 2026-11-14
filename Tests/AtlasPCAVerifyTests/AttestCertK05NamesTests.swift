import XCTest
@testable import AtlasPCAVerify

/// Certificate name rendering (OpenSSL's RFC 2253 escapes, strict string types) and the lenient AIA / EKU readers (attest-nvidia-ocsp.ts).
final class AttestCertK05NamesTests: XCTestCase {
    private typealias F = StrictChainForge

    func testEscapeDNValue() {
        let rows: [(String, String)] = [
            ("plain", "plain"), ("a b", "a b"), ("a#", "a#"), ("a#b", "a#b"), ("\u{e9}", "\u{e9}"),
            ("a,b", "a\\,b"), ("a+b", "a\\+b"), ("a\"b", "a\\\"b"), ("a\\b", "a\\\\b"), ("a<b", "a\\<b"), ("a>b", "a\\>b"), ("a;b", "a\\;b"),
            (" a", "\\ a"), ("#a", "\\#a"), ("a ", "a\\ "), (" ", "\\ "), (" a ", "\\ a\\ "),
            ("a\u{01}b", "a\\01b"), ("\u{1f}", "\\1F"), ("\u{7f}", "\\7F"),
        ]
        for (raw, want) in rows { XCTAssertEqual(Cert.escapeDNValue(raw), want, raw) }
    }

    func testPrintableStringAlphabet() {
        let allowed = Set(Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?*&".utf8))
        for n in 0...255 {
            let b = UInt8(n)
            XCTAssertEqual(Cert.nameString(0x13, [b]) != nil, allowed.contains(b), "byte \(n)")
        }
        XCTAssertEqual(Cert.nameString(0x13, Array("A b".utf8)), "A b")
    }

    func testIA5StringAlphabet() {
        for n in 0...255 { XCTAssertEqual(Cert.nameString(0x16, [UInt8(n)]) != nil, n < 0x80, "byte \(n)") }
    }

    func testNumericStringAlphabet() {
        let allowed = Set(Array("0123456789 ".utf8))
        for n in 0...255 {
            let b = UInt8(n)
            XCTAssertEqual(Cert.nameString(0x12, [b]) != nil, allowed.contains(b), "byte \(n)")
        }
        XCTAssertEqual(Cert.nameString(0x12, Array("12 9".utf8)), "12 9")
    }

    func testBMPString() {
        XCTAssertEqual(Cert.nameString(0x1e, []), "")
        XCTAssertEqual(Cert.nameString(0x1e, [0x00, 0x41]), "A")
        XCTAssertEqual(Cert.nameString(0x1e, [0x26, 0x03, 0x00, 0x41]), "\u{2603}A")
        XCTAssertEqual(Cert.nameString(0x1e, [0x00, 0x41, 0x26, 0x03, 0x00, 0x42, 0x01, 0x23]), "A\u{2603}B\u{123}")
        XCTAssertEqual(Cert.nameString(0x1e, [0xd8, 0x3d, 0xde, 0x00]), "\u{1F600}") // a surrogate pair
        XCTAssertNil(Cert.nameString(0x1e, [0x00]))
        XCTAssertNil(Cert.nameString(0x1e, [0x00, 0x41, 0x00]))
    }

    func testNameTextReadsABMPString() {
        let raw = F.seq(DERB.tlv(0x31, F.seq(F.oid(F.OID_CN) + DERB.tlv(0x1e, [0x26, 0x03]))))
        XCTAssertEqual(Cert.nameText(raw), "CN=\u{2603}")
    }

    private static let AIA = "1.3.6.1.5.5.7.1.1"
    private static let AD_OCSP: [UInt8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]
    private static let AD_CA_ISSUERS: [UInt8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]

    private func withExt(_ oid: String, _ value: [UInt8]) -> AttCert {
        var c = AttCert()
        c.exts = [LenientExt(oid: oid, critical: false, value: value)]
        return c
    }

    private func desc(_ method: [UInt8], _ tag: UInt8, _ text: String) -> [UInt8] {
        F.seq(F.oid(method) + DERB.tlv(tag, Array(text.utf8)))
    }

    func testOcspServers() {
        XCTAssertEqual(Cert.ocspServers(AttCert()), [])
        XCTAssertEqual(Cert.ocspServers(withExt(Self.AIA, [0x04, 0x00])), [])
        XCTAssertEqual(Cert.ocspServers(withExt(Self.AIA, F.seq(desc(Self.AD_OCSP, 0x86, "http://o/")))), ["http://o/"])
        var mixed: [UInt8] = desc(Self.AD_CA_ISSUERS, 0x86, "http://ca/")   // not the OCSP method
        mixed += desc(Self.AD_OCSP, 0x86, "http://a/")
        mixed += desc(Self.AD_OCSP, 0x82, "dns.example")                    // not a URI
        let uriA: [UInt8] = DERB.tlv(0x86, [0x41])
        mixed += F.seq(F.oid(Self.AD_OCSP) + uriA + uriA)                   // three parts
        mixed += F.seq(F.oid(Self.AD_OCSP))                                 // one part
        mixed += F.seq(DERB.tlv(0x0c, Self.AD_OCSP) + uriA)                 // the method is not an OID
        mixed += desc(Self.AD_OCSP, 0x86, "http://b/")
        XCTAssertEqual(Cert.ocspServers(withExt(Self.AIA, F.seq(mixed))), ["http://a/", "http://b/"])
    }

    func testHasOCSPSigningEKU() {
        let EKU = "2.5.29.37"
        let signing = F.oid([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09])
        XCTAssertFalse(Cert.hasOCSPSigningEKU(AttCert()))
        XCTAssertFalse(Cert.hasOCSPSigningEKU(withExt(EKU, [0x04, 0x00])))
        XCTAssertFalse(Cert.hasOCSPSigningEKU(withExt(EKU, F.seq([]))))
        XCTAssertFalse(Cert.hasOCSPSigningEKU(withExt(EKU, F.seq(F.oid(F.OID_SERVER_AUTH)))))
        XCTAssertTrue(Cert.hasOCSPSigningEKU(withExt(EKU, F.seq(signing))))
        XCTAssertTrue(Cert.hasOCSPSigningEKU(withExt(EKU, F.seq(F.oid(F.OID_SERVER_AUTH) + signing))))
    }
}
