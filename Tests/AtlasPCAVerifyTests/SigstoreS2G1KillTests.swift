import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Kill tests for the Sigstore.swift helpers (mutation sheet swift-k05 group 1): time parsing, hostnames, the DER readers,
/// certificate predicates, RFC 3161 token framing, checkpoints and PEM. Each assertion names the mutated line.
final class S2G1SigstoreKillTests: XCTestCase {
    private func failMessage(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch let e as Sigstore.Fail { return e.m } catch { return "other: \(error)" }
    }

    private static func parsed(_ oid: String, _ value: [UInt8]) -> Sigstore.Parsed {
        let t = Sigstore.T(tag: 0x30, start: 0, body: 0, end: 0)
        return Sigstore.Parsed(der: [], tbsKids: [], extsWrapper: t, exts: [Sigstore.Ext(oid: oid, value: value, t: t)])
    }

    // ---------------------------------------------------------------- b64s (lines 55, 57)

    func testB64sRefusesEverythingButPaddedStandardBase64() throws {
        XCTAssertEqual(try Sigstore.b64s("QUJD"), [0x41, 0x42, 0x43])
        XCTAssertEqual(try Sigstore.b64s("QQ=="), [0x41])
        // line 55 &&->||: a length that is not a multiple of 4 with in-alphabet characters
        for s in ["AAA", "AA", "A", "QUJDQ"] { XCTAssertEqual(failMessage { _ = try Sigstore.b64s(s) }, "not base64", s) }
        // line 55 inner &&->||: a multiple-of-4 string with one out-of-alphabet character, one per gap in the alphabet
        for s in ["AA@A", "AA[A", "AA`A", "AA{A", "AA-A", "AA_A", "AA A", "AA\nA", "AA:A", "AA.A", "AA,A"] {
            XCTAssertEqual(failMessage { _ = try Sigstore.b64s(s) }, "not base64", s)
        }
        // line 57 pad <= 2 (->3): three padding characters
        XCTAssertEqual(failMessage { _ = try Sigstore.b64s("A===") }, "not base64")
        XCTAssertEqual(failMessage { _ = try Sigstore.b64s("AAAAA===") }, "not base64")
    }

    // ---------------------------------------------------------------- isoMs (lines 68-83)

    func testIsoMsOffsets() {
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00Z"), Int64(0))
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T01:00:00+01:00"), Int64(0), "line 73 + sign")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00-01:30"), Int64(5_400_000), "line 73 minus sign, oh * 60 + om")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00+00:30"), Int64(-1_800_000), "line 71 om = both digits")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00+23:59"), Int64(-86_340_000), "line 72 23 and 59 are accepted")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00-23:59"), Int64(86_340_000))
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00+24:00"), "line 72 oh <= 23")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00+00:60"), "line 72 om <= 59")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00*00:00"), "line 70 sign")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00+00:0X"), "line 70 both minute digits")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00+0X:00"), "line 70 hour digits")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00+00;00"), "line 70 colon")
        XCTAssertNil(Sigstore.isoMs("+00:0"), "line 68 a 5-byte string is not an offset")
    }

    func testIsoMsLength() {
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:0Z"), "line 76 at least 19 bytes before the Z")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00.Z"), "line 80 a bare point is a fraction")
    }

    func testIsoMsFraction() {
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00.5Z"), Int64(500), "one digit is tenths")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00.12Z"), Int64(120), "two digits are hundredths")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00.123Z"), Int64(123))
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00.1234Z"), Int64(123), "digits past the third are truncated")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00.123456789Z"), Int64(123), "nine fraction digits are the maximum")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00.1234567890Z"), "line 82 ten fraction digits are refused")
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00,5Z"), "the separator is a point")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:01.5+00:00"), Int64(1500))
    }

    // ---------------------------------------------------------------- hostname (lines 95-100)

    func testHostname() {
        XCTAssertEqual(Sigstore.hostname("http://a.com/p"), "a.com")
        XCTAssertEqual(Sigstore.hostname("http://a.com?x"), "a.com", "line 98 ?")
        XCTAssertEqual(Sigstore.hostname("http://a.com#x"), "a.com", "line 98 #")
        XCTAssertEqual(Sigstore.hostname("http://A.COM"), "a.com")
        XCTAssertEqual(Sigstore.hostname("http://exa\tmple.com/x"), "example.com", "line 95 tab")
        XCTAssertEqual(Sigstore.hostname("http://exa\nmple.com/x"), "example.com", "line 95 newline")
        XCTAssertEqual(Sigstore.hostname("http://exa\rmple.com/x"), "example.com", "line 95 carriage return")
        XCTAssertEqual(Sigstore.hostname("http://a.com\u{0}"), "a.com", "line 96 a trailing NUL is trimmed")
        XCTAssertEqual(Sigstore.hostname("http://user:pw@a.com:8080/x"), "a.com", "line 99 userinfo is dropped")
        XCTAssertEqual(Sigstore.hostname("http://[::1]:8080/"), "[::1]", "line 100 an IPv6 literal ends at the bracket")
        XCTAssertNil(Sigstore.hostname("http:///x"))
        XCTAssertNil(Sigstore.hostname("not a url"))
    }

    // ---------------------------------------------------------------- DER readers (lines 155-191)

    func testTlvLengthOctets() throws {
        let t4 = try Sigstore.tlv([0x30, 0x84, 0, 0, 0, 2, 0xAA, 0xBB], 0)
        XCTAssertEqual(t4, Sigstore.T(tag: 0x30, start: 0, body: 6, end: 8), "line 155 four length octets are the maximum")
        XCTAssertEqual(failMessage { _ = try Sigstore.tlv([0x30, 0x85, 0, 0, 0, 0, 0], 0) }, "DER length", "line 155 five length octets")
        let exact = try Sigstore.tlv([0x30, 0x81, 0x00], 0)
        XCTAssertEqual(exact, Sigstore.T(tag: 0x30, start: 0, body: 3, end: 3), "line 155 the length octets may end exactly at the limit")
        XCTAssertEqual(failMessage { _ = try Sigstore.tlv([0x30, 0x82, 0x00], 0) }, "DER length", "line 155 length octets past the limit")
        XCTAssertEqual(failMessage { _ = try Sigstore.tlv([0x30, 0x80, 0x00], 0) }, "DER length", "an indefinite length")
    }

    func testKidAtTheEnd() throws {
        let b: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x05]
        let t = try Sigstore.tlv(b, 0)
        XCTAssertEqual(try Sigstore.kid(b, t, 0).tag, 0x02)
        XCTAssertEqual(failMessage { _ = try Sigstore.kid(b, t, 1) }, "DER element missing", "line 171 i == count")
    }

    private func oid(_ body: [UInt8]) throws -> String {
        let b: [UInt8] = [0x06, UInt8(body.count)] + body
        return try Sigstore.oidText(b, try Sigstore.tlv(b, 0))
    }

    func testOidFirstArcSplit() throws {
        XCTAssertEqual(try oid([0x2b]), "1.3")
        XCTAssertEqual(try oid([0x28]), "1.0", "line 191 40 / 40 = 1")
        XCTAssertEqual(try oid([0x27]), "0.39", "line 191 39 / 40 = 0")
        XCTAssertEqual(try oid([0x78]), "2.40", "line 191 the first arc caps at 2")
        XCTAssertEqual(try oid([0x50]), "2.0")
    }

    func testOidArcEncoding() throws {
        XCTAssertEqual(try oid([0x2a, 0x81, 0x80, 0x01]), "1.2.16385", "line 184 a 0x80 continuation after a continuation byte")
        XCTAssertEqual(failMessage { _ = try self.oid([0x80, 0x01]) }, "OID arc is not minimally encoded")
        XCTAssertEqual(failMessage { _ = try self.oid([0x2a, 0x80, 0x01]) }, "OID arc is not minimally encoded", "line 184 0x80 after a finished arc")
        // line 184 i == body: the first content byte is 0x80 and the last length octet has its high bit set (a 128-byte content)
        let long: [UInt8] = [0x06, 0x81, 0x80, 0x80] + [UInt8](repeating: 0x01, count: 127)
        XCTAssertEqual(failMessage { _ = try Sigstore.oidText(long, try Sigstore.tlv(long, 0)) }, "OID arc is not minimally encoded")
    }

    func testOidArcSize() throws {
        // line 185 56->57: the value before the last byte is exactly 2^56
        let big: [UInt8] = [0x2a, 0x81] + [UInt8](repeating: 0x80, count: 8) + [0x01]
        XCTAssertEqual(failMessage { _ = try self.oid(big) }, "OID arc too large")
        // line 185 56->55: the value before the last byte is 2^55 (accepted); the arc is 2^62 + 1
        let ok: [UInt8] = [0x2a, 0xC0] + [UInt8](repeating: 0x80, count: 7) + [0x01]
        XCTAssertEqual(try oid(ok), "1.2.4611686018427387905")
    }

    // ---------------------------------------------------------------- parseCert (line 207)

    func testParseCertFraming() {
        XCTAssertEqual(failMessage { _ = try Sigstore.parseCert([0x30, 0x00, 0xff]) }, "certificate is not one SEQUENCE", "trailing byte")
        XCTAssertEqual(failMessage { _ = try Sigstore.parseCert([0x31, 0x00]) }, "certificate is not one SEQUENCE", "wrong tag")
    }

    // ---------------------------------------------------------------- sanDecodes / fulcioExt / basicConstraintsCa (lines 238-267)

    func testSanDecodesNameTags() {
        func san(_ tags: [UInt8]) -> Bool {
            let names = tags.flatMap { Sigstore.enc($0, []) }
            return Sigstore.sanDecodes(Self.parsed("2.5.29.17", Sigstore.enc(0x30, names)))
        }
        XCTAssertTrue(san([0x80]), "line 238 0x80 is a GeneralName")
        XCTAssertTrue(san([0x88]), "line 238 0x88 is a GeneralName")
        XCTAssertTrue(san([0xa0]), "line 238 0xa0 is a GeneralName")
        XCTAssertTrue(san([0xa8]), "line 238 0xa8 is a GeneralName")
        XCTAssertTrue(san([0x80, 0x82, 0xa3, 0xa8]))
        XCTAssertFalse(san([0x89]))
        XCTAssertFalse(san([0x90]), "line 238 between the two ranges")
        XCTAssertFalse(san([0xa9]))
        XCTAssertFalse(san([0x70]), "line 238 below the first range")
        XCTAssertFalse(san([0x80, 0x90]))
        XCTAssertTrue(Sigstore.sanDecodes(Self.parsed("2.5.29.15", [])), "no subjectAltName")
    }

    func testFulcioExtRawVersusDer() throws {
        let der: [UInt8] = [0x0c, 0x03, 0x61, 0x62, 0x63]
        let base = "1.3.6.1.4.1.57264.1."
        XCTAssertEqual(try Sigstore.fulcioExt(Self.parsed(base + "6", Array("abc".utf8)), 6), "abc", "line 243 n = 6 is raw")
        XCTAssertEqual(try Sigstore.fulcioExt(Self.parsed(base + "6", der), 6), "\u{0c}\u{03}abc", "line 243 n = 6 is not read as DER")
        XCTAssertEqual(try Sigstore.fulcioExt(Self.parsed(base + "7", der), 7), "abc", "line 243 n = 7 is a DER UTF8String")
        XCTAssertThrowsError(try Sigstore.fulcioExt(Self.parsed(base + "7", Array("abc".utf8)), 7), "line 243 n = 7 is not raw")
        XCTAssertNil(try Sigstore.fulcioExt(Self.parsed(base + "5", der), 6))
    }

    func testBasicConstraintsCa() {
        func bc(_ first: [UInt8]) -> Bool { Sigstore.basicConstraintsCa(Self.parsed("2.5.29.19", Sigstore.enc(0x30, first))) }
        XCTAssertTrue(bc(Sigstore.enc(0x01, [0xff])))
        XCTAssertTrue(bc(Sigstore.enc(0x01, [0x01])), "line 267 any non-zero octet is TRUE")
        XCTAssertFalse(bc(Sigstore.enc(0x01, [0x00])), "line 267 FALSE")
        XCTAssertFalse(bc(Sigstore.enc(0x02, [0x05])), "line 267 the first element must be a BOOLEAN")
        XCTAssertFalse(bc(Sigstore.enc(0x01, [0x01, 0x01])), "line 267 a BOOLEAN is one octet")
        XCTAssertFalse(Sigstore.basicConstraintsCa(Self.parsed("2.5.29.19", Sigstore.enc(0x30, []))))
    }

    // ---------------------------------------------------------------- certificate predicates (lines 261-297)

    func testUnparsableCertificateIsNeverACaNorInsideAnyWindow() {
        XCTAssertFalse(Sigstore.isCA(AttCert()), "line 261")
        XCTAssertFalse(Sigstore.inside(AttCert(), 0), "line 271")
    }

    func testKeyIdsMatch() {
        func match(_ akid: [UInt8], _ skid: [UInt8]) -> Bool {
            var c = AttCert()
            c.exts = [LenientExt(oid: "2.5.29.35", critical: false, value: akid)]
            var up = AttCert()
            up.exts = [LenientExt(oid: "2.5.29.14", critical: false, value: skid)]
            return Sigstore.keyIdsMatch(c, up)
        }
        let sk1: [UInt8] = [0x04, 0x01, 0x01], sk9: [UInt8] = [0x04, 0x01, 0x09]
        XCTAssertTrue(match([0x30, 0x03, 0x80, 0x01, 0x01], sk1))
        XCTAssertFalse(match([0x30, 0x03, 0x80, 0x01, 0x01], sk9))
        XCTAssertFalse(match([], sk9), "line 278 an authorityKeyIdentifier that does not decode")
        XCTAssertTrue(match([0x30, 0x00], sk9), "line 279 an empty AKID sequence names no key id")
        XCTAssertTrue(match([0x31, 0x03, 0x80, 0x01, 0x01], sk9), "line 279 a non-SEQUENCE AKID is not compared")
        XCTAssertFalse(match([0x30, 0x02, 0x80, 0x01], sk9), "line 280 an AKID member that overruns")
        XCTAssertTrue(match([0x30, 0x03, 0x81, 0x01, 0x01], sk9), "line 281 an AKID without a keyIdentifier")
        XCTAssertFalse(match([0x30, 0x03, 0x80, 0x01, 0x01], []), "line 282 a subjectKeyIdentifier that does not decode")
    }

    func testVerifyDerRefusesAKeyTypeItCannotVerify() {
        var k = CertKey()
        k.typ = "ed25519"
        XCTAssertFalse(Sigstore.verifyDer(k, .sha256, [1, 2, 3], [4, 5, 6]), "line 297")
        XCTAssertFalse(Sigstore.verifyDer(CertKey(), .sha256, [], []))
    }

    // ---------------------------------------------------------------- generalizedTime (line 364)

    private func gt(_ s: String) throws -> Int64 {
        let b = Array(s.utf8)
        return try Sigstore.generalizedTime(b, Sigstore.T(tag: 0x18, start: 0, body: 0, end: b.count))
    }

    func testGeneralizedTime() throws {
        XCTAssertEqual(try gt("19700101000000Z"), 0)
        XCTAssertEqual(try gt("19700101000000.5Z"), 500)
        // line 364 14->13: the fourteenth byte is not a digit (':' reads as 10 seconds, so the date itself would be valid)
        XCTAssertEqual(failMessage { _ = try self.gt("2020010100000:Z") }, "genTime malformed")
        XCTAssertEqual(failMessage { _ = try self.gt("19700101000000") }, "genTime malformed")
    }

    // ---------------------------------------------------------------- RFC 3161 token framing (lines 382-393)

    private static let signedDataOid: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]
    private static let tstInfoOid: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04]

    func testRfc3161StatusSequenceDetection() {
        let e = Sigstore.enc
        // line 382 3->2: a 2-byte first SEQUENCE is not a PKIStatusInfo
        let two = e(0x30, e(0x30, e(0x02, [])) + e(0x05, []))
        XCTAssertEqual(failMessage { _ = try Sigstore.verifyRfc3161(two, [], []) }, "not an OID")
        // line 382 - -> +: an empty first SEQUENCE
        let empty = e(0x30, e(0x30, []) + e(0x05, []))
        XCTAssertEqual(failMessage { _ = try Sigstore.verifyRfc3161(empty, [], []) }, "not an OID")
    }

    func testRfc3161ContentInfoNeedsTwoParts() {
        let e = Sigstore.enc
        // line 389 2->1: a ContentInfo with only a content type
        let one = e(0x30, e(0x06, Self.signedDataOid))
        XCTAssertEqual(failMessage { _ = try Sigstore.verifyRfc3161(one, [], []) }, "not CMS SignedData")
        // line 393 2->1: an encapContentInfo with only a content type
        let sd = e(0x30, e(0x02, [3]) + e(0x31, []) + e(0x30, e(0x06, Self.tstInfoOid)))
        let token = e(0x30, e(0x06, Self.signedDataOid) + e(0xa0, sd))
        XCTAssertEqual(failMessage { _ = try Sigstore.verifyRfc3161(token, [], []) }, "content is not TSTInfo")
    }

    // ---------------------------------------------------------------- decInt / pemDer (lines 462, 480)

    func testDecIntLengthBound() throws {
        XCTAssertEqual(try Sigstore.decInt(.string("9007199254740991")), 9_007_199_254_740_991)
        XCTAssertEqual(failMessage { _ = try Sigstore.decInt(.string("9007199254740992")) }, "integer out of range")
        // line 462 16->17: 17 digits are refused as not a decimal integer string (not as out of range)
        XCTAssertEqual(failMessage { _ = try Sigstore.decInt(.string("10000000000000000")) }, "not a decimal integer string")
        XCTAssertEqual(try Sigstore.decInt(.string("0")), 0)
        XCTAssertEqual(failMessage { _ = try Sigstore.decInt(.string("01")) }, "not a decimal integer string")
    }

    func testPemDerAlphabet() throws {
        let begin = "-----BEGIN CERTIFICATE-----\n", end = "-----END CERTIFICATE-----"
        XCTAssertEqual(try Sigstore.pemDer(begin + "QUJD\n" + end), [0x41, 0x42, 0x43])
        // line 480: a character outside the base64 alphabet is "not a PEM" ([]), not a base64 failure
        for bad in ["AA!A", "AA[A", "AA`A", "AA{A", "AA@A", "AA-A"] {
            XCTAssertEqual(try Sigstore.pemDer(begin + bad + "\n" + end), [], bad)
        }
    }

    // ---------------------------------------------------------------- verifyCheckpoint (lines 442, 450)

    private static let cpKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
    private static let cpKeyId: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
    private static let cpRoot = [UInt8](repeating: 7, count: 32)

    private static func cpLog() -> SigstoreRoots.Log {
        let k = try! Cert.keyOfSPKI(Array(cpKey.publicKey.derRepresentation))
        return SigstoreRoots.Log(keyId: cpKeyId, key: k, start: 0, end: Int64.max, v2Name: nil)
    }
    private static func cpHead(_ size: String) -> String { "origin\n\(size)\n\(Data(cpRoot).base64EncodedString())" }
    private static func cpSigB64(_ size: String) -> String {
        let body = Array((cpHead(size) + "\n").utf8)
        let sig = [UInt8](try! cpKey.signature(for: Data(body)).derRepresentation)
        return Data(Array(cpKeyId.prefix(4)) + sig).base64EncodedString()
    }
    private static func cpLine(_ name: String, _ size: String) -> String { "\u{2014} \(name) \(cpSigB64(size))" }
    private static let noSig = "no checkpoint signature by the pinned log key"

    func testCheckpointSignatureLines() throws {
        let log = Self.cpLog()
        let head = Self.cpHead("5")
        XCTAssertNil(try Sigstore.verifyCheckpoint(head + "\n\n" + Self.cpLine("log", "5") + "\n", log, 5, Self.cpRoot), "control: a good line verifies")
        // line 450 first ||: an empty origin name is skipped even with a good signature
        XCTAssertEqual(try Sigstore.verifyCheckpoint(head + "\n\n" + Self.cpLine("", "5") + "\n", log, 5, Self.cpRoot), Self.noSig)
        // line 450 second ||: a name with whitespace is skipped
        XCTAssertEqual(try Sigstore.verifyCheckpoint(head + "\n\n" + Self.cpLine("a\tb", "5") + "\n", log, 5, Self.cpRoot), Self.noSig)
        // line 450 third ||: a signature with characters outside base64 is skipped, not a failure
        let text = head + "\n\n\u{2014} n !!!!\n" + Self.cpLine("log", "5") + "\n"
        XCTAssertNil(try Sigstore.verifyCheckpoint(text, log, 5, Self.cpRoot))
    }

    func testCheckpointSizeText() throws {
        let log = Self.cpLog()
        let differs = "checkpoint size differs from the proof"
        // line 442: a size line that is not a digit string, even when it equals String(size)
        XCTAssertEqual(try Sigstore.verifyCheckpoint(Self.cpHead("-1") + "\n\n", log, -1, Self.cpRoot), differs)
        // line 442: a leading zero is refused even when it equals String(size)
        XCTAssertEqual(try Sigstore.verifyCheckpoint(Self.cpHead("0") + "\n\n", log, 0, Self.cpRoot), differs)
        XCTAssertEqual(try Sigstore.verifyCheckpoint(Self.cpHead("6") + "\n\n", log, 5, Self.cpRoot), differs)
        XCTAssertEqual(try Sigstore.verifyCheckpoint(Self.cpHead("5") + "\n\n", log, 5, Self.cpRoot), Self.noSig, "a matching size goes on to the signatures")
    }
}
