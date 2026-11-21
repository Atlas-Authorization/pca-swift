import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// The freshness, CertID, responder and time rules of an OCSP response (packages/pca/src/attest-nvidia-ocsp.ts). Where the reference refuses through the
/// pkijs schema its text is the library's, so those rows pin the shared prefix of attest-nvidia-ocsp.ts:209 only.
final class AttestNvidiaOcspK05Tests: XCTestCase {
    typealias F = StrictChainForge
    typealias S = AttestOcspStrictTests

    static let T0 = "20270115070000Z"
    static let REJECTED = "OCSP response rejected: "
    static let ISSUER_BAD_SIG = "OCSP response signature does not verify under the issuer key"
    static let NO_MATCH = "no SingleResponse matches the certificate (serial / issuer hashes differ)"
    static let NO_RESPONDER = "no embedded responder certificate verifies the response"
    static let OID_ECDSA_SHA256: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
    static let OID_ECDSA_SHA512: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]

    static func ms(_ text: String) -> Int64 { OCSP.timeMs(Array(text.utf8), false)! }

    static func sign(_ tbs: [UInt8], _ k: F.Key, _ h: AHash = .sha384) -> [UInt8] {
        switch h {
        case .sha256: return Array(try! k.signature(for: SHA256.hash(data: Data(tbs))).derRepresentation)
        case .sha512: return Array(try! k.signature(for: SHA512.hash(data: Data(tbs))).derRepresentation)
        default: return Array(try! k.signature(for: Data(tbs)).derRepresentation)
        }
    }

    static func certID(_ issuer: AttCert, serial: UInt8 = 5, name: [UInt8]? = nil, key: [UInt8]? = nil, nameTag: UInt8 = 0x04, keyTag: UInt8 = 0x04) -> [UInt8] {
        let alg: [UInt8] = F.seq(F.oid(S.OID_SHA256) + [0x05, 0x00])
        let nameHash: [UInt8] = name ?? ACrypto.sha256(issuer.rawSubject)
        let keyHash: [UInt8] = key ?? ACrypto.sha256(try! OCSP.spkiKeyBits(issuer))
        let fields: [UInt8] = DERB.tlv(nameTag, nameHash) + DERB.tlv(keyTag, keyHash) + DERB.tlv(0x02, [serial])
        return F.seq(alg + fields)
    }

    static func single(_ id: [UInt8], status: [UInt8] = [0x80, 0x00], this: String = T0, next: String? = nil) -> [UInt8] {
        var tail: [UInt8] = []
        if let n = next { tail = DERB.tlv(0xa0, S.gt(n)) }
        return F.seq(id + status + S.gt(this) + tail)
    }

    static func tbs(_ singles: [[UInt8]], rid: [UInt8] = DERB.tlv(0xa1, F.name("root")), produced: [UInt8] = S.gt(T0), version: [UInt8] = [], exts: [UInt8] = [], responsesTag: UInt8 = 0x30) -> [UInt8] {
        let responses: [UInt8] = DERB.tlv(responsesTag, singles.flatMap { $0 })
        return F.seq(version + rid + produced + responses + exts)
    }

    /// An OCSPResponse around the bytes of a BasicOCSPResponse.
    static func wrap(_ basic: [UInt8]) -> [UInt8] {
        F.seq(DERB.tlv(0x0a, [0x00]) + DERB.tlv(0xa0, F.seq(F.oid(S.OID_BASIC) + DERB.tlv(0x04, basic))))
    }

    static func signed(_ tbsBytes: [UInt8], signer: F.Key = F.rootKey, oid: [UInt8] = F.OID_ECDSA_SHA384, hash: AHash = .sha384, certs: [UInt8] = []) -> [UInt8] {
        let bits: [UInt8] = [0x00] + sign(tbsBytes, signer, hash)
        return wrap(F.seq(tbsBytes + F.seq(F.oid(oid)) + DERB.tlv(0x03, bits) + certs))
    }

    lazy var root = AttestOcspStrictTests.root()
    lazy var leaf = AttestOcspStrictTests.leaf

    func ask(_ der: [UInt8], now: Int64 = F.NOW) -> OcspResult { OCSP.verifyResponse(der, leaf, root, [leaf, root], now) }

    func id() -> [UInt8] { Self.certID(root) }

    func good(_ r: OcspResult, _ note: String = "", file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(r.ok, "\(note): \(r.reason)", file: file, line: line)
        XCTAssertEqual(r.status, "good", note, file: file, line: line)
        XCTAssertEqual(r.reason, "", note, file: file, line: line)
    }

    func rejected(_ r: OcspResult, _ note: String = "", file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(r.ok, note, file: file, line: line)
        XCTAssertTrue(r.reason.hasPrefix(Self.REJECTED), "\(note): \(r.reason)", file: file, line: line)
    }

    func message(_ f: () throws -> Void) -> String {
        do {
            try f()
            return ""
        } catch {
            return Nvidia.msg(error)
        }
    }

    // ---- tables ----

    /// attest-nvidia-ocsp.ts:43-55
    func testTables() {
        XCTAssertEqual(OCSP.DEFAULT_MAX_MS, 604_800_000)
        let rows: [(String, AHash, Bool)] = [
            ("1.2.840.10045.4.3.2", .sha256, true), ("1.2.840.10045.4.3.3", .sha384, true), ("1.2.840.10045.4.3.4", .sha512, true),
            ("1.2.840.113549.1.1.11", .sha256, false), ("1.2.840.113549.1.1.12", .sha384, false), ("1.2.840.113549.1.1.13", .sha512, false),
        ]
        XCTAssertEqual(OCSP.SIG_ALGS.count, rows.count)
        for (oid, h, ec) in rows {
            XCTAssertEqual(OCSP.SIG_ALGS[oid]?.ec, ec, oid)
            XCTAssertTrue(OCSP.SIG_ALGS[oid]?.hash == h, oid)
        }
    }

    func testEcdsaHashesAreAccepted() {
        good(ask(Self.signed(Self.tbs([Self.single(id())]), oid: Self.OID_ECDSA_SHA256, hash: .sha256)), "sha256")
        good(ask(Self.signed(Self.tbs([Self.single(id())]))), "sha384")
        good(ask(Self.signed(Self.tbs([Self.single(id())]), oid: Self.OID_ECDSA_SHA512, hash: .sha512)), "sha512")
    }

    // ---- times ----

    func t(_ s: String, utc: Bool = false) -> Int64? { OCSP.timeMs(Array(s.utf8), utc) }

    func testGeneralizedTimeValues() {
        XCTAssertEqual(t("20270115171819Z"), DER.epochMs(2027, 1, 15, 17, 18, 19))
        let base = DER.epochMs(2027, 1, 15, 17, 18, 19)!
        let fractions: [(String, Int64)] = [("5", 500), ("125", 125), ("05", 50), ("9", 900), ("999", 999), ("123", 123), ("001", 1)]
        for (f, want) in fractions { XCTAssertEqual(t("20270115171819." + f + "Z"), base + want, f) }
        for bad in ["20270115171819.Z", "20270115171819.50Z", "20270115171819X", "20270115171819Zx", "2a270115171819Z", "20271315000000Z", "2027011517181Z"] {
            XCTAssertNil(t(bad), bad)
        }
    }

    func testUTCTimeValues() {
        XCTAssertEqual(t("270115171819Z", utc: true), DER.epochMs(2027, 1, 15, 17, 18, 19))
        XCTAssertEqual(t("490101000000Z", utc: true), DER.epochMs(2049, 1, 1, 0, 0, 0))
        XCTAssertEqual(t("500101000000Z", utc: true), DER.epochMs(1950, 1, 1, 0, 0, 0))
        XCTAssertEqual(t("990101000000Z", utc: true), DER.epochMs(1999, 1, 1, 0, 0, 0))
        XCTAssertEqual(t("000101000000Z", utc: true), DER.epochMs(2000, 1, 1, 0, 0, 0))
        XCTAssertNil(t("20270115171819Z", utc: true))
        XCTAssertNil(t("271315000000Z", utc: true))
    }

    func wellFormed(_ der: [UInt8]) -> Bool { OCSP.timesWellFormed(der, try! OCSP.readNode(der, 0, der.count)) }

    /// attest-nvidia-ocsp.ts:107-116: every time of the tree, at any depth; anything else is not looked at.
    func testTimesWellFormed() {
        let goodUTC = DERB.tlv(0x17, Array("270115070000Z".utf8)), badUTC = DERB.tlv(0x17, Array("271315000000Z".utf8))
        let goodGT = S.gt(Self.T0), badGT = S.gt("20271315000000Z")
        XCTAssertTrue(wellFormed(goodGT))
        XCTAssertTrue(wellFormed(goodUTC))
        XCTAssertFalse(wellFormed(badGT))
        XCTAssertFalse(wellFormed(badUTC))
        XCTAssertTrue(wellFormed(F.seq(goodGT + goodUTC)))
        XCTAssertFalse(wellFormed(F.seq(goodGT + badUTC)))
        XCTAssertFalse(wellFormed(F.seq(F.seq(badGT))))
        XCTAssertFalse(wellFormed(DERB.tlv(0xa0, badGT)))
        XCTAssertTrue(wellFormed(DERB.tlv(0x04, [0x04, 0x05])), "a primitive's content is not parsed")
        XCTAssertFalse(wellFormed([0x30, 0x02, 0x04, 0x05]), "a constructed node that does not parse")
    }

    func testAMalformedTimeAnywhereRefusesTheResponse() {
        let want = "response carries a malformed (out-of-range) ASN.1 time"
        XCTAssertEqual(ask(Self.signed(Self.tbs([Self.single(id())], produced: S.gt("20271315000000Z")))).reason, want)
        XCTAssertEqual(ask(Self.signed(Self.tbs([Self.single(id(), this: "20270132000000Z")]))).reason, want)
        XCTAssertEqual(ask(Self.signed(Self.tbs([Self.single(id())], exts: DERB.tlv(0xa1, F.seq(DERB.tlv(0x17, Array("271315000000Z".utf8))))))).reason, want)
    }

    // ---- small helpers ----

    /// attest-nvidia-ocsp.ts:120-124
    func testStripLeadingZeros() {
        let rows: [([UInt8], [UInt8])] = [
            ([5, 6], [5, 6]), ([0, 5], [5]), ([0, 0, 5], [5]), ([1, 0], [1, 0]), ([0x80], [0x80]), ([0, 0], [0]), ([0, 0, 0], [0]), ([0], [0]), ([], []),
        ]
        for (input, want) in rows { XCTAssertEqual(OCSP.stripLeading0(input), want, "\(input)") }
    }

    func cert(spki: [UInt8]) -> AttCert {
        var c = AttCert()
        c.rawSPKI = spki
        return c
    }

    func testSpkiKeyBits() throws {
        let alg = F.seq(F.oid(F.OID_EC))
        XCTAssertEqual(try OCSP.spkiKeyBits(cert(spki: F.seq(alg + DERB.tlv(0x03, [0, 1, 2])))), [1, 2])
        XCTAssertEqual(try OCSP.spkiKeyBits(cert(spki: F.seq(alg + DERB.tlv(0x03, [0])))), [])
        let want = "malformed SubjectPublicKeyInfo"
        XCTAssertEqual(message { _ = try OCSP.spkiKeyBits(self.cert(spki: F.seq(alg + DERB.tlv(0x03, [])))) }, want)
        XCTAssertEqual(message { _ = try OCSP.spkiKeyBits(self.cert(spki: F.seq(alg + DERB.tlv(0x03, [0, 1]) + DERB.tlv(0x05, [])))) }, want)
        XCTAssertEqual(message { _ = try OCSP.spkiKeyBits(self.cert(spki: F.seq(alg))) }, want)
    }

    /// attest-nvidia-ocsp.ts:191-202
    func testSigOK() throws {
        let sha384EC = "1.2.840.10045.4.3.3", sha256RSA = "1.2.840.113549.1.1.11"
        let msg = Array("message".utf8), sig = Self.sign(msg, F.rootKey)
        let ec = try Cert.keyOf(root)
        XCTAssertTrue(OCSP.sigOK(sha384EC, msg, sig, ec))
        XCTAssertFalse(OCSP.sigOK(sha384EC, Array("other".utf8), sig, ec))
        XCTAssertFalse(OCSP.sigOK("1.2.3.4", msg, sig, ec), "an unknown algorithm")
        XCTAssertFalse(OCSP.sigOK(sha256RSA, msg, sig, ec), "an RSA algorithm under an EC key")
        var rsa = CertKey()
        rsa.typ = "rsa"
        rsa.rsaN = AttestFailClosedTests.h(AttestFailClosedTests.N)
        rsa.rsaE = [0x01, 0x00, 0x01]
        let pkcs1 = AttestFailClosedTests.h(AttestFailClosedTests.PKCS1)
        XCTAssertTrue(OCSP.sigOK(sha256RSA, AttestFailClosedTests.MSG, pkcs1, rsa))
        XCTAssertFalse(OCSP.sigOK(sha256RSA, msg, pkcs1, rsa))
        XCTAssertFalse(OCSP.sigOK(sha384EC, AttestFailClosedTests.MSG, pkcs1, rsa), "an EC algorithm under an RSA key")
    }

    // ---- structure ----

    /// attest-nvidia-ocsp.ts:225
    func testResponseBytes() {
        XCTAssertEqual(ask(F.seq(DERB.tlv(0x0a, [0x00]))).reason, "successful response carries no responseBytes")
        let tbs = Self.tbs([Self.single(id())])
        let bits: [UInt8] = [0x00] + Self.sign(tbs, F.rootKey)
        let basic = F.seq(tbs + F.seq(F.oid(F.OID_ECDSA_SHA384)) + DERB.tlv(0x03, bits))
        let otherTag = F.seq(DERB.tlv(0x0a, [0x00]) + DERB.tlv(0xa1, F.seq(F.oid(S.OID_BASIC) + DERB.tlv(0x04, basic))))
        XCTAssertFalse(ask(otherTag).ok)
    }

    func testBasicOCSPResponseShape() {
        let tbs = Self.tbs([Self.single(id())]), alg = F.seq(F.oid(F.OID_ECDSA_SHA384))
        let bits: [UInt8] = [0x00] + Self.sign(tbs, F.rootKey)
        let sig = DERB.tlv(0x03, bits)
        good(ask(Self.wrap(F.seq(tbs + alg + sig))))
        rejected(ask(Self.wrap(F.seq(tbs + alg))), "no signature")
        rejected(ask(Self.wrap(F.seq(tbs))), "tbs only")
        var tbsSet = tbs
        tbsSet[0] = 0x31
        let setBits: [UInt8] = [0x00] + Self.sign(tbsSet, F.rootKey)
        rejected(ask(Self.wrap(F.seq(tbsSet + alg + DERB.tlv(0x03, setBits)))), "tbs is not a SEQUENCE")
        rejected(ask(Self.wrap(F.seq(tbs + DERB.tlv(0x31, F.oid(F.OID_ECDSA_SHA384)) + sig))), "the algorithm is not a SEQUENCE")
        rejected(ask(Self.wrap(F.seq(tbs + alg + DERB.tlv(0x04, bits)))), "the signature is not a BIT STRING")
    }

    /// asn1js reads both as an empty signature (asn1js LocalBitStringValueBlock.fromBER), which then does not verify (attest-nvidia-ocsp.ts:308).
    func testAnEmptySignatureDoesNotVerify() {
        let tbs = Self.tbs([Self.single(id())]), alg = F.seq(F.oid(F.OID_ECDSA_SHA384))
        XCTAssertEqual(ask(Self.wrap(F.seq(tbs + alg + DERB.tlv(0x03, [])))).reason, Self.ISSUER_BAD_SIG)
        XCTAssertEqual(ask(Self.wrap(F.seq(tbs + alg + DERB.tlv(0x03, [0x00])))).reason, Self.ISSUER_BAD_SIG)
    }

    func testResponseDataShape() {
        let one = [Self.single(id())]
        good(ask(Self.signed(Self.tbs(one, version: DERB.tlv(0xa0, DERB.tlv(0x02, [0x00]))))), "with a version")
        good(ask(Self.signed(Self.tbs(one, exts: DERB.tlv(0xa1, F.seq([]))))), "with extensions")
        good(ask(Self.signed(Self.tbs(one, version: DERB.tlv(0xa0, DERB.tlv(0x02, [0x00])), exts: DERB.tlv(0xa1, F.seq([]))))), "with both")
        rejected(ask(Self.signed(F.seq(DERB.tlv(0xa1, F.name("root")) + S.gt(Self.T0)))), "no responses")
        rejected(ask(Self.signed(F.seq(DERB.tlv(0xa0, DERB.tlv(0x02, [0x00])) + DERB.tlv(0xa1, F.name("root")) + S.gt(Self.T0)))), "a version, no responses")
        rejected(ask(Self.signed(F.seq([]))), "empty")
        rejected(ask(Self.signed(Self.tbs(one, produced: DERB.tlv(0x17, Array("270115070000Z".utf8))))), "producedAt is a UTCTime")
        rejected(ask(Self.signed(Self.tbs(one, responsesTag: 0x31))), "responses is not a SEQUENCE")
        let key = DERB.tlv(0x04, AHash.sha1.digest(try! OCSP.spkiKeyBits(root)))
        rejected(ask(Self.signed(Self.tbs(one, rid: DERB.tlv(0xa3, key)))), "an unknown responderID choice")
    }

    func testResponderIDByKey() {
        let one = [Self.single(id())]
        let key = AHash.sha1.digest(try! OCSP.spkiKeyBits(root))
        good(ask(Self.signed(Self.tbs(one, rid: DERB.tlv(0xa2, DERB.tlv(0x04, key))))))
        XCTAssertEqual(ask(Self.signed(Self.tbs(one, rid: DERB.tlv(0xa2, DERB.tlv(0x04, [UInt8](repeating: 7, count: 20)))))).reason, Self.NO_RESPONDER)
        XCTAssertFalse(ask(Self.signed(Self.tbs(one, rid: DERB.tlv(0xa2, DERB.tlv(0x0c, key))))).ok, "the key hash is not an OCTET STRING")
    }

    func testSingleResponseShape() {
        rejected(ask(Self.signed(Self.tbs([F.seq(id() + [0x80, 0x00])]))), "no thisUpdate")
        rejected(ask(Self.signed(Self.tbs([F.seq(id())]))), "no status")
        rejected(ask(Self.signed(Self.tbs([F.seq(id() + S.gt(Self.T0) + [0x80, 0x00])]))), "swapped")
    }

    // ---- CertID ----

    func testCertIDFieldsMustBeOctetStrings() {
        rejected(ask(Self.signed(Self.tbs([Self.single(Self.certID(root, nameTag: 0x13))]))), "issuerNameHash")
        rejected(ask(Self.signed(Self.tbs([Self.single(Self.certID(root, keyTag: 0x13))]))), "issuerKeyHash")
    }

    /// attest-nvidia-ocsp.ts:242-253
    func testEveryCertIDFieldMustMatch() {
        let wrong = [UInt8](repeating: 9, count: 32)
        XCTAssertEqual(ask(Self.signed(Self.tbs([Self.single(Self.certID(root, serial: 6))]))).reason, Self.NO_MATCH)
        XCTAssertEqual(ask(Self.signed(Self.tbs([Self.single(Self.certID(root, name: wrong))]))).reason, Self.NO_MATCH)
        XCTAssertEqual(ask(Self.signed(Self.tbs([Self.single(Self.certID(root, key: wrong))]))).reason, Self.NO_MATCH)
        XCTAssertEqual(ask(Self.signed(Self.tbs([Self.single(id()), Self.single(id())]))).reason, "ambiguous: multiple SingleResponses match the certificate")
        good(ask(Self.signed(Self.tbs([Self.single(Self.certID(root, serial: 6)), Self.single(id())]))), "another certificate's entry beside ours")
    }

    // ---- the responder ----

    /// attest-nvidia-ocsp.ts:266-308
    func testIssuerResponder() {
        let tbs = Self.tbs([Self.single(id())])
        XCTAssertEqual(ask(Self.signed(tbs, signer: F.strangerKey)).reason, Self.ISSUER_BAD_SIG)
        let other = Self.tbs([Self.single(id())], rid: DERB.tlv(0xa1, F.name("other")))
        XCTAssertEqual(ask(Self.signed(other)).reason, Self.NO_RESPONDER, "signed by the issuer, but it does not name the issuer")
    }

    func testEmbeddedCertificatesAreReadOnlyFromTheirTag() {
        let tbs = Self.tbs([Self.single(id())], rid: DERB.tlv(0xa1, F.name("resp")))
        good(ask(Self.signed(tbs, signer: F.midKey, certs: DERB.tlv(0xa0, F.seq(S.responder())))), "[0] certs")
        XCTAssertFalse(ask(Self.signed(tbs, signer: F.midKey, certs: DERB.tlv(0xa1, F.seq(S.responder())))).ok, "another tag")
        XCTAssertEqual(ask(Self.signed(tbs, signer: F.midKey)).reason, Self.NO_RESPONDER)
    }

    /// attest-nvidia-ocsp.ts:289-293: the window is closed at both ends. F.cert is valid 2025-01-01 .. 2035-01-01.
    func testDelegatedResponderValidityWindow() {
        let from = "20250101000000Z", to = "20350101000000Z"
        let fromMs = Self.ms(from), toMs = Self.ms(to)
        func at(_ time: String, _ now: Int64) -> OcspResult {
            let tbs = Self.tbs([Self.single(id(), this: time)], rid: DERB.tlv(0xa1, F.name("resp")), produced: S.gt(time))
            return ask(Self.signed(tbs, signer: F.midKey, certs: DERB.tlv(0xa0, F.seq(S.responder()))), now: now)
        }
        good(at(from, fromMs), "at notBefore")
        good(at(to, toMs), "at notAfter")
        let outside = "delegated responder certificate is outside its validity window"
        XCTAssertEqual(at(from, fromMs - 1).reason, outside)
        XCTAssertEqual(at(to, toMs + 1).reason, outside)
    }

    /// attest-nvidia-ocsp.ts:295-297: signed by a chain certificate at or above the issuer, never below it.
    func testDelegatedResponderSignersStartAtTheIssuer() throws {
        let low = try Cert.parseDER(F.cert(subject: "low", issuer: "root", subjectKey: F.leafKey, signer: F.rootKey, serial: 5, exts: [F.bc(false)]))
        let byLow = F.cert(subject: "resp", issuer: "low", subjectKey: F.midKey, signer: F.leafKey, serial: 7, exts: [F.bc(false), S.EKU])
        let tbs = Self.tbs([Self.single(id())], rid: DERB.tlv(0xa1, F.name("resp")))
        let der = Self.signed(tbs, signer: F.midKey, certs: DERB.tlv(0xa0, F.seq(byLow)))
        XCTAssertEqual(OCSP.verifyResponse(der, low, root, [low, root], F.NOW).reason, S.NOT_SIGNED)

        let mid = try Cert.parseDER(F.cert(subject: "mid", issuer: "root", subjectKey: F.midKey, signer: F.rootKey, serial: 2, exts: F.CA))
        let byRoot = F.cert(subject: "resp", issuer: "root", subjectKey: F.strangerKey, signer: F.rootKey, serial: 7, exts: [F.bc(false), S.EKU])
        let tbs2 = Self.tbs([Self.single(Self.certID(mid))], rid: DERB.tlv(0xa1, F.name("resp")))
        let der2 = Self.signed(tbs2, signer: F.strangerKey, certs: DERB.tlv(0xa0, F.seq(byRoot)))
        good(OCSP.verifyResponse(der2, leaf, mid, [leaf, mid, root], F.NOW), "above the issuer")
        XCTAssertEqual(OCSP.verifyResponse(der2, leaf, mid, [leaf], F.NOW).reason, S.NOT_SIGNED, "the issuer is not in the chain: only the issuer signs")
    }

    // ---- freshness ----

    /// attest-nvidia-ocsp.ts:328-334: every bound is inclusive.
    func testFreshnessBoundaries() {
        let this = Self.ms(Self.T0)
        func at(_ now: Int64, next: String? = nil, produced: String = AttestNvidiaOcspK05Tests.T0) -> OcspResult {
            ask(Self.signed(Self.tbs([Self.single(id(), next: next)], produced: S.gt(produced))), now: now)
        }
        good(at(this), "now equals thisUpdate and producedAt")
        XCTAssertEqual(at(this - 1, produced: "20270115060000Z").reason, "response thisUpdate is in the future")
        XCTAssertEqual(at(this, produced: "20270115070001Z").reason, "response producedAt is in the future")
        good(at(this + 1000, produced: "20270115070001Z"), "now equals producedAt, past thisUpdate")
        good(at(this, next: Self.T0), "nextUpdate equals thisUpdate, and now")
        XCTAssertEqual(at(this, next: "20270115065959Z").reason, "response nextUpdate is invalid")
        XCTAssertEqual(at(this + 1, next: Self.T0).reason, "response is stale (past nextUpdate)")
        good(at(this + 604_800_000), "exactly the maximum age")
        XCTAssertEqual(at(this + 604_800_001).reason, "response is older than the maximum accepted age")
    }

    // ---- certStatus ----

    func testStatusesAreVerifiedAnswers() {
        func got(_ status: [UInt8]) -> OcspResult { ask(Self.signed(Self.tbs([Self.single(id(), status: status)]))) }
        let unknown = got([0x82, 0x00])
        XCTAssertTrue(unknown.ok)
        XCTAssertEqual(unknown.status, "unknown")
        let revoked = got(DERB.tlv(0xa1, S.gt("20270101000000Z")))
        XCTAssertTrue(revoked.ok)
        XCTAssertEqual(revoked.status, "revoked")
        let want = "malformed revoked certStatus"
        XCTAssertEqual(got([0xa1, 0x00]).reason, want)
        XCTAssertEqual(got(DERB.tlv(0xa1, S.gt("20270101000000.5Z"))).reason, want)
    }

    /// `^[0-9]{14}Z$` (attest-nvidia-ocsp.ts:364)
    func testIsRevTime() {
        func yes(_ s: String) -> Bool { OCSP.isRevTime(Array(s.utf8)) }
        XCTAssertTrue(yes("20270101000000Z"))
        XCTAssertTrue(yes("29991231235959Z"), "a 9")
        for bad in ["2027010100000xZ", "x0270101000000Z", "202701010000000", "20270101000000Zx", "202701010000000Z"] { XCTAssertFalse(yes(bad), bad) }
    }

    // ---- the chain ----

    /// attest-nvidia-ocsp.ts:411
    func testChainLength() {
        let der = Self.signed(Self.tbs([Self.single(id())]))
        XCTAssertEqual(OCSP.checkChain([leaf, root], [der], F.NOW), "")
        XCTAssertEqual(OCSP.checkChain([leaf], [der], F.NOW), "chain too short for OCSP")
        XCTAssertEqual(OCSP.checkChain([], [der], F.NOW), "chain too short for OCSP")
    }
}
