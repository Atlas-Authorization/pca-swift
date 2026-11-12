import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// Really-signed OCSP responses (attest-nvidia-ocsp.ts): a malformed nextUpdate or embedded certificate is refused, a delegated responder passes `checkIssued`,
/// an rsa-pss key verifies no PKCS#1 signature, and the outer and tbs signature algorithms of a certificate must match (X509_verify).
final class AttestOcspStrictTests: XCTestCase {
    typealias F = StrictChainForge

    static let OID_SHA256: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    static let OID_BASIC: [UInt8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]
    static let OID_OCSP_SIGNING: [UInt8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]
    static let OID_AKID: [UInt8] = [0x55, 0x1d, 0x23]
    static let OID_SKID: [UInt8] = [0x55, 0x1d, 0x0e]
    static let THIS = "20270115070000Z", NEXT = "20270116000000Z" // NOW is 2027-01-15T08:00:00Z
    static let NOT_SIGNED = "delegated responder certificate is not signed by the supplied NVIDIA chain"

    static func gt(_ s: String) -> [UInt8] { DERB.tlv(0x18, Array(s.utf8)) }
    static func skid(_ b: [UInt8]) -> [UInt8] { F.ext(OID_SKID, critical: false, DERB.tlv(0x04, b)) }
    static func akid(_ b: [UInt8]) -> [UInt8] { F.ext(OID_AKID, critical: false, F.seq(DERB.tlv(0x80, b))) }
    static let EKU = F.ext(F.OID_EKU, critical: false, F.seq(F.oid(OID_OCSP_SIGNING)))
    static func root(_ exts: [[UInt8]] = F.CA) -> AttCert { try! Cert.parseDER(F.cert(subject: "root", issuer: "root", subjectKey: F.rootKey, signer: F.rootKey, serial: 1, exts: exts)) }
    static let leaf = try! Cert.parseDER(F.cert(subject: "leaf", issuer: "root", subjectKey: F.leafKey, signer: F.rootKey, serial: 5, exts: F.LEAF))
    static func responder(issuer: String = "root", exts: [[UInt8]] = [F.bc(false), EKU]) -> [UInt8] {
        F.cert(subject: "resp", issuer: issuer, subjectKey: F.midKey, signer: F.rootKey, serial: 7, exts: exts)
    }

    static func single(_ issuer: AttCert, serial: UInt8 = 5, status: [UInt8] = [0x80, 0x00], next: [UInt8]) -> [UInt8] {
        let id = F.seq(F.seq(F.oid(OID_SHA256) + [0x05, 0x00]) + DERB.tlv(0x04, ACrypto.sha256(issuer.rawSubject))
            + DERB.tlv(0x04, ACrypto.sha256(try! OCSP.spkiKeyBits(issuer))) + DERB.tlv(0x02, [serial]))
        return F.seq(id + status + gt(THIS) + next)
    }

    static func response(_ singles: [[UInt8]], responder: String = "root", signer: F.Key = F.rootKey, certs: [UInt8]? = nil) -> [UInt8] {
        let tbs = F.seq(DERB.tlv(0xa1, F.name(responder)) + gt(THIS) + F.seq(singles.flatMap { $0 }))
        let sig: [UInt8] = [0x00] + Array(try! signer.signature(for: Data(tbs)).derRepresentation)
        let basic = F.seq(tbs + F.seq(F.oid(F.OID_ECDSA_SHA384)) + DERB.tlv(0x03, sig) + (certs ?? []))
        return F.seq(DERB.tlv(0x0a, [0x00]) + DERB.tlv(0xa0, F.seq(F.oid(OID_BASIC) + DERB.tlv(0x04, basic))))
    }

    /// A response signed by the delegated responder, with these certificates embedded.
    static func delegated(_ embedded: [[UInt8]], issuer: AttCert) -> [UInt8] {
        response([single(issuer, next: [])], responder: "resp", signer: F.midKey, certs: DERB.tlv(0xa0, F.seq(embedded.flatMap { $0 })))
    }

    func ask(_ der: [UInt8], issuer: AttCert = AttestOcspStrictTests.root()) -> OcspResult {
        OCSP.verifyResponse(der, Self.leaf, issuer, [Self.leaf, issuer], F.NOW)
    }

    func testGoodResponses() {
        let r = Self.root()
        XCTAssertEqual(ask(Self.response([Self.single(r, next: [])])).status, "good")
        XCTAssertEqual(ask(Self.response([Self.single(r, next: DERB.tlv(0xa0, Self.gt(Self.NEXT)))])).status, "good")
        let passed = DERB.tlv(0xa0, Self.gt("20270115073000Z"))
        XCTAssertEqual(ask(Self.response([Self.single(r, next: passed)])).reason, "response is stale (past nextUpdate)")
        // the issuer signed: the embedded certificates are never read
        XCTAssertEqual(ask(Self.response([Self.single(r, next: [])], certs: DERB.tlv(0xa0, F.seq(F.seq([0x01, 0x01, 0xff]))))).status, "good")
    }

    func testAMalformedNextUpdateIsRefused() {
        let r = Self.root()
        let want = "OCSP response rejected: malformed nextUpdate"
        let utc = DERB.tlv(0xa0, DERB.tlv(0x17, Array("270116000000Z".utf8)))
        let two = DERB.tlv(0xa0, Self.gt(Self.NEXT) + Self.gt(Self.NEXT))
        let empty = DERB.tlv(0xa0, [])
        for bad in [utc, two, empty] { XCTAssertEqual(ask(Self.response([Self.single(r, next: bad)])).reason, want) }
        // in a SingleResponse for another certificate too, as the whole structure is parsed
        XCTAssertEqual(ask(Self.response([Self.single(r, serial: 6, next: utc), Self.single(r, next: [])])).reason, want)
        // singleExtensions are not a nextUpdate
        XCTAssertEqual(ask(Self.response([Self.single(r, next: DERB.tlv(0xa1, F.seq([])))])).status, "good")
    }

    func testCertStatusTagsAreExact() {
        let r = Self.root()
        func got(_ status: [UInt8]) -> OcspResult { ask(Self.response([Self.single(r, status: status, next: [])])) }
        XCTAssertEqual(got([0x80, 0x00]).status, "good")
        XCTAssertEqual(got([0x82, 0x00]).status, "unknown")
        XCTAssertEqual(got(DERB.tlv(0xa1, Self.gt("20270101000000Z"))).status, "revoked")
        for tag: UInt8 in [0xa0, 0xa2, 0x81] {
            let bad = got([tag, 0x00])
            XCTAssertFalse(bad.ok)
            XCTAssertEqual(bad.reason, "malformed certStatus")
        }
        XCTAssertEqual(got([0x05, 0x00]).reason, "malformed certStatus")
        XCTAssertEqual(got([0x83, 0x00]).reason, "unrecognised certStatus")
        XCTAssertEqual(got([0xa3, 0x00]).reason, "unrecognised certStatus")
    }

    func testOnlyNextUpdateThenExtensionsFollowThisUpdate() {
        let r = Self.root()
        let want = "OCSP response rejected: malformed SingleResponse"
        let next = DERB.tlv(0xa0, Self.gt(Self.NEXT)), ext = DERB.tlv(0xa1, F.seq([]))
        XCTAssertEqual(ask(Self.response([Self.single(r, next: next + ext)])).status, "good")
        XCTAssertEqual(ask(Self.response([Self.single(r, next: ext)])).status, "good")
        // a past nextUpdate under another tag must not skip the stale check
        let hidden = DERB.tlv(0xa2, Self.gt("20270115073000Z"))
        for tail in [hidden, ext + next, next + next, ext + ext, next + ext + hidden] {
            XCTAssertEqual(ask(Self.response([Self.single(r, next: tail)])).reason, want)
        }
        // every SingleResponse is parsed, matching or not
        XCTAssertEqual(ask(Self.response([Self.single(r, serial: 6, next: hidden), Self.single(r, next: [])])).reason, want)
    }

    func testAMalformedEmbeddedCertificateIsRefused() {
        let r = Self.root()
        XCTAssertEqual(ask(Self.delegated([Self.responder()], issuer: r), issuer: r).status, "good")
        let garbage = F.seq([0x01, 0x01, 0xff])
        let got = ask(Self.delegated([garbage, Self.responder()], issuer: r))
        XCTAssertFalse(got.ok)
        XCTAssertTrue(got.reason.hasPrefix("OCSP response rejected: "), got.reason)
        XCTAssertEqual(ask(Self.delegated([Self.responder(), garbage], issuer: r), issuer: r).ok, false)
        let twoWraps = Self.response([Self.single(r, next: [])], responder: "resp", signer: F.midKey, certs: DERB.tlv(0xa0, F.seq(Self.responder()) + F.seq(Self.responder())))
        XCTAssertEqual(ask(twoWraps).reason, "OCSP response rejected: malformed certs")
    }

    func testDelegatedResponderCheckIssued() {
        // keyCertSign when the issuer has keyUsage
        let noCertSign = Self.root([F.bc(true), F.KU_SIGN])
        XCTAssertEqual(ask(Self.delegated([Self.responder()], issuer: noCertSign), issuer: noCertSign).reason, Self.NOT_SIGNED)
        XCTAssertEqual(ask(Self.delegated([Self.responder()], issuer: Self.root([F.bc(true)])), issuer: Self.root([F.bc(true)])).status, "good")
        // the issuer name
        XCTAssertEqual(ask(Self.delegated([Self.responder(issuer: "other")], issuer: Self.root()), issuer: Self.root()).reason, Self.NOT_SIGNED)
        // the AKID key id against the SKID, when both are present
        let kid: [UInt8] = [1, 2, 3, 4], other: [UInt8] = [9, 9, 9, 9]
        let withSkid = Self.root(F.CA + [Self.skid(kid)])
        func cand(_ a: [UInt8]) -> [UInt8] { Self.responder(exts: [F.bc(false), Self.EKU, a]) }
        XCTAssertEqual(ask(Self.delegated([cand(Self.akid(kid))], issuer: withSkid), issuer: withSkid).status, "good")
        XCTAssertEqual(ask(Self.delegated([cand(Self.akid(other))], issuer: withSkid), issuer: withSkid).reason, Self.NOT_SIGNED)
        XCTAssertEqual(ask(Self.delegated([cand(Self.akid(other))], issuer: Self.root()), issuer: Self.root()).status, "good", "no SKID: nothing to compare")
        XCTAssertEqual(ask(Self.delegated([Self.responder()], issuer: withSkid), issuer: withSkid).status, "good", "no AKID: nothing to compare")
        // an AKID with only a serial: it must be the issuer's (X509_check_akid), SKID or not
        func serialOnly(_ b: [UInt8]) -> [UInt8] { F.ext(Self.OID_AKID, critical: false, F.seq(DERB.tlv(0x82, b))) }
        let wrongSerial: [UInt8] = [withSkid.serial[0] ^ 1]
        XCTAssertEqual(ask(Self.delegated([cand(serialOnly(withSkid.serial))], issuer: withSkid), issuer: withSkid).status, "good")
        XCTAssertEqual(ask(Self.delegated([cand(serialOnly(wrongSerial))], issuer: withSkid), issuer: withSkid).reason, Self.NOT_SIGNED)
        // malformed AKID / SKID
        let badAkid = F.ext(Self.OID_AKID, critical: false, DERB.tlv(0x04, kid))
        XCTAssertEqual(ask(Self.delegated([cand(badAkid)], issuer: withSkid), issuer: withSkid).reason, Self.NOT_SIGNED)
        let badSkid = Self.root(F.CA + [F.ext(Self.OID_SKID, critical: false, DERB.tlv(0x02, kid))])
        XCTAssertEqual(ask(Self.delegated([cand(Self.akid(kid))], issuer: badSkid), issuer: badSkid).reason, Self.NOT_SIGNED)
    }

    private func rsaKey(_ typ: String) -> CertKey {
        var k = CertKey()
        k.typ = typ
        k.rsaN = AttestFailClosedTests.h(AttestFailClosedTests.N)
        k.rsaE = [0x01, 0x00, 0x01]
        return k
    }

    func testPkcs1UnderAnRsaPssKeyIsRefused() {
        let sha256WithRSA = "1.2.840.113549.1.1.11"
        let sig = AttestFailClosedTests.h(AttestFailClosedTests.PKCS1), msg = AttestFailClosedTests.MSG
        XCTAssertTrue(OCSP.sigOK(sha256WithRSA, msg, sig, rsaKey("rsa")))
        XCTAssertFalse(OCSP.sigOK(sha256WithRSA, msg, sig, rsaKey("rsa-pss")))
        var c = AttCert()
        c.sigOID = sha256WithRSA
        c.rawTBS = msg
        c.signature = sig
        c.sigAlgsMatch = true
        XCTAssertTrue(Cert.sigOK(c, rsaKey("rsa")))
        XCTAssertFalse(Cert.sigOK(c, rsaKey("rsa-pss")))
        c.sigAlgsMatch = false
        XCTAssertFalse(Cert.sigOK(c, rsaKey("rsa")))
    }

    func testOuterAndTbsSignatureAlgorithmsMustMatch() throws {
        let good = Self.root()
        XCTAssertTrue(good.sigAlgsMatch)
        XCTAssertTrue(Cert.sigOKBy(good, good))
        // the outer algorithm is not signed: the signature still verifies, the certificate must not
        let outer = F.seq(F.oid(F.OID_ECDSA_SHA384) + [0x05, 0x00])
        let altered = try Cert.parseDER(F.seq(good.rawTBS + outer + DERB.tlv(0x03, [0x00] + good.signature)))
        XCTAssertFalse(altered.sigAlgsMatch)
        XCTAssertFalse(Cert.sigOKBy(altered, good))
    }
}
