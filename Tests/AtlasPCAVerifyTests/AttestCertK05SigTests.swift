import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// RSASSA-PSS parameters (OpenSSL's RSA_PSS_PARAMS template, inside this verifier's profile) and the guards of certificate signature checks.
final class AttestCertK05SigTests: XCTestCase {
    private typealias F = StrictChainForge

    private static let null: [UInt8] = [0x05, 0x00]
    private static let unknown = F.seq(F.oid([0x2a, 0x03]))
    private static let sha1 = F.seq(F.oid([0x2b, 0x0e, 0x03, 0x02, 0x1a]) + null)
    private static let sha256 = F.seq(F.oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) + null)
    private static let sha384 = F.seq(F.oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]) + null)
    private static let mgf1 = F.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08])

    private func a0(_ alg: [UInt8]) -> [UInt8] { DERB.tlv(0xa0, alg) }
    private func mgf(_ alg: [UInt8]) -> [UInt8] { DERB.tlv(0xa1, F.seq(Self.mgf1 + alg)) }
    private func saltOf(_ c: [UInt8]) -> [UInt8] { DERB.tlv(0xa2, DERB.tlv(0x02, c)) }
    private func trailer(_ c: [UInt8]) -> [UInt8] { DERB.tlv(0xa3, DERB.tlv(0x02, c)) }

    private func accept(_ body: [UInt8], _ hash: AHash, _ salt: Int, line: UInt = #line) {
        let p = Cert.pssParams(F.seq(body))
        XCTAssertEqual(p?.hash, Optional(hash), line: line)
        XCTAssertEqual(p?.salt, Optional(salt), line: line)
    }

    func testPssParamsAccepted() {
        let s256: [UInt8] = a0(Self.sha256) + mgf(Self.sha256)
        let s384: [UInt8] = a0(Self.sha384) + mgf(Self.sha384)
        accept([], .sha1, 20)
        accept(a0(Self.sha1), .sha1, 20)
        accept(mgf(Self.sha1), .sha1, 20)
        accept(s256, .sha256, 20)
        accept(s256 + saltOf([0x20]), .sha256, 32)
        accept(s384 + saltOf([0x30]) + trailer([0x01]), .sha384, 48)
        accept(saltOf([0x00]), .sha1, 0)
        accept(saltOf([0x0f, 0xff, 0xff]), .sha1, 0x0fffff)
        accept(saltOf([0x08, 0x00, 0x01]), .sha1, 0x080001)
        accept(saltOf([0x10, 0x00, 0x00]), .sha1, 0x100000) // the bound itself
        accept(trailer([0x01]), .sha1, 20)
    }

    func testPssParamsOfARealCertificate() throws {
        let pss = try Cert.parseDER(AttestFailClosedTests.der(AttestFailClosedTests.PSS_CERT))
        let p = try XCTUnwrap(Cert.pssParams(pss.sigParams))
        XCTAssertEqual(p.hash, AHash.sha384)
        XCTAssertEqual(p.salt, 48)
    }

    func testPssParamsRefused() {
        XCTAssertNil(Cert.pssParams(nil))                        // absent: RFC 4055 requires them
        XCTAssertNil(Cert.pssParams([]))
        XCTAssertNil(Cert.pssParams(Self.null))
        XCTAssertNil(Cert.pssParams([0x30, 0x02, 0xa0, 0x05]))   // a field past the end
        func refuse(_ body: [UInt8], _ name: String, line: UInt = #line) { XCTAssertNil(Cert.pssParams(F.seq(body)), name, line: line) }
        refuse(DERB.tlv(0xa0, []), "empty wrapper")
        refuse(DERB.tlv(0xa0, Self.sha1 + Self.sha1), "two inside a wrapper")
        refuse(a0(Self.unknown), "unknown hash")
        refuse(DERB.tlv(0xa0, DERB.tlv(0x31, F.oid([0x2b, 0x0e, 0x03, 0x02, 0x1a]))), "hash not a SEQUENCE")
        refuse(DERB.tlv(0xa1, F.seq(F.oid([0x2a, 0x03]) + Self.sha1)), "mask not MGF1")
        refuse(DERB.tlv(0xa1, F.seq(Self.mgf1)), "MGF1 without a hash")
        refuse(DERB.tlv(0xa1, F.seq(Self.mgf1 + Self.null)), "MGF1 hash not a SEQUENCE")
        refuse(mgf(Self.unknown), "MGF1 unknown hash")
        refuse(DERB.tlv(0xa1, DERB.tlv(0x31, Self.mgf1 + Self.sha1)), "mask not a SEQUENCE")
        refuse(DERB.tlv(0xa2, DERB.tlv(0x04, [0x20])), "salt not an INTEGER")
        refuse(saltOf([]), "salt empty")
        refuse(saltOf([0x00, 0x20]), "salt non-minimal")
        refuse(saltOf([0x80]), "salt negative")
        refuse(saltOf([0x10, 0x00, 0x01]), "salt over the bound")
        refuse(saltOf([0x01, 0x00, 0x00, 0x00]), "salt over three octets")
        refuse(trailer([0x02]), "trailer 2")
        refuse(trailer([0x00]), "trailer 0")
        refuse(DERB.tlv(0xa4, DERB.tlv(0x02, [0x01])), "unknown field")
        refuse(saltOf([0x20]) + saltOf([0x20]), "duplicate field")
        refuse(saltOf([0x20]) + a0(Self.sha1), "fields out of order")
        refuse(a0(Self.sha256), "MGF1 hash differs (default mask)")
        refuse(mgf(Self.sha256), "MGF1 hash differs (default hash)")
        refuse(a0(Self.sha256) + mgf(Self.sha384), "MGF1 hash differs")
    }

    func testSigOKUnderPssKeys() throws {
        let pss = try Cert.parseDER(AttestFailClosedTests.der(AttestFailClosedTests.PSS_CERT))
        var k = try Cert.keyOf(pss)
        k.typ = "rsa"
        XCTAssertTrue(Cert.sigOK(pss, k))
        k.typ = "rsa-pss"
        XCTAssertTrue(Cert.sigOK(pss, k))
        k.typ = "ec"
        XCTAssertFalse(Cert.sigOK(pss, k))
        k.typ = "rsa"
        var noParams = pss
        noParams.sigParams = nil
        XCTAssertFalse(Cert.sigOK(noParams, k))
        var badParams = pss
        badParams.sigParams = Self.null
        XCTAssertFalse(Cert.sigOK(badParams, k))
    }

    func testAnUnknownSignatureAlgorithmDoesNotVerify() {
        var c = AttCert()
        c.sigAlgsMatch = true
        c.sigOID = "1.2.3"
        var k = CertKey()
        k.typ = "rsa"
        XCTAssertFalse(Cert.sigOK(c, k))
    }

    func testAPkcs1SignatureMustVerify() throws {
        let rsa = try Cert.parseDER(AttestFailClosedTests.der(AttestFailClosedTests.RSA_CERT))
        let k = try Cert.keyOf(rsa)
        XCTAssertTrue(Cert.sigOK(rsa, k))
        var bad = rsa
        bad.signature[bad.signature.count - 1] ^= 0x01
        XCTAssertFalse(Cert.sigOK(bad, k))
    }

    func testEd25519Signatures() throws {
        let sk = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x07, count: 32))
        let msg: [UInt8] = [0x01, 0x02, 0x03]
        var c = AttCert()
        c.sigAlgsMatch = true
        c.sigOID = Cert.OID_ED25519
        c.rawTBS = msg
        c.signature = Array(try sk.signature(for: Data(msg)))
        var k = CertKey()
        k.typ = "ed25519"
        k.ed = Array(sk.publicKey.rawRepresentation)
        XCTAssertTrue(Cert.sigOK(c, k))
        k.typ = "rsa"                       // right bytes, wrong key type
        XCTAssertFalse(Cert.sigOK(c, k))
        k.typ = "ed25519"
        c.rawTBS = [0x09]                   // right key type, wrong message
        XCTAssertFalse(Cert.sigOK(c, k))
    }

    func testCheckIssuedRefusesAnUnreadableIssuer() {
        var child = AttCert(), issuer = AttCert()
        child.rawIssuer = [0x01]
        issuer.rawSubject = [0x01]
        issuer.raw = [0x02, 0x01, 0x00]
        XCTAssertFalse(Cert.checkIssued(child, issuer))
    }

    func testSigOKByRefusesAnUnreadableParentKey() {
        var child = AttCert()
        child.sigAlgsMatch = true
        XCTAssertFalse(Cert.sigOKBy(child, AttCert()))
    }
}
