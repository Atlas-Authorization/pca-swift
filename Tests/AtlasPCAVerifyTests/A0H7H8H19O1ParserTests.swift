import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import AtlasPCAVerify

/// H7: the lenient JSON number grammar.
final class A0H7LenientNumberTests: XCTestCase {
    func testNonJsonNumbersAreRefused() {
        for t in ["01", "1.", "-", "1e", "+1", "-01", "1e+", ".5", "00", "1.e3", "[01]", "-.5"] {
            let r: Bool? = S2Deadline.within(10, "lenient \(t)") { (try? StrictJSON.parseLenient(t)) == nil }
            XCTAssertEqual(r, true, t)
        }
        do { _ = try StrictJSON.parseLenient("1."); XCTFail("accepted") } catch {
            XCTAssertTrue("\(error)".contains("bad number"), "\(error)")
        }
    }

    func testJsonNumbersAreAccepted() throws {
        XCTAssertEqual(try StrictJSON.parseLenient("0"), .int(0))
        XCTAssertEqual(try StrictJSON.parseLenient("10"), .int(10))
        XCTAssertEqual(try StrictJSON.parseLenient("-5"), .int(-5))
        XCTAssertEqual(try StrictJSON.parseLenient("1.5e3"), .double(1500))
        XCTAssertEqual(try StrictJSON.parseLenient("2E-1"), .double(0.2))
        guard case .double(let z) = try StrictJSON.parseLenient("-0") else { return XCTFail("-0 is a double") }
        XCTAssertTrue(z == 0 && z.sign == .minus)
    }
}

/// H8: issuer RSASSA-PSS-params restrictions (the real PSS_CERT is SHA-384 / MGF1-SHA-384 / salt 48).
final class A0H8PssKeyRestrictionTests: XCTestCase {
    private typealias F = StrictChainForge
    private static let null: [UInt8] = [0x05, 0x00]
    private static let h384 = F.seq(F.oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]) + null)
    private static let h256 = F.seq(F.oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) + null)
    private static let mgf1 = F.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08])
    private static let pssOID = F.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a])

    private func params(_ h: [UInt8], _ m: [UInt8], _ salt: UInt8) -> [UInt8] {
        F.seq(DERB.tlv(0xa0, h) + DERB.tlv(0xa1, F.seq(Self.mgf1 + m)) + DERB.tlv(0xa2, DERB.tlv(0x02, [salt])))
    }

    /// The cert's key, re-wrapped under an id-RSASSA-PSS AlgorithmIdentifier carrying `p` (nil = no params), through keyOfSPKI.
    private func keyWith(_ p: [UInt8]?, _ pss: AttCert) throws -> CertKey {
        let raw = pss.rawSPKI
        let spki = try Cert.readElem(raw, 0, raw.count, 0x30)
        let ks = try Cert.kids(raw, spki)
        let alg = F.seq(Self.pssOID + (p ?? []))
        var k = try Cert.keyOfSPKI(F.seq(alg + Array(raw[ks[1].hdr..<ks[1].end])))
        XCTAssertEqual(k.typ, "rsa-pss")
        k.typ = "rsa-pss"
        return k
    }

    func testKeyParamsAreParsedAndEnforced() throws {
        let pss = try Cert.parseDER(AttestFailClosedTests.der(AttestFailClosedTests.PSS_CERT))
        let un = try keyWith(nil, pss)
        XCTAssertNil(un.pssRestrict)
        XCTAssertFalse(un.pssBad)
        XCTAssertTrue(Cert.sigOK(pss, un), "unrestricted key")
        let ok = try keyWith(params(Self.h384, Self.h384, 48), pss)
        XCTAssertEqual(ok.pssRestrict?.hash, AHash.sha384)
        XCTAssertEqual(ok.pssRestrict?.mgf, AHash.sha384)
        XCTAssertEqual(ok.pssRestrict?.salt, 48)
        XCTAssertTrue(Cert.sigOK(pss, ok), "SHA-384 salt 48 under a SHA-384/48 key")
        XCTAssertTrue(Cert.sigOK(pss, try keyWith(params(Self.h384, Self.h384, 20), pss)), "signature salt 48 >= key salt 20")
        XCTAssertFalse(Cert.sigOK(pss, try keyWith(params(Self.h384, Self.h384, 49), pss)), "signature salt 48 < key salt 49")
        XCTAssertFalse(Cert.sigOK(pss, try keyWith(params(Self.h256, Self.h256, 48), pss)), "key hash SHA-256, signature SHA-384")
        XCTAssertFalse(Cert.sigOK(pss, try keyWith(params(Self.h384, Self.h256, 48), pss)), "key MGF1 hash differs")
        XCTAssertTrue(try keyWith(Self.null, pss).pssBad, "params present but not a SEQUENCE")
        XCTAssertFalse(Cert.sigOK(pss, try keyWith(Self.null, pss)))
    }

    func testComparison() {
        var k = CertKey()
        k.typ = "rsa-pss"
        k.pssRestrict = (.sha384, .sha384, 48)
        XCTAssertFalse(Cert.pssWithinKey(k, hash: .sha256, mgf: .sha256, salt: 32), "SHA-256 under a SHA-384 key")
        XCTAssertTrue(Cert.pssWithinKey(k, hash: .sha384, mgf: .sha384, salt: 48))
        XCTAssertTrue(Cert.pssWithinKey(k, hash: .sha384, mgf: .sha384, salt: 64))
        XCTAssertFalse(Cert.pssWithinKey(k, hash: .sha384, mgf: .sha384, salt: 20))
        XCTAssertFalse(Cert.pssWithinKey(k, hash: .sha384, mgf: .sha256, salt: 48))
        k.pssRestrict = nil
        XCTAssertTrue(Cert.pssWithinKey(k, hash: .sha256, mgf: .sha256, salt: 20), "unrestricted")
    }
}

/// H19: the cheap equation runs first, the torsion checks only on success.
final class A0H19Ed25519VerifyFirstTests: XCTestCase {
    func testForgedRandomSignaturesAreRefusedFast() {
        let pk = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let t0 = Date()
        let r: Bool? = S2Deadline.within(10, "forged signatures") {
            var any = false
            for _ in 0..<200 {
                var sig = (0..<64).map { _ in UInt8.random(in: 0...255) }
                sig[63] &= 0x0f // S < L
                if Ed25519Strict.verify(publicKey: pk, message: [1, 2, 3], signature: sig) { any = true }
            }
            return any
        }
        XCTAssertEqual(r, false)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 5, "200 forged signatures must not each pay two [L]P torsion tests")
    }

    func testValidSignatureStillVerifiesAndTamperingFails() {
        let sk = Curve25519.Signing.PrivateKey()
        let pk = Array(sk.publicKey.rawRepresentation)
        let msg: [UInt8] = Array("h19".utf8)
        let sig = Array((try! sk.signature(for: Data(msg))) as Data)
        XCTAssertEqual(S2Deadline.within(30, "valid") { Ed25519Strict.verify(publicKey: pk, message: msg, signature: sig) }, true)
        XCTAssertFalse(Ed25519Strict.verify(publicKey: pk, message: msg + [0], signature: sig))
        var hi = sig
        hi[63] = 0xff // S >= L
        XCTAssertFalse(Ed25519Strict.verify(publicKey: pk, message: msg, signature: hi))
    }
}

/// O1: ECDSA DER minimality before the platform parser.
final class A0O1EcdsaMinimalDerTests: XCTestCase {
    private func int(_ v: [UInt8], pad: Bool = false) -> [UInt8] {
        var m = Array(v.drop(while: { $0 == 0 }))
        if m.isEmpty { m = [0] }
        if m[0] & 0x80 != 0 { m = [0] + m }
        if pad { m = [0] + m } // always one extra zero: a non-minimal INTEGER whatever the top bit is
        return [0x02, UInt8(m.count)] + m
    }
    private func sigDER(_ raw: [UInt8], padR: Bool = false, trailing: [UInt8] = []) -> [UInt8] {
        let h = raw.count / 2
        let body = int(Array(raw[0..<h]), pad: padR) + int(Array(raw[h...]))
        return [0x30, UInt8(body.count)] + body + trailing
    }

    func testMinimalAcceptedNonMinimalRefused() {
        let sk = P256.Signing.PrivateKey()
        let pt = Array(sk.publicKey.x963Representation)
        let msg: [UInt8] = Array("o1".utf8)
        let raw = Array((try! sk.signature(for: Data(msg))).rawRepresentation)
        let good = sigDER(raw)
        XCTAssertEqual(S2Deadline.within(10, "good") { ACrypto.ecVerify(curve: "P-256", point: pt, hash: .sha256, message: msg, der: good) }, true)
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-256", point: pt, hash: .sha256, message: msg, der: sigDER(raw, padR: true)), "non-minimal r")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-256", point: pt, hash: .sha256, message: msg, der: sigDER(raw, trailing: [0])), "trailing data")
    }

    func testShape() {
        let ok: [UInt8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        XCTAssertTrue(ACrypto.derSigMinimal(ok, maxInt: 33))
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00], maxInt: 33), "outer length short")
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02], maxInt: 33), "padding byte before a low-bit value")
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02], maxInt: 33), "negative")
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], maxInt: 33), "0x81 length under 128")
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], maxInt: 0), "integer over the curve size")
        XCTAssertFalse(ACrypto.derSigMinimal([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], maxInt: 33), "not a SEQUENCE")
        // P-521-size body: two 66-byte integers with a long-form SEQUENCE length
        let big = [UInt8](repeating: 0x11, count: 66)
        let body: [UInt8] = [0x02, 66] + big + [0x02, 66] + big
        XCTAssertTrue(ACrypto.derSigMinimal([0x30, 0x81, UInt8(body.count)] + body, maxInt: 67))
    }
}
