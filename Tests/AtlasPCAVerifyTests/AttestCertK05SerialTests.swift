import XCTest
@testable import AtlasPCAVerify

/// A serial number INTEGER with illegal padding is refused, as c2i_ASN1_INTEGER refuses it inside d2i_X509.
final class AttestCertK05SerialTests: XCTestCase {
    private typealias F = StrictChainForge

    private func why(_ serial: [UInt8]) -> String {
        let alg = F.seq(F.oid([0x2a, 0x03])), bits: [UInt8] = [0x03, 0x01, 0x00], utc = DERB.tlv(0x17, Array("250101000000Z".utf8))
        let tbs: [UInt8] = DERB.tlv(0x02, serial) + alg + F.seq([]) + F.seq(utc + utc) + F.seq([]) + F.seq(alg + bits)
        do { _ = try Cert.parseDER(F.seq(F.seq(tbs) + alg + bits)); return "ok" } catch { return (error as? AttestError)?.message ?? "?" }
    }

    func testIllegalPaddingIsRefused() {
        let padding = "error:0688010A:asn1 encoding routines::illegal padding"
        XCTAssertEqual(why([0x00, 0x01]), padding)
        XCTAssertEqual(why([0x00, 0x00]), padding)
        XCTAssertEqual(why([0xff, 0x80]), padding)
        XCTAssertEqual(why([0xff, 0xff]), padding)
    }

    func testMinimalSerialsParse() {
        for ok: [UInt8] in [[0x00], [0x01], [0xff], [0x00, 0x80], [0xff, 0x7f], [0x01, 0x00], [0x7f, 0x80], [0x80, 0x00]] {
            XCTAssertEqual(why(ok), "ok", "\(ok)")
        }
    }
}
