import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// PcaGrant URL limits (RFC 9396 authorization_details), the undo receipt body, and the strict Ed25519 artifact check.
final class S2G7MiscKillTests: XCTestCase {
    typealias J = JSONValue

    func url(_ n: Int) -> String { "https://" + String(repeating: "a", count: n - 8) }

    func testHttpsUrlLength() {
        XCTAssertTrue(PcaGrant.isHttpsUrl(J.string(url(2048))), "exactly 2048 bytes")
        XCTAssertFalse(PcaGrant.isHttpsUrl(J.string(url(2049))))
        XCTAssertTrue(PcaGrant.isHttpsUrl(J.string(url(2047))))
        XCTAssertTrue(PcaGrant.isHttpsUrl(J.string(url(9))))
        XCTAssertFalse(PcaGrant.isHttpsUrl(J.string("https://")), "no authority")
    }

    func testHttpsUrlCharacterRange() {
        XCTAssertTrue(PcaGrant.isHttpsUrl(J.string("https://a!b")), "0x21 is the first printable")
        XCTAssertTrue(PcaGrant.isHttpsUrl(J.string("https://a~b")), "0x7e is the last printable")
        for bad in ["https://a b", "https://a\u{7f}b", "https://a#b", "https://a\\b", "https://a\u{1}b", "http://a", "https://@a", "https://a@b"] {
            XCTAssertFalse(PcaGrant.isHttpsUrl(J.string(bad)), bad)
        }
        XCTAssertFalse(PcaGrant.isHttpsUrl(nil))
        XCTAssertFalse(PcaGrant.isHttpsUrl(J.int(1)))
        XCTAssertFalse(PcaGrant.isHttpsUrl(J.null))
    }

    // ---- an undo receipt whose body cannot be canonicalised ----

    func testAReceiptWithALoneSurrogateNoteIsRefused() {
        let signer = Base64URLStrict.encode([UInt8](repeating: 5, count: 32))
        let sig = Base64URLStrict.encode([UInt8](repeating: 6, count: 64))
        func receipt(_ note: String) -> JSONValue {
            J.object(["v": J.int(1), "kind": J.string(Undo.RECEIPT_KIND), "record": J.string("r1"), "event": J.string("opened"), "state": J.string("open"), "at": J.int(1),
                      "compensation_digest": J.string("c"), "prev": J.string(""), "note": J.string(note), "signer": J.string(signer), "sig": J.string(sig)])
        }
        // a plain note reaches the signature check (and fails it: the signature is not real); a note carrying the lone-surrogate sentinel
        // has no strict canonical form and is refused before it
        XCTAssertFalse(Undo.verifyReceipt(receipt("n"), expectedSigner: signer))
        XCTAssertFalse(Undo.verifyReceipt(receipt("n" + String(Unicode.Scalar(0xFDD0)!)), expectedSigner: signer))
    }

    func testTokenLengthLimit() {
        XCTAssertNil(Undo.decodeToken(String(repeating: "A", count: 4097)), "4097 characters is not valid base64url anyway")
        XCTAssertNil(Undo.decodeToken(""))
    }

    // ---- verifyEd ----

    func testVerifyEdAcceptsAStringSignature() throws {
        let k = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 8, count: 32))
        let pk = Base64URLStrict.encode(Array(k.publicKey.rawRepresentation))
        let msg: [UInt8] = Array("hello".utf8)
        let sig = Base64URLStrict.encode(Array(try k.signature(for: Data(msg))))
        XCTAssertTrue(IV.verifyEd(pk, msg, J.string(sig)))
        XCTAssertFalse(IV.verifyEd(pk, msg, nil))
        XCTAssertFalse(IV.verifyEd(pk, msg, J.int(1)))
        XCTAssertFalse(IV.verifyEd(pk, Array("other".utf8), J.string(sig)))
    }
}
