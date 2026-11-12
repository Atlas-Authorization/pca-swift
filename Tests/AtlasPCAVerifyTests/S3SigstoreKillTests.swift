import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Sigstore.b64s (line 55): length a multiple of 4 AND every character in the standard base64 alphabet.
final class S3SigstoreKillTests: XCTestCase {
    func testAcceptsStandardBase64() throws {
        XCTAssertEqual(try Sigstore.b64s("QUJD"), [65, 66, 67])
        XCTAssertEqual(try Sigstore.b64s("QQ=="), [65])
        XCTAssertEqual(try Sigstore.b64s("+/8="), [0xfb, 0xff])
    }

    func testRefusesWrongLengthAndForeignCharacters() {
        for s in ["QUJDR", "QQ", "QUJ", "QU!D", "QU D", "QU-D", "QU_D", "QU\nD", "QU\u{e9}D", "QU:D", "QU@D", "QU[D", "QU`D", "QU{D", "QU/;", "QU9:", "QU/\u{7f}"] {
            XCTAssertThrowsError(try Sigstore.b64s(s), "refused: \(s.debugDescription)")
        }
    }
}
