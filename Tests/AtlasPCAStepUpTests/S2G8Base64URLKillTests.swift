import XCTest
import Foundation
@testable import AtlasPCAStepUp

/// Kill test (mutation sheet swift-k05 group 8) for Base64URL.decode: padding is trimmed before the length is judged.
final class S2G8Base64URLKillTests: XCTestCase {
    func testDecodeToleratesExtraPadding() {
        XCTAssertEqual(Base64URL.decode("QQ"), Data([0x41]))
        XCTAssertEqual(Base64URL.decode("QQ=="), Data([0x41]))
        XCTAssertEqual(Base64URL.decode("QQ==="), Data([0x41]), "line 15 padding is trimmed before the length is checked")
        XCTAssertEqual(Base64URL.decode("QUI==="), Data([0x41, 0x42]))
        XCTAssertEqual(Base64URL.decode("QUJD"), Data([0x41, 0x42, 0x43]))
        XCTAssertNil(Base64URL.decode("Q"))
    }
}
