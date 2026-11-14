import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Base64URLStrict.swift line 20: the second byte of each triple is bytes[i + 1] (a wrong offset reads the third byte).
final class A0KillBase64URLStrictTests: XCTestCase {
    func testEncodeOfThreeBytesUsesTheSecondByte() {
        XCTAssertEqual(Base64URLStrict.encode([1, 2, 3]), "AQID", "line 20")
    }
}
