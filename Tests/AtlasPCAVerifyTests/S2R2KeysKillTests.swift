import XCTest
@testable import AtlasPCAVerify

final class S2R2KeysKillTests: XCTestCase {
    func testSigningSeamIsOffByDefault() {
        XCTAssertFalse(PCAPQKey.signingDisabledForTests, "line 78")
    }
}
