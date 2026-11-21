import XCTest
@testable import AtlasPCAVerify

final class S2R2KeysKillTests: XCTestCase {
    func testSigningSeamIsOffByDefault() {
        XCTAssertFalse(PCAPQKey.signingDisabledForTests, "line 78")
    }

    #if !canImport(CryptoKit) && !canImport(COQS)
    func testNoBackendMeansNoSigning() {
        XCTAssertFalse(PCAPQKey.signingAvailable, "line 73")
    }
    #endif
}
