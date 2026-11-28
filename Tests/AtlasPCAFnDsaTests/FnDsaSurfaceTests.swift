import XCTest
@testable import AtlasPCAFnDsa

final class FnDsaSurfaceTests: XCTestCase {
    func testTheDefaultBackendRefusesWithTheNamedMessage() {
        XCTAssertTrue(FnDsa.NO_FN_DSA_BACKEND_MESSAGE.hasPrefix("no FN-DSA backend registered"))
    }
}
