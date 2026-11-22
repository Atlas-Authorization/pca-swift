import XCTest
@testable import AtlasPCALweOt

final class EndemicSurfaceTests: XCTestCase {
    func testTheSecretWidthConstantIsTheLatticeSymbolWidth() {
        XCTAssertEqual(ENDEMIC_SECRET_BYTES, 32)
        XCTAssertEqual(ENDEMIC_SECRET_BYTES, EndemicOt.secretBytes)
    }
}
