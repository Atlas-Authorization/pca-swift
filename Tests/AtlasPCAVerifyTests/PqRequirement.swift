import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A job that is meant to have ML-DSA (every platform has it: the vendored CMLDSA target, or CryptoKit on OS 26) sets `PCA_REQUIRE_PQ=1`: a replay that would skip its
/// ML-DSA cases for want of it fails there instead, so the skip can never hide that no job runs those cases.
enum PqRequirement {
    static var required: Bool { ProcessInfo.processInfo.environment["PCA_REQUIRE_PQ"] == "1" }

    /// Call where a case is left out because ML-DSA is unavailable: true (skip it) only when the job does not require ML-DSA.
    static func mayLeaveOut(_ what: String, file: StaticString = #filePath, line: UInt = #line) -> Bool {
        if required { XCTFail("PCA_REQUIRE_PQ is set but ML-DSA is not available: \(what) cannot be left out", file: file, line: line); return false }
        return true
    }
}

final class PqRequirementTests: XCTestCase {
    func testMlDsaIsPresentWhereTheJobRequiresIt() {
        if PqRequirement.required { XCTAssertTrue(MLDSA.available, "PCA_REQUIRE_PQ=1 but this build has no ML-DSA") }
    }
}
