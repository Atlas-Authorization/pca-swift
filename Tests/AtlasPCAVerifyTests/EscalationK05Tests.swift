import XCTest
@testable import AtlasPCAVerify

/// `verifyEscalationAnswer` (packages/pca/src/escalation.ts:146): the clock guard is `isSafeInt(now)`, so +-(2^53-1) is a usable clock.
final class EscalationK05Tests: XCTestCase {
    private static let CLOCK = "the verifier clock is not a safe integer (fail closed)"
    private static let NEXT = "malformed escalation answer: not an object"

    private func reason(_ now: Int64) -> String {
        PCA.verifyEscalationAnswer(nil, principals: [], bind: EscalationBinding(policyDigest: "", actionDigest: "", historyHead: ""), now: now).reason
    }

    func testClockBoundaries() {
        XCTAssertEqual(reason(Canonical.MAX_SAFE), Self.NEXT)
        XCTAssertEqual(reason(-Canonical.MAX_SAFE), Self.NEXT)
        XCTAssertEqual(reason(Canonical.MAX_SAFE + 1), Self.CLOCK)
        XCTAssertEqual(reason(-Canonical.MAX_SAFE - 1), Self.CLOCK)
    }
}
