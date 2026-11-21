import XCTest
@testable import AtlasPCAVerify

/// The `fresh_at` member's wire bounds (packages/pca/src/fresh-at.ts:161) and the policy's optional `require` (absent = no token needed, 177).
final class FreshAtMemberK05Tests: XCTestCase {
    private static let BAD = "'fresh_at' scope and policy_digest must be non-empty strings"

    private func s(_ n: Int) -> String { String(repeating: "s", count: n) }

    func testScopeAndDigestBoundsOnTheWire() {
        XCTAssertNil(FreshAt.validateWire(FreshAtK05Tests.token(scope: s(256))))
        XCTAssertNil(FreshAt.validateWire(FreshAtK05Tests.token(digest: s(128))))
        // either one alone refuses: the other is fine in both cases
        XCTAssertEqual(FreshAt.validateWire(FreshAtK05Tests.token(scope: s(257))), Self.BAD)
        XCTAssertEqual(FreshAt.validateWire(FreshAtK05Tests.token(digest: s(129))), Self.BAD)
    }

    func testRequireDefaultsToFalse() {
        let local = FreshAt.State(revocationEpoch: 0, ledgerTreeSize: 0, budgetVersion: 0, policyRevision: 0, policyDigest: "d")
        let p = FreshAtPolicy(signer: "s", scope: "x", local: local)
        XCTAssertFalse(p.require)
        XCTAssertEqual(FreshAt.decide(nil, p, now: 0), .absent)
    }
}
