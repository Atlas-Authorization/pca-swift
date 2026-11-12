import XCTest
@testable import AtlasPCAVerify

/// A fault after every core check passed must deny (cross-language check: pcactn.ts turns a throw there into 'malformed').
/// `PCA.verify` cannot throw (no hooks, a non-throwing signature), so the faults that can come after the core checks are the
/// authorize callbacks: the last one, the replay claim, and the revocation hook. Each must deny, never leave allow standing.
final class AuthorizeLastStepFaultTests: XCTestCase {
    private struct Boom: Error {}
    private struct ThrowingStore: PCAStateStore {
        func claim(key: String, counter: Int64) throws -> ClaimResult { throw Boom() }
        func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool { throw Boom() }
    }

    func testTheControlIsAllowed() {
        XCTAssertTrue(AZ.run(AZ.signed()).allow)
    }

    func testAThrowingReplayClaimDenies() {
        let r = AZ.run(AZ.signed()) { $0.stateStore = ThrowingStore() }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.checks["replay"], .fail)
        XCTAssertEqual(r.reason, "replay: the replay store failed (fail closed)")
    }

    func testAThrowingRevocationHookDenies() {
        let r = AZ.run(AZ.signed()) { $0.isRevoked = { _, _ in throw Boom() } }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["revocation"], .fail)
    }
}
