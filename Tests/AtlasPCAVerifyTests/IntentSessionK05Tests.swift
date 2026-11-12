import XCTest
@testable import AtlasPCAVerify

/// The fail-closed backstops behind `shapeError`, reached through the `verifyShapedRoot` seam (the reference's catch in
/// packages/pca/src/intent-session.ts:340-341 refuses the same inputs).
final class IntentSessionK05Tests: XCTestCase {
    private static let MALFORMED = "malformed session root"

    func testANonObjectOrSignerlessRootIsRefused() {
        let roots: [JSONValue] = [.null, .object([:]), .object(["signer": .int(1)])]
        for v in roots {
            let r = IntentSession.verifyShapedRoot(v, pqPins: nil)
            XCTAssertFalse(r.ok)
            XCTAssertEqual(r.reason, Self.MALFORMED)
        }
    }

    func testABodyTheCanonicalFormRefusesIsRefused() {
        let r = IntentSession.verifyShapedRoot(.object(["signer": .string("x"), "session": .double(.nan)]), pqPins: nil)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, Self.MALFORMED)
    }
}
