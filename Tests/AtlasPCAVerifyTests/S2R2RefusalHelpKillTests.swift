import XCTest
@testable import AtlasPCAVerify

/// explainRefusal finds the check by the leading [a-z_] run (RefusalHelp.swift:57); a reason with no colon is matched only by that run.
final class S2R2RefusalHelpKillTests: XCTestCase {
    func testHeadRunBounds() {
        XCTAssertEqual(explainRefusal("chain").check, "chain", "'a' is in the run")
        XCTAssertEqual(explainRefusal("authorize").check, "authorize", "'z' is in the run")
        XCTAssertEqual(explainRefusal("chain9").check, "chain", "the run stops at the first non-letter")
        XCTAssertEqual(explainRefusal("authorize_config").check, "authorize_config", "'_' is in the run")
        XCTAssertEqual(explainRefusal("authorize9").check, "authorize")
    }
}
