import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Blueprint.Registry takes its lock once per epoch / get call and gives it back (Blueprint.swift lines 65 and 71).
final class S2H3BlueprintLockTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testEpochAndGetTakeTheLockOnceAndReleaseIt() {
        let st = Blueprint.MemoryStore()
        let reg = Blueprint.Registry(operators: ["op"], store: st)
        XCTAssertEqual(S2LK.check(st.lock, "epoch") { reg.epoch }, 0)
        XCTAssertNil(S2LK.check(st.lock, "get") { (try? reg.get("nope")) ?? nil })
    }
}
