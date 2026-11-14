import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Lock kills (see S2LK) in classes whose names carry the source stem, so the mutation tool runs them first.
final class A0LockOperationsTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func rec(_ id: String, _ st: OperationState) -> OperationRecord {
        OperationRecord(id: id, state: st, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: 1)
    }

    /// Operations.swift lines 120, 128, 134 (create, get, transition).
    func testMemoryOperationStoreTakesItsLock() {
        let s = MemoryOperationStore()
        _ = S2LK.check(s.lock, "create") { s.create(rec("a", .pending)) }
        XCTAssertEqual(S2LK.check(s.lock, "get") { s.get("a") }?.id, "a")
        XCTAssertTrue(S2LK.check(s.lock, "transition") { s.transition("a", from: .pending, to: rec("a", .executing)) })
    }
}

final class A0LockBlueprintTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// Blueprint.swift line 65 (epoch), with accept and get alongside.
    func testBlueprintRegistryTakesItsLockOncePerCall() {
        let st = Blueprint.MemoryStore()
        let reg = Blueprint.Registry(operators: ["o"], store: st)
        S2LK.check(st.lock, "epoch") { _ = reg.epoch }
        S2LK.check(reg.lock, "accept") { _ = reg.accept(nil) }
        S2LK.check(st.lock, "get") { _ = try? reg.get("k") }
    }
}
