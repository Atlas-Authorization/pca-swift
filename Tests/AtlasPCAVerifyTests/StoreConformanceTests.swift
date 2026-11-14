import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The store conformance helper: it passes the in-memory stores and CATCHES stores that break the invariants the guards rely on
/// (a guard that has never failed proves nothing).
final class StoreConformanceTests: XCTestCase {
    /// Reads, pauses, then writes without holding anything across the gap: the textbook check-then-act race.
    final class RacyStateStore: PCAStateStore, @unchecked Sendable {
        private let lock = NSLock()
        private var heads: [String: Int64] = [:]
        func claim(key: String, counter: Int64) -> ClaimResult {
            lock.lock()
            let cur = heads[key]
            lock.unlock()
            if let c = cur, !(counter > c) { return ClaimResult(ok: false, lastCounter: c) }
            Thread.sleep(forTimeInterval: 0.002)
            lock.lock()
            heads[key] = counter
            lock.unlock()
            return ClaimResult(ok: true)
        }
    }

    /// Admits everything.
    struct ForgetfulStateStore: PCAStateStore {
        func claim(key: String, counter: Int64) -> ClaimResult { ClaimResult(ok: true) }
    }

    /// `create` always says it created the record.
    final class AlwaysCreatesStore: OperationStore, @unchecked Sendable {
        let inner = MemoryOperationStore()
        func create(_ record: OperationRecord) throws -> OperationCreate { _ = try inner.create(record); return .created }
        func get(_ id: String) throws -> OperationRecord? { try inner.get(id) }
        func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool { try inner.transition(id, from: from, to: next) }
    }

    /// Every transition applies, whatever the current state.
    final class AlwaysTransitionsStore: OperationStore, @unchecked Sendable {
        let inner = MemoryOperationStore()
        func create(_ record: OperationRecord) throws -> OperationCreate { try inner.create(record) }
        func get(_ id: String) throws -> OperationRecord? { try inner.get(id) }
        func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool { _ = try inner.transition(id, from: from, to: next); return true }
    }

    func status(_ r: StoreConformanceReport, _ name: String) -> String? { r.checks.first { $0.name == name }?.status }

    func testMemoryStateStorePasses() {
        let shared = MemoryStateStore()
        let r = StateStoreConformance(name: "memory", open: { (shared, {}) }, durable: false, shared: true).run()
        XCTAssertTrue(r.ok, r.description)
        XCTAssertEqual(status(r, "claim-burst"), "pass")
        XCTAssertEqual(status(r, "claim-concurrent"), "pass")
        XCTAssertEqual(status(r, "retry-after-timeout"), "pass")
        XCTAssertEqual(status(r, "claim-durability"), "skip", "a store that declares itself not durable is skipped, never passed")
        XCTAssertEqual(status(r, "crash-after-claim"), "skip")
    }

    func testARacyStoreIsCaught() {
        let shared = RacyStateStore()
        let r = StateStoreConformance(name: "racy", open: { (shared, {}) }, shared: true).run()
        XCTAssertFalse(r.ok, "a check-then-act claim must fail claim-concurrent\n\(r)")
        XCTAssertEqual(status(r, "claim-concurrent"), "fail")
        XCTAssertEqual(status(r, "claim-burst"), "pass", "the race only shows under concurrency")
    }

    func testAForgetfulStoreIsCaught() {
        let r = StateStoreConformance(name: "forgetful", open: { (ForgetfulStateStore(), {}) }, shared: true).run()
        XCTAssertEqual(status(r, "claim-burst"), "fail")
        XCTAssertFalse(r.ok)
    }

    func testAStoreThatForgetsAfterRestartIsCaught() {
        // "durable" per its declaration, but every handle is a fresh empty store
        let r = StateStoreConformance(name: "amnesiac", open: { (MemoryStateStore(), {}) }, durable: true, shared: true).run()
        XCTAssertEqual(status(r, "claim-durability"), "fail")
        XCTAssertEqual(status(r, "crash-after-claim"), "fail")
        XCTAssertEqual(status(r, "retry-after-timeout"), "fail", "a retry must not be admitted after a lost answer")
    }

    func testAnOpenFailureIsAFailedCheck() {
        struct Down: Error {}
        let r = StateStoreConformance(name: "down", open: { throw Down() }).run()
        XCTAssertFalse(r.ok)
    }

    func testMemoryOperationStorePasses() {
        let shared = MemoryOperationStore()
        let r = OperationStoreConformance(name: "memory", open: { (shared, {}) }, durable: false, shared: true).run()
        XCTAssertTrue(r.ok, r.description)
        XCTAssertEqual(r.checks.filter { $0.status == "pass" }.count, 5, r.description)
        XCTAssertEqual(status(r, "durability"), "skip")
    }

    func testBrokenOperationStoresAreCaught() {
        let a = OperationStoreConformance(name: "always-creates", open: { (AlwaysCreatesStore(), {}) }, shared: false).run()
        XCTAssertEqual(status(a, "create-once"), "fail")
        let b = OperationStoreConformance(name: "always-transitions", open: { (AlwaysTransitionsStore(), {}) }, shared: false).run()
        XCTAssertEqual(status(b, "transition-once"), "fail")
        XCTAssertEqual(status(b, "wrong-state"), "fail")
        let c = OperationStoreConformance(name: "amnesiac", open: { (MemoryOperationStore(), {}) }, durable: true).run()
        XCTAssertEqual(status(c, "durability"), "fail")
    }
}
