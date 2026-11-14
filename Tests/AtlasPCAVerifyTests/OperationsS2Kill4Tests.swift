import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Operation records (T3): the error text, the settle/finish helpers, the stores and the wall clock (operations.ts).
final class S2G4OperationsKillTests: XCTestCase {
    struct LocErr: LocalizedError { var errorDescription: String? { "loc boom" } }
    struct Plain: Error {}

    final class Box: @unchecked Sendable {
        var value: OperationRecord?
    }

    /// Lets the claim and the first transition through, then refuses every later write.
    final class FailingFinishStore: OperationStore, @unchecked Sendable {
        struct Boom: Error {}
        let inner = MemoryOperationStore()
        private var transitions = 0
        func create(_ record: OperationRecord) throws -> OperationCreate { inner.create(record) }
        func get(_ id: String) throws -> OperationRecord? { inner.get(id) }
        func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool {
            transitions += 1
            if transitions >= 2 { throw Boom() }
            return inner.transition(id, from: from, to: next)
        }
    }

    func rec(_ id: String, _ st: OperationState, startedAt: Int64 = 1, executingAt: Int64? = nil) -> OperationRecord {
        OperationRecord(id: id, state: st, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: startedAt, executingAt: executingAt)
    }

    func wallMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // ---- error text and outcome defaults ----

    func testErrorMessage() {
        XCTAssertEqual(errorMessage(PCAFailure("recorded verbatim")), "recorded verbatim")
        XCTAssertEqual(errorMessage(LocErr()), "loc boom", "a LocalizedError is recorded by its description")
        XCTAssertEqual(errorMessage(Plain()), String(describing: Plain()))
    }

    func testOutcomesAreNotRecordedByDefault() {
        XCTAssertFalse(ExecuteOutcome(.failed, id: "x", error: "e").recorded)
        XCTAssertFalse(ExecuteOutcome(.pending, id: "x").recorded)
        XCTAssertFalse(ExecuteOutcome(.refused, reason: "r").recorded)
        XCTAssertFalse(ExecuteOutcome(.committed, id: "x").replayed)
    }

    // ---- the memory store ----

    func testTransitionStoresTheRecordUnderTheTransitionId() {
        let s = MemoryOperationStore()
        _ = s.create(rec("a", .pending))
        XCTAssertTrue(s.transition("a", from: .pending, to: rec("zzz", .executing)))
        XCTAssertEqual(s.get("a")?.id, "a")
        XCTAssertEqual(s.get("a")?.state, .executing)
        XCTAssertNil(s.get("zzz"))
    }

    /// Not a deterministic kill for a dropped lock (a data race is probabilistic); it must at least stay correct under contention.
    func testStoresStayConsistentUnderContention() {
        let s = MemoryOperationStore()
        let kv = MemoryAtomicKV()
        DispatchQueue.concurrentPerform(iterations: 4) { t in
            for i in 0..<100 {
                let id = "t\(t)-\(i)"
                _ = s.create(self.rec(id, .pending))
                _ = s.get(id)
                _ = s.listOpen()
                kv.update(id) { _ in JSONValue.int(1) }
                _ = kv.get(id)
            }
        }
        XCTAssertEqual(s.listOpen().count, 400)
        XCTAssertEqual(kv.get("t0-0"), JSONValue.int(1))
    }

    // ---- settleStale ----

    func testAnExecutingRecordWithoutAMarkerAgesFromItsClaim() throws {
        let store = MemoryOperationStore()
        // executingAt == 0 is "no marker": aged from startedAt (1_000_000), 500 ms old against a 1000 ms timeout
        let fresh = try PCA.settleStale(store, rec("a", .executing, startedAt: 1_000_000, executingAt: 0), 1_000_500, 1000)
        XCTAssertEqual(fresh.state, .executing)
        // executingAt == 1 is a marker: aged from 1, far over the timeout
        let marked = try PCA.settleStale(store, rec("a", .executing, startedAt: 1_000_000, executingAt: 1), 1_000_500, 1000)
        XCTAssertEqual(marked.state, .uncertain)
        XCTAssertEqual(marked.finishedAt, 1_000_500)
    }

    // ---- finishRecord / answerCurrent ----

    func testFinishRecordRetriesFromUncertainOnlyForAnExecutingRecord() throws {
        func put(_ st: OperationState) -> MemoryOperationStore {
            let s = MemoryOperationStore()
            _ = s.create(rec("a", st))
            return s
        }
        // recovery settled the slow execution meanwhile: stored uncertain, ours executing
        let s1 = put(.uncertain)
        XCTAssertTrue(try PCA.finishRecord(s1, rec("a", .executing)) { $0.state = .committed })
        XCTAssertEqual(s1.get("a")?.state, .committed)
        // a pending record does not retry
        let s2 = put(.uncertain)
        XCTAssertFalse(try PCA.finishRecord(s2, rec("a", .pending)) { $0.state = .aborted })
        XCTAssertEqual(s2.get("a")?.state, .uncertain)
        // the plain case
        let s3 = put(.executing)
        XCTAssertTrue(try PCA.finishRecord(s3, rec("a", .executing)) { $0.state = .failed })
        XCTAssertEqual(s3.get("a")?.state, .failed)
        // nothing stored
        XCTAssertFalse(try PCA.finishRecord(MemoryOperationStore(), rec("a", .executing)) { $0.state = .failed })
    }

    func testAnswerCurrent() {
        let s = MemoryOperationStore()
        XCTAssertEqual(PCA.answerCurrent(s, "gone", 10, 1000), ExecuteOutcome(.uncertain, id: "gone", reason: "the operation record disappeared", replayed: true))
        var done = rec("a", .committed)
        done.result = JSONValue.string("r")
        _ = s.create(done)
        XCTAssertEqual(PCA.answerCurrent(s, "a", 10, 1000), ExecuteOutcome(.committed, id: "a", result: JSONValue.string("r"), replayed: true, recorded: true))
    }

    // ---- the wall clock ----

    func testTheDefaultOptionClockIsTheWallClockInMilliseconds() {
        XCTAssertLessThan(abs(ExecuteOptions().clock() - wallMs()), 60_000)
    }

    func testRecoveryReadsTheWallClockInMilliseconds() throws {
        let s = MemoryOperationStore()
        _ = s.create(rec("old", .pending, startedAt: wallMs() - 600_000))
        _ = s.create(rec("new", .pending, startedAt: wallMs()))
        XCTAssertEqual(try PCA.recoverOperation(s, id: "old")?.state, .aborted, "ten minutes old against the 5 minute default")
        XCTAssertEqual(try PCA.recoverOperation(s, id: "new")?.state, .pending, "just claimed")
    }

    func testResolveStampsTheWallClockInMilliseconds() throws {
        let s = MemoryOperationStore()
        _ = s.create(rec("u", .uncertain))
        XCTAssertTrue(try PCA.resolveOperation(s, id: "u", outcome: .failed(error: "never applied")))
        let at = try XCTUnwrap(s.get("u")?.finishedAt)
        XCTAssertLessThan(abs(at - wallMs()), 60_000)
    }

    // ---- executeAuthorized ----

    func testTheRecordIsExecutingWhileFnRuns() async throws {
        let store = MemoryOperationStore()
        let box = Box()
        let o = await PCA.executeAuthorized(OperationRecordTests.authorization(id: "op-x"), options: ExecuteOptions(store: store, now: { 1000 })) { _ in
            box.value = store.get("op-x")
            return JSONValue.string("done")
        }
        XCTAssertEqual(o.status, .committed)
        XCTAssertEqual(box.value?.state, .executing)
        XCTAssertEqual(box.value?.executingAt, 1000)
        XCTAssertEqual(store.get("op-x")?.state, .committed)
    }

    func testACommitThatCannotBeWrittenIsNotRecorded() async throws {
        let store = FailingFinishStore()
        let o = await PCA.executeAuthorized(OperationRecordTests.authorization(id: "op-y"), options: ExecuteOptions(store: store, now: { 1000 })) { _ in
            JSONValue.string("done")
        }
        XCTAssertEqual(o.status, .committed)
        XCTAssertEqual(o.result, JSONValue.string("done"))
        XCTAssertFalse(o.recorded, "fn ran but the record stays executing")
        XCTAssertEqual(store.inner.get("op-y")?.state, .executing)
    }
}
