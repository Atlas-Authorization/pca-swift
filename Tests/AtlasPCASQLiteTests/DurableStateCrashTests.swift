import XCTest
import Foundation
import AtlasPCAVerify

/// Real SIGKILL crash safety of the durable state (the Rust lane's `tests/durable_state.rs`): the worker executable writes a value and kills itself at a named step of
/// the write; the parent then reopens the directory. Skipped when the worker executable is not next to the test bundle.
final class DurableStateCrashTests: XCTestCase {
    func tmp() throws -> String {
        let d = NSTemporaryDirectory() + "pca-ds-crash-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(atPath: d) }
        return d
    }

    /// Seeds `k = old`, then runs the worker that sets `k = new` and dies at `point`; answers the directory.
    func crashAt(_ point: String) throws -> String {
        let worker = Bundle(for: DurableStateCrashTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent("pca-state-worker")
        guard FileManager.default.isExecutableFile(atPath: worker.path) else { throw XCTSkip("pca-state-worker is not next to the test bundle") }
        let d = try tmp()
        try openDurableState(DurableStateOptions(dir: d)).set("k", .string("old"))
        let p = Process()
        p.executableURL = worker
        p.arguments = ["durable-set", d, "new"]
        var env = ProcessInfo.processInfo.environment
        env["PCA_DURABLE_TEST"] = "1"
        env["PCA_DURABLE_TEST_RECOVER_CRASH_AT"] = point
        p.environment = env
        try p.run()
        p.waitUntilExit()
        XCTAssertEqual(p.terminationReason, .uncaughtSignal, "the child must die by a signal")
        XCTAssertEqual(p.terminationStatus, SIGKILL, "the child must die by SIGKILL")
        return d
    }

    func testKilledBetweenTheTempWriteAndTheRenameTheOldStateIsIntactAndTheDeadLockIsTakenOver() throws {
        let d = try crashAt("after-temp-write")
        let s = try openDurableState(DurableStateOptions(dir: d, lockTimeoutMs: 5_000))
        XCTAssertEqual(try s.get("k"), .string("old"))
        try s.set("k", .string("later"))
        _ = try s.verify()
    }

    func testKilledAfterTheJournalRenameTheNewValueIsDurableAndTheHeadIsRepaired() throws {
        let d = try crashAt("after-journal-rename")
        let s = try openDurableState(DurableStateOptions(dir: d, lockTimeoutMs: 5_000))
        XCTAssertEqual(try s.get("k"), .string("new"))
        let head = try String(contentsOfFile: d + "/state.head", encoding: .utf8)
        let seq = try s.verify().seq
        XCTAssertTrue(head.contains("\"seq\":\(seq)"), "the open repaired the head: \(head)")
    }
}
