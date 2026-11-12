import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the StoreConformance.swift survivors of group 5 by running the conformance helpers against RECORDING stores and asserting the exact
/// trace the helpers must produce (which handle, which counter, how many handles are opened, which are closed, how often restart runs).
final class S2G5Log: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [String] = []
    func add(_ e: String) {
        lock.lock()
        events.append(e)
        lock.unlock()
    }
    func all() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return events
    }
    func has(_ prefix: String) -> [String] { all().filter { $0.hasPrefix(prefix) } }
}

private func s2g5Prefix(_ key: String) -> String { String(key.split(separator: ":").last ?? "") }

final class S2G5RecState: PCAStateStore, @unchecked Sendable {
    let inner: PCAStateStore
    let serial: Int
    let log: S2G5Log
    init(inner: PCAStateStore, serial: Int, log: S2G5Log) {
        self.inner = inner
        self.serial = serial
        self.log = log
    }
    func claim(key: String, counter: Int64) throws -> ClaimResult {
        let r = try inner.claim(key: key, counter: counter)
        log.add("c|\(s2g5Prefix(key))|\(serial)|\(counter)|\(r.ok)")
        return r
    }
}

final class S2G5StateRig: @unchecked Sendable {
    let backend: PCAStateStore = MemoryStateStore()
    let log = S2G5Log()
    private let lock = NSLock()
    private var opens = 0
    private var restartCount = 0
    var restarts: Int {
        lock.lock()
        defer { lock.unlock() }
        return restartCount
    }

    func open() throws -> (store: any PCAStateStore, close: () -> Void) {
        lock.lock()
        opens += 1
        let s = opens
        lock.unlock()
        log.add("open|\(s)")
        let l = log
        return (S2G5RecState(inner: backend, serial: s, log: log), { l.add("close|\(s)") })
    }

    func conf(durable: Bool, shared: Bool, rounds: Int, copies: Int, handles: Int) -> StateStoreConformance {
        StateStoreConformance(name: "rig", open: { try self.open() }, restart: { self.lock.lock(); self.restartCount += 1; self.lock.unlock() },
                              durable: durable, shared: shared, rounds: rounds, copies: copies, handles: handles)
    }
}

/// Throws on any claim that is not strictly newer than the head (instead of answering `ok: false`).
final class S2G5ThrowingStaleStore: PCAStateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var heads: [String: Int64] = [:]
    func claim(key: String, counter: Int64) throws -> ClaimResult {
        lock.lock()
        defer { lock.unlock() }
        if let c = heads[key], !(counter > c) { throw PCAFailure("stale") }
        heads[key] = counter
        return ClaimResult(ok: true)
    }
}

final class S2G5StateConformanceKillTests: XCTestCase {
    private func status(_ r: StoreConformanceReport, _ name: String) -> String? { r.checks.first { $0.name == name }?.status }
    private func note(_ r: StoreConformanceReport, _ name: String) -> String { r.checks.first { $0.name == name }?.note ?? "" }
    /// The event without its trailing ok flag.
    private func noOk(_ es: [String]) -> [String] { es.map { String($0.split(separator: "|", omittingEmptySubsequences: false).dropLast().joined(separator: "|")) } }

    func testInitDefaults() {
        let c = StateStoreConformance(name: "d", open: { (MemoryStateStore(), {}) })
        XCTAssertFalse(c.durable, "line 102")
        XCTAssertFalse(c.shared, "line 102")
        XCTAssertEqual(c.rounds, 10)
        XCTAssertEqual(c.copies, 16)
        XCTAssertEqual(c.handles, 4)
        XCTAssertNil(c.restart)
        let o = OperationStoreConformance(name: "d", open: { (MemoryOperationStore(), {}) })
        XCTAssertFalse(o.durable, "line 273")
        XCTAssertFalse(o.shared, "line 273")
        XCTAssertEqual(o.copies, 16)
        XCTAssertNil(o.restart)
    }

    func testFullDurableSharedTrace() {
        let rig = S2G5StateRig()
        let r = rig.conf(durable: true, shared: true, rounds: 2, copies: 4, handles: 3).run()
        XCTAssertTrue(r.ok, r.description)
        for n in ["claim-burst", "claim-concurrent", "claim-durability", "crash-after-claim", "retry-after-timeout"] { XCTAssertEqual(status(r, n), "pass", n) }
        XCTAssertEqual(note(r, "claim-concurrent"), "2 rounds x 4 copies over 3 handle(s)")
        XCTAssertEqual(rig.log.has("open|"), (1...10).map { "open|\($0)" }, "handles opened: 1 burst, 3 concurrent, 1 durability, 1 reopen, 1 crash, 1 reopen, 2 retry")
        XCTAssertEqual(Set(rig.log.has("close|")), Set((1...10).map { "close|\($0)" }), "every handle is closed")
        XCTAssertEqual(rig.log.has("close|").count, 10)
        XCTAssertEqual(rig.restarts, 2, "restart runs once in claim-durability and once in crash-after-claim (lines 224, 235)")

        let burst = (1...25).map { "c|burst|1|\($0)|true" } + (1...25).reversed().map { "c|burst|1|\($0)|false" } + ["c|burst|1|26|true"]
        XCTAssertEqual(rig.log.has("c|burst|"), burst, "lines 150, 155, 160")
        XCTAssertEqual(rig.log.has("c|burst-other|"), ["c|burst-other|1|1|true"], "line 163")
        XCTAssertEqual(rig.log.has("c|durability|"), ["c|durability|5|1|true", "c|durability|5|2|true", "c|durability|5|3|true",
                                                       "c|durability|6|3|false", "c|durability|6|4|true"], "lines 214, 225")
        XCTAssertEqual(rig.log.has("c|crash|"), ["c|crash|7|1|true", "c|crash|8|1|false", "c|crash|8|2|true"], "lines 233, 236")
        XCTAssertEqual(rig.log.has("c|retry|"), ["c|retry|9|1|true", "c|retry|10|1|false", "c|retry|10|2|true"], "lines 243, 251, 253")

        // 2 rounds x 4 copies over handles 2,3,4: copy i uses handle 2 + (i % 3)
        let conc = rig.log.has("c|concurrent|")
        XCTAssertEqual(noOk(conc).sorted(), ["c|concurrent|2|1", "c|concurrent|2|1", "c|concurrent|2|2", "c|concurrent|2|2",
                                              "c|concurrent|3|1", "c|concurrent|3|2", "c|concurrent|4|1", "c|concurrent|4|2"])
        XCTAssertEqual(conc.filter { $0.hasSuffix("|1|true") || $0.hasSuffix("|2|true") }.count, 2, "exactly one winner per round")
        // distinct counters 3...6 raced on handles (n % 3), then replayed on handle 1 of the race (serial 2)
        let dist = rig.log.has("c|concurrent-distinct|")
        XCTAssertEqual(dist.count, 8)
        XCTAssertEqual(noOk(Array(dist[0..<4])).sorted(), ["c|concurrent-distinct|2|5", "c|concurrent-distinct|3|3", "c|concurrent-distinct|3|6", "c|concurrent-distinct|4|4"],
                       "line 187")
        XCTAssertTrue(dist[0..<4].contains("c|concurrent-distinct|3|6|true"), "the highest counter is admitted")
        XCTAssertEqual(Array(dist[4..<8]), ["c|concurrent-distinct|2|3|false", "c|concurrent-distinct|2|4|false", "c|concurrent-distinct|2|5|false",
                                            "c|concurrent-distinct|2|6|false"], "line 195")
    }

    func testSingleHandleSmallRace() {
        let rig = S2G5StateRig()
        let r = rig.conf(durable: false, shared: true, rounds: 1, copies: 1, handles: 1).run()
        XCTAssertTrue(r.ok, r.description)
        XCTAssertEqual(status(r, "claim-durability"), "skip")
        XCTAssertEqual(status(r, "crash-after-claim"), "skip")
        XCTAssertEqual(note(r, "claim-concurrent"), "1 rounds x 1 copies over 1 handle(s)", "lines 131, 172")
        XCTAssertEqual(rig.log.has("open|"), ["open|1", "open|2", "open|3", "open|4"])
        XCTAssertEqual(rig.log.has("c|concurrent|"), ["c|concurrent|2|1|true"])
        XCTAssertEqual(rig.log.has("c|concurrent-distinct|"), ["c|concurrent-distinct|2|2|true", "c|concurrent-distinct|2|2|false"])
        XCTAssertEqual(rig.log.has("c|retry|"), ["c|retry|3|1|true", "c|retry|4|1|false", "c|retry|4|2|true"])
        XCTAssertEqual(rig.restarts, 0)
    }

    func testUnsharedUsesOneHandle() {
        let rig = S2G5StateRig()
        let r = rig.conf(durable: false, shared: false, rounds: 1, copies: 1, handles: 4).run()
        XCTAssertTrue(r.ok, r.description)
        XCTAssertEqual(note(r, "claim-concurrent"), "1 rounds x 1 copies over 1 handle(s)", "line 131: not shared is one handle")
        XCTAssertEqual(rig.log.has("open|"), ["open|1", "open|2", "open|3", "open|4"])
        XCTAssertEqual(rig.log.has("c|retry|"), ["c|retry|3|1|true", "c|retry|3|1|false", "c|retry|3|2|true"], "an unshared store retries on the same handle")
    }

    /// handles, rounds and copies below 1 count as 1 (a mutant that lets them reach 0 traps on an empty range / modulo by zero).
    func testNonPositiveSizesCountAsOne() {
        let rig = S2G5StateRig()
        let r = rig.conf(durable: false, shared: true, rounds: 0, copies: 0, handles: 0).run()
        XCTAssertTrue(r.ok, r.description)
        XCTAssertEqual(note(r, "claim-concurrent"), "1 rounds x 1 copies over 1 handle(s)")
    }

    func testAStoreThatThrowsOnStaleClaimsIsCaught() {
        let shared = S2G5ThrowingStaleStore()
        let r = StateStoreConformance(name: "throwing", open: { (shared, {}) }, shared: true).run()
        XCTAssertEqual(status(r, "claim-burst"), "fail")
        XCTAssertTrue(note(r, "claim-burst").hasPrefix("replay of counter 25 errored: stale"), "line 157: \(note(r, "claim-burst"))")
        XCTAssertEqual(status(r, "claim-concurrent"), "fail")
        XCTAssertTrue(note(r, "claim-concurrent").contains("is admitted again after the race (err stale)"), "line 196: \(note(r, "claim-concurrent"))")
    }

    // ---- the lossy wrapper and the counter ----

    func testLossyStoreLosesOnlyTheFirstAnswer() throws {
        let l = LossyStateStore(MemoryStateStore())
        XCTAssertThrowsError(try l.claim(key: "k", counter: 1)) { XCTAssertEqual(errorMessage($0), "timeout (answer lost after commit)") }
        XCTAssertTrue(try l.claim(key: "k", counter: 2).ok, "line 78: only the first answer is lost")
        XCTAssertTrue(try l.claim(key: "k", counter: 3).ok)
        // the first claim did commit
        XCTAssertFalse(try l.inner.claim(key: "k", counter: 1).ok)
    }

    /// Exactly one of many concurrent first claims loses its answer (lines 76, 79 guard that read-modify-write).
    func testLossyStoreLosesExactlyOnceUnderRace() {
        let l = LossyStateStore(MemoryStateStore())
        let thrown = ConformanceCounter()
        DispatchQueue.concurrentPerform(iterations: 64) { i in
            do { _ = try l.claim(key: "k\(i)", counter: 1) } catch { thrown.add() }
        }
        XCTAssertEqual(thrown.value, 1)
    }

    func testConformanceCounterIsExactUnderRace() {
        let c = ConformanceCounter()
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            for _ in 0..<5000 { c.add() }
            c.add(3)
        }
        XCTAssertEqual(c.value, 8 * 5003, "lines 53, 58")
    }
}

// ---- operation stores ----

final class S2G5RecOp: OperationStore, @unchecked Sendable {
    let inner: OperationStore
    let serial: Int
    let log: S2G5Log
    init(inner: OperationStore, serial: Int, log: S2G5Log) {
        self.inner = inner
        self.serial = serial
        self.log = log
    }
    func create(_ record: OperationRecord) throws -> OperationCreate {
        let r = try inner.create(record)
        var kind = "created"
        if case .existing = r { kind = "existing" }
        log.add("o|create|\(s2g5Prefix(record.id))|\(serial)|\(record.startedAt)|\(kind)")
        return r
    }
    func get(_ id: String) throws -> OperationRecord? {
        log.add("o|get|\(s2g5Prefix(id))|\(serial)")
        return try inner.get(id)
    }
    func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool {
        let r = try inner.transition(id, from: from, to: next)
        log.add("o|transition|\(s2g5Prefix(id))|\(serial)|\(from.rawValue)|\(next.state.rawValue)|\(r)")
        return r
    }
}

final class S2G5OpRig: @unchecked Sendable {
    let backend: OperationStore
    let log = S2G5Log()
    private let lock = NSLock()
    private var opens = 0
    private var restartCount = 0
    var restarts: Int {
        lock.lock()
        defer { lock.unlock() }
        return restartCount
    }
    init(backend: OperationStore = MemoryOperationStore()) { self.backend = backend }

    func open() throws -> (store: any OperationStore, close: () -> Void) {
        lock.lock()
        opens += 1
        let s = opens
        lock.unlock()
        log.add("open|\(s)")
        let l = log
        return (S2G5RecOp(inner: backend, serial: s, log: log), { l.add("close|\(s)") })
    }

    func conf(durable: Bool, shared: Bool, copies: Int) -> OperationStoreConformance {
        OperationStoreConformance(name: "rig", open: { try self.open() }, restart: { self.lock.lock(); self.restartCount += 1; self.lock.unlock() },
                                  durable: durable, shared: shared, copies: copies)
    }

    /// The trace events for one id prefix, without the leading "o|".
    func events(_ idPrefix: String) -> [String] {
        log.has("o|").filter { $0.split(separator: "|", omittingEmptySubsequences: false)[2] == idPrefix }
    }
}

/// create: first caller gets `.created`, every other caller gets a record of ANOTHER id.
final class S2G5ForeignExistingStore: OperationStore, @unchecked Sendable {
    private let lock = NSLock()
    private var first = true
    func create(_ record: OperationRecord) throws -> OperationCreate {
        lock.lock()
        defer { lock.unlock() }
        if first {
            first = false
            return .created
        }
        var other = record
        other.id = "foreign"
        return .existing(other)
    }
    func get(_ id: String) throws -> OperationRecord? { nil }
    func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool { false }
}

/// create never creates (always says another record exists).
final class S2G5NoCreateStore: OperationStore, @unchecked Sendable {
    func create(_ record: OperationRecord) throws -> OperationCreate {
        var other = record
        other.id = "foreign"
        return .existing(other)
    }
    func get(_ id: String) throws -> OperationRecord? { nil }
    func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool { false }
}

final class S2G5OperationConformanceKillTests: XCTestCase {
    private func status(_ r: StoreConformanceReport, _ name: String) -> String? { r.checks.first { $0.name == name }?.status }
    private func note(_ r: StoreConformanceReport, _ name: String) -> String { r.checks.first { $0.name == name }?.note ?? "" }
    private func noResult(_ es: [String]) -> [String] { es.map { String($0.split(separator: "|", omittingEmptySubsequences: false).dropLast().joined(separator: "|")) } }

    func testFullDurableSharedTrace() {
        let rig = S2G5OpRig()
        let r = rig.conf(durable: true, shared: true, copies: 4).run()
        XCTAssertTrue(r.ok, r.description)
        for n in ["create-once", "transition-once", "wrong-state", "get-missing", "shared", "durability"] { XCTAssertEqual(status(r, n), "pass", n) }
        XCTAssertEqual(rig.log.has("open|"), (1...10).map { "open|\($0)" }, "2 + 2 + 1 + 1 + 2 + 1 + 1 handles (lines 301, 313, 324, 335, 343)")
        XCTAssertEqual(Set(rig.log.has("close|")), Set((1...10).map { "close|\($0)" }), "lines 373-376: every handle is closed")
        XCTAssertEqual(rig.log.has("close|").count, 10)
        XCTAssertEqual(rig.restarts, 1, "line 380")

        let create = rig.events("create")
        XCTAssertEqual(noResult(create).sorted(), ["o|create|create|1|1", "o|create|create|1|1", "o|create|create|2|1", "o|create|create|2|1"], "lines 283, 300, 301")
        XCTAssertEqual(create.filter { $0.hasSuffix("|created") }.count, 1)

        let tr = rig.events("transition")
        XCTAssertEqual(tr.first, "o|create|transition|3|1|created", "the creator is the first handle")
        XCTAssertEqual(noResult(Array(tr.dropFirst())).sorted(),
                       ["o|transition|transition|3|pending|executing", "o|transition|transition|3|pending|executing",
                        "o|transition|transition|4|pending|executing", "o|transition|transition|4|pending|executing"], "line 313")
        XCTAssertEqual(tr.filter { $0.hasSuffix("|true") }.count, 1)

        XCTAssertEqual(rig.events("wrong"), ["o|create|wrong|5|1|created", "o|transition|wrong|5|executing|committed|false", "o|get|wrong|5"], "line 329")
        XCTAssertEqual(rig.events("missing"), ["o|transition|missing|5|pending|committed|false"])
        XCTAssertEqual(rig.events("never"), ["o|get|never|6"], "line 335")
        XCTAssertEqual(rig.events("shared"), ["o|create|shared|7|1|created", "o|get|shared|8"], "lines 343, 345, 346")
        XCTAssertEqual(rig.events("durable"), ["o|create|durable|9|1|created", "o|get|durable|10"])
    }

    func testUnsharedNotDurableTrace() {
        let rig = S2G5OpRig()
        let r = rig.conf(durable: false, shared: false, copies: 1).run()
        XCTAssertTrue(r.ok, r.description)
        XCTAssertEqual(rig.log.has("open|"), ["open|1", "open|2", "open|3", "open|4"], "one handle per check when not shared")
        XCTAssertEqual(rig.events("create"), ["o|create|create|1|1|created"], "lines 300, 301: one copy, one handle")
        XCTAssertEqual(rig.events("transition"), ["o|create|transition|2|1|created", "o|transition|transition|2|pending|executing|true"], "line 313")
        XCTAssertEqual(rig.events("never"), ["o|get|never|4"])
        let shared = r.checks.first { $0.name == "shared" }
        XCTAssertEqual(shared?.status, "skip", "line 350")
        XCTAssertEqual(shared?.note, "shared is false")
        XCTAssertEqual(status(r, "durability"), "skip")
        XCTAssertEqual(rig.restarts, 0)
    }

    func testZeroCopiesCountAsOne() {
        let rig = S2G5OpRig()
        let r = rig.conf(durable: false, shared: false, copies: 0).run()
        XCTAssertTrue(r.ok, r.description)
        XCTAssertEqual(rig.events("create").count, 1, "line 300: copies below 1 count as 1")
    }

    func testALoserWithoutTheExistingRecordIsCountedAsOneHundred() {
        let r = OperationStoreConformance(name: "foreign", open: { (S2G5ForeignExistingStore(), {}) }, copies: 2).run()
        XCTAssertEqual(status(r, "create-once"), "fail")
        XCTAssertTrue(note(r, "create-once").hasPrefix("101 concurrent creates of one id reported created"), "line 307: \(note(r, "create-once"))")
    }

    func testAFailedCreateInDurabilityStillClosesTheHandle() {
        let rig = S2G5OpRig(backend: S2G5NoCreateStore())
        let r = rig.conf(durable: true, shared: false, copies: 1).run()
        XCTAssertEqual(status(r, "durability"), "fail")
        XCTAssertEqual(note(r, "durability"), "create failed", "line 372")
        let opened = rig.log.has("open|").count
        XCTAssertEqual(rig.log.has("close|").count, opened, "line 373: the handle of the failed create is closed")
    }
}
