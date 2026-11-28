import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Behavioural tests of the conformance runner: the good adapters pass, every bad adapter is flagged (a checker that passes everything is worthless).
final class StoreConformanceRunnerTests: XCTestCase {
    typealias C = PCAStoreConformance

    static func small(_ tests: [String]? = nil) -> C.ConformanceOptions {
        var o = C.ConformanceOptions()
        o.tests = tests
        o.workload.clients = 6
        o.workload.durationMs = 300
        o.workload.rounds = 6
        o.workload.revisitKeys = 40
        o.workload.seed = 11
        return o
    }

    func testTheInMemoryAdapterPassesAndSkipsWhatItCannotDo() throws {
        let r = try C.runConformance(C.inMemoryAdapter(), Self.small())
        let rep = try r.format()
        XCTAssertEqual(r.status, "pass", rep)
        XCTAssertEqual(r.tests.count, 10) // 5 tests x (consume, advance)
        XCTAssertEqual(r.tests.filter { $0.test == "durability" }.map { $0.status }, ["skip", "skip"])
        XCTAssertEqual(r.tests.filter { $0.test == "crash" }.map { $0.status }, ["skip", "skip"])
        XCTAssertTrue(try r.format().hasPrefix("pca-store-conformance: in-memory (MemoryStateStore) -> PASS"))
        XCTAssertTrue(r.jsonText().contains("\"adapter\""))
        XCTAssertNoThrow(try C.assertConformance(C.inMemoryAdapter(), Self.small(["burst"])))
    }

    func testTheDurableFileAdapterPassesDurabilityAndTheCrashRun() throws {
        let dir = NSTemporaryDirectory() + "pcasc-test-" + UUID().uuidString
        defer { try? FileManager.default.removeItem(atPath: dir) }
        var o = Self.small(["burst", "durability", "crash"])
        var crash = C.CrashOptions(adapters: { C.durableFileAdapter(dir: dir) })
        crash.processes = 2
        crash.killEveryMs = 150
        crash.workload.clients = 2
        crash.workload.durationMs = 600
        o.crash = crash
        let r = try C.runConformance(C.durableFileAdapter(dir: dir), o)
        let rep = try r.format()
        XCTAssertNotEqual(r.status, "fail", rep)
        XCTAssertEqual(r.tests.filter { $0.test == "durability" }.map { $0.status }, ["pass", "pass"])
    }

    func testEveryBadAdapterIsFlagged() throws {
        XCTAssertEqual(try C.runTest(C.readThenWriteAdapter(), "burst", "consume", Self.small()).status, "fail")
        XCTAssertEqual(try C.runTest(C.volatileAdapter(), "durability", "consume", Self.small()).status, "fail")
        XCTAssertEqual(try C.runTest(C.volatileAdapter(), "durability", "advance", Self.small()).status, "fail")
        XCTAssertEqual(try C.runTest(C.evictingAdapter(capacity: 8), "retention", "consume", Self.small()).status, "fail")
        var many = Self.small()
        many.workload.clients = 8 // enough same-value pairs over the rounds that an equal counter is certainly accepted twice
        many.workload.rounds = 20
        XCTAssertEqual(try C.runTest(C.nonStrictCounterAdapter(), "burst", "advance", many).status, "fail")
    }

    func testDetectKindsAndTheBuiltinTable() throws {
        XCTAssertEqual(try C.detectKinds(C.inMemoryAdapter()), ["consume", "advance"])
        XCTAssertEqual(try C.detectKinds(C.nonStrictCounterAdapter()), ["advance"])
        XCTAssertEqual(Set(C.REFERENCE_ADAPTERS.keys), ["in-memory", "durable-file", "bad-read-then-write", "bad-volatile", "bad-evicting", "bad-non-strict-counter"])
        XCTAssertTrue(C.REFERENCE_ADAPTERS["bad-evicting"]!(["capacity": "3"]).name.contains("capacity 3"))
        XCTAssertThrowsError(try C.runTest(C.inMemoryAdapter(), "nope", "consume", Self.small()))
    }

    func testRandomNamespacesDiffer() { XCTAssertNotEqual(C.randomNamespace(), C.randomNamespace()) }
}

final class StoreConformanceLoadTests: XCTestCase {
    typealias C = PCAStoreConformance

    func testBuiltinAndRegisteredAdaptersLoadAndTheRestIsRefused() throws {
        XCTAssertTrue(try C.loadAdapter("builtin:in-memory").name.hasPrefix("in-memory"))
        XCTAssertTrue(try C.loadAdapter("builtin:bad-evicting", ["capacity": "5"]).name.contains("capacity 5"))
        XCTAssertThrowsError(try C.loadAdapter("builtin:nope"))
        XCTAssertThrowsError(try C.loadAdapter("registered:never-registered"))
        XCTAssertThrowsError(try C.loadAdapter("./adapter.js"))
        C.registerAdapter("mine") { _ in C.inMemoryAdapter() }
        XCTAssertTrue(try C.loadAdapter("registered:mine").name.hasPrefix("in-memory"))
    }
}
