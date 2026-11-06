import XCTest
import Foundation
@testable import AtlasPCAVerify
import AtlasPCASQLite

/// The SQLite stores: the atomic single-statement claim, the durable operation records and the atomic key/value store the plan registry
/// runs on, each shared by several connections to one file (the race a cluster of verifier processes presents), plus the store
/// conformance helper run against them.
final class SQLiteStoreTests: XCTestCase {
    var path = ""

    override func setUp() {
        super.setUp()
        path = FileManager.default.temporaryDirectory.appendingPathComponent("pca-\(UUID().uuidString).sqlite").path
    }

    override func tearDown() {
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
        super.tearDown()
    }

    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func bump() { lock.lock(); n += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    }

    static func authorization(id: String) -> PCA.AuthorizeResult {
        PCA.AuthorizeResult(allow: true, status: 200, checks: [:], checkNames: [], reasons: [], reason: nil,
                            operation: PCA.AuthorizedOperation(verb: "payments.refund", resource: "/orders/1", paramsDigest: "d", id: id),
                            pcactn: .object(["action": .object(["reversibility_class": .string("reversible")])]), verdict: nil, missing: nil)
    }

    // ---- the replay store ----

    func testClaimSemantics() throws {
        let db = try SQLiteDatabase(path: path)
        let s = try SQLiteStateStore(database: db)
        XCTAssertNil(try s.last(key: "k"))
        XCTAssertEqual(try s.claim(key: "k", counter: 5), ClaimResult(ok: true))
        XCTAssertEqual(try s.last(key: "k"), 5)
        XCTAssertEqual(try s.claim(key: "k", counter: 5), ClaimResult(ok: false, lastCounter: 5))
        XCTAssertEqual(try s.claim(key: "k", counter: 3), ClaimResult(ok: false, lastCounter: 5))
        XCTAssertEqual(try s.claim(key: "k", counter: 6), ClaimResult(ok: true))
        XCTAssertEqual(try s.claim(key: "other", counter: 1), ClaimResult(ok: true), "keys are independent streams")
        XCTAssertEqual(try s.claim(key: "big", counter: 9_007_199_254_740_991), ClaimResult(ok: true))
    }

    func testAcrossConnectionsExactlyOneClaimWins() async throws {
        let dbs = try (0..<4).map { _ in try SQLiteDatabase(path: path) }
        let stores = try dbs.map { try SQLiteStateStore(database: $0) }
        let wins = Counter()
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<64 {
                group.addTask { if (try? stores[i % stores.count].claim(key: "race", counter: 1))?.ok == true { wins.bump() } }
            }
        }
        XCTAssertEqual(wins.value, 1)
    }

    func testDurableAcrossReopen() throws {
        do {
            let s = try SQLiteStateStore(path: path)
            XCTAssertTrue(try s.claim(key: "k", counter: 1).ok)
        }
        let again = try SQLiteStateStore(path: path)
        XCTAssertFalse(try again.claim(key: "k", counter: 1).ok, "a restarted verifier must still refuse the claimed counter")
        XCTAssertTrue(try again.claim(key: "k", counter: 2).ok)
    }

    func testClosedDatabaseFailsClosed() throws {
        let db = try SQLiteDatabase(path: path)
        let s = try SQLiteStateStore(database: db)
        db.close()
        XCTAssertThrowsError(try s.claim(key: "k", counter: 1))
        XCTAssertThrowsError(try s.last(key: "k"))
        db.close() // idempotent
    }

    func testInvalidTableNamesAreRefused() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        for bad in ["", "1abc", "a-b", "a b", "x; DROP TABLE y", String(repeating: "a", count: 64)] {
            XCTAssertThrowsError(try SQLiteStateStore(database: db, table: bad), bad)
            XCTAssertThrowsError(try SQLiteOperationStore(database: db, table: bad), bad)
            XCTAssertThrowsError(try SQLiteAtomicKV(database: db, table: bad), bad)
        }
    }

    // ---- the store conformance helper over SQLite ----

    func testStateStoreConformance() throws {
        let p = path
        let report = StateStoreConformance(name: "sqlite", open: {
            let db = try SQLiteDatabase(path: p)
            return (try SQLiteStateStore(database: db), { db.close() })
        }, durable: true, shared: true).run()
        XCTAssertTrue(report.ok, report.description)
        XCTAssertEqual(report.checks.filter { $0.status == "pass" }.count, 5, report.description)
    }

    func testOperationStoreConformance() throws {
        let p = path
        let report = OperationStoreConformance(name: "sqlite", open: {
            let db = try SQLiteDatabase(path: p)
            return (try SQLiteOperationStore(database: db), { db.close() })
        }, durable: true, shared: true).run()
        XCTAssertTrue(report.ok, report.description)
        XCTAssertEqual(report.checks.filter { $0.status == "pass" }.count, 6, report.description)
    }

    // ---- operation records ----

    func testExecuteOnceAcrossConnections() async throws {
        let stores = try (0..<4).map { _ in try SQLiteOperationStore(database: try SQLiteDatabase(path: path)) }
        let calls = Counter()
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<32 {
                group.addTask {
                    _ = await PCA.executeAuthorized(Self.authorization(id: "op-1"), options: ExecuteOptions(store: stores[i % stores.count])) { _ in
                        calls.bump()
                        return .string("done")
                    }
                }
            }
        }
        XCTAssertEqual(calls.value, 1, "fn ran more than once")
        let rec = try stores[0].get("op-1")
        XCTAssertEqual(rec?.state, .committed)
        XCTAssertEqual(rec?.result, .string("done"))
    }

    func testRecoveryAfterACrash() async throws {
        // a process died after claiming (pending) and another after starting the side effect (executing)
        do {
            let s = try SQLiteOperationStore(path: path)
            XCTAssertEqual(try s.create(OperationRecord(id: "a", state: .pending, verb: "v", resource: "/r", paramsDigest: "d", reversibility: "reversible", startedAt: 1_000)).isCreated, true)
            XCTAssertEqual(try s.create(OperationRecord(id: "b", state: .executing, verb: "v", resource: "/r", paramsDigest: "d", reversibility: "irreversible", startedAt: 1_000, executingAt: 1_010)).isCreated, true)
            XCTAssertEqual(try s.create(OperationRecord(id: "c", state: .committed, verb: "v", resource: "/r", paramsDigest: "d", reversibility: "reversible", startedAt: 1_000, result: .int(1))).isCreated, true)
        }
        let s = try SQLiteOperationStore(path: path)
        XCTAssertEqual(try s.listOpen().map { $0.id }, ["a", "b"])
        let settled = try PCA.recoverOperations(s, olderThanMs: 60_000, now: { 1_000 + 120_000 })
        XCTAssertEqual(settled.map { "\($0.id):\($0.state.rawValue)" }, ["a:aborted", "b:uncertain"])
        XCTAssertEqual(try s.listOpen(), [])
        // the uncertain one is never re-run; reconciliation settles it
        let ran = Counter()
        let o = await PCA.executeAuthorized(Self.authorization(id: "b"), options: ExecuteOptions(store: s)) { _ in ran.bump(); return nil }
        XCTAssertEqual(o.status, .uncertain)
        XCTAssertEqual(ran.value, 0)
        XCTAssertTrue(try PCA.resolveOperation(s, id: "b", outcome: .committed(result: .string("reconciled")), now: { 9 }))
        XCTAssertEqual(try s.get("b")?.state, .committed)
        XCTAssertFalse(try PCA.resolveOperation(s, id: "b", outcome: .failed(error: "late")), "only an uncertain record can be resolved")
    }

    // ---- the key/value store and the plan registry ----

    func testAtomicKVAndPlanRegistryOverConnections() async throws {
        let kvs = try (0..<2).map { _ in try SQLiteAtomicKV(database: try SQLiteDatabase(path: path)) }
        let regs = kvs.map { PlanRegistry(kv: $0) }
        let node: JSONValue = .object(["id": .string("n1"), "verb": .string("v"), "resource": .string("/r")])
        let drafted = regs[0].draft(grantRef: "g/1", nodes: .array([node]))
        let root = try XCTUnwrap(drafted.record?.root)
        XCTAssertTrue(regs[1].validate(grantRef: "g/1", root: root).ok, "the second connection sees the first one's draft")
        let wins = Counter()
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<32 {
                group.addTask { if regs[i % regs.count].commit(grantRef: "g/1", root: root).ok { wins.bump() } }
            }
        }
        XCTAssertEqual(wins.value, 1)
        XCTAssertTrue(regs[0].authorize(grantRef: "g/1", root: root, approval: PlanApproval(by: "p")).ok)
        XCTAssertTrue(regs[1].isPlanAuthorized(grantRef: "g/1", planRoot: root))
        // durable
        let reopened = PlanRegistry(kv: try SQLiteAtomicKV(path: path))
        XCTAssertTrue(reopened.isPlanAuthorized(grantRef: "g/1", planRoot: root))
        // a throwing transaction leaves the key untouched
        struct Boom: Error {}
        XCTAssertThrowsError(try SQLiteDatabase(path: path).transaction { () throws -> Int in throw Boom() })
        XCTAssertTrue(reopened.isPlanAuthorized(grantRef: "g/1", planRoot: root))
    }

    func testKVOperationStoreOverSQLite() throws {
        let kv = try SQLiteAtomicKV(path: path)
        let s = KVOperationStore(kv: kv)
        let rec = OperationRecord(id: "a", state: .pending, verb: "v", resource: "/r", paramsDigest: "d", reversibility: "costly", startedAt: 7)
        XCTAssertTrue(try s.create(rec).isCreated)
        XCTAssertFalse(try s.create(rec).isCreated)
        var next = rec
        next.state = .committed
        next.result = .object(["n": .int(5)])
        XCTAssertFalse(try s.transition("a", from: .executing, to: next))
        XCTAssertTrue(try s.transition("a", from: .pending, to: next))
        XCTAssertEqual(try s.get("a")?.result, .object(["n": .int(5)]))
    }
}

extension OperationCreate {
    var isCreated: Bool { if case .created = self { return true } else { return false } }
}
