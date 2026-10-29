import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Counts calls from many tasks.
final class CallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func increment() {
        lock.lock()
        defer { lock.unlock() }
        n += 1
    }
    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return n
    }
}

/// Operation records (T3): replays operation-vectors.json scenario by scenario, then concurrency and the fail-closed paths. A
/// missing vector file FAILS (it is loaded, never skipped).
final class OperationRecordTests: XCTestCase {
    static let EMPTY_DIGEST = IV.strictHash(.object([:])) ?? ""

    static func authorization(id: String, allow: Bool = true, verb: String = "payments.refund", resource: String = "/orders/1", digest: String? = nil,
                              signedClass: String? = "reversible", exp: JSONValue? = nil) -> PCA.AuthorizeResult {
        var action: JObject = [:]
        if let c = signedClass { action["reversibility_class"] = .string(c) }
        var p: JObject = ["action": .object(action)]
        if let e = exp { p["exp"] = e }
        return PCA.AuthorizeResult(allow: allow, status: allow ? 200 : 403, checks: [:], checkNames: [], reasons: [], reason: nil,
                                   operation: allow ? PCA.AuthorizedOperation(verb: verb, resource: resource, paramsDigest: digest ?? EMPTY_DIGEST, id: id) : nil,
                                   pcactn: .object(p), verdict: nil, missing: nil)
    }

    func runStep(_ store: MemoryOperationStore, _ s: JSONValue) async throws -> JSONValue {
        let at = s.get("at")?.safeInt ?? 0
        let older = s.get("older_than_ms")?.safeInt ?? 0
        switch s.get("op")?.asString {
        case "seed"?:
            let rec = try XCTUnwrap(OperationRecord(json: s.get("record") ?? .null))
            guard case .created = store.create(rec) else { XCTFail("seed: record exists"); return .null }
            return .null
        case "get"?:
            return store.get(s.get("id")?.asString ?? "")?.json ?? .null
        case "recover"?:
            let rs = try PCA.recoverOperations(store, olderThanMs: older, now: { at })
            return .array(rs.map { .object(["id": .string($0.id), "state": .string($0.state.rawValue)]) })
        case "recover_one"?:
            return try PCA.recoverOperation(store, id: s.get("id")?.asString ?? "", olderThanMs: older, now: { at })?.json ?? .null
        case "resolve"?:
            let o = s.get("outcome")
            let res: OperationResolution = o?.get("state")?.asString == "committed" ? .committed(result: o?.get("result")) : .failed(error: o?.get("error")?.asString ?? "")
            return .bool(try PCA.resolveOperation(store, id: s.get("id")?.asString ?? "", outcome: res, now: { at }))
        default:
            break
        }
        // execute
        let id = s.get("id")?.asString ?? ""
        let notAllowed = s.get("not_allowed") == .bool(true)
        let az = Self.authorization(id: id, allow: !notAllowed, verb: s.get("verb")?.asString ?? "payments.refund",
                                    resource: s.get("resource")?.asString ?? "/orders/1", digest: s.get("params_digest")?.asString,
                                    signedClass: s.get("signed_class")?.asString, exp: s.get("exp"))
        var opts = ExecuteOptions(store: s.get("no_store") == .bool(true) ? nil : store, reversibilityClass: s.get("server_class")?.asString,
                                  pendingTimeoutMs: s.get("timeout_ms")?.safeInt ?? 0, now: { at })
        if s.get("recheck_for")?.asString == "always" { opts.recheckFor = "always" }
        let rc = s.get("recheck")
        if rc?.asString == "ok" {
            opts.recheck = { _ in .pass }
        } else if let msg = rc?.get("refuse")?.asString {
            opts.recheck = { _ in .refuse(msg) }
        } else if let msg = rc?.get("throw")?.asString {
            opts.recheck = { _ in throw PCAFailure(msg) }
        }
        let fnSpec = s.get("fn")
        let calls = CallCounter()
        let innerOpts = opts
        let out = await PCA.executeAuthorized(az, options: opts) { h in
            calls.increment()
            switch fnSpec?.get("kind")?.asString {
            case "throw"?: throw PCAFailure(fnSpec?.get("message")?.asString ?? "")
            case "reenter"?:
                let inner = await PCA.executeAuthorized(az, options: innerOpts) { _ in throw PCAFailure("inner must not run") }
                return .string(inner.status.rawValue)
            default:
                return fnSpec?.get("result") ?? .string(h.idempotencyKey)
            }
        }
        let rec: JSONValue = (s.get("no_store") == .bool(true) || notAllowed) ? .null : (store.get(id)?.json ?? .null)
        return .object(["outcome": out.json, "fn_calls": .int(Int64(calls.value)), "record": rec])
    }

    func testOperationVectors() async throws {
        let doc = try ConformanceTests.load("operation-vectors.json")
        XCTAssertEqual(doc.get("constants")?.get("pending_timeout_ms")?.safeInt, PCA.OPERATION_PENDING_TIMEOUT_MS)
        let scenarios = doc.get("scenarios")?.asArray ?? []
        XCTAssertEqual(scenarios.count, 19)
        for sc in scenarios {
            let name = sc.get("name")?.asString ?? "?"
            let store = MemoryOperationStore()
            let steps = sc.get("steps")?.asArray ?? []
            let expect = sc.get("expect")?.asArray ?? []
            XCTAssertEqual(steps.count, expect.count, name)
            for (i, st) in steps.enumerated() where i < expect.count {
                let got = Canonical.canonicalize(try await runStep(store, st))
                XCTAssertEqual(got, Canonical.canonicalize(expect[i]), "\(name) step \(i) (\(st.get("op")?.asString ?? "?"))")
            }
        }
    }

    // Of N concurrent executions of one authorization exactly one runs fn; every other is answered from the record.
    func testConcurrentExecutionsRunOnce() async throws {
        let store = MemoryOperationStore()
        let calls = CallCounter()
        let firsts = CallCounter()
        let refused = CallCounter()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<64 {
                group.addTask {
                    let o = await PCA.executeAuthorized(Self.authorization(id: "op-c"), options: ExecuteOptions(store: store)) { _ in
                        calls.increment()
                        return .string("done")
                    }
                    if !o.replayed && o.status == .committed { firsts.increment() }
                    if o.status == .refused { refused.increment() }
                }
            }
        }
        XCTAssertEqual(calls.value, 1, "fn ran more than once")
        XCTAssertEqual(firsts.value, 1)
        XCTAssertEqual(refused.value, 0)
        let r = store.get("op-c")
        XCTAssertEqual(r?.state, .committed)
        XCTAssertEqual(r?.result, .string("done"))
    }

    func testRefusesWithoutCheckedAuthorization() async {
        let store = MemoryOperationStore()
        let ran = CallCounter()
        let fn: (ExecutionHandle) async throws -> JSONValue? = { _ in ran.increment(); return nil }
        let other = PCA.Operation(verb: "payments.refund", resource: "/other", params: .object([:]))
        var o = await PCA.executeAuthorized(Self.authorization(id: "op-x"), options: ExecuteOptions(store: store, operation: other), fn)
        XCTAssertEqual(o.status, .refused, "an authorization for another operation")
        o = await PCA.executeAuthorized(Self.authorization(id: ""), options: ExecuteOptions(store: store), fn)
        XCTAssertEqual(o.status, .refused, "an authorization without an operation id")
        o = await PCA.executeAuthorized(Self.authorization(id: "op-y", allow: false), options: ExecuteOptions(store: store), fn)
        XCTAssertEqual(o.status, .refused, "a denial")
        XCTAssertEqual(ran.value, 0)
        // the right operation passes the binding
        let same = PCA.Operation(verb: "payments.refund", resource: "/orders/1", params: .object([:]))
        o = await PCA.executeAuthorized(Self.authorization(id: "op-z"), options: ExecuteOptions(store: store, operation: same), fn)
        XCTAssertEqual(o.status, .committed)
        XCTAssertEqual(ran.value, 1)
    }

    /// A store that cannot decide refuses; nothing runs.
    struct BrokenStore: OperationStore {
        func create(_ record: OperationRecord) throws -> OperationCreate { throw PCAFailure("db down") }
        func get(_ id: String) throws -> OperationRecord? { nil }
        func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool { false }
    }

    func testStoreFailureFailsClosed() async {
        let ran = CallCounter()
        let o = await PCA.executeAuthorized(Self.authorization(id: "op-b"), options: ExecuteOptions(store: BrokenStore())) { _ in ran.increment(); return nil }
        XCTAssertEqual(o.status, .refused)
        XCTAssertEqual(o.reason, "executeAuthorized: the operation store failed (fail closed): db down")
        XCTAssertEqual(ran.value, 0)
        XCTAssertThrowsError(try PCA.recoverOperations(BrokenStore()), "a store without listOpen cannot recover all")
    }

    func testRecordJSONRoundTrip() throws {
        let r = OperationRecord(id: "i", state: .committed, verb: "v", resource: "r", paramsDigest: "p", reversibility: "reversible", startedAt: 1, result: .string("x"))
        XCTAssertEqual(Canonical.canonicalize(r.json),
                       #"{"id":"i","params_digest":"p","resource":"r","result":"x","reversibility":"reversible","startedAt":1,"state":"committed","verb":"v"}"#)
        XCTAssertEqual(OperationRecord(json: r.json), r)
        XCTAssertNil(OperationRecord(json: .object(["id": .string("i"), "state": .string("bogus")])))
    }
}
