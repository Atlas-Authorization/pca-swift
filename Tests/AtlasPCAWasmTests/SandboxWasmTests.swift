import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCAWasm

/// The in-process WasmKit core-module host: handle use, fuel, the memory cap, the import allow-list, malformed input, egress.
final class SandboxWasmTests: XCTestCase {
    typealias S = PCASandbox

    static func grant(_ verb: String, _ res: String) -> (S.Grant, PCA.Operation) {
        let op = PCA.Operation(verb: verb, resource: res, params: JSONValue.object([:]))
        let d = IV.strictHash(op.params)!
        return (S.Grant(allow: true, operation: PCA.AuthorizedOperation(verb: verb, resource: res, paramsDigest: d, id: "op")), op)
    }

    /// Handles: 1 fs.read -> [7,8,9]; 2 net.ok (in policy) -> [1]; 3 net.evil (out of policy) -> executor error.
    static func fixture() throws -> S.HandleTable {
        let policy = S.EgressPolicy(now: { 0 })
        let (g, op) = grant("net.ok", "api.example.com")
        try policy.admit(g, op, toRequest: { _ in S.EgressTemplate(method: "GET", scheme: "https", host: "api.example.com", path: "/v1") })
        func fetch(_ url: String) -> S.Executor { { _ in
            if policy.claim(S.EgressRequest(method: "GET", url: url)).allow { return [1] }
            throw S.SandboxError("denied")
        } }
        let t = S.HandleTable(runtimeClass: "wasi_no_ambient", log: S.ReceiptLog(), executors: ["fs.read": { _ in [7, 8, 9] }, "net.ok": fetch("https://api.example.com/v1"), "net.evil": fetch("https://evil.example/x")])
        for (v, r) in [("fs.read", "/x"), ("net.ok", "api.example.com"), ("net.evil", "evil.example")] {
            let (g, op) = grant(v, r)
            _ = try t.mint(g, op)
        }
        return t
    }

    static func tool(_ calls: [S.ToolCall], returns: String? = nil, extraImports: [(module: String, name: String)] = [], memory: (min: Int, max: Int?) = (1, 1), spin: Bool = false) -> [UInt8] {
        S.buildTool(S.ToolSpec(calls: calls, returns: returns, extraImports: extraImports, memory: memory, spin: spin))
    }

    func opts(_ fuel: Int = 10_000_000) -> S.CoreOptions { S.CoreOptions(fuel: fuel) }

    func testHandleResultLandsInMemory() throws {
        let t = try Self.fixture()
        XCTAssertEqual(S.runCore(t, Self.tool([S.ToolCall(handle: 1, ptr: 0, cap: 16)], returns: "byte0"), options: opts()), .ok(7))
        XCTAssertFalse(t.size == 0)
    }

    func testProbeSeesCountAndVerb() throws {
        XCTAssertEqual(S.runCore(try Self.fixture(), S.buildProbeTool(), options: opts()), .ok(3 * 256 + Int(UInt8(ascii: "f"))))
    }

    func testInfiniteLoopHitsFuel() throws {
        XCTAssertEqual(S.runCore(try Self.fixture(), Self.tool([], spin: true), options: opts(10_000)), .failed("fuel_exhausted"))
    }

    /// WasmKit cannot interrupt a guest: the caller still gets `timeout` on time, and the abandoned run ends when its (here modest) fuel does.
    func testWallClockReturnsOnTimeButFuelBoundsTheGuest() throws {
        var o = opts(300_000_000)
        o.timeoutMs = 100
        let start = Date()
        XCTAssertEqual(S.runCore(try Self.fixture(), Self.tool([], spin: true), options: o), .failed("timeout"))
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }

    func testFuelIsRequired() throws {
        XCTAssertEqual(S.runCore(try Self.fixture(), Self.tool([]), options: opts(0)), .failed("bad_fuel"))
        XCTAssertEqual(S.runCore(try Self.fixture(), Self.tool([]), options: opts(-5)), .failed("bad_fuel"))
    }

    func testMemoryOverCapOrUndeclaredIsRefused() throws {
        let t = try Self.fixture()
        for mem: (min: Int, max: Int?) in [(1, 257), (1, nil), (257, 257)] {
            XCTAssertEqual(S.runCore(t, Self.tool([], memory: mem), options: opts()), .failed("memory_limits"))
        }
        var o = opts()
        o.maxMemoryPages = 2
        XCTAssertEqual(S.runCore(t, Self.tool([], memory: (1, 4)), options: o), .failed("memory_limits"))
        XCTAssertEqual(S.runCore(t, Self.tool([], memory: (1, 4)), options: opts()), .ok(0))
        // shared memory (flag 3) and memory64 (flag 4+) are refused by the section parser
        var shared = Self.tool([], memory: (1, 1))
        let at = (8..<shared.count - 5).first { Array(shared[$0..<$0 + 6]) == [5, 4, 1, 1, 1, 1] }! // memory section: id, size, count, flag, min, max
        XCTAssertEqual(shared[at + 3], 1)
        shared[at + 3] = 3
        XCTAssertEqual(S.runCore(t, shared, options: opts()), .failed("memory_limits"))
        shared[at + 3] = 5
        XCTAssertEqual(S.runCore(t, shared, options: opts()), .failed("memory_limits"))
    }

    func testForbiddenImportsAreRefused() throws {
        for (m, n) in [("wasi_snapshot_preview1", "fd_write"), ("env", "x"), ("pca:act", "other")] {
            XCTAssertEqual(S.runCore(try Self.fixture(), Self.tool([], extraImports: [(module: m, name: n)]), options: opts()), .failed("ambient_import:\(m).\(n)"))
        }
    }

    func testMalformedSizeAndEntry() throws {
        let t = try Self.fixture()
        XCTAssertEqual(S.runCore(t, [], options: opts()), .failed("module_size"))
        XCTAssertEqual(S.runCore(t, [1, 2, 3, 4, 5, 6, 7, 8, 9], options: opts()), .failed("malformed_module"))
        let m = Self.tool([])
        XCTAssertEqual(S.runCore(t, m, entry: "nope", options: opts()), .failed("no_entry"))
        var o = opts()
        o.maxModuleBytes = 10
        XCTAssertEqual(S.runCore(t, m, options: o), .failed("module_size"))
    }

    func testBadOutputWindowSpendsNoUse() throws {
        let t = try Self.fixture()
        XCTAssertEqual(S.runCore(t, Self.tool([S.ToolCall(handle: 1, ptr: 70_000, cap: 16)]), options: opts()), .ok(-4))
        XCTAssertEqual(S.runCore(t, Self.tool([S.ToolCall(handle: 1, ptr: 0, cap: 16)]), options: opts()), .ok(3))
        // window math is unsigned 32-bit: ptr + cap wrapping past 2^32 is still out of memory
        XCTAssertEqual(S.runCore(try Self.fixture(), Self.tool([S.ToolCall(handle: 1, ptr: -8, cap: 16)]), options: opts()), .ok(-4))
    }

    func testResultLargerThanTheWindowIsRefused() throws {
        XCTAssertEqual(S.runCore(try Self.fixture(), Self.tool([S.ToolCall(handle: 1, ptr: 0, cap: 2)]), options: opts()), .ok(-3))
    }

    func testEgressInsidePolicyPassesOutsideIsRefused() throws {
        let t = try Self.fixture()
        XCTAssertEqual(S.runCore(t, Self.tool([S.ToolCall(handle: 2, ptr: 0, cap: 16)]), options: opts()), .ok(1))
        // out-of-policy host: the executor throws, the guest sees executor_error (-5), and the receipt log records an error
        XCTAssertEqual(S.runCore(t, Self.tool([S.ToolCall(handle: 3, ptr: 0, cap: 16)]), options: opts()), .ok(-5))
    }
}
