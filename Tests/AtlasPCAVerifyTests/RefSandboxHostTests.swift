import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The subprocess WebAssembly hosts: the pin logic, the JSON-lines protocol against a fake host whose hash is pinned here, and (when
/// PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256 name a built reference host) real runs of the component and core modes.
final class RefSandboxHostTests: XCTestCase {
    typealias S = PCASandbox

    static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    /// A table holding one fs.read handle whose executor returns [5, 6].
    static func table() throws -> S.HandleTable {
        let t = S.HandleTable(runtimeClass: "wasi_no_ambient", log: S.ReceiptLog(), executors: ["fs.read": { _ in [5, 6] }])
        let op = PCA.Operation(verb: "fs.read", resource: "/x", params: JSONValue.object([:]))
        let d = IV.strictHash(op.params)!
        _ = try t.mint(S.Grant(allow: true, operation: PCA.AuthorizedOperation(verb: "fs.read", resource: "/x", paramsDigest: d, id: "op")), op)
        return t
    }

    /// A shell script pinned by its own hash.
    static func fake(_ tag: String, _ body: String) throws -> S.HostBinary {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pca-host-test-\(ProcessInfo.processInfo.processIdentifier)-\(tag)")
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let script = "#!/bin/sh\n\(body)\n"
        let path = dir.appendingPathComponent("host.sh").path
        try script.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        return S.HostBinary(path: path, expectedSha256: hex(Canonical.sha256(Array(script.utf8))))
    }

    func testPinRefusals() throws {
        let t = try Self.table()
        let o = S.ComponentOptions(fuel: 1000)
        XCTAssertEqual(S.runComponent(t, [0x78], host: S.HostBinary(path: "/nonexistent/pca-wasmtime-host", expectedSha256: String(repeating: "a", count: 64)), options: o), .failed("host_missing"))
        XCTAssertEqual(S.runComponent(t, [0x78], host: S.HostBinary(path: "/bin/sh", expectedSha256: ""), options: o), .failed("host_unpinned"))
        XCTAssertEqual(S.runComponent(t, [0x78], host: S.HostBinary(path: "/bin/sh", expectedSha256: String(repeating: "0", count: 64)), options: o), .failed("host_hash_mismatch"))
        XCTAssertEqual(S.runComponent(t, [0x78], host: S.HostBinary(path: "/bin/sh", expectedSha256: String(repeating: "0", count: 64)), options: S.ComponentOptions(fuel: 0)), .failed("bad_fuel"))
        XCTAssertEqual(S.runCoreSubprocess(t, [0], host: S.HostBinary(path: "/bin/sh", expectedSha256: ""), fuel: -1), .failed("bad_fuel"))
        // a pin of the right hash matches
        let h = try Self.fake("pin", "exit 0")
        XCTAssertNil(S.verifyHostBinary(h))
        XCTAssertNil(S.verifyHostBinary(S.HostBinary(path: h.path, expectedSha256: h.expectedSha256.uppercased())))
    }

    #if os(macOS) || os(Linux)
    func testProtocolAgainstFakeHost() throws {
        // count -> reply, invoke(1) -> reply, then done
        let h = try Self.fake("proto", "printf '{\"op\":\"count\"}\\n'; read a; printf '{\"op\":\"verb\",\"h\":1}\\n'; read v; printf '{\"op\":\"invoke\",\"h\":1}\\n'; read b; case \"$a$v$b\" in *'{\"n\":1}'*'{\"ok\":\"fs.read\"}'*'{\"ok\":[5,6]}'*) printf '{\"done\":5,\"fuel_used\":1}\\n';; *) printf '{\"fail\":\"bad_reply\"}\\n';; esac")
        let t = try Self.table()
        XCTAssertEqual(S.runComponent(t, [0x78], host: h, options: S.ComponentOptions(fuel: 1000)), .ok(5))
        // the single use is spent: the second run gets err -2 and the fake reports bad_reply
        XCTAssertEqual(S.runComponent(t, [0x78], host: h, options: S.ComponentOptions(fuel: 1000)), .failed("bad_reply"))
    }

    func testHungHostIsKilledAndGarbageIsRefused() throws {
        let t = try Self.table()
        var o = S.ComponentOptions(fuel: 1000)
        o.timeoutMs = 200
        XCTAssertEqual(S.runComponent(t, [0x78], host: try Self.fake("hang", "read a"), options: o), .failed("timeout"))
        XCTAssertEqual(S.runComponent(t, [0x78], host: try Self.fake("junk", "echo not-json"), options: S.ComponentOptions(fuel: 1000)), .failed("host_protocol"))
        XCTAssertEqual(S.runComponent(t, [0x78], host: try Self.fake("quiet", "exit 0"), options: S.ComponentOptions(fuel: 1000)), .failed("host_exit"))
        XCTAssertEqual(S.runComponent(t, [0x78], host: try Self.fake("fail", "echo '{\"fail\":\"fuel_exhausted\"}'"), options: S.ComponentOptions(fuel: 1000)), .failed("fuel_exhausted"))
    }

    func testChildEnvironmentIsEmptyAndArgsAreSpawned() throws {
        // the fake host reports "done" = number of environment variables it sees besides the shell's own (0), and fails unless it got a file argument
        let h = try Self.fake("env", "[ -f \"$1\" ] || { echo '{\"fail\":\"no_file\"}'; exit 0; }; n=$(env | grep -vE '^(PWD|_|SHLVL|OLDPWD)=' | wc -l | tr -d ' '); echo \"{\\\"done\\\":$n}\"")
        let r = S.runComponent(try Self.table(), [0x78], host: h, options: S.ComponentOptions(fuel: 1000))
        if case .ok(let n) = r { XCTAssertEqual(n, 0, "no variable but the ones the shell itself defines (PWD, _, SHLVL, OLDPWD) may exist") } else { XCTFail("\(r)") }
    }

    func testTempDirIsRemoved() throws {
        let before = Set((try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)) ?? []).filter { $0.hasPrefix("pca-comp-") }
        _ = S.runComponent(try Self.table(), [0x78], host: try Self.fake("quiet2", "exit 0"), options: S.ComponentOptions(fuel: 1000))
        let after = Set((try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)) ?? []).filter { $0.hasPrefix("pca-comp-") }
        XCTAssertTrue(after.isSubset(of: before))
    }
    #endif

    static func real() throws -> S.HostBinary {
        let e = ProcessInfo.processInfo.environment
        guard let p = e["PCA_WASMTIME_HOST_BIN"], let h = e["PCA_WASMTIME_HOST_SHA256"] else {
            if e["CI"] != nil { throw NSError(domain: "Ref", code: 1, userInfo: [NSLocalizedDescriptionKey: "CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256"]) }
            throw XCTSkip("PCA_WASMTIME_HOST_BIN / PCA_WASMTIME_HOST_SHA256 not set: no built reference host to run against")
        }
        return S.HostBinary(path: p, expectedSha256: h)
    }

    func testRealHostComponentLimits() throws {
        let host = try Self.real()
        let wat = Array(S.referenceComponentWat().utf8)
        XCTAssertEqual(S.runComponent(try Self.table(), wat, host: host, options: S.ComponentOptions(fuel: 1_000_000)), .ok(5))
        XCTAssertEqual(S.runComponent(try Self.table(), Array(S.referenceComponentWat(spin: true).utf8), host: host, options: S.ComponentOptions(fuel: 10_000)), .failed("fuel_exhausted"))
        let amb = Array(S.referenceComponentWat(extraImport: "wasi:cli/environment@0.2.0").utf8)
        XCTAssertEqual(S.runComponent(try Self.table(), amb, host: host, options: S.ComponentOptions(fuel: 1_000_000)), .failed("ambient_import:wasi:cli/environment@0.2.0"))
    }

    func testRealHostCoreMode() throws {
        let host = try Self.real()
        let m = S.buildTool(S.ToolSpec(calls: [S.ToolCall(handle: 1, ptr: 0, cap: 16)], returns: "byte0"))
        XCTAssertEqual(S.runCoreSubprocess(try Self.table(), m, host: host, fuel: 1_000_000), .ok(5))
        let spin = S.buildTool(S.ToolSpec(calls: [], spin: true))
        XCTAssertEqual(S.runCoreSubprocess(try Self.table(), spin, host: host, fuel: 10_000), .failed("fuel_exhausted"))
        // wall clock: a huge budget, a short deadline
        XCTAssertEqual(S.runCoreSubprocess(try Self.table(), spin, host: host, fuel: 1 << 52, timeoutMs: 300), .failed("timeout"))
        let amb = S.buildTool(S.ToolSpec(calls: [], extraImports: [(module: "wasi_snapshot_preview1", name: "fd_write")]))
        XCTAssertEqual(S.runCoreSubprocess(try Self.table(), amb, host: host, fuel: 1_000_000), .failed("ambient_import:wasi_snapshot_preview1.fd_write"))
        let big = S.buildTool(S.ToolSpec(calls: [], memory: (1, 257)))
        XCTAssertEqual(S.runCoreSubprocess(try Self.table(), big, host: host, fuel: 1_000_000), .failed("memory_limits"))
    }
}
