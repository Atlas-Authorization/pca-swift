import Foundation

/// Subprocess hosts for WebAssembly tools: the component host and the core-module mode of the one pinned reference host binary. The binary is the only
/// thing that interprets the guest: it meters instruction fuel, refuses every import but the handle interface, enforces a wall-clock deadline and a
/// memory cap, and has no WASI. This side answers its handle requests (JSON lines on stdio) from a `HandleTable`.
///
/// Trust in the binary: its path comes from the caller's configuration only (never from the guest or a request) and its SHA-256 is pinned. A missing
/// binary, a missing pin or a different hash is refused before anything is spawned; there is no PATH search. The child gets an empty environment and no
/// shell. Limit of the pin: the hash is checked on the file's bytes, then the path is executed, so a writer who can replace the file in between wins that
/// race; install the binary where only the operator can write. Not available on iOS (no process spawning): every run reports host_unavailable there.
extension PCASandbox {
    public enum RunResult: Equatable {
        case ok(Int)
        case failed(String)
    }

    /// Where the reference host binary is and the SHA-256 (64 hex chars) it must have.
    public struct HostBinary {
        public var path: String
        public var expectedSha256: String
        public init(path: String, expectedSha256: String) { self.path = path; self.expectedSha256 = expectedSha256 }
    }

    public struct ComponentOptions {
        /// Required: a budget is a decision. A positive integer no larger than 2^53.
        public var fuel: Int
        public var timeoutMs = 10_000
        public var maxResultBytes = 1 << 20
        public init(fuel: Int) { self.fuel = fuel }
    }

    private static func hexString(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    /// Check the binary against its pin; the refusal reason (host_unpinned, host_missing, host_hash_mismatch) or nil.
    public static func verifyHostBinary(_ h: HostBinary) -> String? {
        let pin = h.expectedSha256.lowercased()
        guard pin.utf8.count == 64, pin.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else { return "host_unpinned" }
        guard let data = FileManager.default.contents(atPath: h.path) else { return "host_missing" }
        let got = Array(hexString(Canonical.sha256([UInt8](data))).utf8), want = Array(pin.utf8)
        var diff: UInt8 = 0
        for i in 0..<64 { diff |= got[i] ^ want[i] } // constant time
        return diff == 0 ? nil : "host_hash_mismatch"
    }

    private static func fuelOk(_ f: Int) -> Bool { f >= 1 && f <= 1 << 53 }

    /// Run `component` (binary or WAT text) under the pinned host with `fuel` instructions and a wall-clock timeout, serving its handle requests from
    /// `table`. Reasons: bad_fuel, host_unpinned, host_missing, host_hash_mismatch, host_unavailable, host_protocol, host_exit, timeout, or whatever the
    /// host reports (fuel_exhausted, ambient_import:<name>, trap, ...).
    public static func runComponent(_ table: HandleTable, _ component: [UInt8], host: HostBinary, options o: ComponentOptions) -> RunResult {
        guard fuelOk(o.fuel) else { return .failed("bad_fuel") }
        if let r = verifyHostBinary(host) { return .failed(r) }
        return runHost(table, host, ["__FILE__", String(o.fuel)], component, o.timeoutMs, o.maxResultBytes)
    }

    /// Core-module mode of the same pinned binary: `core <module> <fuel> <maxPages> <timeoutMs> [entry]`. The host enforces fuel, a wall-clock epoch
    /// deadline, the memory cap and the import allow-list; this is the route that bounds a guest in wall-clock time (WasmKit cannot interrupt one).
    public static func runCoreSubprocess(_ table: HandleTable, _ module: [UInt8], host: HostBinary, fuel: Int, maxPages: Int = 256, timeoutMs: Int = 5000, entry: String = "run") -> RunResult {
        guard fuelOk(fuel) else { return .failed("bad_fuel") }
        if let r = verifyHostBinary(host) { return .failed(r) }
        // the host's own deadline fires first, so its reason wins over the parent's kill timer
        return runHost(table, host, ["core", "__FILE__", String(fuel), String(maxPages), String(timeoutMs), entry], module, timeoutMs + 1000, 1 << 20)
    }

    #if os(macOS) || os(Linux)
    private final class LineQueue {
        private let cond = NSCondition()
        private var lines: [String?] = []
        func push(_ l: String?) { cond.lock(); lines.append(l); cond.signal(); cond.unlock() }
        /// .some(nil) = stdout closed; nil = deadline passed.
        func pop(until d: Date) -> String?? {
            cond.lock(); defer { cond.unlock() }
            while lines.isEmpty { if !cond.wait(until: d) && lines.isEmpty { return nil } }
            return .some(lines.removeFirst())
        }
    }

    private static func runHost(_ table: HandleTable, _ host: HostBinary, _ args: [String], _ payload: [UInt8], _ timeoutMs: Int, _ maxResult: Int) -> RunResult {
        signal(SIGPIPE, SIG_IGN) // a child that exited must not kill this process on write
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("pca-comp-" + hexString((0..<8).map { _ in UInt8.random(in: 0...255) }))
        do { try fm.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) } catch { return .failed("host_unavailable") }
        defer { try? fm.removeItem(at: dir) }
        let file = dir.appendingPathComponent("tool.component")
        guard (try? Data(payload).write(to: file)) != nil else { return .failed("host_unavailable") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: host.path)
        p.arguments = args.map { $0 == "__FILE__" ? file.path : $0 }
        p.environment = [:]
        let inPipe = Pipe(), outPipe = Pipe()
        p.standardInput = inPipe
        p.standardOutput = outPipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return .failed("host_unavailable") }
        defer { kill(p.processIdentifier, SIGKILL); p.waitUntilExit() }
        let q = LineQueue()
        let reader = outPipe.fileHandleForReading
        Thread.detachNewThread {
            var buf: [UInt8] = []
            while true {
                let d = reader.availableData
                if d.isEmpty { q.push(nil); return }
                buf += d
                while let nl = buf.firstIndex(of: 0x0A) {
                    q.push(String(decoding: buf[..<nl], as: UTF8.self))
                    buf.removeSubrange(...nl)
                }
            }
        }
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000)
        while true {
            guard let got = q.pop(until: deadline) else { return .failed("timeout") }
            guard let line = got else { return .failed("host_exit") }
            guard let m = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any] else { return .failed("host_protocol") }
            if let f = m["fail"] as? String { return .failed(f) }
            if let d = m["done"] as? Int { return .ok(d) }
            var h = 0.0
            if let x = m["h"] as? Double, x == x.rounded() { h = x }
            let reply: [String: Any]
            switch m["op"] as? String {
            case "count": reply = ["n": table.size]
            case "verb": reply = table.verbOf(h).map { ["ok": $0] as [String: Any] } ?? ["err": -1]
            case "invoke":
                switch (try? table.use(h)) ?? .failed(.executor_error) {
                case .ok(let b): reply = b.count > maxResult ? ["err": -3] : ["ok": b.map { Int($0) }]
                case .failed(let f): reply = ["err": USE_ERR.first { $0.0 == f.rawValue }?.1 ?? -5]
                }
            default: return .failed("host_protocol")
            }
            guard var out = try? JSONSerialization.data(withJSONObject: reply) else { return .failed("host_protocol") }
            out.append(0x0A)
            do { try inPipe.fileHandleForWriting.write(contentsOf: out) } catch { return .failed("host_exit") }
        }
    }
    #else
    private static func runHost(_ table: HandleTable, _ host: HostBinary, _ args: [String], _ payload: [UInt8], _ timeoutMs: Int, _ maxResult: Int) -> RunResult { .failed("host_unavailable") }
    #endif
}
