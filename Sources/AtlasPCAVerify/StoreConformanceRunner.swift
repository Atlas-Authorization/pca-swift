import Foundation

/// The conformance run (types.ts, harness.ts, crash.ts, runner.ts, reference.ts of pca-store-conformance): every test for every operation the adapter
/// implements, each recorded history checked for linearizability, with a report. A PASS is evidence, not proof (the kit checks the histories it observed);
/// a FAIL is a recorded history that no sequential order explains, unless the adapter itself is mis-wired. Clients are threads.
extension PCAStoreConformance {
    // MARK: adapter

    /// What an adapter declares; a nil member is detected from the first client (or, for `durable`, assumed true).
    public struct Capabilities: Equatable {
        public var consumeOnce: Bool?
        public var advance: Bool?
        /// The store claims durability: consumed keys and counters survive closing every client and `restart()`. Declare false ONLY for a single-process
        /// in-memory store whose lifetime covers the action lifetime; the durability test is then skipped.
        public var durable: Bool?
        public init(consumeOnce: Bool? = nil, advance: Bool? = nil, durable: Bool? = nil) { self.consumeOnce = consumeOnce; self.advance = advance; self.durable = durable }
    }

    /// One connection / verifier instance talking to the shared backend. Implement whichever of the two operations you ship (and answer the matching
    /// `has...`). Both are atomic across every client of the same backend, durable, and FAIL CLOSED (throw when they cannot decide).
    public protocol StoreClient: AnyObject {
        var hasConsumeOnce: Bool { get }
        var hasAdvance: Bool { get }
        /// True iff there is no live record for `key` (live = its stored horizon is >= `nowMs`); then records `retainUntilMs`.
        func consumeOnce(_ key: String, retainUntilMs: Double, nowMs: Double) throws -> Bool
        /// True iff `counter` is strictly greater than the stored value; then stores it.
        func advance(_ streamKey: String, counter: Double) throws -> Bool
        /// Release the connection. The backend's state must survive it.
        func close()
    }

    /// The adapter a store author implements to run the kit against THEIR store: `open` returns one client per simulated verifier instance, all on the same
    /// shared backend.
    public protocol StoreAdapter: AnyObject {
        var name: String { get }
        var capabilities: Capabilities? { get }
        func open() throws -> any StoreClient
        var hasRestart: Bool { get }
        /// Restart the BACKEND after every client was closed. Without it the durability test only closes and re-opens clients.
        func restart() throws
        var hasCrash: Bool { get }
        /// Crash the backend abruptly (kill -9 equivalent). Followed by `restart`.
        func crash() throws
        /// Release everything the adapter holds (pools, temp dirs). Never drop shared data here.
        func teardown()
    }

    // MARK: workloads

    /// Workload settings; nil members take the reference defaults.
    public struct WorkloadOptions {
        /// Concurrent clients (each `adapter.open()`), default 16.
        public var clients: Int?
        /// Concurrent run length, default 2000 ms.
        public var durationMs: Double?
        /// Contention window: every client targets the same `spread` keys within one window (default 5 ms, 3 keys).
        public var windowMs: Double?
        public var spread: Int?
        /// Counter values are drawn from [0, values) so duplicates and reorderings occur (default 20).
        public var values: Int?
        /// consumeOnce horizon: retainUntil = now + retentionMs (default 10 minutes, longer than any run).
        public var retentionMs: Double?
        /// A call that has not settled after this long is recorded as unknown (open-ended), default 5000 ms.
        public var opTimeoutMs: Int?
        /// Same-key burst rounds, default 20.
        public var rounds: Int?
        /// Retention run: distinct keys written then revisited, default 500.
        public var revisitKeys: Int?
        /// Key prefix. Default: random per run, so runs never collide with each other or with real data.
        public var namespace: String?
        /// PRNG seed (default random).
        public var seed: Int64?
        public init() {}
    }

    /// The recorded history of a run, how many calls failed or timed out, and a note.
    public struct WorkloadResult {
        public var ops: [Op]
        public var errors: Int
        public var note: String?
        public init(ops: [Op], errors: Int, note: String?) { self.ops = ops; self.errors = errors; self.note = note }
    }

    struct Resolved {
        var clients: Int, spread: Int, values: Int, rounds: Int, revisitKeys: Int
        var durationMs: Double, windowMs: Double, retentionMs: Double
        var opTimeoutMs: Int, seed: Int64, namespace: String
    }

    static func resolve(_ o: WorkloadOptions) -> Resolved {
        Resolved(clients: o.clients ?? 16, spread: o.spread ?? 3, values: o.values ?? 20, rounds: o.rounds ?? 20, revisitKeys: o.revisitKeys ?? 500,
                 durationMs: o.durationMs ?? 2000, windowMs: o.windowMs ?? 5, retentionMs: o.retentionMs ?? 600_000, opTimeoutMs: o.opTimeoutMs ?? 5000,
                 seed: o.seed ?? Int64.random(in: 0..<(1 << 31)), namespace: o.namespace ?? randomNamespace())
    }

    /// A fresh key prefix: runs never collide with each other or with real data.
    public static func randomNamespace() -> String {
        "pcasc-" + String(Int64(Date().timeIntervalSince1970 * 1000), radix: 36) + "-" + String(Int64.random(in: 0..<2_176_782_336), radix: 36)
    }

    /// What every operation needs: where to record, the retention horizon and the per-call timeout.
    public struct OpContext {
        public var rec: Recorder
        public var retentionMs: Double
        public var opTimeoutMs: Int
        public init(rec: Recorder, retentionMs: Double, opTimeoutMs: Int) { self.rec = rec; self.retentionMs = retentionMs; self.opTimeoutMs = opTimeoutMs }
    }

    private final class Slot<T>: @unchecked Sendable {
        var value: T?
        let lock = NSLock()
        func set(_ v: T?) { lock.lock(); value = v; lock.unlock() }
        func get() -> T? { lock.lock(); defer { lock.unlock() }; return value }
    }

    /// Run `f` on its own thread; true when it finished within `timeoutMs`. A call that has not finished then keeps running (it cannot be killed): the
    /// caller records it as unknown, so it may still take effect at any later time.
    private static func within(_ timeoutMs: Int, _ f: @escaping () -> Void) -> Bool {
        let sem = DispatchSemaphore(value: 0)
        let t = Thread { f(); sem.signal() }
        t.start()
        return sem.wait(timeout: .now() + .milliseconds(max(0, timeoutMs))) == .success
    }

    /// Settle `fn` as a definite boolean, or nil (unknown) on a throw or a timeout.
    public static func settle(_ timeoutMs: Int, _ fn: @escaping () throws -> Bool) -> Bool? {
        let out = Slot<Bool>()
        let done = within(timeoutMs) { out.set(try? fn()) }
        return done ? out.get() : nil
    }

    /// Record and perform one operation. For `advance`, `value` is the counter; for `consume` it is ignored.
    @discardableResult
    public static func perform(_ c: any StoreClient, _ client: String, _ kind: String, _ key: String, _ value: Double, _ ctx: OpContext) -> Bool? {
        let now = Double(Int64(Date().timeIntervalSince1970 * 1000))
        let consume = kind == "consume"
        let lo = consume ? now : value
        let w = consume ? now + ctx.retentionMs : value
        let token = ctx.rec.invoke(client: client, kind: kind, key: key, lo: lo, w: w)
        let r = settle(ctx.opTimeoutMs) { consume ? try c.consumeOnce(key, retainUntilMs: w, nowMs: now) : try c.advance(key, counter: value) }
        ctx.rec.complete(token, r)
        return r
    }

    public static func openClients(_ adapter: any StoreAdapter, _ n: Int) throws -> [any StoreClient] {
        var out: [any StoreClient] = []
        do {
            for _ in 0..<max(0, n) { out.append(try adapter.open()) }
        } catch {
            closeClients(out)
            throw error
        }
        return out
    }

    public static func closeClients(_ clients: [any StoreClient]) { for c in clients { c.close() } }

    /// Where a windowed client's keys and values come from (shared by every client and process).
    public struct Window {
        public var namespace = ""
        public var windowMs: Double = 5
        public var spread = 3
        public var values = 20
        public var origin: Double = 0
        public var deadline: Double = 0
        public var rand = Prng(seed: 0)
        public var stop: () -> Bool = { false }
        public init() {}
    }

    /// The client loop of the concurrent run, shared with the crash harness: until `deadline`, pick one of the `spread` keys of the current window (all
    /// clients compute the same window from `origin`) and operate on it.
    public static func driveWindowed(_ c: any StoreClient, _ client: String, _ kind: String, _ ctx: OpContext, _ o: Window) {
        while clock() < o.deadline && !o.stop() {
            let win = Int64(((clock() - o.origin) / o.windowMs).rounded(.down))
            let key = "\(o.namespace):\(kind):\(win):\(Int64(o.rand.rand(Double(o.spread))))"
            perform(c, client, kind, key, o.rand.rand(Double(o.values)), ctx)
        }
    }

    private static func countUnknown(_ ops: [Op]) -> Int { ops.filter { $0.res == "unknown" }.count }

    /// Run the bodies at once, each on its own thread, and wait for all of them.
    private static func runAll(_ bodies: [() -> Void]) {
        let group = DispatchGroup()
        for b in bodies {
            group.enter()
            let t = Thread { b(); group.leave() }
            t.start()
        }
        group.wait()
    }

    /// `rounds` times: every client fires one operation at the SAME fresh key at once.
    public static func runBurst(_ adapter: any StoreAdapter, _ kind: String, _ opts: WorkloadOptions = WorkloadOptions()) throws -> WorkloadResult {
        let o = resolve(opts)
        let rand = Prng(seed: Double(o.seed))
        let rec = MemoryRecorder()
        let ctx = OpContext(rec: rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs)
        let clients = try openClients(adapter, o.clients)
        defer { closeClients(clients) }
        for r in 0..<o.rounds {
            let key = "\(o.namespace):\(kind):burst:\(r)"
            var bodies: [() -> Void] = []
            for i in clients.indices {
                let v = rand.rand(Double(o.values))
                let c = clients[i]
                bodies.append { perform(c, "c\(i)", kind, key, v, ctx) }
            }
            runAll(bodies)
        }
        let ops = rec.ops()
        return WorkloadResult(ops: ops, errors: countUnknown(ops), note: nil)
    }

    /// Every client loops on the windowed keys for `durationMs`.
    public static func runConcurrent(_ adapter: any StoreAdapter, _ kind: String, _ opts: WorkloadOptions = WorkloadOptions()) throws -> WorkloadResult {
        let o = resolve(opts)
        let rec = MemoryRecorder()
        let ctx = OpContext(rec: rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs)
        let clients = try openClients(adapter, o.clients)
        defer { closeClients(clients) }
        let origin = clock()
        var bodies: [() -> Void] = []
        for i in clients.indices {
            let c = clients[i]
            var w = Window()
            w.namespace = o.namespace; w.windowMs = o.windowMs; w.spread = o.spread; w.values = o.values
            w.origin = origin; w.deadline = origin + o.durationMs; w.rand = Prng(seed: Double(o.seed + Int64(i)))
            let win = w
            bodies.append { driveWindowed(c, "c\(i)", kind, ctx, win) }
        }
        runAll(bodies)
        let ops = rec.ops()
        return WorkloadResult(ops: ops, errors: countUnknown(ops), note: nil)
    }

    /// Retention: write `revisitKeys` distinct keys (consume once / advance to 1), then revisit every one while it is still live (same counter): each
    /// revisit must answer false. Catches early pruning and capacity eviction of live records.
    public static func runRetention(_ adapter: any StoreAdapter, _ kind: String, _ opts: WorkloadOptions = WorkloadOptions()) throws -> WorkloadResult {
        let o = resolve(opts)
        let rec = MemoryRecorder()
        let ctx = OpContext(rec: rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs)
        let clients = try openClients(adapter, o.clients)
        defer { closeClients(clients) }
        let keys = (0..<o.revisitKeys).map { "\(o.namespace):\(kind):keep:\($0)" }
        for pass in ["write", "revisit"] {
            var i = 0
            while i < keys.count {
                var bodies: [() -> Void] = []
                for j in clients.indices where i + j < keys.count {
                    let c = clients[j], key = keys[i + j]
                    bodies.append { perform(c, "\(pass)-c\(j)", kind, key, 1, ctx) }
                }
                runAll(bodies)
                i += clients.count
            }
        }
        let ops = rec.ops()
        return WorkloadResult(ops: ops, errors: countUnknown(ops), note: nil)
    }

    /// Durability: consume a key / advance a stream to 7, close the client, `restart()` the backend when the adapter can, open a new client and read back:
    /// the key must stay consumed and the counter must not go backwards (7 refused, 8 accepted).
    public static func runDurability(_ adapter: any StoreAdapter, _ kind: String, _ opts: WorkloadOptions = WorkloadOptions()) throws -> WorkloadResult {
        let o = resolve(opts)
        let rec = MemoryRecorder()
        let ctx = OpContext(rec: rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs)
        let key = "\(o.namespace):\(kind):durable"
        let before = try adapter.open()
        perform(before, "before-restart", kind, key, 7, ctx)
        before.close()
        if adapter.hasRestart { try adapter.restart() }
        let after = try adapter.open()
        perform(after, "after-restart", kind, key, 7, ctx)
        if kind == "advance" { perform(after, "after-restart", kind, key, 8, ctx) }
        after.close()
        let ops = rec.ops()
        return WorkloadResult(ops: ops, errors: countUnknown(ops),
                              note: adapter.hasRestart ? "backend restarted between write and read" : "no restart() hook: clients closed and re-opened only")
    }

    // MARK: crash

    /// Crash-run settings on top of the workload settings.
    public struct CrashOptions {
        public var workload = WorkloadOptions()
        /// Opens an adapter over the SHARED backend; called once per client process (and once for the control that crashes the backend).
        public var adapters: (() throws -> any StoreAdapter)?
        /// Client processes alive at once (default 3); `workload.clients` is per process (default 4).
        public var processes: Int?
        /// Kill one client process this often (default 400 ms; 0 = never).
        public var killEveryMs: Int?
        /// Crash + restart the backend once mid-run when the adapter has `crash()` (default true).
        public var backendCrash: Bool?
        /// History directory (default: a fresh temp dir).
        public var dir: String?
        public init(adapters: (() throws -> any StoreAdapter)? = nil) { self.adapters = adapters }
    }

    public struct CrashResult {
        public var ops: [Op]
        public var errors: Int
        public var kills: Int
        public var backendCrashes: Int
        public var torn: Int
        public var pending: Int
        public var processes: Int
    }

    private final class Proc: @unchecked Sendable {
        let rec: FileRecorder
        var killed = false
        let lock = NSLock()
        let done = DispatchSemaphore(value: 0)
        init(rec: FileRecorder) { self.rec = rec }
        func kill() { lock.lock(); killed = true; lock.unlock(); rec.kill() }
        var isKilled: Bool { lock.lock(); defer { lock.unlock() }; return killed }
    }

    /// Several client "processes" (each a group of client threads with its own history file) run the windowed workload against the same backend; every
    /// `killEveryMs` one of them is KILLED (its recorder stops writing, so its in-flight operations stay PENDING, like a SIGKILLed process) and a replacement
    /// starts under a new identity. When the adapter has `crash()` the backend is crashed and restarted once mid-run. Every writer is joined before the
    /// histories are read (a partial history can make a FALSE look unexplained).
    public static func runCrash(_ kind: String, _ o: CrashOptions) throws -> CrashResult {
        guard let adapters = o.adapters else { throw JSError("runCrash needs an adapter supplier (CrashOptions.adapters)") }
        let dir = o.dir ?? NSTemporaryDirectory() + "pcasc-hist-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let w = o.workload
        let durationMs = w.durationMs ?? 3000, killEveryMs = o.killEveryMs ?? 400
        let seed = w.seed ?? Int64.random(in: 0..<(1 << 31))
        let rand = Prng(seed: Double(seed))
        let origin = clock(), deadline = origin + durationMs
        let clients = w.clients ?? 4
        let namespace = w.namespace ?? randomNamespace()
        let windowMs = w.windowMs ?? 5, spread = w.spread ?? 3, values = w.values ?? 20
        let retentionMs = w.retentionMs ?? 600_000, opTimeoutMs = w.opTimeoutMs ?? 5000

        var live: [Proc] = [], all: [Proc] = []
        var n = 0
        func spawn() throws {
            let proc = "p\(n)"
            let procSeed = seed + 7919 * Int64(n)
            n += 1
            let rec = try FileRecorder(path: dir + "/h-\(proc).jsonl", proc: proc)
            let me = Proc(rec: rec)
            live.append(me); all.append(me)
            let t = Thread {
                crashWorker(me, adapters, kind, proc, clients, namespace, windowMs, spread, values, retentionMs, opTimeoutMs, origin, deadline, procSeed)
                me.done.signal()
            }
            t.start()
        }
        for _ in 0..<(o.processes ?? 3) { try spawn() }
        let control: (any StoreAdapter)? = try (o.backendCrash != false ? adapters() : nil)
        var kills = 0, backendCrashes = 0
        let half = origin + durationMs / 2
        while killEveryMs > 0 && clock() + Double(killEveryMs) < deadline {
            Thread.sleep(forTimeInterval: Double(killEveryMs) / 1000)
            if !live.isEmpty {
                let v = live[Int(rand.rand(Double(live.count)))]
                v.kill()
                live.removeAll { $0 === v }
                kills += 1
                try spawn()
            }
            if let c = control, c.hasCrash, backendCrashes == 0, clock() >= half {
                try c.crash()
                if c.hasRestart { try c.restart() }
                backendCrashes += 1
            }
        }
        for p in all { p.done.wait() }
        control?.teardown()
        let files = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).filter { $0.hasPrefix("h-") && $0.hasSuffix(".jsonl") }.sorted()
        var text = ""
        for f in files { text += (try? String(contentsOfFile: dir + "/" + f, encoding: .utf8)) ?? ""; text += "\n" }
        let h = parseHistory(text)
        return CrashResult(ops: h.ops, errors: countUnknown(h.ops), kills: kills, backendCrashes: backendCrashes, torn: h.torn, pending: h.pending, processes: n)
    }

    /// One client process: open an adapter, run the windowed workload on `clients` threads, record to the process's file.
    private static func crashWorker(_ me: Proc, _ adapters: () throws -> any StoreAdapter, _ kind: String, _ proc: String, _ clients: Int, _ namespace: String,
                                    _ windowMs: Double, _ spread: Int, _ values: Int, _ retentionMs: Double, _ opTimeoutMs: Int, _ origin: Double,
                                    _ deadline: Double, _ seed: Int64) {
        var cs: [any StoreClient] = []
        do {
            let adapter = try adapters() // the adapter's owner tears the backend down, never a client process
            let ctx = OpContext(rec: me.rec, retentionMs: retentionMs, opTimeoutMs: opTimeoutMs)
            cs = try openClients(adapter, clients)
            var bodies: [() -> Void] = []
            for i in cs.indices {
                let c = cs[i]
                var w = Window()
                w.namespace = namespace; w.windowMs = windowMs; w.spread = spread; w.values = values
                w.origin = origin; w.deadline = deadline; w.rand = Prng(seed: Double(seed + Int64(i)))
                w.stop = { me.isKilled }
                let win = w
                bodies.append { driveWindowed(c, proc + "c\(i)", kind, ctx, win) }
            }
            runAll(bodies)
        } catch {
            // a worker that cannot run records nothing; the parent sees fewer operations
        }
        closeClients(cs)
        me.rec.close()
    }

    // MARK: runner

    /// Workload, checker and crash settings of a run.
    public struct ConformanceOptions {
        public var workload = WorkloadOptions()
        /// Which tests to run (default all).
        public var tests: [String]?
        public var budget = PCAStoreConformance.DEFAULT_SEARCH_BUDGET
        public var minimize = true
        public var minimizeLimit = 200
        /// The crash test needs an adapter supplier over the shared backend (each "process" opens its own). Without it: skipped.
        public var crash: CrashOptions?
        public init() {}
    }

    /// One test's report: `status` is pass, fail, skip or unresolved.
    public struct TestReport: Equatable {
        public var test: String
        public var kind: String
        public var status: String
        public var ops: Int
        public var keys: Int
        public var errors: Int
        public var violations: [KeyResult]
        public var unresolved: Int
        public var note: String?

        public func json() -> JSONValue {
            var m: JObject = ["test": .string(test), "kind": .string(kind), "status": .string(status), "ops": .int(Int64(ops)), "keys": .int(Int64(keys)),
                              "errors": .int(Int64(errors)), "violations": .array(violations.map { PCAStoreConformance.json($0) }), "unresolved": .int(Int64(unresolved))]
            if let n = note { m["note"] = .string(n) }
            return .object(m)
        }
    }

    public struct ConformanceReport {
        public var adapter: String
        public var status: String
        public var tests: [TestReport]

        public func json() -> JSONValue { .object(["adapter": .string(adapter), "status": .string(status), "tests": .array(tests.map { $0.json() })]) }
        public func format() throws -> String { try PCAStoreConformance.formatReport(json(), maxKeys: 3) }
        public func jsonText() -> String { PCAStoreConformance.reportJson(json()) }
        public var ok: Bool { status == "pass" }
    }

    /// Which operations the adapter implements: declared capabilities win, else what its first client exposes.
    public static func detectKinds(_ adapter: any StoreAdapter) throws -> [String] {
        let caps = adapter.capabilities ?? Capabilities()
        let c = try adapter.open()
        defer { c.close() }
        var kinds: [String] = []
        if caps.consumeOnce ?? c.hasConsumeOnce { kinds.append("consume") }
        if caps.advance ?? c.hasAdvance { kinds.append("advance") }
        return kinds
    }

    private static func judge(_ test: String, _ kind: String, _ w: WorkloadResult, _ o: ConformanceOptions) -> TestReport {
        let h = checkHistory(w.ops, budget: o.budget, minimize: o.minimize, minimizeLimit: o.minimizeLimit)
        let definite = (h.outcomes["true"] ?? 0) + (h.outcomes["false"] ?? 0)
        let status = !h.violations.isEmpty ? "fail" : (!h.unresolved.isEmpty || definite == 0) ? "unresolved" : "pass"
        var notes: [String] = []
        if let n = w.note, !n.isEmpty { notes.append(n) }
        if definite == 0 { notes.append("no definite answer was observed (every call failed or timed out)") }
        return TestReport(test: test, kind: kind, status: status, ops: h.ops, keys: h.keys, errors: w.errors, violations: h.violations, unresolved: h.unresolved.count,
                          note: notes.isEmpty ? nil : notes.joined(separator: "; "))
    }

    private static func skip(_ test: String, _ kind: String, _ note: String) -> TestReport {
        TestReport(test: test, kind: kind, status: "skip", ops: 0, keys: 0, errors: 0, violations: [], unresolved: 0, note: note)
    }

    public static func runTest(_ adapter: any StoreAdapter, _ test: String, _ kind: String, _ opts: ConformanceOptions = ConformanceOptions()) throws -> TestReport {
        if test == "durability" && adapter.capabilities?.durable == false {
            return skip(test, kind, "the adapter declares durable: false (only correct for one process whose lifetime covers the action lifetime)")
        }
        if test == "crash" && opts.crash?.adapters == nil {
            return skip(test, kind, "needs an adapter supplier over the shared backend (the crash test runs the adapter in several client processes)")
        }
        let w: WorkloadResult
        switch test {
        case "burst": w = try runBurst(adapter, kind, opts.workload)
        case "concurrent": w = try runConcurrent(adapter, kind, opts.workload)
        case "retention": w = try runRetention(adapter, kind, opts.workload)
        case "durability": w = try runDurability(adapter, kind, opts.workload)
        case "crash":
            var c = opts.crash!
            let ow = opts.workload
            c.workload.clients = c.workload.clients ?? ow.clients
            c.workload.durationMs = c.workload.durationMs ?? ow.durationMs
            c.workload.windowMs = c.workload.windowMs ?? ow.windowMs
            c.workload.spread = c.workload.spread ?? ow.spread
            c.workload.values = c.workload.values ?? ow.values
            c.workload.retentionMs = c.workload.retentionMs ?? ow.retentionMs
            c.workload.opTimeoutMs = c.workload.opTimeoutMs ?? ow.opTimeoutMs
            c.workload.namespace = c.workload.namespace ?? ow.namespace
            c.workload.seed = c.workload.seed ?? ow.seed
            let r = try runCrash(kind, c)
            w = WorkloadResult(ops: r.ops, errors: r.errors, note: nil)
        default: throw JSError("unknown test \(test)")
        }
        return judge(test, kind, w, opts)
    }

    public static func runConformance(_ adapter: any StoreAdapter, _ opts: ConformanceOptions = ConformanceOptions()) throws -> ConformanceReport {
        let kinds = try detectKinds(adapter)
        if kinds.isEmpty { throw JSError("\(adapter.name): the client implements neither consumeOnce nor advance") }
        var tests: [TestReport] = []
        for test in opts.tests ?? ALL_TESTS { for kind in kinds { tests.append(try runTest(adapter, test, kind, opts)) } }
        return ConformanceReport(adapter: adapter.name, status: overall(tests.map { $0.json() }), tests: tests)
    }

    /// Run the kit and fail with the formatted report (counterexamples included) when the store does not pass: the test-runner binding.
    @discardableResult
    public static func assertConformance(_ adapter: any StoreAdapter, _ opts: ConformanceOptions = ConformanceOptions()) throws -> ConformanceReport {
        let r = try runConformance(adapter, opts)
        if !r.ok { throw JSError(try r.format()) }
        return r
    }
}

// MARK: reference adapters

/// Reference adapters. The GOOD ones must pass the kit; the BAD ones are positive controls the kit MUST flag (a checker that passes everything is
/// worthless). Each bad adapter reproduces one real mistake from the replay-store verification work.
extension PCAStoreConformance {
    private final class FnClient: StoreClient, @unchecked Sendable {
        let consume: ((String, Double, Double) throws -> Bool)?
        let adv: ((String, Double) throws -> Bool)?
        init(consume: ((String, Double, Double) throws -> Bool)?, advance: ((String, Double) throws -> Bool)?) { self.consume = consume; self.adv = advance }
        var hasConsumeOnce: Bool { consume != nil }
        var hasAdvance: Bool { adv != nil }
        func consumeOnce(_ key: String, retainUntilMs: Double, nowMs: Double) throws -> Bool {
            guard let f = consume else { throw JSError("consumeOnce is not implemented") }
            return try f(key, retainUntilMs, nowMs)
        }
        func advance(_ streamKey: String, counter: Double) throws -> Bool {
            guard let f = adv else { throw JSError("advance is not implemented") }
            return try f(streamKey, counter)
        }
        func close() {}
    }

    private final class FnAdapter: StoreAdapter, @unchecked Sendable {
        let name: String
        let capabilities: Capabilities?
        let openFn: () throws -> any StoreClient
        let restartFn: (() throws -> Void)?
        init(name: String, durable: Bool, consumeOnce: Bool? = nil, restart: (() throws -> Void)? = nil, open: @escaping () throws -> any StoreClient) {
            self.name = name; self.capabilities = Capabilities(consumeOnce: consumeOnce, durable: durable); self.openFn = open; self.restartFn = restart
        }
        func open() throws -> any StoreClient { try openFn() }
        var hasRestart: Bool { restartFn != nil }
        func restart() throws { try restartFn?() }
        var hasCrash: Bool { false }
        func crash() throws {}
        func teardown() {}
    }

    private static func yieldTurn() { Thread.sleep(forTimeInterval: 0.001) }

    private static func wholeMs(_ d: Double) throws -> Int64 {
        guard d.isFinite, abs(d) <= 9_007_199_254_740_991 else { throw PCAStoreArgumentError() }
        return Int64(d)
    }

    private static func memoryClient(_ store: MemoryStateStore) -> FnClient {
        FnClient(consume: { k, r, n in try store.consumeOnce(key: k, retainUntil: try wholeMs(r), now: try wholeMs(n)) },
                 advance: { k, c in store.claim(key: k, counter: try wholeMs(c)).ok })
    }

    /// GOOD for ONE process: the library's in-memory state store. Not durable (declared), not shared between processes.
    public static func inMemoryAdapter() -> any StoreAdapter {
        let store = MemoryStateStore()
        return FnAdapter(name: "in-memory (MemoryStateStore)", durable: false) { memoryClient(store) }
    }

    /// GOOD: the crash-safe, multi-process file store (`openDurableState`), one handle per client, atomic `update`. `dir` defaults to a fresh temp directory.
    public static func durableFileAdapter(dir: String? = nil) -> any StoreAdapter {
        let d = dir ?? NSTemporaryDirectory() + "pcasc-durable-" + UUID().uuidString
        return FnAdapter(name: "durable-state file store (\(d))", durable: true, restart: {}) {
            let st = try openDurableState(DurableStateOptions(dir: d))
            return FnClient(consume: { key, retainUntilMs, nowMs in
                guard nowMs.isFinite, retainUntilMs.isFinite, retainUntilMs >= nowMs else { throw JSError("RangeError: consumeOnce: retainUntilMs is before nowMs") }
                var first = false
                try st.update("n:\(key)") { prev in
                    if let p = IV.num(prev), !(nowMs.isFinite && p < nowMs) { return nil }
                    first = true
                    return numValue(retainUntilMs) // any old horizon is < now <= retainUntil here, so the new horizon is the larger one
                }
                return first
            }, advance: { key, counter in
                var ok = false
                try st.update("c:\(key)") { prev in
                    if let p = IV.num(prev), !(counter > p) { return nil }
                    ok = true
                    return numValue(counter)
                }
                return ok
            })
        }
    }

    /// BAD: read, then write after a pause (no transaction / no compare-and-set). Two clients both read "absent".
    public static func readThenWriteAdapter() -> any StoreAdapter {
        final class State: @unchecked Sendable {
            let lock = NSLock()
            var seen: [String: Double] = [:], counters: [String: Double] = [:]
        }
        let s = State()
        return FnAdapter(name: "BAD read-then-write (pause between check and set)", durable: false) {
            FnClient(consume: { k, r, now in
                s.lock.lock(); let until = s.seen[k]; s.lock.unlock()
                yieldTurn()
                if let u = until, !(now.isFinite && u < now) { return false }
                s.lock.lock(); s.seen[k] = r; s.lock.unlock()
                return true
            }, advance: { k, c in
                s.lock.lock(); let last = s.counters[k]; s.lock.unlock()
                yieldTurn()
                if let l = last, !(c > l) { return false }
                s.lock.lock(); s.counters[k] = c; s.lock.unlock()
                return true
            })
        }
    }

    /// BAD: claims durability but keeps state in process memory, so a restart forgets every consumed key and counter.
    public static func volatileAdapter() -> any StoreAdapter {
        final class Holder: @unchecked Sendable { var store = MemoryStateStore() }
        let h = Holder()
        return FnAdapter(name: "BAD volatile (state lost on restart)", durable: true, restart: { h.store = MemoryStateStore() }) { memoryClient(h.store) }
    }

    /// BAD: a bounded cache that evicts the oldest record when full, LIVE or not (capacity eviction / early prune).
    public static func evictingAdapter(capacity: Int = 64) -> any StoreAdapter {
        final class Cache: @unchecked Sendable {
            let lock = NSLock()
            var order: [String] = []
            var values: [String: Double] = [:]
            func put(_ k: String, _ v: Double, _ capacity: Int) {
                if values[k] == nil { order.append(k) }
                values[k] = v
                while order.count > capacity { values[order.removeFirst()] = nil }
            }
        }
        let seen = Cache(), counters = Cache()
        return FnAdapter(name: "BAD evicting cache (capacity \(capacity), evicts live records)", durable: false) {
            FnClient(consume: { k, r, now in
                seen.lock.lock(); defer { seen.lock.unlock() }
                if let u = seen.values[k], !(now.isFinite && u < now) { return false }
                seen.put(k, r, capacity)
                return true
            }, advance: { k, c in
                counters.lock.lock(); defer { counters.lock.unlock() }
                if let l = counters.values[k], !(c > l) { return false }
                counters.put(k, c, capacity)
                return true
            })
        }
    }

    /// BAD: a counter that accepts a value EQUAL to the last one (`>=` instead of `>`), so one counter is accepted twice.
    public static func nonStrictCounterAdapter() -> any StoreAdapter {
        final class State: @unchecked Sendable { let lock = NSLock(); var counters: [String: Double] = [:] }
        let s = State()
        return FnAdapter(name: "BAD non-strict counter (accepts an equal value)", durable: false, consumeOnce: false) {
            FnClient(consume: nil, advance: { k, c in
                s.lock.lock(); defer { s.lock.unlock() }
                if let l = s.counters[k], c < l { return false }
                s.counters[k] = c
                return true
            })
        }
    }

    /// Built-in adapters by name (`builtin:<name>`); each takes the `option k=v` pairs.
    public static let REFERENCE_ADAPTERS: [String: ([String: String]) -> any StoreAdapter] = [
        "in-memory": { _ in inMemoryAdapter() },
        "durable-file": { o in durableFileAdapter(dir: o["dir"]) },
        "bad-read-then-write": { _ in readThenWriteAdapter() },
        "bad-volatile": { _ in volatileAdapter() },
        "bad-evicting": { o in evictingAdapter(capacity: o["capacity"].flatMap { Double($0) }.map { Int($0) } ?? 64) },
        "bad-non-strict-counter": { _ in nonStrictCounterAdapter() },
    ]
}
