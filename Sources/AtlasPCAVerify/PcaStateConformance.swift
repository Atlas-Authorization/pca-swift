import Foundation
import Dispatch

// The pca-state conformance profile: run your replay store behind the REAL request guard (`PcaGuard`, full authorize path) with real signed
// PCActns, and check the replay-state invariant: one action id (grant, leaf holder, counter) goes from unconsumed to consumed at most once,
// however many copies arrive, on however many instances or processes, across crashes after the claim and retries after a timeout.
//
//     let report = PcaStateConformance(name: "postgres", open: { (store, close) }, durable: true, shared: true).run()
//     XCTAssertTrue(report.ok, report.description)
//
// Checks: claim-burst / claim-concurrent / claim-durability (the store's claim on its own, as `StateStoreConformance` runs them), one-instance
// (N concurrent copies of one proof to one guard: exactly one admitted, every round), instances (the copies spread over K guards on separate
// handles, built multi-instance: a store only an in-process lock can serialise is refused there and fails), processes (the same race across K
// child processes), crash-after-claim (admitted, then the instance dies before its handler runs: the same proof is denied afterwards, the next
// counter admitted; with a worker the instance is a child process that SIGKILLs itself right after the admission) and retry-after-timeout
// (the commit lands but its answer is lost: the guard fails closed and the retry is denied; and a retry on another instance while the first
// commit is still in flight: exactly one admitted). A check the store declares it cannot meet is skipped, never passed.
//
// The process checks need a worker: an executable of yours that calls `PcaStateConformance.workerMain` with a way to open your store.

/// How to start one worker process: the executable and the arguments that come before the configuration text.
public struct PcaStateWorker: Sendable {
    public var executable: URL
    public var arguments: [String]
    /// Passed to the worker's `open` (a database path, a connection string): never inspected here.
    public var options: [String: String]
    public init(executable: URL, arguments: [String] = [], options: [String: String] = [:]) {
        self.executable = executable
        self.arguments = arguments
        self.options = options
    }
}

/// Pre-signed PCActns (counters 1..n) from one agent under one grant, with the request headers each is sent with.
struct PcaStateFixture {
    let grant: JSONValue
    let headers: [[String: String]]
    let pin: JSONValue

    static let audience = "pca-state-conformance"
    static let operation = PCA.Operation(verb: "read", resource: "doc:1", params: .object([:]))
    private static let provenanceSeed = [UInt8](repeating: 5, count: 32)

    static func make(_ n: Int) throws -> PcaStateFixture {
        let principal = PCASuiteKey.ed25519(try PCAEdKey.generate())
        let holder = PCASuiteKey.ed25519(try PCAEdKey.generate())
        let envelope: JObject = [
            "predicates": .array([.object(["verb": .string("read"), "resource": .string("doc:*")])]),
            "caveats": .array([]), "agent_binding": .object([:]),
            "risk_policy": .object(["weights": .object(["alpha": .int(0), "beta": .int(0), "gamma": .int(0), "delta": .int(0), "epsilon": .int(0), "zeta": .int(0)]),
                                    "theta1": .double(0.5), "theta2": .double(0.8), "kappa": .int(1), "lambda": .int(0), "rho": .int(0), "bMax": .int(1000)]),
        ]
        let grant = try PCAIssue.mintGrant(principal: principal, holder: holder.id!, envelope: envelope, goal: "store conformance").grant
        let node: JObject = ["id": .string("n1"), "verb": .string("read"), "resource": .string("doc:1"), "params_digest": .string(Merkle.paramsDigest(.object([:]))),
                             "reversibility_class": .string("irreversible")]
        let plan = try PCAIssue.commitPlan([node])
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        var headers: [[String: String]] = []
        var pin: JSONValue = .null
        for i in 1...max(1, n) {
            let p = try PCAIssue.buildPCActn(.init(grant: grant, chain: [grant], plan: plan, nodeId: "n1", params: .object([:]), counter: Int64(i), signer: holder,
                                                    aud: audience, iat: now, extras: ["nonce": .string(PCAIssue.random(16))]))
            let recorder = try ProvenanceRecorder(mediator: "pca-state-conformance", kid: "k1", signer: .ed25519(try PCAEdKey(seed: provenanceSeed)))
            pin = recorder.pin
            headers.append(PCAIssue.headers(p, provenance: try PCA.principalDirectProvenance(recorder, operation)))
        }
        return PcaStateFixture(grant: grant, headers: headers, pin: pin)
    }

    var json: JSONValue {
        .object(["grant": grant, "pin": pin, "headers": .array(headers.map { h in .object(Dictionary(uniqueKeysWithValues: h.map { (JKey($0.key), JSONValue.string($0.value)) })) })])
    }

    static func from(_ v: JSONValue?) -> PcaStateFixture? {
        guard let g = v?.get("grant"), let pin = v?.get("pin"), let hs = v?.get("headers")?.asArray else { return nil }
        var out: [[String: String]] = []
        for h in hs {
            guard let o = h.asObject, o.values.allSatisfy({ $0.asString != nil }) else { return nil }
            out.append(Dictionary(uniqueKeysWithValues: o.map { ($0.key.s, $0.value.asString!) }))
        }
        return PcaStateFixture(grant: g, headers: out, pin: pin)
    }

    /// The guard under test: the real `PcaGuard`, full authorize path, the store as the replay store.
    func guardFor(_ store: any PCAStateStore, multiInstance: Bool) throws -> PcaGuard {
        let g = grant
        var az = PcaAuthorizeConfig(stateStore: store, isRevoked: { _, _ in false }, plan: PCA.SINGLE_STEP, operation: { _ in Self.operation },
                                    riskSource: PCA.insecureCalmRisk)
        az.multiInstance = multiInstance
        az.argProvenance = ArgProvenanceOptions(mediators: [pin])
        return try PcaGuard(PcaGuardConfig(audience: Self.audience, resolveGrant: { _ in g }, authorize: az))
    }

    func request(_ counter: Int) -> PcaGuardRequest { PcaGuardRequest(method: "POST", path: "/doc/1", headers: headers[counter - 1]) }
}

enum PcaStateOutcome: String {
    case admitted, replay, error

    /// admitted / denied as a replay (the counter check failed) / any other denial (fail closed, e.g. a store error).
    static func of(_ d: PcaGuardDecision) -> PcaStateOutcome {
        switch d {
        case .allow: return .admitted
        case let .deny(x):
            // a replay is the counter check refusing the counter; a store that failed (a lost answer, a timeout) also marks the replay check but is an ERROR,
            // exactly as the reference tells the two apart: only a reason that names the replay itself counts
            guard let a = x.authorization, a.checks["replay"] == .fail else { return .error }
            return a.reasons.contains { $0.contains("(replay)") } ? .replay : .error
        }
    }
}

/// A claim that blocks until released, to hold a commit in flight.
final class GatedStateStore: PCAStateStore, @unchecked Sendable {
    let inner: PCAStateStore
    let entered = DispatchSemaphore(value: 0)
    let gate = DispatchSemaphore(value: 0)
    init(_ inner: PCAStateStore) { self.inner = inner }
    var scope: PCAStoreScope { inner.scope }
    func claim(key: String, counter: Int64) throws -> ClaimResult {
        entered.signal()
        gate.wait()
        return try inner.claim(key: key, counter: counter)
    }
}

/// Configures `PcaStateConformance.run`.
public struct PcaStateConformance {
    public var name: String
    /// Returns a NEW handle onto the SAME backend each call (one handle = one verifier instance's connection), and how to close it.
    public var open: () throws -> (store: any PCAStateStore, close: () -> Void)
    /// Crashes and restarts the backend; it runs between closing the handles and reopening.
    public var restart: (() throws -> Void)?
    /// State survives closing every handle (and `restart`). False skips the durability and crash checks.
    public var durable: Bool
    /// Several handles can share the backend. False skips the instance and process checks.
    public var shared: Bool
    /// The process checks and the process half of crash-after-claim; without it they are skipped.
    public var worker: PcaStateWorker?
    public var rounds: Int
    public var copies: Int
    public var instances: Int
    public var processes: Int

    public init(name: String, open: @escaping () throws -> (store: any PCAStateStore, close: () -> Void), restart: (() throws -> Void)? = nil,
                durable: Bool = false, shared: Bool = false, worker: PcaStateWorker? = nil, rounds: Int = 10, copies: Int = 16, instances: Int = 4, processes: Int = 3) {
        self.name = name
        self.open = open
        self.restart = restart
        self.durable = durable
        self.shared = shared
        self.worker = worker
        self.rounds = rounds
        self.copies = copies
        self.instances = instances
        self.processes = processes
    }

    private func openN(_ n: Int) throws -> [(store: any PCAStateStore, close: () -> Void)] {
        var out: [(store: any PCAStateStore, close: () -> Void)] = []
        for _ in 0..<n {
            do { out.append(try open()) } catch {
                out.forEach { $0.close() }
                throw PCAFailure("open: \(errorMessage(error))")
            }
        }
        return out
    }

    private func outcome(_ g: PcaGuard, _ fx: PcaStateFixture, _ counter: Int) -> PcaStateOutcome { PcaStateOutcome.of(g.handle(fx.request(counter))) }

    /// How many of `copies` presentations of the proof with `counter` were admitted, spread over `guards`.
    private func race(_ fx: PcaStateFixture, _ guards: [PcaGuard], _ counter: Int, _ copies: Int) -> Int {
        let wins = ConformanceCounter()
        DispatchQueue.concurrentPerform(iterations: max(1, copies)) { i in
            if outcome(guards[i % guards.count], fx, counter) == .admitted { wins.add() }
        }
        return wins.value
    }

    /// Runs every check.
    public func run() -> StoreConformanceReport {
        var rep = StoreConformanceReport(name: name)
        let base = StateStoreConformance(name: name, open: open, restart: restart, durable: durable, shared: shared, rounds: rounds, copies: copies, handles: instances).run()
        for c in base.checks where c.name.hasPrefix("claim-") {
            if c.status == "skip" { rep.skip(c.name, c.note) } else { rep.add(c.name, c.status == "fail" ? c.note : nil, c.note) }
        }
        let nRounds = max(1, rounds), nCopies = max(1, copies)
        rep.add("one-instance", raceCheck(handles: 1, multiInstance: false, rounds: nRounds, copies: nCopies))
        if shared {
            rep.add("instances", raceCheck(handles: max(1, instances), multiInstance: true, rounds: nRounds, copies: nCopies))
        } else {
            rep.skip("instances", "shared is false (one instance only)")
        }
        #if os(macOS) || os(Linux)
        if !shared { rep.skip("processes", "shared is false (one instance only)") } else if let w = worker { rep.add("processes", processRace(w, rounds: nRounds, copies: nCopies)) } else {
            rep.skip("processes", "needs a worker executable (the guards run in child processes)")
        }
        #else
        rep.skip("processes", "child processes are not available on this platform")
        #endif
        if durable { rep.add("crash-after-claim", crashAfterClaim()) } else { rep.skip("crash-after-claim", "durable is false (state dies with the process)") }
        rep.add("retry-after-timeout", retryAfterTimeout())
        return rep
    }

    private func raceCheck(handles: Int, multiInstance: Bool, rounds: Int, copies: Int) -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(handles) } catch { return errorMessage(error) }
        defer { hs.forEach { $0.close() } }
        do {
            let fx = try PcaStateFixture.make(rounds)
            let guards: [PcaGuard]
            do { guards = try hs.map { try fx.guardFor($0.store, multiInstance: multiInstance) } } catch { return "refused in multi-instance mode: \(errorMessage(error))" }
            for r in 1...rounds {
                let n = race(fx, guards, r, copies)
                if n != 1 { return "round \(r): \(n) of \(copies) copies of one proof were admitted (want exactly 1)" }
            }
            return nil
        } catch { return errorMessage(error) }
    }

    private func crashAfterClaim() -> String? {
        let h1: [(store: any PCAStateStore, close: () -> Void)]
        do { h1 = try openN(1) } catch { return errorMessage(error) }
        do {
            let fx = try PcaStateFixture.make(max(4, rounds))
            // in process: admitted on handle 1, which is then abandoned (never closed); the backend restarts when it can
            let first = outcome(try fx.guardFor(h1[0].store, multiInstance: shared), fx, 1)
            if let rs = restart { do { try rs() } catch { h1.forEach { $0.close() }; return "restart: \(errorMessage(error))" } }
            let h2: [(store: any PCAStateStore, close: () -> Void)]
            do { h2 = try openN(1) } catch { h1.forEach { $0.close() }; return errorMessage(error) }
            let g = try fx.guardFor(h2[0].store, multiInstance: shared)
            let again = outcome(g, fx, 1), next = outcome(g, fx, 2)
            h2.forEach { $0.close() }
            h1.forEach { $0.close() }
            if first != .admitted || again != .replay || next != .admitted {
                return "in process: admitted=\(first.rawValue), same proof after the instance died=\(again.rawValue), next counter=\(next.rawValue)"
            }
            #if os(macOS) || os(Linux)
            if let w = worker { return processCrash(w, fx) }
            #endif
            return nil
        } catch {
            h1.forEach { $0.close() }
            return errorMessage(error)
        }
    }

    private func retryAfterTimeout() -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(shared ? 2 : 1) } catch { return errorMessage(error) }
        defer { hs.forEach { $0.close() } }
        do {
            let fx = try PcaStateFixture.make(4)
            let other = hs[hs.count - 1].store
            // 1. the commit lands, its answer is lost: the guard fails closed, the retry (another instance when shared) is a replay
            let first = outcome(try fx.guardFor(LossyStateStore(hs[0].store), multiInstance: shared), fx, 1)
            let og = try fx.guardFor(other, multiInstance: shared)
            let retry = outcome(og, fx, 1), next = outcome(og, fx, 2)
            if first != .error || retry != .replay || next != .admitted {
                return "lost answer: first=\(first.rawValue), retry=\(retry.rawValue), next counter=\(next.rawValue)"
            }
            // 2. the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
            let slow = GatedStateStore(hs[0].store)
            let sg = try fx.guardFor(slow, multiInstance: shared)
            let results = ConformanceCounter()
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global().async {
                if self.outcome(sg, fx, 3) == .admitted { results.add() }
                group.leave()
            }
            slow.entered.wait()
            group.enter()
            DispatchQueue.global().async {
                if self.outcome(og, fx, 3) == .admitted { results.add() }
                group.leave()
            }
            slow.gate.signal()
            group.wait()
            if results.value != 1 { return "in-flight retry: \(results.value) admitted of 2 (want exactly 1)" }
            return nil
        } catch { return errorMessage(error) }
    }

    // ---- child processes ----

    #if os(macOS) || os(Linux)
    private struct WorkerLine { let counter: Int; let admitted: Int; let replays: Int; let errors: Int }

    private struct WorkerRun {
        var signalled: Bool
        var lines: [WorkerLine]
        var admitted: Int { lines.reduce(0) { $0 + $1.admitted } }
        var replays: Int { lines.reduce(0) { $0 + $1.replays } }
    }

    private func start(_ w: PcaStateWorker, _ fx: PcaStateFixture, _ cfg: JObject, out: String) throws -> Process {
        var c = cfg
        c["fixture"] = fx.json
        c["out"] = .string(out)
        var o = JObject()
        for (k, v) in w.options { o[JKey(k)] = .string(v) }
        c["options"] = .object(o)
        let p = Process()
        p.executableURL = w.executable
        p.arguments = w.arguments + [Canonical.canonicalize(.object(c))]
        try p.run()
        return p
    }

    private func finish(_ p: Process, out: String) -> WorkerRun {
        p.waitUntilExit()
        var lines: [WorkerLine] = []
        if let text = try? String(contentsOfFile: out, encoding: .utf8) {
            for l in text.split(separator: "\n") {
                guard let v = JSONValue.parse(String(l)), let c = v.get("counter")?.safeInt else { continue }
                lines.append(WorkerLine(counter: Int(c), admitted: Int(v.get("admitted")?.safeInt ?? 0), replays: Int(v.get("replays")?.safeInt ?? 0), errors: Int(v.get("errors")?.safeInt ?? 0)))
            }
        }
        return WorkerRun(signalled: p.terminationReason == .uncaughtSignal, lines: lines)
    }

    private func tempDir() throws -> String {
        let d = NSTemporaryDirectory() + "pcasc-pstate-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        return d
    }

    private func processRace(_ w: PcaStateWorker, rounds: Int, copies: Int) -> String? {
        do {
            let fx = try PcaStateFixture.make(rounds)
            let dir = try tempDir()
            defer { try? FileManager.default.removeItem(atPath: dir) }
            let origin = Int64(Date().timeIntervalSince1970 * 1000) + 3000 // time for every process to start and open its handles
            var ps: [(Process, String)] = []
            for i in 0..<max(1, processes) {
                let out = dir + "/p\(i).jsonl"
                ps.append((try start(w, fx, ["mode": .string("race"), "rounds": .int(Int64(rounds)), "origin": .int(origin), "roundMs": .int(150),
                                             "copies": .int(Int64(copies)), "instances": .int(2)], out: out), out))
            }
            let runs = ps.map { finish($0.0, out: $0.1) }
            for r in 1...rounds {
                let n = runs.reduce(0) { $0 + $1.lines.filter { $0.counter == r }.reduce(0) { $0 + $1.admitted } }
                if n != 1 { return "round \(r): \(n) presentations admitted across \(runs.count) processes (want exactly 1)" }
            }
            if let bad = runs.first(where: { $0.signalled || $0.lines.count != rounds }) { return "a worker did not finish (\(bad.lines.count) of \(rounds) rounds recorded)" }
            return nil
        } catch { return errorMessage(error) }
    }

    /// A child process admits counter 3 and is SIGKILLed before its handler; a new process retries it; the next counter is admitted.
    private func processCrash(_ w: PcaStateWorker, _ fx: PcaStateFixture) -> String? {
        do {
            let dir = try tempDir()
            defer { try? FileManager.default.removeItem(atPath: dir) }
            func one(_ mode: String, _ counter: Int, _ file: String) throws -> WorkerRun {
                finish(try start(w, fx, ["mode": .string(mode), "counter": .int(Int64(counter)), "copies": .int(1), "instances": .int(1)], out: dir + "/" + file), out: dir + "/" + file)
            }
            let killed = try one("admit-then-die", 3, "a.jsonl")
            if let rs = restart { try rs() }
            let retried = try one("race", 3, "b.jsonl")
            let fresh = try one("race", 4, "c.jsonl")
            if !(killed.signalled && killed.admitted == 1 && retried.admitted == 0 && retried.replays == 1 && fresh.admitted == 1) {
                return "child process: killed after admission=\(killed.signalled && killed.admitted == 1), retry in a new process admitted \(retried.admitted), next counter admitted \(fresh.admitted)"
            }
            return nil
        } catch { return errorMessage(error) }
    }

    // ---- the worker side ----

    /// The entry of one worker process: `configText` is the last argument the parent passed; `open` opens a handle onto the shared backend from the
    /// parent's `options`. Returns the process exit status. Mode `admit-then-die` records the admission and SIGKILLs the process before any handler.
    public static func workerMain(_ configText: String, open: ([String: String]) throws -> (store: any PCAStateStore, close: () -> Void)) -> Int32 {
        guard let cfg = JSONValue.parse(configText), let fx = PcaStateFixture.from(cfg.get("fixture")), let out = cfg.get("out")?.asString else { return 2 }
        var options: [String: String] = [:]
        for (k, v) in cfg.get("options")?.asObject ?? [:] { if let s = v.asString { options[k.s] = s } }
        let nInstances = Int(cfg.get("instances")?.safeInt ?? 1), copies = Int(cfg.get("copies")?.safeInt ?? 1)
        let mode = cfg.get("mode")?.asString ?? "race"
        do {
            var handles: [(store: any PCAStateStore, close: () -> Void)] = []
            for _ in 0..<max(1, nInstances) { handles.append(try open(options)) }
            let guards = try handles.map { try fx.guardFor($0.store, multiInstance: true) }
            func record(_ counter: Int, _ rs: [PcaStateOutcome]) {
                let line = Canonical.canonicalize(.object(["counter": .int(Int64(counter)), "admitted": .int(Int64(rs.filter { $0 == .admitted }.count)),
                                                           "replays": .int(Int64(rs.filter { $0 == .replay }.count)), "errors": .int(Int64(rs.filter { $0 == .error }.count))])) + "\n"
                if let h = FileHandle(forWritingAtPath: out) { h.seekToEndOfFile(); h.write(Data(line.utf8)); h.closeFile() } else {
                    FileManager.default.createFile(atPath: out, contents: Data(line.utf8))
                }
            }
            func presentations(_ counter: Int) -> [PcaStateOutcome] {
                var res = [PcaStateOutcome](repeating: .error, count: max(1, copies))
                let lock = PCALock()
                DispatchQueue.concurrentPerform(iterations: res.count) { i in
                    let o = PcaStateOutcome.of(guards[i % guards.count].handle(fx.request(counter)))
                    lock.lock(); res[i] = o; lock.unlock()
                }
                return res
            }
            if mode == "admit-then-die" {
                let counter = Int(cfg.get("counter")?.safeInt ?? 1)
                record(counter, presentations(counter))
                kill(getpid(), SIGKILL)
                return 3
            }
            let rounds = Int(cfg.get("rounds")?.safeInt ?? 1)
            for r in 0..<rounds {
                let counter = cfg.get("counter")?.safeInt.map { Int($0) } ?? r + 1
                let at = (cfg.get("origin")?.safeInt ?? Int64(Date().timeIntervalSince1970 * 1000)) + Int64(r) * (cfg.get("roundMs")?.safeInt ?? 0)
                while Int64(Date().timeIntervalSince1970 * 1000) < at { usleep(2000) }
                record(counter, presentations(counter))
            }
            handles.forEach { $0.close() }
            return 0
        } catch { return 1 }
    }
    #endif
}
