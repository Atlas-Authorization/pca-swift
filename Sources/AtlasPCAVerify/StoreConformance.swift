import Foundation
import Dispatch

// Store conformance: run your replay store (`PCAStateStore`, the one behind `PCA.authorize`) and your `OperationStore` through the
// invariants the guards rely on, from a test in your own repository:
//
//     let report = StateStoreConformance(name: "postgres", open: { (store, close) }, durable: true, shared: true).run()
//     XCTAssertTrue(report.ok, report.description)
//
// State store checks: claim-burst (strictly increasing counters admitted once each, repeats and older counters refused),
// claim-concurrent (N copies of one counter on several handles: exactly one admitted, every round; distinct counters in a race never
// admit the same one twice and always admit the highest), claim-durability (state survives closing every handle and a restart),
// crash-after-claim (admitted, then the instance dies without closing: the same counter stays refused), retry-after-timeout (the claim
// commits but its answer is lost: the retry is refused, the next counter admitted). Operation store checks: create-once,
// transition-once, wrong-state, get-missing, shared, durability. A check the store declares it cannot meet (not `durable`, not
// `shared`) is skipped, never passed.

/// The outcome of one check: `status` is "pass", "fail" or "skip".
public struct StoreConformanceCheck: Equatable, Sendable {
    public let name: String
    public let status: String
    public let note: String
}

/// The outcome of a conformance run.
public struct StoreConformanceReport: CustomStringConvertible, Sendable {
    public let name: String
    public private(set) var checks: [StoreConformanceCheck] = []

    init(name: String) { self.name = name }

    /// True when no check failed.
    public var ok: Bool { !checks.contains { $0.status == "fail" } }

    mutating func add(_ check: String, _ failure: String?, _ note: String = "") {
        checks.append(StoreConformanceCheck(name: check, status: failure == nil ? "pass" : "fail", note: failure ?? note))
    }

    mutating func skip(_ check: String, _ why: String) { checks.append(StoreConformanceCheck(name: check, status: "skip", note: why)) }

    public var description: String {
        var s = "store conformance: \(name) -> \(ok ? "PASS" : "FAIL")\n"
        for c in checks { s += "  [\(c.status.uppercased())] \(c.name) \(c.note)\n" }
        return s
    }
}

/// A counter several threads bump.
final class ConformanceCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func add(_ k: Int = 1) {
        lock.lock()
        defer { lock.unlock() }
        n += k
    }
    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return n
    }
}

private func confKey(_ prefix: String) -> String { "conf:\(UUID().uuidString):\(prefix)" }

private func race(_ n: Int, _ body: (Int) -> Void) { DispatchQueue.concurrentPerform(iterations: n, execute: body) }

/// A state store that commits a claim and then loses the answer once.
private final class LossyStateStore: PCAStateStore, @unchecked Sendable {
    let inner: PCAStateStore
    private let lock = NSLock()
    private var lose = true
    init(_ inner: PCAStateStore) { self.inner = inner }
    func claim(key: String, counter: Int64) throws -> ClaimResult {
        let r = try inner.claim(key: key, counter: counter)
        lock.lock()
        let lost = lose
        lose = false
        lock.unlock()
        if lost { throw PCAFailure("timeout (answer lost after commit)") }
        return r
    }
}

/// Configures `StateStoreConformance.run`.
public struct StateStoreConformance {
    public var name: String
    /// Returns a NEW handle onto the SAME backend each call (one handle = one verifier instance's connection), and how to close it.
    public var open: () throws -> (store: any PCAStateStore, close: () -> Void)
    /// Crashes and restarts the backend; it runs between closing the handles and reopening.
    public var restart: (() throws -> Void)?
    /// State survives closing every handle (and `restart`). False skips the durability checks.
    public var durable: Bool
    /// Several handles can share the backend. False runs the race checks on one handle.
    public var shared: Bool
    /// The size of the race checks: rounds (default 10), copies (16) and handles (4).
    public var rounds: Int
    public var copies: Int
    public var handles: Int

    public init(name: String, open: @escaping () throws -> (store: any PCAStateStore, close: () -> Void), restart: (() throws -> Void)? = nil,
                durable: Bool = false, shared: Bool = false, rounds: Int = 10, copies: Int = 16, handles: Int = 4) {
        self.name = name
        self.open = open
        self.restart = restart
        self.durable = durable
        self.shared = shared
        self.rounds = rounds
        self.copies = copies
        self.handles = handles
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

    private func claim(_ s: PCAStateStore, _ key: String, _ n: Int64) -> (ok: Bool, err: String?) {
        do { return (try s.claim(key: key, counter: n).ok, nil) } catch { return (false, errorMessage(error)) }
    }

    /// Runs the state store checks.
    public func run() -> StoreConformanceReport {
        var rep = StoreConformanceReport(name: name)
        let handleCount = shared ? max(1, handles) : 1
        rep.add("claim-burst", claimBurst())
        rep.add("claim-concurrent", claimConcurrent(handleCount), "\(max(1, rounds)) rounds x \(max(1, copies)) copies over \(handleCount) handle(s)")
        if durable {
            rep.add("claim-durability", claimDurability())
            rep.add("crash-after-claim", crashAfterClaim())
        } else {
            rep.skip("claim-durability", "durable is false (state dies with the process)")
            rep.skip("crash-after-claim", "durable is false (state dies with the process)")
        }
        rep.add("retry-after-timeout", retryAfterTimeout())
        return rep
    }

    private func claimBurst() -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(1) } catch { return errorMessage(error) }
        defer { hs.forEach { $0.close() } }
        let s = hs[0].store, key = confKey("burst")
        let n: Int64 = 25
        for i in 1...n {
            let r = claim(s, key, i)
            if !r.ok { return "counter \(i) was not admitted on first use (err \(r.err ?? "none"))" }
        }
        for i in stride(from: n, through: 1, by: -1) {
            let r = claim(s, key, i)
            if let e = r.err { return "replay of counter \(i) errored: \(e)" }
            if r.ok { return "counter \(i) was admitted twice (or an older counter was admitted after a newer one)" }
        }
        let next = claim(s, key, n + 1)
        if !next.ok { return "the next counter after refusals was not admitted (err \(next.err ?? "none"))" }
        // keys are independent streams
        let other = claim(s, confKey("burst-other"), 1)
        if !other.ok { return "a fresh key refused counter 1 (err \(other.err ?? "none"))" }
        return nil
    }

    private func claimConcurrent(_ handleCount: Int) -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(handleCount) } catch { return errorMessage(error) }
        defer { hs.forEach { $0.close() } }
        let nRounds = max(1, rounds), nCopies = max(1, copies)
        let key = confKey("concurrent")
        for round in 1...nRounds {
            let wins = ConformanceCounter(), errs = ConformanceCounter()
            race(nCopies) { i in
                let r = self.claim(hs[i % hs.count].store, key, Int64(round))
                if r.err != nil { errs.add() } else if r.ok { wins.add() }
            }
            if wins.value != 1 { return "round \(round): \(wins.value) of \(nCopies) copies of one counter were admitted (want exactly 1; \(errs.value) errors)" }
        }
        // distinct counters racing on one key: the highest is always admitted and nothing is admitted twice
        let base = Int64(nRounds)
        let key2 = confKey("concurrent-distinct")
        let admitted = ConformanceCounter(), highest = ConformanceCounter()
        race(nCopies) { i in
            let n = i + 1
            if self.claim(hs[n % hs.count].store, key2, base + Int64(n)).ok {
                admitted.add()
                if n == nCopies { highest.add() }
            }
        }
        if highest.value != 1 { return "the highest of \(nCopies) racing counters was not admitted" }
        for i in 1...nCopies {
            let r = claim(hs[0].store, key2, base + Int64(i))
            if r.ok || r.err != nil { return "counter \(base + Int64(i)) is admitted again after the race (err \(r.err ?? "none"))" }
        }
        return nil
    }

    private func afterReopen(_ key: String, used: Int64, next: Int64, _ what: String) -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(1) } catch { return errorMessage(error) }
        defer { hs.forEach { $0.close() } }
        let again = claim(hs[0].store, key, used)
        if again.ok || again.err != nil { return "counter \(used) was admitted again after \(what) (err \(again.err ?? "none"))" }
        let n = claim(hs[0].store, key, next)
        if !n.ok { return "counter \(next) was not admitted after \(what) (err \(n.err ?? "none"))" }
        return nil
    }

    private func claimDurability() -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(1) } catch { return errorMessage(error) }
        let key = confKey("durability")
        for i in 1...3 {
            let r = claim(hs[0].store, key, Int64(i))
            if !r.ok {
                hs.forEach { $0.close() }
                return "counter \(i) was not admitted (err \(r.err ?? "none"))"
            }
        }
        hs.forEach { $0.close() }
        if let rs = restart { do { try rs() } catch { return "restart: \(errorMessage(error))" } }
        return afterReopen(key, used: 3, next: 4, "closing every handle")
    }

    private func crashAfterClaim() -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(1) } catch { return errorMessage(error) }
        // the instance dies after the claim and before its handler ran: its handle is abandoned, never closed
        let key = confKey("crash")
        let r = claim(hs[0].store, key, 1)
        if !r.ok { return "counter 1 was not admitted (err \(r.err ?? "none"))" }
        if let rs = restart { do { try rs() } catch { return "restart: \(errorMessage(error))" } }
        let out = afterReopen(key, used: 1, next: 2, "the instance died")
        hs.forEach { $0.close() }
        return out
    }

    private func retryAfterTimeout() -> String? {
        let hs: [(store: any PCAStateStore, close: () -> Void)]
        do { hs = try openN(2) } catch { return errorMessage(error) }
        defer { hs.forEach { $0.close() } }
        let first = hs[0].store
        let other = shared ? hs[hs.count - 1].store : first
        let lossy = LossyStateStore(first)
        let key = confKey("retry")
        let lost = claim(lossy, key, 1)
        if lost.ok || lost.err == nil { return "the lossy wrapper must lose the first answer" }
        let retry = claim(other, key, 1)
        if retry.ok || retry.err != nil { return "the retry of a claim whose answer was lost was admitted (err \(retry.err ?? "none")): the commit had already landed" }
        let next = claim(other, key, 2)
        if !next.ok { return "the next counter after the retry was not admitted (err \(next.err ?? "none"))" }
        return nil
    }
}

/// Configures `OperationStoreConformance.run`.
public struct OperationStoreConformance {
    public var name: String
    /// Returns a NEW handle onto the SAME backend each call, and how to close it.
    public var open: () throws -> (store: any OperationStore, close: () -> Void)
    public var restart: (() throws -> Void)?
    /// Records survive closing every handle (and `restart`).
    public var durable: Bool
    /// Handles share the backend.
    public var shared: Bool
    /// Concurrent callers per race (default 16).
    public var copies: Int

    public init(name: String, open: @escaping () throws -> (store: any OperationStore, close: () -> Void), restart: (() throws -> Void)? = nil,
                durable: Bool = false, shared: Bool = false, copies: Int = 16) {
        self.name = name
        self.open = open
        self.restart = restart
        self.durable = durable
        self.shared = shared
        self.copies = copies
    }

    private func record(_ id: String) -> OperationRecord {
        OperationRecord(id: id, state: .pending, verb: "v", resource: "/r", paramsDigest: "d", reversibility: "reversible", startedAt: 1)
    }

    private func handles(_ n: Int) throws -> [(store: any OperationStore, close: () -> Void)] {
        var out: [(store: any OperationStore, close: () -> Void)] = []
        for _ in 0..<n {
            do { out.append(try open()) } catch {
                out.forEach { $0.close() }
                throw PCAFailure("open: \(errorMessage(error))")
            }
        }
        return out
    }

    /// Runs the operation store checks.
    public func run() -> StoreConformanceReport {
        var rep = StoreConformanceReport(name: name)
        let nCopies = max(1, copies)
        rep.add("create-once", check(shared ? 2 : 1) { hs in
            let id = confKey("create")
            let created = ConformanceCounter()
            race(nCopies) { i in
                switch try? hs[i % hs.count].store.create(self.record(id)) {
                case .created?: created.add()
                case let .existing(r)?: if r.id != id { created.add(100) }
                case nil: break
                }
            }
            return created.value == 1 ? nil : "\(created.value) concurrent creates of one id reported created (want exactly 1; >=100 means a loser got no existing record)"
        })
        rep.add("transition-once", check(shared ? 2 : 1) { hs in
            let id = confKey("transition")
            guard case .created? = try? hs[0].store.create(self.record(id)) else { return "create failed" }
            let won = ConformanceCounter()
            race(nCopies) { i in
                var next = self.record(id)
                next.state = .executing
                if (try? hs[i % hs.count].store.transition(id, from: .pending, to: next)) == true { won.add() }
            }
            return won.value == 1 ? nil : "\(won.value) concurrent transitions out of pending won (want exactly 1)"
        })
        rep.add("wrong-state", check(1) { hs in
            let s = hs[0].store
            let id = confKey("wrong")
            guard case .created? = try? s.create(self.record(id)) else { return "create failed" }
            var next = self.record(id)
            next.state = .committed
            if (try? s.transition(id, from: .executing, to: next)) != false { return "a transition from the wrong state applied (or errored)" }
            guard let got = (try? s.get(id)) ?? nil, got.state == .pending else { return "the record changed after a refused transition" }
            if (try? s.transition(confKey("missing"), from: .pending, to: next)) != false { return "a transition of an unknown id applied (or errored)" }
            return nil
        })
        rep.add("get-missing", check(1) { hs in
            do {
                return try hs[0].store.get(confKey("never")) == nil ? nil : "an unknown id returned a record"
            } catch {
                return "get of an unknown id errored: \(errorMessage(error))"
            }
        })
        if shared {
            rep.add("shared", check(2) { hs in
                let id = confKey("shared")
                guard case .created? = try? hs[0].store.create(self.record(id)) else { return "create failed" }
                guard let got = (try? hs[1].store.get(id)) ?? nil, got.id == id else { return "another handle does not see the record" }
                return nil
            })
        } else {
            rep.skip("shared", "shared is false")
        }
        if durable {
            rep.add("durability", durability())
        } else {
            rep.skip("durability", "durable is false")
        }
        return rep
    }

    /// Opens `n` handles, runs `body`, closes them. The body returns a failure message or nil.
    private func check(_ n: Int, _ body: ([(store: any OperationStore, close: () -> Void)]) -> String?) -> String? {
        let hs: [(store: any OperationStore, close: () -> Void)]
        do { hs = try handles(n) } catch { return errorMessage(error) }
        defer { hs.forEach { $0.close() } }
        return body(hs)
    }

    private func durability() -> String? {
        let id = confKey("durable")
        do {
            let a = try open()
            guard case .created? = try? a.store.create(record(id)) else {
                a.close()
                return "create failed"
            }
            a.close()
        } catch {
            return errorMessage(error)
        }
        if let rs = restart { do { try rs() } catch { return "restart: \(errorMessage(error))" } }
        do {
            let b = try open()
            defer { b.close() }
            guard let got = (try? b.store.get(id)) ?? nil, got.state == .pending else { return "the record did not survive closing every handle" }
        } catch {
            return errorMessage(error)
        }
        return nil
    }
}
