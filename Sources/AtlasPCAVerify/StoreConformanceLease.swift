import Foundation

/// Conformance for PCA guardian lease stores (lease-conformance.ts). A lease store holds the one record that says who the guardian leader is. What it must
/// get right: the compare-and-swap is linearizable (one winner among racing contenders, a wrong `expected` never writes), the fencing epoch never goes down,
/// a stale holder cannot renew or release after a takeover, its clock is a finite number, and acknowledged leases survive a restart or crash. Each check is one
/// such claim, driven against YOUR store through a `LeaseStoreAdapter`.
extension PCAStoreConformance {
    public struct LeaseRecord: Equatable {
        public var holder: String
        /// The fencing epoch: it increments on every takeover and never goes down.
        public var epoch: Int64
        public var expiresAt: Double
        public init(holder: String, epoch: Int64, expiresAt: Double) { self.holder = holder; self.epoch = epoch; self.expiresAt = expiresAt }
    }

    /// The store under test: `read` the record (nil: never held), `now` the store's clock (epoch ms) and `cas(expected, next)`, which replaces the record iff
    /// the stored one equals `expected` (nil: none), atomically, and never lowers the epoch.
    public protocol LeaseStore: AnyObject {
        func read() throws -> LeaseRecord?
        func now() throws -> Double
        func cas(_ expected: LeaseRecord?, _ next: LeaseRecord) throws -> Bool
    }

    public struct LeaseStoreHandle {
        public var store: any LeaseStore
        /// Another client on the SAME backend (the first stays usable).
        public var reopen: () throws -> any LeaseStore
        /// Optional: kill the backend abruptly, then return a client on whatever survived.
        public var crash: (() throws -> any LeaseStore)?
        public var close: (() -> Void)?
        public init(store: any LeaseStore, reopen: @escaping () throws -> any LeaseStore, crash: (() throws -> any LeaseStore)? = nil, close: (() -> Void)? = nil) {
            self.store = store; self.reopen = reopen; self.crash = crash; self.close = close
        }
    }

    public struct LeaseStoreAdapter {
        public var name: String
        /// Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported.
        public var durable: Bool?
        public var create: () throws -> LeaseStoreHandle
        public init(name: String, durable: Bool? = nil, create: @escaping () throws -> LeaseStoreHandle) { self.name = name; self.durable = durable; self.create = create }
    }

    public struct LeaseCheck {
        public var name: String
        public var claim: String
        /// nil, `durable` or `crash`.
        public var needs: String?
        public var run: (LeaseStoreHandle) throws -> Void
    }

    public struct LeaseCheckResult: Equatable {
        public var name: String
        /// `pass`, `fail` or `skip`.
        public var status: String
        public var detail: String?
    }

    public struct LeaseConformanceReport: Equatable {
        public var adapter: String
        public var status: String
        public var checks: [LeaseCheckResult]
    }

    // MARK: the guardian lease helpers the checks drive

    public static let DEFAULT_LEASE_SKEW_MS = 1_000.0
    public static let MAX_LEASE_TTL_MS = 3_600_000.0

    public struct LeaseOutcome: Equatable {
        public var ok: Bool
        public var lease: LeaseRecord?
        public var reason: String?
        static func fail(_ r: String) -> LeaseOutcome { LeaseOutcome(ok: false, lease: nil, reason: r) }
    }

    private static func validRecord(_ r: LeaseRecord) -> Bool { r.epoch >= 1 && r.epoch <= Canonical.MAX_SAFE && r.expiresAt.isFinite && r.expiresAt >= 0 }

    private static func leaseOpts(_ holder: String, _ ttl: Double, _ skew: Double) -> Bool {
        !holder.isEmpty && holder.utf16.count <= 256 && ttl.rounded() == ttl && ttl >= 2 && ttl <= MAX_LEASE_TTL_MS && skew.isFinite && skew >= 0 && skew < ttl
    }

    private static func snapshot(_ s: any LeaseStore) throws -> (LeaseRecord?, Double) {
        let cur = try s.read()
        let now = try s.now()
        if !now.isFinite || (cur.map { !validRecord($0) } ?? false) { throw JSError("corrupt lease state") }
        return (cur, now)
    }

    /// Take the lease if it is free (never held, released, or expired past the skew). The epoch increments on every takeover.
    public static func acquireLease(_ s: any LeaseStore, _ holder: String, ttlMs: Double, skewMs: Double = DEFAULT_LEASE_SKEW_MS) -> LeaseOutcome {
        guard leaseOpts(holder, ttlMs, skewMs) else { return .fail("invalid") }
        do {
            let (cur, now) = try snapshot(s)
            if let c = cur, c.expiresAt + skewMs > now, c.expiresAt != 0 { return .fail("held") }
            let next = LeaseRecord(holder: holder, epoch: (cur?.epoch ?? 0) + 1, expiresAt: now + ttlMs)
            return try s.cas(cur, next) ? LeaseOutcome(ok: true, lease: next, reason: nil) : .fail("lost-race")
        } catch { return .fail("store-error") }
    }

    /// Extend a lease the caller still holds; refused once the holder's own safe window has passed, or after any takeover.
    public static func renewLease(_ s: any LeaseStore, _ lease: LeaseRecord, ttlMs: Double, skewMs: Double = DEFAULT_LEASE_SKEW_MS) -> LeaseOutcome {
        guard validRecord(lease), leaseOpts(lease.holder, ttlMs, skewMs) else { return .fail("invalid") }
        do {
            let (cur, now) = try snapshot(s)
            guard let c = cur, c.holder == lease.holder, c.epoch == lease.epoch else { return .fail("stale") }
            if c.expiresAt - skewMs <= now { return .fail("expired") }
            let next = LeaseRecord(holder: c.holder, epoch: c.epoch, expiresAt: now + ttlMs)
            return try s.cas(c, next) ? LeaseOutcome(ok: true, lease: next, reason: nil) : .fail("lost-race")
        } catch { return .fail("store-error") }
    }

    /// Give the lease up early (`expiresAt` 0, epoch kept). Only the current holder at the current epoch can.
    public static func releaseLease(_ s: any LeaseStore, _ lease: LeaseRecord) -> LeaseOutcome {
        guard validRecord(lease) else { return .fail("invalid") }
        do {
            let (cur, _) = try snapshot(s)
            guard let c = cur, c.holder == lease.holder, c.epoch == lease.epoch, c.expiresAt != 0 else { return .fail("stale") }
            let next = LeaseRecord(holder: c.holder, epoch: c.epoch, expiresAt: 0)
            return try s.cas(c, next) ? LeaseOutcome(ok: true, lease: next, reason: nil) : .fail("lost-race")
        } catch { return .fail("store-error") }
    }

    // MARK: the checks

    private static let LO = (ttl: 600_000.0, skew: 1_000.0)

    private static func need(_ cond: Bool, _ what: String) throws { if !cond { throw JSError(what) } }
    private static func needEq<T: Equatable>(_ got: T, _ want: T, _ what: String = "") throws {
        if got != want { throw JSError((what.isEmpty ? "" : what + ": ") + "expected \(want) but got \(got)") }
    }

    private static func won(_ s: any LeaseStore, _ who: String) throws -> LeaseRecord {
        let r = acquireLease(s, who, ttlMs: LO.ttl, skewMs: LO.skew)
        try need(r.ok, "acquire for \(who) failed: \(r.reason ?? "")")
        return r.lease!
    }

    /// Run the bodies at once, each on its own thread, and collect their results in order.
    private static func race<T>(_ bodies: [() -> T]) -> [T] {
        let slots = RaceSlots<T>(Array(repeating: nil, count: bodies.count))
        let group = DispatchGroup()
        for (i, b) in bodies.enumerated() {
            group.enter()
            Thread { let r = b(); slots.lock.lock(); slots.v[i] = r; slots.lock.unlock(); group.leave() }.start()
        }
        group.wait()
        return slots.v.map { $0! }
    }

    public static let LEASE_CHECKS: [LeaseCheck] = [
        LeaseCheck(name: "empty-store-has-no-lease", claim: "a new store has no lease and a finite clock", needs: nil) { h in
            try needEq(try h.store.read(), nil)
            try need(try h.store.now().isFinite, "the store clock must be a finite number")
        },
        LeaseCheck(name: "first-acquire-is-epoch-1", claim: "the first holder gets epoch 1 and an expiry from the store clock", needs: nil) { h in
            let l = try won(h.store, "a")
            try needEq(l.epoch, 1)
            try needEq(try h.store.read(), l)
            try need(l.expiresAt > (try h.store.now()), "the expiry must be after the store clock")
        },
        LeaseCheck(name: "wrong-expected-record-never-writes", claim: "cas with an expected record that is not the stored one returns false and changes nothing", needs: nil) { h in
            try needEq(try h.store.cas(LeaseRecord(holder: "x", epoch: 1, expiresAt: 5), LeaseRecord(holder: "y", epoch: 2, expiresAt: 9)), false)
            try needEq(try h.store.read(), nil)
            let l = try won(h.store, "a")
            try needEq(try h.store.cas(nil, LeaseRecord(holder: "y", epoch: 2, expiresAt: 9)), false)
            try needEq(try h.store.read(), l)
        },
        LeaseCheck(name: "racing-acquirers-have-one-winner", claim: "many contenders at once: exactly one acquires, at epoch 1", needs: nil) { h in
            var clients: [any LeaseStore] = [h.store]
            for _ in 0..<3 { clients.append(try h.reopen()) }
            var bodies: [() -> LeaseOutcome] = []
            for (i, c) in clients.enumerated() {
                bodies.append { acquireLease(c, "h\(i)a", ttlMs: LO.ttl, skewMs: LO.skew) }
                bodies.append { acquireLease(c, "h\(i)b", ttlMs: LO.ttl, skewMs: LO.skew) }
            }
            try needEq(race(bodies).filter { $0.ok }.count, 1)
            try needEq(try h.store.read()?.epoch, 1)
        },
        LeaseCheck(name: "takeover-after-release-bumps-the-epoch", claim: "a released lease is free at once and the next holder gets a strictly higher epoch", needs: nil) { h in
            let a = try won(h.store, "a")
            try need(releaseLease(h.store, a).ok, "release failed")
            try needEq(try won(h.store, "b").epoch, 2)
        },
        LeaseCheck(name: "epoch-never-goes-down", claim: "cas refuses a record with a lower epoch even when the expected record matches", needs: nil) { h in
            let a = try won(h.store, "a")
            _ = releaseLease(h.store, a)
            let b = try won(h.store, "b")
            let ok = (try? h.store.cas(b, LeaseRecord(holder: "z", epoch: 1, expiresAt: b.expiresAt))) ?? false
            try needEq(ok, false)
            try needEq(try h.store.read(), b)
        },
        LeaseCheck(name: "stale-holder-cannot-renew-or-release", claim: "after a takeover the old (holder, epoch) is refused as stale for renew and release", needs: nil) { h in
            let a = try won(h.store, "a")
            _ = releaseLease(h.store, a)
            let b = try won(h.store, "b")
            try needEq(renewLease(h.store, a, ttlMs: LO.ttl, skewMs: LO.skew), .fail("stale"))
            try needEq(releaseLease(h.store, a), .fail("stale"))
            try needEq(try h.store.read(), b)
        },
        LeaseCheck(name: "state-survives-reopen", claim: "an acknowledged lease is there when another client opens the same backend", needs: "durable") { h in
            let l = try won(h.store, "a")
            try needEq(try h.reopen().read(), l)
        },
        LeaseCheck(name: "acknowledged-lease-survives-a-crash", claim: "after an abrupt backend kill the lease and its epoch are still there, and the next epoch is higher", needs: "crash") { h in
            let a = try won(h.store, "a")
            _ = releaseLease(h.store, a)
            let back = try h.crash!()
            try needEq(try back.read()?.epoch, 1)
            try needEq(try won(back, "b").epoch, 2)
        },
    ]

    /// Run the lease checks (only those named in `only` when given) against fresh handles from the adapter.
    public static func runLeaseStoreConformance(_ adapter: LeaseStoreAdapter, only: [String]? = nil) -> LeaseConformanceReport {
        var checks: [LeaseCheckResult] = []
        for c in LEASE_CHECKS {
            if let o = only, !o.contains(c.name) { continue }
            if c.needs == "durable" && adapter.durable == false { checks.append(LeaseCheckResult(name: c.name, status: "skip", detail: "the adapter declares durable: false")); continue }
            let h: LeaseStoreHandle
            do { h = try adapter.create() } catch { checks.append(LeaseCheckResult(name: c.name, status: "fail", detail: "\(error)")); continue }
            defer { h.close?() }
            if c.needs == "crash" && h.crash == nil { checks.append(LeaseCheckResult(name: c.name, status: "skip", detail: "the adapter has no crash()")); continue }
            do { try c.run(h); checks.append(LeaseCheckResult(name: c.name, status: "pass", detail: nil)) } catch {
                checks.append(LeaseCheckResult(name: c.name, status: "fail", detail: (error as? JSError)?.message ?? "\(error)"))
            }
        }
        return LeaseConformanceReport(adapter: adapter.name, status: checks.contains { $0.status == "fail" } ? "fail" : "pass", checks: checks)
    }

    /// The text report: a header line, then one line per check (the first line of a failure's detail).
    public static func formatLeaseReport(_ r: LeaseConformanceReport) -> String {
        (["pca-store-conformance (lease store): \(r.adapter) -> \(r.status.uppercased())"]
            + r.checks.map { c in "  [\(c.status.uppercased())] \(c.name)" + (c.detail.map { ": " + (IV.split($0, "\n").first ?? "") } ?? "") }).joined(separator: "\n")
    }

    // MARK: reference adapters

    private final class MemoryLease: LeaseStore, @unchecked Sendable {
        enum Defect { case none, noCas, epochRegress, lostUpdate }
        final class Backend: @unchecked Sendable { let lock = NSLock(); var rec: LeaseRecord? }
        let b: Backend
        let defect: Defect
        init(_ b: Backend, _ defect: Defect = .none) { self.b = b; self.defect = defect }
        func read() throws -> LeaseRecord? { b.lock.lock(); defer { b.lock.unlock() }; return b.rec }
        func now() throws -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
        func cas(_ expected: LeaseRecord?, _ next: LeaseRecord) throws -> Bool {
            if defect == .noCas { b.lock.lock(); b.rec = next; b.lock.unlock(); return true }
            b.lock.lock(); let seen = b.rec; b.lock.unlock()
            if defect == .lostUpdate { Thread.sleep(forTimeInterval: 0.001) }
            b.lock.lock(); defer { b.lock.unlock() }
            if (defect == .lostUpdate ? seen : b.rec) != expected { return false }
            if defect != .epochRegress, next.epoch < (b.rec?.epoch ?? 0) { return false }
            b.rec = next
            return true
        }
    }

    /// GOOD, in process: a compare-and-swap store over memory (not durable).
    public static func memoryLeaseStoreAdapter() -> LeaseStoreAdapter {
        LeaseStoreAdapter(name: "in-memory lease store", durable: false) {
            let b = MemoryLease.Backend()
            return LeaseStoreHandle(store: MemoryLease(b), reopen: { MemoryLease(b) })
        }
    }

    /// A store with a switchable defect, for the positive controls (each reproduces a real mistake).
    private static func defective(_ name: String, _ defect: MemoryLease.Defect, amnesia: Bool = false) -> LeaseStoreAdapter {
        LeaseStoreAdapter(name: name, durable: true) {
            let b = MemoryLease.Backend()
            let again: () throws -> any LeaseStore = { if amnesia { b.lock.lock(); b.rec = nil; b.lock.unlock() }; return MemoryLease(b, defect) }
            return LeaseStoreHandle(store: MemoryLease(b, defect), reopen: again, crash: again)
        }
    }
    public static func noCasLeaseStoreAdapter() -> LeaseStoreAdapter { defective("BAD no compare-and-swap (writes whatever the caller expected)", .noCas) }
    public static func epochRegressLeaseStoreAdapter() -> LeaseStoreAdapter { defective("BAD epoch regression (accepts a lower fencing epoch)", .epochRegress) }
    public static func lostUpdateLeaseStoreAdapter() -> LeaseStoreAdapter { defective("BAD lost update (read, pause, write)", .lostUpdate) }
    public static func amnesiaLeaseStoreAdapter() -> LeaseStoreAdapter { defective("BAD amnesia (claims durability, forgets on reopen)", .none, amnesia: true) }

    public static let LEASE_REFERENCE_ADAPTERS: [String: () -> LeaseStoreAdapter] = [
        "lease-memory": memoryLeaseStoreAdapter,
        "bad-lease-no-cas": noCasLeaseStoreAdapter,
        "bad-lease-epoch-regress": epochRegressLeaseStoreAdapter,
        "bad-lease-lost-update": lostUpdateLeaseStoreAdapter,
        "bad-lease-amnesia": amnesiaLeaseStoreAdapter,
    ]
}

fileprivate final class RaceSlots<T>: @unchecked Sendable { let lock = NSLock(); var v: [T?]; init(_ v: [T?]) { self.v = v } }
