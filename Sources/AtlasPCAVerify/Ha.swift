import Foundation

/// Guardian-set high availability (the reference's `ha`): which guardians are live, whether a co-sign quorum is available, the degrade mode when it
/// is lost, signer selection and failover order (all pure over health facts), plus a durable FENCED leader lease: at most one holder, a strictly
/// monotone fencing epoch, store-side expiry, and "no leader" whenever the store errs. It never fails open. Sets, leases and results are the
/// reference's objects as JSON trees (a stored record may be corrupt on purpose). Lease safety needs a linearizable compare-and-swap in the store
/// and a holder clock error below `skewMs`.
public enum PCAHa {
    public static let MAX_LEASE_TTL_MS: Int64 = 3_600_000
    public static let DEFAULT_LEASE_SKEW_MS: Int64 = 1_000
    private static let MAX_HOLDER_LEN = 256
    private static let MAX_SAFE = Double(Canonical.MAX_SAFE)

    private static func fin(_ v: JSONValue?) -> Double? { ToolSchema.fin(v) }
    private static func num(_ d: Double) -> JSONValue { d.isFinite ? PCAFacade.jsNum(d) : .double(d) }
    private static func isInt(_ v: JSONValue?) -> Bool { fin(v).map { $0.rounded(.towardZero) == $0 } ?? false }
    private static func isObject(_ v: JSONValue?) -> Bool { v?.isObject == true }
    /// `typeof x === 'object' && x !== null` (an array is one).
    private static func isObjectLike(_ v: JSONValue?) -> Bool {
        switch v { case .object?, .array?: return true; default: return false }
    }

    // ---- pure decisions ----

    /// Guardians both flagged healthy AND with a fresh heartbeat at `now`. A malformed set, a non-finite clock or stale window, a non-finite or
    /// FUTURE-dated heartbeat or a non-boolean `healthy` counts as down.
    public static func liveGuardians(_ set: JSONValue?, _ now: JSONValue?, _ opts: JSONValue? = nil) -> [JSONValue] {
        let staleV = JS.present(opts?.get("staleMs")) ?? .int(30_000)
        guard let n = fin(now), let stale = fin(staleV), stale >= 0, case let .array(gs)? = set?.get("guardians"), gs.allSatisfy({ isObjectLike($0) }) else { return [] }
        return gs.filter { g in
            guard g.get("healthy") == .bool(true), let seen = fin(g.get("lastSeen")) else { return false }
            return seen <= n && n - seen <= stale
        }
    }

    private static func weightOf(_ g: JSONValue) -> Double { fin(g.get("weight")) ?? 0 }

    /// The ICU root collation order `localeCompare` gives: Foundation's ICU-backed locale-aware compare under the root locale (tertiary strength, so a
    /// lower case letter sorts before its upper case form and canonically equivalent strings are equal). Platform caveat: Apple's Foundation and the
    /// open-source Foundation on Linux each bundle their own ICU, so a script whose tailoring changed between ICU releases may order differently from the
    /// reference's runtime; identifiers of the Latin script and digits, which a guardian set uses, are stable.
    private static func collate(_ a: String, _ b: String) -> Int {
        switch a.compare(b, options: [], range: nil, locale: Locale(identifier: "")) {
        case .orderedAscending: return -1
        case .orderedDescending: return 1
        case .orderedSame: return 0
        }
    }

    /// Weight (high first), then freshness, then id; JavaScript's stable sort and its TypeError for an id that is not a string.
    private static func ordered(_ live: [JSONValue]) throws -> [JSONValue] {
        func cmp(_ a: JSONValue, _ b: JSONValue) throws -> Int {
            let w = weightOf(b) - weightOf(a)
            if w != 0 && !w.isNaN { return w < 0 ? -1 : 1 }
            let s = (fin(b.get("lastSeen")) ?? .nan) - (fin(a.get("lastSeen")) ?? .nan)
            if s != 0 && !s.isNaN { return s < 0 ? -1 : 1 }
            guard case let .string(x)? = a.get("id"), case let .string(y)? = b.get("id") else { throw JSError("a.id.localeCompare is not a function") }
            return collate(x, y)
        }
        var err: Error?
        let idx = live.indices.sorted { i, j in
            if err != nil { return i < j }
            do { let c = try cmp(live[i], live[j]); return c != 0 ? c < 0 : i < j } catch { err = error; return i < j }
        }
        if let e = err { throw e }
        return idx.map { live[$0] }
    }

    public static func quorumStatus(_ set: JSONValue?, _ now: JSONValue?, _ opts: JSONValue? = nil) -> JSONValue {
        let live = liveGuardians(set, now, opts).count
        var total = 0
        if case let .array(g)? = set?.get("guardians") { total = g.count }
        var o: JObject = [
            "total": .int(Int64(total)),
            "live": .int(Int64(live)),
            "available": .bool(isInt(set?.get("quorum")) && fin(set?.get("quorum"))! >= 1 && Double(live) >= fin(set?.get("quorum"))!),
            "degraded": .bool(live > 0 && Double(live) < JS.toNumber(set?.get("quorum"))),
        ]
        if let q = set?.get("quorum") { o["quorum"] = q }
        return .object(o)
    }

    /// `normal` with a quorum, `read-only` below it with some guardian live (unless the policy forbids it), else `halt`.
    public static func degradeMode(_ status: JSONValue?, _ policy: JSONValue? = nil) -> String {
        if JS.truthy(status?.get("available")) { return "normal" }
        if JS.toNumber(status?.get("live")) > 0 && policy?.get("allowReadOnly") != .bool(false) { return "read-only" }
        return "halt"
    }

    /// The `quorum` freshest, highest-weight live guardians' ids; empty below quorum. Throws for a null set, as the reference does.
    public static func selectSigners(_ set: JSONValue?, _ now: JSONValue?, _ opts: JSONValue? = nil) throws -> [JSONValue] {
        let live = liveGuardians(set, now, opts)
        if set == nil || set == .null { throw JSError("Cannot read properties of null (reading 'quorum')") }
        guard isInt(set?.get("quorum")), let q = fin(set?.get("quorum")), q >= 1, Double(live.count) >= q else { return [] }
        return try ordered(live).prefix(Int(q)).map { $0.get("id") ?? .null }
    }

    /// A primary and ordered standbys (`{primary, standbys}`).
    public static func failoverPlan(_ set: JSONValue?, _ now: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        let live = try ordered(liveGuardians(set, now, opts))
        return .object(["primary": JS.present(live.first?.get("id")) ?? .null, "standbys": .array(live.dropFirst().map { $0.get("id") ?? .null })])
    }

    /// An error string, or nil when the set is well formed (quorum in range, unique non-empty ids).
    public static func validateGuardianSet(_ set: JSONValue?) -> String? {
        guard isObjectLike(set) else { return "guardian set is not an object" }
        guard case let .array(gs)? = set?.get("guardians"), !gs.isEmpty else { return "guardian set is empty" }
        guard isInt(set?.get("quorum")), let q = fin(set?.get("quorum")), q >= 1 else { return "quorum must be an integer ≥ 1" }
        if q > Double(gs.count) { return "quorum exceeds guardian count" }
        guard gs.allSatisfy({ isObjectLike($0) && !($0.get("id")?.asString ?? "").isEmpty }) else { return "guardian id must be a non-empty string" }
        // JavaScript compares strings by code unit: Swift String == would equate canonically equivalent spellings
        if Set(gs.map { Array($0.get("id")!.asString!.utf16) }).count != gs.count { return "duplicate guardian ids" }
        return nil
    }

    // ---- the fenced lease ----

    /// The persistence contract: `cas` replaces the record iff the stored one equals `expected` (nil = none), atomically and linearizably, and returns
    /// whether it did; `next.epoch` never goes below the stored one. `now` is the STORE's clock: every expiry decision uses it.
    public protocol LeaseStore: AnyObject {
        func read() throws -> JSONValue?
        func cas(_ expected: JSONValue?, _ next: JSONValue) throws -> Bool
        func now() throws -> Double
    }

    /// A lease that cannot be used because the fence did not hold.
    public struct FenceError: Error, Equatable {
        /// `stale`, `expired`, `store-error` or `no-lease`.
        public let reason: String
        public var message: String { "fenced: \(reason)" }
    }

    private static func safeInteger(_ v: JSONValue?) -> Bool { fin(v).map { $0.rounded(.towardZero) == $0 && abs($0) <= MAX_SAFE } ?? false }

    private static func validRecord(_ r: JSONValue?) -> Bool {
        guard isObject(r), r?.get("holder")?.asString != nil, safeInteger(r?.get("epoch")), fin(r?.get("epoch"))! >= 1,
              let e = fin(r?.get("expiresAt")), e >= 0 else { return false }
        return true
    }

    /// JavaScript `===` over the lease members.
    private static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if let x = fin(a), let y = fin(b) { return x == y }
        if a?.asString != nil, let x = a?.asString, let y = b?.asString { return Array(x.utf16) == Array(y.utf16) }
        return a == b && !(a?.isNumber ?? false)
    }

    private static func eqLease(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        guard let x = a, let y = b else { return a == nil && b == nil }
        return ["holder", "epoch", "expiresAt"].allSatisfy { same(x.get($0), y.get($0)) }
    }

    private static func leaseOpts(_ holder: JSONValue?, _ o: JSONValue?) -> (ttl: Double, skew: Double)? {
        guard let h = holder?.asString, !h.isEmpty, h.utf16.count <= MAX_HOLDER_LEN else { return nil }
        guard isInt(o?.get("ttlMs")), let ttl = fin(o?.get("ttlMs")), ttl >= 2, ttl <= Double(MAX_LEASE_TTL_MS) else { return nil }
        guard let skew = fin(JS.present(o?.get("skewMs")) ?? .int(DEFAULT_LEASE_SKEW_MS)), skew >= 0, skew < ttl else { return nil }
        return (ttl, skew)
    }

    /// The record and the store clock; a corrupt record or clock is a store error (never "free").
    private static func snapshot(_ s: LeaseStore) throws -> (cur: JSONValue?, now: Double) {
        let cur = try s.read()
        let now = try s.now()
        if !now.isFinite || (cur != nil && !validRecord(cur)) { throw JSError("corrupt lease state") }
        return (cur, now)
    }

    private static func ok(_ lease: JSONValue) -> JSONValue { .object(["ok": .bool(true), "lease": lease]) }
    private static func fail(_ reason: String, _ detail: String? = nil) -> JSONValue {
        var o: JObject = ["ok": .bool(false), "reason": .string(reason)]
        if let d = detail { o["detail"] = .string(d) }
        return .object(o)
    }
    private static func storeError(_ e: Error) -> JSONValue { fail("store-error", (e as? JSError)?.message ?? "unknown") }
    private static func record(_ holder: JSONValue?, _ epoch: Double, _ expiresAt: Double) -> JSONValue {
        .object(["holder": holder ?? .null, "epoch": num(epoch), "expiresAt": num(expiresAt)])
    }

    /// Take the lease if it is free (never held, released, or expired past the skew); the epoch increments on every takeover.
    /// `o`: `{ttlMs, skewMs?}`. Result `{ok:true, lease}` or `{ok:false, reason, detail?}` (`invalid`, `held`, `lost-race`, `store-error`).
    public static func acquireLease(_ store: LeaseStore, _ holder: JSONValue?, _ o: JSONValue?) -> JSONValue {
        guard let p = leaseOpts(holder, o) else { return fail("invalid") }
        do {
            let (cur, now) = try snapshot(store)
            if let c = cur, !(fin(c.get("expiresAt"))! + p.skew <= now), fin(c.get("expiresAt"))! != 0 { return fail("held") }
            let next = record(holder, (cur.flatMap { fin($0.get("epoch")) } ?? 0) + 1, now + p.ttl)
            return try store.cas(cur, next) ? ok(next) : fail("lost-race")
        } catch { return storeError(error) }
    }

    /// Extend a lease the caller still holds; refused once the holder's own safe window (expiry minus skew) has passed, or after any takeover.
    public static func renewLease(_ store: LeaseStore, _ lease: JSONValue?, _ o: JSONValue?) -> JSONValue {
        guard validRecord(lease), let p = leaseOpts(lease?.get("holder"), o) else { return fail("invalid") }
        do {
            let (cur, now) = try snapshot(store)
            guard let c = cur, same(c.get("holder"), lease?.get("holder")), same(c.get("epoch"), lease?.get("epoch")) else { return fail("stale") }
            if !(fin(c.get("expiresAt"))! - p.skew > now) { return fail("expired") }
            let next = record(c.get("holder"), fin(c.get("epoch"))!, now + p.ttl)
            return try store.cas(c, next) ? ok(next) : fail("lost-race")
        } catch { return storeError(error) }
    }

    /// Give the lease up early (`expiresAt` 0, epoch kept). Only the current holder at the current epoch can.
    public static func releaseLease(_ store: LeaseStore, _ lease: JSONValue?) -> JSONValue {
        guard validRecord(lease) else { return fail("invalid") }
        do {
            let (cur, _) = try snapshot(store)
            guard let c = cur, same(c.get("holder"), lease?.get("holder")), same(c.get("epoch"), lease?.get("epoch")), fin(c.get("expiresAt"))! != 0 else { return fail("stale") }
            let next = record(c.get("holder"), fin(c.get("epoch"))!, 0)
            return try store.cas(c, next) ? ok(next) : fail("lost-race")
        } catch { return storeError(error) }
    }

    /// Is this exact (holder, epoch) still the leader, with its safe window open, per the store? Any error answers no.
    /// `skewMs` nil = the default. Result `{ok:true}` or `{ok:false, reason: stale | expired | store-error}`.
    public static func assertFence(_ store: LeaseStore, _ token: JSONValue?, _ skewMs: JSONValue? = nil) -> JSONValue {
        do {
            let skewV: JSONValue = skewMs ?? .int(DEFAULT_LEASE_SKEW_MS)
            guard JS.truthy(token), let skew = fin(skewV), skew >= 0 else { return fail("stale") }
            let (cur, now) = try snapshot(store)
            guard let c = cur, same(c.get("holder"), token?.get("holder")), same(c.get("epoch"), token?.get("epoch")) else { return fail("stale") }
            return fin(c.get("expiresAt"))! - skew > now ? .object(["ok": .bool(true)]) : fail("expired")
        } catch { return fail("store-error") }
    }

    /// Wrap a co-sign so it runs only while the caller is the fenced leader. The fence is checked before AND after the signature: a leader that lost
    /// the lease mid-signature gets a `FenceError` and the signature is discarded. Downstream must also `FenceGuard.admit` the epoch.
    public static func fencedSigner<R>(_ store: LeaseStore, getLease: @escaping () -> JSONValue?, sign: @escaping () throws -> R,
                                       skewMs: JSONValue? = nil) -> () throws -> (result: R, epoch: JSONValue) {
        {
            let held = getLease()
            guard JS.truthy(held), let lease = held else { throw FenceError(reason: "no-lease") }
            func check() throws {
                let r = assertFence(store, lease, skewMs)
                if r.get("ok") != .bool(true) { throw FenceError(reason: r.get("reason")?.asString ?? "stale") }
            }
            try check()
            let result = try sign()
            try check()
            return (result, lease.get("epoch") ?? .null)
        }
    }

    /// Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write).
    public final class FenceGuard {
        private var hi: Int64
        public init(initial: JSONValue? = nil) { hi = (initial?.safeInt).map { $0 > 0 ? $0 : 0 } ?? 0 }
        public func admit(_ epoch: JSONValue?) -> Bool {
            guard let e = epoch?.safeInt, e >= 1, e >= hi else { return false }
            hi = e
            return true
        }
        public func highest() -> Int64 { hi }
    }

    /// The factory under the reference's name.
    public static func createFenceGuard(_ initial: JSONValue? = nil) -> FenceGuard { FenceGuard(initial: initial) }

    /// An in-memory key-value cell for `KvLeaseStore`: `update` is the atomic compare-and-swap primitive.
    public final class MemoryKv: @unchecked Sendable {
        private var m: [String: JSONValue] = [:]
        private let lock = NSLock()
        public init() {}
        public func get(_ key: String) -> JSONValue? { lock.lock(); defer { lock.unlock() }; return m[key] }
        public func set(_ key: String, _ v: JSONValue?) { lock.lock(); defer { lock.unlock() }; m[key] = v }
        /// `f` sees the current value (nil = none) and returns the value to store, or nil to leave it.
        public func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) {
            lock.lock(); defer { lock.unlock() }
            if let n = f(m[key]) { m[key] = n }
        }
    }

    /// The reference lease store over a `MemoryKv` (any durable cell with an atomic `update` serves the same way).
    public final class KvLeaseStore: LeaseStore {
        private let kv: MemoryKv
        private let key: String
        private let clock: () throws -> Double
        public init(_ kv: MemoryKv, key: String = "ha/lease", now: @escaping () throws -> Double = { Date().timeIntervalSince1970 * 1000 }) {
            self.kv = kv; self.key = key; self.clock = now
        }
        public func read() throws -> JSONValue? {
            let v = kv.get(key)
            if v != nil && !PCAHa.validRecord(v) { throw JSError("corrupt lease state") }
            return v
        }
        public func cas(_ expected: JSONValue?, _ next: JSONValue) throws -> Bool {
            guard PCAHa.validRecord(next) else { throw JSError("invalid lease record") }
            var matched = false
            kv.update(key) { prev in
                if prev != nil && !PCAHa.validRecord(prev) { return nil }
                if !PCAHa.eqLease(prev, expected) || ToolSchema.fin(next.get("epoch"))! < (prev.flatMap { ToolSchema.fin($0.get("epoch")) } ?? 0) { return nil }
                matched = true
                return next
            }
            return matched
        }
        public func now() throws -> Double { try clock() }
    }
}
