import Foundation

/// Conformance kit for lease storage (pca-grants lease-store-conformance.ts). Run it against any `AtomicKV` (the in-memory one, an opened durable
/// state, or your own database adapter) before trusting that store with leases. It throws `LeaseStoreConformance.Failure` on the first failure and
/// returns the list of checks passed. It proves: leases spread over the shards; an update is atomic (of many concurrent renewals of one lease
/// exactly one wins and the rest are forks); different leases do not interfere; a prefix revocation lands in every shard and a lease revocation
/// only in its own; a store opened with another shard count is refused rather than silently empty; state survives a reopen (give `reopen`); a
/// later-issued lease under a revoked prefix is a new lease; with a TTL ceiling, old revocations are pruned from every shard and a longer
/// `max_ttl` is refused.
public enum LeaseStoreConformance {
    public struct Failure: Error, CustomStringConvertible {
        public let check: String
        public let detail: String
        public var description: String { "lease store conformance: \(check): \(detail)" }
    }

    /// The store under test.
    public struct Kit {
        /// A fresh, empty store.
        public var open: () throws -> any AtomicKV
        /// The same store opened again as a restarted process would (state kept); nil skips the restart check.
        public var reopen: ((any AtomicKV) throws -> any AtomicKV)?
        /// Shard count; 16 by default.
        public var shards: Int
        public init(open: @escaping () throws -> any AtomicKV, reopen: ((any AtomicKV) throws -> any AtomicKV)? = nil, shards: Int = Lease.DEFAULT_SHARDS) {
            self.open = open; self.reopen = reopen; self.shards = shards
        }
    }

    private static let T0: Int64 = 1_800_000_000_000
    private static let DAY: Int64 = 86_400_000

    private static func key() throws -> PCAEdKey { try Ed25519Deterministic.key(seed: [UInt8](repeating: 61, count: 32)) }

    private static func mk(_ id: String, _ over: JObject = [:]) -> JObject {
        var m: JObject = ["lease_id": .string(id), "path": .string("svc/\(id.utf16.count % 3)/" + id), "grant_ref": .string("g-" + id), "holder": .string("agent"), "requester": .string("alice"),
                          "approvers": .array([.string("bob")]), "justification_digest": .string("j1"), "seq": .int(1), "issued_at": .int(T0), "renewed_at": .int(T0),
                          "expires_at": .int(T0 + 600_000), "max_ttl": .int(3_600_000)]
        for (k, v) in over { m[k] = v }
        return m
    }

    private static func fail(_ c: String, _ d: String) -> Failure { Failure(check: c, detail: d) }

    private static func expectEq(_ check: String, _ got: JSONValue, _ want: JSONValue) throws {
        let g = Canonical.canonicalize(got), w = Canonical.canonicalize(want)
        if g != w { throw fail(check, "got \(g), want \(w)") }
    }

    private static func acc(_ a: Lease.Accept) -> JSONValue {
        var m: JObject = ["ok": .bool(a.code == nil)]
        if let c = a.code { m["code"] = .string(c) }
        return .object(m)
    }

    private static func rev(_ r: Lease.Revoke) -> JSONValue {
        var m: JObject = ["ok": .bool(r.code == nil)]
        if r.code == nil { m["revoked"] = .int(Int64(r.revoked)) }
        return .object(m)
    }

    private static func okRevoked(_ n: Int64) -> JSONValue { .object(["ok": .bool(true), "revoked": .int(n)]) }

    public static func runLeaseStoreConformance(_ kit: Kit) throws -> [String] {
        let sk = try key()
        func lease(_ id: String, _ over: JObject = [:]) throws -> JSONValue { try PCAGrants.signLease(sk, mk(id, over)) }
        func revocation(_ target: String, _ value: String, _ at: Int64) throws -> JSONValue {
            try PCAGrants.signLeaseRevocation(sk, ["target": .string(target), "value": .string(value), "revoked_at": .int(at)])
        }
        func okAccept(_ reg: Lease.Registry, _ rec: JSONValue) -> Bool { reg.accept(rec).code == nil }
        func deny(_ reg: Lease.Registry, _ rec: JSONValue?, _ now: Int64) -> String { Lease.checkLease(rec, registry: reg, now: .int(now)).decision }
        func seqs(_ h: [Lease.HistoryEntry]) -> JSONValue { .array(h.map { .int($0.seq) }) }

        var passed: [String] = []
        let shards = kit.shards
        let policy = Lease.Policy(authorities: [sk.id])
        let wall: @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }

        // 1. spread
        do {
            let reg = try Lease.Registry(policy: policy, kv: try kit.open(), shards: shards, clock: wall)
            let ids = (0..<256).map { "lease-\($0)" }
            for id in ids { try expectEq("spread: issue \(id)", .bool(okAccept(reg, try lease(id))), .bool(true)) }
            var per = [Int](repeating: 0, count: shards)
            for id in ids { per[Lease.shardOf(id, shards)] += 1 }
            let used = per.filter { $0 > 0 }.count
            if Double(per.max() ?? 0) > Double(ids.count) / 4.0 || Double(used) < Double(shards) / 2.0 { throw fail("spread", "256 leases landed \(per)") }
            for id in ids where reg.get(id)?[JKey("lease_id")]?.asString != id { throw fail("spread", "\(id) not found after issue") }
            passed.append("spread")
        }

        // 2. atomic update
        do {
            let reg = try Lease.Registry(policy: policy, kv: try kit.open(), shards: shards, clock: wall)
            _ = reg.accept(try lease("hot"))
            var recs: [JSONValue] = []
            for i in 0..<8 {
                recs.append(try lease("hot", ["seq": .int(2), "renewed_at": .int(T0 + 1000), "expires_at": .int(T0 + 700_000 + Int64(i)), "justification_digest": .string("r\(i)")]))
            }
            final class Tally: @unchecked Sendable { var wins: Int64 = 0, forks: Int64 = 0; let lock = NSLock() }
            let t = Tally()
            DispatchQueue.concurrentPerform(iterations: recs.count) { i in
                let a = reg.accept(recs[i])
                t.lock.lock(); defer { t.lock.unlock() }
                if a.code == nil { t.wins += 1 } else if a.code == "lease_fork" { t.forks += 1 }
            }
            try expectEq("atomic: one winner", .int(t.wins), .int(1))
            try expectEq("atomic: the rest are forks", .int(t.forks), .int(7))
            try expectEq("atomic: ledger length", seqs(reg.history("hot")), .array([.int(1), .int(2)]))
            passed.append("atomic update")
        }

        // 3. independence
        do {
            let reg = try Lease.Registry(policy: policy, kv: try kit.open(), shards: shards, clock: wall)
            let ids = (0..<32).map { "ind-\($0)" }
            for id in ids { _ = reg.accept(try lease(id)) }
            var all = true
            for id in ids {
                all = okAccept(reg, try lease(id, ["seq": .int(2), "renewed_at": .int(T0 + 10), "expires_at": .int(T0 + 900_000), "justification_digest": .string("j2")])) && all
            }
            try expectEq("independence", .bool(all), .bool(true))
            passed.append("independent leases")
        }

        // 4 + 5. revocation placement
        do {
            let reg = try Lease.Registry(policy: policy, kv: try kit.open(), shards: shards, clock: wall)
            let ids = (0..<64).map { "rv-\($0)" }
            for id in ids { _ = reg.accept(try lease(id, ["path": .string("db/prod/ro")])) }
            let lone = try lease("lone", ["path": .string("other/x")])
            _ = reg.accept(lone)
            let byLease = try revocation("lease", "lone", T0 + 5)
            try expectEq("revoke by lease", rev(reg.revoke(byLease)), okRevoked(1))
            var holders = 0
            for i in 0..<shards where !(try reg.shardRevocations(i)).isEmpty { holders += 1 }
            try expectEq("lease revocation lands in exactly one shard", .int(Int64(holders)), .int(1))
            try expectEq("revoked lease is dead", .string(deny(reg, lone, T0 + 6)), .string("deny"))
            let byPrefix = try revocation("prefix", "db/prod", T0 + 10)
            try expectEq("revoke by prefix covers every lease in every shard", rev(reg.revoke(byPrefix)), okRevoked(64))
            try expectEq("revoke twice is idempotent", rev(reg.revoke(byPrefix)), okRevoked(64))
            for i in 0..<shards {
                let n = try reg.shardRevocations(i).filter { $0[JKey("sig")] == byPrefix.get("sig") }.count
                if n == 0 { throw fail("prefix revocation in every shard", "shard \(i) lacks it") }
                try expectEq("no duplicate in shard \(i)", .int(Int64(n)), .int(1))
            }
            for id in ids {
                try expectEq("check \(id)", .string(deny(reg, reg.get(id).map { .object($0) }, T0 + 11)), .string("deny"))
                let again = try lease(id, ["path": .string("db/prod/ro"), "seq": .int(2), "renewed_at": .int(T0 + 20), "expires_at": .int(T0 + 700_000), "justification_digest": .string("x")])
                try expectEq("renewal of \(id) refused", .bool(okAccept(reg, again)), .bool(false))
            }
            let fresh = try lease("after", ["path": .string("db/prod/ro"), "issued_at": .int(T0 + 100), "renewed_at": .int(T0 + 100), "expires_at": .int(T0 + 900_000)])
            try expectEq("a lease issued after the revocation is new", .bool(okAccept(reg, fresh)), .bool(true))
            passed.append("revocation placement")
        }

        // 6. shard-count mismatch
        do {
            let kv = try kit.open()
            _ = try Lease.Registry(policy: policy, kv: kv, shards: shards, clock: wall).accept(try lease("m1"))
            let other = try Lease.Registry(policy: policy, kv: kv, shards: shards * 2, clock: wall)
            try expectEq("shard mismatch accept", acc(other.accept(try lease("m2"))), .object(["ok": .bool(false), "code": .string("store_unreachable")]))
            try expectEq("shard mismatch check", .string(deny(other, try lease("m1"), T0 + 1)), .string("deny"))
            passed.append("shard count is pinned")
        }

        // 7. restart
        if let reopen = kit.reopen {
            let kv = try kit.open()
            let reg = try Lease.Registry(policy: policy, kv: kv, shards: shards, clock: wall)
            let l = try lease("persist")
            _ = reg.accept(l)
            _ = reg.accept(try lease("persist", ["seq": .int(2), "renewed_at": .int(T0 + 5), "expires_at": .int(T0 + 800_000), "justification_digest": .string("j2")]))
            _ = reg.revoke(try revocation("prefix", "gone", T0 + 50))
            let again = try Lease.Registry(policy: policy, kv: try reopen(kv), shards: shards, clock: wall)
            try expectEq("restart: renewal ledger", seqs(again.history("persist")), .array([.int(1), .int(2)]))
            try expectEq("restart: revocation kept", .int(Int64(try again.shardRevocations(0).count)), .int(1))
            try expectEq("restart: old record still superseded", .string(deny(again, l, T0 + 6)), .string("deny"))
            passed.append("state survives a restart")
        }

        // 8. ceiling and pruning
        do {
            final class Clock: @unchecked Sendable { var now: Int64; let lock = NSLock(); init(_ n: Int64) { now = n }
                func get() -> Int64 { lock.lock(); defer { lock.unlock() }; return now }
                func set(_ n: Int64) { lock.lock(); defer { lock.unlock() }; now = n } }
            let clk = Clock(T0)
            let capped = Lease.Policy(authorities: [sk.id], maxTtlCeiling: DAY)
            let reg = try Lease.Registry(policy: capped, kv: try kit.open(), shards: shards, clock: { clk.get() })
            try expectEq("ceiling refuses a longer max_ttl", acc(reg.accept(try lease("big", ["max_ttl": .int(DAY + 1), "expires_at": .int(T0 + 1000)]))),
                         .object(["ok": .bool(false), "code": .string("ttl_ceiling")]))
            _ = reg.accept(try lease("small", ["max_ttl": .int(DAY)]))
            _ = reg.revoke(try revocation("prefix", "svc", T0))
            for i in 0..<shards { try expectEq("kept before the ceiling passes (shard \(i))", .int(Int64(try reg.shardRevocations(i).count)), .int(1)) }
            clk.set(T0 + DAY + 1)
            let t = clk.get()
            _ = reg.accept(try lease("trigger", ["issued_at": .int(t), "renewed_at": .int(t), "expires_at": .int(t + 1000), "max_ttl": .int(5000)]))
            _ = reg.revoke(try revocation("prefix", "zzz", t))
            for i in 0..<shards {
                let vals = try reg.shardRevocations(i).map { $0[JKey("value")]?.asString ?? "" }
                if vals.contains("svc") { throw fail("pruning", "shard \(i) still holds the expired revocation") }
                if !vals.contains("zzz") { throw fail("pruning", "shard \(i) lost the fresh revocation") }
            }
            passed.append("pruning bounds revocations")
        }
        return passed
    }
}
