import XCTest
import Foundation
@testable import AtlasPCAVerify

/// H15 (strict): lease, break-glass and blueprint state lives in a REQUIRED store, so a restart or a second instance over the same store sees
/// revocations, uses, reviews and disabled blueprints. A store that cannot answer fails closed with `store_unreachable`.
struct A0H15ThrowingKV: AtomicKV {
    struct Down: Error {}
    func get(_ key: String) throws -> JSONValue? { throw Down() }
    func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws { throw Down() }
}

final class A0H15LeaseStoreTests: XCTestCase {
    private static let key = V2F.key("a0h15-lease-authority")
    private static var authority: String { V2F.pub(key) }
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func lease(_ id: String, seq: Int64 = 1, renewed: Int64 = 1000, expires: Int64 = 1500, digest: String = "j") -> JSONValue {
        var l: JObject = ["v": .int(1), "lease_id": .string(id), "path": .string("svc/a"), "grant_ref": .string("g"), "holder": .string("h"), "requester": .string("r"),
                          "approvers": .array([.string("a")]), "justification_digest": .string(digest), "seq": .int(seq), "issued_at": .int(1000),
                          "renewed_at": .int(renewed), "expires_at": .int(expires), "max_ttl": .int(2000), "authority": .string(Self.authority)]
        l["sig"] = .string(V2F.sign(Self.key, IV.message(Lease.DOMAIN, .object(l))!))
        return .object(l)
    }

    private func revocation(_ value: String, at: Int64 = 5000) -> JSONValue {
        var r: JObject = ["v": .int(1), "target": .string("lease"), "value": .string(value), "revoked_at": .int(at), "authority": .string(Self.authority)]
        r["sig"] = .string(V2F.sign(Self.key, IV.message(Lease.REVOKE_DOMAIN, .object(r))!))
        return .object(r)
    }

    private func reg(_ kv: any AtomicKV, ceiling: Int64? = nil, shards: Int = 16, clock: @escaping @Sendable () -> Int64 = { 0 }) throws -> Lease.Registry {
        try Lease.Registry(policy: Lease.Policy(authorities: [Self.authority], maxTtlCeiling: ceiling), kv: kv, shards: shards, clock: clock)
    }

    func testARevocationSurvivesANewRegistryOverTheSameStore() throws {
        let kv = MemoryAtomicKV()
        let first = try reg(kv)
        let l1 = lease("L1")
        XCTAssertTrue(first.accept(l1).ok)
        XCTAssertTrue(first.revoke(revocation("L1")).ok)
        let second = try reg(kv)
        XCTAssertEqual(second.accept(l1).code, "revoked", "the signed seq-1 record is refused by a registry that never saw the revocation call")
        XCTAssertEqual(Lease.checkLease(l1, registry: second, now: .int(1100)).code, "revoked")
    }

    func testTwoRegistriesOnOneStoreShareTheNewestRecord() throws {
        let kv = MemoryAtomicKV()
        let a = try reg(kv), b = try reg(kv)
        XCTAssertTrue(a.accept(lease("L2")).ok)
        XCTAssertEqual(b.accept(lease("L2", seq: 2, renewed: 1100, expires: 1600, digest: "j2")).seq, 2)
        XCTAssertEqual(a.accept(lease("L2", seq: 2, renewed: 1100, expires: 1600, digest: "j3")).code, "lease_fork", "the other registry's seq 2 is visible")
        XCTAssertEqual(a.history("L2").count, 2)
    }

    func testAStoreThatCannotAnswerFailsClosed() throws {
        let r = try reg(A0H15ThrowingKV())
        XCTAssertEqual(r.accept(lease("L3")).code, "store_unreachable")
        XCTAssertEqual(r.revoke(revocation("L3")).code, "store_unreachable")
        XCTAssertEqual(Lease.checkLease(lease("L3"), registry: r, now: .int(1100)).code, "store_unreachable")
        XCTAssertNil(r.get("L3"))
        XCTAssertEqual(r.history("L3"), [])
    }

    func testTwoConcurrentRenewalsExactlyOneWins() throws {
        let kv = MemoryAtomicKV()
        let a = try reg(kv), b = try reg(kv)
        XCTAssertTrue(a.accept(lease("L4")).ok)
        let r1 = lease("L4", seq: 2, renewed: 1100, expires: 1600, digest: "x"), r2 = lease("L4", seq: 2, renewed: 1100, expires: 1700, digest: "y")
        let box = A0H15ResultBox()
        let results: [String]? = S2Deadline.within(20, "concurrent renewals") {
            let g = DispatchGroup()
            for (reg, rec) in [(a, r1), (b, r2)] {
                g.enter()
                DispatchQueue.global().async {
                    let r = reg.accept(rec)
                    box.add(r.ok ? "ok" : (r.code ?? "?"))
                    g.leave()
                }
            }
            g.wait()
            return box.all()
        }
        XCTAssertEqual((results ?? []).filter { $0 == "ok" }.count, 1, "exactly one renewal wins: \(results ?? [])")
        XCTAssertEqual((results ?? []).filter { $0 == "lease_fork" }.count, 1)
    }

    /// F5: a revocation is pruned once `revoked_at + ceiling` is past (clock injected); without a ceiling nothing is pruned.
    func testRevocationsArePrunedPastTheCeilingOnly() throws {
        let kv = MemoryAtomicKV()
        let now = LockedClock(0)
        let r = try reg(kv, ceiling: 2000, shards: 1, clock: { now.value })
        XCTAssertTrue(r.revoke(revocation("old", at: 0)).ok)
        XCTAssertEqual(try (0..<r.shardCount).reduce(0) { $0 + (try r.shardRevocations($1)).count }, 1)
        now.value = 2001
        XCTAssertTrue(r.accept(lease("fresh")).ok, "an accept prunes the single shard")
        XCTAssertEqual(try r.shardRevocations(0).count, 0, "0 + 2000 < 2001")
        XCTAssertTrue(r.revoke(revocation("other", at: 2001)).ok)
        XCTAssertEqual(try r.shardRevocations(0).count, 1, "the old one (0 + 2000 < 2001) is gone, the new one stays")
        let kv2 = MemoryAtomicKV()
        let keep = try reg(kv2, ceiling: nil, clock: { 10_000_000 })
        XCTAssertTrue(keep.revoke(revocation("old", at: 0)).ok)
        XCTAssertEqual(try (0..<keep.shardCount).reduce(0) { $0 + (try keep.shardRevocations($1)).count }, 1, "no ceiling: kept")
    }

    func testTheShardCountIsPinnedInTheStore() throws {
        let kv = MemoryAtomicKV()
        let a = try Lease.Registry(policy: Lease.Policy(authorities: [Self.authority]), kv: kv, shards: 4)
        XCTAssertTrue(a.accept(lease("L5")).ok)
        let b = try Lease.Registry(policy: Lease.Policy(authorities: [Self.authority]), kv: kv, shards: 8)
        XCTAssertEqual(b.accept(lease("L6")).code, "store_unreachable", "another shard count would hide existing leases")
        XCTAssertThrowsError(try Lease.Registry(policy: Lease.Policy(authorities: [Self.authority]), kv: kv, shards: 0))
        XCTAssertThrowsError(try Lease.Registry(policy: Lease.Policy(authorities: [Self.authority]), kv: kv, shards: 4097))
    }
}

final class A0H15ResultBox: @unchecked Sendable {
    private let l = NSLock()
    private var v: [String] = []
    func add(_ x: String) { l.lock(); v.append(x); l.unlock() }
    func all() -> [String] { l.lock(); defer { l.unlock() }; return v }
}

final class LockedClock: @unchecked Sendable {
    private let l = NSLock()
    private var v: Int64
    init(_ v: Int64) { self.v = v }
    var value: Int64 { get { l.lock(); defer { l.unlock() }; return v } set { l.lock(); v = newValue; l.unlock() } }
}

final class A0H15BreakGlassStoreTests: XCTestCase {
    private static let authority = V2F.key("a0h15-bg-authority"), reviewer = V2F.key("a0h15-bg-reviewer")
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func grant(maxUses: Int64) -> JSONValue {
        var b: JObject = ["v": .int(1), "id": .string("g1"), "holder": .string("holder-1"), "grant_ref": .string("ref"), "reason_digest": .string("rd"), "max_uses": .int(maxUses),
                          "issued_at": .int(1_000_000), "expires_at": .int(1_001_000), "review_within": .int(5000), "notify_to": .string("n"), "authority": .string(V2F.pub(Self.authority))]
        b["sig"] = .string(V2F.sign(Self.authority, IV.message(BreakGlass.DOMAIN, .object(b))!))
        return .object(b)
    }

    private func reg(_ kv: any AtomicKV) throws -> BreakGlass.Registry {
        try BreakGlass.Registry(policy: BreakGlass.Policy(authorities: [V2F.pub(Self.authority)], reviewers: [V2F.pub(Self.reviewer)]), kv: kv)
    }

    private func use(_ r: BreakGlass.Registry, at: Int64) -> BreakGlass.Decision {
        r.use(id: .string("g1"), holder: .string("holder-1"), actionDigest: .string("d"), now: .int(at), notified: .bool(true))
    }

    func testAUseLimitHoldsAcrossTwoRegistriesOnOneStore() throws {
        let kv = MemoryAtomicKV()
        let a = try reg(kv), b = try reg(kv)
        XCTAssertTrue(a.accept(grant(maxUses: 1), now: .int(1_000_000)).ok)
        XCTAssertEqual(use(a, at: 1_000_100).decision, "allow")
        XCTAssertEqual(use(b, at: 1_000_200).code, "budget_exhausted", "the other instance sees the use")
    }

    func testAStoreThatCannotAnswerFailsClosed() throws {
        let r = try reg(A0H15ThrowingKV())
        XCTAssertEqual(r.accept(grant(maxUses: 1), now: .int(1_000_000)).code, "store_unreachable")
        XCTAssertEqual(use(r, at: 1_000_100).code, "store_unreachable")
        XCTAssertTrue(r.frozen(holder: .string("holder-1"), now: .int(1_000_000)), "an unanswerable store is frozen")
    }

    func testAnOverdueUnreviewedHolderIsFrozenForANewRegistry() throws {
        let kv = MemoryAtomicKV()
        let a = try reg(kv)
        XCTAssertTrue(a.accept(grant(maxUses: 2), now: .int(1_000_000)).ok)
        XCTAssertEqual(use(a, at: 1_000_100).decision, "allow")
        let b = try reg(kv)
        XCTAssertTrue(b.frozen(holder: .string("holder-1"), now: .int(1_000_100 + 5000)))
        XCTAssertFalse(b.frozen(holder: .string("holder-1"), now: .int(1_000_100 + 4999)))
    }
}

final class A0H15BlueprintStoreTests: XCTestCase {
    private static let op = V2F.key("a0h15-bp-operator")
    private static let CHAIN: JSONValue = .array([.object(["issuer": .string("root"), "holder": .string("BP")]), .object(["issuer": .string("BP"), "holder": .string("inst")])])
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func rec(epoch: Int64, status: String = "active", extra: JObject = [:]) -> JSONValue {
        var b: JObject = ["v": .int(1), "id": .string("bp1"), "key": .string("BP"), "ceiling": .array([]), "epoch": .int(epoch), "status": .string(status),
                          "issued_at": .int(1), "operator": .string(V2F.pub(Self.op))]
        for (k, v) in extra { b[k] = v }
        b["sig"] = .string(V2F.sign(Self.op, IV.message(Blueprint.DOMAIN, .object(b))!))
        return .object(b)
    }

    func testADisabledBlueprintStaysDisabledForANewRegistry() {
        let store = Blueprint.MemoryStore()
        let a = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: store)
        XCTAssertTrue(a.accept(rec(epoch: 5, status: "disabled")).ok)
        let b = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: store)
        XCTAssertEqual(b.accept(rec(epoch: 4)).code, "stale_epoch", "the replayed active epoch 4 is older than the stored epoch 5")
        XCTAssertEqual(Blueprint.check(chain: Self.CHAIN, registry: b, now: .int(0), mode: "any").code, "blueprint_disabled")
        XCTAssertEqual(b.epoch, 5)
    }

    func testTheKVStoreKeepsRecordsAndTheMaximumEpoch() throws {
        let kv = MemoryAtomicKV()
        let a = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: Blueprint.KVStore(kv: kv))
        XCTAssertTrue(a.accept(rec(epoch: 3)).ok)
        XCTAssertTrue(a.accept(rec(epoch: 7)).ok)
        let b = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: Blueprint.KVStore(kv: kv))
        XCTAssertEqual(b.epoch, 7)
        XCTAssertEqual(try b.get("BP")?[JKey("epoch")]?.safeInt, 7)
        XCTAssertEqual(b.accept(rec(epoch: 6)).code, "stale_epoch")
    }

    func testAStoreThatCannotAnswerFailsClosed() {
        struct Down: Error {}
        struct DownStore: Blueprint.Store {
            func get(_ key: String) throws -> JObject? { throw Down() }
            func put(_ b: JObject) throws { throw Down() }
            func maxEpoch() throws -> Int64 { throw Down() }
        }
        let r = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: DownStore())
        XCTAssertEqual(r.accept(rec(epoch: 1)).code, "store_unreachable")
        XCTAssertEqual(Blueprint.check(chain: Self.CHAIN, registry: r, now: .int(0), mode: "any").code, "store_unreachable")
        XCTAssertEqual(Blueprint.check(chain: Self.CHAIN, registry: r, now: .int(0), mode: "any", minEpoch: 1).code, "store_unreachable")
    }

    /// F4: runtime_pins with no hook -> admission_required; hook false or throwing -> not_admitted; true -> continues (allow here).
    func testTheAdmittedHook() {
        struct Boom: Error {}
        let store = Blueprint.MemoryStore()
        let r = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: store)
        let pins: JSONValue = .array([.object(["model_id": .string("m")])])
        XCTAssertTrue(r.accept(rec(epoch: 1, extra: ["runtime_pins": pins])).ok)
        func gate(_ hook: ((String, JObject) throws -> Bool)?) -> Blueprint.Decision { Blueprint.check(chain: Self.CHAIN, registry: r, now: .int(0), mode: "any", admitted: hook) }
        XCTAssertEqual(gate(nil).code, "admission_required")
        XCTAssertEqual(gate({ _, _ in false }).code, "not_admitted")
        XCTAssertEqual(gate({ _, _ in throw Boom() }).code, "not_admitted")
        XCTAssertEqual(gate({ _, _ in true }).decision, "allow")
        var seen: [String] = []
        XCTAssertEqual(gate({ holder, bp in seen.append(holder + "/" + (bp[JKey("id")]?.asString ?? "")); return true }).decision, "allow")
        XCTAssertEqual(seen, ["inst/bp1"], "the hook sees the instance key and the record")
    }
}
