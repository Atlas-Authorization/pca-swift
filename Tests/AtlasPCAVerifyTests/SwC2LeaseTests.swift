import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Lease registry: shard hashing, shard-count limits and pin, revocation pruning at its boundary, and fail-closed answers of a store that
/// cannot decide, against packages/pca-grants/src/lease.ts.
final class SwC2LeaseTests: XCTestCase {
    private static let key = V2F.key("swc2-lease-authority")
    private static var authority: String { V2F.pub(key) }

    final class Clock: @unchecked Sendable {
        var t: Int64
        init(_ t: Int64) { self.t = t }
    }

    /// A store that can be switched off.
    final class SwitchKV: AtomicKV, @unchecked Sendable {
        struct Down: Error {}
        let inner = MemoryAtomicKV()
        var down = false
        func get(_ key: String) throws -> JSONValue? {
            if down { throw Down() }
            return inner.get(key)
        }
        func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws {
            if down { throw Down() }
            inner.update(key, f)
        }
    }

    private func lease(_ id: String, maxTtl: Int64 = 1000, expires: Int64 = 1500) -> JSONValue {
        var l: JObject = ["v": .int(1), "lease_id": .string(id), "path": .string("svc/a"), "grant_ref": .string("g"), "holder": .string("h"), "requester": .string("r"),
                          "approvers": .array([.string("a")]), "justification_digest": .string("j"), "seq": .int(1), "issued_at": .int(1000), "renewed_at": .int(1000),
                          "expires_at": .int(expires), "max_ttl": .int(maxTtl), "authority": .string(Self.authority)]
        l["sig"] = .string(V2F.sign(Self.key, IV.message(Lease.DOMAIN, .object(l))!))
        return .object(l)
    }

    private func revocation(_ value: String, at: Int64) -> JSONValue {
        var r: JObject = ["v": .int(1), "target": .string("lease"), "value": .string(value), "revoked_at": .int(at), "authority": .string(Self.authority)]
        r["sig"] = .string(V2F.sign(Self.key, IV.message(Lease.REVOKE_DOMAIN, .object(r))!))
        return .object(r)
    }

    private func registry(_ kv: any AtomicKV, shards: Int = 4, ceiling: Int64? = nil, clock: Clock? = nil) -> Lease.Registry {
        let policy = Lease.Policy(authorities: [Self.authority], minApprovals: 1, maxTtlCeiling: ceiling)
        if let c = clock { return try! Lease.Registry(policy: policy, kv: kv, shards: shards, clock: { c.t }) }
        return try! Lease.Registry(policy: policy, kv: kv, shards: shards)
    }

    func testShardLimits() throws {
        XCTAssertEqual(Lease.DEFAULT_SHARDS, 16)
        XCTAssertEqual(Lease.MAX_SHARDS, 4096)
        XCTAssertEqual(try Lease.Registry(policy: Lease.Policy(authorities: []), kv: MemoryAtomicKV()).shardCount, 16)
        for ok in [1, 2, 4095, 4096] { XCTAssertNoThrow(try Lease.Registry(policy: Lease.Policy(authorities: []), kv: MemoryAtomicKV(), shards: ok), "\(ok)") }
        for bad in [0, -1, 4097] {
            XCTAssertThrowsError(try Lease.Registry(policy: Lease.Policy(authorities: []), kv: MemoryAtomicKV(), shards: bad), "\(bad)") {
                XCTAssertEqual(($0 as? PCAProducerError)?.message, "LeaseRegistry: shards must be an integer from 1 to 4096")
            }
        }
    }

    func testShardOfIsTheBigEndianFirstFourBytesOfSha256() {
        for i in 0..<80 {
            let id = "lease-\(i)"
            let h = Canonical.sha256(Canonical.utf8(id))
            let v = UInt64(h[0]) << 24 | UInt64(h[1]) << 16 | UInt64(h[2]) << 8 | UInt64(h[3])
            for n in [16, 4096, 1_000_003, Int(UInt32.max)] {
                XCTAssertEqual(Lease.shardOf(id, n), Int(v % UInt64(n)), "\(id) over \(n)")
            }
        }
    }

    func testTheDefaultClockIsTheWallClockInMilliseconds() throws {
        let reg = try Lease.Registry(policy: Lease.Policy(authorities: []), kv: MemoryAtomicKV())
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        XCTAssertLessThan(abs(reg.clock() - now), 600_000, "within ten minutes of the system clock, in milliseconds")
    }

    func testTheMetaDocumentPinsTheShardCount() throws {
        let kv = MemoryAtomicKV()
        let reg = registry(kv, shards: 7)
        XCTAssertNil(kv.get("lease/meta"))
        XCTAssertTrue(try reg.ready())
        XCTAssertEqual(kv.get("lease/meta"), .object(["v": .int(1), "shards": .int(7)]))
    }

    func testRevocationsLiveExactlyUntilRevokedAtPlusTheCeiling() throws {
        let clock = Clock(6000)
        let reg = registry(MemoryAtomicKV(), shards: 1, ceiling: 1000, clock: clock)
        XCTAssertEqual(reg.revoke(revocation("OTHER", at: 5000)), Lease.Revoke(ok: true, revoked: 0))
        XCTAssertEqual(try reg.shardRevocations(0).count, 1, "kept at revoked_at + ceiling == now")
        clock.t = 6001
        XCTAssertEqual(reg.revoke(revocation("OTHER", at: 5000)), Lease.Revoke(ok: true, revoked: 0))
        XCTAssertEqual(try reg.shardRevocations(0).count, 0, "dropped one millisecond later")
    }

    func testAcceptingALeasePrunesExpiredRevocations() throws {
        let clock = Clock(6000)
        let reg = registry(MemoryAtomicKV(), shards: 1, ceiling: 1000, clock: clock)
        XCTAssertTrue(reg.revoke(revocation("OTHER", at: 5000)).ok)
        XCTAssertEqual(try reg.shardRevocations(0).count, 1)
        clock.t = 6001
        XCTAssertEqual(reg.accept(lease("L1")), Lease.Accept(ok: true, replaced: true, seq: 1))
        XCTAssertEqual(try reg.shardRevocations(0).count, 0)
    }

    func testAShardIndexMustBeInRange() throws {
        let reg = registry(MemoryAtomicKV(), shards: 4)
        XCTAssertNoThrow(try reg.shardRevocations(0))
        XCTAssertNoThrow(try reg.shardRevocations(3))
        XCTAssertThrowsError(try reg.shardRevocations(4)) { XCTAssertEqual(($0 as? PCAProducerError)?.message, "no such shard") }
        XCTAssertThrowsError(try reg.shardRevocations(5))
        XCTAssertThrowsError(try reg.shardRevocations(-1)) { XCTAssertEqual(($0 as? PCAProducerError)?.message, "no such shard") }
    }

    func testADifferentShardCountIsRefused() throws {
        let kv = MemoryAtomicKV()
        XCTAssertTrue(try registry(kv, shards: 4).ready())
        let b = registry(kv, shards: 5)
        XCTAssertEqual(b.accept(lease("L1")), Lease.Accept(ok: false, code: "store_unreachable"))
        XCTAssertEqual(b.revoke(revocation("L1", at: 5000)), Lease.Revoke(ok: false, code: "store_unreachable"))
        XCTAssertEqual(kv.get("lease/meta"), .object(["v": .int(1), "shards": .int(4)]))
    }

    func testAStoreThatGoesDownRefuses() throws {
        let kv = SwitchKV()
        let reg = registry(kv)
        XCTAssertTrue(reg.accept(lease("L1")).ok)
        kv.down = true
        XCTAssertEqual(reg.accept(lease("L2")), Lease.Accept(ok: false, code: "store_unreachable"))
        XCTAssertEqual(reg.revoke(revocation("L1", at: 5000)), Lease.Revoke(ok: false, code: "store_unreachable"))
        let fresh = registry(kv)
        XCTAssertEqual(fresh.accept(lease("L2")), Lease.Accept(ok: false, code: "store_unreachable"))
        XCTAssertEqual(fresh.revoke(revocation("L1", at: 5000)), Lease.Revoke(ok: false, code: "store_unreachable"))
    }
}
