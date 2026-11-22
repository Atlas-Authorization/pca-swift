import XCTest
@testable import AtlasPCAVerify

/// `Lease.Policy.maxTtlCeiling`, pinned to packages/pca-grants/src/lease.ts:219 (constructor) and :245 (`ttl_ceiling`, right after `over_max_ttl`).
final class LeaseCeilingTests: XCTestCase {
    private static let key = V2F.key("lease-authority")
    private static var authority: String { V2F.pub(key) }

    private func lease(_ id: String, maxTtl: Int64, expires: Int64 = 1500) -> JSONValue {
        var l: JObject = ["v": .int(1), "lease_id": .string(id), "path": .string("svc/a"), "grant_ref": .string("g"), "holder": .string("h"), "requester": .string("r"),
                          "approvers": .array([.string("a")]), "justification_digest": .string("j"), "seq": .int(1), "issued_at": .int(1000), "renewed_at": .int(1000),
                          "expires_at": .int(expires), "max_ttl": .int(maxTtl), "authority": .string(Self.authority)]
        l["sig"] = .string(V2F.sign(Self.key, IV.message(Lease.DOMAIN, .object(l))!))
        return .object(l)
    }

    private func reg(_ ceiling: Int64?) throws -> Lease.Registry {
        try Lease.Registry(policy: Lease.Policy(authorities: [Self.authority], minApprovals: 1, maxTtlCeiling: ceiling), kv: MemoryAtomicKV())
    }

    func testCeiling() throws {
        XCTAssertEqual(try reg(1000).accept(lease("below", maxTtl: 999)).code, nil)
        XCTAssertEqual(try reg(1000).accept(lease("at", maxTtl: 1000)).ok, true)
        XCTAssertEqual(try reg(1000).accept(lease("above", maxTtl: 1001)).code, "ttl_ceiling")
        XCTAssertEqual(try reg(nil).accept(lease("absent", maxTtl: 1_000_000_000)).ok, true)
        // over_max_ttl is decided first
        XCTAssertEqual(try reg(1000).accept(lease("over", maxTtl: 1001, expires: 2002)).code, "over_max_ttl")
    }

    func testMalformedCeilingThrows() throws {
        for bad in [Int64(0), -1, Canonical.MAX_SAFE + 1] {
            XCTAssertThrowsError(try reg(bad)) { XCTAssertEqual(($0 as? PCAProducerError)?.message, "LeaseRegistry: maxTtlCeiling must be a positive integer") }
        }
        XCTAssertNoThrow(try reg(1))
        XCTAssertNoThrow(try reg(Canonical.MAX_SAFE))
    }
}
