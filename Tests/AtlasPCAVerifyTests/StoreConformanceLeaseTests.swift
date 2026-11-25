import XCTest
import Foundation
@testable import AtlasPCAVerify

final class StoreConformanceLeaseTests: XCTestCase {
    typealias S = PCAStoreConformance

    func testTheGoodStorePassesAndSkipsWhatItCannotDo() {
        let r = S.runLeaseStoreConformance(S.memoryLeaseStoreAdapter())
        XCTAssertEqual(r.status, "pass", S.formatLeaseReport(r))
        XCTAssertEqual(r.checks.filter { $0.status == "pass" }.count, 7)
        XCTAssertEqual(r.checks.first { $0.name == "state-survives-reopen" }?.status, "skip")
        XCTAssertEqual(r.checks.first { $0.name == "acknowledged-lease-survives-a-crash" }?.status, "skip")
        XCTAssertTrue(S.formatLeaseReport(r).hasPrefix("pca-store-conformance (lease store): in-memory lease store -> PASS\n  [PASS] empty-store-has-no-lease"))
        XCTAssertEqual(S.runLeaseStoreConformance(S.memoryLeaseStoreAdapter(), only: ["epoch-never-goes-down"]).checks.count, 1)
    }

    func testEveryDefectiveStoreIsFlaggedByTheCheckThatCatchesIt() {
        func failing(_ a: S.LeaseStoreAdapter) -> [String] { S.runLeaseStoreConformance(a).checks.filter { $0.status == "fail" }.map { $0.name } }
        XCTAssertTrue(failing(S.noCasLeaseStoreAdapter()).contains("wrong-expected-record-never-writes"))
        XCTAssertTrue(failing(S.epochRegressLeaseStoreAdapter()).contains("epoch-never-goes-down"))
        XCTAssertTrue(failing(S.lostUpdateLeaseStoreAdapter()).contains("racing-acquirers-have-one-winner"))
        XCTAssertTrue(failing(S.amnesiaLeaseStoreAdapter()).contains("state-survives-reopen"))
        XCTAssertEqual(Set(S.LEASE_REFERENCE_ADAPTERS.keys), ["lease-memory", "bad-lease-no-cas", "bad-lease-epoch-regress", "bad-lease-lost-update", "bad-lease-amnesia"])
    }

    func testTheLeaseHelpersFollowTheFencingRules() throws {
        let store = S.memoryLeaseStoreAdapter()
        let h = try store.create()
        let a = S.acquireLease(h.store, "a", ttlMs: 10_000)
        XCTAssertTrue(a.ok)
        XCTAssertEqual(S.acquireLease(h.store, "b", ttlMs: 10_000).reason, "held")
        XCTAssertEqual(S.acquireLease(h.store, "", ttlMs: 10_000).reason, "invalid")
        XCTAssertEqual(S.acquireLease(h.store, "b", ttlMs: 1).reason, "invalid")
        let renewed = S.renewLease(h.store, a.lease!, ttlMs: 10_000)
        XCTAssertTrue(renewed.ok)
        XCTAssertEqual(renewed.lease?.epoch, 1)
        XCTAssertTrue(S.releaseLease(h.store, renewed.lease!).ok)
        XCTAssertEqual(S.releaseLease(h.store, renewed.lease!).reason, "stale") // already released
        XCTAssertEqual(S.acquireLease(h.store, "b", ttlMs: 10_000).lease?.epoch, 2)
        XCTAssertEqual(S.renewLease(h.store, a.lease!, ttlMs: 10_000).reason, "stale")
    }

    /// The reference's check inventory: names, claims and the capability each needs, in order.
    func testTheCheckInventoryMatchesTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-store-conformance.json.gz", ["inventory"]) { c in
            guard c.arg(0)?.asString == "lease" else { d.skip("inventory/\(c.arg(0)?.asString ?? ""): that profile is not carried"); return }
            let got: JSONValue = .array(S.LEASE_CHECKS.map { .object(["name": .string($0.name), "claim": .string($0.claim), "needs": $0.needs.map { .string($0) } ?? .null]) })
            d.add(c, Base.diff(c, .value(got)))
        }
        XCTAssertEqual(n, 8)
        d.finish(1)
    }
}
