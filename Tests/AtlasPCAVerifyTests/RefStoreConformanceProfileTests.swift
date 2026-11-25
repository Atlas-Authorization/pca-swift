import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The bond, budget, ledger and mesh-witness profile suites: the reference stores pass, every defective store is flagged by the check that catches it, and the
/// check inventory (names, claims, capability needed) matches the reference's corpus entry.
final class RefStoreConformanceProfileTests: XCTestCase {
    typealias S = PCAStoreConformance

    private func failing(_ r: S.ProfileReport) -> [String] { r.checks.filter { $0.status == "fail" }.map { $0.name } }

    private func assertGood(_ r: S.ProfileReport, _ text: String, durable: Bool, total: Int) {
        XCTAssertEqual(r.status, "pass", text)
        XCTAssertEqual(r.checks.count, total)
        if durable {
            XCTAssertEqual(r.checks.filter { $0.status == "pass" }.count, total, text)
        } else {
            XCTAssertEqual(r.checks.filter { $0.status == "skip" }.map { $0.name }, ["state-survives-reopen", r.checks.last?.name ?? ""], text) // durable and crash checks
        }
    }

    func testTheGoodBondStoresPass() throws {
        let m = try S.runBondStoreConformance(S.memoryBondStoreAdapter())
        assertGood(m, S.formatBondReport(m), durable: false, total: S.BOND_CHECKS.count)
        let d = try S.runBondStoreConformance(S.durableBondStoreAdapter())
        assertGood(d, S.formatBondReport(d), durable: true, total: S.BOND_CHECKS.count)
        XCTAssertTrue(S.formatBondReport(m).hasPrefix("pca-store-conformance (bond store): KvBondStore over an in-memory kv -> PASS\n  [PASS] empty-store-reads-empty"))
        XCTAssertEqual(try S.runBondStoreConformance(S.memoryBondStoreAdapter(), only: ["hostile-names-are-plain-keys"]).checks.count, 1)
    }

    func testEveryDefectiveBondStoreIsFlagged() throws {
        func f(_ a: S.BondStoreAdapter) throws -> [String] { try failing(S.runBondStoreConformance(a)) }
        XCTAssertTrue(try f(S.nonAtomicBondStoreAdapter()).contains("settle-needs-the-expected-phase"))
        XCTAssertTrue(try f(S.noReplayBondStoreAdapter()).contains("open-retry-is-replayed-and-different-terms-conflict"))
        XCTAssertFalse(try f(S.lostUpdateBondStoreAdapter()).isEmpty)
        XCTAssertTrue(try f(S.amnesiaBondStoreAdapter()).contains("state-survives-reopen"))
        XCTAssertTrue(try f(S.clockRewindBondStoreAdapter()).contains("time-high-water-only-moves-forward"))
        XCTAssertEqual(Set(S.BOND_REFERENCE_ADAPTERS.keys), ["bond-memory", "bond-durable-file", "bad-bond-non-atomic", "bad-bond-no-replay", "bad-bond-lost-update", "bad-bond-amnesia", "bad-bond-clock-rewind"])
    }

    func testTheGoodBudgetLedgersPass() throws {
        let m = try S.runBudgetLedgerConformance(S.memoryBudgetLedgerAdapter())
        assertGood(m, S.formatBudgetReport(m), durable: false, total: S.BUDGET_CHECKS.count)
        let d = try S.runBudgetLedgerConformance(S.durableBudgetLedgerAdapter())
        assertGood(d, S.formatBudgetReport(d), durable: true, total: S.BUDGET_CHECKS.count)
        XCTAssertTrue(S.formatBudgetReport(m).hasPrefix("pca-store-conformance (budget ledger): KvBudgetLedger over an in-memory kv -> PASS\n  [PASS] empty-key-is-empty"))
    }

    func testEveryDefectiveBudgetLedgerIsFlagged() throws {
        func f(_ a: S.BudgetLedgerAdapter) throws -> [String] { try failing(S.runBudgetLedgerConformance(a)) }
        XCTAssertTrue(try f(S.noCapBudgetLedgerAdapter()).contains("reservation-counts-at-once-and-cap-is-inclusive"))
        XCTAssertTrue(try f(S.noCasBudgetLedgerAdapter()).contains("expected-version-is-compare-and-swap"))
        XCTAssertFalse(try f(S.lostUpdateBudgetLedgerAdapter()).isEmpty)
        XCTAssertTrue(try f(S.amnesiaBudgetLedgerAdapter()).contains("state-survives-reopen"))
        XCTAssertTrue(try f(S.releaseUnreservedBudgetLedgerAdapter()).contains("release-without-reserve-credits-nothing"))
        XCTAssertTrue(try f(S.releaseCommittedBudgetLedgerAdapter()).contains("settle-rules"))
        XCTAssertTrue(try f(S.lateCommitBudgetLedgerAdapter()).contains("a-late-commit-cannot-overspend"))
        XCTAssertTrue(try f(S.noReplayBudgetLedgerAdapter()).contains("reserve-retry-is-a-replay"))
        XCTAssertTrue(try f(S.sharedKeysBudgetLedgerAdapter()).contains("keys-are-independent"))
        XCTAssertTrue(try f(S.expireCommittedBudgetLedgerAdapter()).contains("expiry-releases-only-open-reservations-past-their-deadline"))
        XCTAssertTrue(try f(S.expireStartedBudgetLedgerAdapter()).contains("expiry-releases-only-open-reservations-past-their-deadline"))
        XCTAssertTrue(try f(S.volatileClaimsDurableBudgetLedgerAdapter()).contains("durable-claim-matches-the-adapter"))
        XCTAssertEqual(S.BUDGET_REFERENCE_ADAPTERS.count, 14)
    }

    func testTheGoodLedgerStoresPass() throws {
        let m = try S.runLedgerStoreConformance(S.memoryLedgerStoreAdapter())
        assertGood(m, S.formatLedgerReport(m), durable: false, total: S.LEDGER_CHECKS.count)
        let d = try S.runLedgerStoreConformance(S.durableLedgerStoreAdapter())
        assertGood(d, S.formatLedgerReport(d), durable: true, total: S.LEDGER_CHECKS.count)
        XCTAssertTrue(S.formatLedgerReport(m).hasPrefix("pca-store-conformance (ledger store): KvLedgerStore over an in-memory kv -> PASS\n  [PASS] empty-store-is-empty"))
    }

    func testEveryDefectiveLedgerStoreIsFlagged() throws {
        func f(_ a: S.LedgerStoreAdapter) throws -> [String] { try failing(S.runLedgerStoreConformance(a)) }
        XCTAssertTrue(try f(S.noCasLedgerStoreAdapter()).contains("append-at-another-position-conflicts-without-trace"))
        XCTAssertTrue(try f(S.partialBatchLedgerStoreAdapter()).contains("a-batch-is-all-or-nothing"))
        XCTAssertFalse(try f(S.lostUpdateLedgerStoreAdapter()).isEmpty)
        XCTAssertTrue(try f(S.amnesiaLedgerStoreAdapter()).contains("state-survives-reopen"))
        XCTAssertTrue(try f(S.checkpointRegressLedgerStoreAdapter()).contains("checkpoints-stay-inside-the-log-and-never-go-back"))
        XCTAssertTrue(try f(S.noReplayLedgerStoreAdapter()).contains("append-retry-is-a-replay"))
        XCTAssertEqual(Set(S.LEDGER_REFERENCE_ADAPTERS.keys).count, 8)
    }

    func testTheMeshWitnessStoresPass() {
        let m = S.runMeshWitnessStoreConformance(S.memoryMeshWitnessStoreAdapter())
        XCTAssertEqual(m.status, "pass", S.formatProfile("mesh witness store", m))
        XCTAssertEqual(m.checks.count, 7)
        let f = S.runMeshWitnessStoreConformance(S.fileMeshWitnessStoreAdapter())
        XCTAssertEqual(f.status, "pass", S.formatProfile("mesh witness store", f))
        XCTAssertEqual(f.checks.count, 10)
    }

    /// The reference's check inventories: names, claims and the capability each needs (mesh witness: the case names), in order.
    func testTheCheckInventoriesMatchTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-store-conformance.json.gz", ["inventory"]) { c in
            guard let kind = c.arg(0)?.asString else { return }
            let got: JSONValue
            switch kind {
            case "bond": got = S.inventory(S.BOND_CHECKS)
            case "budget": got = S.inventory(S.BUDGET_CHECKS)
            case "ledger": got = S.inventory(S.LEDGER_CHECKS)
            case "lease": d.skip("inventory/lease: compared by StoreConformanceLeaseTests"); return
            default:
                let flags = kind.components(separatedBy: "+")
                XCTAssertEqual(flags[0], "mesh-witness")
                let a = S.MeshWitnessStoreAdapter(name: kind, make: { MemoryMeshWitnessStore() }, reopen: flags.contains("reopen") ? { $0 } : nil,
                                                  damage: flags.contains("damage") ? { _ in } : nil)
                got = .array(S.meshWitnessStoreCases(a).map { .string($0.name) })
            }
            d.add(c, Base.diff(c, .value(got)))
        }
        XCTAssertEqual(n, 8)
        d.finish(7)
    }
}
