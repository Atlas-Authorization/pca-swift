import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Second sweep: the sites where a non-finite value still reached the admitting side of a comparison (NaN, +Infinity, -Infinity), plus the server-layer
/// clocks, timeouts and approval expiries. Each test notes what the old comparison did.
final class NonFiniteInfinityKillTests2: XCTestCase {
    private static let bad: [Double] = [.nan, .infinity, -.infinity]

    // pre-fix: `nowMs < notAfter` held for -Infinity, so an enrollment read as live under a broken clock (the next failure was the helper commitment)
    func testPufEnrollmentExpiryRefusesANonFiniteClock() throws {
        var o = PCAAttestPuf.VerifierOptions(policy: PCAAttestPuf.Policy(measurements: ["m"]))
        o.resolveEnrollment = { _, _, _ in .object(["providerId": .string("p"), "notAfter": .int(100)]) }
        o.resolveEvidence = { _, _ in .object(["provider_id": .string("p"), "alg": .string("a")]) }
        let v = try PCAAttestPuf.createPufVerifier(o)
        let live = try v.verify(document: .object([:]), ctx: .object([:]), nowMs: 50, expected: .object([:]))
        XCTAssertNotEqual(live.reason, "PUF enrollment has expired")
        for x in Self.bad {
            let r = try v.verify(document: .object([:]), ctx: .object([:]), nowMs: x, expected: .object([:]))
            XCTAssertEqual(r.reason, "PUF enrollment has expired")
        }
    }

    // pre-fix: a non-finite clock or skew skipped the per-key validity window checks
    func testMaaJwksEvaluationRefusesANonFiniteClockOrSkew() {
        let jwks: JSONValue = .object(["keys": .array([.object(["kid": .string("k")])])])
        func reason(_ now: Double, _ skew: Double?) -> String? {
            var p = PCAMaaKeys.Policy(trustedIssuers: ["https://a.example"])
            p.clockSkewMs = skew
            let r = PCAMaaKeys.evaluateMaaJwks(jwks, issuer: "https://a.example", policy: p, nowMs: now)
            return r.get("rejected")?.asArray?.first?.get("reason")?.asString
        }
        XCTAssertEqual(reason(1000, nil), "no x5c")
        for x in Self.bad {
            XCTAssertEqual(reason(x, nil), "clock and skew must be finite")
            XCTAssertEqual(reason(1000, x), "clock and skew must be finite")
        }
    }

    // pre-fix: an infinite ttl or skew, or a NaN limit, was accepted and widened every later window
    func testMaaKeyTrustRefusesNonFiniteWindows() throws {
        func make(_ edit: (inout PCAMaaKeys.Policy) -> Void) throws {
            var p = PCAMaaKeys.Policy(trustedIssuers: ["https://a.example"])
            edit(&p)
            _ = try PCAMaaKeys.createMaaKeyTrust(policy: p, store: PCAMaaKeys.MemoryKeyStateStore(), fetch: { _ in PCAMaaKeys.Response(status: 200, body: []) })
        }
        XCTAssertNoThrow(try make { $0.maxStaleMs = .infinity })
        for x in Self.bad {
            XCTAssertThrowsError(try make { $0.ttlMs = x })
            XCTAssertThrowsError(try make { $0.clockSkewMs = x })
        }
        XCTAssertThrowsError(try make { $0.maxStaleMs = .nan })
        XCTAssertThrowsError(try make { $0.maxNewKeysPerFetch = .nan })
        XCTAssertThrowsError(try make { $0.maxInitialKeys = .nan })
    }

    // pre-fix: an infinite balance credited or debited as if it were an ordinary one
    func testBondMovesRefuseANonFiniteBalance() {
        for x in Self.bad {
            for op in ["credit", "debit"] {
                XCTAssertThrowsError(try PCABondMath.applyBondMoves({ _ in x }, [.object(["account": .string("a"), "op": .string(op), "amount": .int(1)])]))
            }
        }
    }

    private final class OpenStub: BondStore {
        let count: Double, sum: Double, balance: Double
        init(count: Double = 0, sum: Double = 0, balance: Double = 1000) { self.count = count; self.sum = sum; self.balance = balance }
        func read(_ claimId: String, _ depositor: String?) throws -> JSONValue {
            .object(["balances": .array([.array([.string("d"), .double(balance)])]), "openTotals": .object(["count": .double(count), "sum": .double(sum)]), "highWater": .int(0)])
        }
        func commit(_ plan: JSONValue, _ observedAt: JSONValue) throws -> JSONValue { throw PCAStoreError("store_unavailable", "stub") }
        func deposit(_ account: JSONValue, _ amount: JSONValue) throws -> Double { throw PCAStoreError("store_unavailable", "stub") }
    }

    private func openMessage(_ stub: OpenStub) throws -> String? {
        let key: PCASuiteKey = .ed25519(try PCAEdKey(seed: [UInt8](repeating: 4, count: 32)))
        do { _ = try StoreBondLedger(store: stub, guardian: key, clock: { 1000 }).openBond("c", amount: 1, depositor: "d"); return nil } catch { return (error as? JSError)?.message ?? "other" }
    }

    // pre-fix: `-Infinity + 1 > cap` and `NaN + 1 > cap` were false and an infinite balance covered any bond
    func testOpenBondRefusesNonFiniteTotalsAndBalances() throws {
        XCTAssertNil(try openMessage(OpenStub()) .flatMap { $0 == "other" ? nil : $0 }, "control: a finite book reaches the store")
        for x in [Double.nan, -Double.infinity] {
            XCTAssertEqual(try openMessage(OpenStub(count: x)), "openBond: depositor open-claim cap reached")
            XCTAssertEqual(try openMessage(OpenStub(sum: x)), "openBond: depositor aggregate open-bond cap exceeded")
        }
        XCTAssertEqual(try openMessage(OpenStub(balance: .infinity)), "openBond: insufficient balance for the bond")
    }

    // pre-fix: a cap that is not a number never read as exceeded
    func testBudgetReserveTreatsAnUnreadableCapAsExceeded() throws {
        let acc: JSONValue = .object(["id": .string("spend"), "agg": .string("sum"), "val": .string("action.params.amount"), "sel": .object(["verbs": .array([.string("pay")])]),
                                      "win": .object(["kind": .string("task")]), "key": .null, "domain_max": .string("many"), "holder": .object(["kind": .string("site_local")]),
                                      "scope": .string("principal")])
        let ev: JSONValue = .object(["id": .string("e"), "verb": .string("pay"), "resource": .string("r"), "params": .object(["amount": .int(1)]), "t": .int(1000)])
        let ledger = KvBudgetLedger(kv: MemoryAtomicKV(), durable: false)
        let out = try ledger.reserve("principal/alice", .object(["event": ev, "accumulators": .array([acc])]))
        XCTAssertEqual(out.get("outcome")?.asString, "over_cap")
    }

    // pre-fix: a negative timeout aged every record out (the check was `age > timeout`)
    func testRecoveryNeverSettlesOnANegativeTimeout() throws {
        let s = MemoryOperationStore()
        _ = s.create(OperationRecord(id: "a", state: .pending, verb: "v", resource: "r", paramsDigest: "d", reversibility: "reversible", startedAt: 1))
        XCTAssertEqual(try PCA.recoverOperation(s, id: "a", olderThanMs: -1, now: { 10 })?.state, .pending)
        XCTAssertEqual(try PCA.recoverOperation(s, id: "a", olderThanMs: 5, now: { 10 })?.state, .aborted)
    }

    // pre-fix: `age < -1` was false, so compensation never waited for the effect report
    func testUndoCoordinatorRefusesANegativeEffectTimeout() throws {
        var o = PCAUndoOptions(store: MemoryUndoStore(), engine: { _, _ in nil }, signerSecret: [UInt8](repeating: 9, count: 32), audience: "rs",
                               resolveGrant: { _, _ in JSONValue.null }, compensate: { _ in nil }, operations: MemoryOperationStore(), notifier: { _ in .object([:]) }, alert: { _ in })
        o.insecureVolatileStore = true
        XCTAssertNoThrow(try PCAUndoCoordinator.create(o))
        o.effectTimeoutMs = -1
        XCTAssertThrowsError(try PCAUndoCoordinator.create(o)) { XCTAssertEqual(($0 as? UndoError)?.code, "config") }
    }

    // pre-fix: `now < +Infinity` held, so an approval whose stored expiry was infinite stayed executable forever
    func testPlanStatusRefusesAnInfiniteStoredApprovalExpiry() throws {
        let kv = MemoryAtomicKV()
        let reg = PlanRegistry(kv: kv, now: { 100 })
        let node: JSONValue = .object(["id": .string("n1"), "verb": .string("v"), "resource": .string("/r")])
        let root = try XCTUnwrap(reg.draft(grantRef: "g", nodes: .array([node])).record?.root)
        XCTAssertTrue(reg.validate(grantRef: "g", root: root).ok)
        XCTAssertTrue(reg.commit(grantRef: "g", root: root).ok)
        XCTAssertTrue(reg.authorize(grantRef: "g", root: root, approval: PlanApproval(by: "p", expiresAt: 1000)).ok)
        XCTAssertTrue(reg.status(grantRef: "g", root: root, now: 100).executable)
        try kv.update("pca-plan:g:" + root) { v in
            guard var o = v?.asObject, var a = o["approval"]?.asObject else { return v }
            a["expiresAt"] = .double(.infinity)
            o["approval"] = .object(a)
            return .object(o)
        }
        XCTAssertFalse(reg.status(grantRef: "g", root: root, now: 100).executable)
    }

    // pre-fix: `ge` of NaN or +Infinity made `expiry > ge` false, so any wallet expiry passed
    func testErc7715GrantExpiryMustBeASafeInteger() {
        let mgr = "0x" + String(repeating: "a", count: 40)
        func perm(_ a: String) -> JSONValue {
            .object(["type": .string("native-token-allowance"), "data": .object(["tokenAddress": .string("0xt"), "allowance": .string(a)]), "isAdjustmentAllowed": .bool(false)])
        }
        func granted(_ expiresAt: JSONValue) -> String? {
            let sent: JSONValue = .object(["chainId": .string("0x1"), "to": .string("0xabc"), "from": .string("0xdef"), "permission": perm("0x10")])
            let got: JSONValue = .object(["context": .string("0x1234"), "delegationManager": .string(mgr), "chainId": .string("0x1"), "to": .string("0xabc"), "from": .string("0xdef"),
                                          "permission": perm("0x10"), "rules": .array([.object(["type": .string("expiry"), "data": .object(["timestamp": .int(900)])])])])
            return Erc7715.verifyGrantedPermission(.object(["grantDigest": .string("gd"), "expiresAtSec": expiresAt]), sent, got, allowedManagers: .array([.string(mgr)]), contextOwner: nil)
        }
        XCTAssertNil(granted(.int(1000)))
        for x in Self.bad { XCTAssertEqual(granted(.double(x)), "expiry_extended") }
    }

    // pre-fix: an infinite parent budget covered any allocation and any debit
    func testRiskBudgetsRefuseAnInfiniteParentBudget() {
        let inf: JSONValue = .object(["B": .double(.infinity), "tau": .int(0)])
        let fin: JSONValue = .object(["B": .int(5), "tau": .int(0)])
        XCTAssertEqual(PCARiskBudgets.subBudget(fin, alloc: 3).get("ok"), .bool(true))
        XCTAssertEqual(PCARiskBudgets.subBudget(inf, alloc: 3).get("ok"), .bool(false))
        XCTAssertEqual(PCARiskBudgets.debitConsolidated(inf, fin, 1).get("ok"), .bool(false))
        XCTAssertEqual(PCARiskBudgets.debitConsolidated(fin, inf, 1).get("ok"), .bool(false))
        XCTAssertEqual(PCARiskBudgets.debitConsolidated(fin, fin, 1).get("ok"), .bool(true))
    }

    // pre-fix: a NaN bound compared false against every limit, so the window was admitted
    func testChallengeWindowPolicyRefusesNaNBounds() {
        let ok = Optimistic.ChallengeWindowPolicy(minWindowMs: 10, maxWindowMs: 100, maxSkewMs: 5)
        XCTAssertNil(Optimistic.validateWindow(issuedAt: 1000, windowMs: 50, serverNow: 1000, policy: ok))
        let nanSkew = Optimistic.ChallengeWindowPolicy(minWindowMs: 10, maxWindowMs: 100, maxSkewMs: .nan)
        let nanMin = Optimistic.ChallengeWindowPolicy(minWindowMs: .nan, maxWindowMs: 100, maxSkewMs: 5)
        let nanMax = Optimistic.ChallengeWindowPolicy(minWindowMs: 10, maxWindowMs: .nan, maxSkewMs: 5)
        for p in [nanSkew, nanMin, nanMax] { XCTAssertNotNil(Optimistic.validateWindow(issuedAt: 1000, windowMs: 50, serverNow: 1000, policy: p)) }
    }
}
