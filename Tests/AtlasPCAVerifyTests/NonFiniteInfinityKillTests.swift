import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A clock, window, limit or amount that is not finite (NaN, +Infinity, -Infinity) never admits. Every refusal below reads as the negation of its
/// positive condition AND demands a finite operand, so an infinity cannot land on the admitting side of a comparison.
final class NonFiniteInfinityKillTests: XCTestCase {
    private static let bad: [Double] = [.nan, .infinity, -.infinity]

    // pre-fix: `nowSec < held` was false for NaN and +Infinity, so a live replay key read as free
    func testDpopReplayStoreRefusesNonFiniteClock() throws {
        let store = try InMemoryDpopReplayStore()
        XCTAssertTrue(try store.addIfAbsent("k", expiresAtSec: 100, nowSec: 10))
        for v in Self.bad { XCTAssertFalse(try store.addIfAbsent("k", expiresAtSec: 100, nowSec: v)) }
    }

    // pre-fix: the same comparison in the SET replay store
    func testSetReplayStoreRefusesNonFiniteClock() throws {
        let store = try PCASignals.createInMemorySetReplayStore()
        XCTAssertTrue(try store.addIfAbsent("j", expiresAtSec: 100, nowSec: 10))
        for v in Self.bad { XCTAssertFalse(try store.addIfAbsent("j", expiresAtSec: 100, nowSec: v)) }
    }

    // pre-fix: `existing >= nowSec` was false for NaN and +Infinity
    func testWebBotAuthReplayCacheRefusesNonFiniteClock() throws {
        let cache = WebBotAuthMemoryReplayCache()
        XCTAssertTrue(try cache.claim("k", 100, 10))
        for v in Self.bad { XCTAssertFalse(try cache.claim("k", 100, v)) }
    }

    // pre-fix: `now >= expiresAt` was false for NaN and -Infinity, so a session stayed pending
    func testCibaBrokerReadsANonFiniteClockAsExpired() throws {
        var clock = 1_800_000_000_000.0
        let broker = PCACibaBroker.memory(now: { clock })
        let stepUp: JSONValue = .object(["id": .string("su1"), "verb": .string("transfer"), "resource": .string("acct"), "goalCommit": .string("abcdefghijklmnop")])
        let req = try broker.start(stepUp)
        let id = req.get("auth_req_id")?.asString ?? ""
        XCTAssertEqual(try broker.poll(id), .pending)
        for v in Self.bad {
            clock = v
            XCTAssertEqual(try broker.poll(id), .expired)
        }
    }

    // pre-fix: a NaN time was recorded (NaN < last is false) and +Infinity pruned every recorded event
    func testSlidingWindowCounterNeverForgetsOrRecordsANonFiniteTime() throws {
        let c = try PCAWallet.SlidingWindowCounter(windowMs: 1000)
        XCTAssertTrue(try c.tryAdd(10, 5))
        XCTAssertThrowsError(try c.tryAdd(.nan, 5))
        XCTAssertThrowsError(try c.tryAdd(-.infinity, 5))
        XCTAssertFalse(try c.tryAdd(.infinity, 5))
        XCTAssertEqual(c.count(.infinity), 1)
        XCTAssertEqual(c.count(10), 1)
    }

    // pre-fix: an infinite tolerance admitted any timestamp
    func testStripeWebhookRefusesAnInfiniteToleranceAndANonFiniteClock() {
        let body = "{\"a\":1}", secret = "whsec_test"
        let header = PCAPayments.signStripePayload(body, secret, 1000)
        XCTAssertTrue(PCAPayments.verifyStripeSignature(body, header, secret, nowSec: 1000, toleranceSec: 300))
        XCTAssertFalse(PCAPayments.verifyStripeSignature(body, header, secret, nowSec: 1000, toleranceSec: .infinity))
        for v in Self.bad { XCTAssertFalse(PCAPayments.verifyStripeSignature(body, header, secret, nowSec: v, toleranceSec: 300)) }
    }

    // pre-fix: a budget of +Infinity covered every cost
    func testAnInfiniteOrNaNBudgetCoversNothing() {
        XCTAssertTrue(Risk.covers(5, 1))
        for v in Self.bad { XCTAssertFalse(Risk.covers(v, 1)) }
    }

    // pre-fix: `now < granted || now >= granted + ttl` admitted NaN, and an infinite ttl never ended
    func testClassApprovalNeverCoversOnANonFiniteClockOrTtl() {
        let a = PCAApprovals.approveClass(["pay"], ttlMs: 1000, by: "p", now: 1000)
        XCTAssertTrue(PCAApprovals.classApprovalCovers(a, verb: "pay", resource: "r", now: 1500))
        for v in Self.bad { XCTAssertFalse(PCAApprovals.classApprovalCovers(a, verb: "pay", resource: "r", now: v)) }
        let forever = PCAApprovals.approveClass(["pay"], ttlMs: .infinity, by: "p", now: 1000)
        XCTAssertFalse(PCAApprovals.classApprovalCovers(forever, verb: "pay", resource: "r", now: 1500))
    }

    // pre-fix: a present-but-non-finite hint was skipped, so the envelope still permitted the call
    func testEnvelopePermitsRefusesNonFiniteHints() {
        func env(_ hints: JObject) -> JSONValue {
            .object(["ok": .bool(true), "unsatisfiable": .array([]), "scopes": .null, "remainingBudgetHints": .object(hints)])
        }
        XCTAssertTrue(AgentNative.envelopePermits(env(["expiresAt": .int(200)]), verb: "v", resource: "r", now: 100))
        for v in Self.bad {
            XCTAssertFalse(AgentNative.envelopePermits(env(["expiresAt": .double(v)]), verb: "v", resource: "r", now: 100))
            XCTAssertFalse(AgentNative.envelopePermits(env(["notBefore": .double(v)]), verb: "v", resource: "r", now: 100))
        }
        for v in [Double.nan, .infinity] {
            XCTAssertFalse(AgentNative.envelopePermits(env(["delegationDepthRemaining": .double(v)]), verb: "v", resource: "r"))
        }
    }

    // pre-fix: `amount > max` was false for NaN and -Infinity, so the amount sailed through the range
    func testAp2AmountRangeRefusesNonFiniteAmounts() throws {
        let open: JSONValue = .object(["constraints": .array([.object(["type": .string("payment.amount_range"), "currency": .string("USD"), "max": .int(1000)])])])
        func closed(_ amount: JSONValue) -> JSONValue { .object(["payment_amount": .object(["amount": amount, "currency": .string("USD")])]) }
        let ctx: JSONValue = .object(["now": .int(1)])
        XCTAssertEqual(try PCAAp2.checkPaymentConstraints(open, closed(.int(10)), ctx), [])
        for v in Self.bad { XCTAssertFalse(try PCAAp2.checkPaymentConstraints(open, closed(.double(v)), ctx).isEmpty) }
    }

    // pre-fix: a cumulative spend of -Infinity passed `spend <= cap`
    func testAp2BudgetRefusesANonFiniteSpend() throws {
        let open: JSONValue = .object(["constraints": .array([.object(["type": .string("payment.budget"), "currency": .string("USD"), "max": .int(10)])])])
        func closed(_ amount: JSONValue) -> JSONValue { .object(["payment_amount": .object(["amount": amount, "currency": .string("USD")])]) }
        let ctx: JSONValue = .object(["now": .int(1), "context": .object(["totalAmount": .int(0), "totalUses": .int(0)])])
        XCTAssertEqual(try PCAAp2.checkPaymentConstraints(open, closed(.int(10)), ctx), [])
        for v in Self.bad { XCTAssertFalse(try PCAAp2.checkPaymentConstraints(open, closed(.double(v)), ctx).isEmpty) }
    }

    // pre-fix: +Infinity was emitted as an expiry that reads as none; -Infinity read as "period ended"; NaN never ended
    func testSharedPaymentTokenLimitsRefuseANonFinitePeriodEnd() throws {
        let (m, _) = try RefPaymentsTests.mandate()
        func withEnd(_ pe: Double) -> JSONValue {
            var o = m.asObject ?? [:]
            var t = o["terms"]?.asObject ?? [:]
            t["periodEnd"] = .double(pe)
            o["terms"] = .object(t)
            return .object(o)
        }
        let now: JSONValue = .int(1_800_000_000_000)
        XCTAssertNoThrow(try PCAPayments.sharedPaymentTokenLimits(withEnd(1_900_000_000_000), now))
        for v in Self.bad {
            XCTAssertThrowsError(try PCAPayments.sharedPaymentTokenLimits(withEnd(v), now)) {
                XCTAssertEqual(($0 as? JSError)?.message, "sharedPaymentTokenLimits: periodEnd must be an epoch-ms time")
            }
        }
    }

    // pre-fix: a +Infinity or NaN cap admitted every amount; a -Infinity cap and a negative or -0 cap gave the "exceeds" reason
    func testAcpSpendCapMustBeANonNegativeSafeInteger() throws {
        func authority(_ cap: JSONValue?) -> JSONValue {
            var o: JObject = ["currency": .string("USD"), "merchants": .null, "categories": .null]
            if let c = cap { o["maxAmount"] = c }
            return .object(o)
        }
        let req: JSONValue = .object(["amount": .int(1), "currency": .string("USD"), "merchant": .string("m")])
        let reason = "authorized spend cap is not a non-negative integer (fail closed)"
        let caps: [JSONValue] = [.double(.nan), .double(.infinity), .double(-.infinity), .int(-1), .double(-0.0), .double(1.5), .null, .string("5")]
        for cap in caps {
            let r = try PCAAcp.checkPaymentAuthority(authority(cap), req)
            XCTAssertEqual(r.get("ok"), .bool(false))
            XCTAssertEqual(r.get("reason")?.asString, reason)
        }
        XCTAssertEqual(try PCAAcp.checkPaymentAuthority(authority(nil), req).get("ok"), .bool(true))
        XCTAssertEqual(try PCAAcp.checkPaymentAuthority(authority(.int(5)), req).get("ok"), .bool(true))
    }

    // pre-fix: an unknown frequency was a violation only when a last-used date existed
    func testAp2UnknownRecurrenceFrequencyIsAlwaysAViolation() throws {
        let rec: JSONValue = .object(["constraints": .array([.object(["type": .string("payment.agent_recurrence"), "frequency": .string("HOURLY")])])])
        let closed: JSONValue = .object(["payment_amount": .object(["amount": .int(10), "currency": .string("USD")])])
        let ctx: JSONValue = .object(["now": .int(1), "context": .object(["totalAmount": .int(0), "totalUses": .int(0)])])
        // the mandate also lacks the amount range and budget a recurrence requires, so those violations come too; the unknown frequency must be among them
        XCTAssertTrue(try PCAAp2.checkPaymentConstraints(rec, closed, ctx).contains("unknown recurrence frequency"))
    }

    // pre-fix: an infinite stored high-water mark made the clock infinite and the window read as finalized, which opens settlement
    func testBondChallengeStatusNeverFinalizesOnANonFiniteClock() throws {
        final class Stub: BondStore {
            let high: Double
            init(_ high: Double) { self.high = high }
            func read(_ claimId: String, _ depositor: String?) throws -> JSONValue {
                .object(["bond": .object(["claimId": .string(claimId), "window": .object(["registeredAt": .int(1000), "windowMs": .int(500)])]),
                         "balances": .array([]), "openTotals": .object(["count": .int(0), "sum": .int(0)]), "highWater": .double(high)])
            }
            func commit(_ plan: JSONValue, _ observedAt: JSONValue) throws -> JSONValue { throw PCAStoreError("store_unavailable", "stub") }
            func deposit(_ account: JSONValue, _ amount: JSONValue) throws -> Double { throw PCAStoreError("store_unavailable", "stub") }
        }
        let key: PCASuiteKey = .ed25519(try PCAEdKey(seed: [UInt8](repeating: 4, count: 32)))
        let ok = try StoreBondLedger(store: Stub(0), guardian: key, clock: { 1200 })
        XCTAssertEqual(try ok.challengeStatus("c").get("phase")?.asString, "open")
        // only +Infinity survives the max with the clock (NaN and -Infinity lose to it)
        XCTAssertThrowsError(try StoreBondLedger(store: Stub(.infinity), guardian: key, clock: { 1200 }).challengeStatus("c"))
        for v in Self.bad { XCTAssertThrowsError(try StoreBondLedger(store: Stub(0), guardian: key, clock: { v }).challengeStatus("c")) }
    }

    // pre-fix: a non-finite clock or window read as "finalized", which opens settlement
    func testClaimStatusRefusesNonFiniteClockOrWindow() {
        for v in Self.bad {
            XCTAssertThrowsError(try Optimistic.claimStatus(issuedAt: 100, windowMs: 50, now: v))
            XCTAssertThrowsError(try Optimistic.claimStatus(issuedAt: 100, windowMs: v, now: 120))
            XCTAssertThrowsError(try Optimistic.claimStatus(issuedAt: v, windowMs: 50, now: 120))
        }
        XCTAssertEqual(try Optimistic.claimStatus(issuedAt: 100, windowMs: 50, now: 120), "open")
    }
}
