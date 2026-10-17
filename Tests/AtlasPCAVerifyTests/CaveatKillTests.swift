import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Boundary / fail-closed pins for `PCA.evaluateCaveats` (Caveats.swift), each mirroring the TypeScript reference
/// (`envelopeCaveatEvaluator` in packages/pca/src/predicates.ts, `maxSpendSatisfied` in agent-native.ts). Every case asserts
/// the exact `(ok, failed)` pair so a flipped comparison or a fail-open guard is observable.
final class CaveatKillTests: XCTestCase {
    private func o(_ d: [String: JSONValue]) -> JSONValue { .object(JObject(uniqueKeysWithValues: d.map { (JKey($0.key), $0.value) })) }
    private let now: Int64 = 1_800_000_000_000

    private func ev(_ caveat: JSONValue, _ ctx: JSONValue) -> (Bool, [String]) {
        let r = PCA.evaluateCaveats(.array([caveat]), context: ctx)
        return (r.ok, r.failed)
    }
    private func ctx(_ extra: [String: JSONValue] = [:]) -> JSONValue {
        var d: [String: JSONValue] = ["now": .int(now)]
        for (k, v) in extra { d[k] = v }
        return o(d)
    }

    // expires {at}: now < at; a missing / non-finite `at` is unsatisfied (TS: fin(caveat.at) && now < at).
    func testExpiresMissingAtFailsClosed() {
        XCTAssert(ev(o(["type": .string("expires")]), ctx()) == (false, ["expires"]))
        XCTAssert(ev(o(["type": .string("expires"), "at": .string("9999999999999")]), ctx()) == (false, ["expires"]))
        XCTAssert(ev(o(["type": .string("expires"), "at": .int(now + 1)]), ctx()) == (true, []))
        XCTAssert(ev(o(["type": .string("expires"), "at": .int(now)]), ctx()) == (false, ["expires"]))
    }

    // not_before {at}: now >= at; a missing `at` is unsatisfied.
    func testNotBeforeMissingAtFailsClosed() {
        XCTAssert(ev(o(["type": .string("not_before")]), ctx()) == (false, ["not_before"]))
        XCTAssert(ev(o(["type": .string("not_before"), "at": .bool(true)]), ctx()) == (false, ["not_before"]))
        XCTAssert(ev(o(["type": .string("not_before"), "at": .int(now)]), ctx()) == (true, []))
        XCTAssert(ev(o(["type": .string("not_before"), "at": .int(now + 1)]), ctx()) == (false, ["not_before"]))
    }

    // delegation_depth {max}: depth <= max; a missing max OR a missing ctx depth is unsatisfied.
    func testDelegationDepthMissingFieldsFailClosed() {
        let dd = { (m: JSONValue?) -> JSONValue in
            var d: [String: JSONValue] = ["type": .string("delegation_depth")]
            if let m = m { d["max"] = m }
            return self.o(d)
        }
        XCTAssert(ev(dd(nil), ctx(["delegation_depth": .int(0)])) == (false, ["delegation_depth"]))
        XCTAssert(ev(dd(.int(3)), ctx()) == (false, ["delegation_depth"]))
        XCTAssert(ev(dd(.int(3)), ctx(["delegation_depth": .int(3)])) == (true, []))
        XCTAssert(ev(dd(.int(3)), ctx(["delegation_depth": .int(4)])) == (false, ["delegation_depth"]))
    }

    // budget_alloc {limit}: satisfied iff limit is finite and >= 0 (0 and fractional limits included).
    func testBudgetAllocBoundaries() {
        let ba = { (l: JSONValue?) -> JSONValue in
            var d: [String: JSONValue] = ["type": .string("budget_alloc")]
            if let l = l { d["limit"] = l }
            return self.o(d)
        }
        XCTAssert(ev(ba(nil), ctx()) == (false, ["budget_alloc"]))
        XCTAssert(ev(ba(.string("1")), ctx()) == (false, ["budget_alloc"]))
        XCTAssert(ev(ba(.int(0)), ctx()) == (true, []), "limit 0 is a valid (empty) allocation")
        XCTAssert(ev(ba(.double(0.5)), ctx()) == (true, []))
        XCTAssert(ev(ba(.int(1)), ctx()) == (true, []))
        XCTAssert(ev(ba(.double(-0.5)), ctx()) == (false, ["budget_alloc"]))
    }

    // max_spend {usd}: a zero limit admits a zero spend (TS: fin(lim) && spend <= lim).
    func testMaxSpendZeroLimitAdmitsZeroSpend() {
        let ms = o(["type": .string("max_spend"), "usd": .int(0)])
        let spend = { (a: JSONValue) in self.o(["action": self.o(["params": self.o(["amount": a])])]) }
        XCTAssert(ev(ms, spend(.int(0))) == (true, []))
        XCTAssert(ev(ms, spend(.double(0.01))) == (false, ["max_spend"]))
        XCTAssert(ev(o(["type": .string("max_spend"), "usd": .double(-1)]), spend(.int(0))) == (false, ["max_spend"]))
    }

    // reversibility_max {class}: a class equal to the limit is allowed (cur <= lim).
    func testReversibilityMaxEqualClassAllowed() {
        for (i, cls) in ["reversible", "rate_limited", "irreversible"].enumerated() {
            let cv = o(["type": .string("reversibility_max"), "class": .string(cls)])
            XCTAssert(ev(cv, ctx(["reversibility_class": .string(cls)])) == (true, []), cls)
            if i > 0 {
                let less = ["reversible", "rate_limited", "irreversible"][i - 1]
                XCTAssert(ev(o(["type": .string("reversibility_max"), "class": .string(less)]),
                             ctx(["reversibility_class": .string(cls)])) == (false, ["reversibility_max"]), cls)
            }
        }
    }

    // rate {max, per_secs}: per_secs must be > 0 (0 refused, fractional accepted); the window is (now - per_secs*1000, now].
    func testRatePerSecsAndWindowBoundaries() {
        let rate = { (max: JSONValue, per: JSONValue) in self.o(["type": .string("rate"), "max": max, "per_secs": per]) }
        let times = { (ts: [Int64]) in self.ctx(["recent_action_times": .array(ts.map { .int($0) })]) }
        // per_secs 0 is malformed even though the (empty) window would count nothing
        XCTAssert(ev(rate(.int(5), .int(0)), times([])) == (false, ["rate"]))
        XCTAssert(ev(rate(.int(5), .double(-1)), times([])) == (false, ["rate"]))
        // a fractional per_secs in (0, 1] is valid
        XCTAssert(ev(rate(.int(1), .double(0.5)), times([])) == (true, []))
        XCTAssert(ev(rate(.int(1), .int(1)), times([])) == (true, []))
        XCTAssert(ev(rate(.int(1), .double(0.5)), times([now - 100])) == (false, ["rate"]))
        // an action exactly at `now` is inside the window (t <= now)
        XCTAssert(ev(rate(.int(1), .int(60)), times([now])) == (false, ["rate"]))
        XCTAssert(ev(rate(.int(2), .int(60)), times([now])) == (true, []))
        // a time in the future or exactly at the lower bound is outside it
        XCTAssert(ev(rate(.int(1), .int(60)), times([now + 1])) == (true, []))
        XCTAssert(ev(rate(.int(1), .int(60)), times([now - 60_000])) == (true, []))
        XCTAssert(ev(rate(.int(1), .int(60)), times([now - 59_999])) == (false, ["rate"]))
    }
}
