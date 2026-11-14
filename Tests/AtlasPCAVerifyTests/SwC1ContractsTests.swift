import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Boundaries, defaults and clause transitions of the behavioural contract validator and monitor.
final class SwC1ContractsTests: XCTestCase {
    let NOW = 1_700_000_000_000.0

    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }
    func act(_ verb: String) -> JSONValue { .object(["action": .object(["verb": .string(verb), "resource": .string("/r")])]) }
    func contract(_ clauses: String, invariants: String = "") -> JSONValue {
        let inv = invariants.isEmpty ? "" : #","invariants":[\#(invariants)]"#
        return J(#"{"version":1,"principal":"p"\#(inv),"clauses":[\#(clauses)]}"#)
    }
    func nest(_ n: Int) -> JSONValue {
        var s = #"{"id":"leaf","kind":"never","p":{"verb":"x"}}"#
        for i in 0..<n { s = #"{"id":"a\#(i)","kind":"and","clauses":[\#(s)]}"# }
        return J(s)
    }
    let ORDER = #"{"id":"order","kind":"precedes","p":{"verb":"review"},"q":{"verb":"deploy"}}"#

    // ---- validation boundaries -------------------------------------------------------------------------------------------------

    func testClauseIdLengthBoundary() {
        let ok = String(repeating: "a", count: 128), long = String(repeating: "a", count: 129)
        XCTAssertEqual(Contracts.validateContract(contract(#"{"id":"\#(ok)","kind":"never","p":{"verb":"x"}}"#)), [])
        XCTAssertEqual(Contracts.validateContract(contract(#"{"id":"\#(long)","kind":"never","p":{"verb":"x"}}"#)), ["\(long): id too long"])
    }

    func testEachTriggerIsValidatedPerKind() {
        for kind in ["precedes", "requires_prior"] {
            XCTAssertEqual(Contracts.validateContract(contract(#"{"id":"c","kind":"\#(kind)","p":5,"q":{"verb":"x"}}"#)), ["c: p: not an object"], kind)
            XCTAssertEqual(Contracts.validateContract(contract(#"{"id":"c","kind":"\#(kind)","p":{"verb":"x"},"q":5}"#)), ["c: q: not an object"], kind)
            XCTAssertEqual(Contracts.validateContract(contract(#"{"id":"c","kind":"\#(kind)","p":{"verb":"x"},"q":{"verb":"y"}}"#)), [], kind)
        }
        let r = #""within":3"#
        XCTAssertEqual(Contracts.validateContract(contract(#"{"id":"c","kind":"responds_within","p":5,"q":{"verb":"x"},\#(r)}"#)), ["c: p: not an object"])
        XCTAssertEqual(Contracts.validateContract(contract(#"{"id":"c","kind":"responds_within","p":{"verb":"x"},"q":5,\#(r)}"#)), ["c: q: not an object"])
    }

    func testWithinUpperBoundIsInclusive() {
        func within(_ w: Int) -> [String] {
            Contracts.validateContract(contract(#"{"id":"c","kind":"responds_within","p":{"verb":"a"},"q":{"verb":"b"},"within":\#(w)}"#))
        }
        XCTAssertEqual(within(1), [])
        XCTAssertEqual(within(Prohibitions.MAX_DEADLINE), [])
        XCTAssertEqual(within(Prohibitions.MAX_DEADLINE + 1), ["c: within must be an integer in [1, MAX_DEADLINE]"])
        XCTAssertEqual(within(0), ["c: within must be an integer in [1, MAX_DEADLINE]"])
    }

    func testInvariantCountBoundaryAndProblemsAreReported() {
        func invs(_ n: Int) -> String { (0..<n).map { #"{"id":"i\#($0)","kind":"never","when":{"verb":"x"}}"# }.joined(separator: ",") }
        XCTAssertEqual(Contracts.validateContract(contract("", invariants: invs(Prohibitions.MAX_INVARIANTS))), [])
        XCTAssertEqual(Contracts.validateContract(contract("", invariants: invs(Prohibitions.MAX_INVARIANTS + 1))), ["too many invariants"])
        let bad = #"{"id":"bad","kind":"nope"}"#
        let expected = Prohibitions.validateInvariant(J(bad))
        XCTAssertFalse(expected.isEmpty)
        XCTAssertEqual(Contracts.validateContract(contract("", invariants: bad)), expected)
    }

    func testCountClausesNestingCap() {
        XCTAssertEqual(Contracts.countClauses([nest(0)]), 1)
        XCTAssertEqual(Contracts.countClauses([nest(2)]), 3)
        XCTAssertEqual(Contracts.countClauses([nest(16)]), 17)
        // 17 `and`s put the leaf's list at level 18, beyond MAX_CLAUSE_DEPTH + 1: that list counts as MAX_CLAUSES + 1 at once
        XCTAssertEqual(Contracts.countClauses([nest(17)]), 17 + Contracts.MAX_CLAUSES + 1)
        XCTAssertEqual(Contracts.countClauses([nest(17)], 1), 17 + Contracts.MAX_CLAUSES + 1)
        XCTAssertEqual(Contracts.countClauses([nest(16)], 2), 16 + Contracts.MAX_CLAUSES + 1)
    }

    // ---- clause transitions ----------------------------------------------------------------------------------------------------

    func ev(_ cl: String, _ ctx: JSONValue, state: JObject? = nil) -> ClauseTransition {
        Contracts.evalClause(J(cl).asObject ?? [:], ctx, state ?? (Prohibitions.emptyState(NOW).asObject ?? [:]), NOW, SafeRegex.Budget())
    }

    func testRespondsWithinOpensAnObligationOfTheWindow() throws {
        let noWithin = ev(#"{"id":"r","kind":"responds_within","p":{"verb":"alarm"},"q":{"verb":"ack"}}"#, act("alarm"))
        XCTAssertTrue(noWithin.ok)
        XCTAssertEqual(try XCTUnwrap(noWithin.deadlineSet[JKey("r")]), 0)
        let three = ev(#"{"id":"r","kind":"responds_within","p":{"verb":"alarm"},"q":{"verb":"ack"},"within":3}"#, act("alarm"))
        XCTAssertEqual(try XCTUnwrap(three.deadlineSet[JKey("r")]), 3)
        let idle = ev(#"{"id":"r","kind":"responds_within","p":{"verb":"alarm"},"q":{"verb":"ack"},"within":3}"#, act("other"))
        XCTAssertTrue(idle.ok)
        XCTAssertNil(idle.reason)
        XCTAssertNil(try XCTUnwrap(idle.deadlineSet[JKey("r")]))
    }

    func testRespondsWithinMissedDeadlineIsAViolation() {
        let cl = #"{"id":"r","kind":"responds_within","p":{"verb":"alarm"},"q":{"verb":"ack"},"within":2}"#
        let st: JObject = ["deadlines": .object(["r": .int(1)])]
        let t = ev(cl, act("other"), state: st)
        XCTAssertFalse(t.ok)
        XCTAssertEqual(t.reason, JSONValue.string("bounded-liveness deadline missed (no q within 2 actions of p)"))
        XCTAssertEqual(t.rows.count, 1)
        XCTAssertEqual(t.rows[0].get("result"), JSONValue.string("violated"))
        // a response in time discharges the obligation
        let answered = ev(cl, act("ack"), state: st)
        XCTAssertTrue(answered.ok)
        XCTAssertNil(answered.reason)
    }

    func testAndKeepsTheFirstFailureAndItsReason() {
        let both = #"{"id":"both","kind":"and","clauses":[{"id":"n1","kind":"never","p":{"verb":"delete"},"description":"first"},{"id":"n2","kind":"never","p":{"verb":"delete"},"description":"second"}]}"#
        let bad = ev(both, act("delete"))
        XCTAssertFalse(bad.ok)
        XCTAssertEqual(bad.reason, JSONValue.string("first"))
        XCTAssertEqual(bad.rows.count, 2)
        let good = ev(both, act("read"))
        XCTAssertTrue(good.ok)
        XCTAssertNil(good.reason)
        let second = ev(#"{"id":"both","kind":"and","clauses":[{"id":"n1","kind":"never","p":{"verb":"zap"},"description":"first"},{"id":"n2","kind":"never","p":{"verb":"delete"},"description":"second"}]}"#, act("delete"))
        XCTAssertFalse(second.ok)
        XCTAssertEqual(second.reason, JSONValue.string("second"))
    }

    func testUnknownClauseKindFailsClosed() {
        let t = ev(#"{"id":"u","kind":"zzz"}"#, act("read"))
        XCTAssertFalse(t.ok)
        XCTAssertEqual(t.reason, JSONValue.string("unknown clause kind (fail closed)"))
        XCTAssertEqual(t.rows[0].get("result"), JSONValue.string("violated"))
    }

    // ---- the monitor -----------------------------------------------------------------------------------------------------------

    func testResultDefaultsAreFalse() {
        let c = contract(ORDER)
        let s0 = Prohibitions.emptyState(NOW)
        for a in [act("review"), act("deploy")] {
            let r = Contracts.advanceContract(s0, a, c)
            XCTAssertFalse(r.allow)
            XCTAssertFalse(r.permitted)
        }
    }

    func testCheckAndAdvanceReportsPermittedAndOk() {
        let c = contract(ORDER)
        let s0 = Prohibitions.emptyState(NOW)
        let violating = Contracts.checkAndAdvanceContract(permitted: true, s0, act("deploy"), c)
        XCTAssertFalse(violating.ok)
        XCTAssertFalse(violating.allow)
        XCTAssertTrue(violating.permitted)
        let admitted = Contracts.checkAndAdvanceContract(permitted: true, s0, act("review"), c)
        XCTAssertTrue(admitted.ok)
        XCTAssertTrue(admitted.allow)
        XCTAssertTrue(admitted.permitted)
        let denied = Contracts.checkAndAdvanceContract(permitted: false, s0, act("review"), c)
        XCTAssertFalse(denied.ok)
        XCTAssertFalse(denied.allow)
        XCTAssertFalse(denied.permitted)
        XCTAssertEqual(denied.decidedBy, "contract")
    }

    func testClauseIdsWithOneAngleBracketAreContractViolationsNotStructural() {
        let s0 = Prohibitions.emptyState(NOW)
        for id in ["<a", "a>"] {
            let r = Contracts.advanceContract(s0, act("delete"), contract(#"{"id":"\#(id)","kind":"never","p":{"verb":"delete"}}"#))
            XCTAssertFalse(r.ok)
            XCTAssertEqual(r.violated, [id])
            XCTAssertEqual(r.decidedBy, "contract", id)
        }
    }

    func testStaleHeadOnAnUnreadableStateNamesStateOnce() {
        let r = Contracts.advanceContract(.null, act("review"), contract(ORDER), expectedSeq: 0)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.decidedBy, "state")
        XCTAssertEqual(r.violated, ["<state>"])
        XCTAssertEqual(r.reasons, ["<state>: malformed monitor state", "<state>: stale state head (seq)"])
    }

    func testAnOverlayThatOverflowsTheStateIsRefused() {
        var s = Prohibitions.emptyState(NOW).asObject ?? [:]
        var latched: JObject = [:]
        for i in 0..<Prohibitions.MAX_STATE_KEYS { latched[JKey("k\(i)")] = .int(1_700_000_000_000) }
        s["latched"] = .object(latched)
        let state: JSONValue = .object(s)
        XCTAssertNil(Prohibitions.stateProblem(state))
        // the `order` latch would be the 1025th key
        let r = Contracts.advanceContract(state, act("review"), contract(ORDER))
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.decidedBy, "state")
        XCTAssertEqual(r.reasons.last, "<state>: resulting state invalid: malformed monitor state: too many keys")
        XCTAssertEqual(r.next, state)
    }
}
