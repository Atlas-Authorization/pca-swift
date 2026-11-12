import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Behavioural contracts and the durable enforcer (translated from contracts.test.ts, contracts-enforcer.test.ts and
/// contracts-fail-closed-table.test.ts), including concurrent tasks on one store.
final class K05GContractsTests: XCTestCase {
    let key = try! PCAEdKey(seed: [UInt8](repeating: 1, count: 32))
    let otherKey = try! PCAEdKey(seed: [UInt8](repeating: 9, count: 32))
    let NOW = 1_700_000_000_000.0
    var PRIN: String { key.id }

    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }
    func act(_ verb: String, _ res: String = "/r", _ params: String? = nil) -> JSONValue {
        var a: JObject = ["verb": .string(verb), "resource": .string(res)]
        if let p = params { a["params"] = J(p) }
        return .object(["action": .object(a)])
    }
    func contract(_ clauses: String, invariants: String? = nil) -> JSONValue {
        let inv = invariants.map { #","invariants":[\#($0)]"# } ?? ""
        return J(#"{"version":1,"principal":"\#(PRIN)"\#(inv),"clauses":[\#(clauses)]}"#)
    }
    func signed(_ clauses: String, invariants: String? = nil) throws -> JSONValue { try Contracts.signContract(contract(clauses, invariants: invariants), principal: key) }
    func with(_ s: JSONValue, _ k: String, _ v: JSONValue) -> JSONValue {
        guard case var .object(o) = s else { return s }
        o[JKey(k)] = v
        return .object(o)
    }

    let NEVER_DELETE = #"{"id":"no-delete","kind":"never","p":{"verb":"delete"}}"#
    let ORDER = #"{"id":"order","kind":"precedes","p":{"verb":"review"},"q":{"verb":"deploy"}}"#
    let ACK = #"{"id":"ack","kind":"responds_within","p":{"verb":"alarm"},"q":{"verb":"ack"},"within":2}"#

    func advance(_ s: JSONValue, _ a: JSONValue, _ c: JSONValue, now: Double? = nil) -> AdvanceContractResult { Contracts.advanceContract(s, a, c, now: now) }

    func testValidateExactProblems() {
        let V = Contracts.validateContract
        XCTAssertEqual(V(nil), ["contract not an object"])
        XCTAssertEqual(V(J(#"{"version":2,"principal":""}"#)), ["unsupported version 2", "principal missing"])
        XCTAssertEqual(V(J(#"{"principal":"p"}"#)), ["unsupported version undefined"])
        XCTAssertEqual(V(J(#"{"version":1,"principal":"p","clauses":5}"#)), ["clauses not an array"])
        XCTAssertEqual(V(J(#"{"version":1,"principal":"p","invariants":5}"#)), ["invariants not an array"])
        XCTAssertEqual(V(contract("\(NEVER_DELETE),\(NEVER_DELETE)")), ["no-delete: duplicate id"])
        // a clause id may not collide with an embedded invariant id (shared state keys)
        XCTAssertEqual(V(contract(NEVER_DELETE, invariants: #"{"id":"no-delete","kind":"never","when":{"verb":"x"}}"#)), ["no-delete: duplicate id"])
        XCTAssertEqual(V(contract(#"{"id":"z","kind":"eventually","p":{"verb":"x"}}"#)), ["z: unknown clause kind eventually"])
        XCTAssertEqual(V(contract(#"{"id":"r","kind":"responds_within","p":{"verb":"a"},"q":{"verb":"b"},"within":0}"#)), ["r: within must be an integer in [1, MAX_DEADLINE]"])
        XCTAssertEqual(V(contract(#"{"id":"r","kind":"and","clauses":[]}"#)), ["r: and.clauses must be a non-empty array"])
        XCTAssertEqual(V(contract(#"{"id":"r","kind":"never"}"#)), ["r: p: not an object"])
        XCTAssertEqual(V(contract(#"{"kind":"never","p":{"verb":"x"}}"#)), ["<no id>: missing clause id"])
        XCTAssertEqual(V(contract(#"{"id":"__proto__","kind":"never","p":{"verb":"x"}}"#)), ["__proto__: forbidden id"])
    }

    func testClauseBoundsAndNesting() {
        func nest(_ depth: Int) -> String {
            var s = #"{"id":"leaf","kind":"never","p":{"verb":"x"}}"#
            for i in 0..<depth { s = #"{"id":"a\#(i)","kind":"and","clauses":[\#(s)]}"# }
            return s
        }
        XCTAssertEqual(Contracts.validateContract(contract(nest(14))), []) // 15 levels
        XCTAssertEqual(Contracts.validateContract(contract(nest(15))), []) // 16 levels
        XCTAssertEqual(Contracts.validateContract(contract(nest(16))), ["clause nesting too deep"])
        let many = (0..<256).map { #"{"id":"c\#($0)","kind":"never","p":{"verb":"x"}}"# }
        XCTAssertEqual(Contracts.validateContract(contract(many.joined(separator: ","))), [])
        XCTAssertEqual(Contracts.validateContract(contract((many + [#"{"id":"c256","kind":"never","p":{"verb":"x"}}"#]).joined(separator: ","))), ["too many clauses"])
    }

    func testSignVerify() throws {
        let sc = try signed(ORDER)
        XCTAssertEqual(Contracts.verifyContract(sc, expectedPrincipal: PRIN), .pass)
        XCTAssertEqual(Contracts.verifyContract(sc, expectedPrincipal: otherKey.id), .no("principal mismatch"))
        XCTAssertEqual(Contracts.verifyContract(with(sc, "clauses", J("[\(NEVER_DELETE)]"))), .no("id does not match content"))
        XCTAssertEqual(Contracts.verifyContract(with(sc, "sig", .string("AAAA"))), .no("bad signature"))
        XCTAssertEqual(Contracts.verifyContract(contract(ORDER)), .no("id does not match content"))
        XCTAssertThrowsError(try Contracts.signContract(contract(#"{"id":"r","kind":"never"}"#), principal: key))
        XCTAssertEqual(try Contracts.contractId(sc), sc.get("id")?.asString)
    }

    func testNeverAndAlways() {
        let c = contract(NEVER_DELETE)
        let r = Contracts.checkContract(act("delete"), c, Prohibitions.emptyState(NOW))
        XCTAssertEqual(r.violated, ["no-delete"])
        XCTAssertEqual(r.reasons, ["no-delete: never-invariant violated (forbidden action)"])
        XCTAssertTrue(Contracts.checkContract(act("read"), c, Prohibitions.emptyState(NOW)).ok)
        let always = contract(#"{"id":"only-read","kind":"always","p":{"verb":"read"},"description":"read only"}"#)
        XCTAssertTrue(Contracts.checkContract(act("read"), always, Prohibitions.emptyState(NOW)).ok)
        XCTAssertEqual(Contracts.checkContract(act("write"), always, Prohibitions.emptyState(NOW)).reasons, ["only-read: read only"])
    }

    func testPrecedesAndRequiresPrior() {
        let c = contract(ORDER)
        var s = Prohibitions.emptyState(NOW)
        var r = advance(s, act("deploy"), c)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.decidedBy, "contract")
        XCTAssertEqual(r.reasons, ["order: precedence violated (prerequisite p not yet admitted before q)"])
        XCTAssertEqual(r.next, s) // a refusal never advances
        r = advance(s, act("review"), c)
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.next.get("latched")?.asObject?.keys.map { $0.s }, ["order"])
        s = r.next
        XCTAssertTrue(advance(s, act("deploy"), c).ok)
        let rp = contract(#"{"id":"rp","kind":"requires_prior","q":{"verb":"deploy"},"p":{"verb":"review"}}"#)
        XCTAssertFalse(advance(Prohibitions.emptyState(NOW), act("deploy"), rp).ok)
    }

    func testRespondsWithin() {
        let c = contract(ACK)
        var s = Prohibitions.emptyState(NOW)
        var r = advance(s, act("alarm"), c)
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.next.get("deadlines"), .object(["ack": .int(2)]))
        s = r.next
        r = advance(s, act("other"), c)
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.next.get("deadlines"), .object(["ack": .int(1)]))
        let late = advance(r.next, act("other"), c)
        XCTAssertFalse(late.ok)
        XCTAssertEqual(late.violated, ["ack"])
        XCTAssertEqual(late.reasons, ["ack: bounded-liveness deadline missed (no q within 2 actions of p)"])
        let answered = advance(r.next, act("ack"), c)
        XCTAssertTrue(answered.ok)
        XCTAssertNil(answered.next.get("deadlines")) // discharged: an empty map is omitted
        // an ambiguous response (a q whose where cannot be decided) does not discharge
        let amb = contract(#"{"id":"w","kind":"responds_within","p":{"verb":"alarm"},"q":{"verb":"ack","where":[{"field":"action.params.ok","op":"eq","value":true}]},"within":1}"#)
        let opened = advance(Prohibitions.emptyState(NOW), act("alarm"), amb).next
        XCTAssertFalse(advance(opened, act("ack"), amb).ok)
    }

    func testAnd() {
        let c = contract(#"{"id":"both","kind":"and","clauses":[{"id":"n","kind":"never","p":{"verb":"delete"}},{"id":"o","kind":"precedes","p":{"verb":"review"},"q":{"verb":"deploy"}}]}"#)
        let r = Contracts.checkContract(act("delete"), c, Prohibitions.emptyState(NOW))
        XCTAssertEqual(r.violated, ["n"])
        XCTAssertEqual(r.evaluated.compactMap { $0.get("id")?.asString }, ["n", "o"]) // the `and` itself emits no row
    }

    func testDegenerateContractIsTheProhibitionMonitor() {
        let inv = #"{"id":"spend","kind":"cap","when":{"verb":"pay"},"amount":"action.params.usd","max":100,"window_secs":60}"#
        let c = J(#"{"version":1,"principal":"\#(PRIN)","invariants":[\#(inv)],"clauses":[]}"#)
        let k = J(#"{"version":1,"principal":"\#(PRIN)","invariants":[\#(inv)]}"#)
        let a = act("pay", "/v", #"{"usd":60}"#)
        let viaContract = advance(Prohibitions.emptyState(NOW), a, c)
        let viaMonitor = Prohibitions.advanceStateStrict(a, k, Prohibitions.emptyState(NOW))
        XCTAssertEqual(try Prohibitions.stateDigest(viaContract.next), try Prohibitions.stateDigest(viaMonitor.state))
        XCTAssertNil(contract(NEVER_DELETE).get("invariants"))
    }

    func testStaleForgedAndRolledBackState() throws {
        let c = contract(ORDER)
        let s0 = Prohibitions.emptyState(NOW)
        let s1 = advance(s0, act("review"), c).next
        XCTAssertEqual(Contracts.advanceContract(s1, act("deploy"), c, expectedSeq: 0).reasons.last, "<state>: stale state head (seq)")
        XCTAssertEqual(Contracts.advanceContract(s1, act("deploy"), c, expectedStateDigest: try Prohibitions.stateDigest(s0)).reasons.last, "<state>: stale state head (digest)")
        XCTAssertTrue(Contracts.advanceContract(s1, act("deploy"), c, expectedSeq: 1, expectedStateDigest: try Prohibitions.stateDigest(s1)).ok)
        let forged = with(s1, "seq", .int(5)) // seq > 0 with a parent still present but a ledger entry in the future is refused
        XCTAssertTrue(Contracts.advanceContract(with(forged, "parent", .null), act("deploy"), c).decidedBy == "state")
        let back = Contracts.advanceContract(s1, act("deploy"), c, now: NOW - 1)
        XCTAssertFalse(back.ok)
        XCTAssertEqual(back.decidedBy, "state")
    }

    func testCheckAndAdvanceContract() {
        let c = contract(ORDER)
        let s0 = Prohibitions.emptyState(NOW)
        let denied = Contracts.checkAndAdvanceContract(permitted: false, s0, act("review"), c)
        XCTAssertFalse(denied.allow)
        XCTAssertEqual(denied.reasons.last, "<permission>: not permitted")
        XCTAssertEqual(denied.next, s0)
        let ok = Contracts.checkAndAdvanceContract(permitted: true, s0, act("review"), c)
        XCTAssertTrue(ok.allow)
        XCTAssertEqual(ok.next.get("seq"), .int(1))
    }

    func testTotality() {
        for bad in [JSONValue.null, .int(3), .string("x"), .array([]), .object([:])] {
            XCTAssertFalse(Contracts.checkContract(bad, bad, bad).ok)
            XCTAssertFalse(Contracts.advanceContract(bad, bad, bad).ok)
            XCTAssertFalse(Contracts.verifyContract(bad).ok)
        }
        XCTAssertEqual(Contracts.checkContract(act("x"), contract(ORDER), .null).violated, ["<state>"])
        XCTAssertEqual(Contracts.checkContract(.null, contract(ORDER), Prohibitions.emptyState(NOW)).violated, ["<action>"])
    }

    // ---- the enforcer -------------------------------------------------------------------------------------------------------------

    final class Clock: @unchecked Sendable { var t: Double; init(_ t: Double) { self.t = t } }
    final class FailingKV: AtomicKV, @unchecked Sendable {
        struct Boom: Error {}
        func get(_ key: String) throws -> JSONValue? { throw Boom() }
        func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws { throw Boom() }
    }

    func enforcer(_ clauses: String, kv: AtomicKV = MemoryAtomicKV(), clock: Clock? = nil, latch: Bool = true) throws -> (ContractEnforcer, JSONValue, Clock) {
        let sc = try signed(clauses)
        let ck = clock ?? Clock(NOW)
        return (try ContractEnforcer.open(kv: kv, contract: sc, principal: PRIN, now: { ck.t }, latchOnViolation: latch), sc, ck)
    }

    func testEnforcerOpenPinsThePrincipal() throws {
        let sc = try signed(ORDER)
        XCTAssertThrowsError(try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: sc, principal: ""))
        XCTAssertThrowsError(try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: sc, principal: otherKey.id)) { e in
            XCTAssertEqual("\(e)", "ContractEnforcer: contract refused: principal mismatch")
        }
        XCTAssertThrowsError(try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: contract(ORDER), principal: PRIN))
    }

    func testEnforcerCheckOutcomesAndLatch() throws {
        let (e, sc, _) = try enforcer("\(NEVER_DELETE),\(ORDER)")
        XCTAssertEqual(e.check(act("deploy")).reason, "violated")
        // a violation latched the enforcer: every later action is refused, even a good one
        let l = e.check(act("review"))
        XCTAssertEqual(l.reason, "latched")
        XCTAssertEqual(l.violated, ["order"])
        XCTAssertEqual(l.reasons, ["<latched>: contract violated at seq 0"])
        XCTAssertEqual(e.peek(act("review")).reason, "latched")
        XCTAssertEqual(try e.state()?.latched, true)
        let id = try XCTUnwrap(sc.get("id")?.asString)
        XCTAssertFalse(e.reset(try ContractEnforcer.signContractReset(principal: otherKey, contractId: id, seq: 0)))
        XCTAssertFalse(e.reset(try ContractEnforcer.signContractReset(principal: key, contractId: id, seq: 1))) // bound to the latched sequence
        XCTAssertFalse(e.reset("garbage"))
        XCTAssertTrue(e.reset(try ContractEnforcer.signContractReset(principal: key, contractId: id, seq: 0)))
        XCTAssertFalse(e.reset(try ContractEnforcer.signContractReset(principal: key, contractId: id, seq: 0))) // nothing latched any more
        let ok = e.check(act("review"))
        XCTAssertTrue(ok.allow)
        XCTAssertEqual(ok.seq, 1)
        XCTAssertEqual(e.check(act("deploy"), permitted: false).reason, "permission") // a plain refusal does not latch
        XCTAssertTrue(e.check(act("deploy")).allow)
    }

    func testEnforcerWithoutLatchJustDenies() throws {
        let (e, _, _) = try enforcer(NEVER_DELETE, latch: false)
        XCTAssertEqual(e.check(act("delete")).reason, "violated")
        XCTAssertTrue(e.check(act("read")).allow)
    }

    func testEnforcerFailClosed() throws {
        let (e, _, _) = try enforcer(ORDER, kv: FailingKV())
        let r = e.check(act("review"))
        XCTAssertEqual(r, EnforceResult(allow: false, reason: "store-error", violated: [], reasons: ["store error (fail closed)"], seq: 0))
        XCTAssertEqual(e.peek(act("review")).reason, "store-error")
        XCTAssertFalse(e.reset("x"))
        XCTAssertThrowsError(try e.state())
        // a corrupt or foreign document denies and is never overwritten
        let kv = MemoryAtomicKV()
        let (e2, sc, _) = try enforcer(ORDER, kv: kv)
        let foreign: JSONValue = J(#"{"v":1,"contract_id":"someone-else","state":{"now":1,"seq":0,"parent":null,"ledger":{},"latched":{}}}"#)
        kv.update("contract/" + (sc.get("id")?.asString ?? "")) { _ in foreign }
        XCTAssertEqual(e2.check(act("review")).reason, "state-error")
        XCTAssertEqual(e2.peek(act("review")).reason, "state-error")
        XCTAssertEqual(try? kv.get("contract/" + (sc.get("id")?.asString ?? "")), foreign)
        XCTAssertThrowsError(try e2.state())
    }

    func testEnforcerLatchedSeqMustBeAnIntegerAndClockNeverGoesBack() throws {
        let kv = MemoryAtomicKV()
        let (e, sc, clock) = try enforcer(ORDER, kv: kv)
        let id = try XCTUnwrap(sc.get("id")?.asString)
        XCTAssertTrue(e.check(act("review")).allow)
        clock.t = NOW - 5000 // the wall clock went back: the state clock does not
        XCTAssertTrue(e.check(act("deploy")).allow)
        XCTAssertEqual(try e.state()?.state.get("now"), PD.num(NOW))
        clock.t = .nan
        let r = e.check(act("deploy"))
        XCTAssertEqual(r.reason, "state-error")
        XCTAssertEqual(r.reasons, ["<state>: clock is not finite"])
        // a latched document whose seq is not an integer is corrupt
        let key = "contract/\(id)"
        kv.update(key) { prev in
            guard case var .object(o)? = prev else { return nil }
            o["latched"] = .object(["seq": .double(1.5), "violated": .array([])])
            return .object(o)
        }
        clock.t = NOW
        XCTAssertEqual(e.check(act("deploy")).reason, "state-error")
    }

    func testPeekIsReadOnly() throws {
        let kv = MemoryAtomicKV()
        let (e, _, _) = try enforcer(NEVER_DELETE, kv: kv)
        XCTAssertEqual(e.peek(act("delete")).reason, "violated")
        XCTAssertTrue(e.peek(act("read")).allow)
        XCTAssertNil(try e.state()) // nothing was written
        XCTAssertTrue(e.check(act("read")).allow)
        XCTAssertEqual(e.peek(act("read")).seq, 1)
    }

    func testTwoEnforcersOnOneStoreSerialise() throws {
        let kv = MemoryAtomicKV()
        let (a, sc, ck) = try enforcer(ORDER, kv: kv)
        let b = try ContractEnforcer.open(kv: kv, contract: sc, principal: PRIN, now: { ck.t })
        XCTAssertEqual(a.check(act("read")).seq, 1)
        XCTAssertEqual(b.check(act("read")).seq, 2)
        XCTAssertEqual(a.check(act("read")).seq, 3)
    }

    func testConcurrentTasksOnOneStoreEachGetADistinctSequence() async throws {
        let kv = MemoryAtomicKV()
        let (e, _, _) = try enforcer(NEVER_DELETE, kv: kv)
        let n = 64
        let action = act("read")
        let seqs: [Int] = await withTaskGroup(of: Int.self) { group in
            for _ in 0..<n { group.addTask { e.check(action).seq } }
            var out: [Int] = []
            for await s in group { out.append(s) }
            return out
        }
        XCTAssertEqual(seqs.sorted(), Array(1...n))
        XCTAssertEqual(try e.state()?.state.get("seq"), .int(Int64(n)))
    }

    func testNonAsciiIdsAndTextsRoundTrip() throws {
        let c = #"{"id":"\u00e9t\u00e9","kind":"never","p":{"verb":"d\u00e9truire"},"description":"interdit \u2014 nope"}"#
        let (e, _, _) = try enforcer(c)
        let r = e.check(act("d\u{e9}truire"))
        XCTAssertEqual(r.violated, ["\u{e9}t\u{e9}"])
        XCTAssertEqual(r.reasons, ["\u{e9}t\u{e9}: interdit \u{2014} nope"])
    }
}
