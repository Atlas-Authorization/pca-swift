import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The undo-window coordinator: admission, the durable record, the one-click veto, the compensation at most once, finalization, the budget release (no evidence
/// unless the caller supplies it) and every fail-closed refusal. Hand-written: no shared corpus exists for the coordinator in any language.
final class UndoCoordinatorTests: XCTestCase {
    final class Box<T> { var v: T; init(_ v: T) { self.v = v } }

    static func edKey(_ b: UInt8) throws -> PCAEdKey { try PCAEdKey(seed: [UInt8](repeating: b, count: 32)) }
    static let D43 = String(repeating: "A", count: 43)

    func grant() throws -> JSONValue {
        let env: JObject = ["predicates": .array([.object(["verb": .string("pay"), "resource": .string("invoice:*")]), .object(["verb": .string("pay.refund"), "resource": .string("invoice:*")])]),
                            "caveats": .array([]), "risk_policy": .object(PCAFacade.DEFAULT_RISK_POLICY)]
        return try PCAIssue.mintGrant(principal: .ed25519(try Self.edKey(1)), holder: try Self.edKey(2).id, envelope: env, goal: "pay invoices", salt: "s").grant
    }

    let op: JSONValue = .object(["verb": .string("pay"), "resource": .string("invoice:1"), "params": .object(["amount": .int(5)])])

    func action(_ g: JSONValue, _ cls: String? = nil) throws -> JSONValue {
        let a = try PCAAgent(signer: .ed25519(try Self.edKey(2)), aud: "rs", grant: g)
        a.clock = { 1_000 }
        // the signed class is a member of the plan node's action (a top-level extra would be a stray member the admission never reads)
        var node: JObject = ["id": .string("n1"), "verb": .string("pay"), "resource": .string("invoice:1"), "params_digest": .string(Merkle.paramsDigest(.object(["amount": .int(5)])))]
        if let c = cls { node["reversibility_class"] = .string(c) }
        try a.commitPlan([node])
        return try a.actNode("n1", params: .object(["amount": .int(5)]))
    }

    func plan(_ verb: String = "pay.refund", target: Bool = true) -> JSONValue {
        var c: JObject = ["verb": .string(verb), "params": .object([:]), "def_digest": .string(Self.D43)]
        if target { c["target_param"] = .string("payment") }
        return .object(["def_digest": .string(Self.D43), "compensation": .object(c)])
    }

    struct Rig {
        let c: PCAUndoCoordinator
        let calls: Box<[JSONValue]>
        let alerts: Box<[JSONValue]>
        let notices: Box<[JSONValue]>
        let ops: MemoryOperationStore
    }

    func build(_ g: JSONValue, _ clock: Box<Double>, deliver: Bool = true, store: UndoStore? = nil, engine: ((JSONValue, String) throws -> JSONValue?)? = nil,
               policy: ((JSONValue, JSONValue) throws -> JSONValue?)? = nil, budget: PCAUndoBudget? = nil, bonds: UndoBondLedger? = nil) throws -> Rig {
        let calls = Box<[JSONValue]>([]), alerts = Box<[JSONValue]>([]), notices = Box<[JSONValue]>([])
        let ops = MemoryOperationStore()
        var o = PCAUndoOptions(store: store ?? MemoryUndoStore(), engine: engine ?? { _, _ in self.plan() }, signerSecret: [UInt8](repeating: 9, count: 32), audience: "rs",
                               resolveGrant: { _, _ in g }, compensate: { call in calls.v.append(call); return .object(["refund": .string("r1")]) }, operations: ops,
                               notifier: { n in notices.v.append(n); return deliver ? .object(["delivered": .bool(true)]) : .object(["delivered": .bool(false), "reason": .string("no channel")]) },
                               alert: { a in alerts.v.append(a) })
        o.policy = policy
        o.budget = budget
        o.bonds = bonds
        o.now = { clock.v }
        o.insecureVolatileStore = true
        return Rig(c: try PCAUndoCoordinator.create(o), calls: calls, alerts: alerts, notices: notices, ops: ops)
    }

    func ok(_ v: JSONValue) -> Bool { v.get("ok") == .bool(true) }

    func testVetoWithTheTokenCompensatesOnce() throws {
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock)
        let adm = r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g)
        XCTAssertNil(adm.get("refused"), "\(adm)")
        let info = try r.c.open(adm)
        let id = adm.get("id")?.asString ?? ""
        XCTAssertEqual(info.get("obligation")?.get("kind")?.asString, "undo_window")
        XCTAssertEqual(try r.c.get(id)?.get("state")?.asString, "open")
        _ = try r.c.recordEffect(id, result: .object(["id": .string("pay_1")]))
        clock.v = 2_000
        let v = r.c.veto(id, token: info.get("token"))
        XCTAssertTrue(ok(v), "\(v)")
        XCTAssertEqual(v.get("record")?.get("state")?.asString, "compensated")
        XCTAssertEqual(v.get("replayed"), .bool(false))
        XCTAssertEqual(r.calls.v.map { $0.get("operation")?.get("params") }, [.object(["payment": .string("pay_1")])])
        let again = r.c.veto(id, token: info.get("token")) // the same veto is a replay: the compensation never runs twice
        XCTAssertTrue(ok(again))
        XCTAssertEqual(again.get("replayed"), .bool(true))
        XCTAssertEqual(r.calls.v.count, 1)
        XCTAssertTrue(r.alerts.v.isEmpty)
    }

    func testATokenForAnotherRecordOrAfterTheWindowIsRefused() throws {
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock)
        let adm = r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g)
        let info = try r.c.open(adm)
        let id = adm.get("id")?.asString ?? ""
        XCTAssertFalse(ok(r.c.veto(id, token: .string("not a token"))))
        clock.v = Double(adm.get("window_end")?.safeInt ?? 0) + 1
        XCTAssertFalse(ok(r.c.veto(id, token: info.get("token"))))
        XCTAssertTrue(r.calls.v.isEmpty)
    }

    func testFinalizeClosesTheWindowAndAlertsAnUnreportedEffect() throws {
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock)
        let adm = r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g)
        _ = try r.c.open(adm)
        let id = adm.get("id")?.asString ?? ""
        XCTAssertEqual(try r.c.finalizeDue(), []) // the window is still open
        clock.v = Double(adm.get("window_end")?.safeInt ?? 0) + 5
        XCTAssertEqual(try r.c.finalizeDue(), [id])
        XCTAssertEqual(try r.c.get(id)?.get("state")?.asString, "finalized")
        XCTAssertEqual(r.alerts.v.map { $0.get("code")?.asString }, ["effect_unknown"])
        XCTAssertTrue(r.calls.v.isEmpty)
    }

    func testAWindowNobodyWasToldAboutIsAborted() throws {
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock, deliver: false)
        let adm = r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g)
        XCTAssertThrowsError(try r.c.open(adm))
        let id = adm.get("id")?.asString ?? ""
        XCTAssertEqual(try r.c.get(id)?.get("state")?.asString, "finalized")
        XCTAssertEqual(r.alerts.v.first?.get("code")?.asString, "notify_failed")
        XCTAssertEqual(r.alerts.v.first?.get("level")?.asString, "critical")
    }

    func testAdmissionRefusesWhatIsNotConfirmedReversible() throws {
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock)
        XCTAssertTrue(r.c.admit(pcactn: try action(g, "irreversible"), operation: op, converted: false, grant: g).get("refused")?.asString?.hasPrefix("the signed class is irreversible") == true)
        let none = try build(g, clock, engine: { _, _ in nil })
        XCTAssertTrue(none.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g).get("refused")?.asString?.contains("not confirmed reversible") == true)
        let off = try build(g, clock, policy: { _, _ in .object(["mode": .string("off")]) })
        XCTAssertEqual(off.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g).get("refused")?.asString, "policy: undo windows are off")
        let esc = try build(g, clock, policy: { _, _ in .object(["mode": .string("escalations")]) })
        XCTAssertTrue(esc.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g).get("refused")?.asString?.contains("windows only replace approvals") == true)
        XCTAssertNil(esc.c.admit(pcactn: try action(g), operation: op, converted: true, grant: g).get("refused"))
    }

    func testACompensationTheGrantDoesNotAllowIsRefused() throws {
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock, engine: { _, _ in self.plan("admin.delete", target: false) })
        XCTAssertTrue(r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g).get("refused")?.asString?.contains("not authorized under the grant") == true)
    }

    func testAVolatileStoreAndMissingComponentsFailClosed() throws {
        let g = try grant()
        func opts() -> PCAUndoOptions {
            PCAUndoOptions(store: MemoryUndoStore(), engine: { _, _ in nil }, signerSecret: [UInt8](repeating: 9, count: 32), audience: "rs", resolveGrant: { _, _ in g },
                           compensate: { _ in nil }, operations: MemoryOperationStore(), notifier: { _ in .object([:]) }, alert: { _ in })
        }
        XCTAssertThrowsError(try PCAUndoCoordinator.create(opts())) { XCTAssertEqual(($0 as? UndoError)?.code, "not_durable") }
        var bad = opts()
        bad.audience = ""
        XCTAssertThrowsError(try PCAUndoCoordinator.create(bad)) { XCTAssertEqual(($0 as? UndoError)?.code, "config") }
    }

    func testTheKvStoreAndEffectReporting() throws {
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock, store: KvUndoStore(MemoryAtomicKV(), durable: false))
        let adm = r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g)
        _ = try r.c.open(adm)
        let id = adm.get("id")?.asString ?? ""
        XCTAssertEqual(try r.c.get(id)?.get("ver")?.safeInt, 0)
        let rec = try PCAUndoServer.reportUndoEffect(r.c, id: id, status: "committed", result: .object(["id": .string("p9")]))
        XCTAssertEqual(rec.get("effect")?.get("result"), .object(["id": .string("p9")]))
        let v = r.c.veto(id, operator: "ops")
        XCTAssertEqual(v.get("record")?.get("state")?.asString, "compensated")
        XCTAssertEqual(r.calls.v.first?.get("operation")?.get("params"), .object(["payment": .string("p9")]))
    }

    /// A reserved event held by the record, then released by the rollback: the ledger's event after the veto.
    func releasedEvent(_ makeBudget: (BudgetLedger) -> PCAUndoBudget) throws -> JSONValue {
        let g = try grant(), clock = Box(1_000.0)
        let ledger = KvBudgetLedger(kv: MemoryAtomicKV(), durable: true)
        let r = try build(g, clock, budget: makeBudget(ledger))
        let adm = r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g)
        _ = try r.c.open(adm)
        let id = adm.get("id")?.asString ?? ""
        let ev: JSONValue = .object(["id": .string(id), "verb": .string("pay"), "resource": .string("invoice:1"), "params": .object([:]), "t": .int(1_000)])
        XCTAssertEqual(try ledger.reserve("principal/p", .object(["event": ev, "accumulators": .array([])])).get("outcome")?.asString, "reserved")
        _ = try r.c.holdBudget(id, [.object(["key": .string("principal/p"), "id": .string(id)])])
        _ = try r.c.recordEffect(id, result: .object(["id": .string("pay_1")]))
        let v = r.c.veto(id, operator: "ops")
        XCTAssertEqual(v.get("record")?.get("state")?.asString, "compensated")
        XCTAssertFalse(r.calls.v.isEmpty)
        return try ledger.snapshot("principal/p").get("events")?.asArray?.first ?? .null
    }

    func testAReleaseCarriesNoEvidenceUnlessTheCallerSuppliesIt() throws {
        let event = try releasedEvent { PCAUndoBudget(ledger: $0) }
        XCTAssertEqual(event.get("status")?.asString, "released")
        XCTAssertNil(event.get("rel"))
    }

    func testTheCallersReleaseEvidenceIsWhatTheLedgerStores() throws {
        let signer = try Self.edKey(9)
        let seen = Box<[String]>([])
        let event = try releasedEvent { ledger in
            PCAUndoBudget(ledger: ledger, evidence: { r, how in
                seen.v.append("\(r.get("key")?.asString ?? "")/\(how)")
                return try PCABudgetLedger.signRelease(key: r.get("key")?.asString ?? "", id: r.get("id")?.asString ?? "", reason: how, at: .int(1_000), secret: signer)
            })
        }
        XCTAssertEqual(seen.v, ["principal/p/rollback"])
        XCTAssertEqual(event.get("status")?.asString, "released")
        XCTAssertTrue(PCABudgetLedger.verifyRelease(event.get("rel"), expectedSigner: .string(signer.id)))
        XCTAssertEqual(event.get("rel")?.get("reason")?.asString, "rollback")
    }

    func testRollbackOnSlashNeedsABondLedger() throws {
        let g = try grant()
        let r = try build(g, Box(1_000.0))
        XCTAssertThrowsError(try r.c.rollbackOnSlash(.object(["claimId": .string("x")]))) { XCTAssertEqual(($0 as? UndoError)?.code, "config") }
    }

    func testRollbackOnSlashUndoesTheRecordOfTheBond() throws {
        final class Bonds: UndoBondLedger {
            func slashBond(_ params: JSONValue) throws -> JSONValue { .object(["claimId": params.get("claimId") ?? .null, "action": .string("slash")]) }
        }
        let g = try grant(), clock = Box(1_000.0)
        let r = try build(g, clock, bonds: Bonds())
        let adm = r.c.admit(pcactn: try action(g), operation: op, converted: false, grant: g)
        _ = try r.c.open(adm, bond: (ref: "bond-1", challengeEndsAt: 5_000))
        let id = adm.get("id")?.asString ?? ""
        _ = try r.c.recordEffect(id, result: .object(["id": .string("pay_1")]))
        clock.v = 1_500
        let out = try r.c.rollbackOnSlash(.object(["claimId": .string("bond-1")]))
        XCTAssertTrue(ok(out.get("veto") ?? .null), "\(out)")
        XCTAssertEqual(out.get("veto")?.get("record")?.get("state")?.asString, "compensated")
    }
}
