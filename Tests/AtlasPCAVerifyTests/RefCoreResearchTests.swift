import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The shared research-tier corpus in full (every case, every fn): DLP, the immune read side, the console and the freeze set, session scripts,
/// policy simulation and its lints, and disputes derived from settlement records.
final class RefCoreResearchTests: XCTestCase {
    typealias A = RefAnalyzer
    static let err: JSONValue = .object(["$err": .string("Error")])
    private static func d(_ v: JSONValue?) -> Double { IV.num(v) ?? Double.nan }
    private static func key(_ label: String) throws -> PCASuiteKey { .ed25519(try A.key("research/" + label)) }

    /// One result per op; an op that throws records `{"$err": "Error"}`.
    private static func session(_ ops: [JSONValue]) -> JSONValue {
        var agents: [String: PCAFacadeAgent] = [:]
        var sessions: [String: PCASession] = [:]
        return .array(ops.map { item in
            let op = item.asArray ?? []
            func text(_ i: Int) -> String? { i < op.count ? op[i].asString : nil }
            func sess(_ i: Int) throws -> PCASession {
                guard let s = text(i).flatMap({ sessions[$0] }) else { throw PCAProducerError("no such session") }
                return s
            }
            do {
                switch text(0) {
                case "agent":
                    guard let name = text(1), op.count > 2, let goal = op[2].get("goal")?.asString, case let .object(perms)? = op[2].get("permissions"),
                          let p = op[2].get("principal")?.asString, let h = op[2].get("holder")?.asString else { throw PCAProducerError("agent spec") }
                    let permissions = JS.keyOrder(perms).map { k in (k.s, (perms[k]?.asArray ?? []).compactMap { $0.asString }) }
                    let a = try PCAAgent.fromPrincipal(PCAAgentOptions(principal: try key(p), goal: goal, permissions: permissions, holder: try key(h),
                                                                       now: op[2].get("now")?.safeInt, goalSalt: op[2].get("goalSalt")?.asString))
                    agents[name] = a
                    return .string(a.holder.id ?? "")
                case "start":
                    guard let name = text(1), let a = text(2).flatMap({ agents[$0] }) else { throw PCAProducerError("start") }
                    sessions[name] = Session.startSession(a)
                    return .string(sessions[name]!.goalCommit)
                case "mk":
                    guard let name = text(1), op.count > 3, let ms = op[2].asArray?.compactMap({ $0.asString.flatMap { agents[$0] } }), let root = ms.first else { throw PCAProducerError("mk") }
                    let commit = op[3].isNull ? (PCA.readEnvelope(root.grant)?.get("goal_commit")?.asString ?? "") : (op[3].asString ?? "")
                    sessions[name] = PCASession(root: root, members: ms, goalCommit: commit)
                    return .string(commit)
                case "add":
                    guard let name = text(1) else { throw PCAProducerError("add") }
                    // caveats that are not a list add none (the typed API takes a list)
                    let r = try Session.addMember(try sess(2), holder: try text(3).map { try key($0) }, addedCaveats: op.count > 4 ? (op[4].asArray ?? []) : [])
                    sessions[name] = r.session
                    return .string(r.member.holder.id ?? "")
                case "agents": return .array(Session.sessionAgents(try sess(1)).map { .string($0) })
                case "depth": return .int(Int64(Session.sessionDepth(try sess(1))))
                case "shares": return .bool(Session.sharesGoal(try sess(1)))
                case "goal": return .string(try sess(1).goalCommit)
                case "console":
                    guard op.count > 2, case let .array(events) = op[2] else { throw PCAProducerError("events") }
                    return A.out(try Session.sessionConsole(try sess(1), events))
                default: throw PCAProducerError("op")
                }
            } catch { return err }
        })
    }

    /// nil = unhandled fn. `skip` names a case the typed signature cannot express.
    static func call(_ c: BaseCase, skip: (String) -> Void) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "evaluateDlp":
            // verb and resource are text in the typed API; a taint that is not a number is unknown (NaN), as the reference treats it
            guard let ctx = a1, ctx.isObject, let verb = ctx.get("verb")?.asString, let resource = ctx.get("resource")?.asString else { skip("evaluateDlp: verb or resource is not text"); return .value(c.out) }
            return A.run { try PCADlp.evaluate(a0, verb: verb, resource: resource, taint: d(ctx.get("taint"))).json }
        case "defaultDlpPolicy":
            guard let o = a0, !o.isNull else { return .threw(nil) }
            return .value(PCADlp.defaultDlpPolicy(piiResource: o.get("piiResource"), secretsResource: o.get("secretsResource")))
        case "updateBaseline": return A.run { PCAImmune.json(PCAImmune.updateBaseline(PCAImmune.baseline(json: a0), d(a1))) }
        case "baselineStd": return A.run { PD.num(PCAImmune.baselineStd(PCAImmune.baseline(json: a0))) }
        case "assess": return A.run { PCAImmune.json(PCAImmune.assess(json: a0)) }
        case "validateImmuneState": return .value(Base.opt(PCAImmune.validateImmuneState(a0)))
        case "observe":
            return A.run {
                PCAImmune.json(PCAImmune.observe(PCAImmune.state(json: a0), r: d(a1?.get("r")), at: d(a1?.get("at")), stepUp: JS.truthy(a1?.get("stepUp")), denied: JS.truthy(a1?.get("denied"))))
            }
        case "buildConsole":
            guard case let .array(events)? = a0 else { return .threw(nil) }
            return A.run { Console.buildConsole(events) }
        case "anomalies":
            guard case let .array(events)? = a0 else { return .threw(nil) }
            return A.run { .array(Console.anomalies(Console.buildConsole(events))) }
        case "eventFromPCActn":
            guard let outcome = a1?.asString else { skip("eventFromPCActn: outcome is not text"); return .value(c.out) }
            return A.run { try Console.eventFromPCActn(a0 ?? .null, outcome: outcome, at: IV.num(JS.present(a2))) }
        case "freezeAgent": return A.run { try Console.freezeAgent(a0, a1) }
        case "unfreezeAgent": return A.run { try Console.unfreezeAgent(a0, a1) }
        case "isFrozen": return .value(.bool(Console.isFrozen(a0, a1)))
        case "session": return .value(session(a0?.asArray ?? []))
        case "simulate":
            return A.run {
                let policy = try RefPolicyFixture.compile(a0).policy
                guard case let .array(actions)? = a1 else { throw PCAProducerError("actions") }
                return PolicySim.simulate(policy, actions, start: JS.present(a2) == nil ? 0 : d(a2))
            }
        case "lintPolicy":
            return A.run {
                let f = try RefPolicyFixture.compile(a0)
                return .array(PolicySim.lintPolicy(f.policy, limitOrder: f.limitOrder))
            }
        case "disputesFromSettlements":
            return A.run {
                guard case let .array(records)? = a0 else { throw PCAProducerError("records") }
                let guardian = a1?.asString == "@g" ? Base64URLStrict.encode(try A.key("research/guardian").pub) : (a1?.asString ?? "")
                let map = a2?.asObject ?? [:]
                var pins: [String: String]?
                if let p = JS.present(a3)?.get("pqPins")?.asObject { pins = [:]; for (k, v) in p { pins?[k.s] = v.asString } }
                let r = Reputation.disputesFromSettlements(records, guardianPublicKey: guardian, subjectOf: { map[JKey($0)]?.asString }, pins: pins)
                return .object(["disputes": .array(r.disputes), "rejected": .int(Int64(r.rejected))])
            }
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let diffs = Base.Diffs()
        var untyped = 0
        let n = try Base.each("ref-core-research-java.json.gz") { c in
            var skipped = false
            guard let got = Self.call(c, skip: { diffs.skip($0); skipped = true }) else { XCTFail("unhandled fn \(c.fn)"); return }
            if skipped { untyped += 1; return }
            diffs.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 6188)
        // evaluateDlp: 36 cases with a null verb, 36 with a null resource, 36 with a number as the resource
        XCTAssertEqual(untyped, 108)
        diffs.finish(6188 - 108)
    }

    func testTheFreezeSetAndTheSessionLimit() throws {
        let set = try Console.freezeAgent(Console.EMPTY_FREEZE, .string("b"))
        let two = try Console.freezeAgent(set, .string("a"))
        XCTAssertEqual(two, .object(["frozen": .array([.string("a"), .string("b")])]))
        XCTAssertEqual(try Console.freezeAgent(two, .string("a")), two)
        XCTAssertTrue(Console.isFrozen(two, .string("a")))
        XCTAssertFalse(Console.isFrozen(try Console.unfreezeAgent(two, .string("a")), .string("a")))
        XCTAssertTrue(Console.isFrozen(nil, .string("a")))
        XCTAssertTrue(Console.isFrozen(two, .string("")))
        let root = try PCAAgent.fromPrincipal(PCAAgentOptions(principal: try Self.key("p"), goal: "ship", permissions: [("github", ["read"])], holder: try Self.key("h"), now: 0))
        var s = Session.startSession(root)
        XCTAssertTrue(Session.sharesGoal(s))
        for _ in 0..<Session.SESSION_MAX_DEPTH { s = try Session.addMember(s).session }
        XCTAssertEqual(Session.sessionDepth(s), 32)
        XCTAssertThrowsError(try Session.addMember(s))
    }
}
