import XCTest
import Foundation
@testable import AtlasPCAVerify

final class ObjectiveBindingTests: XCTestCase {
    typealias O = PCAObjectiveRisk

    private static let policy: JSONValue = .object([
        "weights": .object(["alpha": .double(0.25), "beta": .double(0.2), "gamma": .double(0.2), "delta": .double(0.2), "epsilon": .double(0.1), "zeta": .double(0.05)]),
        "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1),
    ])
    private static let action: JSONValue = .object(["verb": .string("delete"), "resource": .string("doc:1"), "params": .object([:])])
    private static let instance: JSONValue = .object([
        "registry": .object(["trusted_verifiers": .array([.string("v1")]),
                             "entries": .array([.object(["verb": .string("delete"), "inverse_kind": .string("restore"), "fidelity": .string("exact"),
                                                         "verification": .object(["verifier_id": .string("v1"), "evidence_digest": .string("e1")])])])]),
        "graph": .object(["nodes": .array([.object(["id": .string("doc:1")])]), "edges": .array([])]),
    ])

    private static func grant(_ objective: JSONValue?, extra: JObject = [:]) -> JSONValue {
        var env: JObject = ["type": .string("envelope"), "goal_commit": .string("g"), "predicates": .array([]), "caveats": .array([]), "agent_binding": .object([:]), "risk_policy": policy]
        if let o = objective { env["objective_risk"] = o }
        for (k, v) in extra { env[k] = v }
        return .object(["id": .string("grant"), "caveats": .array([.object(env)])])
    }

    private func committed(on: String? = nil) throws -> JSONValue {
        let emb = try O.nativeHashEmbedder()
        let reg = O.InverseRegistry(trustedVerifiers: ["v1"]).register("delete", .object(["inverseKind": .string("restore"), "fidelity": .string("exact"),
                                                                       "verification": .object(["verifierId": .string("v1"), "evidenceDigest": .string("e1")])]))
        let graph = try O.ResourceGraph().addNode(.object(["id": .string("doc:1")]))
        var o: JObject = ["v": .int(1), "embedder": .object(["scheme": .string("native"), "model_id": emb.modelId, "config": emb.config]),
                          "goal": try O.commitGoal(emb, Self.action), "registry_digest": .string(try reg.digest()), "graph_digest": .string(try graph.digest()),
                          "authorized_kinds": .array([.string("restore")])]
        if let m = on { o["on_mismatch"] = .string(m) }
        return .object(o)
    }

    func testNothingCommittedLeavesTheHeuristic() {
        XCTAssertEqual(O.resolveObjectiveRisk(grant: Self.grant(nil), action: Self.action, instance: nil).get("mode"), .string("none"))
    }

    func testAMalformedCommitmentIsADeniedMismatch() {
        let r = O.resolveObjectiveRisk(grant: Self.grant(.object(["v": .int(2)])), action: Self.action, instance: Self.instance)
        XCTAssertEqual(r.get("mode"), .string("mismatch"))
        XCTAssertEqual(r.get("onMismatch"), .string("deny"))
        XCTAssertEqual(r.get("reasons"), .array([.string("objective_risk: unsupported shape/version")]))
    }

    func testACommittedGrantWithoutInstanceConfigIsAMismatch() throws {
        let r = O.resolveObjectiveRisk(grant: Self.grant(try committed()), action: Self.action, instance: nil)
        XCTAssertEqual(r.get("mode"), .string("mismatch"))
        XCTAssertEqual(r.get("reasons")?.asArray?.count, 1)
    }

    func testAReproducedCommitmentGivesTheObjectiveInputs() throws {
        let r = O.resolveObjectiveRisk(grant: Self.grant(try committed()), action: Self.action, instance: Self.instance, taint: 0, age: 0)
        XCTAssertEqual(r.get("mode"), .string("objective"), "\(r)")
        let rv = try XCTUnwrap(IV.num(r.get("r")))
        XCTAssertTrue(rv >= 0 && rv <= 1)
        XCTAssertEqual(r.get("inputs")?.get("reversibility"), .int(1), "a verified, authorized, exact inverse is reversible")
        XCTAssertFalse((r.get("evidenceDigest")?.asString ?? "").isEmpty)
    }

    func testAnInstanceThatCannotReproduceTheDigestsIsAMismatch() throws {
        var inst = Self.instance.asObject!
        inst["registry"] = .object([:])
        let r = O.resolveObjectiveRisk(grant: Self.grant(try committed()), action: Self.action, instance: .object(inst))
        XCTAssertEqual(r.get("mode"), .string("mismatch"))
        XCTAssertEqual(r.get("reasons")?.asArray?.first, .string("registry digest does not match the committed digest"))
    }

    func testAGrantCannotAskForTheHeuristicOnItsOwn() throws {
        var inst = Self.instance.asObject!
        inst["registry"] = .object([:])
        let g = Self.grant(try committed(on: "heuristic"))
        XCTAssertEqual(O.resolveObjectiveRisk(grant: g, action: Self.action, instance: .object(inst)).get("onMismatch"), .string("deny"))
        inst["allow_heuristic_fallback"] = .bool(true)
        XCTAssertEqual(O.resolveObjectiveRisk(grant: g, action: Self.action, instance: .object(inst)).get("onMismatch"), .string("heuristic"))
    }
}
