import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the IntentV2.swift survivors of group 5: the text loader, the env members, the session policy guard, and what the pipeline puts into
/// the verifier-computed env (accumulator posts, monitor states, provenance, classes) and into the single-source list.
final class S2G5IntentV2KillTests: XCTestCase {
    typealias F = V2F
    private func s(_ x: String) -> JSONValue { .string(x) }

    func testFromJSONTextLoadsAnObject() {
        XCTAssertNotNil(IntentV2Context.fromJSONText(#"{"a":1}"#), "line 20")
        XCTAssertNil(IntentV2Context.fromJSONText("[1]"))
        XCTAssertNil(IntentV2Context.fromJSONText("not json"))
    }

    func testEnvJSONCarriesEachMember() {
        let x: JObject = ["k": .int(1)]
        XCTAssertEqual(IntentV2Env().json, .object([:]))
        XCTAssertEqual(IntentV2Env(canon: x).json, .object(["canon": .object(x)]), "line 37")
        XCTAssertEqual(IntentV2Env(acc: x).json, .object(["acc": .object(x)]), "line 38")
        XCTAssertEqual(IntentV2Env(mon: x).json, .object(["mon": .object(x)]), "line 39")
        XCTAssertEqual(IntentV2Env(world: x).json, .object(["world": .object(x)]), "line 40")
        XCTAssertEqual(IntentV2Env(prov: x).json, .object(["prov": .object(x)]), "line 41")
        XCTAssertEqual(IntentV2Env(cls: x).json, .object(["class": .object(x)]), "line 42")
    }

    func testAMisconfiguredRevocationAgeIsRefusedFirst() {
        func ctx(_ v: JSONValue) -> JSONValue { .object(["policy": .object(["session": .object(["max_revocation_age_s": v])])]) }
        let why = "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)"
        XCTAssertEqual(IntentV2.sessionStep([:], .null, ctx(.int(-1)), 0), why, "line 222")
        XCTAssertEqual(IntentV2.sessionStep([:], .null, ctx(.string("x")), 0), why)
        XCTAssertNotEqual(IntentV2.sessionStep([:], .null, ctx(.int(5)), 0), why)
    }

    // ---- the env the pipeline computes ----

    func testAccumulatorPostsLandInTheEnv() {
        let env = PCA.intentV2Env(pcactn: F.P0, grant: F.G0, now: F.NOW, context: IntentV2Context(F.ctx()))
        XCTAssertEqual(env?.acc?["trip_spend"], .object(["post": .int(38_900)]), "line 405")
    }

    func testMonitorStatesLandInTheEnv() {
        let mon: JSONValue = .object(["id": s("m"), "kind": s("requires_prior"), "p": .object(["verb": s("air.book")]), "q": .object(["verb": s("hotel.book")]),
                                      "status": s("committed")])
        let RM = F.root(["monitors": .array([mon])])
        let gm = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: RM.R)
        let p = F.build(gm, is: F.is0(["root": s(RM.R)]))
        let ctx = F.ctx(["session": .object(["root": RM.S, "grants": .array([])]), "acc": IntentV2KillTests.acc(0, monitors: ["m": s("unmet")])])
        let env = PCA.intentV2Env(pcactn: p, grant: gm, now: F.NOW, context: IntentV2Context(ctx))
        XCTAssertEqual(env?.mon?["m"], .object(["state": s("unmet")]), "lines 413, 490")
        XCTAssertNotNil(env?.acc?["trip_spend"])
    }

    func testProvenanceLandsInTheEnv() {
        let pp = F.build(F.G0, is: F.is0(["prov": .object(["action.params.offer_id": .array([s("skyair:offer:1")])])]))
        let policy: JSONValue = .object(["provenance": .object(["params": .object(["action.params.offer_id": s("material")]),
                                                                 "registry": .object(["skyair:offer:1": s("first_party")])])])
        let ctx = F.ctx(["wb": .object(["artifacts": .object([:]), "policy": policy])])
        let env = PCA.intentV2Env(pcactn: pp, grant: F.G0, now: F.NOW, context: IntentV2Context(ctx))
        XCTAssertNotNil(env?.prov, "line 505")
    }

    func testClassesLandInTheEnv() {
        let j1 = IntentWBKillTests.j1, j2 = IntentWBKillTests.j2
        let vs = [IntentWBKillTests.verdict(j1, "apologetic"), IntentWBKillTests.verdict(j2, "apologetic")]
        let refs: [JSONValue] = vs.map { .string(F.ref(IntentWB.CLASSIFIER_REF_DOMAIN, "c", $0)) }
        var params = F.PARAMS.asObject!
        params["body"] = IntentWBKillTests.BODY
        let p = F.build(F.G0, is: F.is0(["classes": .array(refs)]), params: .object(params))
        let policy: JSONValue = .object(["classifiers": IntentWBKillTests.clsPolicy().get("classifiers")!])
        let ctx = F.ctx(["params": .object(params), "wb": .object(["artifacts": .object(["verdicts": .array(vs)]), "policy": policy])])
        let env = PCA.intentV2Env(pcactn: p, grant: F.G0, now: F.NOW, context: IntentV2Context(ctx))
        XCTAssertNotNil(env?.cls, "line 506")
    }

    /// A world decided by ONE oracle is model-derived for rule 21 (line 501): a layer ceiling that reads it is refused as `tighten`.
    func testASingleOracleWorldIsModelDerived() {
        let o1 = IntentWBKillTests.o1
        let fact = F.fact(value: .int(39_800), oracle: "o1", by: o1)
        let worldPolicy: JSONValue = .object(["worlds": .array([IntentWBKillTests.world(min: 1, faulty: 0, oracles: [IntentWBKillTests.oracle("o1", o1)])])])
        let p = F.build(F.G0, is: F.is0(["facts": IntentWBKillTests.refs([fact])]))
        let reads: JSONValue = .array([.object(["verb": s("*"), "where": .array([.object(["field": s("env.world.fare"), "op": s("eq"), "value": .int(39_800)])])])])
        let ctx = F.ctx(["layers": .object(["org": .object(["predicates": reads])]),
                         "wb": .object(["artifacts": .object(["facts": .array([fact])]), "policy": .object(["world": worldPolicy])])])
        let r = IntentV2.decide(p.asObject!, grant: F.G0, ctx: IntentV2Context(ctx), now: F.NOW)
        XCTAssertEqual(r.env?.world?["fare"], .int(39_800))
        let tighten = r.checks.first { $0.name == "tighten" }
        XCTAssertNotNil(tighten, "a single-source world path makes rule 21 apply")
        XCTAssertEqual(tighten?.ok, false)
        XCTAssertTrue(tighten?.reason.contains("env.world.fare") ?? false, tighten?.reason ?? "")
    }
}
