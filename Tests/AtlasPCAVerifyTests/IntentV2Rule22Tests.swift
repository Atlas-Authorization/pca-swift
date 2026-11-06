import XCTest
@testable import AtlasPCAVerify

/// Rule 22 and the grant action pin in the verifier pipeline, pinned to packages/pca/src/intent-v2.ts: context validation (83-87), the schema
/// step's integrity check (321-325), `pin` (614-622) and `traits` (623-634), in that order.
final class IntentV2Rule22Tests: XCTestCase {
    typealias F = V2F
    private static let VERB = "air.book"
    private static let ROOT = F.digest("pack-root"), DEF = F.digest("def"), DEF0 = F.digest("def-old")
    private static let reg = Actions.coreRegistry
    /// What an unconfirmed write verb must carry: every trait, floors at the join of them all.
    private static let rho: Profile = {
        var p = try! Actions.floorOf(reg, Actions.topTraits(reg))
        p.rev = "irreversible"
        return p
    }()
    private static let RISK: JSONValue = .object([
        "bMax": .int(1000), "kappa": .int(1), "lambda": .int(0), "rho": .int(0), "theta1": .double(0.5), "theta2": .double(0.8),
        "weights": .object(["alpha": .int(0), "beta": .int(0), "delta": .int(0), "epsilon": .int(0), "gamma": .int(0), "zeta": .int(0)]),
    ])
    private static let registryKey = F.key("registry"), reviewer = F.key("reviewer")
    private static let ACTIONS_KEYS: JSONValue = .array([.object(["kid": .string("reg"), "alg": .string("ed25519"), "pk": .string(F.pub(registryKey))])])
    private static let PINS: JSONValue = .object(["keys": .array([.object(["kid": .string("rev"), "pk": .string(F.pub(reviewer)), "roles": .array([.string("reviewer")])])])])
    private static let p: JObject = ["aud": .string(F.AUD), "action": .object(["verb": .string(VERB), "resource": .string("r"), "params_digest": .string(IV.strictHash(.object([:]))!)])]

    private func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }

    private func doc(traits: [String]? = nil, floors: JSONValue? = nil, aud: String = F.AUD, pack: String = IntentV2Rule22Tests.ROOT, withPack: Bool = true) -> JSONValue {
        var d: JObject = ["v": .int(2), "kind": .string("pca-action-schema"), "site": .string("https://skyair.example"), "aud": .string(aud), "version": .string("1"),
                          "verbs": .array([.object(["verb": .string(Self.VERB), "kind": .string("write"), "params": .object([:]), "effects": strs(["pay"]),
                                                    "traits": strs(traits ?? Actions.topTraits(Self.reg)), "def": .string(Self.DEF), "floors": floors ?? Self.rho.json])])]
        if withPack { d["pack"] = .object(["ns": .string("air"), "version": .string("1.0.0"), "root": .string(pack)]) }
        return F.signSchema(d)
    }

    /// A read verb confirmed by a pinned reviewer: no traits, bottom floors.
    private func confirmedDoc() -> JSONValue {
        var v: JObject = ["verb": .string(Self.VERB), "kind": .string("read"), "reversibility": .string("reversible"), "params": .object([:]), "effects": strs(["read"])]
        let facts = Actions.factsDigest(v)
        v["traits"] = .array([])
        v["def"] = .string(Self.DEF)
        v["floors"] = Profile().json
        var a: JObject = ["def_digest": .string(Self.DEF), "traits_digest": .string(Actions.traitsDigest(Self.reg)), "facts_digest": .string(facts), "final_traits": .array([]),
                          "dismissed": .array([]), "reviewer_kid": .string("rev"), "ts": .int(1)]
        a["sig"] = .string(F.sign(Self.reviewer, Actions.reviewMessage(a)!))
        v["confirmation"] = .object(a)
        return F.signSchema(["v": .int(2), "kind": .string("pca-action-schema"), "site": .string("https://skyair.example"), "aud": .string(F.AUD), "version": .string("1"), "verbs": .array([.object(v)])])
    }

    private func grant(caveats: [String] = [], actions: JSONValue? = nil) -> JSONValue {
        var e: JObject = ["type": .string("envelope"), "goal_commit": .string(F.digest("goal")), "predicates": .array([]), "caveats": .array(caveats.map { .object(["type": .string($0)]) }),
                          "agent_binding": .object([:]), "risk_policy": Self.RISK]
        if let a = actions { e["actions"] = a }
        return F.cap(issuer: F.principal, holder: F.agent, caveats: [.object(e)])
    }

    private func pin(_ over: JObject = [:], root: String = IntentV2Rule22Tests.ROOT) -> JSONValue {
        var x: JObject = ["pack": .object(["ns": .string("air"), "root": .string(root)]), "on_new_action": .string("deny")]
        for (k, v) in over { x[k] = v }
        return .object(x)
    }

    private func ctx(_ d: JSONValue?, closed: Bool = true, _ over: JObject = [:]) -> JObject {
        var c: JObject = ["params": .object([:])]
        if let d = d { c["schema"] = .object(["docs": .array([d]), "keys": F.KEYS]) }
        if closed { c["policy"] = .object(["schema": .object(["closed_world": .bool(true)])]) }
        for (k, v) in over { c[k] = v }
        return c
    }

    /// `name` for a passed check, `name=reason` for a failed one.
    private func run(_ g: JSONValue, _ c: JObject, now: Int64 = V2F.NOW) -> [String] {
        IntentV2.decide(Self.p, grant: g, ctx: IntentV2Context(.object(c)), now: now).checks.map { $0.ok ? $0.name : "\($0.name)=\($0.reason)" }
    }

    func testFixtureIsAWellFormedHonestV2Schema() {
        let d = doc()
        XCTAssertNil(ActionSchema.shapeError(d))
        XCTAssertNil(Actions.schemaFloorError(d.asObject!))
        XCTAssertGreaterThanOrEqual(Self.rho.esc, 1)
        XCTAssertFalse(Self.rho.caveats.isEmpty)
        XCTAssertFalse(Self.rho.context.isEmpty)
        XCTAssertNil(ActionSchema.shapeError(confirmedDoc()))
        XCTAssertNil(Actions.schemaFloorError(confirmedDoc().asObject!, Self.PINS))
    }

    // ---- context ----------------------------------------------------------------------------------------------------------

    func testContextValidation() {
        func err(_ o: JObject) -> String? { IntentV2.contextError(.object(o)) }
        let rev = "reviewers must be {keys: [...]}"
        XCTAssertEqual(err(["reviewers": .null]), rev)
        XCTAssertEqual(err(["reviewers": .array([])]), rev)
        XCTAssertEqual(err(["reviewers": .object([:])]), rev)
        XCTAssertEqual(err(["reviewers": .object(["keys": .object([:])])]), rev)
        XCTAssertNil(err(["reviewers": .object(["keys": .array([])])]))
        let cc = "call_context must be an array of strings"
        XCTAssertEqual(err(["call_context": .string("x")]), cc)
        XCTAssertEqual(err(["call_context": .array([.int(1)])]), cc)
        XCTAssertEqual(err(["call_context": .array([.string("a"), .null])]), cc)
        XCTAssertNil(err(["call_context": .array([])]))
        XCTAssertNil(err(["call_context": .array([.string("a")])]))
        XCTAssertEqual(err(["actions": .array([])]), "actions must be an object")
        XCTAssertEqual(err(["actions": .null]), "actions must be an object")
        XCTAssertNil(err(["actions": .object([:])]))
        for k in ["records", "keys", "reapprovals"] {
            XCTAssertEqual(err(["actions": .object([JKey(k): .object([:])])]), "actions.\(k) must be an array")
            XCTAssertNil(err(["actions": .object([JKey(k): .array([])])]))
        }
        // the reference's order: reviewers, call_context, actions, then params
        XCTAssertEqual(err(["reviewers": .null, "call_context": .null]), rev)
        XCTAssertEqual(err(["call_context": .null, "actions": .null]), cc)
        XCTAssertEqual(err(["actions": .null, "params": .null]), "actions must be an object")
        XCTAssertEqual(run(grant(), ["reviewers": .null]), ["schema=malformed v2 context: \(rev)", "intent_session=malformed v2 context: \(rev)"])
    }

    // ---- the schema step ----------------------------------------------------------------------------------------------------

    func testForgedFloorsAreRefusedAfterAudBeforeParams() {
        let forged = doc(floors: Profile().json)
        let why = "schema=schema_floor_forged: \(Self.VERB): schema_floor_forged: floors are below the floor of the carried traits"
        XCTAssertEqual(run(grant(), ctx(forged)), [why])
        var noParams = ctx(forged)
        noParams["params"] = nil
        XCTAssertEqual(run(grant(), noParams), [why])
        XCTAssertEqual(run(grant(), ctx(doc(floors: Profile().json, aud: "other"))), ["schema=schema aud does not match the PCActn aud"])
        var honest = ctx(doc())
        honest["params"] = nil
        XCTAssertEqual(run(grant(), honest).first, "schema=no plaintext params to check against the schema (closed world needs them)")
    }

    func testDroppedImpliedTraitIsRefused() {
        let t = Actions.topTraits(Self.reg).filter { $0 != "pca.money_moving" }
        XCTAssertEqual(run(grant(), ctx(doc(traits: t))), ["schema=schema_floor_forged: \(Self.VERB): schema_traits_forged: missing implied trait pca.money_moving"])
    }

    func testUnknownTraitIsRefused() {
        let r = run(grant(), ctx(doc(traits: Actions.topTraits(Self.reg) + ["zz.custom"])))
        XCTAssertEqual(r.count, 1)
        XCTAssertTrue(r[0].hasPrefix("schema=schema_floor_forged: \(Self.VERB): "), r[0])
        XCTAssertTrue(r[0].contains("unknown trait 'zz.custom'"), r[0])
    }

    func testReviewersReachTheIntegrityCheck() {
        let d = confirmedDoc()
        let r = run(grant(), ctx(d))
        XCTAssertEqual(r.count, 1)
        XCTAssertTrue(r[0].hasPrefix("schema=schema_floor_forged: \(Self.VERB): schema_traits_forged: unconfirmed action must carry every trait"), r[0])
        XCTAssertEqual(run(grant(), ctx(d, ["reviewers": Self.PINS])), ["schema", "traits"]) // bottom floors: nothing more needed
    }

    func testV1SchemaIsUnchanged() {
        let v1 = F.signSchema(["v": .int(1), "kind": .string("pca-action-schema"), "site": .string("https://skyair.example"), "aud": .string(F.AUD), "version": .string("1"),
                               "verbs": .array([.object(["verb": .string(Self.VERB), "kind": .string("write"), "params": .object([:])])])])
        XCTAssertEqual(run(grant(), ctx(v1)), ["schema"])
        XCTAssertEqual(run(grant(actions: pin()), ctx(v1)), ["schema", "pin=pack_mismatch: the schema does not come from the pinned pack 'air'"])
    }

    // ---- traits --------------------------------------------------------------------------------------------------------------

    func testFloorDecisionMeetsTheGrant() {
        let esc = "traits=escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)"
        let deny = "traits=the action floors exceed what the grant authorizes (rule 22)"
        let cc: JObject = ["call_context": strs(Self.rho.context)]
        let fullPin: JObject = ["max_esc": .int(3), "preauth_esc": .int(3)]
        // no pin: max_esc defaults to the top tier, preauth_esc to 0, no caveats, no context
        XCTAssertEqual(run(grant(), ctx(doc())), ["schema", esc])
        // allow: every caveat on the envelope, the context from the call, the esc preauthorized by the pin
        XCTAssertEqual(run(grant(caveats: Self.rho.caveats, actions: pin(fullPin)), ctx(doc(), cc)), ["schema", "pin", "traits"])
        // pin caveats count as well as envelope caveats
        XCTAssertEqual(run(grant(actions: pin(fullPin.merging(["caveats": strs(Self.rho.caveats)]) { $1 })), ctx(doc(), cc)), ["schema", "pin", "traits"])
        // one caveat short, or one context key short: escalate
        XCTAssertEqual(run(grant(caveats: Array(Self.rho.caveats.dropFirst()), actions: pin(fullPin)), ctx(doc(), cc)), ["schema", "pin", esc])
        XCTAssertEqual(run(grant(caveats: Self.rho.caveats, actions: pin(fullPin)), ctx(doc(), ["call_context": strs(Array(Self.rho.context.dropFirst()))])), ["schema", "pin", esc])
        // preauth_esc below the floor: escalate; default preauth_esc is 0
        XCTAssertEqual(run(grant(caveats: Self.rho.caveats, actions: pin(["preauth_esc": .int(Int64(Self.rho.esc - 1))])), ctx(doc(), cc)), ["schema", "pin", esc])
        XCTAssertEqual(run(grant(caveats: Self.rho.caveats, actions: pin(["preauth_esc": .int(Int64(Self.rho.esc))])), ctx(doc(), cc)), ["schema", "pin", "traits"])
        XCTAssertEqual(run(grant(caveats: Self.rho.caveats, actions: pin()), ctx(doc(), cc)), ["schema", "pin", esc])
        // a verb above max_esc is denied, at the boundary it is not
        XCTAssertEqual(run(grant(actions: pin(["max_esc": .int(Int64(Self.rho.esc - 1))])), ctx(doc())), ["schema", "pin", deny])
        XCTAssertEqual(run(grant(actions: pin(["max_esc": .int(Int64(Self.rho.esc))])), ctx(doc())), ["schema", "pin", esc])
        // a malformed pin grants nothing: its members are not read
        XCTAssertEqual(run(grant(caveats: Self.rho.caveats, actions: pin(["preauth_esc": .int(3), "max_esc": .int(9)])), ctx(doc(), cc)),
                       ["schema", "pin=bad_pin: actions.max_esc must be an integer tier 0..3", esc])
    }

    func testTraitsWithAPinNeedNoV2Policy() {
        // no closed_world: `schema` is not reported, the pin's own schema step still finds the v2 document
        XCTAssertEqual(run(grant(actions: pin()), ctx(doc(), closed: false)).first, "pin")
        XCTAssertEqual(run(grant(actions: pin()), ctx(doc(), closed: false)).count, 2)
        // no pin and no schema step: nothing is reported
        XCTAssertEqual(run(grant(), ctx(doc(), closed: false)), [])
    }

    // ---- pin -----------------------------------------------------------------------------------------------------------------

    func testPinDecisions() {
        XCTAssertEqual(run(grant(actions: .null), ctx(doc())).dropFirst().first, "pin=bad_pin: actions must be an object")
        XCTAssertEqual(run(grant(actions: pin(root: F.digest("other"))), ctx(doc())).dropFirst().first,
                       "pin=pack_mismatch: the pack root differs from the pinned root (the grant pins the pack as a whole)")
        XCTAssertEqual(run(grant(actions: pin(["defs": .object([JKey(Self.VERB): .string(Self.DEF)])])), ctx(doc())).dropFirst().first, "pin")
        let other: JObject = ["defs": .object(["other.verb": .string(Self.DEF)])]
        XCTAssertEqual(run(grant(actions: pin(other)), ctx(doc())).dropFirst().first, "pin=new_action: the grant does not name '\(Self.VERB)' (on_new_action: deny)")
        XCTAssertEqual(run(grant(actions: pin(other.merging(["on_new_action": .string("escalate")]) { $1 })), ctx(doc())).dropFirst().first,
                       "pin=escalate: new_action: the grant does not name '\(Self.VERB)' (on_new_action: escalate)")
        XCTAssertEqual(run(grant(actions: pin(["defs": .object([JKey(Self.VERB): .string(Self.DEF0)])])), ctx(doc())).dropFirst().first,
                       "pin=def_changed: the definition differs from the pinned digest and no signed evolution record chains to it")
        // no schema configured: the pin fails on the schema step and `traits` has no document to read
        XCTAssertEqual(run(grant(actions: pin()), ctx(nil, closed: false)), ["pin=this verifier has no action schema configured"])
    }

    private func record(_ cls: String) -> JSONValue {
        let body: JObject = ["v": .int(1), "kind": .string(Actions.EVOLUTION_RECORD_KIND), "ns": .string("air"), "verb": .string(Self.VERB), "from": .string(Self.DEF0), "to": .string(Self.DEF),
                             "class": .string(cls), "reasons": .array([])]
        var r = body
        r["sig"] = .object(["alg": .string("ed25519"), "kid": .string("reg"), "value": .string(F.sign(Self.registryKey, IV.message(Actions.EVOLUTION_DOMAIN, .object(body))!))])
        return .object(r)
    }

    private func reapproval(_ grantId: String, _ diff: String) -> JSONValue {
        let body: JObject = ["v": .int(1), "kind": .string(Actions.REAPPROVAL_KIND), "grant": .string(grantId), "verb": .string(Self.VERB), "diff": .string(diff)]
        var r = body
        r["sig"] = .object(["alg": .string("ed25519"), "value": .string(F.sign(F.principal, IV.message(Actions.REAPPROVAL_DOMAIN, .object(body))!))])
        return .object(r)
    }

    func testEvolutionRecordsAndReapprovalsComeFromTheContext() {
        let g = grant(actions: pin(["defs": .object([JKey(Self.VERB): .string(Self.DEF0)])]))
        let narrow: JObject = ["actions": .object(["records": .array([record("narrow")]), "keys": Self.ACTIONS_KEYS])]
        XCTAssertEqual(run(g, ctx(doc(), narrow)).dropFirst().first, "pin")
        let widen = record("widen")
        let diff = Actions.evolutionDiffDigest(widen)!
        let blocked = "pin=def_changed: the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve (re-approve diff \(diff))"
        XCTAssertEqual(run(g, ctx(doc(), ["actions": .object(["records": .array([widen]), "keys": Self.ACTIONS_KEYS])])).dropFirst().first, blocked)
        // the principal's re-approval is bound to THIS grant id and signed by THIS issuer
        let id = g.get("id")!.asString!
        XCTAssertEqual(run(g, ctx(doc(), ["actions": .object(["records": .array([widen]), "keys": Self.ACTIONS_KEYS, "reapprovals": .array([reapproval(id, diff)])])])).dropFirst().first, "pin")
        XCTAssertEqual(run(g, ctx(doc(), ["actions": .object(["records": .array([widen]), "keys": Self.ACTIONS_KEYS, "reapprovals": .array([reapproval("other", diff)])])])).dropFirst().first, blocked)
        // no registry keys in the context: the record does not count
        XCTAssertEqual(run(g, ctx(doc(), ["actions": .object(["records": .array([record("narrow")])])])).dropFirst().first,
                       "pin=def_changed: the definition differs from the pinned digest and no signed evolution record chains to it")
    }

    // ---- wiring -----------------------------------------------------------------------------------------------------------

    func testABadClockFailsEveryLateRule() {
        let c = "the verifier clock is not a safe integer (fail closed)"
        XCTAssertEqual(run(grant(actions: pin()), ctx(doc()), now: .max), ["schema=\(c)", "pin=\(c)", "traits=\(c)"])
        XCTAssertEqual(run(grant(actions: pin()), ctx(doc(), closed: false), now: .max), ["pin=\(c)", "traits=\(c)"])
    }

    func testAGrantPinNeedsTheV2Pipeline() {
        XCTAssertTrue(PCA.needsModelRules(grant(actions: pin())))
        XCTAssertFalse(PCA.needsModelRules(grant()))
    }
}
