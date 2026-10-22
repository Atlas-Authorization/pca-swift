import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential kill tests of IntentMap.swift (rule 19), the W-B unit IntentWB.swift (rules 16-18: facts / offer sets,
/// provenance / flows / read purpose, classifiers) and the shared artifact helpers against the TS reference:
/// k042-mapartcls.json.gz (k042-mapartcls-oracle.mjs), k042-oracleprov.json.gz (k042-oracleprov-oracle.mjs) and
/// k042-wbmisc.json.gz (k042-wbmisc-oracle.mjs), shared with every native suite. Validators compare refused-or-not; decisions
/// compare the verdict and every result member; a refusal reason TEXT is the reference's, character for character.
final class K042MapWbOracleTests: XCTestCase {
    // ---------------------------------------------------------------- rule 19 / rule 18 (mapartcls)

    private func mapCases(_ fn: String) throws -> [JSONValue] {
        let cs = K042.arr(try K042.json("k042-mapartcls.json.gz")).filter { K042.str($0.get("fn")) == fn }
        XCTAssertFalse(cs.isEmpty, "no oracle cases for \(fn)")
        return cs
    }

    private func validators(_ fn: String, _ ok: (JSONValue) -> Bool) throws {
        var bad: [String] = []
        let cs = try mapCases(fn)
        for c in cs {
            let want = K042.isNull(c.get("out"))
            if ok(K042.arr(c.get("args"))[0]) != want { bad.append("\(K042.str(c.get("name"))): want ok=\(want) (\(K042.canon(c.get("out"))))") }
        }
        K042.report(bad, cs.count)
    }

    /// A validator that gives the refusal reason (nil = well-formed): the verdict and the reference's text must agree.
    private func reasonValidators(_ fn: String, _ f: (JSONValue) -> String?) throws {
        var bad: [String] = []
        let td = K042.TextDiffs()
        let cs = try mapCases(fn)
        for c in cs {
            let want = c.get("out")?.asString
            let got = f(K042.arr(c.get("args"))[0])
            if (want == nil) != (got == nil) { bad.append("\(K042.str(c.get("name"))): want \(K042.canon(c.get("out"))) got \(String(describing: got))") } else { td.add(want, got, K042.str(c.get("name"))) }
        }
        td.finish("validators \(fn)")
        K042.report(bad, cs.count)
    }

    func testMapLeafValidators() throws {
        try reasonValidators("header") { IntentMap.headerError($0) }
        try reasonValidators("cell") { IntentMap.cellError($0) }
        try reasonValidators("metrics") { IntentMap.metricsError($0) }
        try reasonValidators("disclosure") { IntentMap.disclosureError($0) }
        try validators("verdictwire") { IntentWB.validateVerdictWire($0) }
        try reasonValidators("policy") { IntentWB.classifierPolicyError($0) }
    }

    func testNumericCellsAndCellOf() throws {
        var bad: [String] = []
        for c in try mapCases("numcells") {
            let got = IntentMap.numCells(K042.obj(K042.arr(c.get("args"))[0])).map { "[\($0.0),\($0.1)]" }.joined()
            let want = K042.arr(c.get("out")).map { "[\(K042.canon(K042.arr($0)[0])),\(K042.canon(K042.arr($0)[1]))]" }.joined()
            if got != want { bad.append("\(K042.str(c.get("name"))): want \(want) got \(got)") }
        }
        for c in try mapCases("cellof") {
            let a = K042.arr(c.get("args"))
            let r = IntentMap.cellOf(K042.obj(a[0]), resource: a[1], params: a.count > 2 ? a[2] : nil)
            if K042.isNull(c.get("out")) {
                if r != nil { bad.append("\(K042.str(c.get("name"))): want outside, got \(String(describing: r))") }
                continue
            }
            let w = c.get("out")!
            guard let r = r, K042.canon(.array(r.cell.map { .int($0) })) == K042.canon(w.get("cell")), Double(r.flat) == K042.num(w.get("flat")) else {
                bad.append("\(K042.str(c.get("name"))): want \(K042.canon(w)) got \(String(describing: r))")
                continue
            }
        }
        K042.report(bad, 0)
    }

    func testCommitmentAndDecisions() throws {
        var bad: [String] = []
        let td = K042.TextDiffs()
        for c in try mapCases("commit") {
            let got = IntentMap.commit(leaves: K042.arr(c.get("args"))[0])
            if got != c.get("out")?.asString { bad.append("\(K042.str(c.get("name"))): want \(K042.canon(c.get("out"))) got \(String(describing: got))") }
        }
        for c in try mapCases("decide") {
            let o = c.get("out")!
            let r = PCA.intentMapPrimitive(K042.arr(c.get("args"))[0])
            if K042.bool(o.get("ok")) {
                if !r.ok || K042.canon(.array(r.cell.map { .int($0) })) != K042.canon(o.get("cell")) || Double(r.pPpm) != K042.num(o.get("p_ppm")) {
                    bad.append("\(K042.str(c.get("name"))): want \(K042.canon(o)) got ok=\(r.ok) \(r.cell) \(r.pPpm) \(r.reason)")
                }
            } else if r.ok { bad.append("\(K042.str(c.get("name"))): want refused (\(K042.str(o.get("reason")))) got ok") } else { td.add(K042.str(o.get("reason")), r.reason, K042.str(c.get("name"))) }
        }
        td.finish("map decisions")
        K042.report(bad, 0)
    }

    func testClassifierDecisionsAndSignature() throws {
        var bad: [String] = []
        let td = K042.TextDiffs()
        for c in try mapCases("classify") {
            let o = c.get("out")!
            let input = K042.arr(c.get("args"))[0]
            guard input.isObject else { continue } // PCA.intentClassifierPrimitive reads members of an object
            let r = PCA.intentClassifierPrimitive(input)
            if r.ok != K042.bool(o.get("ok")) { bad.append("\(K042.str(c.get("name"))): want ok=\(K042.bool(o.get("ok"))) got \(r.ok) (\(r.reason)) ref \(K042.canon(o.get("reason")))"); continue }
            if r.ok { if K042.canon(r.classes) != K042.canon(o.get("classes")) { bad.append("\(K042.str(c.get("name"))): classes want \(K042.canon(o.get("classes"))) got \(K042.canon(r.classes))") } }
            else { td.add(K042.str(o.get("reason")), r.reason, K042.str(c.get("name"))) }
        }
        td.finish("classifier decisions")
        let a = K042.arr(try mapCases("sigfixture")[0].get("args"))
        let v = K042.obj(a[0]), pk = K042.str(a[1]), other = K042.str(a[2])
        let dom = IntentWB.CLASSIFIER_DOMAIN
        if !IntentWB.verifyArtifactSig(dom, v, pk) { bad.append("the fixture signature must verify under the pinned key") }
        if IntentWB.verifyArtifactSig(dom, v, other) { bad.append("another key verified") }
        if IntentWB.verifyArtifactSig(dom + "x", v, pk) { bad.append("another domain verified") }
        var noSig = v; noSig["sig"] = nil
        var numSig = v; numSig["sig"] = .int(5)
        var lone = v; lone["label"] = .string("a" + String(Canonical.LONE_SURROGATE_SENTINEL))
        // (a version spelled 1.0 is the number 1 after JSON.parse, so it verifies like the reference: no check)
        for (n, m) in [("no sig", noSig), ("numeric sig", numSig), ("lone surrogate", lone)] where IntentWB.verifyArtifactSig(dom, m, pk) { bad.append("\(n) verified") }
        K042.report(bad, 0)
    }

    // ---------------------------------------------------------------- rules 16 / 17 (oracleprov)

    func testOracleProvCorpus() throws {
        let doc = try K042.json("k042-oracleprov.json.gz")
        let cs = K042.arr(doc.get("cases"))
        XCTAssertGreaterThan(cs.count, 1900)
        var bad: [String] = []
        var skipped = 0
        let td = K042.TextDiffs()
        for c in cs {
            let name = K042.str(c.get("name")), kind = K042.str(c.get("kind"))
            var got = "", want = ""
            switch kind {
            case "fn":
                let arg = c.get("arg") ?? .null
                let ok: Bool
                // the validators that give a reason are compared by text too
                var reason: String?? = nil
                switch K042.str(c.get("fn")) {
                case "validateFactWire": ok = IntentWB.validateFactWire(arg)
                case "validateWorldPolicy": reason = .some(IntentWB.validateWorldPolicy(arg)); ok = reason! == nil
                case "validateOfferPolicy": reason = .some(IntentWB.validateOfferPolicy(arg)); ok = reason! == nil
                case "validateOfferSetWire": reason = .some(IntentWB.offerSetWireError(arg)); ok = reason! == nil
                case "validateLabelsWire": ok = IntentWB.validateLabelsWire(arg)
                case "validateFlowRules": reason = .some(IntentWB.flowRulesError(arg)); ok = reason! == nil
                case "validateProvenancePolicy": reason = .some(IntentWB.provenancePolicyError(arg)); ok = reason! == nil
                case "validateProvWire": reason = .some(IntentWB.provWireError(arg)); ok = reason! == nil
                default: skipped += 1; continue
                }
                if let r = reason, let e = r, let w = c.get("want")?.asString { td.add(w, e, name) }
                got = String(ok); want = String(K042.isNull(c.get("want")))
            case "ratio":
                let a = Int64(K042.num(c.get("a"))), b = Int64(K042.num(c.get("b")))
                got = IntentWB.ratioPpm(a, b).map { String($0) } ?? "null"
                want = K042.canon(c.get("want"))
            case "flowRule": skipped += 1; continue // Swift folds the rule lookup into flowAllowed
            case "flowAllowed":
                got = String(IntentWB.flowAllowed(K042.obj(c.get("rules")), K042.str(c.get("cls")), K042.str(c.get("origin")), K042.str(c.get("aud"))))
                want = String(K042.bool(c.get("want")))
            case "active":
                let committed = c.get("committed")
                var cm: JObject = [:]
                if let f = committed?.get("facts") { cm["facts"] = f }
                if let o = committed?.get("offer_set") { cm["offer_set"] = o }
                got = String(IntentWB.worldActive(committed: .object(cm), policy: c.get("policy") ?? .object([:])))
                want = String(K042.bool(c.get("expect")))
            case "read":
                let r = PCA.intentReadPurposePrimitive(c.get("input") ?? .null)
                let e = c.get("expect")
                got = "\(r.outcome)|\(r.minimise)|\(r.uncovered)"
                want = "\(K042.str(e?.get("outcome")))|\(K042.arr(e?.get("minimise")).map { K042.str($0) })|\(K042.arr(e?.get("uncovered")).map { K042.str($0) })"
            case "world":
                let input = c.get("input") ?? .null
                guard input.get("aud")?.asString != nil, input.get("session")?.asString != nil else { skipped += 1; continue }
                let r = PCA.intentWorldPrimitive(input)
                let e = c.get("expect")
                if K042.bool(e?.get("ok")) {
                    want = "ok \(K042.canon(e?.get("world"))) \(K042.canon(e?.get("single_source")))"
                    got = r.ok ? "ok \(K042.canon(r.world)) \(K042.canon(.array((r.singleSource ?? []).map { .string($0) })))" : "fail \(r.reason)"
                } else {
                    want = "fail"; got = r.ok ? "ok" : "fail"
                    if !r.ok { td.add(K042.str(e?.get("reason")), r.reason, name) }
                }
            case "prov":
                let input = c.get("input") ?? .null
                guard input.get("aud")?.asString != nil, input.get("session")?.asString != nil, input.get("action")?.isObject == true else { skipped += 1; continue }
                let r = PCA.intentProvenancePrimitive(input)
                let e = c.get("expect")
                if K042.str(e?.get("outcome")) == "deny" {
                    want = "deny"; got = r.outcome
                    if r.outcome == "deny" { td.add(K042.str(e?.get("reason")), r.reason, name) }
                } else {
                    let lbl = JSONValue.object(Dictionary(uniqueKeysWithValues: r.labels.map { (JKey($0.key), JSONValue.string($0.value)) }))
                    let cls = JSONValue.object(Dictionary(uniqueKeysWithValues: r.classes.map { (JKey($0.key), JSONValue.array($0.value.map { .string($0) })) }))
                    got = [r.outcome, r.friction ?? "null", K042.canon(lbl), K042.canon(cls)].joined(separator: " | ")
                    want = [K042.str(e?.get("outcome")), K042.isNull(e?.get("friction")) ? "null" : K042.str(e?.get("friction")), K042.canon(e?.get("labels")), K042.canon(e?.get("classes"))].joined(separator: " | ")
                }
            default:
                XCTFail("unknown kind \(kind)"); continue
            }
            if got != want { bad.append("\(name)\n    got  \(got.prefix(300))\n    want \(want.prefix(300))") }
        }
        td.finish("oracleprov")
        print("oracleprov: \(skipped) skipped (no Swift counterpart / not expressible)")
        K042.report(bad, cs.count)
    }

    // ---------------------------------------------------------------- the W-B unit (wbmisc)

    func testWbMiscCorpus() throws {
        let cs = K042.arr(try K042.json("k042-wbmisc.json.gz").get("cases"))
        var bad: [String] = []
        var ran = 0, skipped = 0
        let td = K042.TextDiffs()
        for c in cs {
            let name = K042.str(c.get("name"))
            let input = c.get("input") ?? .null
            let exp = c.get("expect")!
            guard let aud = input.get("aud")?.asString, let session = input.get("session")?.asString, let action = input.get("action"), action.isObject,
                  let isess = input.get("intent_session"), isess.isObject else { skipped += 1; continue }
            ran += 1
            // the W-B context shape is the v2 context validator's job (IntentV2.contextError), run before IntentWB.decide
            var wbCtx: JObject = [:]
            if let a = input.get("artifacts") { wbCtx["artifacts"] = a }
            if let p = input.get("policy") { wbCtx["policy"] = p }
            if IntentV2.contextError(.object(["wb": .object(wbCtx)])) != nil {
                if K042.str(exp.get("outcome")) != "deny" || K042.arr(exp.get("checks")).map({ K042.str(K042.arr($0)[0]) }) != ["facts"] {
                    bad.append("\(name): a malformed W-B context must deny on facts, reference \(K042.canon(exp))")
                }
                continue
            }
            let r = IntentWB.decide(now: IV.int(input.get("now")), aud: aud, session: session, action: action, intentSession: isess,
                                    artifacts: input.get("artifacts"), policy: input.get("policy"))
            if r.outcome != K042.str(exp.get("outcome")) { bad.append("\(name): outcome want \(K042.str(exp.get("outcome"))) got \(r.outcome) (\(r.reason ?? ""))"); continue }
            let wantChecks = K042.arr(exp.get("checks")).map { "\(K042.str(K042.arr($0)[0])):\(K042.str(K042.arr($0)[1]))" }
            let gotChecks = r.checks.map { "\($0.0):\($0.1)" }
            if wantChecks != gotChecks { bad.append("\(name): checks want \(wantChecks) got \(gotChecks)"); continue }
            td.add(exp.get("reason")?.asString ?? "", r.reason ?? "", name)
        }
        td.finish("wbmisc")
        print("wbmisc: \(ran) cases run, \(skipped) skipped")
        XCTAssertGreaterThan(ran, 400)
        K042.report(bad, cs.count)
    }
}
