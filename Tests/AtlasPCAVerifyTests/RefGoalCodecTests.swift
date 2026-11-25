import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A positional argument (null when the case carries fewer).
private func arg(_ c: BaseCase, _ i: Int) -> JSONValue { return c.arg(i) ?? JSONValue.null }

/// Differential replay of the goal core (tape codec, digests, normalize, fmt, policy digest, binding, signing) against the reference
/// oracle, plus the typed layer (typecheck, compile, decide through the kernel) over the shared goal conformance vectors. A reference
/// throw requires a native refusal. The card and the reference semantics of the same corpus belong to their own modules and are not
/// replayed here (counted and printed).
final class RefGoalCodecTests: XCTestCase {
    static let file = "ref-goal.json.gz"
    static let other: Set<String> = ["renderCard", "renderCond", "refExplain", "refDecide"]

    private func obj(_ v: JSONValue?) throws -> JSONValue {
        guard let x = v, x.isObject else { throw JSError("object expected") }
        return x
    }
    private func arr(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("array expected") }
        return a
    }
    private func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("string expected") }
        return s
    }
    private func dbl(_ v: JSONValue?) throws -> Double {
        guard let d = IV.num(v) else { throw JSError("number expected") }
        return d
    }
    private func seed(_ v: JSONValue?) throws -> [UInt8] {
        guard let b = Base64URLStrict.decode(try str(v)) else { throw JSError("seed expected") }
        return b
    }

    private func replay(_ fns: [String], _ f: @escaping (BaseCase) throws -> JSONValue) throws {
        let d = Base.Diffs()
        let n = try Base.each(Self.file, Set(fns), seeds: true) { (c: BaseCase) throws -> Void in
            d.add(c, Base.diff(c, Base.run { try f(c) }))
        }
        XCTAssertGreaterThan(n, 0, "no cases of \(fns)")
        d.finish(1)
    }

    func testTapeCodec() throws {
        try replay(["encodeGoal"]) { c in try PCAGoalCodec.encodeGoal(arg(c, 0)) }
        try replay(["decodeGoal"]) { c in try PCAGoalCodec.decodeGoal(arg(c, 0)) }
        try replay(["encodeOntology"]) { c in try PCAGoalCodec.encodeOntology(arg(c, 0)) }
        try replay(["encodeAct"]) { c in try PCAGoalCodec.encodeAct(arg(c, 0)) }
        try replay(["encodeHist"]) { c in try PCAGoalCodec.encodeHist(arg(c, 0)) }
        try replay(["decodePolicy"]) { c in try PCAGoalCodec.decodePolicy(arg(c, 0)) }
    }

    func testDigestsNormalizeAndFmt() throws {
        try replay(["goalDigest"]) { c in JSONValue.string(try PCAGoalDigests.goalDigest(arg(c, 0))) }
        try replay(["nlDigest"]) { c in JSONValue.string(try PCAGoalDigests.nlDigest(try self.str(arg(c, 0)))) }
        try replay(["modelSetDigest"]) { c in
            JSONValue.string(try PCAGoalDigests.modelSetDigest(try self.arr(arg(c, 0)).map { try self.str($0) }))
        }
        try replay(["approvalDigest"]) { c in JSONValue.string(try PCAGoalDigests.approvalDigest(arg(c, 0))) }
        try replay(["canonicalizeGoal"]) { c in try PCAGoalNormalize.canonicalizeGoal(arg(c, 0)) }
        try replay(["stable"]) { c in JSONValue.string(PCAGoalNormalize.stable(arg(c, 0))) }
        try replay(["fmtMoney"]) { c in JSONValue.string(PCAGoalFmt.fmtMoney(try self.str(arg(c, 0)), c.arg(1))) }
        try replay(["fmtQuantity"]) { c in JSONValue.string(try PCAGoalFmt.fmtQuantity(try self.obj(arg(c, 0)))) }
        try replay(["fmtValue"]) { c in JSONValue.string(try PCAGoalFmt.fmtValue(try self.obj(arg(c, 0)))) }
        try replay(["fmtAct"]) { c in JSONValue.string(try PCAGoalFmt.fmtAct(try self.obj(arg(c, 0)))) }
        try replay(["canonicalPolicy"]) { c in JSONValue.string(PCAGoalCompiler.canonicalPolicy(try self.obj(arg(c, 0)))) }
        try replay(["policyDigest"]) { c in JSONValue.string(PCAGoalCompiler.policyDigest(try self.obj(arg(c, 0)))) }
    }

    func testBinding() throws {
        try replay(["actionDigest"]) { c in JSONValue.string(try PCAGoalBinding.actionDigest(try self.obj(arg(c, 0)))) }
        try replay(["bindDecision"]) { c in try PCAGoalBinding.bindDecision(try self.obj(arg(c, 0)), try self.str(arg(c, 1))) }
        try replay(["guardExecute"]) { c in JSONValue.bool(PCAGoalBinding.guardExecute(arg(c, 0), arg(c, 1))) }
        try replay(["claimGate"]) { c in
            var replayed: Double? = nil
            if !arg(c, 2).isNull { replayed = try self.dbl(arg(c, 2)) }
            return JSONValue.string(PCAGoalBinding.claimGate(try self.str(arg(c, 0)), try self.dbl(arg(c, 1)), replayed))
        }
        try replay(["goalCommit"]) { c in
            JSONValue.string(PCAGoalBinding.goalCommit(try self.str(arg(c, 0)), try self.str(arg(c, 1)), try self.str(arg(c, 2))))
        }
        try replay(["openCommit"]) { c in
            JSONValue.bool(PCAGoalBinding.openCommit(try self.str(arg(c, 0)), try self.str(arg(c, 1)), try self.str(arg(c, 2)), try self.str(arg(c, 3))))
        }
    }

    func testSigning() throws {
        // deterministic RFC 8032 signing so the signature bytes equal the reference's
        try replay(["signPayloadSeed"]) { c in
            let key = try Ed25519Deterministic.key(seed: try self.seed(arg(c, 2)))
            return try PCAGoalSign.signPayload(try self.str(arg(c, 0)), arg(c, 1), key, PCASuiteKey.ed25519(key))
        }
        try replay(["signGoalArtifactSeed"]) { c in
            let key = try Ed25519Deterministic.key(seed: try self.seed(arg(c, 2)))
            return try PCAGoalSign.signGoalArtifact(try self.str(arg(c, 0)), try self.obj(arg(c, 1)), PCASuiteKey.ed25519(key))
        }
        try replay(["signerId"]) { c in JSONValue.string(try PCAGoalSign.signerId(try self.seed(arg(c, 0)))) }
        try replay(["goalDomain"]) { c in JSONValue.string(PCAGoalSign.goalDomain(try self.str(arg(c, 0)))) }
        try replay(["verifyPayload"]) { c in
            JSONValue.bool(PCAGoalSign.verifyPayload(arg(c, 0).isObject ? arg(c, 0) : nil, try self.str(arg(c, 1)), try self.arr(arg(c, 2))))
        }
        try replay(["verifyGoalArtifact"]) { c in
            JSONValue.bool(PCAGoalSign.verifyGoalArtifact(try self.str(arg(c, 0)), arg(c, 1), try self.str(arg(c, 2)), try self.arr(arg(c, 3))))
        }
    }

    /// The seed-signing overloads (platform signer; the signature may differ per call) produce artifacts that verify under the pin
    /// and not under another kind or a tampered body.
    func testSeedSignedArtifactVerifies() throws {
        let seed = Canonical.sha256(Array("atlas-pca-conformance/goal/s1".utf8))
        let id = try PCAGoalSign.signerId(seed)
        let signed = try PCAGoalSign.signPayload("goal-tests", JSONValue.object(["t": JSONValue.array([JSONValue.int(1)])]), seed)
        XCTAssertTrue(PCAGoalSign.verifyPayload(signed, "goal-tests", [JSONValue.string(id)]))
        XCTAssertFalse(PCAGoalSign.verifyPayload(signed, "other", [JSONValue.string(id)]))
        XCTAssertFalse(PCAGoalSign.verifyGoalArtifact("approval", signed, "signer", [JSONValue.string(id)]))
        XCTAssertFalse(PCAGoalSign.verifyPayload(signed, "goal-tests", []))
        guard case var .object(o) = signed else { return XCTFail("object expected") }
        o[JKey("payload")] = JSONValue.object(["t": JSONValue.array([JSONValue.int(2)])])
        XCTAssertFalse(PCAGoalSign.verifyPayload(JSONValue.object(o), "goal-tests", [JSONValue.string(id)]))
        let pinned: JSONValue = JSONValue.object(["pk": JSONValue.string(id)])
        XCTAssertTrue(PCAGoalSign.verifyPayload(signed, "goal-tests", [pinned]))
    }

    func testCorpusFunctionsOfOtherModulesAreCounted() throws {
        let n = try Base.each(Self.file, Self.other) { (_: BaseCase) throws -> Void in }
        print("ref-goal: \(n) cases of \(Self.other.sorted()) are replayed by their own modules")
    }

    // ---- the typed layer over the shared vectors (kernel dependent) ----

    private func canon(_ v: JSONValue?) -> String { return Base.canon(v) }

    func testTypedLayerReplaysTheSharedVectors() throws {
        let dir = GoalVectorTests.goalDir
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".json") && $0 != "index.json" }.sorted()
        var bad: [String] = []
        var vectors = 0
        var probes = 0
        var skippedFn = 0
        for name in names {
            let v = try StrictJSON.parseLenient(ConformanceTests.readText(dir.appendingPathComponent(name)))
            let kind = v.get("kind")?.asString ?? ""
            if kind == "fn" { skippedFn += 1; continue }
            guard kind == "gen" || kind == "ill" || kind == "w" else { bad.append("\(name): unknown kind \(kind)"); continue }
            vectors += 1
            let id = v.get("id")?.asString ?? name
            guard let goal = v.get("goal"), let ont = v.get("ontology"), let comp = v.get("compile") else { bad.append("\(id): malformed vector"); continue }
            let compileOk = comp.get("ok") == JSONValue.bool(true)
            do {
                let gd = try PCAGoalDigests.goalDigest(goal)
                if gd != v.get("goal_digest")?.asString { bad.append("\(id): goal_digest") }
                let reasons = try PCAGoalCompiler.typecheck(goal, ont)
                let want = canon(comp.get("reasons"))
                if canon(JSONValue.array(reasons.map { JSONValue.string($0) })) != want { bad.append("\(id): typecheck reasons \(reasons) != \(want)") }
                let cr = try PCAGoalCompiler.compileGoal(goal, ont)
                let crOk = cr.get("ok") == JSONValue.bool(true)
                if crOk != compileOk { bad.append("\(id): compile ok \(crOk) != \(compileOk)") }
                if crOk {
                    if let p = cr.get("policy") {
                        if PCAGoalCompiler.policyDigest(p) != v.get("policy_digest")?.asString { bad.append("\(id): policy_digest") }
                    } else { bad.append("\(id): no policy") }
                } else {
                    if canon(cr.get("reasons")) != want { bad.append("\(id): compile reasons \(canon(cr.get("reasons"))) != \(want)") }
                    if let pd = v.get("policy_digest"), !pd.isNull { bad.append("\(id): policy_digest must be null for a rejected goal") }
                }
                for (i, p) in (v.get("probes")?.asArray ?? []).enumerated() {
                    probes += 1
                    guard let act = p.get("action"), let hist = p.get("history"), let expect = p.get("expect") else { bad.append("\(id)#\(i): malformed probe"); continue }
                    let dp = try PCAGoalCompiler.decidePolicy(goal, ont, act, hist)
                    if compileOk {
                        let decision = dp.get("decision")?.asString ?? ""
                        let got = GV.obj([("decision", JSONValue.string(decision)), ("witness", dp.get("witness") ?? JSONValue.null)])
                        if dp.get("ok") != JSONValue.bool(true) || canon(got) != canon(expect) { bad.append("\(id)#\(i): \(canon(got)) != \(canon(expect))") }
                        if decision == "allow" && dp.get("witnessChecked") != JSONValue.bool(true) { bad.append("\(id)#\(i): witness not checked") }
                        // the reference semantics D_G keeps every grant; a goal with holes compiles to its most restrictive completion (GoalCompile.dfy Strip drops each grant a hole
                        // touches), so the policy decides what the goal without those grants decides
                        var completion = goal
                        let holes = goal.get("holes")?.asArray ?? []
                        if !holes.isEmpty, case var .object(go) = goal {
                            let dropAll = holes.contains { $0.get("global") == JSONValue.bool(true) }
                            let touched = Set(holes.flatMap { ($0.get("affects")?.asArray ?? []).compactMap { $0.asString } })
                            go[JKey("grants")] = JSONValue.array((goal.get("grants")?.asArray ?? []).filter { !dropAll && !touched.contains($0.get("gid")?.asString ?? "") })
                            go[JKey("holes")] = JSONValue.array([])
                            completion = JSONValue.object(go)
                        }
                        let dg = try PCAGoalCompiler.decideGoal(completion, ont, act, hist)
                        if dg != decision { bad.append("\(id)#\(i): decideGoal \(dg) != decidePolicy \(decision)") }
                    } else if dp.get("ok") != JSONValue.bool(false) || canon(expect) != canon(GV.obj([("decision", JSONValue.string("deny")), ("witness", JSONValue.null)])) {
                        bad.append("\(id)#\(i): a rejected goal must deny with no witness")
                    }
                }
            } catch {
                bad.append("\(id): threw \(error)")
            }
        }
        print("typed layer: \(vectors) vectors, \(probes) probes, \(skippedFn) fn vectors left to the runner replay")
        XCTAssertGreaterThanOrEqual(vectors, 200)
        XCTAssertGreaterThan(probes, 1000)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) disagreements:\n" + bad.prefix(30).joined(separator: "\n"))
    }
}
