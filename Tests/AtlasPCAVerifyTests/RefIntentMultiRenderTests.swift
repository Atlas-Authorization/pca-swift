import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay against the reference (@atlasauth/pca-intent) of multi-principal and cross-organisation aggregation, plain-language
/// rendering with the claim diff and boundary witnesses, signed intent statements, and the Intent Map (emit, verify under tampering,
/// digests, committed form, divergence). A reference throw requires a native refusal. Doubles are compared bit for bit first and within
/// 1e-12 relative otherwise; the count of the latter is printed. The natural-language facade vectors (ref-intent-nl-java) are replayed by
/// the compilers test, which owns PCAIntentCompilers.
final class RefIntentMultiRenderTests: XCTestCase {
    static let tol = 1e-12
    var inexact = 0
    typealias Mut = (inout JObject) -> Void

    func close(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.object(x)?, .object(y)?): return Set(x.keys) == Set(y.keys) && x.allSatisfy { close($0.value, y[$0.key]) }
        case let (.array(x)?, .array(y)?): return x.count == y.count && zip(x, y).allSatisfy { close($0, $1) }
        default:
            if let p = IV.num(a), let q = IV.num(b) {
                if p == q || (p.isNaN && q.isNaN) { return true }
                inexact += 1
                return abs(p - q) <= Self.tol * max(abs(p), abs(q)) + 1e-15
            }
            return Base.canon(a) == Base.canon(b)
        }
    }

    func replay(_ file: String, _ label: String, _ min: Int, seeds: Bool = false, _ body: (BaseCase) throws -> JSONValue) throws {
        inexact = 0
        let d = Base.Diffs()
        try Base.each(file, seeds: seeds) { c in
            let got: BaseGot = Base.run { try body(c) }
            if case let .value(v) = got, !c.threw {
                if close(c.out, v) { d.add(c, nil) }
                else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
            } else { d.add(c, Base.diff(c, got)) }
        }
        print("\(label): \(d.run) cases compared, \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(min)
    }

    // ---- helpers ----

    static func ints(_ v: JSONValue?) throws -> [Int] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { guard let i = IV.int($0) else { throw JSError("not an integer") }; return Int(i) }
    }

    static func list(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return a
    }

    static func opt(_ v: JSONValue?) -> JSONValue? { (v == nil || v == .null) ? nil : v }

    static func addNum(_ o: inout JObject, _ key: String, _ d: Double) { o[JKey(key)] = .int(Int64((IV.num(o[JKey(key)]) ?? 0) + d)) }

    static func upd(_ o: inout JObject, _ key: String, _ f: (inout JObject) -> Void) {
        var c = o[JKey(key)]?.asObject ?? [:]
        f(&c)
        o[JKey(key)] = .object(c)
    }

    static func updCell0(_ o: inout JObject, _ f: (inout JObject) -> Void) {
        var cs = o[JKey("cells")]?.asArray ?? []
        if cs.isEmpty { return }
        var c = cs[0].asObject ?? [:]
        f(&c)
        cs[0] = .object(c)
        o[JKey("cells")] = .array(cs)
    }

    static func flip(_ c: inout JObject) { if case let .bool(b)? = c[JKey("in_grant")] { c[JKey("in_grant")] = .bool(!b) } }

    static func learnerOf(_ omega: JSONValue?, _ opts: JSONValue?, _ obs: JSONValue?) throws -> PCAIntentLearner {
        let l = try PCAIntentMap.createLearner(omega: omega, options: opt(opts))
        for x in try list(obs) {
            guard let y = IV.num(x.get("y")), let src = x.get("source")?.asString else { throw JSError("bad observation") }
            // the reference's `observe(outcome, y, source, region)`
            _ = try l.observe(.object(["verb": x.get("verb") ?? .null, "values": x.get("values") ?? .null]), y: Int(y), source: src, region: IntentTree.present(x.get("region")))
        }
        return l
    }

    static func buildMap(_ omega: JSONValue?, _ opts: JSONValue?, _ obs: JSONValue?, _ ref: JSONValue?) throws -> JSONValue {
        return try PCAIntentMap.emit(try learnerOf(omega, opts, obs), intentRef: opt(ref)?.asString)
    }

    static func maps(_ omega: JSONValue?, _ principals: JSONValue?, _ opts: JSONValue?) throws -> [JSONValue] {
        return try list(principals).map { try buildMap(omega, opts, $0.get("observations"), $0.get("ref")) }
    }

    static func secret(_ seed: Int) -> [UInt8] { (0..<32).map { UInt8(truncatingIfNeeded: seed + 7 * $0) } }

    /// The reference's aggregation functions take an OPTIONS object (`{orgs}`); the oracle hands them its organisation map itself, so only a map with an `orgs` member
    /// names organisations to the reference. The native takes the organisation map directly: it gets what the reference's `opts.orgs` is.
    static func orgsOf(_ v: JSONValue?) -> JSONValue? { opt(opt(v)?.get("orgs")) }

    /// The oracle's problem strings: a replay failure carries engine text, compared as "replay failed"; a recompute failure whose text is not a reference-defined message
    /// is "recompute failed: error"; any other unknown problem is "error".
    static func normProblems(_ v: JSONValue, replayOnly: Bool = false) -> JSONValue {
        guard var o = v.asObject, let ps = o["problems"]?.asArray else { return v }
        let defined = #"^(aggregateIntentMaps|ruleOf|liftIntentMap|crossOrgAggregate|commonRefinement|pca-intent|refineOmega)"#
        o["problems"] = .array(ps.map { (p: JSONValue) -> JSONValue in
            guard var q = p.asString else { return p }
            // the intent-map oracle compares any problem that starts with "replay failed" as "replay failed"; the aggregate oracle strips only up to the first ";"
            if replayOnly { return .string(q.hasPrefix("replay failed") ? "replay failed" : q) }
            q = q.replacingOccurrences(of: #"replay failed: [^;]*"#, with: "replay failed", options: .regularExpression)
            if q.hasPrefix("recompute failed: ") {
                if q.dropFirst("recompute failed: ".count).range(of: defined, options: .regularExpression) == nil { q = "recompute failed: error" }
            } else if q.range(of: #"^(input |aggregate does not|recompute failed|replay failed)"#, options: .regularExpression) == nil, q.range(of: defined, options: .regularExpression) == nil {
                q = "error"
            }
            return .string(q)
        })
        return .object(o)
    }

    // ---- aggregation ----

    static var aggMuts: [Mut] { return [
        { _ in },
        { x in upd(&x, "metrics") { addNum(&$0, "residual_risk_ppm", 7) } },
        { x in updCell0(&x) { flip(&$0) } },
        { x in x[JKey("aggregation")] = .null },
        { x in upd(&x, "aggregation") { $0[JKey("rule")] = .string("quorum"); $0[JKey("k")] = .int(1) } },
        { x in upd(&x, "aggregation") { $0[JKey("vetoers")] = .array([]) } },
    ] }

    func testMultiAggAgainstTheReference() throws {
        try K042.requireCovers(["IntentMulti", "IntentMultiAgg"])
        try replay("ref-intent-multi-agg.json.gz", "intent multi aggregation", 70) { c in
            let a = c.args
            switch c.fn {
            case "aggregateScenario":
                let ms = try Self.maps(a[0], a[1], a[4])
                let orgs = Self.orgsOf(a[3])
                let agg = try PCAIntentMultiAgg.aggregateIntentMaps(ms, a[2], orgs)
                var tampered: [JSONValue] = []
                for f in Self.aggMuts {
                    var copy = WJ.plain(agg).asObject ?? [:]
                    f(&copy)
                    tampered.append(Self.normProblems(PCAIntentMultiAgg.verifyAggregate(.object(copy), ms, orgs)))
                }
                var o: JObject = [
                    "aggregate": agg, "digest": .string(try PCAIntentMap.digest(agg)), "rule": try PCAIntentMultiAgg.ruleOf(agg),
                    "verify": Self.normProblems(PCAIntentMultiAgg.verifyAggregate(agg, ms, orgs)), "tampered": .array(tampered),
                    "wrongInputs": Self.normProblems(PCAIntentMultiAgg.verifyAggregate(agg, Array(ms.prefix(max(0, ms.count - 1))), orgs)),
                ]
                let r = a[2]
                if IV.same(r.get("kind")?.asString, "unanimity") && r.get("vetoers") == nil {
                    o["combined"] = try PCAIntentMultiAgg.combineIntentMaps(ms, orgs)
                } else { o["combined"] = .null }
                return .object(o)
            case "aggregateTwoOmegas":
                let ps = try Self.list(a[2])
                let ms = [try Self.buildMap(a[0], nil, ps[0].get("observations"), ps[0].get("ref")),
                          try Self.buildMap(a[1], nil, .array([]), ps[1].get("ref"))]
                return try PCAIntentMultiAgg.aggregateIntentMaps(ms, a[3], nil)
            case "aggregateOfAggregate":
                let ms = try Self.maps(a[0], a[1], nil)
                let agg = try PCAIntentMultiAgg.aggregateIntentMaps(ms, a[2], nil)
                return try PCAIntentMultiAgg.aggregateIntentMaps([agg, ms[0]], a[2], nil)
            case "liftOfAggregate":
                let ms = try Self.maps(a[0], a[1], nil)
                let agg = try PCAIntentMultiAgg.aggregateIntentMaps(Array(ms.prefix(1)), a[2], nil)
                return try PCAIntentMultiAgg.liftIntentMap(agg, a[0])
            case "crossScenario":
                var ms = try Self.list(a[0]).map { try Self.buildMap($0.get("omega"), $0.get("mapOpts"), $0.get("observations"), $0.get("ref")) }
                // the two-argument case is the oracle's tamper scenario: it adds 9 to map 0's claimed residual risk, and the aggregation must refuse the map
                if a.count == 2, case var .object(m0)? = ms.first {
                    Self.upd(&m0, "metrics") { Self.addNum(&$0, "residual_risk_ppm", 9) }
                    ms[0] = .object(m0)
                }
                let orgs = Self.orgsOf(a.count > 2 ? a[2] : nil) // a case may leave the organisations argument out (undefined)
                let r = try PCAIntentMultiAgg.crossOrgAggregate(ms, a[1], orgs)
                var tampered: [JSONValue] = []
                for f in Self.aggMuts {
                    var copy = WJ.plain(r.aggregate).asObject ?? [:]
                    f(&copy)
                    tampered.append(Self.normProblems(PCAIntentMultiAgg.verifyCrossOrgAggregate(.object(copy), ms, orgs)))
                }
                return .object([
                    "aggregate": r.aggregate, "lifted": .array(r.lifted), "omega": r.omega, "digest": .string(try PCAIntentMap.digest(r.aggregate)),
                    "verify": Self.normProblems(PCAIntentMultiAgg.verifyCrossOrgAggregate(r.aggregate, ms, orgs)), "tampered": .array(tampered),
                    "wrong": Self.normProblems(PCAIntentMultiAgg.verifyCrossOrgAggregate(r.aggregate, Array(ms.dropFirst(min(1, ms.count))), orgs)),
                ])
            case "liftScenario":
                return try PCAIntentMultiAgg.liftIntentMap(try Self.buildMap(a[0], a[1], a[2], a[3]), a[4])
            case "omegaKey": return .string(try PCAIntentMultiAgg.omegaKey(a[0]))
            default: throw JSError("not mapped")
            }
        }
    }

    // ---- render, claim diff, witnesses ----

    static func witness(_ o: JSONValue) throws -> PCAIntentWitnesses.Witness {
        guard let kind = o.get("kind")?.asString, let side = o.get("side")?.asString, let verb = o.get("verb")?.asString,
              case let .bool(allows)? = o.get("grantAllows"), let facet = o.get("facet")?.asString, let q = o.get("question")?.asString else { throw JSError("bad witness") }
        return PCAIntentWitnesses.Witness(kind, side, verb, try ints(o.get("cell")), o.get("outcome") ?? .null, allows, facet, q)
    }

    func testRenderAgainstTheReference() throws {
        try K042.requireCovers(["IntentRender", "IntentWitnesses"])
        try replay("ref-intent-render.json.gz", "intent render", 250) { c in
            let a = c.args
            func omega(_ i: Int) throws -> WalletOmega { try WalletOmega(a[i]) }
            func diffs(_ ds: [PCAIntentRender.ClaimDiff]) -> JSONValue { .array(ds.map { $0.toJson() }) }
            switch c.fn {
            case "renderCondition": return .string(try PCAIntentRender.renderCondition(a[0]))
            case "labelOf":
                guard let s = a[0].asString else { throw JSError("not a string") }
                return .string(PCAIntentRender.labelOf(s))
            case "renderCaveat": return .string(try PCAIntentRender.renderCaveat(a[0]))
            case "renderGrant": return .string(try PCAIntentRender.renderGrant(a[0]))
            case "renderQuestion": return .string(try PCAIntentRender.renderQuestion(try PCAIntentLearner.verbSpace(a[0]), try Self.ints(a[1])))
            case "renderAction": return .string(try PCAIntentRender.renderAction(try PCAIntentLearner.verbSpace(a[0]), a[1]))
            case "claimsOf": return .array(try PCAIntentRender.claimsOf(a[0], try omega(1)).map { $0.toJson() })
            case "backTranslationDiff": return diffs(try PCAIntentRender.backTranslationDiff(a[0], a[1], try omega(2)))
            case "claimDiff":
                if a.count > 3 {
                    let names = try Self.list(a[3])
                    guard let n0 = names[0].asString, let n1 = names[1].asString else { throw JSError("bad names") }
                    return diffs(try PCAIntentRender.claimDiff(a[0], a[1], try omega(2), n0, n1))
                }
                return diffs(try PCAIntentRender.claimDiff(a[0], a[1], try omega(2)))
            case "boundaryWitnesses": return .array(try PCAIntentWitnesses.boundaryWitnesses(a[0], try omega(1)).map { $0.toJson() })
            case "checkWitnesses":
                let ws = try Self.list(a[0]).map { try Self.witness($0) }
                let mode = a[1].asString ?? ""
                let r = PCAIntentWitnesses.checkWitnesses(ws) { w in
                    switch mode {
                    case "agree": return w.grantAllows
                    case "flip": return !w.grantAllows
                    case "flip-boundary": return w.kind == "boundary" ? !w.grantAllows : w.grantAllows
                    default: return w.side == "inside" && w.kind != "unconstrained"
                    }
                }
                return .object(["questions": .int(Int64(r.questions)), "mismatches": .array(r.mismatches.map { $0.toJson() })])
            default: throw JSError("not mapped")
            }
        }
    }

    // ---- statements ----

    func testStatementAgainstTheReference() throws {
        try K042.requireCovers(["IntentStatement"])
        try replay("ref-intent-statement.json.gz", "intent statement", 190, seeds: true) { c in
            let a = c.args
            switch c.fn {
            case "signIntent":
                guard let s = a[1].asString, let seed = Base64URLStrict.decode(s) else { throw JSError("bad seed") }
                return try PCAIntentStatement.signIntent(a[0], seed)
            case "verifyIntent":
                let signer = Self.opt(a[1].get("expectedSigner"))?.asString
                return PCAIntentStatement.verifyIntent(a[0], signer, Self.opt(a[1].get("pqPins"))?.asObject)
            case "intentRef": return .string(try PCAIntentStatement.ref(a[0]))
            case "intentGoal":
                guard let r = a[0].asString else { throw JSError("not a string") }
                return .string(PCAIntentStatement.intentGoal(r, a.count > 1 ? a[1].asString : nil))
            case "parseIntentGoal": return PCAIntentStatement.parseIntentGoal(a[0]) ?? .null
            default: throw JSError("not mapped")
            }
        }
    }

    // ---- map ----

    static var mapMuts: [Mut] { return [
        { _ in },
        { x in upd(&x, "metrics") { addNum(&$0, "residual_risk_ppm", 5) } },
        { x in updCell0(&x) { addNum(&$0, "p_ppm", 3) } },
        { x in updCell0(&x) { flip(&$0) } },
        { x in x[JKey("grant_digest")] = .string("AAAA") },
        { x in
            var o = x[JKey("observations")]?.asArray ?? []
            if !o.isEmpty { o.removeLast() }
            x[JKey("observations")] = .array(o)
        },
        { x in x[JKey("kind")] = .string("x") },
        { x in x[JKey("principals")] = .array([.string("a"), .string("b")]) },
        { x in x[JKey("aggregation")] = .object(["rule": .string("unanimity")]) },
        { x in upd(&x, "metrics") { $0[JKey("log2_vs_mbits")] = nil } },
        { x in upd(&x, "learner") { addNum(&$0, "eta_ppm", 100000) } },
        { x in upd(&x, "metrics") { addNum(&$0, "questions", 1) } },
        { x in
            var c = x[JKey("cells")]?.asArray ?? []
            if !c.isEmpty { c.removeLast() }
            x[JKey("cells")] = .array(c)
        },
        { x in
            upd(&x, "omega") { o in
                var vs = o[JKey("verbs")]?.asArray ?? []
                if !vs.isEmpty {
                    var v0 = vs[0].asObject ?? [:]
                    v0[JKey("w")] = .int(5)
                    vs[0] = .object(v0)
                }
                o[JKey("verbs")] = .array(vs)
            }
        },
        { x in upd(&x, "metrics") { $0[JKey("log2_vs_mbits")] = .null } },
        { x in updCell0(&x) { addNum(&$0, "p_ppm", 2) } },
        { x in updCell0(&x) { addNum(&$0, "p_ppm", 1) } },
    ] }

    static func verdict(_ r: (ok: Bool, problems: [String])) -> JSONValue {
        // the oracle compares a "replay failed: <engine text>" problem as "replay failed"
        return normProblems(.object(["ok": .bool(r.ok), "problems": .array(r.problems.map { JSONValue.string($0) })]), replayOnly: true)
    }

    static func mapScenario(_ a: [JSONValue]) throws -> JSONValue {
        let omega = try WalletOmega(a[0])
        let l = try learnerOf(a[0], a[1], a[2])
        let seed = Int(IV.num(a[4]) ?? 0)
        let map = try PCAIntentMap.emit(l, intentRef: opt(a[3])?.asString)
        var tampered: [JSONValue] = []
        for f in mapMuts {
            var copy = WJ.plain(map).asObject ?? [:]
            f(&copy)
            tampered.append(verdict(PCAIntentMap.verify(.object(copy))))
        }
        tampered.append(verdict(PCAIntentMap.verify(nil)))
        tampered.append(verdict(PCAIntentMap.verify(.object(["v": .int(2)]))))
        let approx: [String] = (try PCAIntentMap.omegaFromJSON(map.get("omega")).get("approximate")?.asArray ?? []).compactMap { $0.asString }
        let back = try WalletOmega(try PCAIntentMap.omegaFromJSON(map.get("omega")))
        var out: JObject = [
            "map": map, "digest": .string(try PCAIntentMap.digest(map)), "grantDigest": .string(try PCAIntentMap.grantDigest(map.get("grant"))),
            "verify": verdict(PCAIntentMap.verify(map)), "tampered": .array(tampered),
            "options": try PCAIntentMap.mapLearnerOptions(map), "omegaRoundtrip": PCAIntentMap.omegaToJSON(back, approx),
        ]
        var commit: JObject = [:]
        do {
            let cm = try PCAIntentMap.commitIntentMap(map, secret(seed))
            commit["map_commit"] = .string(cm.mapCommit)
            commit["size"] = .int(Int64(cm.size))
            commit["leaves"] = cm.leavesJson()
            var ds: [JSONValue] = []
            for vs in omega.verbs {
                let t = WalletOmegaMath.verbCellCount(vs)
                for f in [0, t / 2, t - 1] {
                    let oc = WalletOmegaMath.cellRep(vs, WalletOmegaMath.decodeCell(vs, f))
                    var params: JObject = [:]
                    var resource: JSONValue? = nil
                    for (k, v) in oc.get("values")?.asObject ?? [:] {
                        if IV.same(k.s, "action.resource") { resource = v } else { params[JKey(IV.dropPrefix(k.s, 14))] = v }
                    }
                    ds.append(try cm.disclose(vs.verb, resource, .object(params)))
                }
            }
            commit["disclosures"] = .array(ds)
        } catch {
            commit = ["error": .bool(true)]
        }
        out["commit"] = .object(commit)
        return .object(out)
    }

    func testMapAgainstTheReference() throws {
        try K042.requireCovers(["IntentMapKit", "IntentMapCommit", "IntentMap"])
        try replay("ref-intent-map.json.gz", "intent map", 170) { c in
            let a = c.args
            switch c.fn {
            case "mapScenario": return try Self.mapScenario(a)
            case "commitIntentMap":
                let cm = try PCAIntentMap.commitIntentMap(a[0], Self.secret(3))
                return .object(["map_commit": .string(cm.mapCommit), "size": .int(Int64(cm.size)), "leaves": cm.leavesJson()])
            case "grantDigest": return .string(try PCAIntentMap.grantDigest(a[0]))
            case "intentMapDigest": return .string(try PCAIntentMap.digest(a[0]))
            case "omegaToJSON":
                let approx: [String] = (a[0].get("approximate")?.asArray ?? []).compactMap { $0.asString }
                return PCAIntentMap.omegaToJSON(try WalletOmega(a[0]), approx)
            case "omegaFromJSON": return try PCAIntentMap.omegaFromJSON(a[0])
            case "divergence":
                let l = try Self.learnerOf(a[0], a[1], a[2])
                var out: [JSONValue] = []
                for d in try Self.list(a[3]) {
                    guard let y = IV.num(d.get("y")) else { throw JSError("bad answer") }
                    out.append(try PCAIntentMap.applyDivergence(l, d.get("outcome") ?? .null, Int(y)))
                }
                return .array(out)
            default: throw JSError("not mapped")
            }
        }
    }

    func testCommitRejectsShortSecret() {
        XCTAssertThrowsError(try PCAIntentMapCommit.commitMap([], [:], .object([:]), "x", [UInt8](repeating: 0, count: 31)))
    }
}
