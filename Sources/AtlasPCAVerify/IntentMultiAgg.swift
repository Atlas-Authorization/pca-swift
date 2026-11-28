import Foundation

/// Multi-principal aggregation over replay-verified Intent Maps: the joint grant of a rule (unanimity, quorum, weighted, vetoers) per
/// cell, its recomputation check, and the cross-organisation form that lifts maps over different outcome spaces onto their common
/// refinement first. Maps are plain JSON trees; an outcome space is the weight-form JSON `{v, verbs, approximate}`.
public enum PCAIntentMultiAgg {
    typealias NormalRule = PCAIntentMulti.NormalRule
    static let PPM = 1_000_000.0

    private static func ppm(_ x: Double) -> Double { return WJ.jsRound(x * PPM) }
    private static func num(_ d: Double) -> JSONValue { return WJ.plain(.double(d)) }

    private static func fail(_ what: String) -> JSError { return JSError("pca-intent: \(what)") }

    private static func mp(_ o: JSONValue?) throws -> JObject {
        guard let x = o?.asObject else { throw fail("not an object") }
        return x
    }

    private static func ls(_ o: JSONValue?) throws -> [JSONValue] {
        guard let x = o?.asArray else { throw fail("not an array") }
        return x
    }

    private static func dbl(_ o: JSONValue?) throws -> Double {
        guard let d = IV.num(o) else { throw fail("not a number") }
        return d
    }

    private static func isTrue(_ o: JSONValue?) -> Bool {
        if case let .bool(b)? = o { return b }
        return false
    }

    private static func nullable(_ o: JSONValue?) -> JSONValue { return o ?? .null }

    private static func jsMax(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return Double.nan }
        return a > b ? a : b
    }

    private static func jsMin(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return Double.nan }
        return a < b ? a : b
    }

    /// The error text of an own (reference-defined) failure, else a generic marker for engine-specific faults.
    static func ownMessage(_ e: Error) -> String {
        guard let m = (e as? JSError)?.message else { return "error" }
        for p in ["aggregateIntentMaps", "ruleOf", "liftIntentMap", "crossOrgAggregate", "commonRefinement", "pca-intent", "refineOmega"] where IV.startsWith(m, p) {
            return m
        }
        return "error"
    }

    private static func metric(_ m: JObject, _ k: String) throws -> Double {
        guard let v = m[JKey(k)], !v.isNull else { return 0.0 }
        return try dbl(v)
    }

    private static func nullKey(_ m: JObject, _ k: String) -> Bool {
        if let v = m[JKey(k)] { return v.isNull }
        return false
    }

    private static func worstOf(_ maps: [JSONValue], _ k: String, _ sum: Bool) throws -> Double {
        var acc = sum ? 0.0 : -Double.infinity
        for m in maps {
            let v = try metric(try mp(try mp(m)["metrics"]), k)
            acc = sum ? acc + v : jsMax(acc, v)
        }
        return acc
    }

    /// Aggregate single-principal maps over a shared outcome space under a rule (orgs: intent_ref to organisation label, optional).
    public static func aggregateIntentMaps(_ maps: [JSONValue], _ rule: JSONValue?, _ orgs: JSONValue?) throws -> JSONValue {
        if maps.isEmpty { throw JSError("aggregateIntentMaps: no maps") }
        let first = try mp(maps[0])
        let om = JS.stringify(nullable(first[JKey("omega")]))
        for m in maps {
            if !IV.same(JS.stringify(nullable(try mp(m)[JKey("omega")])), om) {
                throw JSError("aggregateIntentMaps: maps must share Omega (lift them with crossOrgAggregate)")
            }
        }
        for mo in maps {
            let m = try mp(mo)
            let single = (try ls(m[JKey("principals")])).count == 1
            if JS.truthy(m[JKey("aggregation")]) || !single || m[JKey("intent_ref")]?.asString == nil {
                throw JSError("aggregateIntentMaps: every input must be a single-principal map with an intent_ref")
            }
        }
        var refs: [String] = []
        for m in maps { refs.append(try mp(m)[JKey("intent_ref")]?.asString ?? "") }
        if !IV.distinct(refs) { throw JSError("aggregateIntentMaps: duplicate principal") }
        let n: NormalRule = try PCAIntentMulti.normalizeRule(rule, refs)
        let omegaJ = try PCAIntentMap.omegaFromJSON(first[JKey("omega")])
        let omega = try WalletOmega(omegaJ)
        var stats: [(mass: Double, harm: Double)] = []
        for vs in omega.verbs {
            let nc = WalletOmegaMath.verbCellCount(vs)
            for c in 0..<nc { stats.append(WalletOmegaMath.cellStats(vs, WalletOmegaMath.decodeCell(vs, c))) }
        }
        let c0 = try ls(first[JKey("cells")])
        var cells: [JSONValue] = []
        var inGrant: [Bool] = []
        for i in 0..<c0.count {
            let c = try mp(c0[i])
            var ps = [Double](repeating: 0, count: maps.count)
            var ins = [Bool](repeating: false, count: maps.count)
            for k in 0..<maps.count {
                let mc = try ls(try mp(maps[k])[JKey("cells")])
                if i >= mc.count { throw fail("index out of range") }
                let ck = try mp(mc[i])
                ps[k] = try dbl(ck[JKey("p_ppm")]) / PPM
                ins[k] = isTrue(ck[JKey("in_grant")])
            }
            let admits = PCAIntentMulti.ruleAdmits(n, ins)
            inGrant.append(admits)
            cells.append(.object(["verb": nullable(c[JKey("verb")]), "cell": nullable(c[JKey("cell")]),
                                  "p_ppm": num(ppm(PCAIntentMulti.jointAcceptance(n, ps))), "in_grant": .bool(admits)]))
        }
        var predicates: [JSONValue] = []
        var worstRev = -1
        var off = 0
        for vs in omega.verbs {
            let nc = WalletOmegaMath.verbCellCount(vs)
            var allowed = [UInt8](repeating: 0, count: nc)
            var anyIn = false
            for c in 0..<nc {
                if off + c >= inGrant.count { throw fail("index out of range") }
                if inGrant[off + c] { allowed[c] = 1; anyIn = true }
            }
            off += nc
            if !anyIn { continue }
            worstRev = max(worstRev, PCAIntentMulti.sevIndex(vs.reversibility))
            predicates.append(contentsOf: PCAIntentLearner.boxesToPredicates(vs, allowed))
        }
        var caveats: [JSONValue] = []
        if worstRev >= 0 { caveats.append(.object(["type": .string("reversibility_max"), "class": .string(PCAIntentMulti.SEV[worstRev])])) }
        let grant: JSONValue = .object(["predicates": .array(predicates), "caveats": .array(caveats)])
        var pR = [Double](repeating: 0, count: maps.count)
        var pB = [Double](repeating: 0, count: maps.count)
        var pF = [Double](repeating: 0, count: maps.count)
        for i in 0..<maps.count {
            var rr = 0.0
            var bb = 0.0
            var rmax = 0.0
            let mc = try ls(try mp(maps[i])[JKey("cells")])
            for j in 0..<mc.count {
                let p = try dbl(try mp(mc[j])[JKey("p_ppm")]) / PPM
                if j >= stats.count || j >= inGrant.count { throw fail("index out of range") }
                let st = stats[j]
                rmax += st.mass * (1 - p) * st.harm
                if inGrant[j] { rr += st.mass * (1 - p) * st.harm } else { bb += st.mass * p }
            }
            pR[i] = rr
            pB[i] = bb
            pF[i] = rmax > 0 ? 1 - rr / rmax : 1.0
        }
        let kind = rule?.get("kind")
        var agg: JObject = ["rule": nullable(kind)]
        if let k = kind?.asString, IV.same(k, "quorum") { agg["k"] = nullable(rule?.get("k")) }
        if let k = kind?.asString, IV.same(k, "weighted") {
            var w: JObject = [:]
            for i in 0..<refs.count { w[JKey(refs[i])] = num(n.weights[i]) }
            agg["weights"] = .object(w)
            agg["threshold"] = nullable(rule?.get("threshold"))
        }
        var vetoers: [JSONValue] = []
        for i in 0..<refs.count where n.veto[i] { vetoers.append(.string(refs[i])) }
        agg["vetoers"] = .array(vetoers)
        var per: [JSONValue] = []
        var maxR = -Double.infinity
        var maxB = -Double.infinity
        var minF = Double.infinity
        for i in 0..<refs.count {
            var x: JObject = ["intent_ref": .string(refs[i])]
            if let org = orgs?.asObject?[JKey(refs[i])], JS.truthy(org) { x["org"] = org }
            let r = ppm(pR[i])
            let b = ppm(pB[i])
            x["residual_risk_ppm"] = num(r)
            x["burden_ppm"] = num(b)
            per.append(.object(x))
            maxR = jsMax(maxR, r)
            maxB = jsMax(maxB, b)
            minF = jsMin(minF, pF[i])
        }
        agg["per_principal"] = .array(per)
        var anyNull = false
        for m in maps {
            if nullKey(try mp(try mp(m)[JKey("metrics")]), "log2_vs_mbits") { anyNull = true }
        }
        let firstMetrics = try mp(first[JKey("metrics")])
        var metrics: JObject = [:]
        metrics["residual_risk_ppm"] = num(maxR)
        metrics["burden_ppm"] = num(maxB)
        metrics["uncertainty_ppm"] = num(try worstOf(maps, "uncertainty_ppm", false))
        metrics["disagreement_ppm"] = num(try worstOf(maps, "disagreement_ppm", false))
        metrics["mean_harm_ppm"] = nullable(firstMetrics[JKey("mean_harm_ppm")])
        metrics["fidelity_est_ppm"] = num(ppm(minF))
        metrics["entropy_mbits"] = num(try worstOf(maps, "entropy_mbits", true))
        metrics["log2_vs_mbits"] = anyNull ? JSONValue.null : num(try worstOf(maps, "log2_vs_mbits", true))
        metrics["questions"] = num(try worstOf(maps, "questions", true))
        metrics["conflicts"] = num(try worstOf(maps, "conflicts", true))
        var obs: [JSONValue] = []
        for m in maps { obs.append(contentsOf: try ls(try mp(m)[JKey("observations")])) }
        let out: JObject = [
            "v": .int(1), "kind": .string("pca-intent-map"), "intent_ref": .null,
            "principals": .array(refs.map { JSONValue.string($0) }),
            "omega": nullable(first[JKey("omega")]), "learner": nullable(first[JKey("learner")]),
            "observations": .array(obs), "cells": .array(cells), "grant": grant,
            "grant_digest": .string(try PCAIntentMap.grantDigest(grant)),
            "metrics": .object(metrics), "aggregation": .object(agg),
        ]
        return .object(out)
    }

    /// The unanimity rule: the joint grant is the intersection of the principals' conservative grants.
    public static func combineIntentMaps(_ maps: [JSONValue], _ orgs: JSONValue?) throws -> JSONValue {
        return try aggregateIntentMaps(maps, .object(["kind": .string("unanimity")]), orgs)
    }

    /// The rule an aggregated map records.
    public static func ruleOf(_ aggMap: JSONValue?) throws -> JSONValue {
        let ao = try mp(aggMap)[JKey("aggregation")]
        if !JS.truthy(ao) { throw JSError("ruleOf: not an aggregated map") }
        let a = try mp(ao)
        var r: JObject = [:]
        if let k = a[JKey("rule")]?.asString, IV.same(k, "unanimity") {
            r["kind"] = .string("unanimity")
        } else if let k = a[JKey("rule")]?.asString, IV.same(k, "quorum") {
            r["kind"] = .string("quorum")
            r["k"] = nullable(a[JKey("k")])
        } else {
            r["kind"] = .string("weighted")
            r["weights"] = nullable(a[JKey("weights")])
            r["threshold"] = nullable(a[JKey("threshold")])
        }
        r["vetoers"] = nullable(a[JKey("vetoers")])
        return .object(r)
    }

    private static func result(_ ok: Bool, _ problems: [String]) -> JSONValue {
        return .object(["ok": .bool(ok), "problems": .array(problems.map { JSONValue.string($0) })])
    }

    private static func problemText(_ problems: [String]) -> String { return problems.joined(separator: "; ") }

    /// Verify an aggregated map against its inputs: replay-verify each input, recompute the aggregate and compare digests.
    public static func verifyAggregate(_ agg: JSONValue?, _ inputs: [JSONValue], _ orgs: JSONValue?) -> JSONValue {
        var problems: [String] = []
        do {
            for i in 0..<inputs.count {
                let r = PCAIntentMap.verify(inputs[i])
                if !r.ok { problems.append("input \(i): \(problemText(r.problems))") }
            }
            if !problems.isEmpty { return result(false, problems) }
            let again = try aggregateIntentMaps(inputs, try ruleOf(agg), orgs)
            if try PCAIntentMap.digest(again) != PCAIntentMap.digest(try agg.orThrow()) { problems.append("aggregate does not match its recomputation") }
        } catch {
            problems.append("recompute failed: " + ownMessage(error))
        }
        return result(problems.isEmpty, problems)
    }

    // MARK: lift

    /// `Region.fromJson(r).toJson()`: the normal form of a region.
    static func regionNormal(_ r: JSONValue) throws -> JSONValue {
        let m = try mp(r)
        guard let verb = m[JKey("verb")]?.asString else { throw fail("region verb") }
        var dims: JObject = [:]
        for (k, v) in try mp(m[JKey("dims")]) {
            let d = try mp(v)
            if let kind = d[JKey("kind")]?.asString, IV.same(kind, "num") {
                dims[k] = .object(["kind": .string("num"), "lo": num(try dbl(d[JKey("lo")])), "hi": num(try dbl(d[JKey("hi")]))])
            } else {
                var values: [JSONValue] = []
                for x in try ls(d[JKey("values")]) {
                    let xm = try mp(x)
                    guard let xk = xm[JKey("kind")]?.asString, let xv = xm[JKey("value")]?.asString else { throw fail("region value") }
                    values.append(.object(["kind": .string(xk), "value": .string(xv)]))
                }
                var cells: [JSONValue] = []
                for c in try ls(d[JKey("cells")]) { cells.append(.int(Int64(try dbl(c)))) }
                dims[k] = .object(["kind": .string("cat"), "values": .array(values), "cells": .array(cells)])
            }
        }
        return .object(["verb": .string(verb), "dims": .object(dims)])
    }

    /// The value-space region of one cell.
    static func regionOfCell(_ vs: WalletVerb, _ idx: [Int]) -> JSONValue {
        var dims: JObject = [:]
        for (k, d) in vs.dims.enumerated() {
            if d.isNum {
                let c = WalletOmegaMath.numCells(d)[idx[k]]
                dims[JKey(d.path)] = .object(["kind": .string("num"), "lo": .int(Int64(c.lo)), "hi": .int(Int64(c.hi))])
            } else {
                dims[JKey(d.path)] = .object(["kind": .string("cat"),
                                              "values": .array(d.values.map { JSONValue.object(["kind": .string($0.kind), "value": .string($0.value)]) }),
                                              "cells": .array([.int(Int64(idx[k]))])])
            }
        }
        return .object(["verb": .string(vs.verb), "dims": .object(dims)])
    }

    /// Lift a replay-verified single-principal map onto a refinement of its outcome space (unseen verbs are denied: null mass 1).
    /// `target` is the weight-form outcome-space JSON.
    public static func liftIntentMap(_ mapO: JSONValue?, _ target: JSONValue) throws -> JSONValue {
        let m = try mp(mapO)
        let principals = m[JKey("principals")]?.asArray
        if JS.truthy(m[JKey("aggregation")]) || (principals?.count ?? 0) > 1 {
            throw JSError("liftIntentMap: lift single-principal maps, then aggregate")
        }
        let src = try WalletOmega(try PCAIntentMap.omegaFromJSON(m[JKey("omega")]))
        let tgt = try WalletOmega(target)
        let o = try PCAIntentMap.mapLearnerOptions(.object(m))
        var nullMass: JObject = [:]
        for vs in tgt.verbs {
            let own = IV.num(o.get("nullMass")?.asObject?[JKey(vs.verb)])
            let known = src.verbs.contains { IV.same($0.verb, vs.verb) }
            nullMass[JKey(vs.verb)] = PCAIntentMap.d(known ? (own ?? 0.2) : 1.0)
        }
        var o2 = try mp(o)
        o2[JKey("nullMass")] = .object(nullMass)
        let l = try PCAIntentMap.createLearner(omega: target, options: .object(o2))
        for obo in try ls(m[JKey("observations")]) {
            let ob = try mp(obo)
            guard let verb = ob[JKey("verb")]?.asString else { throw fail("observation verb") }
            guard let svs = src.verb(verb), let tvs = tgt.verb(verb) else { throw JSError("liftIntentMap: verb \(verb) missing from Omega") }
            let own = try mp(ob[JKey("values")])
            var values = own
            for d in tvs.dims {
                if values[JKey(d.path)] == nil { values[JKey(d.path)] = WalletOmegaMath.repValue(d, 0) }
            }
            guard let cell = WalletOmegaMath.cellOf(svs, values: .object(own)) else {
                throw JSError("liftIntentMap: an observation of \(verb) lies outside the map's own Omega")
            }
            let region: JSONValue
            if let r = ob[JKey("region")], !r.isNull { region = try regionNormal(r) } else { region = regionOfCell(svs, cell) }
            let y = try dbl(ob[JKey("y")])
            guard let source = ob[JKey("source")]?.asString else { throw fail("observation source") }
            _ = try l.observe(.object(["verb": .string(verb), "values": .object(values)]), y: Int(y), source: source, region: region)
        }
        let ir = m[JKey("intent_ref")]
        var ref: String? = nil
        if let r = ir, !r.isNull {
            guard let s = r.asString else { throw fail("intent_ref") }
            ref = s
        }
        return try PCAIntentMap.emit(l, intentRef: ref)
    }

    /// The aggregate, the lifted maps and the common refinement of a cross-organisation aggregation.
    public struct CrossOrg {
        public let aggregate: JSONValue
        public let lifted: [JSONValue]
        public let omega: JSONValue
    }

    /// Replay-verify every map, lift them all onto the common refinement of their spaces, then aggregate.
    public static func crossOrgAggregate(_ maps: [JSONValue], _ rule: JSONValue?, _ orgs: JSONValue?) throws -> CrossOrg {
        for i in 0..<maps.count {
            let r = PCAIntentMap.verify(maps[i])
            if !r.ok { throw JSError("crossOrgAggregate: map \(i) does not verify: \(problemText(r.problems))") }
        }
        var omegas: [JSONValue] = []
        for m in maps { omegas.append(try PCAIntentMap.omegaFromJSON(try mp(m)[JKey("omega")])) }
        let omega = try PCAIntentMulti.commonRefinement(omegas)
        var lifted: [JSONValue] = []
        for m in maps { lifted.append(try liftIntentMap(m, omega)) }
        return CrossOrg(aggregate: try aggregateIntentMaps(lifted, rule, orgs), lifted: lifted, omega: omega)
    }

    /// Verify a cross-org aggregate by recomputing it from the original maps.
    public static func verifyCrossOrgAggregate(_ agg: JSONValue?, _ maps: [JSONValue], _ orgs: JSONValue?) -> JSONValue {
        do {
            let again = try crossOrgAggregate(maps, try ruleOf(agg), orgs).aggregate
            if try PCAIntentMap.digest(again) == PCAIntentMap.digest(try agg.orThrow()) { return result(true, []) }
            return result(false, ["aggregate does not match its recomputation"])
        } catch {
            return result(false, [ownMessage(error)])
        }
    }

    /// The outcome space as canonical-order JSON text (for callers that compare maps).
    public static func omegaKey(_ omega: JSONValue) throws -> String {
        let o = try WalletOmega(omega)
        let approx: [String] = (omega.get("approximate")?.asArray ?? []).compactMap { $0.asString }
        return JS.stringify(PCAIntentMap.omegaToJSON(o, approx))
    }
}

private extension Optional where Wrapped == JSONValue {
    func orThrow() throws -> JSONValue {
        guard let v = self else { throw JSError("pca-intent: missing value") }
        return v
    }
}
