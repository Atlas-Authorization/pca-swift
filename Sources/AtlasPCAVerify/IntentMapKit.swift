import Foundation

/// The Intent Map kit (reference: @atlasauth/pca-intent map.ts and the core intentMapDigest): a learner whose parameters are exactly
/// representable in a map (ppm-quantised), the emitted map (outcome space, learner parameters, observations, per-cell acceptance, the
/// conservative grant and its digest, the fidelity metrics), the parameters a map records, and the replay check that rebuilds the
/// learner from a map and compares every number. The map is plain JSON; probabilities and metrics are integers in parts per million.
public enum PCAIntentMap {
    typealias L = PCAIntentLearner
    static let PPM = 1_000_000.0
    public static let DOMAIN = "atlas-pca/intent-map/v1"
    static let GRANT_DOMAIN = "atlas-pca/intent-grant/v1"

    /// Math.round to an integer; a non-finite or out-of-range value (JSON null in the reference) is 0 here.
    static func rounded(_ x: Double) -> Int64 { let r = WJ.jsRound(x); return r.isFinite && abs(r) < 9e18 ? Int64(r) : 0 }
    static func ppm(_ x: Double) -> Int64 { rounded(x * PPM) }
    static func qz(_ x: Double) -> Double { WJ.jsRound(x * PPM) / PPM }

    static func num(_ o: JSONValue?, _ k: String) throws -> Double? {
        guard let v = o?.get(k), !v.isNull else { return nil }
        guard let d = IV.num(v) else { throw JSError("pca-intent: \(k) must be a number") }
        return d
    }

    static func i(_ n: Int) -> JSONValue { .int(Int64(n)) }
    static func d(_ n: Double) -> JSONValue { WJ.plain(.double(n)) }

    static func nullMassOf(_ o: JSONValue?, _ verb: String) -> Double {
        let nm = o?.get("nullMass")
        if let x = IV.num(nm) { return x }
        if let own = nm?.asObject?[JKey(verb)], let x = IV.num(own) { return x }
        if let x = IV.num(o?.get("defaultNullMass")) { return x }
        return 0.2
    }

    /// Builds a learner whose parameters are exactly representable in an Intent Map.
    public static func createLearner(omega: JSONValue?, options o: JSONValue? = nil) throws -> PCAIntentLearner {
        var opts = try L.Options(json: o)
        let eta = try num(o, "eta")
        opts.eta = qz(eta ?? 0)
        opts.tau = qz(try num(o, "tau") ?? ((eta ?? 0) == 0 ? 1 : 0.95))
        opts.nullMass = nil
        opts.nullMassFn = { qz(nullMassOf(o, $0.verb)) }
        // class: the decay is quantised, a decision list defaults its conditions to boxes
        switch opts.hypothesisClass {
        case .box: break
        case let .union(k, decay): opts.hypothesisClass = .union(k: k, decay: qz(decay ?? 0.25))
        case let .decisionList(r, decay, c): opts.hypothesisClass = .decisionList(maxRules: r, decay: qz(decay ?? 0.25), conditions: c ?? "box")
        }
        func anchor(_ a: L.Anchor) -> L.Anchor {
            L.Anchor(policy: .object(["predicates": a.policy.get("predicates") ?? .null, "caveats": a.policy.get("caveats").flatMap { $0.isNull ? nil : $0 } ?? .array([])]),
                     lambda: WJ.jsRound(a.lambda * 1000) / 1000)
        }
        if let a = opts.anchor { opts.anchor = anchor(a) }
        opts.anchors = opts.anchors.map(anchor)
        if let m = opts.monotone { opts.monotone = (m.paths, qz(m.offMass ?? 0)) }
        if let e = try num(o, "etaPos") { opts.etaPos = qz(e) }
        if let e = try num(o, "etaNeg") { opts.etaNeg = qz(e) }
        if let pm = o?.get("priorMix"), !pm.isNull { opts.priorMix = try priorMixOf(pm) }
        let l = try L(omega: omega, options: opts)
        l.mapParams = o ?? .object([:])
        return l
    }

    /// The learner's priorMix for a data-form population prior: weight(theta) = prod_c q_c^{1[c in theta]} (1 - q_c)^{1[c not in theta]}.
    static func priorMixOf(_ pm: JSONValue) throws -> (beta: Double, weight: (WalletVerb, (Int) -> Bool) throws -> Double) {
        var byVerb: [String: [(cell: Int, lq: Double, lnq: Double)]] = [:]
        for c in pm.get("cells")?.asArray ?? [] {
            guard let verb = c.get("verb")?.asString, let qr = IV.num(c.get("q")), let cell = IV.safe(c.get("cell")) else { throw JSError("pca-intent: priorMix cell") }
            let q = qz(qr)
            guard q >= 0 && q <= 1 && cell >= 0 else { throw JSError("pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0") }
            byVerb[verb, default: []].append((Int(cell), DetMath.detLn(q), DetMath.detLn(1 - q)))
        }
        guard let beta = IV.num(pm.get("beta")) else { throw JSError("pca-intent: priorMix.beta") }
        return (qz(beta), { vs, contains in
            var lw = 0.0
            for t in byVerb[vs.verb] ?? [] { lw += contains(t.cell) ? t.lq : t.lnq }
            return DetMath.detExp(lw)
        })
    }

    // MARK: emit

    public static func omegaToJSON(_ l: PCAIntentLearner) throws -> JSONValue {
        guard let approx = l.omegaApprox else { throw JSError("pca-intent: the outcome space has no approximate list") }
        return omegaToJSON(l.omega, approx)
    }

    /// An object whose members keep the order they are listed in (a JavaScript object's insertion order, which `JSON.stringify` writes).
    private static func ordObj(_ pairs: [(String, JSONValue)]) -> JSONValue {
        var o = JObject()
        for (k, v) in pairs { o[o: k] = v }
        return .object(o)
    }

    /// The map form of an outcome space ({verbs: [{verb, reversibility, w, dims}], approximate}); equal weights are written as 1.
    static func omegaToJSON(_ omega: WalletOmega, _ approx: [String]) -> JSONValue {
        let ws = omega.verbs.map { $0.weight }
        let equal = ws.allSatisfy { abs($0 - ws[0]) < 1e-15 }
        let verbs: [JSONValue] = omega.verbs.map { v in
            let dims: [JSONValue] = v.dims.map { dm in
                if dm.isNum {
                    var m: [(String, JSONValue)] = [("kind", .string("num")), ("path", .string(dm.path)), ("lo", i(dm.lo)), ("hi", i(dm.hi)), ("cuts", .array(dm.cuts.map { i($0) }))]
                    if let dist = dm.dist { m.append(("dist", .string(dist))) }
                    return ordObj(m)
                }
                return ordObj([("kind", .string("cat")), ("path", .string(dm.path)),
                               ("values", .array(dm.values.map { ordObj([("kind", .string($0.kind)), ("value", .string($0.value))]) }))])
            }
            return ordObj([("verb", .string(v.verb)), ("reversibility", .string(v.reversibility)),
                           ("w", equal ? i(1) : .int(max(1, ppm(v.weight)))), ("dims", .array(dims))])
        }
        return ordObj([("verbs", .array(verbs)), ("approximate", .array(approx.map { .string($0) }))])
    }

    static func metricsOf(_ l: PCAIntentLearner) -> JSONValue {
        let m = l.metrics()
        var rmax = 0.0
        for c in l.cells() { rmax += c.mass * (1 - c.p) * c.harm }
        return .object([
            "residual_risk_ppm": .int(ppm(m.residualRisk)), "burden_ppm": .int(ppm(m.burden)), "uncertainty_ppm": .int(ppm(m.uncertainty)),
            "disagreement_ppm": .int(ppm(m.disagreementMass)), "mean_harm_ppm": .int(ppm(m.meanHarm)),
            "fidelity_est_ppm": .int(ppm(rmax > 0 ? 1 - m.residualRisk / rmax : 1)), "entropy_mbits": .int(rounded(m.entropyBits * 1000)),
            "log2_vs_mbits": m.log2VersionSpace.map { .int(rounded($0 * 1000)) } ?? .null,
            "questions": i(m.questions), "conflicts": i(m.conflicts)])
    }

    static func anchorJSON(_ a: JSONValue) throws -> JSONValue {
        guard let lam = IV.num(a.get("lambda")) else { throw JSError("pca-intent: anchor lambda") }
        let pol = a.get("policy")
        var p: JObject = ["caveats": pol?.get("caveats").flatMap { $0.isNull ? nil : $0 } ?? .array([])]
        if let pr = pol?.get("predicates") { p["predicates"] = pr }
        return .object(["policy": .object(p), "lambda_milli": .int(rounded(lam * 1000))])
    }

    public static func grantDigest(_ g: JSONValue?) throws -> String {
        var body: JObject = ["caveats": g?.get("caveats") ?? .array([])]
        if let p = g?.get("predicates") { body["predicates"] = p }
        return try WJ.hash(.object(["d": .string(GRANT_DOMAIN), "g": WJ.plain(.object(body))]))
    }

    /// Content address of an Intent Map (strict canonical, ppm integers).
    public static func digest(_ m: JSONValue) throws -> String { try WJ.hash(.object(["d": .string(DOMAIN), "m": WJ.plain(m)])) }

    /// The map of a learner built with `createLearner`.
    public static func emit(_ l: PCAIntentLearner, intentRef: String? = nil) throws -> JSONValue {
        guard let o = l.mapParams else { throw JSError("pca-intent: build the learner with createLearner() so its parameters are serialisable") }
        var nullMass = JObject()
        for vs in l.omega.verbs { nullMass[JKey(vs.verb)] = .int(ppm(nullMassOf(o, vs.verb))) }
        let grant = l.synthesize()
        var learner: JObject = ["hypothesis_class": .string(PCAIntentLearner.hypothesisClassName(l.hypothesisClass))]
        switch l.hypothesisClass {
        case .box: break
        case let .union(k, decay): learner["class_params"] = .object(["k": d(k), "decay_ppm": .int(ppm(decay ?? 0.25))])
        case let .decisionList(r, decay, _): learner["class_params"] = .object(["max_rules": d(r), "decay_ppm": .int(ppm(decay ?? 0.25))])
        }
        if let s = l.agnosticSlack { learner["agnostic_slack"] = i(s) }
        learner["eta_ppm"] = .int(ppm(l.eta)); learner["tau_ppm"] = .int(ppm(l.tau))
        learner["strategy"] = .string(l.strategy)
        learner["null_mass_ppm"] = .object(nullMass)
        if let a = o.get("anchor"), !a.isNull { learner["anchor"] = try anchorJSON(a) }
        if let a = o.get("anchors")?.asArray, !a.isEmpty { learner["anchors"] = .array(try a.map(anchorJSON)) }
        if let m = o.get("monotone"), !m.isNull {
            learner["monotone"] = .object(["paths": m.get("paths") ?? .array([]), "off_ppm": .int(ppm(IV.num(m.get("offMass")) ?? 0))])
        }
        if (o.get("etaPos").map { !$0.isNull } ?? false) || (o.get("etaNeg").map { !$0.isNull } ?? false) {
            learner["noise"] = .object(["eta_pos_ppm": .int(ppm(l.etaPos)), "eta_neg_ppm": .int(ppm(l.etaNeg))])
        }
        if let pm = o.get("priorMix"), !pm.isNull {
            guard let beta = IV.num(pm.get("beta")) else { throw JSError("pca-intent: priorMix.beta") }
            learner["prior_mix"] = .object(["beta_ppm": .int(ppm(beta)), "cells": .array(try (pm.get("cells")?.asArray ?? []).map { c in
                guard let verb = c.get("verb")?.asString, let cell = c.get("cell"), let q = IV.num(c.get("q")) else { throw JSError("pca-intent: priorMix cell") }
                return .object(["verb": .string(verb), "cell": cell, "q_ppm": .int(ppm(q))])
            })])
        }
        let observations: [JSONValue] = l.observations.map {
            var x: JObject = ["verb": .string($0.verb), "values": $0.values, "y": i($0.y), "source": .string($0.source)]
            if let r = $0.region { x["region"] = r }
            return .object(x)
        }
        let cells: [JSONValue] = l.cells().map { c in
            .object(["verb": .string(c.verb), "cell": .array(c.cell.map { i($0) }), "p_ppm": .int(ppm(c.p)), "in_grant": .bool(c.inGrant)])
        }
        return .object([
            "v": i(1), "kind": .string("pca-intent-map"), "intent_ref": intentRef.map { .string($0) } ?? .null,
            "principals": .array(intentRef.map { [.string($0)] } ?? []), "omega": try omegaToJSON(l), "learner": .object(learner),
            "observations": .array(observations), "cells": .array(cells), "grant": grant, "grant_digest": .string(try grantDigest(grant)), "metrics": metricsOf(l)])
    }

    // MARK: replay

    static func req<T>(_ v: T?, _ what: String) throws -> T { guard let v = v else { throw JSError("pca-intent: map has no usable \(what)") }; return v }

    /// The learner parameters a map records (the inverse of what `emit` writes).
    public static func mapLearnerOptions(_ m: JSONValue) throws -> JSONValue {
        let lr = try req(m.get("learner"), "learner")
        var nullMass = JObject()
        for (k, v) in try req(lr.get("null_mass_ppm")?.asObject, "null_mass_ppm") { nullMass[k] = d(try req(IV.num(v), "null mass") / PPM) }
        let cp = lr.get("class_params")
        let decay = d((IV.num(cp?.get("decay_ppm")) ?? 250_000) / PPM)
        var hc: JSONValue = .object(["kind": .string("box")])
        switch lr.get("hypothesis_class")?.asString {
        case "per-verb-union/v1"?: hc = .object(["kind": .string("union"), "k": cp?.get("k") ?? i(2), "decay": decay])
        case let n? where n == "per-verb-decision-list/v1" || n == "per-verb-decision-list/v2":
            hc = .object(["kind": .string("decision-list"), "maxRules": cp?.get("max_rules") ?? i(2), "decay": decay, "conditions": .string(n == "per-verb-decision-list/v1" ? "atomic" : "box")])
        default: break
        }
        var o: JObject = [
            "eta": d(try req(IV.num(lr.get("eta_ppm")), "eta_ppm") / PPM), "tau": d(try req(IV.num(lr.get("tau_ppm")), "tau_ppm") / PPM),
            "strategy": lr.get("strategy") ?? .null, "nullMass": .object(nullMass), "hypothesisClass": hc]
        if let s = lr.get("agnostic_slack"), !s.isNull { o["agnosticSlack"] = s }
        func anchor(_ a: JSONValue) throws -> JSONValue {
            .object(["policy": a.get("policy") ?? .null, "lambda": d(try req(IV.num(a.get("lambda_milli")), "lambda_milli") / 1000)])
        }
        if let a = lr.get("anchor"), !a.isNull { o["anchor"] = try anchor(a) }
        if let a = lr.get("anchors")?.asArray, !a.isEmpty { o["anchors"] = .array(try a.map(anchor)) }
        if let mo = lr.get("monotone"), !mo.isNull {
            o["monotone"] = .object(["paths": mo.get("paths") ?? .array([]), "offMass": d(try req(IV.num(mo.get("off_ppm")), "off_ppm") / PPM)])
        }
        if let nz = lr.get("noise"), !nz.isNull {
            o["etaPos"] = d(try req(IV.num(nz.get("eta_pos_ppm")), "eta_pos_ppm") / PPM)
            o["etaNeg"] = d(try req(IV.num(nz.get("eta_neg_ppm")), "eta_neg_ppm") / PPM)
        }
        if let pm = lr.get("prior_mix"), !pm.isNull {
            o["priorMix"] = .object(["beta": d(try req(IV.num(pm.get("beta_ppm")), "beta_ppm") / PPM), "cells": .array(try (pm.get("cells")?.asArray ?? []).map { c in
                .object(["verb": c.get("verb") ?? .null, "cell": c.get("cell") ?? .null, "q": d(try req(IV.num(c.get("q_ppm")), "q_ppm") / PPM)])
            })])
        }
        return .object(o)
    }

    /// The outcome space a map records, as an outcome-space object (weights w / total).
    public static func omegaFromJSON(_ j: JSONValue?) throws -> JSONValue {
        let vs = try req(j?.get("verbs")?.asArray, "verbs")
        let tot = try vs.reduce(0.0) { $0 + (try req(IV.num($1.get("w")), "verb weight")) }
        let verbs: [JSONValue] = try vs.map { v in
            var o = try req(v.asObject, "verb")
            o["weight"] = d(try req(IV.num(v.get("w")), "verb weight") / tot)
            o["w"] = nil
            o["dims"] = .array(try (v.get("dims")?.asArray ?? []).map { dm in
                guard var x = dm.asObject else { throw JSError("pca-intent: bad dimension") }
                if x[JKey("kind")]?.asString == "num" { x["cuts"] = x[JKey("cuts")] ?? .array([]); x["dist"] = x[JKey("dist")] ?? .string("uniform") }
                else if case let .array(vals)? = x[JKey("values")], !vals.isEmpty {} // a categorical holds one of its values: with none it holds nothing
                else {
                    throw JSError("omegaFromJSON: categorical dimension '\(x[JKey("path")].map { JS.toString($0) } ?? "undefined")' has no values")
                }
                return .object(x)
            })
            return .object(o)
        }
        return .object(["v": i(1), "verbs": .array(verbs), "approximate": try req(j?.get("approximate"), "approximate")])
    }

    /// Rebuilds the learner a map describes (outcome space, prior, observations).
    public static func learnerFromMap(_ m: JSONValue) throws -> PCAIntentLearner {
        let l = try createLearner(omega: try omegaFromJSON(m.get("omega")), options: try mapLearnerOptions(m))
        for o in try req(m.get("observations")?.asArray, "observations") {
            guard let y = IV.int(o.get("y")) else { throw JSError("pca-intent: observation answer") }
            try l.observe(.object(["verb": o.get("verb") ?? .null, "values": o.get("values") ?? .null]), y: Int(y), source: o.get("source")?.asString ?? "elicitation", region: o.get("region"))
        }
        return l
    }

    /// Replays a single-principal map and checks every number, every cell and the grant.
    public static func verify(_ m: JSONValue?) -> (ok: Bool, problems: [String]) {
        var problems: [String] = []
        guard let m = m, IV.num(m.get("v")) == 1, m.get("kind")?.asString == "pca-intent-map" else { return (false, ["not an intent map v1"]) }
        if (m.get("principals")?.asArray?.count ?? 0) > 1 || (m.get("aggregation").map { JS.truthy($0) } ?? false) {
            return (false, ["combined map: verify each principal map and recombine with verifyAggregate"])
        }
        do {
            let r = try emit(try learnerFromMap(m), intentRef: m.get("intent_ref")?.asString)
            let claimed = m.get("grant_digest")?.asString
            if r.get("grant_digest")?.asString != claimed || (try? grantDigest(m.get("grant"))) != claimed { problems.append("grant does not match the replayed posterior") }
            let rc = r.get("cells")?.asArray ?? [], mc = m.get("cells")?.asArray ?? []
            if rc.count != mc.count { problems.append("cell count differs") }
            else {
                for (idx, c) in rc.enumerated() {
                    let x = mc[idx]
                    guard let p = IV.num(c.get("p_ppm")), let q = IV.num(x.get("p_ppm")), c.get("verb")?.asString == x.get("verb")?.asString,
                          c.get("in_grant") == x.get("in_grant"), abs(p - q) <= 2 else { problems.append("cell \(idx) differs"); continue }
                }
            }
            let keys = ["residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm", "fidelity_est_ppm", "entropy_mbits", "log2_vs_mbits", "questions", "conflicts"]
            for k in keys {
                let a = r.get("metrics")?.get(k), b = m.get("metrics")?.get(k)
                let aNull = a == nil || a == .null, bNull = b == nil || b == .null
                let bad: Bool
                if aNull || bNull { bad = !(aNull && bNull && (a == nil) == (b == nil)) }
                else if let x = IV.num(a), let y = IV.num(b) { bad = !(abs(x - y) <= 2) }
                else { bad = true }
                if bad { problems.append("metric \(k) differs (\(b.map { IntentV2.jsString($0) } ?? "undefined") claimed, \(a.map { IntentV2.jsString($0) } ?? "undefined") replayed)") }
            }
        } catch { problems.append("replay failed: \(error)") }
        return (problems.isEmpty, problems)
    }
}
