import Foundation

/// Dimensions beyond the action's own parameters: world state (an observed quantity such as slack against an optimum), argument
/// provenance, and classifier labels. Each lives under its own path prefix; an outcome is lifted onto them from an environment of
/// observed values.
public enum PCAIntentWorld {
    public static let WORLD_PREFIX = "env.world."
    public static let PROV_PREFIX = "env.prov."
    public static let CLASS_PREFIX = "env.class."

    /// A numeric world dimension; `cuts` may be nil, `dist` nil = uniform.
    public static func worldDim(_ name: String, _ lo: Double, _ hi: Double, _ cuts: [Double]?, _ dist: String?) -> PCAIntentOmega.NumDim {
        var uniq: [Double] = []
        var seen: Set<UInt64> = []
        var sawNaN: Bool = false
        for c0 in (cuts ?? []) {
            let c: Double = c0 + 0.0
            if c.isNaN { if !sawNaN { sawNaN = true; uniq.append(c) }; continue }
            if seen.insert(c.bitPattern).inserted { uniq.append(c) }
        }
        let kept: [Double] = uniq.filter { $0 >= lo && $0 <= hi }
        return PCAIntentOmega.NumDim(WORLD_PREFIX + name, lo, hi, PCAIntentOmega.sortedNums(kept), dist ?? "uniform")
    }

    /// Excess over an optimum: cut at 0 and at each slack, log-uniform.
    public static func excessDim(_ name: String, _ hi: Double, _ slacks: [Double]?) -> PCAIntentOmega.NumDim {
        var cuts: [Double] = [0.0]
        if let s = slacks { cuts.append(contentsOf: s) }
        return worldDim(name, 0.0, hi, cuts, "loguniform")
    }

    /// The condition "the observed quantity is at most the slack".
    public static func optimalityCondition(_ name: String, _ slack: Double = 0.0) -> JSONValue {
        return JSONValue.object([JKey("field"): JSONValue.string(WORLD_PREFIX + name), JKey("op"): JSONValue.string("lte"), JKey("value"): PCAIntentOmega.jn(slack)])
    }

    public static func provenanceDim(_ paramPath: String) -> PCAIntentOmega.CatDim {
        return PCAIntentOmega.CatDim(PROV_PREFIX + paramPath, [PCAIntentOmega.CatValue("exact", "first_party"), PCAIntentOmega.CatValue("exact", "trusted"),
                                                              PCAIntentOmega.CatValue("other", PCAIntentOmega.OTHER)])
    }

    public static func classifierDim(_ id: String, _ labels: [String]) -> PCAIntentOmega.CatDim {
        var sorted: [String] = []
        for l in labels.sorted(by: { IV.utf8Less($0, $1) }) {
            if let last = sorted.last, IV.same(last, l) { continue }
            sorted.append(l)
        }
        var v: [PCAIntentOmega.CatValue] = sorted.map { PCAIntentOmega.CatValue("exact", $0) }
        v.append(PCAIntentOmega.CatValue("other", PCAIntentOmega.OTHER))
        return PCAIntentOmega.CatDim(CLASS_PREFIX + id, v)
    }

    /// The space with `dims` added to one verb (a duplicate path throws), dimensions re-sorted by path (UTF-16 order, stable).
    public static func withDims(_ omega: PCAIntentOmega.Omega, _ verb: String, _ dims: [PCAIntentOmega.Dim]) throws -> PCAIntentOmega.Omega {
        var verbs: [PCAIntentOmega.VerbSpace] = []
        var found: Bool = false
        for vs in omega.verbs {
            if !IV.same(vs.verb, verb) {
                verbs.append(PCAIntentOmega.VerbSpace(vs.verb, vs.reversibility, vs.weight, vs.dims))
                continue
            }
            found = true
            var have: Set<JKey> = []
            for d in vs.dims { have.insert(JKey(d.path)) }
            for d in dims where have.contains(JKey(d.path)) { throw JSError("withDims: \(verb) already has a dimension \(d.path)") }
            var all: [PCAIntentOmega.Dim] = vs.dims
            all.append(contentsOf: dims)
            let order: [(Int, PCAIntentOmega.Dim)] = all.enumerated().map { ($0.offset, $0.element) }
            let sortedAll: [(Int, PCAIntentOmega.Dim)] = order.sorted { (a, b) -> Bool in
                if WJ.u16Less(a.1.path, b.1.path) { return true }
                if WJ.u16Less(b.1.path, a.1.path) { return false }
                return a.0 < b.0
            }
            verbs.append(PCAIntentOmega.VerbSpace(vs.verb, vs.reversibility, vs.weight, sortedAll.map { $0.1 }))
        }
        if !found { throw JSError("withDims: no verb \(verb) in the space") }
        return PCAIntentOmega.Omega(verbs, omega.approximate)
    }

    private static func walk(_ root: JSONValue?, _ segs: [String]) -> JSONValue? {
        var cur: JSONValue? = root
        for s in segs {
            guard let o = cur?.asObject, let n = o[JKey(s)] else { return nil }
            cur = n
        }
        return cur
    }

    /// Lift an outcome onto the world / provenance / classifier dimensions from the environment {world?, prov?, class?}.
    public static func liftOutcome(_ o: PCAIntentOmega.Outcome, _ env: JObject, _ dimPaths: [String]) -> PCAIntentOmega.Outcome {
        var values: JObject = o.values
        for p in dimPaths {
            if IV.startsWith(p, WORLD_PREFIX) {
                let v: JSONValue? = walk(env[JKey("world")], [IV.dropPrefix(p, WORLD_PREFIX.unicodeScalars.count)])
                if let d = IV.num(v) { values[JKey(p)] = JSONValue.double(d) } else if let s = v?.asString { values[JKey(p)] = JSONValue.string(s) }
            } else if IV.startsWith(p, PROV_PREFIX) {
                let v: JSONValue? = walk(env[JKey("prov")], IV.split(IV.dropPrefix(p, PROV_PREFIX.unicodeScalars.count), "."))
                values[JKey(p)] = JSONValue.string(v?.asString ?? "agent")
            } else if IV.startsWith(p, CLASS_PREFIX) {
                let v: JSONValue? = walk(env[JKey("class")], [IV.dropPrefix(p, CLASS_PREFIX.unicodeScalars.count)])
                if let s = v?.asString { values[JKey(p)] = JSONValue.string(s) }
            }
        }
        return PCAIntentOmega.Outcome(o.verb, values)
    }
}
