import Foundation

/// The layered lattice over a task learner: deny anywhere wins (a cell outside a ceiling is denied with reason ceiling and is never a
/// question), the effective grant, the uncertain cells (the only cells ever asked about), the wallet-side decision for a concrete
/// outcome, and an organisation layer that is itself a learned map.
public enum PCAIntentLattice {
    /// The learner's verb space in the typed outcome-space model (the learner keeps its own integer-grid form).
    static func verbSpaceOf(_ v: WalletVerb) -> PCAIntentOmega.VerbSpace {
        var dims: [PCAIntentOmega.Dim] = []
        for d in v.dims {
            if d.isNum {
                dims.append(PCAIntentOmega.NumDim(d.path, Double(d.lo), Double(d.hi), d.cuts.map { Double($0) }, d.dist ?? "uniform"))
            } else {
                dims.append(PCAIntentOmega.CatDim(d.path, d.values.map { PCAIntentOmega.CatValue($0.kind, $0.value) }))
            }
        }
        return PCAIntentOmega.VerbSpace(v.verb, v.reversibility, v.weight, dims)
    }

    static func omegaOf(_ l: PCAIntentLearner) -> PCAIntentOmega.Omega {
        return PCAIntentOmega.Omega(l.omega.verbs.map { verbSpaceOf($0) }, l.omegaApprox ?? [])
    }

    /// {effective, uncertain, ceiling}: cell keys {verb, cell} (ceiling ones with their layer) of the learner's cells under the ceilings.
    public static func latticeView(_ task: PCAIntentLearner, _ ceilings: PCAIntentLayers.CeilingAdmitters) throws -> JSONValue {
        var effective: [JSONValue] = []
        var uncertain: [JSONValue] = []
        var ceiling: [JSONValue] = []
        for c in task.cells() {
            guard let vs = task.omega.verb(c.verb) else { throw JSError("latticeView: no verb \(c.verb) in Omega") }
            let layer: String? = PCAIntentLayers.ceilingOf(ceilings, vs, WalletOmegaMath.cellRep(vs, c.cell))
            var key: JObject = [:]
            key[JKey("verb")] = JSONValue.string(c.verb)
            key[JKey("cell")] = JSONValue.array(c.cell.map { JSONValue.int(Int64($0)) })
            if let ly = layer {
                key[JKey("layer")] = JSONValue.string(ly)
                ceiling.append(JSONValue.object(key))
                continue
            }
            if c.vetoed { continue }
            if c.inGrant { effective.append(JSONValue.object(key)) }
            else if c.p > 1e-12 && c.p < task.tau - 1e-12 { uncertain.append(JSONValue.object(key)) }
        }
        return JSONValue.object([JKey("effective"): JSONValue.array(effective), JKey("uncertain"): JSONValue.array(uncertain), JKey("ceiling"): JSONValue.array(ceiling)])
    }

    /// The wallet-side decision for a concrete outcome against a task learner: {decision, layer?, by?}.
    public static func decideOutcomeLayers(_ task: PCAIntentLearner, _ ceilings: PCAIntentLayers.CeilingAdmitters, _ o: JSONValue) -> JSONValue {
        var r: JObject = [:]
        guard let vs = task.omega.verb(o.get("verb")?.asString ?? "\u{0}") else {
            r[JKey("decision")] = JSONValue.string("intent_denied")
            return JSONValue.object(r)
        }
        if let layer = PCAIntentLayers.ceilingOf(ceilings, vs, o) {
            r[JKey("decision")] = JSONValue.string("ceiling")
            r[JKey("layer")] = JSONValue.string(layer)
            return JSONValue.object(r)
        }
        if task.isVetoed(o) || task.acceptance(o) <= 1e-12 {
            r[JKey("decision")] = JSONValue.string("intent_denied")
            return JSONValue.object(r)
        }
        if task.admitsOutcome(o) {
            r[JKey("decision")] = JSONValue.string("admit")
            r[JKey("by")] = JSONValue.int(0)
            return JSONValue.object(r)
        }
        r[JKey("decision")] = JSONValue.string("intent_required")
        return JSONValue.object(r)
    }

    /// An org layer that is itself a learned map over a shared space: the joint grant of the approvers' maps under the org's rule.
    /// Returns {map, policy}.
    public static func orgLayerFromMaps(_ maps: [JSONValue], _ rule: JSONValue?) throws -> JSONValue {
        let map: JSONValue = try PCAIntentMultiAgg.aggregateIntentMaps(maps, rule, nil)
        return JSONValue.object([JKey("map"): map, JKey("policy"): map.get("grant") ?? JSONValue.null])
    }
}
