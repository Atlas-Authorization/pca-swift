import Foundation

// Layered intent, the verifier side: the `layers` check and the full layer decision as public entry points. Layers are predicate sets evaluated by
// the one predicate evaluator. An ABSENT layer is the whole space; a layer PRESENT with null or any value that is not `{predicates: [...]}` is
// malformed and fails closed. Deny anywhere wins: an action outside a ceiling is `ceiling`, never a question. Every function here is total.
public extension PCAIntentLayers {
    /// A layer as a predicate set.
    struct LayerPolicy: Equatable, Sendable {
        public var predicates: [JSONValue]
        public init(predicates: [JSONValue]) { self.predicates = predicates }
        /// Nil unless `v` is exactly `{predicates: [...]}`.
        public init?(json v: JSONValue?) {
            guard PCAIntentLayers.isLayerPolicy(v), case let .array(p)? = v?.get("predicates") else { return nil }
            predicates = p
        }
        public var json: JSONValue { .object(["predicates": .array(predicates)]) }
    }

    enum LayerDecision: Equatable, Sendable {
        /// Admitted by the task layer: 0 for the task grant, k for delta k.
        case admit(by: Int)
        case ceiling(layer: String)
        case intentDenied
        case intentRequired

        /// The reference's wire name: `admit`, `ceiling`, `intent_denied` or `intent_required`.
        public var decision: String {
            switch self {
            case .admit: return "admit"
            case .ceiling: return "ceiling"
            case .intentDenied: return "intent_denied"
            case .intentRequired: return "intent_required"
            }
        }

        public var json: JSONValue {
            var o: JObject = [:]
            o[o: "decision"] = .string(decision)
            if case let .admit(by) = self { o[o: "by"] = .int(Int64(by)) }
            if case let .ceiling(layer) = self { o[o: "layer"] = .string(layer) }
            return .object(o)
        }
    }

    /// `pass`, or the first failing ceiling and why.
    struct CeilingResult: Equatable, Sendable {
        public var pass: Bool
        public var layer: String?
        public var reason: String?
    }

    /// A well-formed layer: an object with exactly one member, `predicates`, an array (closed member set).
    static func isLayerPolicy(_ l: JSONValue?) -> Bool {
        guard case let .object(o)? = l, o.count == 1, case .array? = o["predicates"] else { return false }
        return true
    }

    private static func layerAdmits(_ l: JSONValue, _ ctx: JSONValue) -> Bool { Predicates.evaluate(l.get("predicates"), ctx) }

    private static func closedTo(_ o: JObject, _ allowed: [String]) -> Bool { o.keys.allSatisfy { k in allowed.contains { IV.same($0, k.s) } } }

    /// The `layers` check: the action must be inside the org, then the site, then the std ceiling (absent = no constraint). The first ceiling that
    /// denies is named. `layers` must be an object with no member other than `org`, `site`, `std` (an unknown member fails, reported as `org`); an
    /// empty predicate list admits nothing.
    static func decideLayerCeilings(_ layers: JSONValue?, _ ctx: JSONValue) -> CeilingResult {
        if case let .object(o)? = layers, !closedTo(o, LAYER_CEILINGS) {
            return CeilingResult(pass: false, layer: "org", reason: "layers: unknown member (the layers object is {org?, site?, std?})")
        }
        return ceilingsOf(layers, ctx)
    }

    private static func ceilingsOf(_ layers: JSONValue?, _ ctx: JSONValue) -> CeilingResult {
        guard case let .object(o)? = layers else { return CeilingResult(pass: false, layer: "org", reason: "layers: the layers member is malformed (not an object)") }
        for k in LAYER_CEILINGS {
            guard let layer = o[JKey(k)] else { continue }
            if !isLayerPolicy(layer) { return CeilingResult(pass: false, layer: k, reason: "layers: the \(k) ceiling is malformed (null or not {predicates: [...]})") }
            if !layerAdmits(layer, ctx) { return CeilingResult(pass: false, layer: k, reason: "layers: the action is outside the \(k) ceiling (a ceiling is never a question)") }
        }
        return CeilingResult(pass: true, layer: nil, reason: nil)
    }

    /// The full layer decision for one action, in order: outside the org, site, then std ceiling gives `ceiling`; inside a denied region gives
    /// `intent_denied`; inside the task grant or some delta gives `admit`; otherwise `intent_required`. A grant member other than org / site / std /
    /// task / denied, a `denied` that is present but not an array, a `task` that is not an array (it is required) or any entry that is not
    /// `{predicates: [...]}` is malformed: `intent_denied` (never a question, never an admission).
    static func decideLayers(_ g: JSONValue?, _ ctx: JSONValue) -> LayerDecision {
        if case let .object(o)? = g, !closedTo(o, LAYER_CEILINGS + ["task", "denied"]) { return .intentDenied }
        let c = ceilingsOf(g, ctx)
        if !c.pass { return .ceiling(layer: c.layer ?? "org") }
        let denied = g?.get("denied") ?? .array([])
        guard case let .array(ds) = denied, ds.allSatisfy({ isLayerPolicy($0) }), case let .array(ts)? = g?.get("task"), ts.allSatisfy({ isLayerPolicy($0) }) else { return .intentDenied }
        if ds.contains(where: { layerAdmits($0, ctx) }) { return .intentDenied }
        if let i = ts.firstIndex(where: { layerAdmits($0, ctx) }) { return .admit(by: i) }
        return .intentRequired
    }
}

public extension PCA {
    /// The value-dependent reversibility class of one call of a schema verb: `reversibility_by` maps the value of one parameter (a string, a
    /// boolean or a safe integer, by its text) to a class; an unmapped or absent value takes its `default`, else `irreversible`. Without
    /// `reversibility_by` it is the declared class, else `reversible` for a read and `irreversible` for anything else.
    static func reversibilityOf(_ verb: JSONValue, _ params: JSONValue?) -> String {
        if let by = verb.get("reversibility_by"), JS.truthy(by) {
            // a declaration that is not {param, map, default?} is unusable: the most cautious class
            guard let param = by.get("param")?.asString else { return "irreversible" }
            var key: String?
            switch params?.get(IV.dropPrefix(param, "action.params.".count)) {
            case let .string(s)?: key = s
            case let .bool(b)?: key = b ? "true" : "false"
            case let n?: key = IV.int(n).map { String($0) }
            case nil: break
            }
            if let k = key, let hit = by.get("map")?.get(k) { return hit.asString ?? "irreversible" }
            return by.get("default")?.asString ?? "irreversible"
        }
        return verb.get("reversibility")?.asString ?? (verb.get("kind")?.asString == "read" ? "reversible" : "irreversible")
    }

    /// The `objective_risk` commitment of a grant's envelope: both nil when the grant commits nothing, `malformed` when it commits something this
    /// verifier cannot read (the caller treats that as a mismatch, fail closed).
    static func readObjectiveCommitment(_ grant: JSONValue) -> (commitment: JSONValue?, malformed: String?) {
        guard let raw = readEnvelope(grant)?.get("objective_risk") else { return (nil, nil) }
        func str(_ v: JSONValue?) -> Bool { !(v?.asString ?? "").isEmpty }
        guard case let .object(o) = raw, IV.num(o["v"]) == 1 else { return (nil, "objective_risk: unsupported shape/version") }
        guard case let .object(emb)? = o["embedder"], emb["scheme"]?.asString == "native", str(emb["model_id"]), emb["config"]?.isObject == true else {
            return (nil, "objective_risk.embedder must be { scheme: \"native\", model_id, config }")
        }
        guard case let .object(goal)? = o["goal"], str(goal["commit"]) else { return (nil, "objective_risk.goal must be a goal commitment") }
        if !str(o["registry_digest"]) || !str(o["graph_digest"]) { return (nil, "objective_risk needs registry_digest and graph_digest") }
        if let c = o["calibration_digest"], !str(c) { return (nil, "objective_risk.calibration_digest must be a string") }
        guard case let .array(kinds)? = o["authorized_kinds"], kinds.allSatisfy({ $0.asString != nil }) else { return (nil, "objective_risk.authorized_kinds must be string[]") }
        if let d = o["denominations"], d.asArray == nil { return (nil, "objective_risk.denominations must be an array") }
        if let m = o["on_mismatch"], m.asString != "deny", m.asString != "heuristic" { return (nil, "objective_risk.on_mismatch must be \"deny\" or \"heuristic\"") }
        return (raw, nil)
    }

    /// Digest of the catalog vocabulary a natural-language draft was grounded against: the rows `[verb, reversibility, amountField | null]` sorted
    /// by verb. It is not the connector catalog's own digest.
    static func nlCatalogDigest(_ catalog: PCACatalog = .default) -> String {
        let rows = catalog.all().sorted { Array($0.verb.utf16).lexicographicallyPrecedes(Array($1.verb.utf16)) }
            .map { JSONValue.array([.string($0.verb), .string($0.reversibility), $0.amountField.map { .string($0) } ?? .null]) }
        return Canonical.hashCanonical(.object(["v": .int(1), "rows": .array(rows)]))
    }
}

// The limits and closed vocabularies of an action definition, the trait constants and two small helpers, under the reference's names.
public extension Actions {
    static let ACTION_DEF_VERSION = 1
    static let MAX_VERB_BYTES = 128
    static let MAX_TITLE_BYTES = 120
    static let MAX_DESCRIPTION_BYTES = 1024
    static let MAX_DEF_PARAMS = 64
    static let MAX_DEF_ALIASES = 16
    static let MAX_DEF_TRAITS = 32
    static let MAX_DEF_CONTEXT = 16
    static let MAX_DEF_SIDE_EFFECTS = 16
    static let MAX_PARAM_PATH_DEPTH = 3
    static let MAX_TRAIT_IMPLIES_DEPTH = 8
    static let MAX_REGISTRY_TRAITS = 512
    static let PARAM_TYPES_V1: [String] = PARAM_TYPES
    static let SENSITIVITY_LEVELS = ["free", "material", "critical"]
    /// The highest escalation tier (auto < confirm < cosign < stepup).
    static let ESC_MAX = 3
    /// Trait ids under this prefix are core traits; a registry extension may not define one.
    static let CORE_NAMESPACE = "pca."
    static let DECISION_RANK: [String: Int] = ["deny": 0, "escalate": 1, "allow": 2]

    /// The core trait definitions, in table order.
    static let CORE_TRAIT_DEFS: [TraitDef] = CORE_TRAIT_IDS.compactMap { coreRegistry.traits[JKey($0)] }

    /// Meet in the order deny < escalate < allow; a name outside that set ranks as `deny`.
    static func meetDecision(_ a: String, _ b: String) -> String { (DECISION_RANK[a] ?? 0) <= (DECISION_RANK[b] ?? 0) ? a : b }

    /// The reversibility declaration of a definition: the declared one (a class or a value-dependent `{by, map, default?}`), else `reversible` when
    /// every effect is `read` and `irreversible` otherwise.
    static func declaredReversibility(_ def: JSONValue) -> JSONValue {
        if let r = def.get("reversibility"), !r.isNull { return r }
        let effects = def.get("effects")?.asArray ?? []
        return .string(!effects.isEmpty && effects.allSatisfy { $0 == .string("read") } ? "reversible" : "irreversible")
    }
}
