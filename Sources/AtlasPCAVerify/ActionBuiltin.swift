import Foundation

/// The built-in connector actions and the domain vocabularies as hand-reviewed action definitions (the `core` seed of the catalog packs), the legacy
/// tables they were reconciled from, and the derivation of a domain's ontology terms. The data is the reference's, embedded verbatim. The built-ins are
/// UNCONFIRMED until a release attestation is attached (`releasedBuiltinDefs`); this build carries none, so they stay maximally dangerous when read here
/// (the release signing step stays with the tooling that holds the reviewer key).
public enum ActionBuiltin {
    public static let DOMAIN_NAMES = ["payments", "email", "code_repos", "data_access", "calendar_travel"]

    private static func parse(_ text: String) -> JSONValue { (try? StrictJSON.parseLenient(text)) ?? .null }
    private static let builtin = parse(ActionData.BUILTIN_DEFS), domain = parse(ActionData.DOMAIN_DEFS), catalog = parse(ActionData.LEGACY_CATALOG)
    private static let ontoEffect = parse(ActionData.LEGACY_ONTOLOGY_EFFECT), resolved = parse(ActionData.RESOLUTIONS), verbBindings = parse(ActionData.DOMAIN_VERBS)

    /// The 21 built-in connector action definitions.
    public static func builtinDefs() -> [JSONValue] { AK.arr(builtin) }

    /// The defs the domain vocabularies add to the built-in pack.
    public static func domainDefs() -> [JSONValue] { AK.arr(domain) }

    /// Every def the domain vocabularies and the connector catalog are built from: one pack, one alias namespace.
    public static func corePackDefs() -> [JSONValue] { builtinDefs() + domainDefs() }

    /// What the old catalog said per built-in verb: `verb -> {reversibility, blastRadius}`.
    public static func legacyCatalog() -> JObject { AK.o(catalog) }

    /// What the old payments ontology said (effect class), for the verbs that exist in both models.
    public static func legacyOntologyEffect() -> JObject { AK.o(ontoEffect) }

    /// Every place the old models disagreed and how it was settled: a list of `{verb, field, was, now, reason}`.
    public static func resolutions() -> [JSONValue] { AK.arr(resolved) }

    /// The NL bindings per domain: `domain -> [{id, verb, resourceType, params, ccys?}]`.
    public static func domainVerbBindings() -> JObject { AK.o(verbBindings) }

    private static func defOf(_ pack: [JSONValue], _ verb: String) throws -> JObject {
        for d in pack where d.get("verb") == .string(verb) { return AK.o(d) }
        throw JSError("domain binding names unknown def '\(verb)'")
    }

    private static func bindings(_ domain: String) throws -> [JSONValue] {
        guard let b = domainVerbBindings()[JKey(domain)] else { throw JSError("unknown domain '\(domain)'") }
        return AK.arr(b)
    }

    /// The `verbs` and `aliases` of a domain ontology, derived from the defs (effect class derived, parameter kinds from the def parameters, a money
    /// parameter listing the domain's accepted currencies when the binding names them). Returns `{verbs, aliases}`.
    public static func domainVerbs(_ domain: String, _ reg: TraitRegistry? = nil) throws -> JSONValue {
        let pack = corePackDefs()
        let bs = try bindings(domain)
        let defs = try bs.map { JSONValue.object(try defOf(pack, JS.toString($0.get("verb")))) }
        let onto = try ActionDerive.toOntology(defs, reg ?? Actions.coreRegistry, nil)
        var verbs: [JSONValue] = []
        var aliases: JObject = [:]
        for b in bs {
            let d = try defOf(pack, JS.toString(b.get("verb")))
            let dal = AK.arr(d["aliases"])
            let id = b.get("id") ?? .null
            if !dal.contains(id) { throw JSError("domain binding '\(JS.toString(id))' is not an alias of '\(JS.toString(b.get("verb")))'") }
            let ov = AK.arr(onto.get("verbs")).first { $0.get("id") == b.get("verb") }
            var params: JObject = [:]
            let bp = AK.o(b.get("params"))
            for k in JS.keyOrder(bp) {
                guard let p = ov?.get("params")?.get(JS.toString(bp[k])) else { throw JSError("domain binding '\(JS.toString(id))' surfaces unknown parameter '\(JS.toString(bp[k]))'") }
                params[k] = p.get("kind") == .string("money") && JS.present(b.get("ccys")) != nil ? AK.obj(["kind": .string("money"), "ccys": .array(AK.arr(b.get("ccys")))]) : p
            }
            verbs.append(AK.obj(["id": id, "effect": .string(try ActionDerive.effectClass(d)), "resource_type": b.get("resourceType") ?? .null, "params": .object(params)]))
            for a in dal where a != id { if let s = a.asString { aliases[JKey(s)] = id } }
        }
        return AK.obj(["verbs": .array(verbs), "aliases": .object(aliases)])
    }

    /// The role map of a domain verb for the selector layer: `id -> role -> [NL parameter names carrying it]`.
    public static func domainRoles(_ domain: String) throws -> JObject {
        let pack = corePackDefs()
        var out: JObject = [:]
        for b in try bindings(domain) {
            let d = try defOf(pack, JS.toString(b.get("verb")))
            var roles: JObject = [:]
            let bp = AK.o(b.get("params"))
            let dp = AK.o(d["params"])
            for k in JS.keyOrder(bp) {
                if let r = JS.present(dp[JKey(JS.toString(bp[k]))]?.get("role"))?.asString {
                    roles[JKey(r)] = .array(AK.arr(roles[JKey(r)]) + [.string(k.s)])
                }
            }
            out[JKey(JS.toString(b.get("id")))] = .object(roles)
        }
        return out
    }

    // ---- release attestation (none shipped in this build) ----

    /// The release pins the built-in attestations verify against; nil before the first release signing (always, in this build).
    public static func builtinReleasePins() -> JSONValue? { nil }

    /// The built-in defs with their release attestation attached where the package carries one (none: returned unchanged and unconfirmed).
    public static func releasedBuiltinDefs(_ defs: [JSONValue]? = nil) -> [JSONValue] { defs ?? builtinDefs() }

    /// The attestation check under which released built-ins count as confirmed; nil without pinned release keys (nothing confirmed).
    public static func builtinReviewOpts(_ reg: TraitRegistry? = nil) -> ((JObject) -> Bool)? {
        builtinReleasePins().map { ActionUndoEngine.attestationVerifier($0, reg ?? Actions.coreRegistry) }
    }

    /// Release step: confirm every built-in def (or `defs`) under the release reviewer key, each with its declared traits as the final set. The key is
    /// supplied by the caller and never stored; the result is the confirmed defs, the attestation of each at `review.attestation`.
    public static func signBuiltins(_ reg: TraitRegistry?, _ kid: String, _ key: PCAEdKey, _ ts: JSONValue?, _ defs: [JSONValue]? = nil) throws -> [JSONValue] {
        try (defs ?? builtinDefs()).map { d in
            let def = AK.o(d)
            let traits = Jx.sortUniq(AK.arr(def["traits"]).compactMap { $0.asString })
            return .object(try ImportReview.confirmDef(def, reg ?? Actions.coreRegistry, kid, key, nil, traits.map { .string($0) }, nil, ts))
        }
    }
}
