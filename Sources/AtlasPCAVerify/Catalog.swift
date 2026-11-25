import Foundation

/// The connector action catalog over JSON action specs (`{connector, action, verb, reversibility, blastRadius, amountField?, resource?,
/// description, aliases?, traits?}`), as the reference exposes it: specs keep every member they were given. It is data, not enforcement:
/// it tells a caller how a named action maps onto a verb, a reversibility class and a blast radius. `PCACatalog` is the typed catalog
/// the facade compiles from; `Catalog.DEFAULT_CATALOG` holds the same built-in actions.
public enum Catalog {
    /// Blast-radius presets by shape of action (conservative, overridable).
    public static let BLAST: [String: Double] = ["read": 0.05, "reversibleWrite": 0.2, "rateLimitedWrite": 0.5, "irreversibleWrite": 0.8, "moneyMovement": 0.9]

    /// The built-in actions as JSON specs, in definition order.
    public static let BUILTIN_ACTIONS: [JSONValue] = PCACatalog.builtin.map { a in
        var o: JObject = [:]
        o[o: "connector"] = .string(a.connector)
        o[o: "action"] = .string(a.action)
        o[o: "verb"] = .string(a.verb)
        o[o: "reversibility"] = .string(a.reversibility)
        o[o: "blastRadius"] = PD.num(a.blastRadius)
        if let f = a.amountField { o[o: "amountField"] = .string(f) }
        if let r = a.resource { o[o: "resource"] = .string(r) }
        o[o: "description"] = .string(a.description)
        if !a.aliases.isEmpty { o[o: "aliases"] = .array(a.aliases.map { .string($0) }) }
        // every built-in spec lists its traits, an empty list included (the reference's generated table)
        o[o: "traits"] = .array(a.traits.map { .string($0) })
        return .object(o)
    }

    /// An immutable lookup over action specs, keyed by verb. A later spec of a verb replaces the earlier one in place.
    public struct ActionCatalog: Sendable {
        private var byVerb: [JKey: JSONValue] = [:]
        private var order: [JKey] = []

        init(_ actions: [JSONValue]) {
            for a in actions {
                // a verb that is not text is its own key (never equal to a text verb)
                let k = a.get("verb")?.asString.map { JKey($0) } ?? JKey("\u{0}" + Canonical.canonicalize(a.get("verb") ?? .null))
                if byVerb[k] == nil { order.append(k) }
                byVerb[k] = a
            }
        }

        /// The spec of a verb (`connector.action`).
        public func get(_ verb: String) -> JSONValue? { byVerb[JKey(verb)] }

        /// Every action of a connector, in catalog order.
        public func forConnector(_ connector: String) -> [JSONValue] { all().filter { IV.same($0.get("connector")?.asString, connector) } }

        /// Every action, in order of first appearance by verb.
        public func all() -> [JSONValue] { order.compactMap { byVerb[$0] } }

        /// `connector` + `action` as a human or a model writes them: the exact verb, else an alias of exactly ONE action of that connector.
        /// Absent or ambiguous: nil (never a guess).
        public func resolve(connector: String, action: String) -> JSONValue? {
            if let exact = get(connector + "." + action) { return exact }
            let hits = forConnector(connector).filter { ($0.get("aliases")?.asArray ?? []).contains { IV.same($0.asString, action) } }
            return hits.count == 1 ? hits[0] : nil
        }
    }

    /// Defines one action spec (validates its shape); the verb defaults to `connector.action`. Every other member is kept.
    public static func defineAction(_ spec: JSONValue) throws -> JSONValue {
        guard case var .object(s) = spec, let connector = s["connector"]?.asString, let action = s["action"]?.asString, !connector.isEmpty, !action.isEmpty else {
            throw JSError("defineAction: connector and action are required")
        }
        if connector.unicodeScalars.contains(where: { $0 == "." || Attest.isJSSpace($0) }) { throw JSError("defineAction: connector must not contain whitespace or a dot") }
        if let f = s["amountField"], f.asString?.isEmpty ?? true { throw JSError("defineAction: amountField must be a non-empty string") }
        guard let rev = s["reversibility"]?.asString, PCAAnalyzer.REVERSIBILITY_ORDER.contains(where: { IV.same($0, rev) }) else {
            throw JSError("defineAction: bad reversibility '\(JS.toString(s["reversibility"]))'")
        }
        guard let blast = IV.num(s["blastRadius"]), blast >= 0, blast <= 1 else { throw JSError("defineAction: blastRadius must be in [0,1]") }
        if JS.present(s["verb"]) == nil { s[o: "verb"] = .string(connector + "." + action) }
        return .object(s)
    }

    /// A catalog over `actions` (default: the built-in actions). The specs are taken as given: validate them with `defineAction`.
    public static func buildCatalog(_ actions: [JSONValue] = BUILTIN_ACTIONS) -> ActionCatalog { ActionCatalog(actions) }

    /// The catalog of the built-in actions.
    public static let DEFAULT_CATALOG = buildCatalog()

    /// What a verb the catalog does not know is treated as: irreversible, maximum blast radius.
    public static func uncataloguedSpec(_ verb: String) -> JSONValue {
        let parts = IV.split(verb, ".")
        let rest = parts.dropFirst().joined(separator: ".")
        var o: JObject = [:]
        o[o: "connector"] = .string(parts.first ?? verb)
        o[o: "action"] = .string(rest.isEmpty ? verb : rest)
        o[o: "verb"] = .string(verb)
        o[o: "reversibility"] = .string("irreversible")
        o[o: "blastRadius"] = .int(1)
        o[o: "description"] = .string("(uncatalogued) " + verb)
        return .object(o)
    }

    /// Resolves a verb, failing closed: an unknown verb comes back as `uncataloguedSpec(verb)` with `catalogued` false.
    public static func resolveAction(_ catalog: ActionCatalog, _ verb: String) -> (spec: JSONValue, catalogued: Bool) {
        if let spec = catalog.get(verb) { return (spec, true) }
        return (uncataloguedSpec(verb), false)
    }

    /// The digest of the whole catalog (SHA-256 over the canonical JSON of the specs sorted by verb, in UTF-16 code unit order). Pin it to
    /// refuse a catalog that changed since it was reviewed. Throws when a spec holds a value the canonical form cannot encode.
    public static func catalogDigest(_ catalog: ActionCatalog) throws -> String {
        func verb(_ v: JSONValue) -> String.UTF16View { (v.get("verb")?.asString ?? "").utf16 }
        let specs = catalog.all().sorted { verb($0).lexicographicallyPrecedes(verb($1)) }
        return Base64URLStrict.encode(Canonical.sha256(Array(try SafetyCertificate.canonical(.array(specs)).utf8)))
    }

    /// Throws unless `catalog` hashes to `expected`.
    public static func assertCatalogPinned(_ catalog: ActionCatalog, _ expected: String) throws {
        if !IV.same(try catalogDigest(catalog), expected) { throw JSError("catalog does not match the pinned digest") }
    }

    /// Extends a catalog. Unlike building one from both lists, an extra action may not replace an existing verb with a less cautious one
    /// (a lower reversibility class or a lower blast radius): an extension may only tighten.
    public static func extendCatalog(_ base: ActionCatalog, _ extra: [JSONValue]) throws -> ActionCatalog {
        func sev(_ v: JSONValue?) -> Int { v?.asString.flatMap { c in PCAAnalyzer.REVERSIBILITY_ORDER.firstIndex(where: { IV.same($0, c) }) } ?? -1 }
        for e in extra {
            guard let verb = e.get("verb")?.asString, let old = base.get(verb) else { continue }
            if sev(e.get("reversibility")) < sev(old.get("reversibility")) || JSLoose.lt(e.get("blastRadius"), old.get("blastRadius")) {
                throw JSError("extendCatalog: '\(verb)' would be less cautious than the existing entry")
            }
        }
        return buildCatalog(base.all() + extra)
    }
}
