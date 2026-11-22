import Foundation

/// The outcome space from the site's signed action schema: one dimension per parameter whose effective sensitivity (after the wallet floor)
/// is material or critical, boolean / set / array parameters on their canonical projection path, closed-world default sets for silent
/// parameters. The schema, the slots, the policies and the confirmed values are JSON trees.
public enum PCAIntentSchema {
    public static let WALLET_FLOOR_PREFIXES: [String] = ["money.", "party.", "contact.", "person.", "credential."]
    public static let WALLET_FLOOR_EXACT: [String] = ["text.message"]
    private static let REV: [String] = ["reversible", "rate_limited", "irreversible"]

    /// The derived space with the wallet-floor overrides, the default-pinning slot constraints and the canonical-projection map.
    public final class SchemaOmega {
        public let omega: PCAIntentOmega.Omega
        public let overrides: [JSONValue]
        public let defaults: [JSONValue]
        public let canonOf: [JKey: String]
        init(_ omega: PCAIntentOmega.Omega, _ overrides: [JSONValue], _ defaults: [JSONValue], _ canonOf: [JKey: String]) {
            self.omega = omega; self.overrides = overrides; self.defaults = defaults; self.canonOf = canonOf
        }
    }

    private static func m(_ o: JSONValue?) throws -> JObject { try PCAIntentOmega.obj(o) }

    /// A member that is absent or JSON null is "no value" (a Kotlin null).
    private static func pres(_ v: JSONValue?) -> JSONValue? { JS.present(v) }

    private static func str(_ v: JSONValue?) throws -> String { try PCAIntentOmega.str(v) }

    private static func strs(_ o: JSONValue?, _ dflt: [String]?) throws -> [String]? {
        guard let v = pres(o) else { return dflt }
        var out: [String] = []
        for x in try PCAIntentOmega.arr(v) { out.append(try str(x)) }
        return out
    }

    /// UTF-8 byte order, stable.
    private static func sortedUtf8(_ xs: [String]) -> [String] {
        let idx = xs.enumerated().sorted { a, b in
            if IV.utf8Less(a.element, b.element) { return true }
            if IV.utf8Less(b.element, a.element) { return false }
            return a.offset < b.offset
        }
        return idx.map { $0.element }
    }

    private static func uniqueUtf8(_ xs: [String]) -> [String] {
        var seen = Set<JKey>()
        var out: [String] = []
        for x in xs where seen.insert(JKey(x)).inserted { out.append(x) }
        return sortedUtf8(out)
    }

    private static func floorApplies(_ semantic: String, _ floor: JSONValue?) throws -> Bool {
        let pre = try strs(floor?.get("prefixes"), WALLET_FLOOR_PREFIXES) ?? []
        let ex = try strs(floor?.get("exact"), WALLET_FLOOR_EXACT) ?? []
        if IV.contains(ex, semantic) { return true }
        for p in pre where IV.startsWith(semantic, p) { return true }
        return false
    }

    /// The wallet's effective sensitivity: a site `free` on a floored semantic type becomes `material`.
    public static func effectiveSensitivity(_ d: JSONValue?, _ floor: JSONValue?) throws -> String? {
        _ = try m(d)
        let sens = pres(d?.get("sensitivity"))
        if IV.same(sens?.asString, "free") {
            if try floorApplies(try str(d?.get("semantic")), floor) { return "material" }
        }
        guard let s = sens else { return nil }
        return try str(s)
    }

    private static func maxRev(_ xs: [JSONValue]) throws -> String {
        var a = "reversible"
        for b in xs {
            let bi = b.asString.flatMap { s in REV.firstIndex(where: { IV.same($0, s) }) } ?? -1
            let ai = REV.firstIndex(where: { IV.same($0, a) }) ?? -1
            if bi > ai { a = try str(b) }
        }
        return a
    }

    /// The value-independent reversibility class of a verb declaration (the worst a value can map to).
    public static func verbReversibility(_ v: JSONValue?) throws -> String {
        let vm = try m(v)
        guard let by = pres(vm[JKey("reversibility_by")]) else {
            if let r = pres(vm[JKey("reversibility")]) { return try str(r) }
            return IV.same(vm[JKey("kind")]?.asString, "read") ? "reversible" : "irreversible"
        }
        let b = try m(by)
        let params = try m(vm[JKey("params")])
        var d: JSONValue?
        if let pk = pres(b[JKey("param")]) { d = params[JKey(try str(pk))] }
        let map = try m(b[JKey("map")])
        let mapped: [JSONValue] = Array(map.values)
        var domain: [String]?
        if let dd = pres(d) {
            let dm = try m(dd)
            if IV.same(dm[JKey("type")]?.asString, "boolean") {
                domain = ["true", "false"]
            } else if IV.same(dm[JKey("type")]?.asString, "string"), pres(dm[JKey("values")]) != nil {
                domain = try strs(dm[JKey("values")], nil)
            }
        }
        var covered = domain != nil
        if covered { for x in domain ?? [] where map[JKey(x)] == nil { covered = false } }
        var all: [JSONValue] = mapped
        if !covered { all.append(pres(b[JKey("default")]) ?? JSONValue.string("irreversible")) }
        return try maxRev(covered ? mapped : all)
    }

    /// Every override the wallet floor makes on the schema's verbs: [{verb, path, semantic, declared, effective}].
    public static func walletFloorOverrides(_ verbs: [JSONValue], _ floor: JSONValue?) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for vo in verbs {
            let v = try m(vo)
            let params = try m(v[JKey("params")])
            for k in sortedUtf8(params.keys.map { $0.s }) {
                let d = try m(params[JKey(k)])
                guard let eff = try effectiveSensitivity(.object(d), floor) else { throw JSError("effective sensitivity is null") }
                if !IV.same(d[JKey("sensitivity")]?.asString, eff) {
                    var o = JObject()
                    o[JKey("verb")] = v[JKey("verb")] ?? JSONValue.null
                    o[JKey("path")] = .string(k)
                    o[JKey("semantic")] = d[JKey("semantic")] ?? JSONValue.null
                    o[JKey("declared")] = d[JKey("sensitivity")] ?? JSONValue.null
                    o[JKey("effective")] = .string(eff)
                    out.append(.object(o))
                }
            }
        }
        return out
    }

    private static func canonPath(_ paramPath: String) throws -> String {
        guard paramPath.utf16.count >= 14 else { throw JSError("string index out of range") }
        return "env.canon." + WJ.u16slice(paramPath, 14)
    }

    private static func usesCanon(_ d: JObject) -> Bool {
        let t = d[JKey("type")]?.asString
        return IV.same(t, "boolean") || IV.same(t, "set") || IV.same(t, "array")
    }

    /// The canonical text a value of a canon-projected parameter has.
    public static func canonValue(_ d: JSONValue?, _ x: JSONValue?) throws -> String {
        let dm = try m(d)
        if IV.same(dm[JKey("type")]?.asString, "boolean") { return x == JSONValue.bool(true) ? "true" : "false" }
        let norm = IV.normalized(x ?? JSONValue.null)
        if IV.same(dm[JKey("type")]?.asString, "set") {
            var l: [String] = []
            for e in try PCAIntentOmega.arr(norm) { l.append(try str(e)) }
            guard let c = IV.strictCanon(.array(sortedUtf8(l).map { JSONValue.string($0) })) else { throw JSError("canonicalize: value is outside the strict JSON profile") }
            return c
        }
        guard let c = IV.strictCanon(norm) else { throw JSError("canonicalize: value is outside the strict JSON profile") }
        return c
    }

    /// Derive the space. `o`: schema {verbs}, verbs?, slots?, policies?, confirmed?, floor?, domains?. Throws on a malformed schema.
    public static func deriveOmegaFromSchema(_ o: JSONValue?) throws -> SchemaOmega {
        let om = try m(o)
        let schemaVerbs = try PCAIntentOmega.arr(try m(om[JKey("schema")])[JKey("verbs")])
        var verbNames: [String] = []
        if let vn = pres(om[JKey("verbs")]) {
            verbNames = try strs(vn, nil) ?? []
        } else {
            for v in schemaVerbs {
                let vm = try m(v)
                if IV.same(vm[JKey("kind")]?.asString, "write") {
                    let name = try str(vm[JKey("verb")])
                    if !IV.contains(verbNames, name) { verbNames.append(name) }
                }
            }
            if let sl = pres(om[JKey("slots")]), let sv = pres(try m(sl)[JKey("verbs")]) {
                for n in try strs(sv, nil) ?? [] where !IV.contains(verbNames, n) { verbNames.append(n) }
            }
        }
        var baseOpts = JObject()
        baseOpts[JKey("policies")] = pres(om[JKey("policies")]) ?? JSONValue.array([])
        if let sl = pres(om[JKey("slots")]) { baseOpts[JKey("slots")] = sl }
        baseOpts[JKey("extraVerbs")] = .array(verbNames.map { JSONValue.string($0) })
        let base = try PCAIntentDerive.deriveOmega(.object(baseOpts))
        var floor: JSONValue?
        if pres(om[JKey("floor")]) != nil { floor = JSONValue.object(try m(om[JKey("floor")])) }
        var defaults: [JSONValue] = []
        var canonOf: [JKey: String] = [:]
        var verbs: [PCAIntentOmega.VerbSpace] = []
        let sortedNames = sortedUtf8(verbNames)
        var confirmed = JObject()
        if pres(om[JKey("confirmed")]) != nil { confirmed = try m(om[JKey("confirmed")]) }
        var domains = JObject()
        if pres(om[JKey("domains")]) != nil { domains = try m(om[JKey("domains")]) }
        for verb in sortedNames {
            var decl: JObject?
            for v in schemaVerbs {
                let vm = try m(v)
                if IV.same(vm[JKey("verb")]?.asString, verb) { decl = vm; break }
            }
            guard let dcl = decl else { continue }
            let lits: PCAIntentOmega.VerbSpace? = base.verbs.first { IV.same($0.verb, verb) }
            var dims: [PCAIntentOmega.Dim] = []
            if let l = lits { for d in l.dims where !IV.startsWith(d.path, "action.params.") { dims.append(d) } }
            let params = try m(dcl[JKey("params")])
            for path in sortedUtf8(params.keys.map { $0.s }) {
                let pd = try m(params[JKey(path)])
                if IV.same(try effectiveSensitivity(.object(pd), floor), "free") { continue }
                var lit: PCAIntentOmega.Dim?
                if let l = lits { for d in l.dims where IV.same(d.path, path) { lit = d; break } }
                let silent = lit == nil
                var defaultSet: [JSONValue] = []
                if let c = pres(confirmed[JKey(path)]) { defaultSet.append(contentsOf: try PCAIntentOmega.arr(c)) }
                if pd[JKey("principal_neutral_default")] == JSONValue.bool(true), let dv = pd[JKey("default")] { defaultSet.append(dv) }
                if IV.same(pd[JKey("type")]?.asString, "integer") {
                    var cuts: [Double] = []
                    if let n = lit as? PCAIntentOmega.NumDim { for c in n.cuts where !cuts.contains(c + 0.0) { cuts.append(c + 0.0) } }
                    for x in defaultSet {
                        if let v = IV.num(x), abs(v) <= 9007199254740991.0, v == v.rounded(.down), !cuts.contains(v + 0.0) { cuts.append(v + 0.0) }
                    }
                    let sorted = PCAIntentOmega.sortedNums(cuts)
                    let maxCut = sorted.isEmpty ? 0.0 : sorted[sorted.count - 1]
                    var dom: JObject?
                    if pres(domains[JKey(path)]) != nil { dom = try m(domains[JKey(path)]) }
                    let lo: Double
                    if let dv = pres(dom?[JKey("lo")]) { lo = try PCAIntentOmega.dbl(dv) }
                    else if let mv = pres(pd[JKey("min")]) { lo = try PCAIntentOmega.dbl(mv) }
                    else { lo = PCAIntentOmega.jmin(0.0, sorted.isEmpty ? 0.0 : sorted[0] - 1) }
                    let hi: Double
                    if let dv = pres(dom?[JKey("hi")]) { hi = try PCAIntentOmega.dbl(dv) }
                    else if let mv = pres(pd[JKey("max")]) { hi = try PCAIntentOmega.dbl(mv) }
                    else { hi = PCAIntentOmega.jmax(10.0, PCAIntentOmega.jmax(2 * maxCut, maxCut + 10)) }
                    var kept: [Double] = []
                    for c in sorted where c >= lo && c <= hi { kept.append(c) }
                    dims.append(PCAIntentOmega.NumDim(path, lo, hi, kept, lo >= 0 ? "loguniform" : "uniform"))
                    var nums: [Double] = []
                    for x in defaultSet { if let v = IV.num(x) { nums.append(v) } }
                    if silent && nums.count == 1 {
                        var c = JObject()
                        c[JKey("verb")] = .string(verb)
                        c[JKey("path")] = .string(path)
                        c[JKey("min")] = PCAIntentOmega.jn(nums[0])
                        c[JKey("max")] = PCAIntentOmega.jn(nums[0])
                        defaults.append(.object(c))
                    }
                    continue
                }
                let canon = usesCanon(pd)
                var dimPath = path
                if canon { dimPath = try canonPath(path) }
                if canon { canonOf[JKey(dimPath)] = path }
                var exacts: [String] = []
                var prefixes: [String] = []
                if let c = lit as? PCAIntentOmega.CatDim {
                    for v in c.values {
                        if v.kind == "exact" { exacts.append(v.value) } else if v.kind == "prefix" { prefixes.append(v.value) }
                    }
                }
                if IV.same(pd[JKey("type")]?.asString, "string"), pres(pd[JKey("values")]) != nil { exacts.append(contentsOf: try strs(pd[JKey("values")], nil) ?? []) }
                if IV.same(pd[JKey("type")]?.asString, "boolean") { exacts.append("false"); exacts.append("true") }
                var defTexts: [String] = []
                for x in defaultSet {
                    if canon { defTexts.append(try canonValue(.object(pd), x)) } else { defTexts.append(JS.toString(x)) }
                }
                exacts.append(contentsOf: defTexts)
                var values: [PCAIntentOmega.CatValue] = []
                for s in uniqueUtf8(exacts) { values.append(PCAIntentOmega.CatValue("exact", s)) }
                for s in uniqueUtf8(prefixes) { values.append(PCAIntentOmega.CatValue("prefix", s)) }
                values.append(PCAIntentOmega.CatValue("other", PCAIntentOmega.OTHER))
                dims.append(PCAIntentOmega.CatDim(dimPath, values))
                if silent && !defTexts.isEmpty {
                    var c = JObject()
                    c[JKey("verb")] = .string(verb)
                    c[JKey("path")] = .string(dimPath)
                    c[JKey("oneOf")] = .array(uniqueUtf8(defTexts).map { JSONValue.string($0) })
                    defaults.append(.object(c))
                }
            }
            let ordered = dims.enumerated().sorted { a, b in
                if IV.utf8Less(a.element.path, b.element.path) { return true }
                if IV.utf8Less(b.element.path, a.element.path) { return false }
                return a.offset < b.offset
            }
            let rev = try verbReversibility(.object(dcl))
            verbs.append(PCAIntentOmega.VerbSpace(verb, rev, 0.0, ordered.map { $0.element }))
        }
        for v in verbs { v.weight = 1.0 / Double(verbs.isEmpty ? 1 : verbs.count) }
        var included: [JSONValue] = []
        for v in schemaVerbs {
            if let n = try m(v)[JKey("verb")]?.asString, IV.contains(verbNames, n) { included.append(v) }
        }
        return SchemaOmega(PCAIntentOmega.Omega(verbs, base.approximate), try walletFloorOverrides(included, floor), defaults, canonOf)
    }
}
