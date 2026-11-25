import Foundation

/// Trait selectors and role-addressed parameters for the Goal IR. A selector goal (SelGoal) names a verb selector (a verb, or a class: every
/// verb of the pinned catalog with all of the traits and none of the excluded ones) in its grants, may select by trait in prohibitions and
/// bounds, and may name a parameter by ROLE. `expandSelGoal` lowers it, against the PINNED catalog, to an ordinary Goal (one grant per
/// verb, each with that verb's own parameter path); the proved core compiler then does the rest.
///
/// Fail-closed: a grant verb with no unique parameter of a role the condition names is DROPPED (reported); a prohibition whose role term
/// is unresolved for a verb applies to that verb UNCONDITIONALLY; a bound whose role-addressed value cannot be resolved for every selected
/// verb is a type error; an allow selector is positive (no `none_of`, at least one trait); an UNCONFIRMED verb carries the marker
/// `pca.unreviewed`: a class ALLOW never covers it, a class PROHIBITION or a bound over a trait selector ALWAYS covers it; an unknown
/// trait id is a type error. A catalog is {known, verbs: [{verb, traits, roles}]}.
public enum PCAGoalSelectors {
    /// The marker trait every unconfirmed verb carries.
    public static let UNREVIEWED = "pca.unreviewed"

    // ---------------- small helpers ----------------

    private static func mx(_ v: JSONValue?) throws -> JObject {
        guard let o = v?.asObject else { throw IrError("object expected") }
        return o
    }

    private static func at(_ o: JObject, _ k: String) -> JSONValue? { o[JKey(k)] }

    private static func list(_ v: JSONValue?) throws -> [JSONValue] { try GV.arr(v) }

    /// An object from members, an undefined member (nil) left out as JSON.stringify leaves it out.
    private static func mk(_ kv: [(String, JSONValue?)]) -> JSONValue {
        var o = JObject()
        for (k, v) in kv { if let x = v { o[JKey(k)] = x } }
        return .object(o)
    }

    private static func strs(_ xs: [String]) -> [JSONValue] { xs.map { JSONValue.string($0) } }

    /// The member names in code-unit order (a parsed object has no insertion order).
    private static func sortedKeys(_ o: JObject) -> [String] { o.keys.map { $0.s }.sorted { GV.less($0, $1) } }

    /// SameValueZero membership (Array.includes) of a JSON value.
    private static func has(_ xs: [JSONValue], _ x: JSONValue?) -> Bool {
        for y in xs where IV.strictEq(y, x) { return true }
        return false
    }

    private static func verbName(_ v: JSONValue) throws -> String {
        guard let s = v.asString else { throw IrError("verb must be a string") }
        return s
    }

    private static func hashStrict(_ v: JSONValue) throws -> String {
        Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v)))
    }

    // ---------------- the pinned catalog ----------------

    /// The catalog of a pack of action defs (verb ids and parameter paths are the defs' own). `reg` nil: the core registry;
    /// `pins` (the review pins) may be nil.
    public static func selCatalogOfDefs(_ defs: [JSONValue], _ reg: TraitRegistry?, _ pins: JSONValue?) throws -> JSONValue {
        let r: TraitRegistry = reg ?? Actions.coreRegistry
        var verbs: [(String, JSONValue)] = []
        for dO in defs {
            let d = try mx(dO)
            let params = try mx(at(d, "params"))
            var roleOrder: [String] = []
            var roleMap: [JKey: [JSONValue]] = [:]
            for name in sortedKeys(params) {
                if let role = GV.get(params[JKey(name)], "role") {
                    let rk = GV.jsStr(role)
                    if roleMap[JKey(rk)] == nil { roleOrder.append(rk); roleMap[JKey(rk)] = [] }
                    roleMap[JKey(rk)]!.append(.string(name))
                }
            }
            var roles = JObject()
            for rk in roleOrder { roles[JKey(rk)] = .array(roleMap[JKey(rk)]!) }
            let eff = try Actions.effective(d, r, pins)
            let verb: JSONValue? = at(d, "verb")
            let v = mk([("verb", verb), ("traits", .array(strs(eff.closure))), ("roles", .object(roles))])
            verbs.append((GV.jsStr(verb), v))
        }
        // a stable sort by verb id (UTF-16 code-unit order), as Array.prototype.sort
        let order = verbs.indices.sorted { (i: Int, j: Int) -> Bool in
            let c = GV.cmp(verbs[i].0, verbs[j].0)
            return c != 0 ? c < 0 : i < j
        }
        let known: [String] = r.traits.keys.map { $0.s }.sorted { GV.less($0, $1) }
        return mk([("known", .array(strs(known))), ("verbs", .array(order.map { verbs[$0].1 }))])
    }

    /// The catalog of a shipped domain ontology (core registry, no review pins); nil for an unknown domain.
    public static func selCatalogOfDomain(_ domain: String) throws -> JSONValue? { try PCAGoalOntologies.selCatalog(domain) }

    /// Digest of the catalog (what `catDigest` of a SelGoal must equal).
    public static func selCatalogDigest(_ c: JSONValue) throws -> String {
        try hashStrict(GV.obj([("d", .string("atlas-pca/goal-sel-catalog/v1")), ("catalog", c)]))
    }

    /// Digest of the whole signed selector goal.
    public static func selGoalDigest(_ g: JSONValue) throws -> String {
        try hashStrict(GV.obj([("d", .string("atlas-pca/goal-ir-sel/v1")), ("goal", g)]))
    }

    // ---------------- the verbs of a class selector ----------------

    private static func hasAll(_ ts: [JSONValue], _ req: [JSONValue]) -> Bool {
        for t in req where !has(ts, t) { return false }
        return true
    }

    private static func hasNone(_ ts: [JSONValue], _ ex: [JSONValue]) -> Bool {
        for t in ex where has(ts, t) { return false }
        return true
    }

    /// The verbs of the catalog, in catalog order, whose trait closure contains every `allOf` trait and none of the `noneOf` traits.
    public static func classVerbs(_ cat: JSONValue, _ allOf: [JSONValue], _ noneOf: [JSONValue]) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for vo in try list(GV.get(cat, "verbs")) {
            let v = try mx(vo)
            let ts = try list(at(v, "traits"))
            if hasAll(ts, allOf) && hasNone(ts, noneOf) { out.append(at(v, "verb") ?? .null) }
        }
        return out
    }

    /// The verbs a class ALLOW covers: the class, minus every unconfirmed verb.
    public static func allowClassVerbs(_ cat: JSONValue, _ allOf: [JSONValue], _ noneOf: [JSONValue]) throws -> [JSONValue] {
        var none = noneOf
        none.append(.string(UNREVIEWED))
        return try classVerbs(cat, allOf, none)
    }

    /// The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says.
    public static func floatClassVerbs(_ cat: JSONValue, _ allOf: [JSONValue], _ noneOf: [JSONValue]) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for vo in try list(GV.get(cat, "verbs")) {
            let v = try mx(vo)
            let ts = try list(at(v, "traits"))
            if has(ts, .string(UNREVIEWED)) || (hasAll(ts, allOf) && hasNone(ts, noneOf)) { out.append(at(v, "verb") ?? .null) }
        }
        return out
    }

    // ---------------- role resolution ----------------

    private static func declOf(_ ont: JSONValue, _ verb: String) throws -> JObject? {
        for v in try list(GV.get(ont, "verbs")) where IV.strictEq(GV.get(v, "verb"), .string(verb)) { return v.asObject }
        return nil
    }

    private static func infoOf(_ cat: JSONValue, _ verb: JSONValue?) throws -> JObject? {
        for v in try list(GV.get(cat, "verbs")) where IV.strictEq(GV.get(v, "verb"), verb) { return v.asObject }
        return nil
    }

    /// The one parameter of `verb` carrying `role`, as {path, ty}; none, several or undeclared: nil.
    public static func resolveRole(_ ont: JSONValue, _ cat: JSONValue, _ verb: String, _ role: String) throws -> JSONValue? {
        let info = try infoOf(cat, .string(verb))
        let decl = try declOf(ont, verb)
        guard let inf = info, let dc = decl else { return nil }
        let roles = try mx(at(inf, "roles"))
        let paths: [JSONValue] = try (roles[JKey(role)] != nil ? list(roles[JKey(role)]) : [])
        if paths.count != 1 { return nil }
        for p in try list(at(dc, "params")) where IV.strictEq(GV.get(p, "path"), paths[0]) {
            return mk([("path", GV.get(p, "path")), ("ty", GV.get(p, "ty"))])
        }
        return nil
    }

    private static func resolveTerm(_ ont: JSONValue, _ cat: JSONValue, _ verb: String, _ t: JSONValue?) throws -> JSONValue? {
        switch GV.kind(t) {
        case "param": return mk([("k", .string("param")), ("path", GV.get(t, "path")), ("ty", GV.get(t, "ty"))])
        case "lit": return mk([("k", .string("lit")), ("v", GV.get(t, "v"))])
        case "hist": return mk([("k", .string("hist")), ("bid", GV.get(t, "bid")), ("u", GV.get(t, "u"))])
        case "role":
            guard let r = try resolveRole(ont, cat, verb, GV.jsStr(GV.get(t, "role"))) else { return nil }
            return mk([("k", .string("param")), ("path", GV.get(r, "path")), ("ty", GV.get(r, "ty"))])
        default: return nil
        }
    }

    /// nil as soon as one role term is unresolved for the verb.
    private static func resolveCond(_ ont: JSONValue, _ cat: JSONValue, _ verb: String, _ c: JSONValue?) throws -> JSONValue? {
        let k = GV.kind(c)
        switch k {
        case "true": return mk([("k", .string("true"))])
        case "cmp":
            let l = try resolveTerm(ont, cat, verb, GV.get(c, "l"))
            let r = try resolveTerm(ont, cat, verb, GV.get(c, "r"))
            if let lv = l, let rv = r { return mk([("k", .string("cmp")), ("op", GV.get(c, "op")), ("l", lv), ("r", rv)]) }
            return nil
        case "and", "or":
            let a = try resolveCond(ont, cat, verb, GV.get(c, "a"))
            let b = try resolveCond(ont, cat, verb, GV.get(c, "b"))
            if let av = a, let bv = b { return mk([("k", .string(k)), ("a", av), ("b", bv)]) }
            return nil
        case "not":
            guard let a = try resolveCond(ont, cat, verb, GV.get(c, "c")) else { return nil }
            return mk([("k", .string("not")), ("c", a)])
        default: return nil
        }
    }

    // ---------------- the expansion ----------------

    /// An expanded grant with the source grant id it came from.
    private struct EG {
        let src: JSONValue?
        let g: JSONValue
        var gid: JSONValue? { GV.get(g, "gid") }
        var verb: JSONValue? { GV.get(g, "verb") }
    }

    private static func grantVerbs(_ cat: JSONValue, _ s: JSONValue?) throws -> [JSONValue] {
        if GV.kind(s) == "verb" { return [GV.get(s, "verb") ?? .null] }
        return try allowClassVerbs(cat, try list(GV.get(s, "all_of")), try list(GV.get(s, "none_of")))
    }

    private static func expandGrants(_ ont: JSONValue, _ cat: JSONValue, _ gs: [JSONValue], _ report: inout [JSONValue]) throws -> [EG] {
        var out: [EG] = []
        for gro in gs {
            let gr = try mx(gro)
            let sel = at(gr, "sel")
            let verbs = try grantVerbs(cat, sel)
            var dropped: [JSONValue] = []
            for vo in verbs {
                let v = try verbName(vo)
                guard let c = try resolveCond(ont, cat, v, at(gr, "cond")) else {
                    dropped.append(GV.obj([("verb", .string(v)), ("reason", .string("role_unresolved"))]))
                    continue
                }
                let gid: JSONValue? = GV.kind(sel) == "class" ? JSONValue.string(GV.jsStr(at(gr, "gid")) + "." + v) : at(gr, "gid")
                out.append(EG(src: at(gr, "gid"), g: mk([("gid", gid), ("verb", .string(v)), ("res", at(gr, "res")), ("cond", c)])))
            }
            report.append(mk([("gid", at(gr, "gid")), ("verbs", .array(verbs)), ("dropped", .array(dropped))]))
        }
        return out
    }

    private static func prohVerbs(_ ont: JSONValue, _ cat: JSONValue, _ t: JSONValue?) throws -> [JSONValue] {
        let k = GV.kind(t)
        if k == "verb" { return [GV.get(t, "verb") ?? .null] }
        if k == "effect" {
            var out: [JSONValue] = []
            for v in try list(GV.get(ont, "verbs")) where IV.strictEq(GV.get(v, "cls"), GV.get(t, "cls")) { out.append(GV.get(v, "verb") ?? .null) }
            return out
        }
        return try floatClassVerbs(cat, try list(GV.get(t, "all_of")), try list(GV.get(t, "none_of")))
    }

    private static func expandProhibits(_ ont: JSONValue, _ cat: JSONValue, _ ps: [JSONValue], _ report: inout [JSONValue]) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for po in ps {
            let p = try mx(po)
            let target = at(p, "target")
            let verbs = try prohVerbs(ont, cat, target)
            var unconditional: [JSONValue] = []
            for vo in verbs {
                let v = try verbName(vo)
                let c = try resolveCond(ont, cat, v, at(p, "cond"))
                if c == nil { unconditional.append(.string(v)) }
                let pid: JSONValue? = GV.kind(target) == "verb" ? at(p, "pid") : JSONValue.string(GV.jsStr(at(p, "pid")) + "." + v)
                out.append(mk([
                    ("pid", pid), ("target", GV.obj([("k", .string("verb")), ("verb", .string(v))])), ("res", at(p, "res")),
                    ("cond", c ?? mk([("k", .string("true"))])),
                ]))
            }
            report.append(mk([("pid", at(p, "pid")), ("verbs", .array(verbs)), ("unconditional", .array(unconditional))]))
        }
        return out
    }

    private static func idsOf(_ es: [EG], _ srcs: [JSONValue]) -> [JSONValue] {
        var r: [JSONValue] = []
        for e in es where has(srcs, e.src) { r.append(e.gid ?? .null) }
        return r
    }

    private static func gidsOfVerbs(_ es: [EG], _ vs: [JSONValue]) -> [JSONValue] {
        var r: [JSONValue] = []
        for e in es where has(vs, e.verb) { r.append(e.gid ?? .null) }
        return r
    }

    private static func verbsOfGids(_ es: [EG], _ gids: [JSONValue]) -> [JSONValue] {
        var r: [JSONValue] = []
        for e in es where has(gids, e.gid) { r.append(e.verb ?? .null) }
        return r
    }

    /// The verbs a bound's role-addressed value must resolve for.
    private static func boundRoleVerbs(_ ont: JSONValue, _ cat: JSONValue, _ es: [EG], _ s: JSONValue?) throws -> [JSONValue] {
        let k = GV.kind(s)
        if k == "gids" { return verbsOfGids(es, idsOf(es, try list(GV.get(s, "gids")))) }
        if k == "effect" {
            var r: [JSONValue] = []
            for v in try list(GV.get(ont, "verbs")) where IV.strictEq(GV.get(v, "cls"), GV.get(s, "cls")) { r.append(GV.get(v, "verb") ?? .null) }
            return r
        }
        if k == "trait" { return verbsOfGids(es, gidsOfVerbs(es, try floatClassVerbs(cat, try list(GV.get(s, "all_of")), try list(GV.get(s, "none_of"))))) }
        return []
    }

    private struct BoundValue {
        let term: JSONValue
        let how: String
    }

    /// One value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when the paths differ but the type is one.
    private static func boundValue(_ ont: JSONValue, _ cat: JSONValue, _ vs: [JSONValue], _ t: JSONValue?) throws -> BoundValue? {
        switch GV.kind(t) {
        case "param": return BoundValue(term: mk([("k", .string("param")), ("path", GV.get(t, "path")), ("ty", GV.get(t, "ty"))]), how: "literal")
        case "lit": return BoundValue(term: mk([("k", .string("lit")), ("v", GV.get(t, "v"))]), how: "literal")
        case "hist": return BoundValue(term: mk([("k", .string("hist")), ("bid", GV.get(t, "bid")), ("u", GV.get(t, "u"))]), how: "literal")
        case "role":
            var rs: [JSONValue] = []
            for v in vs {
                guard let r = try resolveRole(ont, cat, try verbName(v), GV.jsStr(GV.get(t, "role"))) else { return nil }
                rs.append(r)
            }
            if rs.isEmpty { return nil }
            var samePath = true
            var sameTy = true
            let ty0 = GV.stringify(GV.get(rs[0], "ty"))
            for r in rs {
                if !IV.strictEq(GV.get(r, "path"), GV.get(rs[0], "path")) { samePath = false }
                if !IV.same(GV.stringify(GV.get(r, "ty")), ty0) { sameTy = false }
            }
            if samePath && sameTy { return BoundValue(term: mk([("k", .string("param")), ("path", GV.get(rs[0], "path")), ("ty", GV.get(rs[0], "ty"))]), how: "shared_path") }
            if sameTy { return BoundValue(term: mk([("k", .string("param")), ("path", .string("@" + GV.jsStr(GV.get(t, "role")))), ("ty", GV.get(rs[0], "ty"))]), how: "role_key") }
            return nil
        default: return nil
        }
    }

    private static func mkBound(_ b: JObject, _ bv: BoundValue, _ sel: JSONValue) -> JSONValue {
        mk([
            ("bid", at(b, "bid")), ("sel", sel), ("agg", at(b, "agg")), ("value", bv.term), ("key", at(b, "key")), ("window", at(b, "window")),
            ("scope", at(b, "scope")), ("cap", at(b, "cap")), ("onExceed", at(b, "onExceed")),
        ])
    }

    private static func expandBounds(_ ont: JSONValue, _ cat: JSONValue, _ es: [EG], _ bs: [JSONValue], _ report: inout [JSONValue]) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for bo in bs {
            let b = try mx(bo)
            let sel = at(b, "sel")
            guard let bv = try boundValue(ont, cat, try boundRoleVerbs(ont, cat, es, sel), at(b, "value")) else { continue } // a type error (selReasons), never reached when the goal is well typed
            let k = GV.kind(sel)
            var gids: [JSONValue]? = nil
            if k == "gids" { gids = idsOf(es, try list(GV.get(sel, "gids"))) }
            else if k == "trait" { gids = gidsOfVerbs(es, try floatClassVerbs(cat, try list(GV.get(sel, "all_of")), try list(GV.get(sel, "none_of")))) }
            if k == "effect" {
                out.append(mkBound(b, bv, mk([("k", .string("effect")), ("cls", GV.get(sel, "cls"))])))
                report.append(mk([("bid", at(b, "bid")), ("gids", .array([])), ("dropped", .bool(false)), ("value", .string(bv.how))]))
                continue
            }
            guard let g = gids else { throw IrError("unknown bound selector") }
            if g.isEmpty {
                report.append(mk([("bid", at(b, "bid")), ("gids", .array([])), ("dropped", .bool(true)), ("value", .string(bv.how))]))
                continue
            }
            out.append(mkBound(b, bv, mk([("k", .string("gids")), ("gids", .array(g))])))
            report.append(mk([("bid", at(b, "bid")), ("gids", .array(g)), ("dropped", .bool(false)), ("value", .string(bv.how))]))
        }
        return out
    }

    /// Lower a selector goal to an ordinary Goal against the PINNED catalog: {goal, report}. Pure and total; typing is `selReasons` plus the core typechecker.
    public static func expandSelGoal(_ sg: JSONValue, _ ont: JSONValue, _ cat: JSONValue) throws -> JSONValue {
        var gReport: [JSONValue] = []
        var pReport: [JSONValue] = []
        var bReport: [JSONValue] = []
        let es = try expandGrants(ont, cat, try list(GV.get(sg, "grants")), &gReport)
        let prohibits = try expandProhibits(ont, cat, try list(GV.get(sg, "prohibits")), &pReport)
        let bounds = try expandBounds(ont, cat, es, try list(GV.get(sg, "bounds")), &bReport)
        var deleg = try mx(GV.get(sg, "deleg"))
        deleg[JKey("mayTouch")] = .array(idsOf(es, try list(at(deleg, "mayTouch"))))
        var holes: [JSONValue] = []
        for ho in try list(GV.get(sg, "holes")) {
            var h = try mx(ho)
            h[JKey("affects")] = .array(idsOf(es, try list(at(h, "affects"))))
            holes.append(.object(h))
        }
        let goal = mk([
            ("v", .int(1)), ("principal", GV.get(sg, "principal")), ("ontDigest", GV.get(sg, "ontDigest")), ("nlDigest", GV.get(sg, "nlDigest")),
            ("sources", GV.get(sg, "sources")), ("grants", .array(es.map { $0.g })), ("prohibits", .array(prohibits)), ("bounds", .array(bounds)),
            ("validity", GV.get(sg, "validity")), ("deleg", .object(deleg)), ("escalateOn", GV.get(sg, "escalateOn")),
            ("wildcardAck", .array(idsOf(es, try list(GV.get(sg, "wildcardAck"))))), ("holes", .array(holes)),
        ])
        return GV.obj([("goal", goal), ("report", GV.obj([("grants", .array(gReport)), ("prohibits", .array(pReport)), ("bounds", .array(bReport))]))])
    }

    // ---------------- typing of the selector layer ----------------

    private static func allKnown(_ known: [JSONValue], _ ids: [JSONValue]) -> Bool {
        for i in ids {
            guard let s = i.asString, !s.isEmpty, has(known, i) else { return false }
        }
        return true
    }

    private static func grantSelOk(_ cat: JSONValue, _ g: JSONValue?) throws -> Bool {
        let s = GV.get(g, "sel")
        if GV.kind(s) == "verb" { return true }
        let allOf = try list(GV.get(s, "all_of"))
        if allOf.isEmpty { return false }
        if !(try list(GV.get(s, "none_of"))).isEmpty { return false }
        return allKnown(try list(GV.get(cat, "known")), allOf)
    }

    private static func prohSelOk(_ cat: JSONValue, _ p: JSONValue?) throws -> Bool {
        let t = GV.get(p, "target")
        if GV.kind(t) != "trait" { return true }
        let known = try list(GV.get(cat, "known"))
        if !allKnown(known, try list(GV.get(t, "all_of"))) { return false }
        return allKnown(known, try list(GV.get(t, "none_of")))
    }

    private static func boundSelOk(_ cat: JSONValue, _ gs: [JSONValue], _ b: JSONValue?) throws -> Bool {
        let s = GV.get(b, "sel")
        let k = GV.kind(s)
        if k == "gids" {
            for i in try list(GV.get(s, "gids")) {
                var found = false
                for g in gs where IV.strictEq(GV.get(g, "gid"), i) { found = true }
                if !found { return false }
            }
            return true
        }
        if k == "effect" { return true }
        let known = try list(GV.get(cat, "known"))
        if !allKnown(known, try list(GV.get(s, "all_of"))) { return false }
        return allKnown(known, try list(GV.get(s, "none_of")))
    }

    /// `^[0-9A-Za-z_]{1,64}$` on the string form of an id (the expanded id `<gid>.<verb>` then sorts exactly as (gid, verb)).
    private static func selId(_ v: JSONValue?) -> Bool {
        let u = Array(JS.toString(v).utf16)
        if u.isEmpty || u.count > 64 { return false }
        for c in u {
            let ok = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 95
            if !ok { return false }
        }
        return true
    }

    /// The type reasons of the selector layer, in the order of the formal model, preceded by the checks about the wire rather than the
    /// semantics: the pin (`catalog_digest_mismatch`) and the id grammar (`bad_id`). An empty list is well typed at this layer.
    public static func selReasons(_ sg: JSONValue, _ ont: JSONValue, _ cat: JSONValue) throws -> [JSONValue] {
        var out: [JSONValue] = []
        if !IV.strictEq(GV.get(sg, "catDigest"), .string(try selCatalogDigest(cat))) { out.append(.string("catalog_digest_mismatch")) }
        let grants = try list(GV.get(sg, "grants"))
        var ids: [JSONValue?] = []
        for g in grants { ids.append(GV.get(g, "gid")) }
        for p in try list(GV.get(sg, "prohibits")) { ids.append(GV.get(p, "pid")) }
        for b in try list(GV.get(sg, "bounds")) { ids.append(GV.get(b, "bid")) }
        var idsOk = true
        for i in ids where !selId(i) { idsOk = false }
        if !idsOk { out.append(.string("bad_id")) }
        var catOk = true
        for v in try list(GV.get(cat, "verbs")) {
            if try declOf(ont, try verbName(GV.get(v, "verb") ?? .null)) == nil { catOk = false }
        }
        if !catOk { out.append(.string("catalog_mismatch")) }
        var g1 = true
        var p1 = true
        var b1 = true
        for g in grants { if !(try grantSelOk(cat, g)) { g1 = false } }
        if !g1 { out.append(.string("bad_grant_selector")) }
        for p in try list(GV.get(sg, "prohibits")) { if !(try prohSelOk(cat, p)) { p1 = false } }
        if !p1 { out.append(.string("bad_prohibit_selector")) }
        for b in try list(GV.get(sg, "bounds")) { if !(try boundSelOk(cat, grants, b)) { b1 = false } }
        if !b1 { out.append(.string("bad_bound_selector")) }
        var scratch: [JSONValue] = []
        let es = try expandGrants(ont, cat, grants, &scratch)
        var rb = true
        for b in try list(GV.get(sg, "bounds")) {
            let bo = try mx(b)
            if try boundValue(ont, cat, try boundRoleVerbs(ont, cat, es, at(bo, "sel")), at(bo, "value")) == nil { rb = false }
        }
        if !rb { out.append(.string("unresolved_role_bound")) }
        return out
    }

    /// CompileX: selector reasons first (fail closed), then expansion and the core compiler. `compileGoal` is the injected proved
    /// compiler (goal, ontology) -> {ok: true, policy} | {ok: false, reasons}. Returns {ok, policy, goal, report} or {ok: false, reasons}.
    public static func compileSelGoal(_ sg: JSONValue, _ ont: JSONValue, _ cat: JSONValue, _ compileGoal: (JSONValue, JSONValue) throws -> JSONValue) throws -> JSONValue {
        let rs = try selReasons(sg, ont, cat)
        if !rs.isEmpty { return GV.obj([("ok", .bool(false)), ("reasons", .array(rs))]) }
        let ex = try expandSelGoal(sg, ont, cat)
        guard let goal = GV.get(ex, "goal") else { throw IrError("no goal") }
        let c = try compileGoal(goal, ont)
        if GV.get(c, "ok") == JSONValue.bool(true) {
            return mk([("ok", .bool(true)), ("policy", GV.get(c, "policy")), ("goal", goal), ("report", GV.get(ex, "report"))])
        }
        return mk([("ok", .bool(false)), ("reasons", GV.get(c, "reasons"))])
    }

    // ---------------- acts ----------------

    /// Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
    /// supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first.
    public static func withRoleParams(_ act: JSONValue, _ cat: JSONValue) throws -> JSONValue {
        var params = JObject()
        for (k, v) in try mx(GV.get(act, "params")) where !IV.startsWith(k.s, "@") { params[k] = v }
        if let info = try infoOf(cat, GV.get(act, "verb")) {
            let roles = try mx(at(info, "roles"))
            // the added `@role` members follow the parameters in the roles' own order (insertion order of the reference), not in code-unit order
            var ord = params.keys.map { $0.ord }.max() ?? 0
            for k in JS.keyOrder(roles).map({ $0.s }) {
                let paths = try list(roles[JKey(k)])
                if paths.count == 1, let pv = params[JKey(GV.jsStr(paths[0]))] { ord += 1; params[JKey("@" + k, ord: ord)] = pv }
            }
        }
        var r = try mx(act)
        r[JKey("params")] = .object(params)
        return .object(r)
    }

    // ---------------- the policy card ----------------

    private static func phrase(_ reg: TraitRegistry, _ id: JSONValue) -> String {
        if let s = id.asString, let t = reg.traits[JKey(s)] { return t.cardPhrase }
        return GV.jsStr(id)
    }

    private static func selectorText(_ all: [JSONValue], _ none: [JSONValue], _ reg: TraitRegistry) -> String {
        let ap: [String] = all.map { phrase(reg, $0) }
        let a: String = all.isEmpty ? "every action" : "every action that " + ap.joined(separator: " and ")
        if none.isEmpty { return a }
        let np: [String] = none.map { phrase(reg, $0) }
        return a + ", except those that " + np.joined(separator: " or ")
    }

    private static func qs(_ v: JSONValue?) -> String { GV.q(GV.jsStr(v)) }

    private static func qlist(_ xs: [JSONValue]) -> String { xs.map { qs($0) }.joined(separator: ", ") }

    /// The card of a selector goal: one line per selector clause in the words of the trait phrases, then the card of the expansion.
    /// `reg` nil: the core registry. {lines, warnings}.
    public static func renderSelCard(_ sg: JSONValue, _ ont: JSONValue, _ cat: JSONValue, _ reg: TraitRegistry?) throws -> JSONValue {
        let rg: TraitRegistry = reg ?? Actions.coreRegistry
        let ex = try expandSelGoal(sg, ont, cat)
        let report = ex.get("report") ?? .null
        var lines: [JSONValue] = []
        var warnings: [JSONValue] = []
        let grants = try list(GV.get(sg, "grants"))
        let gReports = try list(GV.get(report, "grants"))
        for i in 0..<grants.count {
            let g = try mx(grants[i])
            let r = try mx(i < gReports.count ? gReports[i] : nil)
            let sel = at(g, "sel")
            let verbs = try list(at(r, "verbs"))
            if GV.kind(sel) == "class" {
                let head = selectorText(try list(GV.get(sel, "all_of")), [], rg)
                lines.append(.string("ALLOW " + qs(at(g, "gid")) + ": " + head + " [\(verbs.count) verb(s) in the pinned catalog: " + qlist(verbs) + "]"))
            }
            for d in try list(at(r, "dropped")) {
                warnings.append(.string("grant " + qs(at(g, "gid")) + " does not cover " + qs(GV.get(d, "verb")) + ": it has no unique parameter for a role the condition names"))
            }
        }
        let prohibits = try list(GV.get(sg, "prohibits"))
        let pReports = try list(GV.get(report, "prohibits"))
        for i in 0..<prohibits.count {
            let p = try mx(prohibits[i])
            let r = try mx(i < pReports.count ? pReports[i] : nil)
            let t = at(p, "target")
            let verbs = try list(at(r, "verbs"))
            if GV.kind(t) == "trait" {
                let head = selectorText(try list(GV.get(t, "all_of")), try list(GV.get(t, "none_of")), rg)
                lines.append(.string("NEVER " + qs(at(p, "pid")) + ": " + head + ", today \(verbs.count) verb(s) [" + qlist(verbs) + "]; it also covers every verb added to the catalog later"))
            }
            for v in try list(at(r, "unconditional")) {
                warnings.append(.string("prohibition " + qs(at(p, "pid")) + " applies to " + qs(v) + " without its condition: the verb has no unique parameter for a role the condition names"))
            }
        }
        let bounds = try list(GV.get(sg, "bounds"))
        let bReports = try list(GV.get(report, "bounds"))
        for i in 0..<bounds.count {
            let b = try mx(bounds[i])
            let r: JSONValue? = i < bReports.count ? bReports[i] : nil
            let sel = at(b, "sel")
            if GV.kind(sel) == "trait", let rv = r {
                let head = selectorText(try list(GV.get(sel, "all_of")), try list(GV.get(sel, "none_of")), rg)
                let n = try list(GV.get(rv, "gids")).count
                lines.append(.string("LIMIT " + qs(at(b, "bid")) + ": over " + head + " (\(n) grant(s))"))
            }
            if let rv = r, GV.get(rv, "dropped") == JSONValue.bool(true) {
                warnings.append(.string("limit " + qs(at(b, "bid")) + " selects no grant and bounds nothing"))
            }
            if let rv = r, GV.get(rv, "value") == JSONValue.string("role_key") {
                warnings.append(.string("limit " + qs(at(b, "bid")) + " sums a role the verbs carry on different parameters: the action must supply the role key"))
            }
        }
        let core = try PCAGoalCard.renderCard(try objV(GV.get(ex, "goal")))
        return GV.obj([("lines", .array(lines + (try list(GV.get(core, "lines"))))), ("warnings", .array(warnings + (try list(GV.get(core, "warnings")))))])
    }

    private static func objV(_ v: JSONValue?) throws -> JSONValue { .object(try mx(v)) }

    /// The closure of a trait id list under the registry (a selector written with a parent trait covers the children by `implies`). `reg` nil: core.
    public static func traitClosure(_ ids: [JSONValue], _ reg: TraitRegistry?) throws -> [String] {
        try Actions.closure(reg ?? Actions.coreRegistry, ids)
    }

    // ---------------- the carrier form (the differential with the extracted model) ----------------

    private static let ROLE_MARK = "\u{1}role:"

    private static func carryTerm(_ t: JSONValue?) -> JSONValue {
        switch GV.kind(t) {
        case "role": return mk([("k", .string("param")), ("path", .string(ROLE_MARK + GV.jsStr(GV.get(t, "role")))), ("ty", GV.obj([("k", .string("s"))]))])
        case "param": return mk([("k", .string("param")), ("path", GV.get(t, "path")), ("ty", GV.get(t, "ty"))])
        case "lit": return mk([("k", .string("lit")), ("v", GV.get(t, "v"))])
        default: return mk([("k", .string("hist")), ("bid", GV.get(t, "bid")), ("u", GV.get(t, "u"))])
        }
    }

    private static func carryCond(_ c: JSONValue?) throws -> JSONValue {
        let k = GV.kind(c)
        switch k {
        case "true": return mk([("k", .string("true"))])
        case "cmp": return mk([("k", .string("cmp")), ("op", GV.get(c, "op")), ("l", carryTerm(GV.get(c, "l"))), ("r", carryTerm(GV.get(c, "r")))])
        case "and", "or":
            let a = try carryCond(GV.get(c, "a"))
            let b = try carryCond(GV.get(c, "b"))
            return mk([("k", .string(k)), ("a", a), ("b", b)])
        case "not": return mk([("k", .string("not")), ("c", try carryCond(GV.get(c, "c")))])
        default: throw IrError("unknown condition")
        }
    }

    /// `all.join("\u{2}") + "\u{1}" + none.join("\u{2}")` (a null member joins as the empty string).
    private static func sel2(_ all: [JSONValue], _ none: [JSONValue]) -> String {
        func join(_ xs: [JSONValue]) -> String { xs.map { $0 == .null ? "" : GV.jsStr($0) }.joined(separator: "\u{2}") }
        return join(all) + "\u{1}" + join(none)
    }

    /// An ordinary Goal carrying a selector goal (selectors ride in strings and role-marked params), so the extracted model decodes it with its existing Goal decoder.
    public static func selCarrier(_ sg: JSONValue) throws -> JSONValue {
        var grants: [JSONValue] = []
        for go in try list(GV.get(sg, "grants")) {
            let g = try mx(go)
            let s = at(g, "sel")
            let verb: String
            if GV.kind(s) == "verb" { verb = "V\u{1}" + GV.jsStr(GV.get(s, "verb")) } else { verb = "C\u{1}" + sel2(try list(GV.get(s, "all_of")), try list(GV.get(s, "none_of"))) }
            grants.append(mk([("gid", at(g, "gid")), ("verb", .string(verb)), ("res", at(g, "res")), ("cond", try carryCond(at(g, "cond")))]))
        }
        var prohibits: [JSONValue] = []
        for po in try list(GV.get(sg, "prohibits")) {
            let p = try mx(po)
            let t = at(p, "target")
            let k = GV.kind(t)
            let verb: String
            if k == "verb" { verb = "V\u{1}" + GV.jsStr(GV.get(t, "verb")) }
            else if k == "effect" { verb = "E\u{1}" + GV.jsStr(GV.get(t, "cls")) }
            else { verb = "T\u{1}" + sel2(try list(GV.get(t, "all_of")), try list(GV.get(t, "none_of"))) }
            prohibits.append(mk([("pid", at(p, "pid")), ("res", at(p, "res")), ("cond", try carryCond(at(p, "cond"))), ("target", GV.obj([("k", .string("verb")), ("verb", .string(verb))]))]))
        }
        var bounds: [JSONValue] = []
        for bo in try list(GV.get(sg, "bounds")) {
            let b = try mx(bo)
            let s = at(b, "sel")
            let k = GV.kind(s)
            let sel: JSONValue
            if k == "gids" { sel = mk([("k", .string("gids")), ("gids", GV.get(s, "gids"))]) }
            else if k == "effect" { sel = mk([("k", .string("effect")), ("cls", GV.get(s, "cls"))]) }
            else { sel = mk([("k", .string("effect")), ("cls", .string("T\u{1}" + sel2(try list(GV.get(s, "all_of")), try list(GV.get(s, "none_of")))))]) }
            bounds.append(mk([
                ("bid", at(b, "bid")), ("key", at(b, "key")), ("window", at(b, "window")), ("scope", at(b, "scope")), ("cap", at(b, "cap")),
                ("onExceed", at(b, "onExceed")), ("agg", at(b, "agg")), ("value", carryTerm(at(b, "value"))), ("sel", sel),
            ]))
        }
        return mk([
            ("v", .int(1)), ("principal", GV.get(sg, "principal")), ("ontDigest", GV.get(sg, "ontDigest")), ("nlDigest", GV.get(sg, "nlDigest")),
            ("sources", GV.get(sg, "sources")), ("grants", .array(grants)), ("prohibits", .array(prohibits)), ("bounds", .array(bounds)),
            ("validity", GV.get(sg, "validity")), ("deleg", GV.get(sg, "deleg")), ("escalateOn", GV.get(sg, "escalateOn")),
            ("wildcardAck", GV.get(sg, "wildcardAck")), ("holes", GV.get(sg, "holes")),
        ])
    }

    private static func tok(_ t: String, _ v: JSONValue) -> JSONValue { .array([.string(t), v]) }

    private static func tapeStrs(_ out: inout [JSONValue], _ xs: [JSONValue]) {
        out.append(tok("i", .int(Int64(xs.count))))
        for x in xs { out.append(tok("s", x)) }
    }

    /// The catalog tape `DecCatalog` reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*.
    /// A parsed catalog has no member order: the roles of a verb are read in code-unit order.
    public static func encodeSelCatalog(_ c: JSONValue) throws -> [JSONValue] {
        var out: [JSONValue] = []
        tapeStrs(&out, try list(GV.get(c, "known")))
        let verbs = try list(GV.get(c, "verbs"))
        out.append(tok("i", .int(Int64(verbs.count))))
        for vo in verbs {
            let v = try mx(vo)
            out.append(tok("s", at(v, "verb") ?? .null))
            tapeStrs(&out, try list(at(v, "traits")))
            let roles = try mx(at(v, "roles"))
            out.append(tok("i", .int(Int64(roles.count))))
            for k in JS.keyOrder(roles).map({ $0.s }) {
                out.append(tok("s", .string(k)))
                tapeStrs(&out, try list(roles[JKey(k)]))
            }
        }
        return out
    }
}
