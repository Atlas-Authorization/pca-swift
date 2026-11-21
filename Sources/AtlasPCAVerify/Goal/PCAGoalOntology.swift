import Foundation

/// The intent-fidelity ontology: the signed authoring vocabulary (types, units, relations, verbs, aliases, templates), its
/// well-formedness checker, the projection onto the Goal IR ontology, template instantiation and locale-aware amount parsing.
/// An ontology, a template and a slot value are parsed JSON objects, like the reference objects. A parsed object keeps no member
/// order: where the reference walks the members of an object (units, params, aliases) the walk is in JavaScript key order for a
/// parsed object (array-index keys ascending, then code-unit order), which is the order the reference's own corpus inputs have
/// whenever a case yields more than one defect from different members.
public enum PCAGoalOntology {
    public static let EFFECT_CLASSES: [String] = ["read", "reversible", "external_send", "irreversible"]

    private static let FOREVER: Int64 = GV.MAX_SAFE

    // ---------------- small value helpers ----------------

    /// A JSON null and a missing member are the same "absent" value.
    private static func nn(_ v: JSONValue?) -> JSONValue? {
        if let x = v, x != JSONValue.null { return x }
        return nil
    }

    private static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        return nn(a) == nn(b)
    }

    private static func nv(_ v: JSONValue?) -> JSONValue { return v ?? JSONValue.null }

    private static func gv(_ v: JSONValue?, _ k: String) -> JSONValue? { return GV.get(v, k) }

    private static func list(_ v: JSONValue?) throws -> [JSONValue] { return try GV.arr(v, "") }

    /// A required object (a missing one throws, like the reference's property access on undefined).
    private static func mx(_ v: JSONValue?) throws -> JSONValue {
        guard let x = v, x.asObject != nil else { throw IrError("object expected") }
        return x
    }

    private static func strOf(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw IrError("string expected") }
        return s
    }

    /// A String or absent; anything else is a refusal (a failed cast in the reference).
    private static func strOrNil(_ v: JSONValue?) throws -> String? {
        guard let x = nn(v) else { return nil }
        guard let s = x.asString else { throw IrError("string expected") }
        return s
    }

    private static func obj(_ v: JSONValue?) -> JSONValue? {
        if let x = v, x.asObject != nil { return x }
        return nil
    }

    private static func eqs(_ v: JSONValue?, _ s: String) -> Bool {
        guard let x = v?.asString else { return false }
        return IV.same(x, s)
    }

    private static func has(_ xs: [JSONValue?], _ x: JSONValue?) -> Bool {
        for y in xs { if same(y, x) { return true } }
        return false
    }

    private static func addUnique(_ xs: inout [JSONValue?], _ x: JSONValue?) {
        if !has(xs, x) { xs.append(x) }
    }

    private static func hasStr(_ xs: [String], _ x: String) -> Bool {
        for y in xs { if IV.same(y, x) { return true } }
        return false
    }

    /// The members of an object in JavaScript key order for a parsed object.
    private static func members(_ v: JSONValue?) -> [(String, JSONValue)] {
        guard let o = v?.asObject else { return [] }
        let names: [String] = JS.keyOrder(o).map { $0.s }
        var out: [(String, JSONValue)] = []
        for k in names {
            if let x = o[JKey(k)] { out.append((k, x)) }
        }
        return out
    }

    private static func isInvisible(_ u: Unicode.Scalar) -> Bool {
        let v = u.value
        return (v >= 0x200B && v <= 0x200F) || v == 0x2060 || v == 0xFEFF
    }

    private static func hasInvisible(_ s: String) -> Bool {
        for u in s.unicodeScalars { if isInvisible(u) { return true } }
        return false
    }

    private static func hasNonPrintable(_ s: String) -> Bool {
        for u in s.unicodeScalars { if u.value < 0x20 || u.value > 0x7e { return true } }
        return false
    }

    private static func nfkc(_ s: String) -> String { return s.precomposedStringWithCompatibilityMapping }

    private static func norm(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for u in nfkc(s).lowercased().unicodeScalars where !isInvisible(u) { out.append(u) }
        return String(out)
    }

    /// `^[A-Za-z0-9_-]+$`
    private static func idLike(_ v: String) -> Bool {
        if v.isEmpty { return false }
        for u in v.unicodeScalars {
            let c = u.value
            let ok = (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F || c == 0x2D
            if !ok { return false }
        }
        return true
    }

    private static func noInvisible(_ x: String) -> Bool {
        return IV.same(x, nfkc(x)) && !hasInvisible(x)
    }

    // ---------------- digest and signing ----------------

    public static func ontologyDigest(_ o: JSONValue) throws -> String {
        let wrapped: JSONValue = GV.obj([("d", .string("atlas-pca/goal-intent-ontology/v1")), ("ontology", o)])
        return try PCAGoalDigests.hashCanonical(wrapped)
    }

    public static func signOntology(_ o: JSONValue, _ seed: [UInt8]) throws -> JSONValue {
        return try PCAGoalSign.signPayload("ontology", o, seed)
    }

    public static func verifyOntology(_ s: JSONValue?, _ pins: [JSONValue]) -> Bool {
        return PCAGoalSign.verifyPayload(s, "ontology", pins)
    }

    /// The declared canonical verb for `word` (the word itself when it is a verb id, else its alias); nil when neither. Case and
    /// homoglyph variants are NOT guessed.
    public static func resolveVerb(_ o: JSONValue, _ word: String) throws -> String? {
        let w = Attest.jsTrim(word)
        for v in try list(gv(o, "verbs")) {
            if eqs(gv(v, "id"), w) { return w }
        }
        if let al = obj(gv(o, "aliases")), GV.has(al, w) {
            return gv(al, w)?.asString
        }
        return nil
    }

    // ---------------- projection onto the IR ontology ----------------

    /// The currency a goal is written in: the first money quantity in its conditions or bound caps (nil for a goal without money).
    public static func goalCcy(_ g: JSONValue) throws -> String? {
        var found: String? = nil
        for gr in try list(gv(g, "grants")) { try condCcy(obj(gv(gr, "cond")), &found) }
        for p in try list(gv(g, "prohibits")) { try condCcy(obj(gv(p, "cond")), &found) }
        for c in try list(gv(g, "escalateOn")) { try condCcy(obj(c), &found) }
        for b in try list(gv(g, "bounds")) {
            if found == nil {
                if let u = obj(gv(gv(b, "cap"), "u")), eqs(gv(u, "k"), "money") { found = try strOrNil(gv(u, "ccy")) }
            }
        }
        return found
    }

    private static func termCcy(_ x: JSONValue?, _ found: inout String?) throws {
        guard let x = x, eqs(gv(x, "k"), "lit") else { return }
        let v = obj(gv(x, "v"))
        var items: [JSONValue] = []
        if GV.kind(v) == "set" { items = try list(gv(v, "items")) } else { items = [nv(v)] }
        for it in items {
            if found == nil && GV.kind(it) == "q" {
                if let u = obj(gv(gv(it, "q"), "u")), eqs(gv(u, "k"), "money") { found = try strOrNil(gv(u, "ccy")) }
            }
        }
    }

    private static func condCcy(_ x: JSONValue?, _ found: inout String?) throws {
        let k = GV.kind(x)
        if k == "cmp" {
            try termCcy(obj(gv(x, "l")), &found)
            try termCcy(obj(gv(x, "r")), &found)
        } else if k == "and" || k == "or" {
            try condCcy(obj(gv(x, "a")), &found)
            try condCcy(obj(gv(x, "b")), &found)
        } else if k == "not" {
            try condCcy(obj(gv(x, "c")), &found)
        }
    }

    private static func paramTy(_ p: JSONValue, _ ccy: String?) throws -> JSONValue {
        let kind = gv(p, "kind")
        if eqs(kind, "id") || eqs(kind, "enum") || eqs(kind, "text") { return GV.obj([("k", .string("s"))]) }
        if eqs(kind, "money") {
            guard let ccys = gv(p, "ccys")?.asArray else { throw IrError("money parameter lists no currency") }
            let c: String
            if let cc = ccy, hasStr(ccys.compactMap { $0.asString }, cc) {
                c = cc
            } else if hasStr(ccys.compactMap { $0.asString }, "USD") {
                c = "USD"
            } else {
                // an empty list has no first member: the reference's `ccys![0]` is undefined (no throw), so the unit carries no currency
                if ccys.isEmpty { return GV.obj([("k", .string("q")), ("u", GV.obj([("k", .string("money"))]))]) }
                guard let first = ccys.first?.asString else { throw IrError("money parameter lists no currency") }
                c = first
            }
            return GV.obj([("k", .string("q")), ("u", GV.obj([("k", .string("money")), ("ccy", .string(c))]))])
        }
        return GV.obj([("k", .string("q")), ("u", GV.obj([("k", nv(kind))]))])
    }

    /// The Goal IR ontology (verbs with effect class and typed parameters, relation tables) of an intent ontology. `ccy` and `rels` may be nil.
    public static func toIrOntology(_ o: JSONValue, _ ccy: String?, _ rels: JSONValue?) throws -> JSONValue {
        var verbs: [JSONValue] = []
        for vo in try list(gv(o, "verbs")) {
            let v = try mx(vo)
            let params = try mx(gv(v, "params"))
            var keys: [String] = []
            for (k, _) in members(params) { keys.append(k) }
            keys.sort { GV.less($0, $1) }
            var ps: [JSONValue] = []
            for path in keys {
                ps.append(GV.obj([("path", .string(path)), ("ty", try paramTy(try mx(gv(params, path)), ccy))]))
            }
            verbs.append(GV.obj([("verb", nv(gv(v, "id"))), ("cls", nv(gv(v, "effect"))), ("params", .array(ps))]))
        }
        return GV.obj([("verbs", .array(verbs)), ("rels", nn(rels) ?? JSONValue.array([]))])
    }

    /// The IR ontology a goal is typed and decided against: money parameters in the goal's own currency.
    public static func ontologyForGoal(_ o: JSONValue, _ g: JSONValue, _ rels: JSONValue?) throws -> JSONValue {
        return try toIrOntology(o, try goalCcy(g), rels)
    }

    /// Relation anchors a goal mentions, declared with no members.
    public static func goalAnchors(_ g: JSONValue) throws -> JSONValue {
        var out: [JKey: JSONValue] = [:]
        for gr in try list(gv(g, "grants")) { try anchorSel(obj(gv(gr, "res")), &out) }
        for p in try list(gv(g, "prohibits")) { try anchorSel(obj(gv(p, "res")), &out) }
        var keys: [String] = []
        for k in out.keys { keys.append(k.s) }
        keys.sort { GV.less($0, $1) }
        var r: [JSONValue] = []
        for k in keys { if let x = out[JKey(k)] { r.append(x) } }
        return .array(r)
    }

    private static func anchorSel(_ s: JSONValue?, _ out: inout [JKey: JSONValue]) throws {
        let k = GV.kind(s)
        if k == "related" {
            let key = GV.jsStr(gv(s, "rel")) + "\u{0}" + GV.jsStr(gv(s, "anchor"))
            out[JKey(key)] = GV.obj([("rel", nv(gv(s, "rel"))), ("anchor", nv(gv(s, "anchor"))), ("members", .array([]))])
        } else if k == "all_of" {
            for p in try list(gv(s, "parts")) { try anchorSel(obj(p), &out) }
        }
    }

    // ---------------- template references ----------------

    private static func d(_ x: String) -> [String] {
        if IV.startsWith(x, "$") { return [IV.dropPrefix(x, 1)] }
        return []
    }

    private static func refsRes(_ s: JSONValue?) throws -> [String] {
        let k = GV.kind(s)
        var out: [String] = []
        if k == "exact" {
            out.append(contentsOf: d(try strOf(gv(s, "id"))))
        } else if k == "oneof" {
            for i in try list(gv(s, "ids")) { out.append(contentsOf: d(try strOf(i))) }
        } else if k == "related" {
            out.append(contentsOf: d(try strOf(gv(s, "anchor"))))
        } else if k == "all_of" {
            for p in try list(gv(s, "parts")) { out.append(contentsOf: try refsRes(obj(p))) }
        }
        return out
    }

    private static func refsTerm(_ x: JSONValue?) throws -> [String] {
        if GV.kind(x) == "slot" { return [try strOf(gv(x, "slot"))] }
        return []
    }

    private static func refsCond(_ c: JSONValue?) throws -> [String] {
        let k = GV.kind(c)
        var out: [String] = []
        if k == "cmp" {
            out.append(contentsOf: try refsTerm(obj(gv(c, "l"))))
            out.append(contentsOf: try refsTerm(obj(gv(c, "r"))))
        } else if k == "and" || k == "or" {
            out.append(contentsOf: try refsCond(obj(gv(c, "a"))))
            out.append(contentsOf: try refsCond(obj(gv(c, "b"))))
        } else if k == "not" {
            out.append(contentsOf: try refsCond(obj(gv(c, "c"))))
        }
        return out
    }

    private static func refsGrant(_ g: JSONValue) throws -> [String] {
        var r = try refsRes(obj(gv(g, "res")))
        r.append(contentsOf: try refsCond(obj(gv(g, "cond"))))
        return r
    }

    private static func refsBound(_ b: JSONValue) -> [String] {
        let cs = gv(b, "cap_slot")
        return GV.truthy(cs) ? [GV.jsStr(cs)] : []
    }

    private static func slotRefs(_ t: JSONValue) throws -> [String] {
        var r: [String] = []
        for g in try list(gv(t, "grants")) { r.append(contentsOf: try refsGrant(try mx(g))) }
        for p in try list(gv(t, "prohibits")) { r.append(contentsOf: try refsGrant(try mx(p))) }
        for b in try list(gv(t, "bounds")) { r.append(contentsOf: refsBound(try mx(b))) }
        return r
    }

    // ---------------- the well-formedness checker ----------------

    private static func bad(_ issues: inout [JSONValue], _ code: String, _ at: String, _ msg: String) {
        issues.append(GV.obj([("code", .string(code)), ("where", .string(at)), ("msg", .string(msg))]))
    }

    /// An issue whose `where` is the raw member (`v.id`): absent when the member is undefined, as JSON.stringify drops it.
    private static func bad(_ issues: inout [JSONValue], _ code: String, id: JSONValue?, _ msg: String) {
        var m: [(String, JSONValue)] = [("code", .string(code))]
        if let w = id { m.append(("where", w)) }
        m.append(("msg", .string(msg)))
        issues.append(GV.obj(m))
    }

    private static func isInteger(_ v: JSONValue?) -> Bool {
        guard let x = IV.num(v) else { return false }
        return !x.isNaN && !x.isInfinite && x == x.rounded(.down)
    }

    private static func findBy(_ listO: JSONValue?, _ key: String, _ v: JSONValue?) throws -> JSONValue? {
        for x in try list(listO) {
            if x.asObject != nil && same(gv(x, key), v) { return x }
        }
        return nil
    }

    private static func strIncludes(_ listO: JSONValue?, _ v: JSONValue?) -> Bool {
        guard let l = listO?.asArray else { return false }
        for x in l { if same(x, v) { return true } }
        return false
    }

    private static func nonEmpty(_ listO: JSONValue?) -> Bool {
        guard let l = listO?.asArray else { return false }
        return !l.isEmpty
    }

    /// A value whose members are read: JavaScript reads a member of any primitive or array (undefined), and throws only on null or undefined.
    private static func mxl(_ v: JSONValue?) throws -> JSONValue {
        guard let x = v, x != JSONValue.null else { throw IrError("object expected") }
        return x
    }

    /// `for (const x of v)`: an array's elements, a string's code points as strings; anything else is not iterable.
    private static func ilist(_ v: JSONValue?) throws -> [JSONValue] {
        if let s = v?.asString { return s.unicodeScalars.map { JSONValue.string(String($0)) } }
        return try list(v)
    }

    /// Every defect of an intent ontology as {code, where, msg}; an empty list means well formed.
    public static func checkOntology(_ oIn: JSONValue) throws -> JSONValue {
        let o = try mxl(oIn)
        var issues: [JSONValue] = []
        var typeIds: [JSONValue?] = []
        var prefixes: [JSONValue?] = []
        for to in try ilist(gv(o, "types")) {
            let t = try mxl(to)
            let tid = gv(t, "id")
            if has(typeIds, tid) { bad(&issues, "dup_type", id: tid, "duplicate type id") }
            typeIds.append(tid)
            let pre = gv(t, "id_prefix")
            if !GV.truthy(pre) || has(prefixes, pre) { bad(&issues, "dup_prefix", id: tid, "id prefix empty or reused") }
            prefixes.append(pre)
        }
        let units = try mxl(gv(o, "units"))
        for (u, uv) in members(units) {
            let dd = try mxl(uv)
            let money = eqs(gv(dd, "kind"), "money")
            if money {
                let ex = gv(dd, "exponent")
                var okExp = false
                if isInteger(ex), let x = IV.num(ex), x >= 0, x <= 4 { okExp = true }
                if !okExp { bad(&issues, "unit_exponent", u, "money unit needs an integer exponent 0..4") }
            }
            if !money && GV.has(dd, "exponent") { bad(&issues, "unit_exponent", u, "only money units carry an exponent") }
        }
        var relIds: [JSONValue?] = []
        for ro in try ilist(gv(o, "relations")) {
            let r = try mxl(ro)
            if has(relIds, gv(r, "id")) { bad(&issues, "dup_relation", id: gv(r, "id"), "duplicate relation") }
            relIds.append(gv(r, "id"))
            if !has(typeIds, gv(r, "from")) || !has(typeIds, gv(r, "to")) {
                bad(&issues, "relation_type", id: gv(r, "id"), "relation endpoint type is not declared")
            }
        }
        var verbIds: [JSONValue?] = []
        var verbs: [(id: JSONValue?, v: JSONValue)] = []
        for vo in try ilist(gv(o, "verbs")) {
            let v = try mxl(vo)
            let vid = GV.jsStr(gv(v, "id"))
            if has(verbIds, gv(v, "id")) { bad(&issues, "dup_verb", id: gv(v, "id"), "duplicate verb") }
            verbIds.append(gv(v, "id"))
            verbs.append((id: gv(v, "id"), v: v))
            var effectOk = false
            if let e = gv(v, "effect")?.asString { effectOk = hasStr(EFFECT_CLASSES, e) }
            if !effectOk { bad(&issues, "no_effect_class", id: gv(v, "id"), "verb has no valid effect class") }
            if !has(typeIds, gv(v, "resource_type")) { bad(&issues, "verb_resource_type", id: gv(v, "id"), "resource type is not declared") }
            for (p, pv) in members(try mxl(gv(v, "params"))) {
                let pt = try mxl(pv)
                let kind = gv(pt, "kind")
                if eqs(kind, "money") {
                    if !nonEmpty(gv(pt, "ccys")) { bad(&issues, "param_ccy", "\(vid).\(p)", "money parameter lists no currency") }
                    if let cs = gv(pt, "ccys")?.asArray {
                        for c in cs {
                            var ud: JSONValue? = nil
                            if let cstr = c.asString { ud = obj(gv(units, cstr)) }
                            if ud == nil || !eqs(gv(ud, "kind"), "money") {
                                bad(&issues, "unit_unknown", "\(vid).\(p)", "currency " + GV.jsStr(c) + " is not a declared money unit")
                            }
                        }
                    }
                } else if eqs(kind, "enum") {
                    if !nonEmpty(gv(pt, "values")) { bad(&issues, "param_enum", "\(vid).\(p)", "enum parameter has no values") }
                } else if eqs(kind, "id") {
                    if !GV.truthy(gv(pt, "of")) || !has(typeIds, gv(pt, "of")) {
                        bad(&issues, "param_type", "\(vid).\(p)", "id parameter type is not declared")
                    }
                } else if !eqs(kind, "text") {
                    var any = false
                    for (_, ud) in members(units) { if same(gv(ud, "kind"), kind) { any = true } }
                    if !any { bad(&issues, "unit_unknown", "\(vid).\(p)", "no declared unit of kind " + GV.jsStr(kind)) }
                }
            }
        }
        func verbFind(_ id: JSONValue?) -> JSONValue? {
            var hit: JSONValue? = nil
            for e in verbs { if same(e.id, id) { hit = e.v } }
            return hit
        }
        // Alias map: a function, keys normalized and collision-free, targets canonical, no chains or cycles.
        let aliases = try mxl(gv(o, "aliases"))
        var seen: [JKey: String] = [:]
        for (k, target) in members(aliases) {
            if !IV.same(k, norm(k)) || (hasNonPrintable(k) && !IV.same(k, nfkc(k))) {
                bad(&issues, "alias_key", k, "alias key is not in normalized form")
            }
            if hasInvisible(k) { bad(&issues, "alias_key", k, "alias key contains invisible characters") }
            let n = norm(k)
            if let prev = seen[JKey(n)], !IV.same(prev, k) { bad(&issues, "alias_collision", k, "collides with " + prev + " after normalization") }
            seen[JKey(n)] = k
            if !has(verbIds, target) { bad(&issues, "alias_target", k, "alias target is not a canonical verb") }
            if let ts = target.asString, GV.has(aliases, ts) { bad(&issues, "alias_chain", k, "alias target is itself an alias (chain or cycle)") }
            if has(verbIds, JSONValue.string(k)) && !same(JSONValue.string(k), target) { bad(&issues, "alias_shadow", k, "alias shadows a canonical verb") }
        }
        // Templates.
        var tids: [JSONValue?] = []
        for to in try ilist(gv(o, "templates")) {
            let t = try mxl(to)
            let w = "template:" + GV.jsStr(gv(t, "id"))
            if has(tids, gv(t, "id")) { bad(&issues, "dup_template", w, "duplicate template id") }
            tids.append(gv(t, "id"))
            let slots = try ilist(gv(t, "slots"))
            var slotNames: [JSONValue?] = []
            for s in slots { addUnique(&slotNames, gv(s, "name")) }
            if slotNames.count != slots.count { bad(&issues, "dup_slot", w, "duplicate slot") }
            let refs = try slotRefs(t)
            for r in refs { if !has(slotNames, JSONValue.string(r)) { bad(&issues, "slot_undeclared", w, "slot \(r) is used but not declared") } }
            for so in slots {
                let s = try mxl(so)
                let sw = w + "." + GV.jsStr(gv(s, "name"))
                let sk = gv(s, "kind")
                if (eqs(sk, "id") || eqs(sk, "id_list")) && (!GV.truthy(gv(s, "of")) || !has(typeIds, gv(s, "of"))) {
                    bad(&issues, "slot_type", sw, "id slot type is not declared")
                }
                if eqs(sk, "money") {
                    let key: String = gv(s, "ccy")?.asString ?? ""
                    let ud = obj(gv(units, key))
                    if ud == nil || !eqs(gv(ud, "kind"), "money") { bad(&issues, "slot_ccy", sw, "money slot currency is not a declared unit") }
                }
                if (eqs(sk, "enum") || eqs(sk, "enum_list")) && !nonEmpty(gv(s, "values")) { bad(&issues, "slot_enum", sw, "enum slot has no values") }
                if !GV.truthy(gv(s, "mandatory")) && !GV.has(s, "default") {
                    bad(&issues, "slot_default", sw, "optional slot needs a default (an unfilled slot must be a hole or a default)")
                }
                if !hasStr(refs, GV.jsStr(gv(s, "name"))) { bad(&issues, "slot_unused", sw, "declared slot is never used") }
            }
            let tgrants = try ilist(gv(t, "grants"))
            if tgrants.isEmpty { bad(&issues, "empty_allow", w, "template has no grant (empty Allow set)") }
            var gids: [JSONValue?] = []
            for g in tgrants { addUnique(&gids, gv(g, "gid")) }
            if gids.count != tgrants.count { bad(&issues, "dup_gid", w, "duplicate grant id") }
            for go in tgrants {
                let g = try mxl(go)
                let gw = w + "." + GV.jsStr(gv(g, "gid"))
                guard let v = verbFind(gv(g, "verb")) else {
                    bad(&issues, "grant_verb", gw, "grant verb is not in the ontology")
                    continue
                }
                try checkResource(o, obj(gv(g, "res")), v, gw, &issues)
                try checkCond(obj(gv(g, "cond")), v, t, gw, &issues)
                let gres = obj(gv(g, "res"))
                if GV.kind(gres) == "any" {
                    var readBounded = false
                    if eqs(gv(v, "effect"), "read") { readBounded = !(try ilist(gv(t, "bounds"))).isEmpty }
                    if !readBounded { bad(&issues, "unbounded", gw, "wildcard resource in a template") }
                }
                if !eqs(gv(v, "effect"), "read") && GV.kind(gres) == "related" {
                    if (try ilist(gv(t, "bounds"))).isEmpty { bad(&issues, "unbounded", gw, "non-read grant on a related set needs an aggregate bound") }
                }
            }
            for po in try ilist(gv(t, "prohibits")) {
                let p = try mxl(po)
                let tg = try mxl(gv(p, "target"))
                let pw = w + "." + GV.jsStr(gv(p, "pid"))
                if GV.kind(tg) == "verb" && verbFind(gv(tg, "verb")) == nil { bad(&issues, "prohibit_verb", pw, "prohibit verb is not in the ontology") }
                if GV.kind(tg) == "effect" {
                    var known = false
                    if let c = gv(tg, "cls")?.asString { known = hasStr(EFFECT_CLASSES, c) }
                    if !known { bad(&issues, "prohibit_effect", pw, "unknown effect class") }
                }
            }
            for bo in try ilist(gv(t, "bounds")) {
                let b = try mxl(bo)
                let bw = w + "." + GV.jsStr(gv(b, "bid"))
                let over = gv(b, "over")
                if !eqs(over, "all") {
                    var unknown = false
                    for x in try ilist(over) { if !has(gids, x) { unknown = true } }
                    if unknown { bad(&issues, "bound_over", bw, "bound selects an unknown grant") }
                }
                let cslot = gv(b, "cap_slot")
                if GV.truthy(cslot) && !has(slotNames, cslot) { bad(&issues, "slot_undeclared", w, "cap slot " + GV.jsStr(cslot) + " is not declared") }
                if GV.truthy(cslot) {
                    let cs = try findBy(.array(slots), "name", cslot)
                    let ck: JSONValue? = (cs == nil) ? nil : gv(cs, "kind")
                    let agg = gv(b, "agg")
                    if cs != nil && !(eqs(ck, "money") || eqs(ck, "count")) { bad(&issues, "bound_cap", bw, "cap slot must be money or count") }
                    if cs != nil && eqs(agg, "count") && !eqs(ck, "count") { bad(&issues, "bound_cap", bw, "count bound needs a count slot") }
                    if cs != nil && eqs(agg, "sum") && !eqs(ck, "money") { bad(&issues, "bound_cap", bw, "sum bound over money needs a money slot") }
                }
                if eqs(gv(b, "agg"), "sum") && !GV.truthy(gv(b, "param")) { bad(&issues, "bound_value", bw, "sum bound has no value parameter") }
            }
            // non-empty and bounded after instantiation with the declared example
            let g = try instantiateTemplate(o, try strOf(gv(t, "id")), obj(gv(t, "example")), "p", "", nil)
            let holes = try ilist(gv(g, "holes"))
            if !holes.isEmpty {
                var hs: [String] = []
                for h in holes { hs.append(GV.jsStr(gv(h, "hid"))) }
                bad(&issues, "example_holes", w, "example leaves holes: " + hs.joined(separator: ","))
            } else if (try ilist(gv(g, "grants"))).count != tgrants.count {
                bad(&issues, "empty_allow", w, "example instantiation dropped a grant")
            } else if !(try hasAllowWitness(o, g)) {
                bad(&issues, "empty_allow", w, "instantiated template has an empty Allow set")
            }
        }
        return .array(issues)
    }

    private static func prefixOf(_ o: JSONValue, _ typeId: JSONValue?) throws -> String? {
        guard let t = try findBy(gv(o, "types"), "id", typeId) else { return nil }
        return try strOrNil(gv(t, "id_prefix"))
    }

    private static func idOk(_ id: String, _ pre: String?) -> Bool {
        if IV.startsWith(id, "$") { return true }
        if let p = pre { return IV.startsWith(id, p) }
        return false
    }

    private static func checkResource(_ o: JSONValue, _ s: JSONValue?, _ v: JSONValue, _ w: String, _ issues: inout [JSONValue]) throws {
        let prefix = try prefixOf(o, gv(v, "resource_type"))
        let k = GV.kind(s)
        if k == "exact" {
            if !idOk(try strOf(gv(s, "id")), prefix) { bad(&issues, "resource_type", w, "exact resource id has the wrong type prefix") }
        } else if k == "oneof" {
            let ids = try list(gv(s, "ids"))
            if ids.isEmpty { bad(&issues, "resource_empty", w, "one_of is empty") }
            for i in ids { if !idOk(try strOf(i), prefix) { bad(&issues, "resource_type", w, "one_of member has the wrong type prefix") } }
        } else if k == "related" {
            if let r = try findBy(gv(o, "relations"), "id", gv(s, "rel")) {
                if !same(gv(r, "to"), gv(v, "resource_type")) { bad(&issues, "relation_type", w, "relation target type differs from the verb resource type") }
                let anchorPre = try prefixOf(o, gv(r, "from"))
                if !idOk(try strOf(gv(s, "anchor")), anchorPre) { bad(&issues, "resource_type", w, "relation anchor has the wrong type prefix") }
            } else {
                bad(&issues, "relation_unknown", w, "relation " + GV.jsStr(gv(s, "rel")) + " is not declared")
            }
        } else if k == "all_of" {
            let parts = try list(gv(s, "parts"))
            if parts.count < 2 { bad(&issues, "all_of_arity", w, "all_of needs at least two parts") }
            for x in parts { try checkResource(o, obj(x), v, w, &issues) }
        }
    }

    private static func checkCond(_ c: JSONValue?, _ v: JSONValue, _ t: JSONValue, _ w: String, _ issues: inout [JSONValue]) throws {
        let k = GV.kind(c)
        if k == "and" || k == "or" {
            try checkCond(obj(gv(c, "a")), v, t, w, &issues)
            try checkCond(obj(gv(c, "b")), v, t, w, &issues)
            return
        }
        if k == "not" {
            try checkCond(obj(gv(c, "c")), v, t, w, &issues)
            return
        }
        if k != "cmp" { return }
        let l = obj(gv(c, "l"))
        var p: JSONValue? = nil
        if GV.kind(l) == "param" {
            let params = try mx(gv(v, "params"))
            if let path = gv(l, "path")?.asString { p = obj(gv(params, path)) }
        }
        guard GV.kind(l) == "param", let pp = p else {
            bad(&issues, "cond_param", w, "left side of a comparison must be a declared parameter of the verb")
            return
        }
        let op = gv(c, "op")
        let ordered = eqs(op, "lt") || eqs(op, "lte") || eqs(op, "gt") || eqs(op, "gte")
        let pk = gv(pp, "kind")
        if ordered && (eqs(pk, "text") || eqs(pk, "enum") || eqs(pk, "id")) { bad(&issues, "cond_order", w, "ordering on a text/enum/id parameter") }
        let x = obj(gv(c, "r"))
        let xk = GV.kind(x)
        let inOp = eqs(op, "in") || eqs(op, "nin")
        if xk == "slot" {
            guard let s = try findBy(gv(t, "slots"), "name", gv(x, "slot")) else { return }
            let sk = gv(s, "kind")
            var okKind: Bool
            if eqs(pk, "money") {
                okKind = eqs(sk, "money")
            } else {
                okKind = same(pk, sk)
                    || (eqs(pk, "enum") && (eqs(sk, "enum") || eqs(sk, "enum_list")))
                    || (eqs(pk, "id") && (eqs(sk, "id") || eqs(sk, "id_list")))
                    || (eqs(pk, "text") && eqs(sk, "text_list"))
            }
            if !okKind {
                bad(&issues, "cond_type", w, "slot " + GV.jsStr(gv(s, "name")) + " (" + GV.jsStr(sk) + ") does not type-check against parameter kind " + GV.jsStr(pk))
            }
            if eqs(pk, "money") && eqs(sk, "money") && !strIncludes(gv(pp, "ccys"), nn(gv(s, "ccy")) ?? JSONValue.string("")) {
                bad(&issues, "cond_unit", w, "slot currency is not accepted by the parameter")
            }
            let isList = eqs(sk, "id_list") || eqs(sk, "enum_list") || eqs(sk, "text_list")
            if isList != inOp { bad(&issues, "cond_type", w, "list slots pair with in/nin and scalar slots with the other operators") }
        } else if xk == "lit" {
            let lv = obj(gv(x, "v"))
            if GV.kind(lv) == "set" {
                let items = try list(gv(lv, "items"))
                if items.isEmpty { bad(&issues, "cond_type", w, "empty literal list") }
                for i in items { try litCheck(obj(i), pp, w, &issues) }
                if !inOp { bad(&issues, "cond_type", w, "a literal set pairs with in/nin") }
            } else {
                try litCheck(lv, pp, w, &issues)
                if inOp { bad(&issues, "cond_type", w, "in/nin needs a list") }
            }
        } else {
            bad(&issues, "cond_term", w, "unsupported right-hand term")
        }
    }

    private static func litCheck(_ l: JSONValue?, _ p: JSONValue, _ w: String, _ issues: inout [JSONValue]) throws {
        let k = GV.kind(l)
        let pk = gv(p, "kind")
        if k == "q" {
            let u = try mx(gv(gv(l, "q"), "u"))
            if !same(gv(u, "k"), pk) { bad(&issues, "cond_type", w, "literal kind differs from the parameter kind") }
            if eqs(gv(u, "k"), "money") && !strIncludes(gv(p, "ccys"), gv(u, "ccy")) { bad(&issues, "cond_unit", w, "literal currency is not accepted by the parameter") }
        } else if k == "s" {
            if !eqs(pk, "enum") && !eqs(pk, "id") && !eqs(pk, "text") { bad(&issues, "cond_type", w, "literal kind differs from the parameter kind") }
            if eqs(pk, "enum") && !strIncludes(gv(p, "values"), gv(l, "s")) { bad(&issues, "cond_enum", w, "enum literal is not a member") }
        } else {
            bad(&issues, "cond_type", w, "nested literal set")
        }
    }

    private static func hasAllowWitness(_ o: JSONValue, _ g: JSONValue) throws -> Bool {
        let ont = try ontologyForGoal(o, g, nil)
        for gr in try list(gv(g, "grants")) {
            if try PCAGoalExamples.allowWitness(g, try mx(gr), ont) == nil { return false }
        }
        return true
    }

    // ---------------- template instantiation ----------------

    private static func quantityOf(_ s: JSONValue, _ v: JSONValue) throws -> JSONValue? {
        if v.asString != nil || v.asArray != nil { return nil }
        guard v.asObject != nil else { throw IrError("slot value is not an object") }
        let kind = gv(s, "kind")
        if GV.has(v, "minor") && eqs(kind, "money") && same(gv(v, "ccy"), gv(s, "ccy")) {
            if let n = GV.safeInt(gv(v, "minor")), n >= 0 {
                return GV.obj([("u", GV.obj([("k", .string("money")), ("ccy", nv(gv(v, "ccy")))])), ("n", .int(n))])
            }
        }
        if GV.has(v, "n") && eqs(kind, "count") {
            if let n = GV.safeInt(gv(v, "n")), n >= 0 {
                return GV.obj([("u", GV.obj([("k", .string("count"))])), ("n", .int(n))])
            }
        }
        if GV.has(v, "ms") && eqs(kind, "duration") {
            if let n = GV.safeInt(gv(v, "ms")), n >= 0 {
                return GV.obj([("u", GV.obj([("k", .string("duration"))])), ("n", .int(n))])
            }
        }
        if GV.has(v, "epoch_ms") && eqs(kind, "instant") {
            if let n = GV.safeInt(gv(v, "epoch_ms")) {
                return GV.obj([("u", GV.obj([("k", .string("instant"))])), ("n", .int(n))])
            }
        }
        return nil
    }

    private static func sv(_ s: JSONValue?) -> JSONValue { return GV.obj([("k", .string("s")), ("s", nv(s))]) }

    /// Typed value(s) of a slot (an array of values), or a reason string when it is missing or invalid (the slot then becomes a Hole).
    /// JSON null for a slot kind that carries no typed value.
    public static func slotLits(_ o: JSONValue, _ s: JSONValue, _ vIn: JSONValue?) throws -> JSONValue {
        guard let v = nn(vIn) else { return .string("missing") }
        let kind = GV.jsStr(gv(s, "kind"))
        switch kind {
        case "money", "count", "duration", "instant":
            guard let q = try quantityOf(s, v) else { return .string("ill-typed") }
            var max: Double? = nil
            if let m = nn(gv(s, "max")) { max = IV.num(m) }
            if let limit = max {
                let qn: Double = kind == "instant" ? 0.0 : GV.toNum(gv(q, "n"))
                if qn > limit { return .string("above the template maximum") }
            }
            return .array([GV.obj([("k", .string("q")), ("q", q)])])
        case "id":
            let pre = try prefixOf(o, gv(s, "of"))
            if let str = v.asString, let p = pre, !p.isEmpty, IV.startsWith(str, p), str.utf16.count > p.utf16.count, idLike(str) {
                return .array([sv(v)])
            }
            return .string("ill-typed")
        case "id_list":
            let pre = try prefixOf(o, gv(s, "of"))
            guard let arr = v.asArray, !arr.isEmpty else { return .string("ill-typed") }
            var out: [JSONValue] = []
            for x in arr {
                let xs = try strOf(x)
                guard let p = pre, !p.isEmpty, IV.startsWith(xs, p), idLike(xs) else { return .string("ill-typed") }
                out.append(sv(x))
            }
            return .array(out)
        case "enum":
            if v.asString != nil && strIncludes(gv(s, "values"), v) { return .array([sv(v)]) }
            return .string("ill-typed")
        case "enum_list":
            guard let arr = v.asArray, !arr.isEmpty else { return .string("ill-typed") }
            var out: [JSONValue] = []
            for x in arr {
                if !strIncludes(gv(s, "values"), x) { return .string("ill-typed") }
                out.append(sv(x))
            }
            return .array(out)
        case "text_list":
            guard let arr = v.asArray, !arr.isEmpty else { return .string("ill-typed") }
            var out: [JSONValue] = []
            for x in arr {
                guard let xs = x.asString, !xs.isEmpty, noInvisible(xs) else { return .string("ill-typed") }
                out.append(sv(x))
            }
            return .array(out)
        default:
            return .null
        }
    }

    private static func isListSlot(_ t: JSONValue, _ name: String) throws -> Bool {
        guard let s = try findBy(gv(t, "slots"), "name", .string(name)) else { return false }
        guard let k = gv(s, "kind")?.asString else { return false }
        return IV.endsWith(k, "_list")
    }

    /// Template -> Goal (canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a hole
    /// is dropped (the most restrictive completion). `sources` may be nil.
    public static func instantiateTemplate(
        _ oIn: JSONValue, _ templateId: String, _ values: JSONValue?, _ principal: String, _ nl: String, _ sources: JSONValue?
    ) throws -> JSONValue {
        let o = try mx(oIn)
        guard let t = try findBy(gv(o, "templates"), "id", .string(templateId)) else { throw IrError("unknown template \(templateId)") }
        // a slot name -> its typed values (an array), or JSON null for a kind that carries none
        var bound: [JKey: JSONValue] = [:]
        var holes: [JSONValue] = []
        for so in try list(gv(t, "slots")) {
            let s = try mx(so)
            let name = GV.jsStr(gv(s, "name"))
            var v: JSONValue? = nil
            if let vals = values, vals.asObject != nil { v = nn(gv(vals, name)) }
            if v == nil { v = gv(s, "default") }
            let r = try slotLits(o, s, v)
            if let reason = r.asString {
                let ccyPart: String = GV.truthy(gv(s, "ccy")) ? " " + GV.jsStr(gv(s, "ccy")) : ""
                let label: String = name.replacingOccurrences(of: "_", with: " ")
                let kindText: String = GV.jsStr(gv(s, "kind"))
                var q: String = "What is the " + label
                q += " (" + kindText + ccyPart
                q += ")? (" + reason + ")"
                holes.append(GV.obj([
                    ("hid", .string(name)), ("q", .string(q)), ("domain", .array([])), ("affects", .array([])), ("global", .bool(false)),
                ]))
            } else {
                bound[JKey(name)] = r
            }
        }
        var verbOf: [JKey: JSONValue] = [:]
        for vo in try list(gv(o, "verbs")) {
            let v = try mx(vo)
            if let id = gv(vo, "id")?.asString { verbOf[JKey(id)] = v }
        }
        let inst = Inst(o, t, bound, verbOf)
        var dropped: [String] = []
        var grants: [JSONValue] = []
        let tbounds = try list(gv(t, "bounds"))
        var keepFlags: [Bool] = []
        for b in tbounds { keepFlags.append(inst.deps(refsBound(try mx(b)))) }
        for (i, bo) in tbounds.enumerated() {
            if keepFlags[i] { continue }
            let b = try mx(bo)
            for go in try list(gv(t, "grants")) {
                let gid = gv(go, "gid")
                var hit = eqs(gv(b, "over"), "all")
                if !hit { hit = strIncludes(.array(try list(gv(b, "over"))), gid) }
                if hit { dropped.append(GV.jsStr(gid)) }
            }
        }
        for go in try list(gv(t, "grants")) {
            let g = try mx(go)
            let gid = GV.jsStr(gv(g, "gid"))
            if try hasStr(dropped, gid) || !inst.deps(try refsGrant(g)) {
                dropped.append(gid)
            } else {
                let res = try inst.subRes(try mx(gv(g, "res")))
                let cond = try inst.subCond(try mx(gv(g, "cond")), try strOrNil(gv(g, "verb")))
                grants.append(GV.obj([("gid", nv(gv(g, "gid"))), ("verb", nv(gv(g, "verb"))), ("res", res), ("cond", cond)]))
            }
        }
        var prohibits: [JSONValue] = []
        for po in try list(gv(t, "prohibits")) {
            let p = try mx(po)
            let tg = try mx(gv(p, "target"))
            var verb: String? = nil
            if GV.kind(tg) == "verb" {
                verb = try strOrNil(gv(tg, "verb"))
            } else {
                for vo in try list(gv(o, "verbs")) {
                    if same(gv(vo, "effect"), gv(tg, "cls")) {
                        verb = try strOrNil(gv(vo, "id"))
                        break
                    }
                }
            }
            if inst.deps(try refsGrant(p)) {
                let res = try inst.subRes(try mx(gv(p, "res")))
                let cond = try inst.subCond(try mx(gv(p, "cond")), verb)
                prohibits.append(GV.obj([("pid", nv(gv(p, "pid"))), ("target", tg), ("res", res), ("cond", cond)]))
            } else {
                prohibits.append(GV.obj([
                    ("pid", nv(gv(p, "pid"))), ("target", tg),
                    ("res", GV.obj([("k", .string("any")), ("reason", .string("hole"))])), ("cond", GV.obj([("k", .string("true"))])),
                ]))
            }
        }
        var kept: [String] = []
        for g in grants { kept.append(GV.jsStr(gv(g, "gid"))) }
        var bounds: [JSONValue] = []
        for (i, bo) in tbounds.enumerated() {
            if !keepFlags[i] { continue }
            let b = try mx(bo)
            var gids: [JSONValue] = []
            if eqs(gv(b, "over"), "all") {
                for g in grants { gids.append(nv(gv(g, "gid"))) }
            } else {
                for x in try list(gv(b, "over")) { if hasStr(kept, GV.jsStr(x)) { gids.append(x) } }
            }
            if gids.isEmpty { continue }
            let capSlot = gv(b, "cap_slot")
            var capLit: JSONValue? = nil
            if GV.truthy(capSlot) { capLit = try inst.single(GV.jsStr(capSlot)) }
            var cap: JSONValue? = nil
            if let cl = capLit, GV.kind(cl) == "q" { cap = obj(gv(cl, "q")) } else { cap = obj(gv(b, "cap")) }
            var verb: String? = nil
            for g in grants {
                if same(gv(g, "gid"), gids[0]) {
                    verb = try strOrNil(gv(g, "verb"))
                    break
                }
            }
            guard let vb = verb else { throw IrError("bound without a surviving grant") }
            var value: JSONValue
            if eqs(gv(b, "agg"), "sum") {
                guard let param = gv(b, "param")?.asString else { throw IrError("parameter undefined is not declared by any verb") }
                let cu = try mx(gv(cap, "u"))
                let hint: String? = try (eqs(gv(cu, "k"), "money") ? strOrNil(gv(cu, "ccy")) : nil)
                value = GV.obj([("k", .string("param")), ("path", .string(param)), ("ty", try inst.tyOf(vb, param, hint))])
            } else {
                let cnt: JSONValue = GV.obj([("u", GV.obj([("k", JSONValue.string("count"))])), ("n", JSONValue.int(1))])
                let one: JSONValue = GV.obj([("k", JSONValue.string("q")), ("q", cnt)])
                value = GV.obj([("k", JSONValue.string("lit")), ("v", one)])
            }
            var bkv: [(String, JSONValue)] = []
            bkv.append(("bid", nv(gv(b, "bid"))))
            bkv.append(("sel", GV.obj([("k", JSONValue.string("gids")), ("gids", JSONValue.array(gids))])))
            bkv.append(("agg", nv(gv(b, "agg"))))
            bkv.append(("value", value))
            bkv.append(("key", JSONValue.string("")))
            bkv.append(("window", GV.obj([("k", JSONValue.string("lifetime"))])))
            bkv.append(("scope", GV.obj([("k", JSONValue.string("session"))])))
            bkv.append(("cap", nv(cap)))
            bkv.append(("onExceed", nv(gv(b, "onExceed"))))
            bounds.append(GV.obj(bkv))
        }
        var srcs: [JSONValue] = []
        if let sa = sources?.asArray { srcs = sa }
        let validity: JSONValue = GV.obj([("notBefore", JSONValue.int(0)), ("notAfter", JSONValue.int(FOREVER)), ("maxIdle", JSONValue.int(0))])
        let deleg: JSONValue = GV.obj([("maxDepth", JSONValue.int(0)), ("narrowOnly", JSONValue.bool(true)), ("mayTouch", JSONValue.array([]))])
        let ontD: String = try ontologyDigest(o)
        let nlD: String = try PCAGoalDigests.nlDigest(nl)
        var kv: [(String, JSONValue)] = []
        kv.append(("v", JSONValue.int(1)))
        kv.append(("principal", JSONValue.string(principal)))
        kv.append(("ontDigest", JSONValue.string(ontD)))
        kv.append(("nlDigest", JSONValue.string(nlD)))
        kv.append(("sources", JSONValue.array(srcs)))
        kv.append(("grants", JSONValue.array(grants)))
        kv.append(("prohibits", JSONValue.array(prohibits)))
        kv.append(("bounds", JSONValue.array(bounds)))
        kv.append(("validity", validity))
        kv.append(("deleg", deleg))
        kv.append(("escalateOn", JSONValue.array([])))
        kv.append(("wildcardAck", JSONValue.array([])))
        kv.append(("holes", JSONValue.array(holes)))
        let goal: JSONValue = GV.obj(kv)
        return try PCAGoalNormalize.canonicalizeGoal(goal)
    }

    /// The substitution state of one instantiation.
    private final class Inst {
        let o: JSONValue
        let t: JSONValue
        let bound: [JKey: JSONValue]
        let verbOf: [JKey: JSONValue]

        init(_ o: JSONValue, _ t: JSONValue, _ bound: [JKey: JSONValue], _ verbOf: [JKey: JSONValue]) {
            self.o = o
            self.t = t
            self.bound = bound
            self.verbOf = verbOf
        }

        func deps(_ refs: [String]) -> Bool {
            for r in refs { if bound[JKey(r)] == nil { return false } }
            return true
        }

        /// The values of a bound slot (a missing or value-less slot is a refusal).
        func values(_ name: String) throws -> [JSONValue] {
            guard let a = bound[JKey(name)]?.asArray, !a.isEmpty else { throw IrError("slot \(name) has no value") }
            return a
        }

        func single(_ name: String) throws -> JSONValue? {
            return PCAGoalOntology.obj(try values(name)[0])
        }

        func sub(_ id: String) throws -> String {
            if IV.startsWith(id, "$") {
                guard let s = PCAGoalOntology.gv(try single(IV.dropPrefix(id, 1)), "s")?.asString else { throw IrError("string expected") }
                return s
            }
            return id
        }

        func subPart(_ r: JSONValue) throws -> JSONValue {
            let k = GV.kind(r)
            if k == "exact" { return GV.obj([("k", .string("exact")), ("id", .string(try sub(try PCAGoalOntology.strOf(PCAGoalOntology.gv(r, "id")))))]) }
            if k == "oneof" {
                var ids: [JSONValue] = []
                for i in try PCAGoalOntology.list(PCAGoalOntology.gv(r, "ids")) { ids.append(.string(try sub(try PCAGoalOntology.strOf(i)))) }
                return GV.obj([("k", .string("oneof")), ("ids", .array(ids))])
            }
            guard var c = r.asObject else { throw IrError("object expected") }
            c[JKey("anchor")] = .string(try sub(try PCAGoalOntology.strOf(PCAGoalOntology.gv(r, "anchor"))))
            return .object(c)
        }

        func subRes(_ r: JSONValue) throws -> JSONValue {
            let k = GV.kind(r)
            if k == "any" { return r }
            if k == "all_of" {
                var ps: [JSONValue] = []
                for p in try PCAGoalOntology.list(PCAGoalOntology.gv(r, "parts")) { ps.append(try subPart(try PCAGoalOntology.mx(p))) }
                return GV.obj([("k", .string("all_of")), ("parts", .array(ps))])
            }
            return try subPart(r)
        }

        func tyOf(_ verb: String?, _ path: String, _ ccy: String?) throws -> JSONValue {
            var p: JSONValue? = nil
            if let vb = verb, let v = verbOf[JKey(vb)] {
                p = PCAGoalOntology.obj(PCAGoalOntology.gv(try PCAGoalOntology.mx(PCAGoalOntology.gv(v, "params")), path))
            }
            if p == nil {
                for vo in try PCAGoalOntology.list(PCAGoalOntology.gv(o, "verbs")) {
                    let x = PCAGoalOntology.obj(PCAGoalOntology.gv(try PCAGoalOntology.mx(PCAGoalOntology.gv(vo, "params")), path))
                    if x != nil {
                        p = x
                        break
                    }
                }
            }
            guard let pp = p else { throw IrError("parameter \(path) is not declared by any verb") }
            return try PCAGoalOntology.paramTy(pp, ccy)
        }

        func lit(_ x: JSONValue?) throws -> JSONValue? {
            let k = GV.kind(x)
            if k == "slot" {
                let slot = try PCAGoalOntology.strOf(PCAGoalOntology.gv(x, "slot"))
                let l = try values(slot)
                let isList = try PCAGoalOntology.isListSlot(t, slot)
                return GV.obj([("k", .string("lit")), ("v", isList ? GV.obj([("k", .string("set")), ("items", .array(l))]) : l[0])])
            }
            if k == "lit" { return GV.obj([("k", .string("lit")), ("v", PCAGoalOntology.nv(PCAGoalOntology.gv(x, "v")))]) }
            return nil
        }

        func ccyOf(_ x: JSONValue?) throws -> String? {
            if let x = x, PCAGoalOntology.eqs(PCAGoalOntology.gv(x, "k"), "lit") {
                let v = PCAGoalOntology.obj(PCAGoalOntology.gv(x, "v"))
                if GV.kind(v) == "q" {
                    if let u = PCAGoalOntology.obj(PCAGoalOntology.gv(PCAGoalOntology.gv(v, "q"), "u")), PCAGoalOntology.eqs(PCAGoalOntology.gv(u, "k"), "money") {
                        return try PCAGoalOntology.strOrNil(PCAGoalOntology.gv(u, "ccy"))
                    }
                }
            }
            return nil
        }

        func term(_ x: JSONValue?, _ v: JSONValue?, _ verb: String?, _ hint: String?) throws -> JSONValue {
            if let v = v { return v }
            let path = try PCAGoalOntology.strOf(PCAGoalOntology.gv(x, "path"))
            return GV.obj([("k", .string("param")), ("path", .string(path)), ("ty", try tyOf(verb, path, hint))])
        }

        func subCond(_ c: JSONValue, _ verb: String?) throws -> JSONValue {
            let k = GV.kind(c)
            if k == "true" { return c }
            if k == "and" || k == "or" {
                let a = try subCond(try PCAGoalOntology.mx(PCAGoalOntology.gv(c, "a")), verb)
                let b = try subCond(try PCAGoalOntology.mx(PCAGoalOntology.gv(c, "b")), verb)
                return GV.obj([("k", .string(k)), ("a", a), ("b", b)])
            }
            if k == "not" { return GV.obj([("k", .string("not")), ("c", try subCond(try PCAGoalOntology.mx(PCAGoalOntology.gv(c, "c")), verb))]) }
            let l = PCAGoalOntology.obj(PCAGoalOntology.gv(c, "l"))
            let r = PCAGoalOntology.obj(PCAGoalOntology.gv(c, "r"))
            let lv = try lit(l)
            let rv = try lit(r)
            var hint = try ccyOf(lv)
            if hint == nil { hint = try ccyOf(rv) }
            let tl = try term(l, lv, verb, hint)
            let tr = try term(r, rv, verb, hint)
            return GV.obj([("k", .string("cmp")), ("op", PCAGoalOntology.nv(PCAGoalOntology.gv(c, "op"))), ("l", tl), ("r", tr)])
        }
    }

    // ---------------- locale-aware human number parsing ----------------

    private static func amountFail(_ reason: String) -> JSONValue {
        return GV.obj([("ok", .bool(false)), ("reason", .string(reason))])
    }

    private static let DOT: UInt8 = 0x2E
    private static let COMMA: UInt8 = 0x2C

    /// A non-empty ASCII text made of digits, '.' and ',' that starts with a digit.
    private static func isAmount(_ t: [UInt8]) -> Bool {
        guard let f = t.first, f >= 0x30, f <= 0x39 else { return false }
        for c in t { if !((c >= 0x30 && c <= 0x39) || c == DOT || c == COMMA) { return false } }
        return true
    }

    private static func lastIndex(_ t: [UInt8], _ c: UInt8) -> Int {
        var i = t.count - 1
        while i >= 0 {
            if t[i] == c { return i }
            i -= 1
        }
        return -1
    }

    private static func countOf(_ t: [UInt8], _ c: UInt8) -> Int {
        var n = 0
        for x in t { if x == c { n += 1 } }
        return n
    }

    /// Split on a single separator byte, keeping empty parts (Java split with limit -1).
    private static func splitAll(_ t: [UInt8], _ sep: UInt8) -> [[UInt8]] {
        var out: [[UInt8]] = []
        var cur: [UInt8] = []
        for c in t {
            if c == sep {
                out.append(cur)
                cur = []
            } else {
                cur.append(c)
            }
        }
        out.append(cur)
        return out
    }

    /// "1,000.50", "1.000,50", "$20", "20 dollars": {ok: true, minor} or {ok: false, reason}. Ambiguous literals ("1,000" with no locale
    /// hint, "1.000") are NOT guessed. `locale` is "en" (',' is thousands), "de" ('.' is thousands) or nil.
    public static func parseHumanAmount(_ text: String, _ exponent: Int, _ locale: String?) throws -> JSONValue {
        var kept: [UInt8] = []
        for u in Attest.jsTrim(nfkc(text)).unicodeScalars {
            let c = u.value
            if (c >= 0x30 && c <= 0x39) || c == 0x2E || c == 0x2C { kept.append(UInt8(c)) }
        }
        let t = kept
        if !isAmount(t) { return amountFail("not a number") }
        if t.count >= 2 {
            for i in 1..<t.count {
                if (t[i] == DOT || t[i] == COMMA) && (t[i - 1] == DOT || t[i - 1] == COMMA) { return amountFail("not a number") }
            }
        }
        let lastDot = lastIndex(t, DOT)
        let lastComma = lastIndex(t, COMMA)
        var dec: UInt8? = nil
        var thou: UInt8? = nil
        if lastDot >= 0 && lastComma >= 0 {
            dec = lastDot > lastComma ? DOT : COMMA
            thou = dec == DOT ? COMMA : DOT
        } else if lastDot >= 0 || lastComma >= 0 {
            let sep: UInt8 = lastDot >= 0 ? DOT : COMMA
            let parts = splitAll(t, sep)
            let groupLike = parts.count > 2 || parts[parts.count - 1].count == 3
            if !groupLike {
                dec = sep
            } else if parts.count > 2 {
                thou = sep
            } else if let loc = locale, !loc.isEmpty {
                if IV.same(loc, "en") == (sep == COMMA) { thou = sep } else { dec = sep }
            } else {
                return amountFail("ambiguous separator")
            }
        }
        var intPart: [UInt8] = t
        var frac: [UInt8] = []
        if let dc = dec {
            let i = lastIndex(t, dc)
            intPart = Array(t[0..<i])
            frac = Array(t[(i + 1)...])
        }
        if let th = thou {
            let groups = splitAll(intPart, th)
            var badGroup = false
            if groups.count > 1 {
                for i in 1..<groups.count { if groups[i].count != 3 { badGroup = true } }
            }
            if badGroup || groups[0].isEmpty || groups[0].count > 3 { return amountFail("malformed grouping") }
            var joined: [UInt8] = []
            for gp in groups { joined.append(contentsOf: gp) }
            intPart = joined
        }
        if frac.count > exponent { return amountFail("more decimals than the currency allows") }
        var digits: [UInt8] = intPart + frac
        var pad = frac.count
        while pad < exponent {
            digits.append(0x30)
            pad += 1
        }
        if digits.isEmpty { return amountFail("out of range") }
        var start = 0
        while start < digits.count - 1 && digits[start] == 0x30 { start += 1 }
        let sig = Array(digits[start...])
        if sig.count > 16 { return amountFail("out of range") }
        guard let v = Int64(String(decoding: sig, as: UTF8.self)), v <= GV.MAX_SAFE else { return amountFail("out of range") }
        return GV.obj([("ok", .bool(true)), ("minor", .int(v))])
    }

    private static func isJsWhitespace(_ u: Unicode.Scalar) -> Bool {
        let c = u.value
        switch c {
        case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF: return true
        default: return c >= 0x2000 && c <= 0x200A
        }
    }

    /// The strict front-end contract over `parseHumanAmount`: {minor} | {hole: "AMBIGUOUS_NUMBER"} | {error: "BAD_NUMBER"}.
    /// Only digits, '.' and ',' after one optional leading currency symbol; a decimal separator that contradicts the locale is refused.
    public static func parseMoney(_ text: String, _ exponent: Int, _ locale: String?) throws -> JSONValue {
        var sc = Array(Attest.jsTrim(text).unicodeScalars)
        if let f = sc.first, f.value == 0x24 || f.value == 0x20AC || f.value == 0xA3 {
            sc.removeFirst()
            while let w = sc.first, isJsWhitespace(w) { sc.removeFirst() }
        }
        let tstr = IV.text(sc)
        let t = Array(tstr.utf8)
        let badNumber: JSONValue = GV.obj([("error", .string("BAD_NUMBER"))])
        if !isAmount(t) { return badNumber }
        let both = t.contains(DOT) && t.contains(COMMA)
        if let loc = locale, both {
            let last = max(lastIndex(t, DOT), lastIndex(t, COMMA))
            let want: UInt8 = IV.same(loc, "en") ? DOT : COMMA
            if t[last] != want { return badNumber }
        }
        if locale == nil && !both && countOf(t, DOT) + countOf(t, COMMA) > 1 { return GV.obj([("hole", .string("AMBIGUOUS_NUMBER"))]) }
        let r = try parseHumanAmount(tstr, exponent, locale)
        if gv(r, "ok") == JSONValue.bool(true) { return GV.obj([("minor", nv(gv(r, "minor")))]) }
        if eqs(gv(r, "reason"), "ambiguous separator") { return GV.obj([("hole", .string("AMBIGUOUS_NUMBER"))]) }
        return badNumber
    }
}
