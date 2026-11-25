import Foundation

/// The semantic diff of two versions of one action def: is the NEW definition no more permissive than the OLD one? Classes: equal (only
/// text differs), narrow (every call the new def accepts is accepted by the old one and every old restriction still holds), widen, and
/// incomparable (one dimension widens while another narrows, or the change has no order). Conservative: a def that cannot be ordered
/// is incomparable, never narrow. Only equal and narrow let a pin follow the change without the principal.
public enum ActionDiff {
    private static let DEFAULT_MAX_LEN = 1024.0
    private static let DEFAULT_MAX_ITEMS = 64.0
    private static let INF = Double.infinity
    private static let PROVENANCE = ["first_party", "tool", "agent"]
    private static let SENSITIVITY = ["free", "material", "critical"]
    private static let SCOPE_RANK = ["one": 0, "set": 1, "tenant": 2, "global": 3]
    private static let IDEM_RANK = ["none": 0, "natural": 1, "key_param": 2]

    enum Rel { case eq, narrow, widen, inc }

    static func setRel(_ o: [JSONValue], _ n: [JSONValue]) -> Rel {
        let added = n.contains { x in !o.contains(x) }
        let removed = o.contains { x in !n.contains(x) }
        return added && removed ? .inc : added ? .narrow : removed ? .widen : .eq
    }
    static func rankRel(_ o: Double, _ n: Double) -> Rel { n == o ? .eq : n > o ? .narrow : .widen }
    private static func nz(_ v: JSONValue?, _ d: Double) -> Double { IV.num(JS.present(v)) ?? d }

    private static func domainContains(_ outer: JObject, _ inner: JObject) throws -> Bool {
        guard let ot = outer["type"], let ots = ot.asString else { throw AK.fail("bad_def", "param type") }
        if ot != inner["type"] { return false }
        switch ots {
        case "string", "object_ref":
            if nz(inner["max_len"], DEFAULT_MAX_LEN) > nz(outer["max_len"], DEFAULT_MAX_LEN) { return false }
            if let ov = AK.pres(outer, "values") {
                guard let iv = AK.pres(inner, "values") else { return false }
                let oa = AK.arr(ov)
                if !AK.arr(iv).allSatisfy({ oa.contains($0) }) { return false }
            }
            return AK.pres(outer, "format") == nil || AK.pres(inner, "format") == AK.pres(outer, "format")
        case "integer":
            return nz(inner["min"], -INF) >= nz(outer["min"], -INF) && nz(inner["max"], INF) <= nz(outer["max"], INF)
        case "duration":
            return max(nz(inner["min"], 0), 0) >= max(nz(outer["min"], 0), 0) && nz(inner["max"], INF) <= nz(outer["max"], INF)
        case "set":
            let ov = AK.arr(AK.pres(outer, "values")), iv = AK.arr(AK.pres(inner, "values"))
            if !iv.allSatisfy({ ov.contains($0) }) { return false }
            let oMax = min(nz(outer["max_items"], Double(ov.count)), Double(ov.count))
            let iMax = min(nz(inner["max_items"], Double(iv.count)), Double(iv.count))
            return nz(inner["min_items"], 0) >= nz(outer["min_items"], 0) && iMax <= oMax
        case "array":
            let oi = AK.pres(outer, "items") ?? .string("string"), ii = AK.pres(inner, "items") ?? .string("string")
            if oi != ii { return false }
            if nz(inner["min_items"], 0) < nz(outer["min_items"], 0) || nz(inner["max_items"], DEFAULT_MAX_ITEMS) > nz(outer["max_items"], DEFAULT_MAX_ITEMS) { return false }
            if AK.pres(outer, "items") == .string("integer") { return nz(inner["min"], -INF) >= nz(outer["min"], -INF) && nz(inner["max"], INF) <= nz(outer["max"], INF) }
            return nz(inner["max_len"], DEFAULT_MAX_LEN) <= nz(outer["max_len"], DEFAULT_MAX_LEN)
        default:
            return true
        }
    }

    private static func callsContained(_ outer: JObject, _ inner: JObject) throws -> Bool {
        for (k, v) in inner {
            guard let op = JS.present(outer[k]), case let .object(oo) = op, case let .object(io) = v else { return false }
            if !(try domainContains(oo, io)) { return false }
        }
        for (k, v) in outer {
            if v.get("required") != .bool(true) { continue }
            guard let ip = JS.present(inner[k]), ip.get("required") == .bool(true) else { return false }
        }
        return true
    }

    private static func callSetRel(_ oldP: JObject, _ newP: JObject) throws -> Rel {
        let sub = try callsContained(oldP, newP), sup = try callsContained(newP, oldP)
        return sub && sup ? .eq : sub ? .narrow : sup ? .widen : .inc
    }

    private static func provRank(_ p: JSONValue?) -> Int {
        guard let s = p?.asString, let i = PROVENANCE.firstIndex(of: s) else { return p == nil ? PROVENANCE.count - 1 : -1 }
        return i
    }

    private static func sens(_ p: JObject) -> String { p["sensitivity"]?.asString ?? Actions.effectiveParamSensitivity(p) }

    private static func paramAttrRels(_ o: JObject, _ n: JObject) -> [(String, Rel)] {
        var out: [(String, Rel)] = []
        if AK.pres(o, "role") != AK.pres(n, "role") { out.append(("role", .inc)) }
        out.append(("sensitivity", rankRel(Double(SENSITIVITY.firstIndex(of: sens(o)) ?? -1), Double(SENSITIVITY.firstIndex(of: sens(n)) ?? -1))))
        out.append(("tags", setRel(AK.arr(o["tags"]), AK.arr(n["tags"]))))
        out.append(("provenance_min", rankRel(Double(-provRank(AK.pres(o, "provenance_min"))), Double(-provRank(AK.pres(n, "provenance_min"))))))
        if !AK.sameJsonSorted(o["unit"], n["unit"]) { out.append(("unit", .inc)) }
        out.append(("accumulates", setRel(AK.arr(o["accumulates"]), AK.arr(n["accumulates"]))))
        if !AK.sameJsonSorted(o["default"], n["default"]) || AK.pres(o, "principal_neutral_default") != AK.pres(n, "principal_neutral_default") { out.append(("default", .inc)) }
        return out
    }

    private static func profRel(_ a: JSONValue, _ b: JSONValue) throws -> Rel {
        try ActionEffective.leq(a, b) ? (try ActionEffective.leq(b, a) ? .eq : .narrow) : (try ActionEffective.leq(b, a) ? .widen : .inc)
    }

    private static func sideEffects(_ d: JObject) -> [JSONValue] {
        AK.arr(d["side_effects"]).map { s in .string("\(JS.toString(s.get("target")))|\(JS.toString(s.get("kind")))") }
    }

    private static func utf16Less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    /// The semantic diff of `next` against `prev` (versions of the same verb): `{class, reasons}`. Throws `diff_verb` for two different verbs.
    public static func diffDefs(_ prev: JObject, _ next: JObject, _ reg: TraitRegistry = Actions.coreRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JSONValue {
        if prev["verb"] != next["verb"] {
            throw AK.fail("diff_verb", "diff compares two versions of one verb, not '\(JS.toString(prev["verb"]))' and '\(JS.toString(next["verb"]))'")
        }
        guard Actions.normalizable(prev), Actions.normalizable(next) else { throw JSError("diff: a def is not a well-formed action definition") }
        let o = try Actions.normalize(prev), n = try Actions.normalize(next)
        var rels: [(String, Rel)] = []
        let text = o["title"] != n["title"] || o["description"] != n["description"] || o["compensates"] != n["compensates"]
        rels.append(("effects", setRel(AK.arr(o["effects"]), AK.arr(n["effects"]))))
        let op = AK.o(o["params"]), np = AK.o(n["params"])
        rels.append(("params.accepted_calls", try callSetRel(op, np)))
        for name in AK.sortedKeys(op) where np[JKey(name)] != nil {
            for r in paramAttrRels(AK.o(op[JKey(name)]), AK.o(np[JKey(name)])) { rels.append(("params.\(name).\(r.0)", r.1)) }
        }
        let eo = try ActionEffective.effective(prev, reg, attestationVerified), en = try ActionEffective.effective(next, reg, attestationVerified)
        let ho = AK.o(eo["hint"]), hn = AK.o(en["hint"])
        func cl(_ v: JSONValue?) throws -> [JSONValue] { AK.strs(try Actions.closure(reg, AK.arr(v).compactMap { $0.asString })).asArray ?? [] }
        rels.append(("traits", setRel(try cl(ho["traits"]), try cl(hn["traits"]))))
        rels.append(("profile", try profRel(ho["eff"] ?? .null, hn["eff"] ?? .null)))
        rels.append(("confirmation", rankRel(eo["confirmed"] == .bool(true) ? 0 : 1, en["confirmed"] == .bool(true) ? 0 : 1)))
        rels.append(("effective.traits", setRel(try cl(eo["traits"]), try cl(en["traits"]))))
        rels.append(("effective.profile", try profRel(eo["eff"] ?? .null, en["eff"] ?? .null)))
        let rr = Actions.REV_RANK
        rels.append(("reversibility", rankRel(Double(rr[Actions.worstReversibility(o["reversibility"] ?? .null, op)] ?? 2), Double(rr[Actions.worstReversibility(n["reversibility"] ?? .null, np)] ?? 2))))
        rels.append(("blast", rankRel(IV.num(AK.o(o["blast"])["ppm"]) ?? 0, IV.num(AK.o(n["blast"])["ppm"]) ?? 0)))
        let oi = AK.o(o["idempotency"]), ni = AK.o(n["idempotency"])
        var idem: Rel
        if oi["mode"]?.asString == "key_param" && ni["mode"]?.asString == "key_param" && oi["param"] != ni["param"] { idem = .inc }
        else { idem = rankRel(Double(IDEM_RANK[oi["mode"]?.asString ?? ""] ?? 0), Double(IDEM_RANK[ni["mode"]?.asString ?? ""] ?? 0)) }
        rels.append(("idempotency", idem))
        rels.append(("context", setRel(AK.arr(o["context"]), AK.arr(n["context"]))))
        rels.append(("side_effects", setRel(sideEffects(o), sideEffects(n))))
        let ores = AK.o(o["resource"]), nres = AK.o(n["resource"])
        let resId: Rel
        if AK.sameJsonSorted(ores["id"], nres["id"]) { resId = .eq }
        else if try ActionIdPattern.idPatternContains(ores["id"], nres["id"]) { resId = .narrow }
        else if try ActionIdPattern.idPatternContains(nres["id"], ores["id"]) { resId = .widen }
        else { resId = .inc }
        rels.append(("resource.id", ores["type"] != nres["type"] ? .inc : resId))
        rels.append(("resource.scope", rankRel(-Double(SCOPE_RANK[ores["scope"]?.asString ?? ""] ?? 0), -Double(SCOPE_RANK[nres["scope"]?.asString ?? ""] ?? 0))))
        let ar = setRel(AK.arr(o["aliases"]), AK.arr(n["aliases"]))
        rels.append(("aliases", ar == .narrow ? .widen : ar == .widen ? .narrow : ar))
        rels.append(("bindings", AK.sameJsonSorted(o["bindings"], n["bindings"]) ? .eq : .inc))

        let diffs = rels.filter { $0.1 != .eq }
        var reasons = diffs.map { "\($0.0): " + ($0.1 == .inc ? "incomparable" : $0.1 == .narrow ? "narrow" : "widen") }
        if text { reasons.append("text: title, description or compensates changed") }
        reasons.sort(by: utf16Less)
        let inc = diffs.contains { $0.1 == .inc }, nar = diffs.contains { $0.1 == .narrow }, wid = diffs.contains { $0.1 == .widen }
        var cls = "equal"
        if inc || (nar && wid) { cls = "incomparable" } else if wid { cls = "widen" } else if nar { cls = "narrow" }
        return AK.obj(["class": .string(cls), "reasons": AK.strs(reasons)])
    }

    /// Does a pin follow this change on its own (no principal)?
    public static func diffIsFree(_ cls: String) -> Bool { cls == "equal" || cls == "narrow" }
}

/// The author-facing semantic diff of two versions of one def (equal | narrow | widen | incomparable, with the reasons) and the per-verb
/// diff of two packs. Conservative: anything it cannot show to be no wider is widening.
public enum ActionDefDiff {
    private static let SENSITIVITY = ["free", "material", "critical"]
    private static let PROVENANCE = ["first_party", "tool", "agent"]
    private static let SCOPE_RANK = ["one": 0, "set": 1, "tenant": 2, "global": 3]

    private static func jsNumText(_ v: JSONValue?) -> String { v == nil ? "undefined" : JS.toString(v) }

    private static func num(_ k: String, _ f: String, _ lowerIsWider: Bool, _ x: JObject, _ y: JObject, _ wide: inout [String], _ narrow: inout [String]) throws {
        let o = AK.pres(x, f), n = AK.pres(y, f)
        if o == nil && n == nil { return }
        let od = IV.num(o), nd = IV.num(n)
        if let a = od, let b = nd, a == b { return }
        func rank(_ v: JSONValue?, _ d: Double?) throws -> Double {
            if v == nil { return lowerIsWider ? -Double.infinity : Double.infinity }
            guard let d = d else { throw AK.fail("bad_def", "param \(k): \(f) is not a number") }
            return d
        }
        let ro = try rank(o, od), rn = try rank(n, nd)
        let widerNew = lowerIsWider ? rn < ro : rn > ro
        let line = "param \(k): \(f) \(jsNumText(o)) to \(jsNumText(n))"
        if widerNew { wide.append(line) } else { narrow.append(line) }
    }

    private static func pl(_ v: JSONValue?) -> Int {
        guard let v = v else { return PROVENANCE.count }
        guard let s = v.asString, let i = PROVENANCE.firstIndex(of: s) else { return -1 }
        return i
    }
    private static func sens(_ p: JObject) -> String { p["sensitivity"]?.asString ?? Actions.effectiveParamSensitivity(p) }
    private static func floorRank(_ r: JSONValue?) -> Int {
        guard let s = r?.asString, let f = Actions.ROLE_SENSITIVITY_FLOOR[s] else { return 0 }
        return SENSITIVITY.firstIndex(of: f) ?? 0
    }

    private static func paramDiff(_ k: String, _ x: JObject, _ y: JObject, _ wide: inout [String], _ narrow: inout [String], _ incomp: inout [String]) throws {
        if x["type"] != y["type"] { incomp.append("param \(k): type changed") }
        try num(k, "min", true, x, y, &wide, &narrow); try num(k, "max", false, x, y, &wide, &narrow); try num(k, "max_len", false, x, y, &wide, &narrow)
        try num(k, "max_items", false, x, y, &wide, &narrow); try num(k, "min_items", true, x, y, &wide, &narrow)
        if JS.stringify(AK.pres(x, "unit") ?? .null) != JS.stringify(AK.pres(y, "unit") ?? .null) { incomp.append("param \(k): unit changed") }
        let vo = AK.pres(x, "values"), vn = AK.pres(y, "values")
        if vo != nil || vn != nil {
            if let vo = vo, let vn = vn {
                let oa = AK.arr(vo), na = AK.arr(vn)
                let added = na.filter { !oa.contains($0) }.map { JS.toString($0) }
                let removed = oa.filter { !na.contains($0) }.map { JS.toString($0) }
                if !added.isEmpty { wide.append("param \(k): values added (\(added.joined(separator: ", ")))") }
                if !removed.isEmpty { narrow.append("param \(k): values removed (\(removed.joined(separator: ", ")))") }
            } else if vo == nil { narrow.append("param \(k): values restricted") }
            else { wide.append("param \(k): values unrestricted") }
        }
        if x["required"] == .bool(true) && y["required"] == .bool(false) { wide.append("param \(k): required to optional") }
        if x["required"] == .bool(false) && y["required"] == .bool(true) { narrow.append("param \(k): optional to required") }
        let px = pl(AK.pres(x, "provenance_min")), py = pl(AK.pres(y, "provenance_min"))
        if py > px { wide.append("param \(k): provenance_min loosened") } else if py < px { narrow.append("param \(k): provenance_min tightened") }
        let sx = SENSITIVITY.firstIndex(of: sens(x)) ?? -1, sy = SENSITIVITY.firstIndex(of: sens(y)) ?? -1
        if sy < sx { wide.append("param \(k): sensitivity lowered") } else if sy > sx { narrow.append("param \(k): sensitivity raised") }
        if AK.pres(x, "role") != AK.pres(y, "role") {
            let fx = floorRank(AK.pres(x, "role")), fy = floorRank(AK.pres(y, "role"))
            if fy < fx { wide.append("param \(k): role changed to a lower-floor role") }
            else if fy > fx { narrow.append("param \(k): role changed to a higher-floor role") }
            else { incomp.append("param \(k): role changed") }
        }
    }

    /// The diff of `b` against `a`: `{class, breaking, reasons}`.
    public static func diffDefs(_ a: JObject, _ b: JObject, _ reg: TraitRegistry = Actions.coreRegistry) throws -> JSONValue {
        if a["verb"] != b["verb"] {
            return AK.obj(["class": .string("widen"), "breaking": .bool(true), "reasons": AK.strs(["verb renamed: removed + added (grants on the old verb do not follow)"])])
        }
        var wide: [String] = [], narrow: [String] = [], incomp: [String] = []
        var breaking = false
        guard Actions.normalizable(a), Actions.normalizable(b) else { throw JSError("diff: a def is not a well-formed action definition") }
        let na = try Actions.normalize(a), nb = try Actions.normalize(b)
        let ea = AK.o(try ActionEffective.effective(a, reg)["hint"]), eb = AK.o(try ActionEffective.effective(b, reg)["hint"])
        let pa = ea["eff"] ?? .null, pb = eb["eff"] ?? .null
        if !(try ActionEffective.leq(pa, pb)) { wide.append("the effective profile is not at least the old one") }
        else if !(try ActionEffective.profileEq(pa, pb)) { narrow.append("the effective profile rose") }

        let fa = AK.arr(na["effects"]), fb = AK.arr(nb["effects"])
        for e in fa where !fb.contains(e) { wide.append("effect \(JS.toString(e)) removed") }
        for e in fb where !fa.contains(e) { narrow.append("effect \(JS.toString(e)) added") }
        let ta = AK.arr(na["traits"]), tb = AK.arr(nb["traits"])
        for t in ta where !tb.contains(t) { wide.append("declared trait \(JS.toString(t)) removed") }
        for t in tb where !ta.contains(t) { narrow.append("declared trait \(JS.toString(t)) added") }
        let pma = AK.o(na["params"]), pmb = AK.o(nb["params"])
        let ra = Actions.worstReversibility(na["reversibility"] ?? .null, pma), rb = Actions.worstReversibility(nb["reversibility"] ?? .null, pmb)
        let rr = Actions.REV_RANK
        if (rr[rb] ?? 2) < (rr[ra] ?? 2) { wide.append("reversibility lowered (\(ra) to \(rb))") }
        else if (rr[rb] ?? 2) > (rr[ra] ?? 2) { narrow.append("reversibility raised (\(ra) to \(rb))") }
        let ba = Int64(IV.num(AK.o(na["blast"])["ppm"]) ?? 0), bb = Int64(IV.num(AK.o(nb["blast"])["ppm"]) ?? 0)
        if bb < ba { wide.append("blast lowered") } else if bb > ba { narrow.append("blast raised") }
        let ia = AK.o(na["idempotency"])["mode"]?.asString == "none" ? 0 : 1, ib = AK.o(nb["idempotency"])["mode"]?.asString == "none" ? 0 : 1
        if ib < ia { wide.append("idempotency loosened") } else if ib > ia { narrow.append("idempotency added") }

        let resa = AK.o(na["resource"]), resb = AK.o(nb["resource"])
        if resa["type"] != resb["type"] { incomp.append("resource type changed") }
        let sa = SCOPE_RANK[resa["scope"]?.asString ?? ""] ?? 0, sb = SCOPE_RANK[resb["scope"]?.asString ?? ""] ?? 0
        if sb > sa { wide.append("resource scope widened") } else if sb < sa { narrow.append("resource scope narrowed") }
        let inOld = try ActionIdPattern.idPatternContains(resa["id"], resb["id"]), inNew = try ActionIdPattern.idPatternContains(resb["id"], resa["id"])
        if !inOld { wide.append("the resource id pattern is not contained in the old one") }
        else if !inNew { narrow.append("the resource id pattern is narrower") }

        for k in JS.keyOrder(pma) {
            let x = AK.o(pma[k])
            guard let y = JS.present(pmb[k]) else { narrow.append("param \(k.s) removed"); breaking = true; continue }
            try paramDiff(k.s, x, AK.o(y), &wide, &narrow, &incomp)
            if x["required"] == .bool(false) && y.get("required") == .bool(true) { breaking = true }
        }
        for k in JS.keyOrder(pmb) where pma[k] == nil {
            let req = AK.o(pmb[k])["required"]
            if req == .bool(true) || (req != nil && req != .bool(false) && req != .null) { narrow.append("required param \(k.s) added"); breaking = true }
            else { wide.append("optional param \(k.s) added") }
        }
        if AK.o(a["review"])["state"]?.asString == "confirmed" && AK.o(b["review"])["state"]?.asString != "confirmed" { narrow.append("review state left confirmed") }

        var cls = "equal"
        if !incomp.isEmpty || (!wide.isEmpty && !narrow.isEmpty) { cls = "incomparable" } else if !wide.isEmpty { cls = "widen" } else if !narrow.isEmpty { cls = "narrow" }
        let cmpEq = try cls == "equal" && Actions.defDigest(a) != Actions.defDigest(b)
        var reasons: [String] = []
        for r in wide { reasons.append("widen: " + r) }
        for r in narrow { reasons.append("narrow: " + r) }
        for r in incomp { reasons.append("incomparable: " + r) }
        if cmpEq { reasons.append("equal: only title or description changed") }
        return AK.obj(["class": .string(cls), "breaking": .bool(breaking), "reasons": AK.strs(reasons)])
    }

    /// Per-verb diff of two sets of defs: `{verb, class, breaking, reasons}` (a removed verb is `removed`, a new one `added`).
    public static func diffPacks(_ olds: [JSONValue], _ news: [JSONValue], _ reg: TraitRegistry = Actions.coreRegistry) throws -> [JSONValue] {
        var o: [String: JSONValue] = [:], n: [String: JSONValue] = [:]
        for d in olds { guard let v = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }; o[v] = d }
        for d in news { guard let v = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }; n[v] = d }
        var out: [JSONValue] = []
        for v in Set(o.keys).union(n.keys).sorted(by: { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }) {
            switch (o[v], n[v]) {
            case (nil, _): out.append(AK.obj(["verb": .string(v), "class": .string("added"), "breaking": .bool(false), "reasons": .array([])]))
            case (_?, nil): out.append(AK.obj(["verb": .string(v), "class": .string("removed"), "breaking": .bool(true), "reasons": AK.strs(["verb removed"])]))
            case let (x?, y?):
                let d = try diffDefs(AK.o(x), AK.o(y), reg)
                out.append(AK.obj(["verb": .string(v), "class": d.get("class") ?? .null, "breaking": d.get("breaking") ?? .null, "reasons": d.get("reasons") ?? .null]))
            }
        }
        return out
    }
}
