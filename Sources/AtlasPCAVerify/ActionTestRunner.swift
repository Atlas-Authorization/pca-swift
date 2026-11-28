import Foundation

/// Executable examples and generic property checks of an action pack: every def's examples run through the real pipeline in process (derive the schema,
/// conform the params, expand the floors, decide), plus T2 monotonicity over trait additions and subsets, digest stability across the JSON and YAML forms,
/// and the schema round trip (the example conforms; every mutation of it is refused). The example policy (`under`) is a small allow selector evaluated
/// here; it can only pre-authorize. Examples and property checks describe the action AS REVIEWED (its hint view): they are authoring tests, not enforcement.
public enum ActionTestRunner {
    private static let SEL_KEYS = ["trait", "verb", "where", "caveats", "context"]
    public static let CAVEAT_KINDS = ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"]

    private static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    private static func hintOf(_ d: JObject, _ reg: TraitRegistry) throws -> JObject {
        let e = try ActionEffective.effective(d, reg, nil)
        var out = e
        for (k, v) in AK.o(e["hint"]) { out[k] = v }
        out["confirmed"] = .bool(true)
        return out
    }

    /// The example policy as a list of selectors, or the reason it is malformed.
    private static func parseUnder(_ under: JSONValue?, _ present: Bool) -> (sels: [JObject], error: String?) {
        if !present { return ([], nil) }
        let msg = "under must be {allow: selector | [selector]}"
        guard case let .object(u)? = under else { return ([], msg) }
        for k in JS.keyOrder(u) where k.s != "allow" { return ([], msg) }
        let allow = u["allow"]
        var list: [JSONValue] = []
        if case let .array(a)? = allow { list = a } else if let al = allow { list = [al] } else { list = [.null] }
        var out: [JObject] = []
        let selMsg = "an allow selector has trait, verb, where, caveats, context"
        for s in list {
            guard case let .object(m) = s else { return ([], selMsg) }
            for k in JS.keyOrder(m) where !SEL_KEYS.contains(k.s) { return ([], selMsg) }
            if (m[JKey("trait")] != nil) == (m[JKey("verb")] != nil) { return ([], "an allow selector names exactly one of trait and verb") }
            if m[JKey("where")] != nil && m["where"]?.asObject == nil { return ([], "where must be an object") }
            if m[JKey("caveats")] != nil {
                var ok = false
                if case let .array(cs)? = m["caveats"] { ok = cs.allSatisfy { $0.asString.map { CAVEAT_KINDS.contains($0) } ?? false } }
                if !ok { return ([], "caveats must be known caveat kinds") }
            }
            out.append(m)
        }
        return (out, nil)
    }

    private static func domainOf(_ v: String) -> String {
        let u = Array(v.utf16)
        let i = u.lastIndex(of: 64).map { $0 + 1 } ?? 0
        return String(decoding: u[i...], as: UTF16.self).lowercased()
    }

    /// The caveats of the grant a matching allow selector stands for, or nil when it does not match this call.
    private static func grantOf(_ sel: JObject, _ d: JObject, _ flat: JObject, _ eff: JObject) -> [String]? {
        if let tv = sel["trait"] {
            guard let t = tv.asString else { return nil }
            if !AK.arr(eff["closure"]).contains(.string(t.contains(".") ? t : "pca." + t)) { return nil }
        }
        if sel[JKey("verb")] != nil && sel["verb"] != d["verb"] { return nil }
        var caveats: [String] = []
        func addC(_ c: String) { if !caveats.contains(c) { caveats.append(c) } }
        if case let .array(cs)? = sel["caveats"] { for c in cs { if let s = c.asString { addC(s) } } }
        if case let .object(w)? = sel["where"] {
            for key in JS.keyOrder(w) {
                let cond = w[key]!
                let dom = key.s.hasSuffix(".domain")
                let name = dom ? String(key.s.dropLast(".domain".count)) : key.s
                guard let pd = JS.present(AK.o(d["params"])[JKey(name)]) else { return nil }
                guard let v = flat[JKey(name)] else { return nil }
                if case let .array(list) = cond {
                    guard let s = v.asString, list.contains(.string(dom ? domainOf(s) : s)) else { return nil }
                } else if case let .object(cm) = cond {
                    guard let n = IV.num(v) else { return nil }
                    if cm[JKey("max")] != nil, let mx = IV.num(cm["max"]), n > mx { return nil }
                    if cm[JKey("min")] != nil, let mn = IV.num(cm["min"]), n < mn { return nil }
                } else { return nil }
                let role = AK.pres(AK.o(pd), "role")?.asString ?? ""
                if role.hasPrefix("contact.") || role == "party.payee" { addC("recipient_scope") }
                else if role == "money.amount" { addC("amount_cap") }
                else if role == "count.limit" { addC("count_cap") }
                else if role.hasPrefix("id.") { addC("resource_scope") }
            }
        }
        return caveats
    }

    private static func floorDecision(_ grantCaveats: [String], _ maxEsc: Int64, _ preauth: Int64, _ context: Set<String>, _ rho: JObject) -> String {
        let esc = IV.int(rho["esc"]) ?? 0
        if esc > maxEsc { return "deny" }
        for c in AK.arr(rho["caveats"]) { if !grantCaveats.contains(c.asString ?? "") { return "escalate" } }
        for c in AK.arr(rho["context"]) { if !context.contains(c.asString ?? "") { return "escalate" } }
        return esc > preauth ? "escalate" : "allow"
    }

    /// Decide one example: `{got, why}`.
    public static func decideExample(_ d: JObject, _ ex: JObject, _ reg: TraitRegistry, _ defs: [JSONValue]) throws -> JSONValue {
        let doc = try ActionDerive.toSchemaDoc(defs, reg, ["site": .string("https://example.invalid"), "aud": .string("example"), "version": .string("0")], nil)
        guard let verb = d["verb"]?.asString else { throw AK.fail("bad_def", "verb") }
        let params = AK.o(ex["params"])
        let flat = ActionDerive.flattenParams(params)
        let c = ActionSchema.conform(doc, verb: verb, params: .object(flat))
        if !c.ok { return AK.obj(["got": .string("deny"), "why": .string("schema_violation \(c.code)" + ((c.path ?? "").isEmpty ? "" : " (\(c.path!))"))]) }
        let op = try ActionDerive.operationOf(d, params)
        if op.get("ok") != .bool(true) { return AK.obj(["got": .string("deny"), "why": op.get("reason") ?? .null]) }
        let parsed = parseUnder(ex["under"], ex[JKey("under")] != nil)
        if let e = parsed.error { return AK.obj(["got": .string("deny"), "why": .string("bad example policy: \(e)")]) }
        let eff = try hintOf(d, reg)
        var callCtx = Set<String>()
        if let idem = AK.pres(d, "idempotency") {
            if idem.get("mode") == .string("natural") { callCtx.insert("idempotency") }
            if idem.get("mode") == .string("key_param"), let p = AK.pres(AK.o(idem), "param"), let ps = p.asString, flat[JKey(ps)] != nil { callCtx.insert("idempotency") }
        }
        var gc: [String] = []
        var pre: Int64 = 0
        for s in parsed.sels {
            guard let g = grantOf(s, d, flat, eff) else { continue }
            pre = 3
            for x in g where !gc.contains(x) { gc.append(x) }
            if case let .array(cx)? = s["context"] { for k in cx { if let ks = k.asString { callCtx.insert(ks) } } }
        }
        let rho = AK.o(eff["eff"])
        let got = floorDecision(gc, 3, pre, callCtx, rho)
        var why = "floor satisfied"
        if got != "allow" {
            var need: [String] = []
            for k in AK.arr(rho["caveats"]) { if let s = k.asString, !gc.contains(s) { need.append(s) } }
            for k in AK.arr(rho["context"]) { if let s = k.asString, !callCtx.contains(s) { need.append(s) } }
            why = "floor needs " + (need.isEmpty ? "escalation tier " + JS.toString(rho["esc"]) : need.joined(separator: ", "))
        }
        return AK.obj(["got": .string(got), "why": .string(why)])
    }

    // ---- mutations of a conforming example ----

    private static func isBool(_ v: JSONValue?) -> Bool { if case .bool? = v { return true } else { return false } }

    private static func mutations(_ d: JObject, _ flat: JObject) -> [(String, JObject)] {
        var out: [(String, JObject)] = []
        var extra = flat
        extra["zz_undeclared"] = .string("x")
        out.append(("extra param", extra))
        let ps = AK.o(d["params"])
        for k in AK.sortedKeys(flat) {
            guard let pd = ps[JKey(k)], case let .object(p) = pd else { continue }
            if p["required"] != .bool(false) { var w = flat; w[JKey(k)] = nil; out.append(("missing \(k)", w)) }
            let v = flat[JKey(k)]
            var sw = flat
            if v?.asString != nil { sw[JKey(k)] = .int(12345) }
            else if IV.num(v) != nil || isBool(v) { sw[JKey(k)] = .string("x") }
            else { sw[JKey(k)] = .object([:]) }
            out.append(("type swap \(k)", sw))
            if IV.num(v) != nil && p["type"] == .string("integer") {
                if p[JKey("max")] != nil, let mx = IV.num(p["max"]) { var m = flat; m[JKey(k)] = .int(Int64(mx + 1)); out.append(("above max \(k)", m)) }
                if p[JKey("min")] != nil, let mn = IV.num(p["min"]) { var m = flat; m[JKey(k)] = .int(Int64(mn - 1)); out.append(("below min \(k)", m)) }
            }
            if v?.asString != nil && p["type"] == .string("string") {
                if AK.pres(p, "values") != nil { var m = flat; m[JKey(k)] = .string("not_a_listed_value_zz"); out.append(("outside values \(k)", m)) }
                if p[JKey("max_len")] != nil, let ml = IV.num(p["max_len"]) { var m = flat; m[JKey(k)] = .string(String(repeating: "x", count: Int(ml) + 1)); out.append(("too long \(k)", m)) }
            }
        }
        return out
    }

    private static func digestOk(_ r: JSONValue, _ want: String) throws -> Bool {
        guard AK.arr(r.get("errors")).isEmpty, let first = AK.arr(r.get("defs")).first else { return false }
        return try Actions.defDigest(AK.o(first)) == want
    }

    private static func firstMessage(_ r: JSONValue) -> String {
        let errs = AK.arr(r.get("errors"))
        return errs.isEmpty ? "digest differs" : JS.toString(errs[0].get("message"))
    }

    /// Run examples and property checks for a set of defs (one pack). `propLimit` bounds the trait subsets tried per def (nil = 256). The digest check across the
    /// YAML form hands `{ns, actions: [def]}` to `yamlLoader` (a YAML front end: stringify, parse, load; nil = `ActionsText.roundTrip`, the libyaml loader over the emitted text).
    /// Returns `{examples, props, ok}`.
    public static func runDefTests(_ defs: [JSONValue], _ reg: TraitRegistry, _ propLimit: Int?, _ yamlLoader: ((JSONValue) -> JSONValue)? = nil) throws -> JSONValue {
        var examples: [JSONValue] = [], props: [JSONValue] = []
        let limit = propLimit ?? 256
        for d0 in defs {
            let d = AK.o(d0)
            guard let verb = d["verb"]?.asString else { throw AK.fail("bad_def", "verb") }
            if case let .array(exs)? = d["examples"] {
                for (index, ex0) in exs.enumerated() {
                    let ex = AK.o(ex0)
                    let r = try decideExample(d, ex, reg, defs)
                    examples.append(AK.obj(["verb": .string(verb), "index": .int(Int64(index)), "expect": ex["expect"] ?? .null, "got": r.get("got") ?? .null,
                                            "ok": .bool(r.get("got") == ex["expect"]), "why": r.get("why") ?? .null]))
                }
            }
            // T2: adding any core trait never lowers the effective profile
            let eff = try hintOf(d, reg)
            let effP = eff["eff"] ?? .null
            var lowered: [String] = []
            for t in Actions.CORE_TRAIT_IDS {
                if !(try ActionEffective.leq(effP, try ActionEffective.effWithTrait(d, t, reg))) { lowered.append(t) }
            }
            props.append(AK.obj(["verb": .string(verb), "name": .string("adding a trait never lowers the profile"), "ok": .bool(lowered.isEmpty), "detail": .string(lowered.joined(separator: ", "))]))

            // T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
            let ts = AK.arr(eff["traits"]).compactMap { $0.asString }
            var bad = 0
            let total = min(Int64(1) << Int64(min(ts.count, 20)), Int64(limit))
            let top = try Actions.floorOf(reg, ts)
            var mask: Int64 = 0
            while mask < total {
                var sub: [String] = []
                for i in 0..<ts.count where ((mask >> Int64(i & 31)) & 1) != 0 { sub.append(ts[i]) }
                if !Actions.leq(try Actions.floorOf(reg, sub), top) { bad += 1 }
                mask += 1
            }
            props.append(AK.obj(["verb": .string(verb), "name": .string("floors are monotone over trait subsets"), "ok": .bool(bad == 0), "detail": .string("\(total) subsets, \(bad) violations")]))

            // one digest across the JSON and YAML forms
            let want = try Actions.defDigest(d)
            let viaJson = ActionAuthor.loadActionsValue(d0)
            let doc: JSONValue = AK.obj(["ns": .string(verb.components(separatedBy: ".")[0]), "actions": .array([d0])])
            let viaYaml = (yamlLoader ?? ActionsText.roundTrip)(doc)
            let okJ = try digestOk(viaJson, want), okY = try digestOk(viaYaml, want)
            props.append(AK.obj(["verb": .string(verb), "name": .string("one digest across JSON and YAML forms"), "ok": .bool(okJ && okY),
                                 "detail": .string(okJ && okY ? "" : "json " + (okJ ? "ok" : firstMessage(viaJson)) + "; yaml " + (okY ? "ok" : firstMessage(viaYaml)))]))

            // schema round trip: each example conforms, every mutation is refused
            guard case let .array(exs)? = d["examples"], !exs.isEmpty else {
                props.append(AK.obj(["verb": .string(verb), "name": .string("schema round trip"), "ok": .bool(true), "detail": .string("skipped: no examples")]))
                continue
            }
            let sdoc = try ActionDerive.toSchemaDoc(defs, reg, ["site": .string("https://example.invalid"), "aud": .string("example"), "version": .string("0")], nil)
            var accepted: [String] = []
            var tried = 0
            for ex0 in exs {
                let flat = ActionDerive.flattenParams(AK.o(ex0.get("params")))
                if !ActionSchema.conform(sdoc, verb: verb, params: .object(flat)).ok { continue } // a deliberately non-conforming example is a deny example
                for m in mutations(d, flat) {
                    tried += 1
                    if ActionSchema.conform(sdoc, verb: verb, params: .object(m.1)).ok, !accepted.contains(m.0) { accepted.append(m.0) }
                }
            }
            props.append(AK.obj(["verb": .string(verb), "name": .string("schema round trip"), "ok": .bool(accepted.isEmpty),
                                 "detail": .string(accepted.isEmpty ? "\(tried) mutations refused" : "accepted: " + accepted.joined(separator: ", "))]))
        }
        let ok = examples.allSatisfy { $0.get("ok") == .bool(true) } && props.allSatisfy { $0.get("ok") == .bool(true) }
        return AK.obj(["examples": .array(examples), "props": .array(props), "ok": .bool(ok)])
    }

    /// The report as plain lines, one PASS or FAIL per example and property, then a count.
    public static func testText(_ r: JObject) -> String {
        var lines: [String] = []
        for e in AK.arr(r["examples"]) {
            lines.append((e.get("ok") == .bool(true) ? "PASS" : "FAIL") + "  " + JS.toString(e.get("verb")) + " example " + String((IV.int(e.get("index")) ?? 0) + 1)
                         + ": expected " + JS.toString(e.get("expect")) + ", got " + JS.toString(e.get("got")) + " (" + JS.toString(e.get("why")) + ")")
        }
        for q in AK.arr(r["props"]) {
            let detail = q.get("detail")?.asString ?? ""
            lines.append((q.get("ok") == .bool(true) ? "PASS" : "FAIL") + "  " + JS.toString(q.get("verb")) + " " + JS.toString(q.get("name")) + (detail.isEmpty ? "" : ": " + detail))
        }
        let f = lines.filter { $0.hasPrefix("FAIL") }.count
        lines.append("\(lines.count - f) passed, \(f) failed")
        return lines.joined(separator: "\n")
    }
}
