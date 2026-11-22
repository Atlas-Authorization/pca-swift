import Foundation

/// The 24 stable lint rules (14 errors LD-001..014, 10 warnings LW-001..010), SARIF output and the rule-list digest. Pure: defs in,
/// findings out, deterministic order. A def that does not pass validation is reported as LD-000 and not linted further. The rule list
/// and its digest are those of the policy CI gate (one copy).
public enum ActionLint {
    public static let STRUCTURE_RULE = ("LD-000", "error", "the def is not well formed and cannot be loaded")
    public static let NOTE_RULE = ("LN-001", "note", "an informational note from the loader")

    /// The digest a policy gate pins: the ordered (id, severity, title) list.
    public static func lintRulesDigest() throws -> String { try PCAPolicyCi.lintRulesDigest() }

    private static let DESTROY = ["delete", "destroy", "remove", "purge", "drop", "erase", "wipe", "revoke", "terminate", "truncate"]
    private static let SEND = ["send", "email", "notify", "sms", "message", "post_to", "broadcast", "invite"]
    private static let EXPORT = ["export", "download", "dump", "backup", "extract"]
    private static let NAME_GROUPS = [["create_", "new_", "add_", "make_"], ["delete_", "remove_", "destroy_"]]
    private static let OWN_RULES = ["money_has_currency", "money_amount_bounded", "pay_has_idempotency"]
    private static let CRITICAL_ROLES: Set<String> = ["money.amount", "party.payee", "person.national_id", "credential.secret", "credential.token", "credential.key", "code.command", "query.sql"]
    private static let CRITICAL_TAGS: Set<String> = ["secret", "credential"]

    /// `^(?:w1|w2|...)(?:_|\z)`
    private static func startsWord(_ s: String, _ words: [String]) -> Bool { words.contains { s == $0 || s.hasPrefix($0 + "_") } }
    private static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    private static func isCritical(_ q: JObject) -> Bool {
        if q["sensitivity"] == .string("critical") { return true }
        if let r = q["role"]?.asString, CRITICAL_ROLES.contains(r) { return true }
        if case let .array(tg)? = q["tags"] { for t in tg { if let s = t.asString, CRITICAL_TAGS.contains(s) { return true } } }
        return false
    }

    private static func lastSeg(_ verb: String) -> String {
        let u = Array(verb.utf16)
        guard let i = u.lastIndex(of: 46) else { return verb }
        return String(decoding: u[(i + 1)...], as: UTF16.self)
    }

    private static func bindingKeys(_ d: JObject) -> [String] {
        var out: [String] = []
        guard let b = AK.pres(d, "bindings") else { return out }
        func g(_ k: String, _ f: String) -> String { JS.toString(b.get(k)?.get(f)) }
        if AK.pres(AK.o(b), "mcp") != nil { out.append("mcp:" + g("mcp", "tool")) }
        if AK.pres(AK.o(b), "openapi") != nil { out.append("openapi:" + g("openapi", "operationId")) }
        if AK.pres(AK.o(b), "http") != nil { out.append("http:" + g("http", "method").uppercased() + " " + g("http", "path")) }
        if AK.pres(AK.o(b), "graphql") != nil { out.append("graphql:" + g("graphql", "op") + "." + g("graphql", "field")) }
        if AK.pres(AK.o(b), "grpc") != nil { out.append("grpc:" + g("grpc", "service") + "/" + g("grpc", "method")) }
        if AK.pres(AK.o(b), "asyncapi") != nil { out.append("asyncapi:" + g("asyncapi", "op") + " " + g("asyncapi", "channel")) }
        return out
    }

    private static func vocabularyIssues(_ x: JSONValue, _ reg: TraitRegistry) -> [String] {
        var out: [String] = []
        guard case let .object(o) = x else { return out }
        if case let .array(effects)? = o["effects"] {
            for e in effects where !(e.asString.map { IV.contains(Actions.EFFECTS, $0) } ?? false) { out.append("unknown effect '\(JS.toString(e))'") }
        }
        if case let .object(params)? = o["params"] {
            for k in JS.keyOrder(params) {
                guard case let .object(qm) = params[k]! else { continue }
                if let r = qm["role"], !Actions.isRole(r) { out.append("\(k.s): unknown role '\(JS.toString(r))'") }
                if let f = qm["format"], !Actions.isFormat(f) { out.append("\(k.s): unknown format '\(JS.toString(f))'") }
            }
        }
        if case let .array(ctx)? = o["context"] {
            for c in ctx where !(c.asString.map { Actions.isContextKey($0) } ?? false) {
                out.append("unknown context key '\(JS.toString(c))' (known: \(Actions.CONTEXT_KEYS.joined(separator: ", ")), session_taint_max:<level>)")
            }
        }
        if case let .array(tr)? = o["traits"] {
            for t in tr { if let s = t.asString, reg.traits[JKey(s)] == nil { out.append("unknown trait '\(s)'") } }
        }
        return out
    }

    private static func severityOf(_ rule: String) -> String {
        if rule == STRUCTURE_RULE.0 { return "error" }
        return PCAPolicyCi.LINT_RULES.first { $0.id == rule }?.severity ?? "error"
    }

    private static func add(_ out: inout [JObject], _ rule: String, _ verb: String?, _ message: String, _ param: String?) {
        var f: JObject = ["rule": .string(rule), "severity": .string(severityOf(rule))]
        if let v = verb { f["verb"] = .string(v) }
        if let p = param { f["param"] = .string(p) }
        f["message"] = .string(message)
        out.append(f)
    }

    private static func pick(_ np: JObject, _ names: [String], _ pred: (JObject) -> Bool) -> [String] { names.filter { pred(AK.o(np[JKey($0)])) } }
    private static func tags(_ q: JObject) -> [JSONValue] { AK.arr(q["tags"]) }
    private static func roleStarts(_ q: JObject, _ pfx: String) -> Bool { q["role"]?.asString?.hasPrefix(pfx) ?? false }
    public static func isReadOnly(_ effects: [JSONValue]) -> Bool { !effects.isEmpty && effects.allSatisfy { $0 == .string("read") } }

    private static func groupOf(_ grp: [String], _ verb: String) -> String? { grp.first { lastSeg(verb).hasPrefix($0) } }

    private static func isJsSpace(_ u: UInt16) -> Bool {
        (9...13).contains(u) || u == 32 || u == 0xa0 || u == 0x1680 || (0x2000...0x200a).contains(u) || u == 0x2028 || u == 0x2029 || u == 0x202f || u == 0x205f || u == 0x3000 || u == 0xfeff
    }

    /// The first whitespace-separated token of a title (`title.split(/\s+/)[0]`: empty when the title starts with white space).
    private static func firstWord(_ t: String) -> String {
        let u = Array(t.utf16)
        var i = 0
        while i < u.count && !isJsSpace(u[i]) { i += 1 }
        return String(decoding: u[..<i], as: UTF16.self)
    }

    /// Lint a pack's defs (raw values, so a malformed one is still reported). `opts`: {customTraits?, stability?, ns?}; `attestationVerified`
    /// is the registry layer's signature check (nil: an attestation needs a `sig` member to count). Findings are sorted by verb, rule, param, message.
    public static func lintDefs(_ raw: [JSONValue], _ opts: JObject?, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> [JSONValue] {
        var out: [JObject] = []
        var reg = Actions.coreRegistry
        if case let .array(custom)? = opts?["customTraits"], !custom.isEmpty {
            do { reg = try Actions.extendRegistry(Actions.coreRegistry, custom) }
            catch let e as ActionKitError { add(&out, "LD-007", nil, "invalid custom traits: " + e.message, nil) }
            catch { add(&out, "LD-007", nil, "invalid custom traits: \(error)", nil) }
        }
        var defs: [JObject] = []
        for x in raw {
            let verb = x.get("verb")?.asString
            let vocab = vocabularyIssues(x, reg)
            if !vocab.isEmpty { for v in vocab { add(&out, "LD-007", verb, v, nil) }; continue }
            if let bad = Actions.validateDef(x) { add(&out, STRUCTURE_RULE.0, verb, bad, nil); continue }
            defs.append(AK.o(x))
        }
        var byVerb: [JKey: JObject] = [:]
        var names: [JKey: String] = [:]
        for d in defs {
            let v = d["verb"]?.asString ?? ""
            if byVerb[JKey(v)] != nil { add(&out, "LD-009", v, "verb '\(v)' is defined twice", nil) }
            byVerb[JKey(v)] = d
        }
        for d in defs {
            let v = d["verb"]?.asString ?? ""
            var ns: [String] = [v]
            if case let .array(al)? = d["aliases"] { ns += al.compactMap { $0.asString } }
            for n in ns {
                if let owner = names[JKey(n)], owner != v { add(&out, "LD-009", v, "'\(n)' is also a name of '\(owner)'", nil) }
                else if names[JKey(n)] == nil { names[JKey(n)] = v }
            }
        }
        var bound: [JKey: String] = [:]
        for d in defs {
            let v = d["verb"]?.asString ?? ""
            for k in bindingKeys(d) {
                if let owner = bound[JKey(k)], owner != v { add(&out, "LD-014", v, "binding \(k) is also bound by '\(owner)'", nil) }
                else { bound[JKey(k)] = v }
            }
        }
        for grp in NAME_GROUPS {
            var order: [String] = [], used: [String: Int] = [:]
            for d in defs {
                if let g = groupOf(grp, d["verb"]?.asString ?? "") { if used[g] == nil { order.append(g) }; used[g, default: 0] += 1 }
            }
            if used.count > 1 {
                let es = order.sorted { a, b in used[a]! != used[b]! ? used[a]! > used[b]! : u16less(a, b) }
                let win = es[0]
                for d in defs {
                    let v = d["verb"]?.asString ?? ""
                    if let g = groupOf(grp, v), g != win { add(&out, "LW-008", v, "uses '\(g)' where its siblings use '\(win)'", nil) }
                }
            }
        }
        if let fileNs = opts?["ns"]?.asString {
            for d in defs {
                let v = d["verb"]?.asString ?? ""
                let first = v.components(separatedBy: ".")[0]
                if first != fileNs { add(&out, "LW-008", v, "verb namespace '\(first)' differs from the file namespace '\(fileNs)'", nil) }
            }
        }
        for d in defs { try lintOne(&out, d, try Actions.normalize(d), reg, byVerb, opts, attestationVerified) }

        func cmp(_ a: String?, _ b: String?) -> Int { let x = a ?? "", y = b ?? ""; return x == y ? 0 : u16less(x, y) ? -1 : 1 }
        out.sort { a, b in
            var c = cmp(a["verb"]?.asString, b["verb"]?.asString)
            if c == 0 { c = cmp(a["rule"]?.asString, b["rule"]?.asString) }
            if c == 0 { c = cmp(a["param"]?.asString, b["param"]?.asString) }
            if c == 0 { c = cmp(a["message"]?.asString, b["message"]?.asString) }
            return c < 0
        }
        return out.map { .object($0) }
    }

    private static func lintOne(_ out: inout [JObject], _ d: JObject, _ n: JObject, _ reg: TraitRegistry, _ byVerb: [JKey: JObject], _ opts: JObject?, _ att: ((JObject) -> Bool)?) throws {
        let verb = d["verb"]?.asString ?? ""
        let np = AK.o(n["params"])
        let pn = AK.sortedKeys(np)
        guard let eff = try? ActionEffective.effective(d, reg, att) else { return }
        let hint = AK.o(eff["hint"])
        let tset = AK.arr(hint["traits"]), cl = AK.arr(hint["closure"])
        let effects = AK.arr(d["effects"])
        let last = lastSeg(verb)
        let idem = AK.o(n["idempotency"])

        if startsWord(last, DESTROY) && !effects.contains(.string("delete")) { add(&out, "LD-001", verb, "the verb says '\(last)' but effects do not include delete", nil) }
        for k in pick(np, pn, { $0["role"] == .string("money.amount") || $0["role"] == .string("money.fee") }) {
            let u = AK.pres(AK.o(np[JKey(k)]), "unit")
            if u == nil || u!.get("kind") != .string("money") { add(&out, "LD-002", verb, "a money parameter needs a unit of kind money with a currency", k) }
            else if u!.get("ccy")?.asString == nil {
                let from = u!.get("ccy")?.get("from")?.asString
                let c = from.flatMap { AK.pres(np, $0) }
                if c == nil || c!.get("role") != .string("money.currency") || c!.get("format") != .string("iso_currency") {
                    add(&out, "LD-002", verb, "the currency parameter '\(from ?? "null")' needs role money.currency and format iso_currency", k)
                }
            }
        }
        for k in pick(np, pn, { $0["role"] == .string("money.currency") }) where AK.o(np[JKey(k)])["format"] != .string("iso_currency") { add(&out, "LD-002", verb, "a currency parameter needs the iso_currency format", k) }
        for k in pick(np, pn, { $0["type"] == .string("integer") || $0["type"] == .string("duration") }) {
            let q = AK.o(np[JKey(k)])
            if roleStarts(q, "id.") { continue }
            if q["role"] == .string("count.limit") && AK.pres(q, "max") != nil { continue }
            let noMin = AK.pres(q, "min") == nil, noMax = AK.pres(q, "max") == nil
            if noMin || noMax { add(&out, "LD-003", verb, "a numeric parameter needs both min and max (has " + (noMin ? "no min" : "min") + ", " + (noMax ? "no max" : "max") + ")", k) }
        }
        if (effects.contains(.string("pay")) || tset.contains(.string("pca.money_moving"))) && idem["mode"] == .string("none") { add(&out, "LD-004", verb, "a money-moving action needs idempotency key_param or natural", nil) }
        let pii = pick(np, pn) { tags($0).contains(.string("pii")) || roleStarts($0, "contact.") || roleStarts($0, "person.") }
        if !pii.isEmpty {
            var expected = Set<String>()
            for s in AK.arr(d["side_effects"]) { if let k = s.get("kind")?.asString, k == "send" || k == "export" { expected.insert(k) } }
            if startsWord(last, SEND) { expected.insert("send") }
            if startsWord(last, EXPORT) { expected.insert("export") }
            for e in expected.sorted(by: u16less) where !effects.contains(.string(e)) {
                add(&out, "LD-005", verb, "personal data can " + (e == "send" ? "be sent" : "be exported") + " (" + pii.joined(separator: ", ") + ") but effects do not include " + e, nil)
            }
        }
        for c in AK.arr(eff["clamps"]) {
            add(&out, "LD-006", verb, "declared " + (c.get("field") == .string("rev") ? "reversibility" : "blast") + " " + JS.toString(c.get("declared")) + " is below the floor " + JS.toString(c.get("floor")), nil)
        }
        let res = AK.o(n["resource"])
        if res["id"] == .string("*") && res["scope"] == .string("one") { add(&out, "LD-008", verb, "resource id '*' with scope one names every resource at once", nil) }
        if !isReadOnly(effects) && ActionUndo.mayBeReversible(d) {
            if let comp = AK.pres(d, "compensates") {
                if let cs = comp.asString, let cd = byVerb[JKey(cs)] {
                    if let s = try? ActionUndo.compensationShape(d, cd), s.get("ok") != .bool(true) { add(&out, "LD-010", verb, "compensates '\(cs)', which cannot undo it: " + JS.toString(s.get("reason")), nil) }
                } else { add(&out, "LD-010", verb, "compensates '\(JS.toString(comp))', which is not in the pack", nil) }
            } else { add(&out, "LD-010", verb, "a write declared reversible must name its compensating action (compensates)", nil) }
        }
        let review = AK.o(d["review"])
        if review["state"] == .string("confirmed") {
            if let a = AK.pres(review, "attestation") {
                let ao = AK.o(a)
                let digest = try Actions.defDigest(d)
                if a.get("def_digest") != .string(digest) { add(&out, "LD-011", verb, "the attestation covers a different digest of this def", nil) }
                else if a.get("traits_digest") != .string(Actions.traitsDigest(reg)) { add(&out, "LD-011", verb, "the attestation was made against a different trait registry", nil) }
                else if (att != nil ? !att!(d) : ao[JKey("sig")] == nil) { add(&out, "LD-011", verb, "the attestation is not signed by a pinned reviewer", nil) }
            } else { add(&out, "LD-011", verb, "confirmed without an attestation", nil) }
        }
        var dismissed: [JSONValue] = []
        if review["state"] == .string("confirmed"), case let .array(ds)? = AK.o(review["attestation"])["dismissed"] { for x in ds { dismissed.append(x.get("trait") ?? .null) } }
        if let prov = AK.pres(review, "provenance"), case let .array(un)? = prov.get("union") {
            for t in un where !cl.contains(t) && !dismissed.contains(t) { add(&out, "LD-011", verb, "the union-added trait \(JS.toString(t)) was removed without a signed dismissal", nil) }
        }
        let required = AK.arr(AK.o(hint["eff"])["prules"]).compactMap { $0.asString }
        for r in try ActionEffective.prulesViolations(d, required) where !OWN_RULES.contains(r) { add(&out, "LD-012", verb, "structural rule \(r) is required by the action's traits and violated", nil) }
        if isReadOnly(effects) {
            let enforced = AK.arr(d["context"]).contains(.string("sandbox_attested"))
            for k in pick(np, pn, { $0["role"] == .string("code.command") || $0["role"] == .string("query.sql") }) where !enforced {
                add(&out, "LD-013", verb, "a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)", k)
            }
            for k in pick(np, pn, { tags($0).contains(.string("credential")) }) { add(&out, "LD-013", verb, "a read-only action handles a credential", k) }
        }

        if let desc = AK.pres(d, "description") {
            if (desc.asString?.utf8.count ?? 0) > 400 { add(&out, "LW-001", verb, "description is longer than 400 bytes", nil) }
        } else { add(&out, "LW-001", verb, "description is missing", nil) }
        let title = d["title"]?.asString ?? ""
        let first = firstWord(title).lowercased()
        let fu = Array(first.utf16)
        let sEnd = fu.count >= 2 && first.hasSuffix("s") && fu[fu.count - 2] != 115
        if first.hasSuffix("ing") || first.hasSuffix("ed") || (sEnd && !(first.hasSuffix("us") || first.hasSuffix("is"))) || ["a", "an", "the"].contains(first) {
            add(&out, "LW-001", verb, "title '\(title)' is not imperative", nil)
        }
        for k in pick(np, pn, { $0["type"] == .string("string") && AK.pres($0, "max_len") == nil && AK.pres($0, "values") == nil }) { add(&out, "LW-002", verb, "a string parameter without max_len (the default is 1024; say it)", k) }
        if cl.contains(.string("pca.external_communication")) {
            let ks = pick(np, pn) { q in
                q["type"] == .string("string") && AK.pres(q, "values") == nil && AK.pres(q, "format") == nil && (AK.pres(q, "role") == nil || roleStarts(q, "text.")) && !tags(q).contains(.string("free_text_outbound"))
            }
            for k in ks {
                if let ip = idem["param"]?.asString, k == ip { continue }
                add(&out, "LW-003", verb, "free text flows into an outbound action without tags: [free_text_outbound]", k)
            }
        }
        if opts?["stability"]?.asString == "stable", let st = review["state"]?.asString, st == "unreviewed" || st == "suggested" { add(&out, "LW-004", verb, "a \(st) def in a stable pack", nil) }
        if let a = AK.pres(review, "attestation"), case let .array(dis)? = a.get("dismissed") {
            for x in dis where Attest.jsTrim(x.get("reason")?.asString ?? "").utf16.count < 5 { add(&out, "LW-005", verb, "dismissed trait \(JS.toString(x.get("trait"))) has no reason", nil) }
        }
        for k in pick(np, pn, { $0["type"] == .string("array") && AK.pres($0, "max_items") == nil }) { add(&out, "LW-006", verb, "an array parameter without max_items", k) }
        for k in pick(np, pn, { isCritical($0) && AK.pres($0, "provenance_min") == nil }) { add(&out, "LW-007", verb, "a critical parameter without provenance_min", k) }
        let exNone = AK.arr(d["examples"]).isEmpty
        if (tset.contains(.string("pca.money_moving")) || tset.contains(.string("pca.destructive")) || tset.contains(.string("pca.privilege_change"))) && exNone { add(&out, "LW-009", verb, "no example for a money-moving, destructive or privilege-changing action", nil) }
        if AK.pres(d, "since") == nil { add(&out, "LW-010", verb, "since is missing", nil) }
    }

    /// Does the run fail? Errors always; warnings under `strict`.
    public static func lintFails(_ fs: [JSONValue], _ strict: Bool) -> Bool {
        fs.contains { f in
            let s = f.get("severity")
            return s == .string("error") || (strict && s == .string("warning"))
        }
    }

    private static func padEnd(_ s: String, _ n: Int) -> String { s.utf16.count >= n ? s : s + String(repeating: " ", count: n - s.utf16.count) }

    /// Plain text, one line per finding.
    public static func lintText(_ fs: [JSONValue]) -> String {
        if fs.isEmpty { return "0 errors, 0 warnings" }
        var e = 0, w = 0
        for f in fs { let s = f.get("severity"); if s == .string("error") { e += 1 } else if s == .string("warning") { w += 1 } }
        var lines: [String] = []
        func nonEmpty(_ v: JSONValue?) -> Bool { guard let v = JS.present(v) else { return false }; return v != .string("") }
        for f in fs {
            let file = f.get("file"), verb = f.get("verb"), param = f.get("param")
            let hasFile = nonEmpty(file), hasVerb = nonEmpty(verb), hasParam = nonEmpty(param)
            var loc = ""
            if hasFile {
                loc = JS.toString(file)
                if JS.present(f.get("line")) != nil { loc += ":" + JS.toString(f.get("line")) + ":" + (JS.present(f.get("column")) != nil ? JS.toString(f.get("column")) : "1") }
                loc += ": "
            }
            var line = padEnd(JS.toString(f.get("severity")), 7) + " " + JS.toString(f.get("rule")) + "  " + loc
            if hasVerb { line += JS.toString(verb) }
            if hasParam { line += " [" + JS.toString(param) + "]" }
            if hasVerb || hasParam { line += ": " }
            line += JS.toString(f.get("message"))
            lines.append(line)
        }
        let notes = fs.count - e - w
        var tail = "\(e) error" + (e == 1 ? "" : "s") + ", \(w) warning" + (w == 1 ? "" : "s")
        if notes > 0 { tail += ", \(notes) note" + (notes == 1 ? "" : "s") }
        return lines.joined(separator: "\n") + "\n" + tail
    }

    private static func level(_ s: String?) -> String { s == "error" ? "error" : s == "warning" ? "warning" : "note" }

    /// SARIF 2.1.0 so findings appear as pull request annotations. `tool`: {name?, version?}.
    public static func toSarif(_ fs: [JSONValue], _ tool: JObject?) -> JSONValue {
        var rules: [(String, String, String)] = [STRUCTURE_RULE, NOTE_RULE]
        for r in PCAPolicyCi.LINT_RULES { rules.append((r.id, r.severity, r.title)) }
        let rs: [JSONValue] = rules.map { AK.obj(["id": .string($0.0), "shortDescription": AK.obj(["text": .string($0.2)]), "defaultConfiguration": AK.obj(["level": .string(level($0.1))])]) }
        var driver: JObject = ["name": AK.pres(tool ?? [:], "name") ?? .string("pca actions lint")]
        if let v = AK.pres(tool ?? [:], "version"), v != .string("") { driver["version"] = v }
        driver["rules"] = .array(rs)
        var results: [JSONValue] = []
        for f in fs {
            let file = JS.present(f.get("file")), verb = JS.present(f.get("verb")), param = JS.present(f.get("param"))
            let hasFile = file != nil && file != .string(""), hasVerb = verb != nil && verb != .string("")
            var loc: JObject = [:]
            if hasFile {
                var pl: JObject = ["artifactLocation": AK.obj(["uri": file!])]
                if let line = JS.present(f.get("line")) { pl["region"] = AK.obj(["startLine": line, "startColumn": JS.present(f.get("column")) ?? .int(1)]) }
                loc["physicalLocation"] = .object(pl)
            }
            if hasVerb { loc["logicalLocations"] = .array([AK.obj(["name": verb!, "kind": .string("member")])]) }
            var text = ""
            if hasVerb { text = JS.toString(verb) + (param != nil && param != .string("") ? " [" + JS.toString(param) + "]" : "") + ": " }
            text += JS.toString(f.get("message"))
            results.append(AK.obj(["ruleId": f.get("rule") ?? .null, "level": .string(level(f.get("severity")?.asString)), "message": AK.obj(["text": .string(text)]), "locations": .array([.object(loc)])]))
        }
        return AK.obj(["$schema": .string("https://json.schemastore.org/sarif-2.1.0.json"), "version": .string("2.1.0"),
                       "runs": .array([AK.obj(["tool": AK.obj(["driver": .object(driver)]), "results": .array(results)])])])
    }
}
