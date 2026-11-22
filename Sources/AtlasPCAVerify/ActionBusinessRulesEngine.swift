import Foundation

/// The rules engine: a rules block compiled into tighten rules and count accumulators (each rule carries the signal `escalate` or `deny`, so a rule
/// can only lower a decision), their evaluation, the examples, the plain-language text, the lints and the semantic diff of two blocks.
extension ActionBusinessRules {
    static let LIKE_SPECIALS: Set<Character> = ["\\", "*", "?"]
    static let DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

    static func pp(_ n: String) -> String { "action.params." + n }
    static func cond(_ field: String, _ op: String, _ value: JSONValue) -> JSONValue { AK.obj(["field": .string(field), "op": .string(op), "value": value]) }
    static func mins(_ hhmm: String) -> Int {
        let u = Array(hhmm.utf8)
        return Int(u[0] - 48) * 600 + Int(u[1] - 48) * 60 + Int(u[3] - 48) * 10 + Int(u[4] - 48)
    }

    private static func ccyCond(_ m: JSONValue, _ c: String) -> JSONValue? {
        let ccy = AK.o(m.get("ccy"))
        if let p = ccy["param"]?.asString { return cond(pp(p), "eq", .string(c)) }
        return ccy["literal"] == .string(c) ? nil : cond("action.verb", "eq", .string("\u{0}never"))
    }

    private static func andOf(_ cs: [JSONValue?]) -> JSONValue {
        let xs = cs.compactMap { $0 }
        return xs.count == 1 ? xs[0] : AK.obj(["all_of": .array(xs)])
    }

    private static func ruleId(_ s: String) -> String {
        let units = s.lowercased().utf16.map { u -> UInt16 in
            (u >= 97 && u <= 122) || (u >= 48 && u <= 57) || u == 95 ? u : 95
        }
        return String(decoding: units.prefix(64), as: UTF16.self)
    }

    private static func rule(_ id: String, _ when: JSONValue, _ signal: String, _ reason: String) -> JObject {
        [JKey("id"): .string(id), JKey("when"): when, JKey("signal"): .string(signal), JKey("reason"): .string(reason)]
    }

    private static func listText(_ xs: [String]) -> String { xs.joined(separator: ", ") }

    private static func unlisted(_ money: JSONValue?, _ listed: [String], _ verb: JSONValue?) -> JSONValue? {
        guard let money = money else { return nil }
        let ccy = AK.o(money.get("ccy"))
        if let p = ccy["param"]?.asString { return AK.obj(["not": cond(pp(p), "in", AK.strs(listed))]) }
        if let lit = ccy["literal"]?.asString, listed.contains(lit) { return nil }
        return cond("action.verb", "eq", verb ?? .null)
    }

    private static func okAt(_ x: JObject, _ path: String) -> JSONValue {
        var any: [JSONValue] = []
        if own(x, "domains") {
            for dm in AK.arr(x["domains"]) {
                var esc = ""
                for ch in (dm.asString ?? "") { if LIKE_SPECIALS.contains(ch) { esc.append("\\") }; esc.append(ch) }
                any.append(cond(path, "like", .string("*@" + esc)))
            }
        }
        if own(x, "addresses") { any.append(cond(path, "in", .array(AK.arr(x["addresses"]).sorted { u16less($0.asString ?? "", $1.asString ?? "") }))) }
        return AK.obj(["any_of": .array(any)])
    }

    // ---- compile ----

    /// Compile a rules block for `d`. Throws `bad_rules` for a malformed block. Deterministic.
    /// `compileBusinessRules` over a JSON value: anything but an object is `bad_rules` ("rules must be an object"), as the reference's validation reports it.
    public static func compileBusinessRules(_ d: JObject, rulesValue: JSONValue?) throws -> JObject {
        guard case let .object(r)? = rulesValue else { throw bad("rules must be an object") }
        return try compileBusinessRules(d, r)
    }

    /// `explainBusinessRules` over a JSON value (see `compileBusinessRules(_:rulesValue:)`).
    public static func explainBusinessRules(_ d: JObject, rulesValue: JSONValue?) throws -> [String] {
        guard case let .object(r)? = rulesValue else { throw bad("rules must be an object") }
        return try explainBusinessRules(d, r)
    }

    /// `runRuleExamples` over a JSON value (see `compileBusinessRules(_:rulesValue:)`).
    public static func runRuleExamples(_ d: JObject, rulesValue: JSONValue?) throws -> [JSONValue] {
        guard case let .object(r)? = rulesValue else { throw bad("rules must be an object") }
        return try runRuleExamples(d, r)
    }

    public static func compileBusinessRules(_ d: JObject, _ rules: JObject) throws -> JObject {
        try validateRules(d, .object(rules))
        var t: [JObject] = [], acc: [JSONValue] = []
        let verb = d["verb"] ?? .null
        guard let verbS = verb.asString else { throw bad("the action has no verb") }
        var out: JObject = [JKey("v"): .int(1), JKey("verb"): verb, JKey("rules_digest"): .string(try businessRulesDigest(verbS, rules)), JKey("def_digest"): .string(try Actions.defDigest(d))]
        let approval = rules["approval"]?.asObject
        let money: JSONValue? = try (own(rules, "amount") || (approval.map { own($0, "above") } ?? false)) ? moneyOf(d) : nil
        let exp = try money.map { try expOf($0) } ?? 0
        if own(rules, "amount") {
            let maxes = AK.o(rules["amount"]?.get("max"))
            let listed = AK.sortedKeys(maxes)
            let mm = money!
            for c in listed {
                let mx = try minorUnits(maxes[JKey(c)], exp, "rules.amount.max.\(c)")
                t.append(rule(ruleId("amount_max_" + c), andOf([ccyCond(mm, c), cond(pp(mm.get("amount")?.asString ?? ""), "gt", .int(mx))]), "deny", "the amount is above the " + formatMoney(mx, c, exp) + " ceiling"))
            }
            if let u = unlisted(money, listed, verb) { t.append(rule("amount_currency", u, "deny", "only " + listText(listed) + " amounts are allowed")) }
        }
        if let ap = approval {
            var need: JObject = [JKey("approvers"): own(ap, "approvers") ? (ap["approvers"] ?? .null) : .int(1)]
            if own(ap, "group") { need[JKey("group")] = ap["group"] }
            out[JKey("approval")] = .object(need)
            if ap["always"] == .bool(true) { t.append(rule("approval_always", cond("action.verb", "eq", verb), "escalate", "this action always needs approval")) }
            else {
                let above = AK.o(ap["above"])
                let listed = AK.sortedKeys(above)
                let mm = money!
                for c in listed {
                    let x = try minorUnits(above[JKey(c)], exp, "rules.approval.above.\(c)")
                    t.append(rule(ruleId("approval_above_" + c), andOf([ccyCond(mm, c), cond(pp(mm.get("amount")?.asString ?? ""), "gt", .int(x))]), "escalate", "amounts above " + formatMoney(x, c, exp) + " need approval"))
                }
                if let u = unlisted(money, listed, verb) { t.append(rule("approval_currency", u, "escalate", "amounts in a currency other than " + listText(listed) + " need approval")) }
            }
        }
        if own(rules, "scope") {
            for (i, s0) in AK.arr(rules["scope"]).enumerated() {
                let s = AK.o(s0)
                let name = try resolveParamRef(d, refOf(s), "rules.scope[\(i)]").name
                // `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
                let eq = AK.obj(["field": .string(pp(name)), "op": .string("eq"), "ref": .string("subject." + JS.toString(s["caller"]))])
                t.append(rule("scope_\(i)", AK.obj(["not": eq]), "deny", name + " must be the caller's own " + JS.toString(s["caller"])))
            }
        }
        if own(rules, "rate") {
            for (i, r0) in AK.arr(rules["rate"]).enumerated() {
                let r = AK.o(r0)
                let id = "rate_\(i)"
                let by = own(r, "by") ? JS.toString(r["by"]) : "principal"
                let per = JS.toString(r["per"])
                acc.append(AK.obj(["id": .string(id), "agg": .string("count"), "sel": AK.obj(["verbs": .array([verb])]),
                    "win": AK.obj(["kind": .string("sliding"), "ms": .int(RATE_PERIODS[per] ?? 0)]), "key": .null, "domain_max": r["max"] ?? .null, "cap": r["max"] ?? .null,
                    "holder": AK.obj(["kind": .string("site_local")]), "scope": .string(by)]))
                t.append(rule(id, cond("env.acc." + id, "gte", r["max"] ?? .null), "deny", "at most " + JS.toString(r["max"]) + " per " + per + " per " + by))
            }
        }
        if own(rules, "hours") {
            let h = AK.o(rules["hours"])
            let from = mins(JS.toString(h["from"])), to = mins(JS.toString(h["to"]))
            let dows = AK.arr(h["days"]).map { RULE_DAYS.firstIndex(of: $0.asString ?? "") ?? -1 }.sorted()
            let dowsJ = JSONValue.array(dows.map { .int(Int64($0)) }), nextJ = JSONValue.array(dows.map { .int(Int64(($0 + 1) % 7)) })
            let gte = cond("env.clock.min", "gte", .int(Int64(from))), lt = cond("env.clock.min", "lt", .int(Int64(to)))
            let inTime = from < to ? AK.obj(["all_of": .array([gte, lt])]) : AK.obj(["any_of": .array([gte, lt])])
            let day = from < to ? cond("env.clock.dow", "in", dowsJ)
                : AK.obj(["any_of": .array([AK.obj(["all_of": .array([cond("env.clock.dow", "in", dowsJ), gte])]), AK.obj(["all_of": .array([cond("env.clock.dow", "in", nextJ), lt])])])])
            out[JKey("clock_tz")] = h["tz"]
            t.append(rule("hours", AK.obj(["not": AK.obj(["all_of": .array([day, inTime])])]), own(h, "outside") ? JS.toString(h["outside"]) : "escalate", "outside " + hoursText(h)))
        }
        if own(rules, "recipients") {
            let x = AK.o(rules["recipients"])
            let res = try resolveParamRef(d, refOf(x), "rules.recipients")
            let p = AK.o(res.p)
            let ok: JSONValue
            if p["type"] == .string("string") { ok = okAt(x, pp(res.name)) }
            else {
                let n = Int(IV.num(p["max_items"]) ?? 0)
                var all: [JSONValue] = []
                for i in 0..<max(n, 0) { all.append(AK.obj(["any_of": .array([cond(pp("\(res.name).\(i)"), "exists", .bool(false)), okAt(x, pp("\(res.name).\(i)"))])])) }
                all.append(cond(pp("\(res.name).\(n)"), "exists", .bool(false)))
                ok = AK.obj(["all_of": .array(all)])
            }
            t.append(rule("recipients", AK.obj(["not": ok]), "deny", res.name + " may only name " + recipientsText(x)))
        }
        if own(rules, "required") {
            let ps = AK.o(d["params"])
            for (i, n0) in AK.arr(rules["required"]).enumerated() {
                let n = n0.asString ?? ""
                let missing = ps[JKey(n)]?.get("type") == .string("string")
                    ? AK.obj(["any_of": .array([cond(pp(n), "exists", .bool(false)), cond(pp(n), "eq", .string(""))])])
                    : cond(pp(n), "exists", .bool(false))
                t.append(rule("required_\(i)", missing, "deny", n + " is required"))
            }
        }
        for i in t.indices {
            if let rs = t[i]["reason"]?.asString, rs.utf16.count > 256 { t[i]["reason"] = .string(String(decoding: Array(rs.utf16.prefix(253)), as: UTF16.self) + "...") }
        }
        out[JKey("tighten")] = .array(t.map { .object($0) })
        out[JKey("accumulators")] = .array(acc)
        return out
    }

    // ---- evaluate ----

    /// The predicate context the compiled rules are evaluated in. Verifier-computed `env` members only.
    public static func rulesContext(_ c: JObject, _ i: JObject) -> JSONValue {
        var env: JObject = [:]
        if own(c, "clock_tz"), let k = clockAt(IV.num(i["now"]) ?? Double.nan, c["clock_tz"]?.asString) { env[JKey("clock")] = k }
        var acc: JObject = [:]
        let counts = i["counts"]?.asObject
        for a in AK.arr(c["accumulators"]) {
            guard let id = a.get("id")?.asString, let n = counts?[JKey(id)], let nd = IV.num(n), nd == nd.rounded(), abs(nd) <= 9007199254740991.0, nd >= 0 else { continue }
            acc[JKey(id)] = n
        }
        env[JKey("acc")] = .object(acc)
        var action: JObject = [JKey("verb"): c["verb"] ?? .null, JKey("resource"): JS.present(i["resource"]) ?? .string("")]
        if let p = i["params"] { action[JKey("params")] = p }
        return AK.obj(["action": .object(action), "subject": JS.present(i["subject"]) ?? .object([:]), "env": .object(env)])
    }

    /// Evaluate compiled rules: `allow` unless a rule fires; a fired rule caps the decision at its signal. Never throws.
    public static func evaluateBusinessRules(_ c: JObject, _ i: JObject) -> JObject {
        let ctx = rulesContext(c, i)
        var decision = "allow"
        var reasons: [JSONValue] = [], fired: [JSONValue] = []
        var approval = false
        for r0 in AK.arr(c["tighten"]) {
            let r = AK.o(r0)
            if Predicates.conditionTri(r["when"] ?? .null, ctx, SafeRegex.Budget()) == .f { continue }
            let signal = JS.toString(r["signal"])
            decision = PCA.meet(decision, signal)
            fired.append(r["id"] ?? .null)
            reasons.append(.string(JS.toString(r["id"]) + ": " + (JS.present(r["reason"]).map { JS.toString($0) } ?? signal)))
            if signal == "escalate" && JS.toString(r["id"]).hasPrefix("approval_") { approval = true }
        }
        var out: JObject = [JKey("decision"): .string(decision), JKey("reasons"): .array(reasons), JKey("fired"): .array(fired)]
        if approval, let a = JS.present(c["approval"]) { out[JKey("approval")] = a }
        return out
    }

    /// The decision with rules applied to a base decision: the meet, so rules never raise it.
    public static func withBusinessRules(_ base: String, _ verdict: JObject) -> String { PCA.meet(base, JS.toString(verdict["decision"])) }

    /// Run a rules block's examples: a list of `{index, expect, got, ok, why}`.
    public static func runRuleExamples(_ d: JObject, _ rules: JObject) throws -> [JSONValue] {
        let c = try compileBusinessRules(d, rules)
        guard own(rules, "examples") else { return [] }
        var out: [JSONValue] = []
        for (index, e0) in AK.arr(rules["examples"]).enumerated() {
            let e = AK.o(e0)
            var counts: JObject = [:]
            for (k, a) in AK.arr(c["accumulators"]).enumerated() {
                counts[JKey(JS.toString(a.get("id")))] = e["recent"]?.asObject?[JKey(String(k))] ?? .int(0)
            }
            var inp: JObject = [JKey("params"): e["params"] ?? .null]
            if let cl = JS.present(e["caller"]) { inp[JKey("subject")] = cl }
            let now = JS.present(e["at"]).map { parseUtc(JS.toString($0)) } ?? parseUtc("2026-01-07T15:00:00Z")
            inp[JKey("now")] = now == now.rounded() ? .int(Int64(now)) : .double(now)
            inp[JKey("counts")] = .object(counts)
            let v = evaluateBusinessRules(c, inp)
            let why = AK.arr(v["reasons"]).map { JS.toString($0) }.joined(separator: "; ")
            out.append(AK.obj(["index": .int(Int64(index)), "expect": e["expect"] ?? .null, "got": v["decision"] ?? .null, "ok": .bool(v["decision"] == e["expect"]), "why": .string(why.isEmpty ? "no rule fired" : why)]))
        }
        return out
    }

    // ---- plain language ----

    static func hoursText(_ h: JObject) -> String {
        let idx = AK.arr(h["days"]).map { RULE_DAYS.firstIndex(of: $0.asString ?? "") ?? 0 }.sorted()
        var run = idx.count > 2
        for k in 1..<max(idx.count, 1) where idx[k] != idx[k - 1] + 1 { run = false }
        let days = run ? DAY_NAMES[idx[0]] + "-" + DAY_NAMES[idx[idx.count - 1]] : idx.map { DAY_NAMES[$0] }.joined(separator: ", ")
        return days + " " + JS.toString(h["from"]) + "-" + JS.toString(h["to"]) + " (" + JS.toString(h["tz"]) + ")"
    }

    static func recipientsText(_ x: JObject) -> String {
        var parts: [String] = []
        if own(x, "domains") { for dm in AK.arr(x["domains"]) { parts.append("addresses at " + JS.toString(dm)) } }
        if own(x, "addresses") { for a in AK.arr(x["addresses"]) { parts.append(JS.toString(a)) } }
        return parts.joined(separator: " or ")
    }

    private static func moneyList(_ mp: JObject, _ exp: Int) throws -> String {
        try AK.sortedKeys(mp).map { c in formatMoney(try minorUnits(mp[JKey(c)], exp, c), c, exp) }.joined(separator: ", ")
    }

    /// One plain sentence per rule. Throws `bad_rules` for a malformed block.
    public static func explainBusinessRules(_ d: JObject, _ rules: JObject) throws -> [String] {
        try validateRules(d, .object(rules))
        var out: [String] = []
        let approval = rules["approval"]?.asObject
        let m: JSONValue? = try (own(rules, "amount") || (approval.map { own($0, "above") } ?? false)) ? moneyOf(d) : nil
        let exp = try m.map { try expOf($0) } ?? 0
        if own(rules, "amount") { out.append("Refuses amounts above " + (try moneyList(AK.o(rules["amount"]?.get("max")), exp)) + "; any other currency is refused.") }
        if let ap = approval {
            let n = own(ap, "approvers") ? (IV.num(ap["approvers"]) ?? 0) : 1.0
            let who = JS.number(n) + " approver" + (n == 1.0 ? "" : "s") + (own(ap, "group") && ap["group"] != .string("") ? " from the " + JS.toString(ap["group"]) + " group" : "")
            out.append(ap["always"] == .bool(true) ? "Always needs approval by \(who)." : "Needs approval by \(who) when the amount is above " + (try moneyList(AK.o(ap["above"]), exp)) + " (or in another currency).")
        }
        if own(rules, "scope") {
            for s0 in AK.arr(rules["scope"]) {
                let s = AK.o(s0)
                let name = try resolveParamRef(d, refOf(s), "rules.scope").name
                out.append("Only the caller's own records: \(name) must be the caller's " + JS.toString(s["caller"]) + ".")
            }
        }
        if own(rules, "rate") {
            for r0 in AK.arr(rules["rate"]) {
                let r = AK.o(r0)
                out.append("At most " + JS.toString(r["max"]) + " per " + JS.toString(r["per"]) + " per " + (r["by"] == .string("org") ? "organisation" : "principal") + ".")
            }
        }
        if own(rules, "hours") {
            let h = AK.o(rules["hours"])
            out.append("Only " + hoursText(h) + "; outside those hours it " + (h["outside"] == .string("deny") ? "is refused" : "needs approval") + ".")
        }
        if own(rules, "recipients") {
            let x = AK.o(rules["recipients"])
            let name = try resolveParamRef(d, refOf(x), "rules.recipients").name
            out.append(name + " may only name " + recipientsText(x) + ".")
        }
        if own(rules, "required") { out.append("Requires " + listText(AK.arr(rules["required"]).map { JS.toString($0) }) + ".") }
        return out
    }

    // ---- lint ----

    /// The rules lints (ids LR-*): `[id, severity, title]`.
    public static let BUSINESS_RULE_LINTS: [[String]] = [
        ["LR-001", "error", "a rules block is malformed or names a parameter the action does not have"],
        ["LR-002", "error", "a contradiction: under the rules the action can never be allowed"],
        ["LR-003", "warning", "a rule that can never fire or that another rule already covers"],
        ["LR-004", "error", "a rules example does not decide as it expects"],
    ]

    private static func finding(_ d: JObject, _ rule: String, _ severity: String, _ message: String) -> JSONValue {
        AK.obj(["rule": .string(rule), "severity": .string(severity), "verb": d["verb"] ?? .null, "message": .string(message)])
    }

    /// Lint one action's rules.
    public static func lintBusinessRules(_ d: JObject, _ rules: JSONValue?) throws -> [JSONValue] {
        var out: [JSONValue] = []
        if let e = businessRulesError(d, rules) { return [finding(d, "LR-001", "error", e)] }
        let r = AK.o(rules)
        let approval = r["approval"]?.asObject
        let ps = AK.o(d["params"])
        let above = approval.map { own($0, "above") } ?? false
        let m: JSONValue? = try (own(r, "amount") || above) ? moneyOf(d) : nil
        let exp = try m.map { try expOf($0) } ?? 0
        let amt: JObject? = m.map { AK.o(ps[JKey($0.get("amount")?.asString ?? "")]) }
        var ccyValues: [JSONValue]? = nil
        if let m = m {
            let ccy = AK.o(m.get("ccy"))
            if let p = ccy["param"]?.asString { ccyValues = ps[JKey(p)]?.get("values")?.asArray }
            else { ccyValues = [ccy["literal"] ?? .null] }
        }
        if own(r, "amount"), m != nil {
            let maxes = AK.o(r["amount"]?.get("max"))
            let listed = JS.keyOrder(maxes).map { $0.s }
            if let cv = ccyValues, !cv.contains(where: { $0.asString.map { listed.contains($0) } ?? false }) {
                out.append(finding(d, "LR-002", "error", "rules.amount: none of the action's currencies (" + cv.map { JS.toString($0) }.joined(separator: ", ") + ") has a ceiling, so every call is refused"))
            }
            for c in listed {
                let mx = try minorUnits(maxes[JKey(c)], exp, c)
                if let cv = ccyValues, !cv.contains(.string(c)) { out.append(finding(d, "LR-003", "warning", "rules.amount.max.\(c): the action never uses \(c)")) }
                if let a = amt, own(a, "min"), Double(mx) < (IV.num(a["min"]) ?? 0) { out.append(finding(d, "LR-002", "error", "rules.amount.max.\(c): the ceiling " + formatMoney(mx, c, exp) + " is below the parameter's minimum, so every \(c) call is refused")) }
                if let a = amt, own(a, "max"), Double(mx) >= (IV.num(a["max"]) ?? 0) { out.append(finding(d, "LR-003", "warning", "rules.amount.max.\(c): the parameter's own maximum already bounds the amount below this ceiling")) }
            }
        }
        if above, m != nil {
            let ab = AK.o(approval?["above"])
            let amount = own(r, "amount") ? r["amount"]?.get("max") : nil
            for k in JS.keyOrder(ab) {
                let c = k.s
                let x = try minorUnits(ab[k], exp, c)
                let ceil = amount?.asObject?[JKey(c)]
                if let ce = ceil, ce != .null, x >= (try minorUnits(ce, exp, c)) { out.append(finding(d, "LR-003", "warning", "rules.approval.above.\(c): above the amount ceiling, so the approval can never be asked for")) }
                if own(r, "amount") && (ceil == nil || ceil == .null) { out.append(finding(d, "LR-003", "warning", "rules.approval.above.\(c): \(c) has no ceiling, so it is always refused before an approval")) }
            }
        }
        if own(r, "hours") {
            let h = AK.o(r["hours"])
            if h["from"] == h["to"] { out.append(finding(d, "LR-002", "error", "rules.hours: the window " + JS.toString(h["from"]) + "-" + JS.toString(h["to"]) + " is empty, so the action is " + (h["outside"] == .string("deny") ? "always refused" : "always escalated"))) }
        }
        if own(r, "required") {
            for n in AK.arr(r["required"]) {
                let p = AK.o(ps[JKey(n.asString ?? "")])
                if p["required"] != .bool(false) && p["type"] != .string("string") { out.append(finding(d, "LR-003", "warning", "rules.required: '" + JS.toString(n) + "' is already required by the definition")) }
            }
        }
        if own(r, "rate") {
            var seen: [String: Double] = [:]
            for x0 in AK.arr(r["rate"]) {
                let x = AK.o(x0)
                let per = JS.toString(x["per"])
                let by = own(x, "by") ? JS.toString(x["by"]) : "principal"
                let k = "\(per)|\(by)"
                let mx = IV.num(x["max"]) ?? 0
                if let s = seen[k] { out.append(finding(d, "LR-003", "warning", "rules.rate: two limits per \(per) per \(by); only the lower (" + JS.number(min(s, mx)) + ") matters")) }
                seen[k] = min(seen[k] ?? Double.infinity, mx)
            }
            if let hh = seen["hour|principal"], let dd = seen["day|principal"], dd <= hh { out.append(finding(d, "LR-003", "warning", "rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires")) }
        }
        do {
            for x0 in try runRuleExamples(d, r) {
                let x = AK.o(x0)
                if x["ok"] != .bool(true) { out.append(finding(d, "LR-004", "error", "rules.examples[" + JS.toString(x["index"]) + "]: expected " + JS.toString(x["expect"]) + ", got " + JS.toString(x["got"]) + " (" + JS.toString(x["why"]) + ")")) }
            }
        } catch let err as ActionKitError { out.append(finding(d, "LR-001", "error", err.message)) }
        return out
    }

    // ---- semantic diff ----

    enum Rel { case eq, narrow, widen, inc
        var name: String { switch self { case .eq: return "eq"; case .narrow: return "narrow"; case .widen: return "widen"; case .inc: return "incomparable" } }
    }

    private static func setRel(_ a: [JSONValue], _ b: [JSONValue]) -> Rel {
        let aInB = a.allSatisfy { b.contains($0) }, bInA = b.allSatisfy { a.contains($0) }
        return aInB && bInA ? .eq : bInA ? .narrow : aInB ? .widen : .inc
    }
    private static func numRel(_ a: Double, _ b: Double) -> Rel { a == b ? .eq : b < a ? .narrow : .widen }
    private static func presence(_ o: JObject, _ n: JObject, _ k: String) -> Rel? {
        let a = !own(o, k), b = !own(n, k)
        return a && b ? .eq : a ? .narrow : b ? .widen : nil
    }
    private static func combine(_ rs: [Rel]) -> Rel {
        let inc = rs.contains(.inc), nar = rs.contains(.narrow), wid = rs.contains(.widen)
        return inc || (nar && wid) ? .inc : wid ? .widen : nar ? .narrow : .eq
    }
    private static func flip(_ r: Rel) -> Rel { r == .narrow ? .widen : r == .widen ? .narrow : r }

    private static func ccyMapRel(_ a: JSONValue?, _ b: JSONValue?, _ exp: Int) throws -> Rel {
        // Object.keys of a missing map is a TypeError in the reference (an approval with neither `always` nor `above`)
        for v in [a, b] where v == nil || v == .null { throw JSError("Cannot convert undefined or null to object") }
        let ma = AK.o(a), mb = AK.o(b)
        var rs = [setRel(ma.keys.map { .string($0.s) }, mb.keys.map { .string($0.s) })]
        for (k, v) in ma { if let w = mb[k] { rs.append(numRel(Double(try minorUnits(v, exp, k.s)), Double(try minorUnits(w, exp, k.s)))) } }
        return combine(rs)
    }

    private static func minutesOfWeek(_ h: JObject) -> Set<Int> {
        var s = Set<Int>()
        let from = mins(JS.toString(h["from"])), to = mins(JS.toString(h["to"]))
        for day in AK.arr(h["days"]) {
            let base = (RULE_DAYS.firstIndex(of: day.asString ?? "") ?? 0) * 1440
            if from < to { for x in from..<to { s.insert(base + x) } }
            else if from > to {
                for x in from..<1440 { s.insert(base + x) }
                for x in 0..<to { s.insert(((base + 1440) % 10080) + x) }
            }
        }
        return s
    }

    private static func bestRates(_ rs: JSONValue?) -> [String: Double] {
        var mp: [String: Double] = [:]
        for x0 in AK.arr(rs) {
            let x = AK.o(x0)
            let k = JS.toString(x["per"]) + "|" + (own(x, "by") ? JS.toString(x["by"]) : "principal")
            mp[k] = min(mp[k] ?? Double.infinity, IV.num(x["max"]) ?? 0)
        }
        return mp
    }

    private static func scopeKeys(_ sc: JSONValue?) -> [JSONValue] {
        AK.arr(sc).map { s0 in
            let s = AK.o(s0)
            return .string((JS.present(s["param"]).map { JS.toString($0) } ?? "") + "|" + (JS.present(s["role"]).map { JS.toString($0) } ?? "") + "|" + JS.toString(s["caller"]))
        }
    }

    private static func allowedList(_ x: JObject) -> [String] {
        AK.arr(x["domains"]).map { "@" + JS.toString($0) } + AK.arr(x["addresses"]).map { JS.toString($0) }
    }

    private static func covered(_ x: String, _ set: [String]) -> Bool {
        if set.contains(x) { return true }
        if x.hasPrefix("@") { return false }
        let parts = x.components(separatedBy: "@")
        return parts.count > 1 && set.contains("@" + parts[1])
    }

    /// The semantic diff of two rules blocks of one action (either may be absent). `narrow` and `equal` can be published without a reviewer;
    /// `widen` and `incomparable` need a reviewer's signed rules review. Returns `{class, reasons}`.
    public static func diffBusinessRules(_ d: JObject, _ prev: JObject?, _ next: JObject?) throws -> JObject {
        var rels: [(String, Rel)] = []
        let o = prev ?? [:], n = next ?? [:]
        let hasAbove = { (x: JObject) in own(x, "approval") && own(AK.o(x["approval"]), "above") }
        let m: JSONValue? = try (own(o, "amount") || own(n, "amount") || hasAbove(o) || hasAbove(n)) ? moneyOf(d) : nil
        let exp = try m.map { try expOf($0) } ?? 0

        rels.append(("amount", try presence(o, n, "amount") ?? ccyMapRel(o["amount"]?.get("max"), n["amount"]?.get("max"), exp)))

        var pr = presence(o, n, "approval")
        if pr == nil {
            let a = AK.o(o["approval"]), b = AK.o(n["approval"])
            var rs: [Rel] = []
            let aa = a["always"] == .bool(true), ba = b["always"] == .bool(true)
            if aa && ba { rs.append(.eq) } else if aa { rs.append(.widen) } else if ba { rs.append(.narrow) } else { rs.append(try ccyMapRel(a["above"], b["above"], exp)) }
            rs.append(numRel(-(own(a, "approvers") ? IV.num(a["approvers"]) ?? 0 : 1.0), -(own(b, "approvers") ? IV.num(b["approvers"]) ?? 0 : 1.0)))
            rs.append(a["group"] == b["group"] ? .eq : .inc)
            pr = combine(rs)
        }
        rels.append(("approval", pr!))

        rels.append(("scope", flip(setRel(scopeKeys(o["scope"]), scopeKeys(n["scope"])))))

        let ra = bestRates(o["rate"]), rb = bestRates(n["rate"])
        var rr: [Rel] = []
        for k in Set(ra.keys).union(rb.keys) { rr.append(ra[k] == nil ? .narrow : rb[k] == nil ? .widen : numRel(ra[k]!, rb[k]!)) }
        rels.append(("rate", combine(rr)))

        pr = presence(o, n, "hours")
        if pr == nil {
            let a = AK.o(o["hours"]), b = AK.o(n["hours"])
            if a["tz"] != b["tz"] { pr = .inc }
            else {
                let sa = minutesOfWeek(a), sb = minutesOfWeek(b)
                let inner: Rel = sa == sb ? .eq : sa.isSuperset(of: sb) ? .narrow : sb.isSuperset(of: sa) ? .widen : .inc
                pr = combine([inner, numRel(a["outside"] == .string("deny") ? 0 : 1, b["outside"] == .string("deny") ? 0 : 1)])
            }
        }
        rels.append(("hours", pr!))

        pr = presence(o, n, "recipients")
        if pr == nil {
            let a = AK.o(o["recipients"]), b = AK.o(n["recipients"])
            if a["param"] != b["param"] || a["role"] != b["role"] { pr = .inc }
            else {
                let la = allowedList(a), lb = allowedList(b)
                let bInA = lb.allSatisfy { covered($0, la) }, aInB = la.allSatisfy { covered($0, lb) }
                pr = bInA && aInB ? .eq : bInA ? .narrow : aInB ? .widen : .inc
            }
        }
        rels.append(("recipients", pr!))

        rels.append(("required", flip(setRel(AK.arr(o["required"]), AK.arr(n["required"])))))

        var diffRels: [Rel] = [], reasonList: [String] = []
        for (k, r) in rels where r != .eq {
            diffRels.append(r)
            reasonList.append("rules." + k + ": " + r.name)
        }
        reasonList.sort(by: u16less)
        let cls = combine(diffRels)
        return [JKey("class"): .string(cls == .eq ? "equal" : cls.name), JKey("reasons"): AK.strs(reasonList)]
    }
}
