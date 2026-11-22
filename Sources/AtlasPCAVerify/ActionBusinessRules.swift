import Foundation

/// A platform's own business rules for one action (amount ceilings per currency, approval thresholds, caller-scoped records, rate limits,
/// business hours, allowed recipients, required fields). This file holds the rules block validation, the money and time helpers, the digest
/// and the signed rules review; every value is a JSON tree so results compare byte for byte with the reference. A time zone is an IANA zone id known to
/// the runtime (any spelling of case) or an offset (+HH, +HHMM, +HH:MM), as the reference's Intl takes it.
public enum ActionBusinessRules {
    public static let RULE_DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
    public static let RATE_PERIODS: [String: Int64] = ["hour": 3_600_000, "day": 86_400_000]
    public static let MAX_RULE_CURRENCIES = 32
    public static let MAX_RULE_LIST = 64
    public static let MAX_RULE_APPROVERS = 16
    public static let MAX_RULE_EXAMPLES = 32
    public static let BUSINESS_RULES_DOMAIN = "atlas-pca/action-business-rules/v1"
    public static let RULES_REVIEW_DOMAIN = "atlas-pca/action-rules-review/v1"

    private static let CCY = "[A-Z]{3}"
    private static let NAME = "[a-z][a-z0-9_]{0,63}"
    private static let HHMM = "([01][0-9]|2[0-3]):([0-5][0-9])"
    private static let DOMAIN = "(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    private static let ADDRESS = "[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}"
    private static let AT = "([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z"
    private static let TZ = "[A-Za-z0-9_+\\-/]+"
    private static let RULE_KEYS = ["amount", "approval", "scope", "rate", "hours", "recipients", "required", "examples"]

    static func fm(_ pattern: String, _ v: JSONValue?) -> Bool { v?.asString.map { Actions.fullMatch(pattern, $0) } ?? false }
    static func bad(_ msg: String) -> ActionKitError { ActionKitError(code: "bad_rules", message: msg) }
    static func own(_ o: JObject, _ k: String) -> Bool { o[JKey(k)] != nil }
    static func isObj(_ v: JSONValue?) -> Bool { v?.asObject != nil }
    static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    private static func closed(_ o: JObject, _ allowed: [String], _ at: String) throws {
        for k in JS.keyOrder(o) where !allowed.contains(k.s) { throw bad("\(at): unknown member '\(k.s)'") }
    }

    // ---- references and money ----

    /// The parameter a reference names: `{name, p}`. Throws `bad_rules` when it resolves to none or to several.
    public static func resolveParamRef(_ d: JObject, _ r: JSONValue?, _ at: String) throws -> (name: String, p: JSONValue) {
        guard case let .object(rm)? = r else { throw bad("\(at): name a parameter ({param} or {role})") }
        let hasP = rm["param"]?.asString != nil, hasR = rm["role"]?.asString != nil
        if hasP == hasR { throw bad("\(at): give exactly one of param or role") }
        let ps = AK.o(d["params"])
        let verb = JS.toString(d["verb"])
        if hasP {
            let name = rm["param"]!.asString!
            guard let p = JS.present(ps[JKey(name)]) else { throw bad("\(at): '\(verb)' has no parameter '\(name)'") }
            return (name, p)
        }
        var hits: [String] = []
        for (n, v) in ps where v.get("role") == rm["role"] { hits.append(n.s) }
        hits.sort(by: u16less)
        if hits.count != 1 { throw bad("\(at): '\(verb)' has \(hits.isEmpty ? "no" : "several") parameter\(hits.isEmpty ? "" : "s") with role \(JS.toString(rm["role"]))") }
        return (hits[0], ps[JKey(hits[0])] ?? .null)
    }

    /// The money parameters of an action: `{amount, exp, ccy: {literal} | {param}}`.
    public static func moneyOf(_ d: JObject) throws -> JSONValue {
        let ps = AK.o(d["params"])
        let verb = JS.toString(d["verb"])
        var hits: [String] = []
        for (n, v) in ps where v.get("role") == .string("money.amount") { hits.append(n.s) }
        hits.sort(by: u16less)
        if hits.count != 1 { throw bad("'\(verb)' needs exactly one parameter with role money.amount for an amount or approval-above rule (has \(hits.count))") }
        let name = hits[0]
        let p = AK.o(ps[JKey(name)])
        if p["type"] != .string("integer") { throw bad("'\(verb)': the money.amount parameter '\(name)' must be an integer") }
        guard let u = JS.present(p["unit"]), u.get("kind") == .string("money") else { throw bad("'\(verb)': the amount parameter '\(name)' declares no money unit (its currency)") }
        if let c = u.get("ccy")?.asString { return AK.obj(["amount": .string(name), "exp": u.get("exp") ?? .null, "ccy": AK.obj(["literal": .string(c)])]) }
        let from = u.get("ccy")?.get("from")?.asString
        guard let f = from, ps[JKey(f)] != nil else { throw bad("'\(verb)': the currency parameter '\(from ?? "null")' does not exist") }
        return AK.obj(["amount": .string(name), "exp": u.get("exp") ?? .null, "ccy": AK.obj(["param": .string(f)])])
    }

    static func expOf(_ money: JSONValue) throws -> Int {
        guard let e = IV.num(money.get("exp")) else { throw bad("the money unit declares no exponent") }
        return Int(e)
    }

    /// Integer minor units of a money value under exponent `exp`. Throws `bad_rules` for a non-integer or over-precise value.
    public static func minorUnits(_ v: JSONValue?, _ exp: Int, _ at: String) throws -> Int64 {
        if let num = IV.num(v) {
            guard let i = IV.int(v), num >= 0 else { throw bad("\(at): an amount is a non-negative integer of minor units, or a decimal string") }
            return i
        }
        guard let s = v?.asString else { throw bad("\(at): an amount is a number of minor units or a decimal string") }
        // (0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?
        let parts = s.components(separatedBy: ".")
        let ip = parts[0]
        let digits = { (x: String) in x.utf8.allSatisfy { $0 >= 48 && $0 <= 57 } }
        let intOk = !ip.isEmpty && digits(ip) && (ip == "0" || (ip.utf8.first! != 48 && ip.utf8.count <= 15))
        let frac = parts.count == 2 ? parts[1] : ""
        let fracOk = parts.count == 1 || (parts.count == 2 && (1...6).contains(frac.utf8.count) && digits(frac))
        guard parts.count <= 2, intOk, fracOk else { throw bad("\(at): '\(s)' is not a decimal amount") }
        if frac.utf8.count > exp { throw bad("\(at): '\(s)' has more decimals than the currency's \(exp)") }
        let padded = frac + String(repeating: "0", count: max(0, exp - frac.utf8.count))
        let f = padded.isEmpty ? "0" : padded
        let n = Double(ip)! * pow(10.0, Double(exp)) + Double(f)!
        guard n == n.rounded() && abs(n) <= 9007199254740991.0 else { throw bad("\(at): '\(s)' is too large") }
        return Int64(n)
    }

    // ---- time ----

    static func zoneOf(_ tz: String?) -> TimeZone? {
        guard let tz = tz, !tz.isEmpty, tz.utf16.count <= 64, Actions.fullMatch(TZ, tz) else { return nil }
        // an offset spelling (+HH, +HHMM, +HH:MM, hours 00-23) as the reference's Intl takes it
        let u = Array(tz.utf8)
        if (u[0] == 0x2B || u[0] == 0x2D), Actions.fullMatch("[+-]([01][0-9]|2[0-3])(?::?([0-5][0-9]))?", tz) {
            let d = u.dropFirst().filter { $0 != 0x3A }.map { Int($0) - 48 }
            let secs = ((d[0] * 10 + d[1]) * 60 + (d.count > 2 ? d[2] * 10 + d[3] : 0)) * 60
            return TimeZone(secondsFromGMT: u[0] == 0x2D ? -secs : secs)
        }
        let ids = TimeZone.knownTimeZoneIdentifiers
        if ids.contains(tz) { return TimeZone(identifier: tz) }
        if let z = ids.first(where: { $0.lowercased() == tz.lowercased() }) { return TimeZone(identifier: z) }
        return TimeZone(identifier: tz)
    }

    /// Is this a time zone the runtime knows (IANA name)?
    public static func knownTimeZone(_ tz: JSONValue?) -> Bool { zoneOf(tz?.asString) != nil }

    private static func daysFromCivil(_ y0: Int, _ m: Int, _ d: Int) -> Int64 {
        let y = Int64(m <= 2 ? y0 - 1 : y0)
        let era = Int64((Double(y) / 400.0).rounded(.down))
        let yoe = y - era * 400
        let doy = (153 * Int64(m + (m > 2 ? -3 : 9)) + 2) / 5 + Int64(d) - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    /// `Date.parse` of an RFC 3339 UTC time (`...Z`, whole seconds) as the reference engine reads it; NaN when it does not.
    public static func parseUtc(_ s: String) -> Double {
        guard Actions.fullMatch(AT, s) else { return Double.nan }
        let u = Array(s.utf8)
        func n(_ a: Int, _ b: Int) -> Int { Int(String(decoding: u[a..<b], as: UTF8.self))! }
        let y = n(0, 4), mo = n(5, 7), dd = n(8, 10), h = n(11, 13), mi = n(14, 16), se = n(17, 19)
        if mo < 1 || mo > 12 || dd < 1 || dd > 31 || h > 24 || mi > 59 || se > 59 || (h == 24 && (mi != 0 || se != 0)) { return Double.nan }
        let days = daysFromCivil(y, mo, 1) + Int64(dd - 1)
        return Double(days * 86_400_000 + Int64(h) * 3_600_000 + Int64(mi) * 60_000 + Int64(se) * 1000)
    }

    /// `{dow, min}`: the weekday (0 = Sunday) and minute of day at `now` (ms since the epoch) in the zone `tz`; nil for a bad time or zone.
    public static func clockAt(_ now: Double, _ tz: String?) -> JSONValue? {
        if now.isNaN || now.isInfinite || abs(now) > 8.64e15 { return nil }
        guard let z = zoneOf(tz) else { return nil }
        let ms = Int64(now)
        let local = ms + Int64(z.secondsFromGMT(for: Date(timeIntervalSince1970: Double(ms) / 1000.0))) * 1000
        func floorDiv(_ a: Int64, _ b: Int64) -> Int64 { a >= 0 ? a / b : -((-a + b - 1) / b) }
        func floorMod(_ a: Int64, _ b: Int64) -> Int64 { a - floorDiv(a, b) * b }
        let days = floorDiv(local, 86_400_000)
        return AK.obj(["dow": .int(floorMod(days + 4, 7)), "min": .int(floorMod(local, 86_400_000) / 60_000)])
    }

    public static func formatMoney(_ minor: Int64, _ ccy: String, _ exp: Int) -> String {
        var s = String(minor)
        while s.count < exp + 1 { s = "0" + s }
        let body = exp > 0 ? String(s.dropLast(exp)) + "." + String(s.suffix(exp)) : s
        return body + " " + ccy
    }

    // ---- validation ----

    /// Nil iff `rules` is a well-formed rules block for `d`; the reason otherwise.
    public static func businessRulesError(_ d: JObject, _ rules: JSONValue?) -> String? {
        do { try validateRules(d, rules); return nil }
        catch let e as ActionKitError { return e.message }
        catch { return "\(error)" }
    }

    private static func ccyMap(_ d: JObject, _ m: JSONValue?, _ at: String) throws {
        guard case let .object(o)? = m, !o.isEmpty, o.count <= MAX_RULE_CURRENCIES else { throw bad("\(at): a map of 1..\(MAX_RULE_CURRENCIES) currencies to amounts") }
        let money = try moneyOf(d)
        for k in JS.keyOrder(o) {
            if !Actions.fullMatch(CCY, k.s) { throw bad("\(at): '\(k.s)' is not an ISO 4217 currency code") }
            _ = try minorUnits(o[k], try expOf(money), "\(at).\(k.s)")
        }
    }

    static func refOf(_ s: JObject) -> JSONValue {
        var r: JObject = [:]
        if let p = s["param"] { r["param"] = p }
        if let p = s["role"] { r["role"] = p }
        return .object(r)
    }

    private static func distinct(_ xs: [JSONValue]) -> Bool { var seen: [JSONValue] = []; for x in xs { if seen.contains(x) { return false }; seen.append(x) }; return true }

    private static func listOfRe(_ v: JSONValue?, _ re: String) -> Bool {
        guard case let .array(a)? = v, !a.isEmpty, a.count <= MAX_RULE_LIST else { return false }
        return a.allSatisfy { fm(re, $0) }
    }

    static func validateRules(_ d: JObject, _ rules: JSONValue?) throws {
        guard case let .object(r)? = rules else { throw bad("rules must be an object") }
        try closed(r, RULE_KEYS, "rules")
        if r.keys.filter({ $0.s != "examples" }).isEmpty { throw bad("rules: name at least one rule") }
        if own(r, "amount") {
            guard case let .object(am)? = r["amount"] else { throw bad("rules.amount must be {max: {CCY: amount}}") }
            try closed(am, ["max"], "rules.amount")
            try ccyMap(d, am["max"], "rules.amount.max")
        }
        if own(r, "approval") {
            guard case let .object(ap)? = r["approval"] else { throw bad("rules.approval must be an object") }
            try closed(ap, ["above", "always", "approvers", "group"], "rules.approval")
            if own(ap, "always") && ap["always"] != .bool(true) { throw bad("rules.approval.always is true or absent") }
            if !own(ap, "above") == !own(ap, "always") { throw bad("rules.approval: give exactly one of above or always") }
            if own(ap, "above") { try ccyMap(d, ap["above"], "rules.approval.above") }
            if own(ap, "approvers") { guard let n = IV.int(ap["approvers"]), n >= 1, n <= Int64(MAX_RULE_APPROVERS) else { throw bad("rules.approval.approvers is 1..\(MAX_RULE_APPROVERS)") } }
            if own(ap, "group") && !fm(NAME, ap["group"]) { throw bad("rules.approval.group is a lowercase name") }
        }
        if own(r, "scope") {
            guard case let .array(sc)? = r["scope"], !sc.isEmpty, sc.count <= MAX_RULE_LIST else { throw bad("rules.scope is a list of 1..\(MAX_RULE_LIST) bindings") }
            for (i, s0) in sc.enumerated() {
                let at = "rules.scope[\(i)]"
                guard case let .object(s) = s0 else { throw bad("\(at) must be an object") }
                try closed(s, ["param", "role", "caller"], at)
                let p = try resolveParamRef(d, refOf(s), at).p
                let ty = p.get("type")
                if ty != .string("string") && ty != .string("integer") { throw bad("\(at): the bound parameter must be a string or integer id") }
                if !fm(NAME, s["caller"]) { throw bad("\(at).caller is a lowercase attribute name of the caller") }
            }
        }
        if own(r, "rate") {
            guard case let .array(rt)? = r["rate"], !rt.isEmpty, rt.count <= 4 else { throw bad("rules.rate is a list of 1..4 limits") }
            for (i, x0) in rt.enumerated() {
                let at = "rules.rate[\(i)]"
                guard case let .object(x) = x0 else { throw bad("\(at) must be an object") }
                try closed(x, ["max", "per", "by"], at)
                guard let mx = IV.int(x["max"]), mx >= 1, mx <= 1_000_000 else { throw bad("\(at).max is 1..1000000") }
                if RATE_PERIODS[JS.toString(x["per"])] == nil { throw bad("\(at).per is hour or day") }
                if own(x, "by") && x["by"] != .string("principal") && x["by"] != .string("org") { throw bad("\(at).by is principal or org") }
            }
        }
        if own(r, "hours") {
            guard case let .object(h)? = r["hours"] else { throw bad("rules.hours must be an object") }
            try closed(h, ["days", "from", "to", "tz", "outside"], "rules.hours")
            var daysOk = false
            if case let .array(days)? = h["days"], !days.isEmpty, distinct(days) { daysOk = days.allSatisfy { $0.asString.map { RULE_DAYS.contains($0) } ?? false } }
            if !daysOk { throw bad("rules.hours.days is a list of distinct days (" + RULE_DAYS.joined(separator: ", ") + ")") }
            if !fm(HHMM, h["from"]) || !fm(HHMM, h["to"]) { throw bad("rules.hours.from and .to are HH:MM (24 h)") }
            if !knownTimeZone(h["tz"]) { throw bad("rules.hours.tz '\(JS.toString(h["tz"]))' is not a known IANA time zone") }
            if own(h, "outside") && h["outside"] != .string("escalate") && h["outside"] != .string("deny") { throw bad("rules.hours.outside is escalate or deny") }
        }
        if own(r, "recipients") {
            guard case let .object(x)? = r["recipients"] else { throw bad("rules.recipients must be an object") }
            try closed(x, ["param", "role", "domains", "addresses"], "rules.recipients")
            let res = try resolveParamRef(d, refOf(x), "rules.recipients")
            let p = AK.o(res.p)
            let ty = p["type"]
            if ty == .string("array") || ty == .string("set") {
                if own(p, "items") && p["items"] != .string("string") { throw bad("rules.recipients: '\(res.name)' must hold strings") }
                guard let mi = IV.int(p["max_items"]), mi <= Int64(MAX_RULE_LIST) else { throw bad("rules.recipients: the list parameter '\(res.name)' needs max_items <= \(MAX_RULE_LIST) so every entry can be checked") }
            } else if ty != .string("string") { throw bad("rules.recipients: '\(res.name)' must be a string or a bounded list of strings") }
            if !own(x, "domains") && !own(x, "addresses") { throw bad("rules.recipients: give domains and/or addresses") }
            if own(x, "domains") && !listOfRe(x["domains"], DOMAIN) { throw bad("rules.recipients.domains is a list of lowercase domain names") }
            if own(x, "addresses") && !listOfRe(x["addresses"], ADDRESS) { throw bad("rules.recipients.addresses is a list of lowercase email addresses") }
        }
        if own(r, "required") {
            guard case let .array(rq)? = r["required"], !rq.isEmpty, rq.count <= MAX_RULE_LIST, distinct(rq) else { throw bad("rules.required is a list of distinct parameter names") }
            let ps = AK.o(d["params"])
            for n in rq { guard let s = n.asString, ps[JKey(s)] != nil else { throw bad("rules.required: '\(JS.toString(d["verb"]))' has no parameter '\(JS.toString(n))'") } }
        }
        if own(r, "examples") {
            guard case let .array(ex)? = r["examples"], ex.count <= MAX_RULE_EXAMPLES else { throw bad("rules.examples is a list of at most \(MAX_RULE_EXAMPLES)") }
            for (i, e0) in ex.enumerated() {
                let at = "rules.examples[\(i)]"
                guard case let .object(e) = e0 else { throw bad("\(at) must be an object") }
                try closed(e, ["params", "caller", "at", "recent", "expect"], at)
                if !isObj(e["params"]) { throw bad("\(at).params must be an object") }
                if own(e, "caller") && !isObj(e["caller"]) { throw bad("\(at).caller must be an object") }
                if own(e, "at") { guard let s = e["at"]?.asString, !parseUtc(s).isNaN else { throw bad("\(at).at is an RFC 3339 UTC time (…Z)") } }
                if own(e, "recent") {
                    var ok = false
                    if case let .object(rc)? = e["recent"] { ok = rc.values.allSatisfy { (IV.int($0) ?? -1) >= 0 } }
                    if !ok { throw bad("\(at).recent maps rate indexes to counts") }
                }
                if !(["allow", "escalate", "deny"].contains(e["expect"]?.asString ?? "")) { throw bad("\(at).expect is allow, escalate or deny") }
            }
        }
    }

    // ---- digest and signed review ----

    /// Digest of a rules block (examples are tests, not rules).
    public static func businessRulesDigest(_ verb: String, _ rules: JObject) throws -> String {
        var body = rules
        body[JKey("examples")] = nil
        guard let h = IV.strictHash(AK.obj(["d": .string(BUSINESS_RULES_DOMAIN), "verb": .string(verb), "rules": .object(body)])) else { throw bad("the rules are outside the strict JSON profile") }
        return h
    }

    public static func rulesReviewMessage(_ b: JObject) throws -> [UInt8] {
        let body = AK.obj(["verb": b["verb"] ?? .null, "def_digest": b["def_digest"] ?? .null, "rules_digest": b["rules_digest"] ?? .null, "reviewer_kid": b["reviewer_kid"] ?? .null, "ts": b["ts"] ?? .null])
        guard let m = IV.message(RULES_REVIEW_DOMAIN + "\u{0}", body) else { throw bad("the review is outside the strict JSON profile") }
        return m
    }

    public static func signRulesReview(_ b: JObject, _ key: PCAEdKey) throws -> JSONValue {
        var out = b
        out["sig"] = .string(Base64URLStrict.encode(try key.sign(try rulesReviewMessage(b))))
        return .object(out)
    }

    public static func rulesReviewError(_ r: JSONValue?, _ d: JObject, _ rules: JObject, _ pins: JSONValue?) -> String? {
        guard let pins = pins else { return "no reviewer keys are pinned" } // only an absent value: a null is a malformed pin set
        if let pe = Actions.reviewerPinsError(pins) { return "bad pins: \(pe)" }
        guard case let .object(x)? = r else { return "no rules review" }
        if d["verb"] != x["verb"] { return "the rules review names another action" }
        // the reference's try / catch: a def with no digest is a malformed review with the thrown message
        let digest: String
        do { digest = try Actions.defDigest(d) } catch { return "malformed rules review: \((error as? JSError)?.message ?? "\(error)")" }
        if .string(digest) != x["def_digest"] ?? .null { return "the rules review covers another version of the action" }
        guard let verb = d["verb"]?.asString, let rd = try? businessRulesDigest(verb, rules), x["rules_digest"] == .string(rd) else { return "the rules review covers other rules" }
        guard let sig = x["sig"]?.asString, let kid = x["reviewer_kid"]?.asString, let tsI = IV.int(x["ts"]) else { return "malformed rules review" }
        guard let key = AK.arr(pins.get("keys")).first(where: { $0.get("kid") == .string(kid) }) else { return "no pinned key '\(kid)'" }
        if !AK.arr(key.get("roles")).contains(.string("reviewer")) { return "key '\(JS.toString(key.get("kid")))' does not hold the reviewer role" }
        let ts = Double(tsI)
        if let nb = IV.num(key.get("not_before")), ts < nb { return "the review time is outside the key validity" }
        if let na = IV.num(key.get("not_after")), ts > na { return "the review time is outside the key validity" }
        var body = x
        body[JKey("sig")] = nil
        guard let pk = key.get("pk")?.asString, let msg = try? rulesReviewMessage(body), Ed25519Strict.verifyB64u(pk, msg, sig) else { return "the rules review signature is invalid" }
        return nil
    }
}
