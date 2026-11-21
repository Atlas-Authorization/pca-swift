import Foundation

/// The trusted question card and agent-initiated clarification of the wallet (the PCA Intent Layer v2): a deterministic render from the
/// wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement and a closed-enum
/// reason (no field for agent-authored text), its digest, the "Partly..." and typed-value checks, and the structured clarification
/// request with max-information cell selection. A port of the TypeScript reference (@atlasauth/pca-wallet).
///
/// The card input is a `JSONValue` object with the reference's member names (verb, coords, site, statementText, reversibility, units,
/// action, friction, kind, reason, locale, catalog); the outcome space is passed separately.
public enum PCAWalletCard {
    public static let CARD_DOMAIN = "atlas-pca/intent-card/v2"
    public static let CLARIFY_REASONS = ["ambiguous_parameter", "multiple_options", "price_changed", "constraint_conflict", "missing_value", "other"]
    public static let REASON_LABELS: [String: String] = [
        "ambiguous_parameter": "Your agent found a detail your request did not settle.",
        "multiple_options": "Your agent found several options that match.",
        "price_changed": "Your agent found that a price changed.",
        "constraint_conflict": "Your agent found that two parts of your request conflict.",
        "missing_value": "Your agent needs a value your request did not give.",
        "other": "Your agent needs a decision before it continues.",
    ]
    public static let MAX_CANDIDATES = 8
    static let MAX_VALUES = 64
    static let MAX_STRING = 256

    // ---- text ----

    /// Strip control characters, collapse whitespace, cap length (for the principal's own words and the site's name). Throws for a
    /// non-string (the reference calls a string method on it).
    public static func cleanText(_ s: JSONValue?, _ mx: Int) throws -> String {
        guard let str = s?.asString else { throw JSError("s.replace is not a function") }
        return cleanText(str, mx)
    }

    static func isControl(_ v: UInt32) -> Bool {
        v <= 0x1f || (v >= 0x7f && v <= 0x9f) || (v >= 0x200b && v <= 0x200f) || (v >= 0x2028 && v <= 0x202e) || (v >= 0x2066 && v <= 0x2069)
    }

    static func cleanText(_ s: String, _ mx: Int) -> String {
        var out: [Unicode.Scalar] = []
        var inSpace = false
        for u in s.unicodeScalars {
            let sp = isControl(u.value) || Attest.isJSSpace(u)
            if sp { if !inSpace { out.append(" ") }; inSpace = true } else { out.append(u); inSpace = false }
        }
        while let f = out.first, Attest.isJSSpace(f) { out.removeFirst() }
        while let l = out.last, Attest.isJSSpace(l) { out.removeLast() }
        let t = IV.text(out)
        return t.utf16.count <= mx ? t : WJ.u16slice(t, 0, mx - 1) + "\u{2026}"
    }

    /// The last four letters/digits of a string (all a card ever shows of a string the outcome space does not name).
    public static func last4(_ s: String) -> String {
        let kept = s.unicodeScalars.filter { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) }
        return IV.text(kept.suffix(4)).uppercased()
    }

    static func group(_ digits: String) -> String {
        let d = Array(digits)
        var out = ""
        for (i, c) in d.enumerated() {
            if i > 0 && (d.count - i) % 3 == 0 { out.append(",") }
            out.append(c)
        }
        return out
    }

    static let CURRENCY_SYMBOL: [String: String] = ["USD": "$", "EUR": "\u{20AC}", "GBP": "\u{A3}", "JPY": "\u{A5}"]

    static func isMoney(_ unit: JSONValue?) -> Bool { WJ.isStr(unit?.get("kind"), "money") }

    /// Math.max(0, Math.min(6, Math.floor(unit.exponent))); nil for NaN (the reference computes with NaN).
    static func exponent(_ unit: JSONValue?) -> Int? {
        let e = JS.toNumber(unit?.get("exponent"))
        if e.isNaN { return nil }
        if e.isInfinite { return e > 0 ? 6 : 0 }
        return Int(max(0, min(6, e.rounded(.down))))
    }

    static func symbol(_ unit: JSONValue?) -> String {
        if let c = unit?.get("currency")?.asString, let s = CURRENCY_SYMBOL[c] { return s }
        return JS.toString(unit?.get("currency")) + " "
    }

    static func pow10(_ e: Int) -> Int64 { (0..<e).reduce(Int64(1)) { r, _ in r * 10 } }

    /// Thousands grouping with commas, independent of any locale data (cards render identically anywhere).
    public static func formatNumber(_ xv: JSONValue?, _ unit: JSONValue? = nil) throws -> String {
        guard let x = IV.num(xv), x.isFinite, abs(x.rounded(.towardZero)) < 9.2e18 else { throw JSError("formatNumber: not a finite number") }
        let neg = x < 0
        let a = Int64(abs(x.rounded(.towardZero)))
        if isMoney(unit) {
            guard let e = exponent(unit) else { return (neg ? "-" : "") + symbol(unit) + "NaN" }
            let div = pow10(e)
            let whole = group(String(a / div))
            var frac = ""
            if e > 0 {
                let r = String(a % div)
                frac = "." + String(repeating: "0", count: max(0, e - r.count)) + r
            }
            return (neg ? "-" : "") + symbol(unit) + whole + frac
        }
        return (neg ? "-" : "") + group(String(a))
    }

    // ---- the card ----

    static func accId(_ path: String, _ prefix: String, _ suffix: String) -> String? {
        let u = Array(path.unicodeScalars)
        let p = prefix.unicodeScalars.count, s = suffix.unicodeScalars.count
        guard IV.startsWith(path, prefix), IV.endsWith(path, suffix), u.count > p + s else { return nil }
        let mid = u[p..<(u.count - s)]
        guard mid.allSatisfy({ ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0.value == 95 || $0.value == 46 || $0.value == 45 }) else { return nil }
        return IV.text(mid)
    }

    static func spaced(_ s: String) -> String { s.replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: ".", with: " ") }

    static func dimLabel(_ path: String) -> String {
        if let m = accId(path, "env.acc.", ".post") { return "\(spaced(m)) (running total for this task)" }
        if let m = accId(path, "env.world.", "") { return "\(spaced(m)) (from a signed fact)" }
        if let m = accId(path, "env.mon.", ".state") { return "state of \(spaced(m))" }
        return WalletOmegaMath.labelOf(path)
    }

    public static func isProvPath(_ p: String) -> Bool { IV.startsWith(p, "env.prov.") }

    static func numFact(_ d: WalletDim, _ ids: [Int], _ unit: JSONValue?, _ actionValue: JSONValue?) throws -> String {
        let cells = WalletOmegaMath.numCells(d)
        let lo = cells[ids[0]].lo
        let hi = cells[ids[ids.count - 1]].hi
        let f = { (n: Int) in try formatNumber(WJ.i(n), unit) }
        let range: String
        if lo == hi { range = "exactly \(try f(lo))" }
        else if lo == d.lo && hi == d.hi { range = "any value" }
        else if hi == d.hi { range = "\(try f(lo)) or more" }
        else if lo == d.lo { range = "up to \(try f(hi))" }
        else { range = "\(try f(lo)) \u{2013} \(try f(hi))" }
        var ex = ""
        if WJ.isFiniteNumber(actionValue) { ex = " (this action: " + (try formatNumber(actionValue, unit)) + ")" }
        return range + ex
    }

    static func catValueText(_ d: WalletDim, _ i: Int) -> String {
        let v = d.values[i]
        if v.kind == "exact" { return "\"\(cleanText(v.value, 64))\"" }
        if v.kind == "prefix" { return "anything starting with \"\(cleanText(v.value, 64))\"" }
        return "a value not named in your request"
    }

    static func catFact(_ d: WalletDim, _ ids: [Int], _ actionValue: JSONValue?) -> String {
        let parts = ids.map { catValueText(d, $0) }
        let set = parts.count == 1 ? parts[0] : "\(parts.dropLast().joined(separator: ", ")) or \(parts.last ?? "undefined")"
        guard let av = actionValue?.asString else { return set }
        let named = d.values.contains { $0.kind == "exact" && IV.same($0.value, av) }
        let tail = named ? "\"" + cleanText(av, 64) + "\"" : "a value ending in \"" + last4(av) + "\""
        return set + " (this action: " + tail + ")"
    }

    static func bannerFor(_ path: String, _ levels: [JSONValue]) throws -> String? {
        let w = try PCAWallet.worstProvenance(.array(levels))
        let label = dimLabel(path)
        if w == "web" { return "This \(label) was suggested by content on a web page, not by you." }
        if w == "tool" { return "This \(label) came from a tool result, not from you." }
        if w == "agent" { return "This \(label) was chosen by your agent, not taken from your request or from the site." }
        return nil
    }

    public static func provLevels(_ d: WalletDim, _ ids: [Int]) -> [JSONValue] {
        ids.flatMap { i in d.values[i].value.unicodeScalars.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "|" || $0 == "," }).map { JSONValue.string(IV.text($0)) } }
    }

    /// `action.values[path]` for an action that may be any JSON: a missing or null `values` throws, a non-object has no members.
    static func vget(_ action: JSONValue?, _ path: String) throws -> JSONValue? {
        guard let values = action?.get("values"), values != .null else { throw JSError("Cannot read properties of undefined") }
        return values.get(path)
    }

    static func typedTarget(_ vs: WalletVerb, _ action: JSONValue?, _ units: JSONValue?) throws -> JSONValue? {
        guard let action = action, JS.truthy(action) else { return nil }
        let dims = vs.dims.filter { !isProvPath($0.path) }
        var nums: [WalletDim] = []
        for d in dims where d.isNum { if WJ.isNumber(try vget(action, d.path)) { nums.append(d) } }
        let money = nums.first { isMoney(units?.get($0.path)) }
        if let pick = money ?? nums.first {
            return WJ.obj([("path", .string(pick.path)), ("mode", .string("number")),
                           ("prompt", .string("To allow it, type the \(dimLabel(pick.path)) of this action shown above."))])
        }
        for d in dims where !d.isNum {
            if let s = try vget(action, d.path)?.asString, last4(s).unicodeScalars.count == 4 {
                return WJ.obj([("path", .string(d.path)), ("mode", .string("last4")),
                               ("prompt", .string("To allow it, type the last 4 letters or digits of the \(dimLabel(d.path))."))])
            }
        }
        return nil
    }

    static func answers(_ friction: JSONValue?) -> JSONValue? {
        let key: String?
        if let s = friction?.asString { key = s }
        else if let a = friction?.asArray, a.count == 1, let s = a[0].asString { key = s }
        else { key = nil }
        func ans(_ yes: String) -> JSONValue {
            .array([WJ.obj([("id", .string("no")), ("label", .string("No"))]), WJ.obj([("id", .string("partly")), ("label", .string("Partly\u{2026}"))]),
                    WJ.obj([("id", .string("yes")), ("label", .string(yes))])])
        }
        switch key {
        case "tap"?: return ans("Yes")
        case "hold"?: return ans("Press and hold to allow")
        case "typed"?: return ans("Yes, type the value to confirm")
        case "device"?: return ans("Yes, confirm with your security key")
        default: return nil
        }
    }

    static func lowerFirst(_ s: String) -> String {
        guard let f = s.unicodeScalars.first, ![0x0A, 0x0D, 0x2028, 0x2029].contains(f.value) else { return s }
        return String(f).lowercased() + String(s.unicodeScalars.dropFirst())
    }

    /// Render the trusted question card: `.success(card)` or `.failure(reason)`; a value the reference throws on throws.
    public static func renderCard(_ omega: WalletOmega, _ inp: JSONValue?) throws -> Result<JSONValue, WalletRefusal> {
        guard let inp = inp, inp.isObject else { throw JSError("Cannot read properties of undefined") }
        let loc = JS.present(inp.get("locale")) ?? .string("en")
        if !WJ.isStr(loc, "en") { return .failure(WalletRefusal("unsupported locale \(JS.toString(inp.get("locale")))")) }
        let kind = inp.get("kind")
        let reason = inp.get("reason")
        if WJ.isStr(kind, "clarification") && reason == nil { return .failure(WalletRefusal("a clarification card needs a reason")) }
        if let r = reason, !(r.asString.map { IV.contains(CLARIFY_REASONS, $0) } ?? false) { return .failure(WalletRefusal("unknown clarification reason")) }
        let verb = inp.get("verb")
        let r: PCAWallet.Resolved
        switch try PCAWallet.resolveCoords(omega, verb, inp.get("coords")) {
        case let .failure(f): return .failure(f)
        case let .success(x): r = x
        }
        let vs = r.vs, box = r.box
        let action = inp.get("action")
        if let a = action, JS.truthy(a) {
            let av = a.get("verb")
            if av == nil || verb == nil || av! != verb! { return .failure(WalletRefusal("the action is for another verb")) }
        }
        if let c = JS.present(inp.get("catalog")) { _ = c; throw JSError("catalog.get is not a function") }
        let site = inp.get("site")
        guard let siteObj = site?.asObject else { throw JSError("Cannot read properties of undefined (reading 'name')") }
        _ = siteObj
        var siteName = try cleanText(site?.get("name"), 64)
        if siteName.isEmpty { siteName = try cleanText(site?.get("origin"), 64) }
        var said = ""
        if inp.get("statementText") != nil { said = try cleanText(inp.get("statementText"), 280) }
        let header: String
        if WJ.isStr(kind, "clarification") { header = said.isEmpty ? "Your agent needs a decision" : "Your agent needs a decision for your request \"\(said)\"" }
        else { header = said.isEmpty ? "\(siteName) asks for your confirmation" : "\(siteName) asks on behalf of your request \"\(said)\"" }
        let verbName = verb?.asString ?? ""
        let what: String
        if let spec = PCACatalog.builtin.last(where: { IV.same($0.verb, verbName) }) {
            var d = spec.description
            if d.hasSuffix(".") { d.removeLast() }
            what = lowerFirst(d)
        } else { what = "the action \"\(cleanText(verbName, 64))\" on \(siteName)" }
        let rev = JS.present(inp.get("reversibility")) ?? .string(vs.reversibility)
        let revText = ["reversible": "that can be undone", "rate_limited": "that is rate-limited", "irreversible": "that cannot be undone"]
        let sentence = "Allow \(what), \(rev.asString.flatMap { revText[$0] } ?? "undefined"), with:"
        let units = inp.get("units")
        var facts: [JSONValue] = [], banners: [JSONValue] = [], partial: [JSONValue] = []
        for (k, d) in vs.dims.enumerated() {
            let ids = box[k]
            if isProvPath(d.path) {
                if d.isNum { continue }
                if let b = try bannerFor(IV.dropPrefix(d.path, 9), provLevels(d, ids)) { banners.append(.string(b)) }
                continue
            }
            var av: JSONValue?
            if let a = action, a != .null { av = try vget(a, d.path) }
            let unit = units?.asObject != nil ? units?.get(d.path) : nil
            if d.isNum {
                facts.append(WJ.obj([("key", .string(d.path)), ("label", .string(dimLabel(d.path))), ("text", .string(try numFact(d, ids, unit, av)))]))
                let cells = WalletOmegaMath.numCells(d)
                partial.append(WJ.obj([("path", .string(d.path)), ("kind", .string("num")), ("lo", WJ.i(cells[ids[0]].lo)), ("hi", WJ.i(cells[ids[ids.count - 1]].hi))]))
            } else {
                facts.append(WJ.obj([("key", .string(d.path)), ("label", .string(dimLabel(d.path))), ("text", .string(catFact(d, ids, av)))]))
                let options = ids.map { d.values[$0] }.filter { $0.kind == "exact" }.map { JSONValue.string($0.value) }
                if options.count > 1 { partial.append(WJ.obj([("path", .string(d.path)), ("kind", .string("cat")), ("options", .array(options))])) }
            }
        }
        let friction = inp.get("friction")
        var typed: JSONValue?
        if PCAWallet.frictionRank(friction) >= PCAWallet.frictionRank(.string("typed")) { typed = try typedTarget(vs, action, units) }
        var body = JObject()
        body["v"] = .int(2)
        if let k = kind { body["kind"] = k }
        body["verb"] = verb ?? .null
        body["coords"] = WJ.plain(inp.get("coords") ?? .null)
        body["locale"] = .string("en")
        body["site"] = WJ.obj([("origin", .string(try cleanText(site?.get("origin"), 256))), ("name", .string(siteName))])
        body["header"] = .string(header)
        if let rs = reason?.asString, let label = REASON_LABELS[rs] { body["reason_label"] = .string(label) }
        body["sentence"] = .string(sentence)
        body["facts"] = .array(facts)
        body["banners"] = .array(banners)
        if let f = friction { body["friction"] = f }
        if let a = answers(friction) { body["answers"] = a }
        if let t = typed { body["typed"] = t }
        body["partial"] = .array(partial)
        var out = body
        out["rendered_digest"] = .string(try cardDigest(.object(body)))
        return .success(.object(out))
    }

    /// The content address of a card body (everything but `rendered_digest`).
    public static func cardDigest(_ body: JSONValue?) throws -> String {
        guard let b = body else { throw JSError("canonicalize: undefined") }
        return try WJ.hash(WJ.obj([("d", .string(CARD_DOMAIN)), ("c", WJ.plain(b))]))
    }

    /// Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed.
    public static func cardDigestMatches(_ card: JSONValue?) throws -> Bool {
        guard case let .object(c)? = card else { throw JSError("Cannot destructure") }
        var body = c
        body["rendered_digest"] = nil
        guard let want = c["rendered_digest"]?.asString else { _ = try cardDigest(.object(body)); return false }
        return IV.same(try cardDigest(.object(body)), want)
    }

    /// The plain text of a card, line by line (what a screen reader or a text channel shows).
    public static func cardText(_ card: JSONValue?) throws -> String {
        func joined(_ v: JSONValue?) -> String { (v == nil || v == .null) ? "" : JS.toString(v) }
        guard let card = card, card.isObject else { throw JSError("Cannot read properties of undefined") }
        var lines = [joined(card.get("header"))]
        if JS.truthy(card.get("reason_label")) { lines.append(joined(card.get("reason_label"))) }
        lines.append(joined(card.get("sentence")))
        guard let facts = card.get("facts")?.asArray else { throw JSError("card.facts.map is not a function") }
        for f in facts { lines.append("- \(JS.toString(f.get("label"))): \(JS.toString(f.get("text")))") }
        guard let banners = card.get("banners")?.asArray else { throw JSError("card.banners is not iterable") }
        lines.append(contentsOf: banners.map { joined($0) })
        if JS.truthy(card.get("typed")) { lines.append(joined(card.get("typed")?.get("prompt"))) }
        guard let answers = card.get("answers")?.asArray else { throw JSError("card.answers.map is not a function") }
        lines.append(answers.map { "[\(JS.toString($0.get("label")))]" }.joined(separator: " "))
        return lines.joined(separator: "\n")
    }

    // ---- responses ----

    static func inRange(_ x: JSONValue, _ lo: Double, _ hi: Double) -> Bool {
        guard let n = IV.num(x), n.isFinite, n.rounded(.towardZero) == n, !IV.isNegZero(n) else { return false }
        return n >= lo && n <= hi
    }

    /// Validate a "Partly..." answer against the card: a structured restriction of the shown ranges and values only.
    public static func partialError(_ card: JSONValue?, _ p: JSONValue?) throws -> String? {
        guard let slots = card?.get("partial")?.asArray else { throw JSError("card.partial.find is not a function") }
        guard p != nil, p != .null else { throw JSError("Cannot read properties of undefined (reading 'path')") }
        let path = p?.get("path")
        let ps = path?.asString
        guard let slot = slots.first(where: { ps != nil && WJ.isStr($0.get("path"), ps!) }) else {
            return "the card has no field \(JS.toString(path))"
        }
        guard case let .object(po)? = p else { throw JSError("Cannot use 'in' operator") }
        if WJ.isStr(slot.get("kind"), "num") {
            let lo = IV.num(slot.get("lo")) ?? .nan, hi = IV.num(slot.get("hi")) ?? .nan
            let ilo = lo.isFinite ? Int(lo) : 0, ihi = hi.isFinite ? Int(hi) : 0
            if let u = po["upTo"] {
                return inRange(u, lo, hi) && IV.num(u)! < hi ? nil : "upTo must be an integer in [\(ilo), \(ihi - 1)]"
            }
            if let f = po["from"] {
                return inRange(f, lo, hi) && IV.num(f)! > lo ? nil : "from must be an integer in [\(ilo + 1), \(ihi)]"
            }
            if let e = po["except"] {
                switch e {
                case .null: throw JSError("Cannot read properties of null (reading 'length')")
                case let .array(a): return !a.isEmpty && a.allSatisfy({ inRange($0, lo, hi) }) ? nil : "except values must be integers in [\(ilo), \(ihi)]"
                case let .string(s):
                    if s.isEmpty { return "except values must be integers in [\(ilo), \(ihi)]" }
                    throw JSError("p.except.every is not a function")
                default: return "except values must be integers in [\(ilo), \(ihi)]"
                }
            }
            return "a numeric partly answer needs upTo, from or except"
        }
        guard let nf = po["notFor"] else { return "a categorical partly answer needs notFor" }
        var vals: [JSONValue] = []
        for v in try JS.spread(nf) where !vals.contains(where: { $0 == v }) { vals.append(v) }
        let options = slot.get("options")?.asArray ?? []
        if vals.isEmpty || !vals.allSatisfy({ v in options.contains(where: { IV.same($0.asString, v.asString) }) && v.asString != nil }) { return "notFor must name values shown on the card" }
        if vals.count == options.count { return "excluding every value is a \"No\"" }
        return nil
    }

    static func isTypedStrip(_ u: Unicode.Scalar) -> Bool { Attest.isJSSpace(u) || ",$\u{20AC}\u{A3}\u{A5}".unicodeScalars.contains(u) }

    /// Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money).
    public static func normalizeTyped(_ input: JSONValue?, _ mode: JSONValue?, _ unit: JSONValue? = nil) throws -> String? {
        guard let s = input?.asString else { throw JSError("input.replace is not a function") }
        if WJ.isStr(mode, "last4") {
            let t = s.unicodeScalars.filter { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) }
            let u = IV.text(t).uppercased()
            return u.unicodeScalars.count == 4 ? u : nil
        }
        var t = Array(s.unicodeScalars.filter { !isTypedStrip($0) })
        // replace(/^[A-Z]{3}/i, '')
        if t.count >= 3, t[0..<3].allSatisfy({ ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) }) { t.removeFirst(3) }
        var i = 0
        var neg = false
        if i < t.count, t[i] == "-" { neg = true; i += 1 }
        let ds = i
        while i < t.count, t[i].value >= 48 && t[i].value <= 57 { i += 1 }
        let whole = t[ds..<i]
        if whole.isEmpty { return nil }
        var frac: [Unicode.Scalar] = []
        if i < t.count, t[i] == "." {
            i += 1
            let fs = i
            while i < t.count, t[i].value >= 48 && t[i].value <= 57 { i += 1 }
            if i == fs { return nil }
            frac = Array(t[fs..<i])
        }
        if i != t.count { return nil }
        var e = 0
        if isMoney(unit) {
            guard let x = exponent(unit) else { throw JSError("The number NaN cannot be converted to a BigInt") }
            e = x
        }
        if frac.count > e { return nil }
        var minor = IV.text(whole) + IV.text(frac) + String(repeating: "0", count: e - frac.count)
        while minor.count > 1 && minor.hasPrefix("0") { minor.removeFirst() }
        return (neg && minor != "0" ? "-" : "") + minor
    }

    /// The normalized value the human must type for this card and action (what a site or auditor recomputes).
    public static func expectedTyped(_ card: JSONValue?, _ action: JSONValue?) throws -> String? {
        guard let typed = card?.get("typed"), JS.truthy(typed) else { return nil }
        guard let values = action?.get("values"), values != .null else { throw JSError("Cannot read properties of undefined") }
        let v = values.get(typed.get("path")?.asString ?? "")
        if WJ.isStr(typed.get("mode"), "last4") { if let s = v?.asString, last4(s).unicodeScalars.count == 4 { return last4(s) }; return nil }
        if let n = IV.safe(v), !IV.isNegZero(n) { return String(Int64(n)) }
        return nil
    }

    // ---- agent-initiated clarification (clarify.ts) ----

    static func isPath(_ s: String) -> Bool {
        let segs = s.unicodeScalars.split(separator: ".", omittingEmptySubsequences: false)
        func word<S: Collection>(_ x: S) -> Bool where S.Element == Unicode.Scalar {
            !x.isEmpty && x.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0.value == 95 }
        }
        guard let first = segs.first, let f = first.first, (f.value >= 65 && f.value <= 90) || (f.value >= 97 && f.value <= 122), word(first) else { return false }
        return segs.dropFirst().allSatisfy { word($0) }
    }

    /// Strict parse of a clarification body: `{ok: true, request}` or `{ok: false, error}`. Never throws.
    public static func parseClarifyRequest(_ body: JSONValue?) -> JSONValue {
        func fail(_ e: String) -> JSONValue { WJ.obj([("ok", .bool(false)), ("error", .string(e))]) }
        guard case let .object(b)? = body else { return fail("body must be an object") }
        for k in PCAWallet.keysOf(b) where k != "candidates" && k != "reason" { return fail("unknown member \"\(k)\" (clarifications carry no text)") }
        guard let reason = b["reason"]?.asString, IV.contains(CLARIFY_REASONS, reason) else { return fail("reason must be one of \(CLARIFY_REASONS.joined(separator: ", "))") }
        guard let cands = b["candidates"]?.asArray, !cands.isEmpty, cands.count <= MAX_CANDIDATES else { return fail("candidates must be 1..\(MAX_CANDIDATES) structured actions") }
        var out: [JSONValue] = []
        for (i, c) in cands.enumerated() {
            guard case let .object(co) = c else { return fail("candidates[\(i)] must be an object") }
            for k in PCAWallet.keysOf(co) where k != "verb" && k != "values" { return fail("candidates[\(i)] has an unknown member \"\(k)\"") }
            guard let verb = co["verb"]?.asString, verb.utf16.count > 0, verb.utf16.count <= 128 else { return fail("candidates[\(i)].verb must be a non-empty string") }
            guard case let .object(vo)? = co["values"] else { return fail("candidates[\(i)].values must be an object") }
            let entries = (try? WJ.entries(.object(vo))) ?? []
            if entries.count > MAX_VALUES { return fail("candidates[\(i)] has too many values") }
            var values = JObject()
            for (p, v) in entries {
                if !isPath(p) { return fail("candidates[\(i)] has a malformed path") }
                if !(IV.same(p, "action.resource") || IV.startsWith(p, "action.params.")) { return fail("candidates[\(i)].values may only name action.params.* or action.resource") }
                if WJ.isNumber(v) {
                    if !WJ.isInt(v) { return fail("candidates[\(i)].values.\(p) must be a safe integer") }
                } else if let s = v.asString, s.utf16.count <= MAX_STRING {
                } else { return fail("candidates[\(i)].values.\(p) must be a string (\u{2264} \(MAX_STRING)) or an integer") }
                values[JKey(p)] = v
            }
            out.append(WJ.obj([("verb", .string(verb)), ("values", .object(values))]))
        }
        return WJ.obj([("ok", .bool(true)), ("request", WJ.obj([("candidates", .array(out)), ("reason", .string(reason))]))])
    }

    /// Expected information gain of asking a cell with acceptance p under asymmetric noise (bits).
    public static func informationGain(_ p: Double, _ etaPos: Double, _ etaNeg: Double) -> Double {
        let py = p * (1 - etaNeg) + (1 - p) * etaPos
        return WalletStats.binEnt(py) - (p * WalletStats.binEnt(etaNeg) + (1 - p) * WalletStats.binEnt(etaPos))
    }

    /// The wallet's view of the grant: the acceptance probability, the veto and ceiling predicates (and, for the channel, the cells
    /// confirmed so far), each over `(verb, cell index)`.
    public struct View {
        public var p: (String, [Int]) -> Double
        public var vetoed: (String, [Int]) -> Bool
        public var outsideCeiling: (String, [Int]) -> Bool
        public var confirmed: () -> [(verb: String, idx: [Int])]
        public init(p: @escaping (String, [Int]) -> Double, vetoed: @escaping (String, [Int]) -> Bool, outsideCeiling: @escaping (String, [Int]) -> Bool,
                    confirmed: @escaping () -> [(verb: String, idx: [Int])] = { [] }) {
            self.p = p; self.vetoed = vetoed; self.outsideCeiling = outsideCeiling; self.confirmed = confirmed
        }
    }

    public struct ClarifyPlan {
        public var verdicts: [JSONValue]
        public var ask: (index: Int, verb: String, idx: [Int], p: Double, ig: Double)?
        public var verdictsJSON: JSONValue { .array(verdicts) }
        public var json: JSONValue {
            WJ.obj([("verdicts", .array(verdicts)), ("ask", ask.map { WJ.obj([("index", WJ.i($0.index)), ("verb", .string($0.verb)), ("idx", WJ.arr($0.idx)), ("p", .double($0.p)), ("ig", .double($0.ig))]) } ?? .null)])
        }
    }

    /// Dry-run verdicts for each candidate and the one cell worth asking, if any.
    public static func planClarification(omega: WalletOmega, view: View, candidates: [JSONValue], lift: ((JSONValue) throws -> JSONValue)? = nil, asked: Set<String>,
                                         etaPos: Double, etaNeg: Double) throws -> ClarifyPlan {
        try planClarification(omega: omega, view: view, candidates: candidates, lift: lift, asked: asked, etaPos: etaPos, etaNeg: etaNeg, harm: WalletOmegaMath.DEFAULT_HARM)
    }

    static func planClarification(omega: WalletOmega, view: View, candidates: [JSONValue], lift: ((JSONValue) throws -> JSONValue)? = nil, asked: Set<String>,
                                  etaPos: Double, etaNeg: Double, harm: WalletOmegaMath.HarmModel) throws -> ClarifyPlan {
        var verdicts: [JSONValue] = []
        var best: (index: Int, verb: String, idx: [Int], p: Double, ig: Double, weight: Double, flat: Int)?
        var seen = Set<String>()
        func v(_ i: Int, _ s: String) -> JSONValue { WJ.obj([("index", WJ.i(i)), ("verdict", .string(s))]) }
        for (index, cand) in candidates.enumerated() {
            guard let at = try PCAWallet.cellOfAction(omega, try lift?(cand) ?? cand) else { verdicts.append(v(index, "outside")); continue }
            let vs = at.vs, idx = at.idx
            if view.outsideCeiling(vs.verb, idx) || view.vetoed(vs.verb, idx) { verdicts.append(v(index, "denied")); continue }
            let p = view.p(vs.verb, idx)
            if p <= 0 { verdicts.append(v(index, "denied")); continue }
            if p >= 1 { verdicts.append(v(index, "admitted")); continue }
            let key = PCAWallet.cellKey(vs.verb, idx)
            if asked.contains(key) { verdicts.append(v(index, "asked")); continue }
            verdicts.append(v(index, "uncertain"))
            if seen.contains(key) { continue }
            seen.insert(key)
            let ig = informationGain(p, etaPos, etaNeg)
            let s = WalletOmegaMath.cellStats(vs, idx, harm)
            let c2 = (index: index, verb: vs.verb, idx: idx, p: p, ig: ig, weight: s.mass * s.harm, flat: PCAWallet.flatIndex(vs, idx))
            if let b = best {
                if c2.ig > b.ig + 1e-12 || (abs(c2.ig - b.ig) <= 1e-12 && (c2.weight > b.weight || (c2.weight == b.weight && c2.flat < b.flat))) { best = c2 }
            } else { best = c2 }
        }
        return ClarifyPlan(verdicts: verdicts, ask: best.map { ($0.index, $0.verb, $0.idx, $0.p, $0.ig) })
    }
}
