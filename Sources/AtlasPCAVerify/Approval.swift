import Foundation

// What you see is what you sign (track K7): a port of packages/pca/src/approval-render.ts (render shape, H(R), the approval
// challenge, the speakable match code) and packages/pca-actions/src/approval-render.ts + approval-profiles.ts (the canonical render
// of an action, the PSD2 RTS Art. 5 linking view, the batch commitment). A render that cannot be made completely throws
// `ActionKitError` rather than returning something partial.

public enum Approval {
    public static let RENDER_DOMAIN = "atlas-pca/approval-render/v1"
    public static let CHALLENGE_DOMAIN = "atlas-pca/approval-challenge/v1\u{0}"
    public static let BATCH_DOMAIN = "atlas-pca/approval-batch/v1"
    static let ITEM_DOMAIN = "atlas-pca/approval-batch-item/v1"
    static let PAYEE_DOMAIN = "atlas-pca/approval-payee/v1"
    static let MAX_FIELDS = 64
    static let MAX_DEPTH = 3

    public static let WORDS: [String] = [
        "able", "acid", "aged", "also", "area", "army", "atom", "aunt",
        "away", "baby", "back", "ball", "band", "bank", "base", "bath",
        "bear", "beat", "beef", "bell", "belt", "bend", "bird", "blue",
        "boat", "body", "bold", "bone", "book", "boot", "born", "both",
        "bowl", "bulb", "burn", "bush", "busy", "cafe", "cake", "calm",
        "camp", "card", "care", "cart", "case", "cash", "cast", "cave",
        "cell", "chat", "chef", "chip", "city", "clay", "clip", "club",
        "coal", "coat", "code", "coin", "cold", "cook", "cool", "cope",
        "copy", "cord", "core", "cost", "crew", "crop", "dark", "data",
        "date", "dawn", "deal", "dear", "deck", "deep", "deer", "desk",
        "dial", "dice", "diet", "dish", "dive", "door", "dose", "down",
        "draw", "drop", "drum", "duck", "dust", "duty", "each", "earn",
        "east", "easy", "edge", "echo", "else", "even", "ever", "exit",
        "face", "fact", "fair", "fall", "farm", "fast", "fate", "fern",
        "file", "fill", "film", "find", "fine", "fire", "firm", "fish",
        "five", "flag", "flat", "flow", "foam", "fold", "folk", "food",
        "foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
        "full", "fund", "gain", "game", "gate", "gear", "gift", "girl",
        "glad", "glow", "goat", "gold", "golf", "good", "grab", "gray",
        "grid", "grip", "grow", "gulf", "hair", "half", "hall", "hand",
        "hard", "harp", "hawk", "head", "heat", "help", "herb", "hill",
        "hint", "hold", "hole", "home", "hood", "hook", "hope", "horn",
        "host", "hour", "huge", "hunt", "idea", "inch", "iron", "isle",
        "item", "jade", "jazz", "join", "joke", "jump", "jury", "just",
        "keen", "keep", "kind", "king", "kite", "knee", "knot", "lake",
        "lamp", "land", "lane", "last", "late", "lawn", "lead", "leaf",
        "lean", "left", "lens", "less", "lift", "lime", "line", "link",
        "lion", "list", "live", "load", "loan", "lock", "logo", "long",
        "loop", "lord", "loud", "love", "luck", "lung", "made", "mail",
        "main", "mask", "mass", "mate", "meal", "melt", "menu", "mild",
        "milk", "mind", "mint", "mole", "moon", "more", "moss", "move",
        "much", "nail", "navy", "neat", "neck", "nest", "news", "nice",
    ]

    private static func digestOk(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString else { return false }
        return Base64URLStrict.decode(s, length: 32) != nil
    }

    private static func bounded(_ v: JSONValue?, _ max: Int) -> Bool {
        guard let s = v?.asString else { return false }
        return !s.isEmpty && s.utf8.count <= max
    }

    private static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    private static func closed(_ o: JObject, _ required: [String], _ optional: [String]) -> String? {
        for k in o.keys.sorted() where !required.contains(where: { IV.same($0, k.s) }) && !optional.contains(where: { IV.same($0, k.s) }) {
            return "unknown member '\(k.s)'"
        }
        for k in required where o[JKey(k)] == nil { return "missing member '\(k)'" }
        return nil
    }

    /// nil if `r` is a well-formed render (closed members, sorted unique ids, bounded), else the reason.
    public static func renderShapeError(_ r: JSONValue?) -> String? {
        guard case let .object(o)? = r else { return "render must be an object" }
        if let e = closed(o, ["v", "kind", "verb", "def_digest", "unreviewed", "fields"], []) { return e }
        if IV.int(o["v"]) != 1 || !IV.same(o["kind"]?.asString, "pca-approval-render") { return "not a pca-approval-render v1" }
        if !bounded(o["verb"], 128) { return "verb must be a bounded string" }
        if !digestOk(o["def_digest"]) { return "def_digest must be canonical base64url (32 bytes)" }
        guard case .bool? = o["unreviewed"] else { return "unreviewed must be a boolean" }
        guard case let .array(fs)? = o["fields"], fs.count <= MAX_FIELDS else { return "fields must be an array of at most \(MAX_FIELDS)" }
        var prev: String?
        for fv in fs {
            guard case let .object(f) = fv else { return "a field must be an object" }
            if let e = closed(f, ["id", "class", "value"], ["unit"]) { return e }
            if !bounded(f["id"], 192) || !bounded(f["class"], 128) { return "field id and class must be bounded strings" }
            let id = f["id"]!.asString!
            if let p = prev, !u16less(p, id) { return "fields must be sorted by id and unique" }
            prev = id
            if let uv = f["unit"] {
                guard case let .object(u) = uv else { return "unit must be an object" }
                let kind = u["kind"]?.asString
                if kind == "money" {
                    if closed(u, ["kind", "ccy", "exp"], []) != nil || !bounded(u["ccy"], 16) { return "a money unit needs ccy and exp" }
                    guard let exp = IV.int(u["exp"]), exp >= 0, exp <= 18 else { return "a money unit needs ccy and exp" }
                } else if kind == nil || !["count", "bytes", "duration", "ratio"].contains(kind!) || closed(u, ["kind"], []) != nil {
                    return "unknown unit"
                }
            }
        }
        return nil
    }

    /// H(R); nil for a malformed render (a digest is never made over a shapeless value).
    public static func renderDigest(_ render: JSONValue) -> String? {
        if renderShapeError(render) != nil { return nil }
        return IV.strictHash(.object(["d": .string(RENDER_DOMAIN), "render": render]))
    }

    /// b64u(SHA-256(domain || action_digest || H(R))); nil unless both digests are canonical 32-byte values.
    public static func challenge(actionDigest: String, renderDigest: String) -> String? {
        guard let a = Base64URLStrict.decode(actionDigest, length: 32), let r = Base64URLStrict.decode(renderDigest, length: 32) else { return nil }
        return Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(CHALLENGE_DOMAIN) + a + r))
    }

    /// The speakable match code of a render digest (six words); nil for a malformed digest.
    public static func bindingWords(_ renderDigest: String) -> String? {
        guard let r = Base64URLStrict.decode(renderDigest, length: 32) else { return nil }
        return r.prefix(6).map { WORDS[Int($0)] }.joined(separator: "-")
    }

    // ---- the render --------------------------------------------------------------------------------------------------

    private static func flatten(_ out: inout JObject, _ prefix: String, _ depth: Int, _ v: JSONValue) throws {
        if case let .object(m) = v, depth < MAX_DEPTH, !m.isEmpty {
            for (k, x) in m {
                if k.s.contains(".") { throw ActionKitError(code: "render_bad_params", message: "the parameter key '\(k.s)' contains a dot") }
                try flatten(&out, prefix.isEmpty ? k.s : prefix + "." + k.s, depth + 1, x)
            }
        } else {
            out[JKey(prefix)] = v
        }
    }

    private static func leafOk(_ v: JSONValue) -> Bool {
        switch v {
        case let .string(s): return !Canonical.hasLoneSurrogate(s)
        case .bool: return true
        case let .array(a): return a.allSatisfy(leafOk)
        default: return IV.int(v) != nil
        }
    }

    private static func valueOk(_ type: String, _ v: JSONValue) -> Bool {
        switch type {
        case "integer", "duration": return IV.int(v) != nil
        case "boolean": if case .bool = v { return true } else { return false }
        case "string", "date", "datetime", "object_ref": if case let .string(s) = v { return !Canonical.hasLoneSurrogate(s) } else { return false }
        case "set", "array": if case .array = v { return leafOk(v) } else { return false }
        default: return false
        }
    }

    /// The canonical approval render of `def` for `params`. `confirmed`: whether the definition carries a valid signed confirmation
    /// (the caller decides, as for `effective`); an unconfirmed render carries `unreviewed: true`.
    public static func render(def: JObject, params: JSONValue, confirmed: Bool = false) throws -> JSONValue {
        guard case let .object(p) = params else { throw ActionKitError(code: "render_bad_params", message: "params must be an object") }
        let n = Actions.normalize(def)
        let np = n["params"]!.asObject!
        let verb = n["verb"]!.asString!
        var flat: JObject = [:]
        for (k, v) in p {
            if k.s.contains(".") { throw ActionKitError(code: "render_bad_params", message: "the parameter key '\(k.s)' contains a dot") }
            try flatten(&flat, k.s, 1, v)
        }
        for k in flat.keys where np[k] == nil { throw ActionKitError(code: "render_undeclared_param", message: "'\(k.s)' is not a parameter of \(verb)") }
        for (k, pv) in np where pv.get("required") == .bool(true) && flat[k] == nil {
            throw ActionKitError(code: "render_missing_param", message: "required parameter '\(k.s)' of \(verb) is missing")
        }
        var fields: [JSONValue] = []
        for id in flat.keys.sorted(by: { u16less($0.s, $1.s) }) {
            let pd = np[id]!.asObject!
            let type = pd["type"]!.asString!
            guard valueOk(type, flat[id]!) else { throw ActionKitError(code: "render_bad_value", message: "'\(id.s)' is not a \(type) in the canonical domain") }
            var f: JObject = ["id": .string(id.s), "class": pd["role"] ?? .string("param"), "value": flat[id]!]
            if case let .object(u)? = pd["unit"] {
                if u["kind"]?.asString == "money" {
                    var ccy: String?
                    if let s = u["ccy"]?.asString { ccy = s } else if case let .object(r)? = u["ccy"], let from = r["from"]?.asString { ccy = flat[JKey(from)]?.asString }
                    guard let c = ccy, !c.isEmpty else { throw ActionKitError(code: "render_unresolved_currency", message: "the currency of '\(id.s)' is not a string") }
                    f["unit"] = .object(["kind": .string("money"), "ccy": .string(c), "exp": u["exp"]!])
                } else {
                    f["unit"] = .object(["kind": u["kind"]!])
                }
            }
            fields.append(.object(f))
        }
        return .object([
            "v": .int(1), "kind": .string("pca-approval-render"), "verb": .string(verb), "def_digest": .string(Actions.defDigest(def)),
            "unreviewed": .bool(!confirmed), "fields": .array(fields),
        ])
    }

    // ---- PSD2 RTS Art. 5 ---------------------------------------------------------------------------------------------

    private static func unlinkable(_ m: String) -> ActionKitError { ActionKitError(code: "psd2_unlinkable", message: m) }

    /// The amount and the payee of a payment render (Art. 5(1)).
    public static func psd2Linking(_ r: JSONValue) throws -> JSONValue {
        if r.get("unreviewed") == .bool(true) { throw unlinkable("an unreviewed definition cannot be a payment approval") }
        let fs = (r.get("fields")?.asArray ?? []).compactMap { $0.asObject }
        let amts = fs.filter { $0["class"]?.asString == "money.amount" }
        let payees = fs.filter { $0["class"]?.asString == "party.payee" }
        guard amts.count == 1 else { throw unlinkable("a payment approval needs exactly one money.amount parameter") }
        let a = amts[0]
        guard case let .object(u)? = a["unit"], u["kind"]?.asString == "money" else { throw unlinkable("the money.amount parameter has no money unit") }
        guard let amt = IV.int(a["value"]), amt >= 0 else { throw unlinkable("the amount must be a non-negative integer in minor units") }
        guard payees.count == 1, let payee = payees[0]["value"]?.asString, !payee.isEmpty else { throw unlinkable("a payment approval needs exactly one non-empty party.payee parameter") }
        return .object(["amount_minor": .int(amt), "currency": u["ccy"]!, "exp": u["exp"]!, "payee": .string(payee)])
    }

    /// Minor units as the decimal string of the major unit, without floating point.
    public static func minorToDecimal(_ minor: Int64, _ exp: Int64) throws -> String {
        guard minor >= 0, exp >= 0, exp <= 18 else { throw unlinkable("minor units must be a non-negative safe integer") }
        var s = String(minor)
        if exp == 0 { return s }
        while s.count < Int(exp) + 1 { s = "0" + s }
        let cut = s.index(s.endIndex, offsetBy: -Int(exp))
        return String(s[..<cut]) + "." + String(s[cut...])
    }

    /// One approval over N payments: per-currency totals, the payee set and every item (Art. 5(3)(b)). Items are `{action_digest, render}`.
    public static func batch(_ items: [JSONValue]) throws -> JSONValue {
        guard !items.isEmpty else { throw unlinkable("a batch needs at least one payment") }
        var totals: [String: (exp: Int64, minor: Int64)] = [:]
        var payees = Set<String>()
        var leaves: [JSONValue] = []
        for it in items {
            guard let render = it.get("render") else { throw unlinkable("a batch item needs a render") }
            let link = try psd2Linking(render)
            let ccy = link.get("currency")!.asString!
            let exp = IV.int(link.get("exp"))!, amt = IV.int(link.get("amount_minor"))!
            if let t = totals[ccy], t.exp != exp { throw unlinkable("currency \(ccy) appears with two exponents") }
            let (sum, overflow) = (totals[ccy]?.minor ?? 0).addingReportingOverflow(amt)
            if overflow || sum > Canonical.MAX_SAFE { throw unlinkable("the batch total exceeds the safe integer range") }
            totals[ccy] = (exp, sum)
            payees.insert(link.get("payee")!.asString!)
            guard let rd = renderDigest(render) else { throw unlinkable("a batch item render is malformed") }
            leaves.append(.object(["d": .string(ITEM_DOMAIN), "a": it.get("action_digest") ?? .null, "r": .string(rd)]))
        }
        let tl: [JSONValue] = totals.keys.sorted(by: u16less).map { .object(["ccy": .string($0), "exp": .int(totals[$0]!.exp), "minor": .int(totals[$0]!.minor)]) }
        let pl: [JSONValue] = payees.sorted(by: u16less).map { .object(["d": .string(PAYEE_DOMAIN), "payee": .string($0)]) }
        guard let pr = Merkle.merkleRoot(pl), let ir = Merkle.merkleRoot(leaves) else { throw unlinkable("batch roots could not be computed") }
        let batch: JSONValue = .object(["v": .int(1), "kind": .string("pca-approval-batch"), "n": .int(Int64(items.count)), "totals": .array(tl), "payees_root": .string(pr), "items_root": .string(ir)])
        guard let rd = IV.strictHash(.object(["d": .string(BATCH_DOMAIN), "batch": batch])), let ch = challenge(actionDigest: ir, renderDigest: rd), let w = bindingWords(rd) else {
            throw unlinkable("the batch digest could not be computed")
        }
        return .object(["batch": batch, "action_digest": .string(ir), "render_digest": .string(rd), "challenge": .string(ch), "words": .string(w)])
    }
}
