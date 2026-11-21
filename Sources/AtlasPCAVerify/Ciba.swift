import Foundation

/// CIBA on-ramp for PCA's step-up (port of @atlasauth/pca-ciba): the canonical approval action and the CIBA backchannel
/// authentication request derived from a step-up (OpenID CIBA Core 1.0), the risk-adaptive gate, the budget effect of a decision
/// and the PING callback check. The brokers and approval stores are in CibaBroker.swift.
///
/// CIBA is only the human-notification / decision envelope: the threshold cosign stays the enforcement. Everything here is pure
/// and authorises nothing on its own. Inputs are JSON values (the step-up as the reference's `StepUpRequest` object); every
/// malformed input is refused (`JSError`), never rendered.
public enum PCACiba {
    static let DEFAULT_EXPIRY_SEC = 300
    static let DEFAULT_INTERVAL_SEC = 5
    /// 128 bits of base64url is 22 characters (CIBA Core 7.3).
    static let MIN_AUTH_REQ_ID_LEN = 22
    static let MAX_GOAL_CHARS = 100
    static let MAX_PAYEE_CHARS = 64
    static let PAYEE_KEYS = ["payee", "to", "recipient", "beneficiary", "destination"]
    static let DISPLAYED_PARAM_KEYS: Set<String> = Set(["amount", "currency"] + PAYEE_KEYS)

    static func fail(_ m: String) -> JSError { JSError("ciba: " + m) }

    // MARK: - character classes (JavaScript regex semantics over code points)

    static func scalars(_ s: String) -> [Unicode.Scalar] { Array(s.unicodeScalars) }
    static func string(_ u: [Unicode.Scalar]) -> String { var v = String.UnicodeScalarView(); v.append(contentsOf: u); return String(v) }
    static func same(_ a: String, _ b: String) -> Bool { a.unicodeScalars.elementsEqual(b.unicodeScalars) }
    /// `/^[\x20-\x7E]*$/` (or `+` when `nonEmpty`).
    static func printableASCII(_ s: String, nonEmpty: Bool = false) -> Bool {
        (!nonEmpty || !s.isEmpty) && s.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value <= 0x7e }
    }
    static func isSpace(_ u: Unicode.Scalar) -> Bool { Attest.isJSSpace(u) }
    static func isCcCf(_ u: Unicode.Scalar) -> Bool { CibaUnicode.contains(CibaUnicode.ccCf, u.value) }
    static func isMark(_ u: Unicode.Scalar) -> Bool { CibaUnicode.contains(CibaUnicode.mark, u.value) }
    static func undisplayable(_ u: Unicode.Scalar) -> Bool { CibaUnicode.contains(CibaUnicode.undisplayable, u.value) }
    /// The script group tag of a letter (0 = a letter outside the named groups); nil for a non-letter.
    static func letterGroup(_ u: Unicode.Scalar) -> UInt32? { CibaUnicode.lookup(CibaUnicode.letterGroups, u.value) }

    static func asciiAlnum(_ u: Unicode.Scalar) -> Bool {
        (u.value >= 0x30 && u.value <= 0x39) || (u.value >= 0x41 && u.value <= 0x5a) || (u.value >= 0x61 && u.value <= 0x7a)
    }

    /// `/^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}$/`
    static func isIdent(_ s: String) -> Bool {
        let u = scalars(s)
        guard let f = u.first, asciiAlnum(f), u.count <= 64 else { return false }
        return u.dropFirst().allSatisfy { asciiAlnum($0) || "._:/#@+-".unicodeScalars.contains($0) }
    }

    /// `/because\s+you\s+asked/i` (ASCII case folding, as a non-unicode JavaScript regex does).
    static func forgedClause(_ s: String) -> Bool {
        let u = scalars(s).map { $0.value >= 0x41 && $0.value <= 0x5a ? Unicode.Scalar($0.value + 0x20)! : $0 }
        func word(_ w: String, _ at: Int) -> Int? {
            let ws = Array(w.unicodeScalars)
            guard at + ws.count <= u.count, Array(u[at..<(at + ws.count)]) == ws else { return nil }
            return at + ws.count
        }
        func spaces(_ at: Int) -> Int? {
            var i = at
            while i < u.count, isSpace(u[i]) { i += 1 }
            return i > at ? i : nil
        }
        for i in u.indices {
            if let a = word("because", i), let b = spaces(a), let c = word("you", b), let d = spaces(c), word("asked", d) != nil { return true }
        }
        return false
    }

    /// Untrusted text made safe for a one-line plain-text prompt: control / format / line separators become spaces, whitespace
    /// runs collapse to one space, then trimmed.
    static func plainText(_ s: String) -> String {
        var out: [Unicode.Scalar] = []
        for c in s.unicodeScalars {
            let x: Unicode.Scalar = (isCcCf(c) || c.value == 0x2028 || c.value == 0x2029) ? " " : c
            if isSpace(x) {
                if out.last != " " { out.append(" ") }
            } else {
                out.append(x)
            }
        }
        while out.first == " " { out.removeFirst() }
        while out.last == " " { out.removeLast() }
        return string(out)
    }

    /// At most `max` code points; a cut value ends in "…".
    static func clip(_ s: String, _ max: Int) -> String {
        let u = scalars(s)
        return u.count <= max ? s : string(Array(u.prefix(Swift.max(0, max - 1)))) + "\u{2026}"
    }

    static func cpCount(_ s: String) -> Int { s.unicodeScalars.count }

    /// `Number.isSafeInteger(v)`
    static func safeInt(_ v: JSONValue?) -> Int? {
        switch v {
        case let .int(i)?: return abs(i) <= 9_007_199_254_740_991 ? Int(i) : nil
        case let .double(d)?: return d.isFinite && d.rounded() == d && abs(d) <= 9_007_199_254_740_991 ? Int(d) : nil
        default: return nil
        }
    }

    // MARK: - canonical action

    static func identifier(_ v: JSONValue?, _ what: String) throws -> String {
        guard let s = v?.asString, isIdent(s) else {
            throw fail("the step-up \(what) must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message")
        }
        if forgedClause(s) { throw fail("the step-up \(what) contains an approval-explanation clause") }
        return s
    }

    static func payeeText(_ v: JSONValue?) throws -> String {
        guard let raw = v?.asString else { throw fail("the payee must be a string (a nested value cannot be shown to the approver)") }
        let t = raw.precomposedStringWithCanonicalMapping
        let u = scalars(t)
        let doubleSpace = zip(u, u.dropFirst()).contains { isSpace($0) && isSpace($1) }
        if u.isEmpty || !same(Attest.jsTrim(t), t) || doubleSpace {
            throw fail("the payee must be non-empty without leading, trailing or repeated whitespace")
        }
        if u.contains(where: { undisplayable($0) || $0 == "\r" || $0 == "\n" || $0 == "\t" }) {
            throw fail("the payee contains control, bidirectional or invisible characters and cannot be displayed")
        }
        if u.contains(where: { $0 == "\"" || $0 == "\\" }) { throw fail("the payee must not contain quote or backslash characters") }
        if u.count > MAX_PAYEE_CHARS { throw fail("the payee is longer than \(MAX_PAYEE_CHARS) characters; refusing to truncate what the person approves") }
        if forgedClause(t) { throw fail("the payee contains an approval-explanation clause") }
        // Look-alikes: a combining mark left after NFC, a compatibility form NFKC changes, or letters from more than one script.
        if u.contains(where: isMark) { throw fail("the payee contains combining marks and cannot be shown unambiguously") }
        if !same(t.precomposedStringWithCompatibilityMapping, t) {
            throw fail("the payee contains compatibility/fullwidth characters that imitate plain ones")
        }
        var groups = Set<String>()
        for c in u {
            guard let g = letterGroup(c) else { continue }
            groups.insert(g == 0 ? "other:\(c.value)" : CibaUnicode.groupNames[Int(g)])
        }
        if groups.count > 1 { throw fail("the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike") }
        return t
    }

    /// `/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/`
    static func plainAmount(_ s: String) -> Bool {
        let u = Array(s.utf8)
        let dot = u.firstIndex(of: UInt8(ascii: "."))
        let int = dot.map { Array(u[..<$0]) } ?? u
        let digits = { (a: ArraySlice<UInt8>) in !a.isEmpty && a.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
        guard digits(int[...]), int == [0x30] || int[0] != 0x30 else { return false }
        if let d = dot { return digits(u[(d + 1)...]) }
        return true
    }

    /// The canonical approval action of a step-up (`{verb, amount?, currency?, payee?, resource}`). Refused (R3-05): params keys that
    /// the message does not display, a nested or malformed amount, a missing currency or payee next to an amount, two payee fields,
    /// and a verb / resource that is not a plain identifier.
    public static func cibaActionFromStepUp(_ stepUp: JSONValue) throws -> JSONValue {
        let su = stepUp.asObject ?? [:]
        let params: JObject
        switch su["params"] {
        case nil, .null?: params = [:]
        case let .object(o)?: params = o
        default: throw fail("step-up params must be an object")
        }
        let unknown = params.keys.map(\.s).filter { !DISPLAYED_PARAM_KEYS.contains($0) }.sorted()
        if !unknown.isEmpty {
            throw fail("step-up params field(s) \(unknown.joined(separator: ", ")) are not displayed in the approval message; refusing so the person never approves a hidden field")
        }
        func present(_ k: String) -> JSONValue? { JS.present(params[JKey(k)]) }
        let verb = try identifier(su["verb"], "verb"), resource = try identifier(su["resource"], "resource")
        var action: JObject = ["verb": .string(verb), "resource": .string(resource)]
        let payeeKeys = PAYEE_KEYS.filter { present($0) != nil }
        if payeeKeys.count > 1 { throw fail("more than one payee field (\(payeeKeys.joined(separator: ", "))) in params; the approver would see only one") }
        if let amt = present("amount") {
            let text: String
            switch amt {
            case let .int(i): text = String(i)
            case let .double(d) where d.isFinite: text = JS.number(d)
            case let .string(s): text = s
            default: text = ""
            }
            if !plainAmount(text) { throw fail("the binding message needs a plain non-negative decimal amount (no sign or exponent)") }
            guard let cur = params["currency"]?.asString, cur.unicodeScalars.count == 3,
                  cur.unicodeScalars.allSatisfy({ ($0.value >= 0x41 && $0.value <= 0x5a) || ($0.value >= 0x61 && $0.value <= 0x7a) }) else {
                throw fail("the binding message needs a 3-letter currency code next to the amount")
            }
            if payeeKeys.isEmpty { throw fail("an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it") }
            action["amount"] = .string(text)
            action["currency"] = .string(cur.uppercased())
        } else if present("currency") != nil {
            throw fail("a currency without an amount cannot be displayed")
        }
        if let k = payeeKeys.first { action["payee"] = .string(try payeeText(params[JKey(k)])) }
        return .object(action)
    }

    // MARK: - ASCII form (IDNA)

    /// Plain-ASCII rendering of a payee: itself when printable ASCII, else each non-ASCII word as its IDNA A-label (WHATWG
    /// domain-to-ASCII), or as `\u{hex}` escapes when IDNA refuses the word.
    public static func asciiForm(_ payee: String) -> String {
        if printableASCII(payee) { return payee }
        return payee.unicodeScalars.split(separator: " ", omittingEmptySubsequences: false).map { part -> String in
            let w = string(Array(part))
            if printableASCII(w) { return w }
            if let a = CibaIdna.domainToASCII(w), !a.isEmpty { return a }
            return w.unicodeScalars.map { $0.value > 0x7e ? "\\u{\(String($0.value, radix: 16))}" : String($0) }.joined()
        }.joined(separator: " ")
    }

    // MARK: - binding message

    static func head(_ a: JObject) -> String {
        var h = "Approve \(a["verb"]?.asString ?? "")"
        if let amt = a["amount"]?.asString { h += " \(amt) \(a["currency"]?.asString ?? "")" }
        if let p = a["payee"]?.asString {
            h += " to \"\(p)\"" + (printableASCII(p) ? "" : " [non-ASCII name; ASCII form: \(asciiForm(p))]")
        }
        return h + " on \(a["resource"]?.asString ?? "")"
    }

    /// The rich one-line message `Approve <verb> <amount> <CUR> to "<payee>" on <resource> — because you asked <agent> to '<goal>'`.
    /// The head is never truncated (too long = refused); only the goal clause shrinks or drops to fit.
    static func bindingMessage(_ su: JObject, _ actsFor: String, _ maxChars: Int?) throws -> String {
        let h = head(try cibaActionFromStepUp(.object(su)).asObject ?? [:])
        let limit = maxChars ?? Int.max / 4
        if cpCount(h) > limit {
            throw fail("the binding message needs \(cpCount(h)) characters but bindingMessage.maxChars is \(maxChars ?? 0); refusing to truncate what the person approves")
        }
        var plainGoal = ""
        if let g = su["goal"] {
            guard let gs = g.asString else { throw fail("the step-up goal must be a string") }
            plainGoal = String(plainText(gs).unicodeScalars.map { ($0 == "'" || $0.value == 0x2018 || $0.value == 0x2019) ? "\u{2032}" : Character($0) })
        }
        let goalText: String?
        if !plainGoal.isEmpty {
            goalText = clip(plainGoal, MAX_GOAL_CHARS)
        } else {
            switch su["goalCommit"] {
            case let .string(c)?:
                goalText = c.isEmpty ? nil : "goal \(String(decoding: Array(c.utf16.prefix(10)), as: UTF16.self))\u{2026}"
            case let .array(a)?:
                // `goalCommit.length > 0 ? goal ${goalCommit.slice(0, 10)}…`: an array's first ten elements joined by commas (null / undefined as nothing)
                goalText = a.isEmpty ? nil : "goal " + a.prefix(10).map { $0 == .null ? "" : JS.toString($0) }.joined(separator: ",") + "\u{2026}"
            case nil, .null?: throw fail("the step-up goal commitment is missing")
            default: goalText = nil // a value without a length: no goal clause (as the reference)
            }
        }
        guard let goal = goalText else { return h }
        let prefix = " \u{2014} because you asked \(actsFor) to '"
        let room = limit - cpCount(h + prefix) - 1
        if room >= cpCount(goal) { return "\(h)\(prefix)\(goal)'" }
        if room >= 8 { return "\(h)\(prefix)\(clip(goal, room))'" }
        return h
    }

    static func tokenise(_ s: String) -> String {
        var out: [Unicode.Scalar] = []
        for c in s.unicodeScalars {
            let ok = asciiAlnum(c) || c == "." || c == "_" || c == "-"
            let x: Unicode.Scalar = ok ? c : "-"
            if x == "-" && out.last == "-" { continue }
            out.append(x)
        }
        while let f = out.first, f == "-" || f == "." { out.removeFirst() }
        while let l = out.last, l == "-" || l == "." { out.removeLast() }
        return string(out)
    }

    /// The provider-safe compact form `Approve-<verb>-<amount>-<CUR>-to-<payee>-<resource>` (only `A-Za-z0-9._-`); all or nothing.
    static func compactBindingMessage(_ su: JObject, _ maxChars: Int) throws -> String {
        let a = try cibaActionFromStepUp(.object(su)).asObject ?? [:]
        if let p = a["payee"]?.asString, !printableASCII(p, nonEmpty: true) {
            throw fail("tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)")
        }
        var raw = ["Approve", a["verb"]?.asString ?? ""]
        if let amt = a["amount"]?.asString { raw += [amt, a["currency"]?.asString ?? ""] }
        if let p = a["payee"]?.asString { raw += ["to", p] }
        raw.append(a["resource"]?.asString ?? "")
        let parts = raw.map(tokenise)
        if parts.contains(where: \.isEmpty) { throw fail("tokenOnly binding message cannot represent the verb, payee or resource") }
        let out = parts.joined(separator: "-")
        if out.utf16.count > maxChars {
            throw fail("the binding message needs \(out.utf16.count) characters but bindingMessage.maxChars is \(maxChars); refusing to truncate what the person approves")
        }
        return out
    }

    /// `/^[A-Za-z0-9._-]+$/`
    static func authReqIdChars(_ s: String) -> Bool {
        !s.isEmpty && s.unicodeScalars.allSatisfy { asciiAlnum($0) || $0 == "." || $0 == "_" || $0 == "-" }
    }

    /// Map a step-up to a CIBA backchannel authentication request (`auth_req_id`, `binding_message`, `scope`, `requested_expiry`,
    /// `interval`, `login_hint?`, `stepUpId`, `tier`, and with a canonical render `authorization_details` + `render_digest`). Pure.
    ///
    /// `opts` (the reference's `CibaRequestOptions`): `expiresInSec`, `authReqId`, `stepUpScope`, `loginHint`,
    /// `bindingMessage: {maxChars, tokenOnly}`, `interval`, `actsFor`. A present but malformed option is refused.
    /// The reference reads `opts.actsFor` with no null guard: a null options value is a TypeError, a refusal here.
    public static func toCibaAuthRequest(_ stepUp: JSONValue, options: JSONValue?) throws -> JSONValue {
        if options == .null { throw fail("Cannot read properties of null (reading 'actsFor')") }
        return try toCibaAuthRequest(stepUp, options?.asObject ?? [:])
    }

    public static func toCibaAuthRequest(_ stepUp: JSONValue, _ opts: JObject = [:]) throws -> JSONValue {
        let su = stepUp.asObject ?? [:]
        var actsFor = "your agent"
        if let a = opts["actsFor"] {
            guard let s = a.asString else { throw fail("actsFor must be a string") }
            let p = plainText(s)
            if !p.isEmpty { actsFor = clip(p, 40) }
        }
        var requestedExpiry = DEFAULT_EXPIRY_SEC
        if let e = opts["expiresInSec"] {
            guard let n = safeInt(e), n > 0 else { throw fail("requested_expiry must be a positive integer number of seconds, got \(JS.toString(e))") }
            requestedExpiry = n
        }
        // The verb is spliced into ONE scope-token: a space would smuggle in extra scopes (RFC 6749 3.3).
        let stepUpScope = "urn:atlas:pca:stepup:" + JS.toString(su["verb"])
        if !stepUpScope.unicodeScalars.allSatisfy({ $0.value == 0x21 || ($0.value >= 0x23 && $0.value <= 0x5b) || ($0.value >= 0x5d && $0.value <= 0x7e) }) {
            throw fail("the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)")
        }
        let scope = opts["stepUpScope"] == .bool(false) ? "openid" : "openid \(stepUpScope)"
        var interval = DEFAULT_INTERVAL_SEC
        if let i = opts["interval"] {
            guard let n = safeInt(i), n > 0 else { throw fail("interval must be a positive integer number of seconds, got \(JS.toString(i))") }
            interval = n
        }
        let authReqId: String
        switch JS.present(opts["authReqId"]) {
        case nil:
            guard let id = su["id"] else { throw fail("the step-up has no id") }
            authReqId = Canonical.hashCanonical(.object(["d": .string("atlas-pca/ciba/auth_req_id/v1"), "stepUp": id]))
        case let .string(s)?: authReqId = s
        // stricter than the reference, which lets a number through its string checks
        default: throw fail("auth_req_id must be a string")
        }
        if !authReqIdChars(authReqId) || authReqId.utf16.count < MIN_AUTH_REQ_ID_LEN || authReqId.utf16.count > 1024 {
            throw fail("auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)")
        }
        let bm = opts["bindingMessage"]?.asObject ?? [:]
        var maxOpt: Int?
        if let m = bm["maxChars"] {
            guard let n = safeInt(m), n >= 1 else { throw fail("bindingMessage.maxChars must be a positive integer") }
            maxOpt = n
        }
        let tokenOnly = bm["tokenOnly"] == .bool(true)
        let maxChars = maxOpt ?? 50
        // K7: the binding message is advisory; the canonical render is what the approval commits to. A short word string of H(R)
        // rides in the message so the person can match the push to the original screen.
        var words: String?
        let render = su["render"], digest = su["renderDigest"]
        if render != nil || digest != nil {
            guard let r = render, let d = digest?.asString, let rd = Approval.renderDigest(r), rd == d, let w = Approval.bindingWords(d) else {
                throw fail("the step-up render and its digest do not agree; refusing to send an approval that commits to something else")
            }
            words = w
        }
        let reserve = words.map { $0.utf16.count + 14 } ?? 0
        var message = try tokenOnly
            ? compactBindingMessage(su, maxChars - reserve)
            : bindingMessage(su, actsFor, maxOpt.map { $0 - reserve })
        if let w = words { message = tokenOnly ? "\(message)-match-\(w)" : "\(message) [match code \(w)]" }
        var out: JObject = [
            "auth_req_id": .string(authReqId), "binding_message": .string(message), "scope": .string(scope),
            "requested_expiry": .int(Int64(requestedExpiry)), "interval": .int(Int64(interval)),
        ]
        if let h = opts["loginHint"] { out["login_hint"] = h }
        if let id = su["id"] { out["stepUpId"] = id }
        if let t = su["tier"] { out["tier"] = t }
        if let r = render, let d = digest {
            out["authorization_details"] = .array([.object(["type": .string("pca_approval"), "render": r, "render_digest": d])])
            out["render_digest"] = d
        }
        return .object(out)
    }

    // MARK: - gating and the budget effect

    /// Only a tier-3 step-up (human required) goes through CIBA; tier 2 (guardian auto-cosign), auto and deny never notify a person.
    public static func requiresCiba(_ review: JSONValue) -> Bool {
        review.get("kind") == .string("step_up") && safeInt(review.get("request")?.get("tier")) == 3
    }

    /// The budget effect of a settled decision: `approve` recharges (`B <- min(bMax, B + rho)`, or `bMax` with `full`; tau and asOf
    /// <- now), `deny` leaves the budget unchanged. Budget-level only: the threshold cosign is what authorises the action.
    public static func cibaDecisionToCosign(approve: Bool, budget: Risk.Budget, bMax: Double, rho: Double, now: Double, full: Bool = false)
        -> (budget: Risk.Budget, cosigned: Bool)
    {
        guard approve else { return (budget, false) }
        let nz = { (x: Double) in x.isFinite && x > 0 ? x : 0 }
        let b = full ? nz(bMax) : Swift.min(nz(bMax), budget.b + nz(rho))
        return (Risk.Budget(b: b, tau: now, asOf: now), true)
    }

    // MARK: - PING callback

    /// Validate a PING callback (CIBA Core 10.2): `Authorization: Bearer <client_notification_token>` (constant-time compare) and a
    /// JSON body `{"auth_req_id": ...}` naming this flow. Returns the auth_req_id; throws otherwise. The callback carries no
    /// decision: poll for it.
    public static func verifyPingCallback(authorization: String?, body: JSONValue?, authReqId: String, clientNotificationToken: String?,
                                          clientNotificationTokenIsNull: Bool = false) throws -> String {
        // a null token (not undefined) passes the ping-mode check and only fails when the reference hashes it, after the bearer shape check
        if clientNotificationToken == nil && !clientNotificationTokenIsNull { throw fail("flow was not started in ping mode") }
        // /^bearer +(\S+)$/i
        let u = scalars(authorization ?? "")
        let scheme = Array("bearer".unicodeScalars)
        guard u.count > 7, u.prefix(6).map({ $0.value >= 0x41 && $0.value <= 0x5a ? $0.value + 0x20 : $0.value }) == scheme.map(\.value),
              u[6] == " " else { throw fail("ping callback lacks a bearer token") }
        var i = 6
        while i < u.count, u[i] == " " { i += 1 }
        let token = Array(u[i...])
        if token.isEmpty || token.contains(where: isSpace) { throw fail("ping callback lacks a bearer token") }
        guard let expected = clientNotificationToken else {
            throw JSError("The \"data\" argument must be of type string or an instance of Buffer, TypedArray, or DataView. Received null", code: "ERR_INVALID_ARG_TYPE")
        }
        let a = Canonical.sha256(Array(string(token).utf8)), b = Canonical.sha256(Array(expected.utf8))
        var diff: UInt8 = 0
        for k in 0..<32 { diff |= a[k] ^ b[k] }
        if diff != 0 { throw fail("ping callback bearer does not match the client_notification_token") }
        guard let id = body?.asObject?[JKey("auth_req_id")]?.asString, same(id, authReqId) else {
            throw fail("ping callback auth_req_id does not match this flow")
        }
        return id
    }
}

/// WHATWG domain-to-ASCII for one payee word (UTS 46, non-transitional, CheckBidi, no STD3 rules), as far as an NFKC-stable payee
/// needs it: per code point lowercase mapping, NFC, validity, the RFC 5893 bidi rule, then Punycode (RFC 3492).
/// shortcut: no full UTS 46 mapping table (case folding beyond lowercase, the few valid-but-NV8 / disallowed symbol statuses, CheckJoiners
/// contexts, an existing xn-- label); such a word falls back to the \u escape form. Display only: upgrade if a payee shows that.
enum CibaIdna {
    static func domainToASCII(_ w: String) -> String? {
        if let toAscii = PCAExtraCrypto.domainToASCII { return toAscii(w) } // the registered UTS 46 implementation (AtlasPCAAda)
        var mapped = ""
        for c in w.unicodeScalars {
            if c.value >= 0x41 && c.value <= 0x5a { mapped.unicodeScalars.append(Unicode.Scalar(c.value + 0x20)!) } else if c.value < 0x80 {
                mapped.unicodeScalars.append(c)
            } else { mapped += c.properties.lowercaseMapping }
        }
        let labels = mapped.precomposedStringWithCanonicalMapping.split(separator: ".", omittingEmptySubsequences: false).map { Array($0.unicodeScalars) }
        let rtlDomain = labels.contains { l in l.contains { c in [Bidi.r, .al, .an].contains(bidi(c)) } }
        var out: [String] = []
        for l in labels {
            for c in l {
                if c.value < 0x80 {
                    if forbidden(c) { return nil }
                } else if PCACiba.undisplayable(c) || PCACiba.isSpace(c) || c.value == 0x2028 || c.value == 0x2029 { return nil }
            }
            if let f = l.first, PCACiba.isMark(f) { return nil }
            if rtlDomain && !l.isEmpty && !bidiOk(l) { return nil }
            if l.allSatisfy({ $0.value < 0x80 }) {
                let s = PCACiba.string(l)
                if s.hasPrefix("xn--") { return nil }
                out.append(s)
            } else {
                guard let p = punycode(l) else { return nil }
                out.append("xn--" + p)
            }
        }
        // a host whose last label is numeric goes to the IPv4 parser, which an A-label never satisfies
        var tail = out
        if tail.count > 1, tail.last == "" { tail.removeLast() }
        if let last = tail.last, !last.isEmpty {
            let digits = last.allSatisfy { $0.isASCII && $0.isNumber }
            let hex = (last.hasPrefix("0x") || last.hasPrefix("0X")) && last.dropFirst(2).allSatisfy { $0.isHexDigit }
            if digits || hex { return nil }
        }
        return out.joined(separator: ".")
    }

    /// WHATWG forbidden domain code points (ASCII).
    static func forbidden(_ c: Unicode.Scalar) -> Bool {
        c.value <= 0x20 || c.value == 0x7f || "#%/:<>?@[\\]^|".unicodeScalars.contains(c)
    }

    enum Bidi { case l, r, al, en, an, other }
    static func bidi(_ c: Unicode.Scalar) -> Bidi {
        if c.value >= 0x30 && c.value <= 0x39 { return .en }
        if (0x660...0x669).contains(c.value) { return .an }
        if (0x6f0...0x6f9).contains(c.value) { return .en }
        if let g = PCACiba.letterGroup(c) {
            switch CibaUnicode.groupNames[Int(g)] {
            case "hebrew": return .r
            case "arabic": return .al
            default: return .l
            }
        }
        return .other
    }

    /// RFC 5893 section 2, rules 1-6 (marks are refused earlier, so NSM never occurs).
    static func bidiOk(_ l: [Unicode.Scalar]) -> Bool {
        let cls = l.map(bidi)
        guard let first = cls.first, [.l, .r, .al].contains(first) else { return false }
        let lastStrong = cls.last!
        if first == .l {
            return !cls.contains { [.r, .al, .an].contains($0) } && (lastStrong == .l || lastStrong == .en)
        }
        if cls.contains(.l) { return false }
        if cls.contains(.en) && cls.contains(.an) { return false }
        return [.r, .al, .en, .an].contains(lastStrong)
    }

    /// RFC 3492 Punycode encoding of one label.
    static func punycode(_ input: [Unicode.Scalar]) -> String? {
        let base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700
        func digit(_ d: Int) -> Character { Character(Unicode.Scalar(UInt8(d < 26 ? 0x61 + d : 0x16 + d))) }
        func adapt(_ delta0: Int, _ numPoints: Int, _ first: Bool) -> Int {
            var delta = first ? delta0 / damp : delta0 / 2
            delta += delta / numPoints
            var k = 0
            while delta > ((base - tmin) * tmax) / 2 { delta /= base - tmin; k += base }
            return k + (base - tmin + 1) * delta / (delta + skew)
        }
        let cps = input.map { Int($0.value) }
        var out = String(cps.filter { $0 < 0x80 }.map { Character(Unicode.Scalar(UInt8($0))) })
        let b = out.count
        var h = b
        if b > 0 { out.append("-") }
        var n = 0x80, delta = 0, bias = 72
        while h < cps.count {
            guard let m = cps.filter({ $0 >= n }).min() else { return nil }
            delta += (m - n) * (h + 1)
            n = m
            for c in cps {
                if c < n { delta += 1 }
                if c == n {
                    var q = delta, k = base
                    while true {
                        let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                        if q < t { break }
                        out.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    out.append(digit(q))
                    bias = adapt(delta, h + 1, h == b)
                    delta = 0
                    h += 1
                }
            }
            delta += 1
            n += 1
        }
        return out
    }
}
