import Foundation

/// Self-explaining PCA decisions: the verifier's per-check result, the Policy VM decision and a delegation chain become precise,
/// human-readable explanations plus renderers. Everything here is pure and read-only: it consumes the real shapes of the core, never
/// re-authorizes anything, and degrades a malformed input to a best-effort explanation (`explainVerification` and `explainDecision`
/// never turn a hostile shape into an allow).
///
/// Explanations are plain JSON values with exactly the members of the reference's explanation objects (an absent member is a JS
/// `undefined`); the `*ToText` functions render them. Inputs are JSON values, and the reference's JavaScript value semantics
/// (`String(x)`, `JSON.stringify`, `Number(x)`, relational comparison, truthiness, property reads on any value) are reproduced where
/// an untrusted field reaches them, so a hostile shape produces the same text or the same refusal (a thrown error) as the reference.
/// `now` and the decision context use the reference's camelCase keys (`blastRadius`, `delegationDepth`, ...).
///
/// shortcut: a Swift String cannot hold a lone surrogate, so a cut of an abbreviated or truncated text that would split a surrogate
/// pair drops the lone half (cleanText) or replaces it (short); object member order is the parsed order (see JSLoose).
public enum PCAExplain {
    public static let MAX_TEXT = 400
    public static let VERIFY_CHECK_ORDER = ["wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion",
                                            "leaf_signature", "counter_format"]
    public static let PCACTN_VERSION = 2
    static let MAX_LIFETIME_MS = 3_600_000.0
    static let MAX_SKEW_MS = 60_000.0

    static let CHECK_TITLE: [String: String] = [
        "wire": "wire format", "version": "version", "audience": "audience binding", "validity": "freshness window",
        "cap_chain": "capability chain", "grant_ref_bound": "grant reference binding", "plan_inclusion": "plan inclusion",
        "leaf_signature": "leaf signature", "counter_format": "counter format", "counter": "counter format", "replay": "replay",
        "plan_root_authorized": "plan-root authorization", "taint_gate": "taint gate", "attestation": "agent attestation",
        "threshold": "threshold signature", "revocation": "revocation", "zk_compliance": "zk compliance", "bond": "bond",
        "malformed": "structure",
    ]

    typealias V = JSONValue

    // ---- JavaScript value helpers ----

    private static func get(_ o: V?, _ k: String) -> V? { JSLoose.get(o, k) }
    private static func rd(_ o: V?, _ k: String) throws -> V? { try JSLoose.rd(o, k) }
    /// `o?.[k]`.
    private static func opt(_ o: V?, _ k: String) -> V? { (o == nil || o == .null) ? nil : get(o, k) }
    /// `a ?? b`.
    private static func nn(_ a: V?, _ b: V) -> V { JS.present(a) ?? b }
    private static func str(_ v: V?) -> String { JS.toString(v) }
    private static func truthy(_ v: V?) -> Bool { JS.truthy(v) }
    private static func isObjOrArr(_ v: V?) -> Bool { v?.isObject == true || v?.isArray == true }
    private static func put(_ d: inout JObject, _ k: String, _ v: V?) { if let v = v { d[JKey(k)] = v } }
    private static func numJSON(_ d: Double) -> V { d.rounded() == d && abs(d) <= 9_007_199_254_740_991 ? .int(Int64(d)) : .double(d) }
    private static func isTrue(_ v: V?) -> Bool { v == .bool(true) }
    private static func isFin(_ v: V?) -> Bool { IV.num(v).map { $0.isFinite } ?? false }

    /// `String.prototype.includes` over UTF-16 code units (no canonical equivalence).
    static func includes(_ s: String, _ needle: String) -> Bool {
        let h = Array(s.utf16), n = Array(needle.utf16)
        if n.isEmpty { return true }
        if h.count < n.count { return false }
        for i in 0...(h.count - n.count) where Array(h[i..<(i + n.count)]) == n { return true }
        return false
    }

    /// `r.includes(needle)` where `r` is any reason value: a string searches, an array tests membership, anything else throws.
    private static func reasonIncludes(_ r: V, _ needle: String) throws -> Bool {
        switch r {
        case let .string(s): return includes(s, needle)
        case let .array(a): return a.contains { $0 == .string(needle) }
        default: throw JSError("includes is not a function")
        }
    }

    private static func utf16Slice(_ s: String, _ from: Int, _ to: Int? = nil) -> String {
        let u = Array(s.utf16)
        let a = min(max(from, 0), u.count), b = min(max(to ?? u.count, a), u.count)
        return String(decoding: Array(u[a..<b]), as: UTF16.self)
    }

    private static func startsWith(_ s: String, _ prefix: String) -> Bool { s.utf16.starts(with: prefix.utf16) }

    /// JS `a <= b`.
    private static func le(_ a: V?, _ b: V?) -> Bool {
        let x = JSLoose.prim(a), y = JSLoose.prim(b)
        if case let .string(s)? = x, case let .string(t)? = y { return !t.utf16.lexicographicallyPrecedes(s.utf16) }
        return JS.toNumber(x) <= JS.toNumber(y)
    }

    /// JS `a + n` for a number n: a string or array on the left makes it a concatenation.
    private static func add(_ a: V?, _ n: Double) -> V {
        let p = JSLoose.prim(a)
        if case let .string(s)? = p { return .string(s + JS.number(n)) }
        return .double(JS.toNumber(p) + n)
    }

    // ---- cleanText ----

    private static let spaceSet = #"\t\n\x{0B}\x{0C}\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}"#
    private static let S = "[" + spaceSet + "]"
    private static let notAfterWord = "(?<![A-Za-z0-9_])"
    private static func ci(_ w: String) -> String {
        w.map { c in c.isASCII && c.isLetter ? "[\(c.lowercased())\(c.uppercased())]" : String(c) }.joined()
    }
    private static func re(_ p: String) -> NSRegularExpression {
        // a fixed, reviewed pattern: failing to compile is a programming error, never an input error
        try! NSRegularExpression(pattern: p)
    }
    private static let jwt = re(notAfterWord + #"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"#)
    private static let scheme = re(notAfterWord + "(" + ci("Bearer") + "|" + ci("Basic") + "|" + ci("Token") + ")" + S + "+[A-Za-z0-9_.~+/=-]{6,}")
    private static let userinfo = re("([A-Za-z][A-Za-z0-9+.-]*://)[^" + spaceSet + "/@]*:[^" + spaceSet + "/@]*@")
    private static let pair = re(notAfterWord + "((?:" + ["token", "secret", "password", "passwd", "pwd"].map(ci).joined(separator: "|")
        + "|" + ci("api") + "[_-]?" + ci("key") + "|" + ["key", "signature", "sig", "credential", "authorization", "auth"].map(ci).joined(separator: "|")
        + ")[\"']?" + S + "*[:=]" + S + "*)(\"[^\"]*\"|'[^']*'|[^" + spaceSet + "\"'&,;]+)")
    private static let longRun = re("[A-Za-z0-9_-]{40,}")

    private static func sub(_ s: String, _ r: NSRegularExpression, _ f: (NSTextCheckingResult, NSString) -> String) -> String {
        let ns = s as NSString
        var out = "", last = 0
        for m in r.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            out += f(m, ns)
            last = m.range.location + m.range.length
        }
        return out + ns.substring(from: last)
    }

    /// Removes what looks like a credential from text the explainer builds out of untrusted fields (a caveat value, a resource, an
    /// audience, a reason): JWTs, bearer credentials, URL userinfo, `token=` / `password=` style pairs and long unbroken token runs.
    /// The output is cut to 400 characters. A net, not a proof.
    public static func cleanText(_ text: String) -> String {
        var t = sub(text, jwt) { _, _ in "[redacted]" }
        t = sub(t, scheme) { m, ns in ns.substring(with: m.range(at: 1)) + " [redacted]" }
        t = sub(t, userinfo) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]@" }
        t = sub(t, pair) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]" }
        t = sub(t, longRun) { _, _ in "[redacted]" }
        let ns = t as NSString
        guard ns.length > MAX_TEXT else { return t }
        var n = MAX_TEXT
        if UTF16.isLeadSurrogate(ns.character(at: n - 1)) { n -= 1 }
        return ns.substring(to: n) + "..."
    }

    /// `cleanText(x)` for any value: `String(x)` first.
    public static func cleanText(_ v: JSONValue?) -> String { cleanText(JS.toString(v)) }

    // ---- shared helpers ----

    /// Abbreviate a long b64u key for display: the first `n` characters and an ellipsis.
    private static func short(_ key: V?, _ n: Int = 10) -> String {
        guard case let .string(s)? = key, !s.isEmpty else { return "<none>" }
        return s.utf16.count <= n + 1 ? s : utf16Slice(s, 0, n) + "…"
    }

    /// Compact number: integers stay integers, fractions round to 4 dp; anything else prints as String(x).
    private static func num(_ x: V?) -> String {
        guard let v = IV.num(x), v.isFinite else { return str(x) }
        if v == v.rounded(.down) { return JS.number(v) }
        let y = v * 1e4, f = y.rounded(.down)
        return JS.number((y - f >= 0.5 ? f + 1 : f) / 1e4)
    }

    private static func jstr(_ v: V?) -> String { v.map { JS.stringify($0) } ?? "undefined" }

    private static func caveatType(_ cv: V?) -> String {
        if case let .string(t)? = opt(cv, "type") { return t }
        return "<malformed>"
    }

    /// The caveat's members except `type`, in `Object.keys` order.
    private static func caveatRest(_ cv: V?) -> [(String, V)] {
        guard isObjOrArr(cv) else { return [] }
        return JSLoose.keys(cv).filter { $0 != "type" }.compactMap { k in get(cv, k).map { (k, $0) } }
    }

    private static func restValue(_ rest: [(String, V)], _ k: String) -> V? { rest.first { $0.0 == k }?.1 }

    private static func valueSummary(_ rest: [(String, V)]) -> String {
        rest.prefix(6).map { k, v in "\(k)=\(isObjOrArr(v) ? JS.stringify(v) : num(v))" }.joined(separator: ", ")
    }

    private static func condToText(_ c: V?, _ depth: Int = 0) -> String {
        guard isObjOrArr(c), let c = c else { return "<malformed>" }
        if depth > 6 { return "…" }
        if case let .object(o) = c {
            if case let .array(a)? = o["all_of"] { return "(" + a.map { condToText($0, depth + 1) }.joined(separator: " AND ") + ")" }
            if case let .array(a)? = o["any_of"] { return "(" + a.map { condToText($0, depth + 1) }.joined(separator: " OR ") + ")" }
            if let n = o["not"] { return "NOT " + condToText(n, depth + 1) }
        }
        let ref = get(c, "ref")
        let operand: String
        if let r = ref { operand = "→" + str(r) } else if case let .object(o) = c, let v = o["value"] { operand = num(v) } else { operand = "" }
        return Attest.jsTrim("\(str(get(c, "field"))) \(str(get(c, "op"))) \(operand)")
    }

    private static func whereSummary(_ w: V?) -> String {
        guard case let .array(a)? = w, !a.isEmpty else { return "any (no where-bound)" }
        return a.map { condToText($0) }.joined(separator: " AND ")
    }

    // ---- explainVerification ----

    private static func reasonTail(_ name: String, _ vr: V?) -> String? {
        guard case let .string(r)? = get(vr, "reason") else { return nil }
        let pre = name + ": "
        return startsWith(r, pre) ? utf16Slice(r, pre.utf16.count) : nil
    }

    private static func validityPinpoint(_ p: V?, _ now: V?) -> (detail: String, remedy: String) {
        let exp = get(p, "exp"), iat = get(p, "iat")
        let lifetime = JSLoose.sub(exp, iat)
        if !JSLoose.gt(exp, iat) {
            return ("exp \(str(exp)) ≤ iat \(str(iat)): empty validity window", "set exp strictly greater than iat.")
        }
        if lifetime > MAX_LIFETIME_MS {
            return ("lifetime \(JS.number(lifetime))ms exceeds the \(Int(MAX_LIFETIME_MS))ms maximum",
                    "shorten the window to ≤ \(Int(MAX_LIFETIME_MS))ms (buildPCActn ttlMs).")
        }
        if now != nil {
            if !JSLoose.le(iat, add(now, MAX_SKEW_MS)) {
                return ("iat \(str(iat)) is \(JS.number(JSLoose.sub(iat, now)))ms in the future (> \(Int(MAX_SKEW_MS))ms clock-skew allowance)",
                        "fix the signer clock; do not pre-date actions.")
            }
            if !JSLoose.le(now, exp) {
                return ("expired \(JS.number(JSLoose.sub(now, exp)))ms ago (exp \(str(exp)), now \(str(now)))",
                        "build a fresh action — a PCActn lifetime is short by design.")
            }
        }
        return ("validity window invalid", "build a fresh action with a valid iat/exp window.")
    }

    /// The first `hop <digits>` of a reason.
    private static func hopIndex(_ reason: String) -> Double? {
        let u = Array(reason.utf8), key = Array("hop ".utf8)
        guard u.count > key.count else { return nil }
        for i in 0...(u.count - key.count) where Array(u[i..<(i + key.count)]) == key {
            var j = i + key.count
            while j < u.count, u[j] >= 0x30, u[j] <= 0x39 { j += 1 }
            if j > i + key.count { return Double(String(decoding: u[(i + key.count)..<j], as: UTF8.self)) }
        }
        return nil
    }

    private static func chainReason(_ chain: [V], _ expected: String?) -> String? { Capability.verifyChain(chain, expectedRootIssuer: expected) }

    private static func capChainPinpoint(_ p: V?) -> (detail: String, remedy: String, hop: Double?) {
        let reason: String
        if case let .array(chain)? = get(p, "cap_chain") {
            reason = chainReason(chain, nil) ?? "chain root is not the grant this verifier expects"
        } else {
            reason = "cap_chain is not an array"
        }
        var remedy = "rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats."
        if includes(reason, "root issuer") || includes(reason, "not the grant") {
            remedy = "root the chain at the principal key that minted the grant."
        } else if includes(reason, "widens") {
            remedy = "a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation."
        } else if includes(reason, "caveat") {
            remedy = "attenuation is append-only: never drop, reorder or edit a parent caveat."
        } else if includes(reason, "signature") {
            remedy = "re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite)."
        }
        return (reason, remedy, hopIndex(reason))
    }

    private static func leafSigPinpoint(_ p: V?) -> (detail: String, remedy: String, hop: Double?) {
        let arr = get(p, "cap_chain")?.asArray
        let idx = arr.map { $0.count - 1 } ?? -1
        let leaf: V? = idx >= 0 ? arr?[idx] : nil
        let alg = nn(get(p, "alg"), .string("ed25519"))
        let remedy = "sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder."
        guard truthy(leaf) else { return ("no leaf capability to check the signature against (empty/invalid chain)", remedy, nil) }
        return ("leaf hop #\(idx) signature (holder \(short(get(leaf, "holder"))), suite \(str(alg))) does not verify", remedy, idx >= 0 ? Double(idx) : nil)
    }

    /// The decisive (first failing) check with a concrete detail and remedy.
    private static func pinpoint(_ name: String, _ p: V?, _ vr: V?, _ now: V?) -> (detail: String, remedy: String, hop: Double?) {
        let tail = reasonTail(name, vr)
        let action = opt(p, "action"), plan = opt(p, "plan")
        switch name {
        case "wire":
            return (tail ?? "wire structure / strict-canonical-form check failed",
                    "do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.", nil)
        case "version":
            return (tail ?? "unsupported ver \(num(get(p, "ver"))) (verifier requires \(PCACTN_VERSION))", "re-mint the action at wire version \(PCACTN_VERSION).", nil)
        case "audience":
            return (tail ?? "aud \(jstr(get(p, "aud"))) does not match this resource server / instance",
                    "build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).", nil)
        case "validity":
            let v = validityPinpoint(p, now)
            return (tail ?? v.detail, v.remedy, nil)
        case "cap_chain":
            let c = capChainPinpoint(p)
            return (tail ?? c.detail, c.remedy, c.hop)
        case "grant_ref_bound":
            return (tail ?? "grant_ref \(short(get(p, "grant_ref"))) is not the id of the root capability in cap_chain",
                    "set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.", nil)
        case "plan_inclusion":
            return (tail ?? "action (verb \(jstr(opt(action, "verb"))) on \(jstr(opt(action, "resource")))) is not node \(jstr(opt(plan, "node_id"))) of committed plan \(short(opt(plan, "root")))",
                    "rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).", nil)
        case "leaf_signature":
            let l = leafSigPinpoint(p)
            return (tail ?? l.detail, l.remedy, l.hop)
        case "counter", "counter_format":
            return (tail ?? "counter \(num(get(p, "counter"))) is missing or not a non-negative safe integer",
                    "use a strictly increasing per-holder counter; a repeated counter is a replay.", nil)
        case "malformed":
            return (tail ?? "the PCActn is structurally malformed", "rebuild the action with the SDK; do not construct the wire object by hand.", nil)
        default:
            return (tail ?? "\(name) check failed", "satisfy the \(name) requirement (supply the corresponding verifier hook / proof).", nil)
        }
    }

    /// What held, for a pass.
    private static func passDetail(_ name: String, _ p: V?) -> String {
        switch name {
        case "wire": return "wire structure + strict canonical form valid"
        case "version": return "ver \(num(get(p, "ver"))) supported"
        case "audience": return "aud \(jstr(get(p, "aud"))) matches this resource server"
        case "validity": return "fresh: iat/exp window valid (lifetime \(num(.double(JSLoose.sub(get(p, "exp"), get(p, "iat")) / 1000)))s)"
        case "cap_chain":
            let chain = get(p, "cap_chain")?.asArray
            return "\(chain?.count ?? 0)-hop chain verifies; root issuer \(short(opt(chain?.first, "issuer")))"
        case "grant_ref_bound": return "grant_ref \(short(get(p, "grant_ref"))) is the id of the chain root"
        case "plan_inclusion":
            let plan = opt(p, "plan")
            return "action is node \(jstr(opt(plan, "node_id"))) of committed plan \(short(opt(plan, "root")))"
        case "leaf_signature":
            let leaf = get(p, "cap_chain")?.asArray?.last
            return "leaf holder \(short(opt(leaf, "holder"))) signature valid (suite \(str(nn(get(p, "alg"), .string("ed25519")))))"
        case "counter", "counter_format": return "counter \(num(get(p, "counter"))) well-formed"
        default: return "ok"
        }
    }

    private static func cleanCheck(_ c: JObject) -> JObject {
        var o = c
        o["detail"] = .string(cleanText(c["detail"]?.asString ?? ""))
        return o
    }

    private static func verification(_ verdict: String, _ allow: Bool, _ checks: [JObject], _ decisive: JObject?, _ summary: String) -> V {
        func names(_ status: String) -> V { .array(checks.filter { $0["status"] == .string(status) }.map { $0["name"] ?? .null }) }
        var o: JObject = ["kind": .string("verification"), "verdict": .string(verdict), "allow": .bool(allow), "checks": .array(checks.map { .object($0) }),
                          "passed": names("pass"), "failed": names("fail"), "notEnforced": names("not-enforced"), "summary": .string(summary)]
        if let d = decisive { o["decisive"] = .object(d) }
        return .object(o)
    }

    private static func deniedVerification(_ why: String) -> V {
        let e: JObject = ["name": .string("malformed"), "status": .string("fail"), "title": .string(CHECK_TITLE["malformed"]!), "detail": .string(why),
                          "remedy": .string("pass the PCActn and the verifier result you verified."), "decisive": .bool(true)]
        return verification("deny", false, [e], e, "Denied: " + why)
    }

    /// Walk the normative checks of an offline verification in order: summarize what held for each pass and pinpoint the first failing
    /// check (which hop, which audience mismatch, which validity sub-case, ...) with a concrete remedy. `opts` may carry `now` (epoch
    /// ms) to tell "expired" from "clock skew" precisely. Never throws: a malformed input is a denial.
    ///
    /// `checkOrder` is the order the caller's verifier result listed its checks in: a parsed JSON object keeps no member order, and the
    /// checks beyond the normative nine are reported in that order (without it, in code-unit order).
    public static func explainVerification(_ pcActn: JSONValue?, _ verifyResult: JSONValue?, _ opts: JSONValue? = nil,
                                           checkOrder: [String]? = nil) -> JSONValue {
        guard isObjOrArr(pcActn), isObjOrArr(verifyResult) else { return deniedVerification("the PCActn or the verifier result is missing") }
        do { return try explainVerificationInner(pcActn, verifyResult, opts ?? .object([:]), checkOrder) } catch {
            return deniedVerification("the PCActn or the verifier result is malformed")
        }
    }

    private static func explainVerificationInner(_ p: V?, _ vr: V?, _ opts: V, _ checkOrder: [String]?) throws -> V {
        let statuses = nn(get(vr, "checks"), .object([:]))
        var keys = JSLoose.keys(statuses)
        if let o = checkOrder, statuses.isObject {
            let index = keys.filter { JS.indexKey($0) != nil }
            let named = o.filter { k in keys.contains(k) && JS.indexKey(k) == nil }
            keys = index + named + keys.filter { JS.indexKey($0) == nil && !named.contains($0) }
        }
        var ordered = VERIFY_CHECK_ORDER
        for n in keys where !ordered.contains(n) { ordered.append(n) } // later-milestone / extra checks appended
        let decisiveName = ordered.first { get(statuses, $0) == .string("fail") }
        var checks: [JObject] = []
        var decisive: JObject?
        for name in ordered {
            let status = nn(get(statuses, name), .string("skipped"))
            var detail: String
            var remedy: String?
            var hop: Double?
            if status == .string("fail") {
                let pin = pinpoint(name, p, vr, try rd(opts, "now"))
                detail = pin.detail; remedy = pin.remedy; hop = pin.hop
            } else if status == .string("pass") {
                detail = passDetail(name, p)
            } else if status == .string("not-enforced") {
                detail = "not enforced by this verifier (no hook / opt-out)"
            } else if status == .string("unsupported") {
                detail = "the PCActn carries a feature this verifier does not implement (never a pass)"
            } else {
                detail = "not reached (a terminal earlier check stopped evaluation)"
            }
            var entry: JObject = ["name": .string(name), "status": status, "title": .string(CHECK_TITLE[name] ?? name), "detail": .string(detail)]
            if let r = remedy { entry["remedy"] = .string(r) }
            if let h = hop { entry["hop"] = numJSON(h) }
            if name == decisiveName { entry["decisive"] = .bool(true); decisive = entry }
            checks.append(entry)
        }
        // Allow only on an explicit `allow: true` that no check contradicts and that carries per-check statuses.
        let hasChecks = get(vr, "checks")?.isObject == true
        let allowClaimed = isTrue(get(vr, "allow"))
        let claimed = allowClaimed && hasChecks
        let contradicted = claimed && decisiveName != nil
        let verdict = claimed && !contradicted ? "allow" : "deny"
        let summary: String
        if verdict == "allow" {
            summary = "All \(checks.filter { $0["status"] == .string("pass") }.count) evaluated checks passed (no check failed)."
        } else if allowClaimed && !hasChecks {
            summary = "Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial)."
        } else if contradicted {
            summary = "Denied: the verifier result says allow but the \"\(decisive?["title"]?.asString ?? decisiveName ?? "")\" check failed (inconsistent result, treated as a denial)."
        } else if let d = decisive {
            summary = "Denied at the \"\(d["title"]?.asString ?? "")\" check: \(d["detail"]?.asString ?? "")"
        } else {
            summary = "Denied: " + (get(vr, "reason")?.asString ?? "a check failed")
        }
        return verification(verdict, verdict == "allow", checks.map(cleanCheck), decisive.map(cleanCheck), cleanText(summary))
    }

    private static let GLYPH: [String: String] = ["pass": "✓", "fail": "✗", "not-enforced": "·", "unsupported": "?", "skipped": "–"]

    private static func padEnd(_ s: String, _ n: Int) -> String { s + String(repeating: " ", count: max(0, n - s.utf16.count)) }

    /// Render a verification explanation.
    public static func verificationToText(_ e: JSONValue) -> String {
        var lines = ["PCA verification — \(str(get(e, "verdict")).uppercased())", str(get(e, "summary")), ""]
        for c in get(e, "checks")?.asArray ?? [] {
            let decisive = truthy(get(c, "decisive"))
            let glyph = get(c, "status")?.asString.flatMap { GLYPH[$0] } ?? "undefined"
            lines.append("  \(glyph) \(padEnd(str(get(c, "name")), 16)) \(str(get(c, "detail")))\(decisive ? " ◀ DECISIVE" : "")")
            if decisive && truthy(get(c, "remedy")) { lines.append("      ↳ fix: \(str(get(c, "remedy")))") }
        }
        return lines.joined(separator: "\n")
    }

    // ---- explainDecision ----

    private static func caveatRemedy(_ type: String, _ rest: [(String, V)]) -> String {
        func g(_ k: String) -> V? { restValue(rest, k) }
        switch type {
        case "expires": return "the grant expired at \(num(g("at"))) (epoch ms); obtain a fresh grant or re-mint with a later 'expires'."
        case "not_before": return "the grant is not valid until \(num(g("at"))) (epoch ms); retry after that time."
        case "rate": return "rate limit \(num(g("max")))/\(num(g("per_secs")))s reached; wait for the window to clear or raise the 'rate' caveat."
        case "max_blast_radius": return "the action's blast radius exceeds the caveat max \(num(g("max"))); narrow the action or raise 'max_blast_radius'."
        case "reversibility_max": return "the action is more severe than the allowed class '\(str(g("class")))'; only that class or lower is permitted."
        case "delegation_depth": return "delegation depth exceeds max \(num(g("max"))); act from a shallower hop or raise 'delegation_depth'."
        default: return "caveat '\(type)' is not satisfied; check its parameters against the action/context."
        }
    }

    private static func caveatDetail(_ type: String, _ rest: [(String, V)], _ satisfied: V?) -> String {
        let bound = valueSummary(rest)
        let verb = truthy(satisfied) ? "held" : "NARROWED/DENIED"
        return bound.isEmpty ? "\(type) \(verb)" : "\(type)(\(bound)) \(verb)"
    }

    /// The caveat types decide() reported as failed, from `caveat(s) not satisfied: a,b` reasons.
    private static func failedCaveatTypes(_ reasons: [V]) -> Set<JKey> {
        let needle = Array("caveat(s) not satisfied: ".unicodeScalars)
        var out = Set<JKey>()
        for r in reasons {
            let s = Array(str(r).unicodeScalars)
            guard s.count > needle.count else { continue }
            for i in 0...(s.count - needle.count) where Array(s[i..<(i + needle.count)]) == needle {
                let rest = Array(s[(i + needle.count)...])
                // `(.+)$`: at least one character and no line terminator up to the end of the text
                guard !rest.isEmpty, !rest.contains(where: { [0x0A, 0x0D, 0x2028, 0x2029].contains($0.value) }) else { continue }
                var v = String.UnicodeScalarView(); v.append(contentsOf: rest)
                for t in String(v).split(separator: ",", omittingEmptySubsequences: false) {
                    let trimmed = Attest.jsTrim(String(t))
                    if !trimmed.isEmpty { out.insert(JKey(trimmed)) }
                }
                break
            }
        }
        return out
    }

    private static func riskBand(_ r: V?, _ theta1: V?, _ theta2: V?, _ tier: V?) -> String {
        guard theta1 != nil, theta2 != nil else { return "effective tier t=\(str(tier))" }
        if le(r, theta1) { return "r \(num(r)) ≤ θ1 \(num(theta1)) → claim band (t=1)" }
        if le(r, theta2) { return "θ1 \(num(theta1)) < r \(num(r)) ≤ θ2 \(num(theta2)) → standard band (t=2)" }
        return "r \(num(r)) > θ2 \(num(theta2)) → strong band (t=3)"
    }

    private static func noDecision(_ reason: String) -> V {
        .object(["admit": .bool(false), "needStepUp": .bool(false), "releaseGuardianShare": .bool(false), "r": .int(1),
                 "requiredThreshold": .object(["t": .int(3), "proof": .string("human"), "optimisticAllowed": .bool(false)]),
                 "budget": .object(["B": .int(0), "tau": .int(0), "asOf": .int(0)]), "reasons": .array([.string(reason)])])
    }

    /// Explain a Policy-VM decision: which predicate granted the (verb, resource) and under what `where` bound, which caveat narrowed or
    /// denied (type and offending value), the risk band and the admission path; for anything short of auto-admit the single decisive
    /// reason and remedy. `opts` may carry `envelope` and `context` ({action, caveat, chain}) to pinpoint precisely; without them it
    /// falls back to the decision's own `reasons`. A missing or malformed decision is a denial, never an allow.
    public static func explainDecision(_ pcActn: JSONValue?, _ decision: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        let o = opts ?? .object([:])
        guard isObjOrArr(decision), isObjOrArr(get(decision, "requiredThreshold")), let d = decision else {
            return try explainDecisionInner(noDecision("no policy decision supplied (default-deny)"), o)
        }
        do { return try explainDecisionInner(d, o) } catch {
            return try explainDecisionInner(noDecision("the policy decision could not be explained (default-deny)"), .object([:]))
        }
    }

    /// `evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok`: the reference's camelCase context mapped onto this evaluator's.
    private static func evalCaveat(_ cv: V, _ caveatCtx: V?, _ actionCtx: V?) -> Bool {
        var inner = get(actionCtx, "action") ?? .null
        if !inner.isObject { inner = .object([:]) }
        var c: JObject = [:]
        for (src, dst) in [("now", "now"), ("delegationDepth", "delegation_depth"), ("blastRadius", "blast_radius"),
                           ("reversibilityClass", "reversibility_class"), ("recentActionTimes", "recent_action_times")] {
            if let v = get(caveatCtx, src) { c[JKey(dst)] = v }
        }
        c["action"] = inner
        let params = get(inner, "params")
        var verb = ""
        if case let .string(s)? = get(inner, "verb") { verb = s }
        let call = PCA.ToolCall(tool: verb, args: params?.isObject == true ? params! : .object([:]), toolSignatureDigest: get(actionCtx, "toolBinding")?.asString)
        return PCA.evaluateAgentCaveats(.array([cv]), context: .object(c), actionContext: actionCtx?.isObject == true ? actionCtx : .object([:]), toolCall: call).ok
    }

    /// `evaluatePredicates(predicates, ctx)`: the first matching predicate and its index, else the reason.
    private static func evaluatePredicates(_ preds: V?, _ ctx: V) -> (matched: (V, Int)?, reason: String?) {
        guard case let .array(ps)? = preds, !ps.isEmpty else { return (nil, "envelope grants no predicates") }
        let budget = SafeRegex.Budget()
        for (i, p) in ps.enumerated() where Predicates.predicateMatches(p, ctx, budget) { return ((p, i), nil) }
        return (nil, PCA.envelopePredicatesError(preds, ctx, budget) ?? "no predicate permits this action")
    }

    /// `x.slice(n)` of an array or string.
    private static func sliceFrom(_ v: V, _ n: Int) throws -> V {
        switch v {
        case let .array(a): return .array(Array(a.dropFirst(n)))
        case let .string(s): return .string(utf16Slice(s, n))
        default: throw JSError("slice is not a function")
        }
    }

    /// `for (const x of v)`: an array's items or a string's code points; anything else throws.
    private static func iter(_ v: V) throws -> [V] {
        switch v {
        case let .array(a): return a
        case let .string(s): return s.unicodeScalars.map { .string(String($0)) }
        default: throw JSError("not iterable")
        }
    }

    private static func length(_ v: V?) -> Int? {
        switch v {
        case let .array(a)?: return a.count
        case let .string(s)?: return s.utf16.count
        default: return nil
        }
    }

    private static func explainDecisionInner(_ decision: V, _ opts: V) throws -> V {
        let env = try rd(opts, "envelope")
        let ctx = nn(get(opts, "context"), .object([:]))
        let reasons: [V] = get(decision, "reasons")?.asArray ?? []

        let admitted = isTrue(get(decision, "admit")) // strict: a truthy non-boolean is not an admission
        let rgs = get(decision, "releaseGuardianShare")
        let disposition = admitted ? "auto-admit" : isTrue(rgs) ? "step-up" : "denied"
        let verdict = admitted ? "allow" : "deny"

        // authority: the granting predicate
        var grant: JObject = [:]
        put(&grant, "granted", rgs)
        let chain = get(ctx, "chain")
        let rootCap = opt(chain, "0")
        if truthy(rootCap) { put(&grant, "capabilityId", get(rootCap, "id")) }
        let ctxAction = get(ctx, "action"), ctxCaveat = get(ctx, "caveat")
        let hasEnv = truthy(env)
        if hasEnv && truthy(ctxAction) {
            let pr = evaluatePredicates(get(env, "predicates"), ctxAction!)
            if let (matched, i) = pr.matched {
                grant["granted"] = .bool(true)
                grant["predicate"] = matched
                grant["predicateIndex"] = .int(Int64(i))
                grant["where"] = .string(whereSummary(get(matched, "where")))
            } else {
                grant["granted"] = .bool(false)
                grant["reason"] = .string(pr.reason ?? "no predicate permits this action")
            }
        } else if !truthy(rgs) {
            for r in reasons {
                if try reasonIncludes(r, "predicate") || reasonIncludes(r, "not permitted") { grant["reason"] = r; break }
            }
        }

        // caveats: per-caveat outcome
        var caveats: [JObject] = []
        let failedFromReasons = failedCaveatTypes(reasons)
        let canEval = env != nil && ctxCaveat != nil && ctxAction != nil
        let grantCaveats = nn(opt(env, "caveats"), .array([]))
        let chain0 = opt(chain, "0")
        var rootCount = 0
        if let c0 = chain0, c0 != .null {
            guard let cv0 = try rd(c0, "caveats"), cv0 != .null else { throw JSError("cannot read 'length' of undefined") }
            rootCount = length(cv0) ?? 0
        }
        var delegated: V = .array([])
        if case let .array(ch)? = chain, ch.count > 1 {
            delegated = try sliceFrom(nn(opt(ch[ch.count - 1], "caveats"), .array([])), rootCount)
        }
        func classify(_ cv: V, _ isDelegated: Bool) -> JObject {
            let type = caveatType(cv), rest = caveatRest(cv)
            let satisfied: V?
            if canEval && truthy(ctxCaveat) && truthy(ctxAction) {
                satisfied = .bool(evalCaveat(cv, ctxCaveat, ctxAction))
            } else {
                satisfied = failedFromReasons.contains(JKey(type)) ? .bool(false) : rgs
            }
            var out: JObject = ["type": .string(type)]
            put(&out, "satisfied", satisfied)
            out["value"] = .object(Dictionary(uniqueKeysWithValues: rest.map { (JKey($0.0), $0.1) }))
            out["detail"] = .string(caveatDetail(type, rest, satisfied))
            out["delegated"] = .bool(isDelegated)
            if !truthy(satisfied) { out["remedy"] = .string(caveatRemedy(type, rest)) }
            return out
        }
        for cv in try iter(grantCaveats) { caveats.append(classify(cv, false)) }
        for cv in try iter(delegated) { caveats.append(classify(cv, true)) }

        // risk / tier
        let rt = get(decision, "requiredThreshold")
        let r = get(decision, "r")
        let envNN = env != nil && env != .null
        var riskPolicy: V?
        if envNN {
            riskPolicy = try rd(env, "risk_policy")
            if riskPolicy == nil || riskPolicy == .null { throw JSError("cannot read properties of undefined") }
        }
        let theta1 = opt(riskPolicy, "theta1"), theta2 = opt(riskPolicy, "theta2")
        let tier = get(rt, "t"), proof = get(rt, "proof"), optimistic = get(rt, "optimisticAllowed")
        var risk: JObject = [:]
        put(&risk, "r", r); put(&risk, "tier", tier); put(&risk, "proof", proof); put(&risk, "optimisticAllowed", optimistic)
        risk["band"] = .string(riskBand(r, theta1, theta2, tier))
        if hasEnv { put(&risk, "theta1", theta1); put(&risk, "theta2", theta2) }

        // admission / budget
        let kappa: V? = envNN ? get(riskPolicy, "kappa") : nil
        var costVal: Double?
        if let k = kappa {
            let kv = IV.num(k).flatMap { $0.isFinite ? $0 : nil } ?? 0
            costVal = Risk.cost(IV.num(r).flatMap { $0.isFinite ? $0 : nil } ?? 1, kappa: kv)
        }
        var budgetDepleted = false
        for x in reasons {
            if try reasonIncludes(x, "budget depleted") { budgetDepleted = true; break }
        }
        let path: String
        if admitted { path = "auto-admitted at t=\(str(tier)) (\(str(proof))); metered" }
        else if !truthy(rgs) { path = "guardian share withheld — policy not satisfied (no autonomous or guardian path)" }
        else if budgetDepleted { path = "trust budget cannot cover the cost — step-up to t=3 (human recharge) required" }
        else { path = "step-up to t=\(str(tier)) (\(str(proof))) co-signature required" }
        var admission: JObject = ["admit": .bool(admitted)]
        put(&admission, "needStepUp", get(decision, "needStepUp"))
        put(&admission, "releaseGuardianShare", rgs)
        put(&admission, "budget", get(decision, "budget"))
        admission["path"] = .string(path)
        if let c = costVal { admission["cost"] = numJSON(c) }
        if let k = kappa { admission["kappa"] = k }

        // the single decisive reason
        var decisive: (reason: V, remedy: String?)?
        if !admitted {
            if !truthy(grant["granted"]) {
                decisive = (nn(grant["reason"], .string("action not permitted by the envelope predicates (default-deny)")),
                            "grant a predicate that permits this verb+resource (and satisfies its where bound).")
            } else if let f = caveats.first(where: { !truthy($0["satisfied"]) }) {
                decisive = (.string("caveat '\(f["type"]?.asString ?? "")' narrowed the authority away: \(f["detail"]?.asString ?? "")"),
                            truthy(f["remedy"]) ? str(f["remedy"]) : nil)
            } else if budgetDepleted {
                decisive = (.string("risk \(num(r)) is admissible but the trust budget cannot cover cost κ·r\(costVal.map { "=" + num(numJSON($0)) } ?? "")"),
                            "recharge the budget with a human co-sign, or lower the action risk.")
            } else {
                decisive = (.string("risk \(num(r)) exceeds the auto threshold → step-up to t=\(str(tier)) (\(str(proof)))"),
                            IV.num(tier) == 3 ? "obtain a human step-up co-signature." : "obtain the guardian/principal co-signature for this tier.")
            }
        }

        let summary: String
        if admitted {
            let who = truthy(grant["predicate"]) ? "predicate #\(str(grant["predicateIndex"]))" : "policy"
            summary = "Auto-admitted: \(who) grants it, all caveats held, risk r=\(num(r)) is in the t=\(str(tier)) band and the budget covers it."
        } else if let d = decisive {
            summary = "\(verdict == "deny" && disposition == "denied" ? "Denied" : "Needs step-up"): \(str(d.reason))"
        } else {
            summary = "Not auto-admitted (t=\(str(tier)))."
        }

        var out: JObject = ["kind": .string("decision"), "verdict": .string(verdict), "disposition": .string(disposition), "grant": .object(grant),
                            "caveats": .array(caveats.map { c -> V in
                                var o = c; o["detail"] = .string(cleanText(c["detail"]?.asString ?? "")); return .object(o)
                            }), "risk": .object(risk), "admission": .object(admission)]
        if let d = decisive {
            var o: JObject = ["reason": .string(cleanText(str(d.reason)))]
            if let rem = d.remedy { o["remedy"] = .string(rem) }
            out["decisive"] = .object(o)
        }
        out["reasons"] = .array(reasons.map { .string(cleanText(str($0))) })
        out["summary"] = .string(cleanText(summary))
        return .object(out)
    }

    /// Render a decision explanation. Throws where the reference's renderer throws (a decision whose budget is missing).
    public static func decisionToText(_ e: JSONValue) throws -> String {
        var lines = ["PCA decision — \(str(get(e, "verdict")).uppercased()) (\(str(get(e, "disposition"))))", str(get(e, "summary")), ""]
        let gr = get(e, "grant")
        let pred = get(gr, "predicate")
        if truthy(get(gr, "granted")) && truthy(pred) {
            let pv = get(pred, "verb")
            let verbs: String
            if case let .array(a)? = pv { verbs = a.map { $0 == .null ? "" : str($0) }.joined(separator: "|") } else { verbs = str(pv) }
            lines.append("  authority : predicate #\(str(get(gr, "predicateIndex"))) of grant \(short(get(gr, "capabilityId"))) grants \(verbs) on \(str(nn(get(pred, "resource"), .string("*"))))")
            lines.append("              where \(str(get(gr, "where")))")
        } else {
            lines.append("  authority : NOT granted — \(str(nn(get(gr, "reason"), .string("no predicate permits this action"))))")
        }
        let caveats = get(e, "caveats")?.asArray ?? []
        if caveats.isEmpty {
            lines.append("  caveats   : none")
        } else {
            for c in caveats {
                lines.append("  caveat \(truthy(get(c, "satisfied")) ? "✓" : "✗")  : \(str(get(c, "detail")))\(truthy(get(c, "delegated")) ? " [delegated]" : "")")
                if !truthy(get(c, "satisfied")) && truthy(get(c, "remedy")) { lines.append("              ↳ fix: \(str(get(c, "remedy")))") }
            }
        }
        let risk = get(e, "risk")
        lines.append("  risk      : \(str(get(risk, "band"))); proof=\(str(get(risk, "proof"))), optimistic=\(str(get(risk, "optimisticAllowed")))")
        let a = get(e, "admission")
        let cost = get(a, "cost")
        let costStr = cost != nil ? ", cost κ·r=\(num(cost)) (κ=\(num(get(a, "kappa"))))" : ""
        lines.append("  budget    : \(str(get(a, "path")))\(costStr); B after=\(num(try rd(get(a, "budget"), "B")))")
        let dec = get(e, "decisive")
        if truthy(dec) {
            lines.append("")
            lines.append("  ◀ DECISIVE: \(str(get(dec, "reason")))")
            if truthy(get(dec, "remedy")) { lines.append("      ↳ fix: \(str(get(dec, "remedy")))") }
        }
        return lines.joined(separator: "\n")
    }

    // ---- explainChain ----

    private static func isBudgetAlloc(_ cv: V?) -> Bool {
        guard isObjOrArr(cv), get(cv, "type") == .string("budget_alloc"), let lim = IV.num(get(cv, "limit")) else { return false }
        return lim.isFinite && lim >= 0
    }

    /// The per-node budget subtree carried by a chain: one node per well-formed `budget_alloc` caveat, in delegation order. Reads the
    /// append-only caveat lineage; it does not verify signatures.
    public static func budgetAllocNodes(_ chain: [JSONValue]) throws -> [JSONValue] {
        var out: [V] = []
        guard let leaf = chain.last else { return out }
        guard case let .array(leafCvs)? = try rd(leaf, "caveats") else { return out }
        var hop = 0
        for (ci, cv) in leafCvs.enumerated() {
            while hop < chain.count - 1 {
                let n = length(try rd(chain[hop], "caveats")) ?? 0
                if n <= ci { hop += 1 } else { break }
            }
            guard isBudgetAlloc(cv) else { continue }
            let introducing = chain[hop]
            guard let capId = try rd(introducing, "id"),
                  let nodePath = IV.strictHash(.object(["d": .string("atlas-pca/budget-node/v1"), "cap": capId, "i": .int(Int64(ci))])) else {
                throw JSError("canonicalize: undefined member")
            }
            var node: JObject = ["nodePath": .string(nodePath), "capId": capId]
            put(&node, "holder", try rd(introducing, "holder"))
            node["depth"] = .int(Int64(hop))
            node["caveatIndex"] = .int(Int64(ci))
            node["limit"] = get(cv, "limit") ?? .null
            out.append(.object(node))
        }
        return out
    }

    private static func hopNarrowedSummary(_ isRoot: Bool, _ added: [V]) -> String {
        var bits: [String] = []
        for cv in added {
            let type = caveatType(cv), rest = caveatRest(cv)
            if type == "envelope" {
                let preds = restValue(rest, "predicates")?.asArray?.count ?? 0, inner = restValue(rest, "caveats")?.asArray?.count ?? 0
                bits.append("envelope (\(preds) predicate(s), \(inner) caveat(s))")
            } else if isBudgetAlloc(cv) {
                bits.append("budget_alloc(B_sub=\(num(get(cv, "limit"))))")
            } else {
                let bound = valueSummary(rest)
                bits.append(bound.isEmpty ? "+\(type)" : "+\(type)(\(bound))")
            }
        }
        if bits.isEmpty { return isRoot ? "root grant (no caveats)" : "rebind only (no new caveats)" }
        return (isRoot ? "grants " : "narrows: ") + bits.joined(separator: ", ")
    }

    private static func explainChainInner(_ chain: V?) throws -> JObject {
        let safe = chain?.asArray ?? []
        var hops: [V] = []
        for (i, cap) in safe.enumerated() where truthy(cap) {
            let isRoot = i == 0
            let parent: V? = i > 0 ? safe[i - 1] : nil
            let parentLen = truthy(parent) ? (get(parent, "caveats")?.asArray?.count ?? 0) : 0
            let own = get(cap, "caveats")?.asArray ?? []
            let added = isRoot ? own : own.count >= parentLen ? Array(own.dropFirst(parentLen)) : []
            var hop: JObject = ["index": .int(Int64(i)), "isRoot": .bool(isRoot)]
            put(&hop, "issuer", get(cap, "issuer"))
            put(&hop, "holder", get(cap, "holder"))
            hop["issuerShort"] = .string(short(get(cap, "issuer")))
            hop["holderShort"] = .string(short(get(cap, "holder")))
            hop["alg"] = nn(get(cap, "alg"), .string("ed25519"))
            hop["addedCaveats"] = .array(added)
            hop["addedCaveatTypes"] = .array(added.map { .string(caveatType($0)) })
            hop["narrowed"] = .string(cleanText(hopNarrowedSummary(isRoot, added)))
            if let b = added.first(where: { isBudgetAlloc($0) }) { hop["budgetAlloc"] = get(b, "limit") ?? .null }
            hops.append(.object(hop))
        }
        let root = safe.first, leaf = safe.last
        let nodes = try budgetAllocNodes(safe)
        let summary = safe.isEmpty ? "empty chain (no authority)"
            : "\(short(opt(root, "issuer"))) (principal) delegated through \(safe.count - 1) hop(s) to the acting holder \(short(opt(leaf, "holder"))); \(nodes.count) budget node(s)."
        var out: JObject = ["kind": .string("chain"), "depth": .int(Int64(safe.count)), "hops": .array(hops)]
        put(&out, "rootIssuer", opt(root, "issuer"))
        put(&out, "leafHolder", opt(leaf, "holder"))
        out["budgetNodes"] = .array(nodes)
        out["summary"] = .string(summary)
        return out
    }

    /// Render a delegation chain as an ordered attenuation trace: issuer to holder per hop and what each hop narrowed. With
    /// `opts.verify === true` the chain is also checked (`opts.expectedRootIssuer` pins the root issuer); otherwise the trace shows only
    /// what the chain claims. Throws where the reference throws (an `opts` that is null, a chain whose budget lineage cannot be read).
    public static func explainChain(_ chain: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        let o = opts ?? .object([:])
        var out = try explainChainInner(chain)
        guard isTrue(try rd(o, "verify")) else { return .object(out) }
        var ok = false
        var reason: String? = "chain is not an array"
        if case let .array(ch)? = chain {
            var expected: String?
            if let e = get(o, "expectedRootIssuer") { expected = e.asString ?? "\u{0}<not a string>" } // a non-string pin never equals an issuer
            reason = chainReason(ch, expected)
            ok = reason == nil
        }
        var v: JObject = ["ok": .bool(ok)]
        if let r = reason { v["reason"] = .string(cleanText(r)) }
        out["verification"] = .object(v)
        return .object(out)
    }

    /// Render a chain explanation.
    public static func chainToText(_ e: JSONValue) -> String {
        var lines = ["PCA delegation chain — \(str(get(e, "depth"))) hop(s) (attenuation trace)"]
        if let v = get(e, "verification") {
            lines.append(isTrue(get(v, "ok")) ? "verified: signatures, links and caveat rules hold."
                         : "NOT VALID: \(str(nn(get(v, "reason"), .string("the chain failed verification"))))")
        } else {
            lines.append("UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.")
        }
        lines.append(str(get(e, "summary")))
        lines.append("")
        for h in get(e, "hops")?.asArray ?? [] {
            lines.append("  #\(str(get(h, "index"))) \(isTrue(get(h, "isRoot")) ? "root " : "deleg") \(str(get(h, "issuerShort"))) ──▶ \(str(get(h, "holderShort")))   \(str(get(h, "narrowed")))")
        }
        let nodes = get(e, "budgetNodes")?.asArray ?? []
        if !nodes.isEmpty {
            lines.append("")
            lines.append("  budget subtree: " + nodes.map { "depth \(str(get($0, "depth"))) B_sub=\(num(get($0, "limit")))" }.joined(separator: " → "))
        }
        return lines.joined(separator: "\n")
    }
}
