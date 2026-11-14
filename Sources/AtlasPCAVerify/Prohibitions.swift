import Foundation

// The prohibition language: veto-polarity triggers, constitutions, the monitor, hash-chained monitor state, per-action safety evidence and
// the atomic check-and-advance kernel. A port of `prohibitions.ts` (the TypeScript is authoritative; reason texts are byte-identical).
//
// Everything works on `JSONValue` documents so a malformed or hostile document is judged the way the reference judges it (a JSON null is not
// an absent member, `String(x)` and truthiness follow ECMAScript). Nothing here traps; every function is total and fails closed.
// Where the reference reports "the first problem" of an object it follows key insertion order; a Swift dictionary carries none, so the first
// problem follows sorted key order (a document with one problem, which is every vector, reads the same).

/// A failure of an authoring-time or hashing step (the reference throws there; the verifying entry points turn it into a refusal).
struct PDFail: Error { let what: String }

/// ECMAScript value helpers shared by the prohibition, contract, forbid and gate ports.
enum PD {
    static func isObj(_ v: JSONValue?) -> Bool { if case .object? = v { return true }; return false }
    static func isArr(_ v: JSONValue?) -> Bool { if case .array? = v { return true }; return false }
    static func isNull(_ v: JSONValue?) -> Bool { if case .null? = v { return true }; return false }
    static func isStr(_ v: JSONValue?) -> Bool { if case .string? = v { return true }; return false }
    static func isBool(_ v: JSONValue?) -> Bool { if case .bool? = v { return true }; return false }

    /// `typeof x === 'number' && Number.isFinite(x)`.
    static func fin(_ v: JSONValue?) -> Double? {
        if let d = IV.num(v), d.isFinite { return d }
        return nil
    }

    /// `Number.isInteger(x)`.
    static func isInteger(_ v: JSONValue?) -> Bool {
        guard let d = fin(v) else { return false }
        return d == d.rounded(.towardZero)
    }

    /// `Object.is(x, -0)`.
    static func negZero(_ v: JSONValue?) -> Bool {
        if case let .double(d)? = v { return IV.isNegZero(d) }
        return false
    }

    /// A JSON number for a computed double (an integer-valued safe one is an `int`).
    static func num(_ d: Double) -> JSONValue {
        if d.isFinite, d == d.rounded(.towardZero), abs(d) <= Double(Canonical.MAX_SAFE), !IV.isNegZero(d) { return .int(Int64(d)) }
        return .double(d)
    }

    /// `x !== undefined` of an own member.
    static func has(_ o: JSONValue?, _ k: String) -> Bool { o?.asObject?[JKey(k)] != nil }

    /// JS truthiness of a JSON value (`undefined` is nil).
    static func truthy(_ v: JSONValue?) -> Bool {
        switch v {
        case nil, .null?: return false
        case let .bool(b)?: return b
        case let .int(i)?: return i != 0
        case let .double(d)?: return d != 0 && !d.isNaN
        case let .string(s)?: return !s.isEmpty
        default: return true
        }
    }

    /// ECMAScript `Number::toString`.
    static func numStr(_ v: Double) -> String {
        if v.isNaN { return "NaN" }
        if v.isInfinite { return v > 0 ? "Infinity" : "-Infinity" }
        if v == 0 { return "0" }
        let sign = v < 0 ? "-" : ""
        let r = "\(abs(v))" // the shortest round-trip digits: "1.5", "1e-07", "1.2345e+25", "100.0"
        var mant = r
        var e = 0
        if let ei = r.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            mant = String(r[..<ei])
            e = Int(r[r.index(after: ei)...]) ?? 0
        }
        var ip = mant
        var fp = ""
        if let dot = mant.firstIndex(of: ".") {
            ip = String(mant[..<dot])
            fp = String(mant[mant.index(after: dot)...])
        }
        if fp == "0" { fp = "" }
        let all = Array(ip + fp)
        let lead = all.prefix(while: { $0 == "0" }).count
        var digits = Array(all.dropFirst(lead))
        let n = ip.count + e - lead // value = 0.digits x 10^n
        while digits.last == "0" { digits.removeLast() }
        let k = digits.count
        let ds = String(digits)
        let s: String
        if k <= n && n <= 21 {
            s = ds + String(repeating: "0", count: n - k)
        } else if 0 < n && n <= 21 {
            s = String(digits[..<n]) + "." + String(digits[n...])
        } else if -6 < n && n <= 0 {
            s = "0." + String(repeating: "0", count: -n) + ds
        } else {
            let ex = n - 1
            let es = (ex >= 0 ? "+" : "-") + String(abs(ex))
            s = k == 1 ? ds + "e" + es : String(digits[0]) + "." + String(digits[1...]) + "e" + es
        }
        return sign + s
    }

    /// ECMAScript `String(x)` of a JSON value (`undefined` is nil).
    static func js(_ v: JSONValue?, _ depth: Int = 0) -> String {
        switch v {
        case nil: return "undefined"
        case .null?: return "null"
        case let .bool(b)?: return b ? "true" : "false"
        case let .int(i)?: return numStr(Double(i))
        case let .double(d)?: return numStr(d)
        case let .string(s)?: return s
        case let .array(a)?:
            if depth > 64 { return "" }
            return a.map { x -> String in if case .null = x { return "" }; return js(x, depth + 1) }.joined(separator: ",")
        case .object?: return "[object Object]"
        }
    }

    /// `array.join(',')`.
    static func join(_ a: [JSONValue]) -> String {
        a.map { x -> String in if case .null = x { return "" }; return js(x) }.joined(separator: ",")
    }

    /// JS `o.k` for an object that is not null: a primitive has no members (undefined); null throws.
    static func prop(_ o: JSONValue?, _ k: String) throws -> JSONValue? {
        if o == nil || PD.isNull(o) { throw PDFail(what: "cannot read properties of null") }
        return o?.asObject?[JKey(k)]
    }

    /// `hashCanonical(v)` (strict canonical form); throws where the reference throws.
    static func hash(_ v: JSONValue) throws -> String {
        guard let h = IV.strictHash(v) else { throw PDFail(what: "canonicalize") }
        return h
    }

    /// `domain || sha256(id)`, the message every signed prohibition / contract artifact signs.
    static func domainMessage(_ domain: String, _ id: String) -> [UInt8] {
        Canonical.utf8(domain) + Canonical.sha256(Canonical.utf8(id))
    }

    /// `Math.max` (NaN wins).
    static func jsMax(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : max(a, b) }
    static func jsMin(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : min(a, b) }

    static func str(_ s: String) -> JSONValue { .string(s) }
    static func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
    static func idx(_ i: Int) -> JKey { JKey(String(i)) }
}

/// `{ok, reason?}` of a verification.
public struct ProhibitionVerdict: Equatable, Sendable {
    public let ok: Bool
    public let reason: String?
    public static let pass = ProhibitionVerdict(ok: true, reason: nil)
    public static func no(_ r: String) -> ProhibitionVerdict { ProhibitionVerdict(ok: false, reason: r) }
    public var json: JSONValue {
        var o: JObject = ["ok": .bool(ok)]
        if let r = reason { o["reason"] = .string(r) }
        return .object(o)
    }
}

/// The outcome of evaluating a constitution against one action.
public struct ProhibitionResult: Sendable {
    public var ok: Bool
    /// Ids of violated invariants (or `<constitution>` / `<action>` / `<state>` for structural failures).
    public var violated: [String]
    public var reasons: [String]
    /// Every invariant considered, in constitution order: `{id, kind, result: pass|violated, reason?}`.
    public var evaluated: [JSONValue]
    public var json: JSONValue {
        .object(["ok": .bool(ok), "violated": PD.strs(violated), "reasons": PD.strs(reasons), "evaluated": .array(evaluated)])
    }
}

/// The outcome of a strict state transition.
public struct AdvanceStateResult: Sendable {
    public let ok: Bool
    /// The next monitor state when `ok`.
    public let state: JSONValue?
    public let reason: String?
}

/// `composeAuthority`: `allow = permitted AND prohibitions.ok`.
public struct ComposedDecision: Sendable {
    public let allow: Bool
    /// `prohibition` whenever a veto fired, `permission` when merely not granted, `none` = allowed.
    public let decidedBy: String
    public let permitted: Bool
    public let prohibition: ProhibitionResult
}

/// `checkAndAdvance`: `next` equals the input state unless `allow`.
public struct CheckAndAdvanceResult: Sendable {
    public let allow: Bool
    public let decidedBy: String
    /// Evidence over the PRE-transition state.
    public let evidence: JSONValue
    public let prohibition: ProhibitionResult
    public let next: JSONValue
    public let reason: String?
}

public enum Prohibitions {
    public static let CONSTITUTION_VERSION = 1
    public static let CONSTITUTION_SIG_DOMAIN = "atlas-pca/constitution/v1\u{0}"
    public static let EVIDENCE_VERSION = 1
    public static let SAFETY_EVIDENCE_SIG_DOMAIN = "atlas-pca/safety-evidence/v1\u{0}"
    public static let STATE_DIGEST_DOMAIN = "atlas-pca/monitor-state/v1"
    public static let STATE_CHAIN_DOMAIN = "atlas-pca/monitor-state-link/v1"
    public static let MAX_LEDGER = 10_000
    public static let MAX_INVARIANTS = 256
    public static let MAX_DEADLINE = 1_000_000
    public static let UNHASHABLE = "<unhashable>"
    static let MAX_STATE_ENTRIES = 100_000
    static let MAX_STATE_KEYS = 1024
    static let MAX_ID_LEN = 128
    static let MAX_CONDITION_DEPTH = 32
    static let FORBIDDEN_IDS = ["__proto__", "constructor", "prototype"]
    static let OPS = ["eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of"]

    static func forbiddenId(_ s: String) -> Bool { FORBIDDEN_IDS.contains { IV.same($0, s) } }

    // ---- genesis, commitment ---------------------------------------------------------------------------------------------------

    /// Genesis monitor state at time `now`: empty ledger, no latches, seq 0, no parent.
    public static func emptyState(_ now: Double) -> JSONValue { emptyState(rawNow: PD.num(now)) }

    /// As the reference, which stores whatever `now` it is given (a string or null stays one).
    static func emptyState(rawNow now: JSONValue) -> JSONValue {
        .object(["now": now, "seq": .int(0), "parent": .null, "ledger": .object([:]), "latched": .object([:])])
    }

    static func body(_ c: JObject) -> JObject {
        var b = c
        b[JKey("id")] = nil
        b[JKey("sig")] = nil
        return b
    }

    /// Content address of a constitution body. Throws only on non-canonicalizable input (authoring time).
    public static func constitutionId(_ c: JSONValue) throws -> String {
        guard case let .object(o) = c else { throw PDFail(what: "not an object") }
        return try PD.hash(.object(body(o)))
    }

    /// The principal signs the constitution. Refuses to sign a malformed one.
    public static func signConstitution(_ c: JSONValue, principal: PCAEdKey) throws -> JSONValue {
        let problems = validateConstitution(c)
        if !problems.isEmpty { throw PCAProducerError("signConstitution: " + problems.joined(separator: "; ")) }
        guard case let .object(o) = c else { throw PCAProducerError("signConstitution: not an object") }
        let id = try constitutionId(c)
        var out = body(o)
        out["id"] = .string(id)
        out["sig"] = .string(Base64URLStrict.encode(try principal.sign(PD.domainMessage(CONSTITUTION_SIG_DOMAIN, id))))
        return .object(out)
    }

    /// Well-formed, id matches content, signature by `expectedPrincipal` (or the embedded one). Never throws.
    public static func verifyConstitution(_ sc: JSONValue?, expectedPrincipal: String? = nil) -> ProhibitionVerdict {
        verifySigned(sc, expectedPrincipal, CONSTITUTION_SIG_DOMAIN, validateConstitution)
    }

    /// The shared verification of a signed constitution / contract.
    static func verifySigned(_ sc: JSONValue?, _ expectedPrincipal: String?, _ domain: String, _ validate: (JSONValue?) -> [String]) -> ProhibitionVerdict {
        let problems = validate(sc)
        if let p = problems.first { return .no(p) }
        guard case let .object(o)? = sc, let principal = o["principal"]?.asString else { return .no("verification error (fail closed)") }
        if let ep = expectedPrincipal, !IV.same(principal, ep) { return .no("principal mismatch") }
        guard let id = o["id"]?.asString else { return .no("id does not match content") }
        let cid: String
        do { cid = try PD.hash(.object(body(o))) } catch { return .no("verification error (fail closed)") }
        if !IV.same(id, cid) { return .no("id does not match content") }
        guard let sig = o["sig"]?.asString, Ed25519Strict.verifyB64u(principal, PD.domainMessage(domain, id), sig) else { return .no("bad signature") }
        return .pass
    }

    // ---- validation (strict; unknown forms are rejected, never ignored) --------------------------------------------------------

    static func validateCondition(_ c: JSONValue?, _ depth: Int = 0) -> String? {
        guard case let .object(o)? = c else { return "condition not an object" }
        if depth > MAX_CONDITION_DEPTH { return "condition nesting too deep" }
        if o["all_of"] != nil || o["any_of"] != nil || o["not"] != nil {
            if let n = o["not"] { return validateCondition(n, depth + 1) }
            let key = o["all_of"] != nil ? "all_of" : "any_of"
            guard case let .array(arr)? = o[JKey(key)], !arr.isEmpty else { return "condition.\(key) must be a non-empty array" }
            for child in arr { if let e = validateCondition(child, depth + 1) { return e } }
            return nil
        }
        guard case let .string(field)? = o["field"], !field.isEmpty else { return "condition.field missing" }
        guard case let .string(op)? = o["op"], OPS.contains(where: { IV.same($0, op) }) else { return "unknown condition op \(PD.js(o["op"]))" }
        if let r = o["ref"] {
            if case let .string(s) = r, !s.isEmpty {} else { return "bad condition.ref" }
        }
        if IV.same(op, "member_of"), let col = o["collection"] {
            if case let .string(s) = col, !s.isEmpty {} else { return "bad condition.collection" }
        }
        return nil
    }

    static func validateConditions(_ cs: JSONValue?, _ label: String) -> String? {
        guard case let .array(a)? = cs, !a.isEmpty else { return "\(label) must be a non-empty array" }
        for c in a { if let e = validateCondition(c) { return e } }
        return nil
    }

    /// The structural problem of a trigger `{verb, resource?, where?}` (nil = well formed).
    public static func validateWhen(_ w: JSONValue?, _ label: String) -> String? {
        guard case let .object(o)? = w else { return "\(label): not an object" }
        var verbOk = false
        switch o["verb"] {
        case let .string(s)?: verbOk = !s.isEmpty
        case let .array(a)?:
            verbOk = !a.isEmpty && a.allSatisfy { x in if case let .string(s) = x, !s.isEmpty { return true }; return false }
        default: break
        }
        if !verbOk { return "\(label): bad verb" }
        if let r = o["resource"] {
            guard case let .string(res) = r else { return "\(label): bad resource" }
            if IV.startsWith(res, "re:") {
                let src = IV.dropPrefix(res, 3)
                // an unsafe, over-long or uncompilable regex would make the matcher return false: the veto would silently NOT apply
                if IV.u16(src) > 200 || !SafeRegex.isSafeSource(Array(src.utf16)) { return "\(label): unsafe regex resource" }
            }
        }
        if let wh = o["where"] {
            guard case let .array(conds) = wh else { return "\(label): where not an array" }
            for c in conds { if let e = validateCondition(c) { return "\(label): \(e)" } }
        }
        return nil
    }

    static func actionPath(_ v: JSONValue?) -> Bool {
        if case let .string(s)? = v { return IV.startsWith(s, "action.") }
        return false
    }

    /// Structural problems with an invariant (empty = well-formed).
    public static func validateInvariant(_ inv: JSONValue?) -> [String] {
        guard case let .object(o)? = inv else { return ["invariant not an object"] }
        guard case let .string(id)? = o["id"], !id.isEmpty else { return ["<no id>: missing id"] }
        func err(_ m: String) -> [String] { ["\(id): \(m)"] }
        if IV.u16(id) > MAX_ID_LEN { return err("id too long") }
        if forbiddenId(id) { return err("forbidden id") }
        let kind = o["kind"]
        switch kind?.asString {
        case "never"?:
            if let e = validateWhen(o["when"], "when") { return err(e) }
            return []
        case "never_unless"?:
            if let e = validateWhen(o["when"], "when") { return err(e) }
            if let e = validateConditions(o["unless"], "unless") { return err(e) }
            return []
        case "cap"?:
            if let e = validateWhen(o["when"], "when") { return err(e) }
            if !actionPath(o["amount"]) { return err("amount must be an action.* path") }
            guard let mx = PD.fin(o["max"]), mx >= 0 else { return err("max must be a finite number >= 0") }
            if let ws = o["window_secs"] {
                guard let w = PD.fin(ws), w > 0 else { return err("bad window_secs") }
            }
            return []
        case "rate"?:
            if let e = validateWhen(o["when"], "when") { return err(e) }
            let m = o["max"]
            guard PD.isInteger(m), let mv = IV.num(m), mv >= 0, !PD.negZero(m), mv <= Double(MAX_LEDGER) else { return err("max must be an integer in [0,10000]") }
            guard let w = PD.fin(o["window_secs"]), w > 0 else { return err("window_secs must be > 0") }
            return []
        case "never_after"?:
            if let e = validateWhen(o["after"], "after") ?? validateWhen(o["forbid"], "forbid") { return err(e) }
            return []
        case "require_prior"?:
            if let e = validateWhen(o["when"], "when") ?? validateWhen(o["prior"], "prior") { return err(e) }
            return []
        case "require_approval_over"?:
            if let e = validateWhen(o["when"], "when") { return err(e) }
            if !actionPath(o["amount"]) { return err("amount must be an action.* path") }
            guard let th = PD.fin(o["threshold"]), th >= 0 else { return err("threshold must be a finite number >= 0") }
            if let e = validateConditions(o["approved"], "approved") { return err(e) }
            return []
        default:
            return err("unknown invariant kind \(PD.js(kind))")
        }
    }

    /// Structural problems with a constitution (empty = well-formed).
    public static func validateConstitution(_ c: JSONValue?) -> [String] {
        guard case let .object(o)? = c else { return ["constitution not an object"] }
        var out: [String] = []
        let version = o["version"]
        if !(IV.num(version) == Double(CONSTITUTION_VERSION)) { out.append("unsupported version \(PD.js(version))") }
        if case let .string(p)? = o["principal"], !p.isEmpty {} else { out.append("principal missing") }
        guard case let .array(invs)? = o["invariants"] else { return out + ["invariants not an array"] }
        if invs.count > MAX_INVARIANTS { out.append("too many invariants") }
        var seen = Set<JKey>()
        for inv in invs {
            out.append(contentsOf: validateInvariant(inv))
            if case let .string(id)? = inv.asObject?[JKey("id")] {
                if seen.contains(JKey(id)) { out.append("\(id): duplicate id") }
                seen.insert(JKey(id))
            }
        }
        return out
    }

    // ---- canonical monitor state -----------------------------------------------------------------------------------------------

    /// The structural problem of a monitor state (nil = well-formed). Total.
    public static func stateProblem(_ state: JSONValue?) -> String? {
        guard case let .object(s)? = state, let now = PD.fin(s["now"]), case let .object(ledger)? = s["ledger"], case let .object(latched)? = s["latched"] else {
            return "malformed monitor state"
        }
        let seqV = s["seq"]
        guard PD.isInteger(seqV), let seq = IV.num(seqV), seq >= 0, !PD.negZero(seqV) else { return "malformed monitor state: seq" }
        let parent = s["parent"]
        switch parent {
        case .null?, .string?: break
        default: return "malformed monitor state: parent"
        }
        let genesis = PD.isNull(parent)
        if seq == 0 && !genesis { return "malformed monitor state: genesis has a parent" }
        if seq > 0 && genesis { return "malformed monitor state: missing chain link" }
        if ledger.count > MAX_STATE_KEYS || latched.count > MAX_STATE_KEYS { return "malformed monitor state: too many keys" }
        var total = 0
        for k in ledger.keys.sorted() {
            if forbiddenId(k.s) || IV.u16(k.s) > MAX_ID_LEN { return "malformed monitor state: bad ledger key" }
            guard case let .array(l)? = ledger[k], l.count <= MAX_LEDGER else { return "malformed monitor state: bad ledger" }
            total += l.count
            for e in l {
                guard PD.isObj(e), PD.fin(e.get("t")) != nil, let amount = PD.fin(e.get("amount")), amount >= 0 else { return "malformed monitor state: bad ledger entry" }
                // an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
                if PD.fin(e.get("t"))! > now { return "malformed monitor state: ledger entry after now (clock regression)" }
            }
        }
        if total > MAX_STATE_ENTRIES { return "malformed monitor state: too many entries" }
        for k in latched.keys.sorted() {
            if forbiddenId(k.s) || IV.u16(k.s) > MAX_ID_LEN { return "malformed monitor state: bad latch key" }
            guard let t = PD.fin(latched[k]), !(t > now) else { return "malformed monitor state: bad latch" }
        }
        // additive, optional: bounded-liveness deadline budgets (contracts); absent / empty is a plain state
        if let dlv = s["deadlines"] {
            guard case let .object(dl) = dlv else { return "malformed monitor state: deadlines" }
            if dl.count > MAX_STATE_KEYS { return "malformed monitor state: too many deadline keys" }
            for k in dl.keys.sorted() {
                if forbiddenId(k.s) || IV.u16(k.s) > MAX_ID_LEN { return "malformed monitor state: bad deadline key" }
                guard PD.isInteger(dl[k]), let d = IV.num(dl[k]), d >= 1, d <= Double(MAX_DEADLINE) else { return "malformed monitor state: bad deadline" }
            }
        }
        return nil
    }

    static func entryLess(_ a: JSONValue, _ b: JSONValue) -> Bool {
        let ta = IV.num(a.get("t")) ?? 0, tb = IV.num(b.get("t")) ?? 0
        if ta != tb { return ta < tb }
        return (IV.num(a.get("amount")) ?? 0) < (IV.num(b.get("amount")) ?? 0)
    }

    /// Canonical form of a state: unknown fields dropped, ledger entries reduced to `{t, amount}` and sorted, empty ledger arrays omitted.
    /// Throws on a malformed state.
    public static func canonicalState(_ state: JSONValue?) throws -> JSONValue {
        if let p = stateProblem(state) { throw PDFail(what: p) }
        guard case let .object(s)? = state, case let .object(ledger)? = s["ledger"], let latched = s["latched"] else { throw PDFail(what: "malformed monitor state") }
        var outLedger: JObject = [:]
        for (k, v) in ledger {
            let entries = (v.asArray ?? []).map { e -> JSONValue in .object(["t": e.get("t") ?? .null, "amount": e.get("amount") ?? .null]) }.sorted(by: entryLess)
            if !entries.isEmpty { outLedger[k] = .array(entries) }
        }
        var base: JObject = ["d": .string(STATE_DIGEST_DOMAIN), "now": s["now"] ?? .null, "seq": s["seq"] ?? .null, "parent": s["parent"] ?? .null,
                             "ledger": .object(outLedger), "latched": latched]
        if case let .object(dl)? = s["deadlines"], !dl.isEmpty { base["deadlines"] = .object(dl) }
        return .object(base)
    }

    /// Deterministic digest of the canonical state. Throws if malformed.
    public static func stateDigest(_ state: JSONValue?) throws -> String { try PD.hash(canonicalState(state)) }

    /// `safe(() => ...)`: the digest, or `<unhashable>`.
    static func safeDigest(_ f: () throws -> String) -> String { (try? f()) ?? UNHASHABLE }

    /// The same state at a later `now`; refuses regression. Never throws.
    public static func tickState(_ state: JSONValue?, now: Double) -> (ok: Bool, state: JSONValue?, reason: String?) {
        if stateProblem(state) != nil { return (false, nil, "malformed monitor state") }
        guard now.isFinite, case var .object(s)? = state, let cur = PD.fin(s["now"]), !(now < cur) else { return (false, nil, "clock regression") }
        s["now"] = PD.num(now)
        return (true, .object(s), nil)
    }

    // ---- matching (conservative: unresolvable => MATCHED) ----------------------------------------------------------------------

    /// Does a prohibition trigger match? Verb and resource exactly as the permission DSL; the where-conditions conservatively. FULLY fail-closed:
    /// a malformed trigger, an unsafe regex, an oversized regex subject, an unknown op, a missing field or operand, unavailable params or
    /// incomparable operands all count as MATCHED (the veto applies). A regex evaluation REFUSED by the document budget is "could not
    /// decide", never "no match". `scope` is the enclosing document's regex budget (nil: every evaluation has its own, and a refusal inside
    /// it is not visible here, as in the reference). Never throws.
    static func whenMatches(_ w: JSONValue?, _ ctx: JSONValue?, scope: SafeRegex.Budget? = nil) -> Bool {
        if validateWhen(w, "when") != nil { return true }
        guard case let .object(wo)? = w, let c = ctx, let a = c.get("action"), a.get("verb")?.asString != nil, let actionResource = a.get("resource")?.asString else { return true }
        var oversized = false
        if case let .string(r)? = wo["resource"], IV.startsWith(r, "re:"), IV.u16(actionResource) > Predicates.MAX_RE_RESOURCE_LEN { oversized = true }
        // an oversized subject for a regex resource: the matcher would say "no match", a veto must say "match"
        let refused0 = scope?.refusals ?? 0
        var trigger: JObject = ["verb": wo["verb"] ?? .null]
        if !oversized, let r = wo["resource"] { trigger["resource"] = r }
        if !Predicates.predicateMatches(.object(trigger), c, scope ?? SafeRegex.Budget()) {
            if (scope?.refusals ?? 0) == refused0 { return false }
        }
        if case let .array(conds)? = wo["where"] {
            for cond in conds where Predicates.conditionTri(cond, c, scope ?? SafeRegex.Budget()) == .f { return false }
        }
        return true
    }

    /// AFFIRMATIVE trigger match (plain permission semantics, unresolvable = not matched).
    static func whenAffirmative(_ w: JSONValue?, _ ctx: JSONValue?, scope: SafeRegex.Budget? = nil) -> Bool {
        guard validateWhen(w, "when") == nil, let wv = w else { return false }
        return Predicates.predicateMatches(wv, ctx ?? .null, scope ?? SafeRegex.Budget())
    }

    /// `evaluateCondition(c, ctx)`: cleanly decided true.
    static func conditionHolds(_ c: JSONValue, _ ctx: JSONValue, _ scope: SafeRegex.Budget) -> Bool {
        Predicates.conditionTri(c, ctx, scope) == .t
    }

    static func allHold(_ cs: JSONValue?, _ ctx: JSONValue, _ scope: SafeRegex.Budget) -> Bool {
        (cs?.asArray ?? []).allSatisfy { conditionHolds($0, ctx, scope) }
    }

    // ---- the monitor -----------------------------------------------------------------------------------------------------------

    /// Window entries (sorted so float sums are order-independent). `state` must already be validated.
    static func windowEntries(_ state: JObject, _ id: String, _ windowSecs: JSONValue?) -> [JSONValue] {
        guard case let .object(ledger)? = state["ledger"], case let .array(l)? = ledger[JKey(id)] else { return [] }
        let now = PD.fin(state["now"]) ?? 0
        let lo: Double = windowSecs == nil ? -Double.infinity : now - (IV.num(windowSecs) ?? 0) * 1000
        return l.filter { e in
            let t = IV.num(e.get("t")) ?? 0
            return t > lo && t <= now
        }.sorted(by: entryLess)
    }

    static func reason(_ inv: JObject, _ def: String) -> JSONValue {
        if let d = inv["description"], !d.isNull { return d }
        return .string(def)
    }

    static func evalOne(_ inv: JObject, _ ctx: JSONValue, _ state: JObject, _ scope: SafeRegex.Budget) -> (ok: Bool, reason: JSONValue?) {
        let kind = inv["kind"]?.asString ?? ""
        let id = inv["id"]?.asString ?? ""
        switch kind {
        case "never":
            return whenMatches(inv["when"], ctx, scope: scope) ? (false, reason(inv, "forbidden action")) : (true, nil)
        case "never_unless":
            if !whenMatches(inv["when"], ctx, scope: scope) { return (true, nil) }
            // exceptions must hold AFFIRMATIVELY (unresolvable => false => still forbidden)
            return allHold(inv["unless"], ctx, scope) ? (true, nil) : (false, reason(inv, "forbidden without required condition"))
        case "cap":
            if !whenMatches(inv["when"], ctx, scope: scope) { return (true, nil) }
            let a = Predicates.resolve(ctx, inv["amount"]?.asString ?? "")
            guard let av = a, let amount = PD.fin(av), amount >= 0 else { return (false, .string("amount unresolvable (fail closed)")) }
            var spent = 0.0
            for e in windowEntries(state, id, inv["window_secs"]) { spent += IV.num(e.get("amount")) ?? 0 }
            let mx = IV.num(inv["max"]) ?? 0
            if spent + amount <= mx { return (true, nil) }
            return (false, .string("cap exceeded: \(PD.numStr(spent)) + \(PD.js(av)) > \(PD.js(inv["max"]))"))
        case "rate":
            if !whenMatches(inv["when"], ctx, scope: scope) { return (true, nil) }
            let n = windowEntries(state, id, inv["window_secs"]).count
            if Double(n + 1) <= (IV.num(inv["max"]) ?? 0) { return (true, nil) }
            return (false, .string("rate exceeded: \(n + 1) > \(PD.js(inv["max"])) per \(PD.js(inv["window_secs"]))s"))
        case "never_after":
            if !PD.has(state["latched"], id) || !whenMatches(inv["forbid"], ctx, scope: scope) { return (true, nil) }
            return (false, reason(inv, "forbidden after trigger"))
        case "require_prior":
            if !whenMatches(inv["when"], ctx, scope: scope) { return (true, nil) }
            return PD.has(state["latched"], id) ? (true, nil) : (false, reason(inv, "required prior action not admitted"))
        case "require_approval_over":
            if !whenMatches(inv["when"], ctx, scope: scope) { return (true, nil) }
            let a = Predicates.resolve(ctx, inv["amount"]?.asString ?? "")
            let threshold = IV.num(inv["threshold"]) ?? 0
            var over = true // unresolvable => treated as over
            if let av = a, let amount = PD.fin(av), amount >= 0 { over = amount > threshold }
            if !over { return (true, nil) }
            return allHold(inv["approved"], ctx, scope) ? (true, nil) : (false, reason(inv, "approval required over \(PD.js(inv["threshold"]))"))
        default:
            return (false, .string("evaluation error (fail closed)")) // unreachable after validation
        }
    }

    static func actionOk(_ action: JSONValue?) -> Bool {
        guard let a = action?.get("action") else { return false }
        return a.get("verb")?.asString != nil && a.get("resource")?.asString != nil
    }

    static func structural(_ id: String, _ reason: String) -> ProhibitionResult {
        ProhibitionResult(ok: false, violated: [id], reasons: [reason], evaluated: [.object(["id": .string(id), "kind": .string("structural"), "result": .string("violated"), "reason": .string(reason)])])
    }

    /// Evaluate EVERY invariant (no short-circuit) against the action and running state. Pure, total, fail-closed. The whole constitution is one
    /// document: every invariant and condition shares one regex budget.
    public static func checkProhibitions(_ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?) -> ProhibitionResult {
        checkProhibitions(action, constitution, state, scope: SafeRegex.Budget())
    }

    /// `checkProhibitions` inside an enclosing document's regex budget (a contract: its constitution and clauses are ONE document).
    static func checkProhibitions(_ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?, scope: SafeRegex.Budget) -> ProhibitionResult {
        if let cp = validateConstitution(constitution).first { return structural("<constitution>", cp) }
        if !actionOk(action) { return structural("<action>", "malformed action") }
        if let sp = stateProblem(state) { return structural("<state>", sp) }
        guard let act = action, case let .object(st)? = state, case let .array(invs)? = constitution?.get("invariants") else { return structural("<monitor>", "monitor error (fail closed)") }
        var evaluated: [JSONValue] = []
        for invV in invs {
            guard case let .object(inv) = invV else { continue }
            let r = evalOne(inv, act, st, scope)
            var row: JObject = ["id": inv["id"] ?? .null, "kind": inv["kind"] ?? .null, "result": .string(r.ok ? "pass" : "violated")]
            if let why = r.reason, PD.truthy(why) { row["reason"] = why }
            evaluated.append(.object(row))
        }
        let bad = evaluated.filter { $0.get("result")?.asString == "violated" }
        return ProhibitionResult(
            ok: bad.isEmpty,
            violated: bad.map { $0.get("id")?.asString ?? "" },
            reasons: bad.map { "\($0.get("id")?.asString ?? ""): \($0.get("reason").map { PD.js($0) } ?? "violated")" },
            evaluated: evaluated)
    }

    static func entry(_ t: JSONValue, _ amount: JSONValue) -> JSONValue { .object(["t": t, "amount": amount]) }

    /// Pure, deterministic state transition for an ADMITTED action: records cap / rate contributions, latches `never_after` / `require_prior`
    /// triggers, prunes expired window entries, bounds the ledger, then extends the hash chain (`seq + 1`, `parent`). `now` defaults to
    /// `state.now`. Never throws; `ok: false` on anything it cannot record faithfully.
    public static func advanceStateStrict(_ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?, now nowIn: Double? = nil) -> AdvanceStateResult {
        advanceInner(action, constitution, state, nowIn, SafeRegex.Budget())
    }

    static func advanceInner(_ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?, _ nowIn: Double?, _ scope: SafeRegex.Budget) -> AdvanceStateResult {
        func no(_ r: String) -> AdvanceStateResult { AdvanceStateResult(ok: false, state: nil, reason: r) }
        if let cp = validateConstitution(constitution).first { return no(cp) }
        if let sp = stateProblem(state) { return no(sp) }
        guard case let .object(st)? = state, let stateNow = PD.fin(st["now"]), let seq = IV.num(st["seq"]) else { return no("malformed monitor state") }
        let now = nowIn ?? stateNow
        if !now.isFinite || now < stateNow { return no("clock regression") }
        if !actionOk(action) { return no("malformed action") }
        guard let act = action, case let .array(invs)? = constitution?.get("invariants") else { return no("advance error (fail closed)") }
        do {
            let canon = try canonicalState(state)
            let prevDigest = try PD.hash(canon)
            let actionDigest = try PD.hash(act)
            var ledger: JObject = canon.get("ledger")?.asObject ?? [:]
            var latched: JObject = canon.get("latched")?.asObject ?? [:]
            for invV in invs {
                guard case let .object(inv) = invV, let id = inv["id"]?.asString, let kind = inv["kind"]?.asString else { continue }
                if kind == "cap" || kind == "rate" {
                    let prev = ledger[JKey(id)]?.asArray ?? []
                    let lo: Double = inv["window_secs"] == nil ? -Double.infinity : now - (IV.num(inv["window_secs"]) ?? 0) * 1000
                    var kept = prev.filter { (IV.num($0.get("t")) ?? 0) > lo }
                    if whenMatches(inv["when"], act, scope: scope) {
                        var amount: JSONValue = .int(1)
                        if kind == "cap" {
                            guard let rv = Predicates.resolve(act, inv["amount"]?.asString ?? ""), PD.fin(rv) != nil, (IV.num(rv) ?? -1) >= 0 else {
                                return no("\(id): amount unresolvable")
                            }
                            amount = rv
                        }
                        kept.append(entry(PD.num(now), amount))
                    }
                    kept.sort(by: entryLess)
                    if kept.count > MAX_LEDGER {
                        if kind == "rate" { return no("\(id): rate ledger overflow") }
                        while kept.count > MAX_LEDGER {
                            // merge the oldest two; keeps the LATER time => never under-counts a cap
                            let x = kept[0], y = kept[1]
                            kept.removeFirst(2)
                            kept.insert(entry(y.get("t") ?? .null, PD.num((IV.num(x.get("amount")) ?? 0) + (IV.num(y.get("amount")) ?? 0))), at: 0)
                        }
                    }
                    if kept.isEmpty { ledger[JKey(id)] = nil } else { ledger[JKey(id)] = .array(kept) }
                } else if kind == "never_after" {
                    // conservative match: an ambiguous trigger latches (stricter)
                    if latched[JKey(id)] == nil && whenMatches(inv["after"], act, scope: scope) { latched[JKey(id)] = PD.num(now) }
                } else if kind == "require_prior" {
                    // AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
                    if latched[JKey(id)] == nil && whenAffirmative(inv["prior"], act, scope: scope) { latched[JKey(id)] = PD.num(now) }
                }
            }
            let parent = try PD.hash(.object(["d": .string(STATE_CHAIN_DOMAIN), "state": .string(prevDigest), "action": .string(actionDigest)]))
            let next: JSONValue = .object(["now": PD.num(now), "seq": PD.num(seq + 1), "parent": .string(parent), "ledger": .object(ledger), "latched": .object(latched)])
            if stateProblem(next) != nil { return no("resulting state invalid") }
            return AdvanceStateResult(ok: true, state: next, reason: nil)
        } catch {
            return no("advance error (fail closed)")
        }
    }

    /// `advanceStateStrict` that returns the INPUT state unchanged on failure. Prefer the strict form wherever a silent no-op would under-count a cap.
    public static func advanceState(_ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue, now: Double? = nil) -> JSONValue {
        let r = advanceStateStrict(action, constitution, state, now: now)
        return r.ok ? (r.state ?? state) : state
    }

    // ---- per-action safety evidence --------------------------------------------------------------------------------------------

    /// Build the evidence a verifier re-checks. Never throws.
    public static func proveSafety(_ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?) -> JSONValue {
        evidenceFrom(checkProhibitions(action, constitution, state), action, constitution, state)
    }

    static func evidenceFrom(_ r: ProhibitionResult, _ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?) -> JSONValue {
        let cid = safeDigest { guard let c = constitution else { throw PDFail(what: "constitution") }; return try constitutionId(c) }
        let adg = safeDigest { guard let a = action else { throw PDFail(what: "action") }; return try PD.hash(a) }
        let sdg = safeDigest { try stateDigest(state) }
        var extra: [String] = []
        if cid == UNHASHABLE { extra.append("<constitution>") }
        if adg == UNHASHABLE { extra.append("<action>") }
        if sdg == UNHASHABLE { extra.append("<state>") }
        let now: JSONValue = PD.fin(state?.get("now")) != nil ? (state?.get("now") ?? .int(0)) : .int(0)
        var violated = r.violated
        for x in extra where !r.violated.contains(x) { violated.append(x) }
        return .object([
            "v": .int(Int64(EVIDENCE_VERSION)), "constitution": .string(cid), "action_digest": .string(adg), "state_digest": .string(sdg), "now": now,
            "evaluated": .array(r.evaluated), "ok": .bool(r.ok && extra.isEmpty), "violated": PD.strs(violated),
        ])
    }

    /// Digest of an evidence record.
    public static func evidenceDigest(_ e: JSONValue) throws -> String { try PD.hash(e) }

    /// Offline re-check: recompute the monitor from (action, constitution, state) and require the evidence to match EXACTLY. Never throws.
    public static func verifySafetyEvidence(_ evidence: JSONValue?, _ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?) -> ProhibitionVerdict {
        guard let ev = evidence, PD.isObj(ev), IV.num(ev.get("v")) == Double(EVIDENCE_VERSION) else { return .no("unsupported evidence version") }
        let fresh = proveSafety(action, constitution, state)
        if !IV.same(fresh.get("constitution")?.asString, ev.get("constitution")?.asString) { return .no("constitution mismatch") }
        if !IV.same(fresh.get("action_digest")?.asString, ev.get("action_digest")?.asString) { return .no("action digest mismatch") }
        if !IV.same(fresh.get("state_digest")?.asString, ev.get("state_digest")?.asString) { return .no("state digest mismatch") }
        do {
            if try PD.hash(fresh) != PD.hash(ev) { return .no("evidence does not reproduce") }
        } catch { return .no("verification error (fail closed)") }
        if fresh.get("ok") != .bool(true) {
            return .no("prohibition violated: " + PD.join(fresh.get("violated")?.asArray ?? []))
        }
        return .pass
    }

    /// The binding id: commits to the signer, the evidence digest and the three bound digests. Throws only on unhashable evidence.
    public static func safetyBindingId(_ evidence: JSONValue, signer: String) throws -> String {
        // a missing bound digest is undefined in the reference and does not canonicalize: throw, never hash a null in its place
        guard PD.isObj(evidence), ["constitution", "action_digest", "state_digest"].allSatisfy({ PD.has(evidence, $0) }) else { throw PDFail(what: "canonicalize: unsupported type undefined") }
        return try PD.hash(.object([
            "d": .string(SAFETY_EVIDENCE_SIG_DOMAIN), "signer": .string(signer), "evidence": .string(PD.hash(evidence)),
            "constitution": evidence.get("constitution") ?? .null, "action_digest": evidence.get("action_digest") ?? .null, "state_digest": evidence.get("state_digest") ?? .null,
        ]))
    }

    /// Sign evidence (Ed25519, domain-separated). Refuses evidence whose action / constitution / state could not be digested.
    /// `signerPublic` is the public key recorded as the signer (default: the key's own); the reference takes it separately from the secret.
    public static func signSafetyEvidence(_ evidence: JSONValue, signer: PCAEdKey, signerPublic: String? = nil) throws -> JSONValue {
        guard PD.isObj(evidence), IV.num(evidence.get("v")) == Double(EVIDENCE_VERSION) else { throw PCAProducerError("signSafetyEvidence: unsupported evidence") }
        for k in ["constitution", "action_digest", "state_digest"] {
            guard let d = evidence.get(k)?.asString, !d.isEmpty, d != UNHASHABLE else { throw PCAProducerError("signSafetyEvidence: unbound evidence") }
        }
        let pub = signerPublic ?? signer.id
        if pub.isEmpty { throw PCAProducerError("signSafetyEvidence: signer missing") }
        let id = try safetyBindingId(evidence, signer: pub)
        let sig = Base64URLStrict.encode(try signer.sign(PD.domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, id)))
        return .object(["evidence": evidence, "signer": .string(pub), "id": .string(id), "sig": .string(sig)])
    }

    /// Verify signed evidence offline: signer pinned, binding id, signature, bound digests, internal consistency and (when everything is
    /// supplied) full recomputation. `expected` carries `signer` (string or array), `action` / `actionDigest`, `constitution` /
    /// `constitutionId`, `principal`, `state` / `stateDigest`, `requireOk`. Never throws.
    public static func verifySignedSafetyEvidence(_ signed: JSONValue?, _ expected: JSONValue?) -> ProhibitionVerdict {
        func no(_ r: String) -> ProhibitionVerdict { .no(r) }
        do {
            guard let sg = signed, PD.isObj(sg), let ev = sg.get("evidence"), PD.isObj(ev), let ex = expected, PD.isObj(ex) else { return no("malformed input") }
            if IV.num(ev.get("v")) != Double(EVIDENCE_VERSION) { return no("unsupported evidence version") }
            let signersV: [JSONValue?] = ex.get("signer")?.asArray.map { $0.map { Optional($0) } } ?? [ex.get("signer")]
            let signers: [String?] = signersV.map { $0?.asString }
            if signers.isEmpty || signers.contains(where: { $0 == nil || $0!.isEmpty }) { return no("no pinned signer") }
            guard let signer = sg.get("signer")?.asString, signers.contains(where: { IV.same($0, signer) }) else { return no("signer not trusted") }
            if !PD.has(ex, "action") && !PD.has(ex, "actionDigest") { return no("unbound: action not specified") }
            if !PD.has(ex, "constitution") && !PD.has(ex, "constitutionId") { return no("unbound: constitution not specified") }
            if !PD.has(ex, "state") && !PD.has(ex, "stateDigest") { return no("unbound: state not specified") }
            guard let sid = sg.get("id")?.asString else { return no("binding id mismatch") }
            let bindingId = try safetyBindingId(ev, signer: signer)
            if !IV.same(sid, bindingId) { return no("binding id mismatch") }
            guard let ssig = sg.get("sig")?.asString, Ed25519Strict.verifyB64u(signer, PD.domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, sid), ssig) else { return no("bad signature") }

            let wantAction: String
            if let a = ex.get("action") {
                wantAction = try PD.hash(a)
                if let ad = ex.get("actionDigest"), !IV.same(ad.asString, wantAction) { return no("expected action and digest disagree") }
            } else {
                wantAction = ex.get("actionDigest")?.asString ?? ""
            }
            if !IV.same(ev.get("action_digest")?.asString, wantAction) { return no("action digest mismatch (evidence bound to another action)") }

            if ex.get("principal") != nil {
                guard let sc = ex.get("constitution"), PD.isObj(sc), PD.isStr(sc.get("sig")) else { return no("principal pin requires a signed constitution") }
                guard let pin = ex.get("principal")?.asString else { return no("constitution not authentic: principal mismatch") }
                let vc = verifyConstitution(sc, expectedPrincipal: pin)
                if !vc.ok { return no("constitution not authentic: " + (vc.reason ?? "undefined")) }
            }
            let wantConst: String
            if let c = ex.get("constitution") {
                wantConst = try constitutionId(c)
                if let cid = ex.get("constitutionId"), !IV.same(cid.asString, wantConst) { return no("expected constitution and id disagree") }
            } else {
                wantConst = ex.get("constitutionId")?.asString ?? ""
            }
            if !IV.same(ev.get("constitution")?.asString, wantConst) { return no("constitution mismatch (evidence bound to another constitution)") }
            // a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row
            if let c = ex.get("constitution"), let cp = validateConstitution(c).first { return no("constitution malformed: " + cp) }

            let wantState: String
            if let s = ex.get("state") {
                wantState = try stateDigest(s)
                if let sd = ex.get("stateDigest"), !IV.same(sd.asString, wantState) { return no("expected state and digest disagree") }
            } else {
                wantState = ex.get("stateDigest")?.asString ?? ""
            }
            if !IV.same(ev.get("state_digest")?.asString, wantState) { return no("state digest mismatch (evidence bound to another state)") }

            // internal consistency: the claimed verdict must follow from the claimed rows
            guard let rows = ev.get("evaluated")?.asArray, let violated = ev.get("violated")?.asArray else { return no("malformed evidence") }
            if rows.contains(where: { PD.isObj($0) && PD.has($0, "id") && !PD.isStr($0.get("id")) }) { return no("malformed evidence") }
            let badRows = rows.filter { !(PD.isObj($0) && $0.get("result")?.asString == "pass") }
            let evOk = ev.get("ok")
            if evOk != .bool(badRows.isEmpty && violated.isEmpty) { return no("evidence verdict inconsistent with rows") }

            if let a = ex.get("action"), let c = ex.get("constitution"), let s = ex.get("state") {
                let full = verifySafetyEvidence(ev, a, c, s)
                if !full.ok && evOk == .bool(true) { return no(full.reason ?? "evidence does not reproduce") }
                if !full.ok && evOk == .bool(false), let fr = full.reason, !fr.hasPrefix("prohibition violated") { return no(fr) }
            } else if evOk == .bool(true), let c = ex.get("constitution") {
                guard let invs = try PD.prop(c, "invariants")?.asArray else { throw PDFail(what: "invariants") }
                let ids = try invs.map { try PD.prop($0, "id") }
                if rows.count != ids.count { return no("evidence does not cover every invariant") }
                for (i, r) in rows.enumerated() {
                    let rid = try PD.prop(r, "id")
                    if !PD.strictSame(rid, ids[i]) { return no("evidence does not cover every invariant") }
                }
            }
            if ex.get("requireOk") != .bool(false) && evOk != .bool(true) { return no("prohibition violated: " + PD.join(violated)) }
            return .pass
        } catch {
            return no("verification error (fail closed)")
        }
    }

    // ---- composition: permissions grant, prohibitions veto ---------------------------------------------------------------------

    /// `allow = permitted AND prohibitions.ok`; the monitor runs unconditionally so denial reasons are complete.
    public static func composeAuthority(permitted: Bool, _ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?) -> ComposedDecision {
        composeFrom(permitted, checkProhibitions(action, constitution, state))
    }

    static func composeFrom(_ permitted: Bool, _ prohibition: ProhibitionResult) -> ComposedDecision {
        ComposedDecision(allow: permitted && prohibition.ok, decidedBy: !prohibition.ok ? "prohibition" : (permitted ? "none" : "permission"),
                         permitted: permitted, prohibition: prohibition)
    }

    /// The pure kernel of the server's critical section: guard the head (compare-and-swap), compose authority, build evidence against the
    /// pre-state and, on allow, compute the next state. `expectedSeq` / `expectedStateDigest` are the optimistic-concurrency guards.
    /// Persisting `next` iff `allow` MUST happen in the same atomic step that read `state`. Never throws.
    public static func checkAndAdvance(permitted: Bool, _ action: JSONValue?, _ constitution: JSONValue?, _ state: JSONValue?,
                                       expectedSeq: Double? = nil, expectedStateDigest: String? = nil) -> CheckAndAdvanceResult {
        // ONE document: the constitution is evaluated once and that result feeds both the evidence and the decision
        let monitored = checkProhibitions(action, constitution, state)
        let evidence = evidenceFrom(monitored, action, constitution, state)
        let decision = composeFrom(permitted, monitored)
        func refuse(_ by: String, _ why: String? = nil) -> CheckAndAdvanceResult {
            CheckAndAdvanceResult(allow: false, decidedBy: by, evidence: evidence, prohibition: decision.prohibition, next: state ?? .null, reason: why)
        }
        if let es = expectedSeq, !(PD.isObj(state) && IV.num(state?.get("seq")) == es) { return refuse("state", "stale state head (seq)") }
        if let ed = expectedStateDigest, safeDigest({ try stateDigest(state) }) != ed { return refuse("state", "stale state head (digest)") }
        if !decision.allow { return refuse(decision.decidedBy == "none" ? "permission" : decision.decidedBy) }
        if evidence.get("ok") != .bool(true) { return refuse("prohibition", "evidence not attestable") }
        let adv = advanceStateStrict(action, constitution, state)
        guard adv.ok, let next = adv.state else { return refuse("state", "advance failed: " + (adv.reason ?? "")) }
        return CheckAndAdvanceResult(allow: true, decidedBy: "none", evidence: evidence, prohibition: decision.prohibition, next: next, reason: nil)
    }
}

extension PD {
    /// `a === b` of two JSON members (primitive strict equality; containers are never equal).
    static func strictSame(_ a: JSONValue?, _ b: JSONValue?) -> Bool { IV.strictEq(a, b) }
}
