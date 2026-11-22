import Foundation

/// Agent-native authority primitives (TypeScript `agent-native.ts`): uncertainty attestation (caution claims), rationale binding (commit /
/// reveal / audit), the semantic-firewall builders (`tool_schema` and `predicates` caveats, the agent-native caveat evaluator), capability
/// introspection (what an attenuated chain permits) and the authority lease.
///
/// Pure and deterministic: no clocks (callers pass `now`), no randomness except the default rationale salt. The verification and evaluation
/// functions are total and fail closed; only the authoring helpers (`bindRationale`, `toolSchemaCaveat`, `predicatesCaveat`, `grantLease`) throw,
/// so a bad artefact is never minted. Values are `JSONValue` (the decoded JSON of the reference): a number is "finite" exactly when
/// `Number.isFinite` says so on the JSON number, and a result that is an object in the reference is a `JSONValue` object here. `PCASigners.signCaution`,
/// `PCASigners.signHeartbeat`, `PCA.evaluateToolSchema` and `ToolSchema.validateArgSchema` of the same family live elsewhere.
public enum AgentNative {
    // ---- constants ----
    public static let CAVEAT_ENVELOPE = "envelope"
    public static let CAVEAT_EXPIRES = "expires"
    public static let CAVEAT_NOT_BEFORE = "not_before"
    public static let CAVEAT_RATE = "rate"
    public static let CAVEAT_MAX_BLAST_RADIUS = "max_blast_radius"
    public static let CAVEAT_REVERSIBILITY_MAX = "reversibility_max"
    public static let CAVEAT_DELEGATION_DEPTH = "delegation_depth"
    /// Delegated verb/resource narrowing, `{allow: Predicate[]}`.
    public static let CAVEAT_PREDICATES = "predicates"
    /// Tool-call authority bound to an exact tool + signature + (nested) argument schema.
    public static let CAVEAT_TOOL_SCHEMA = "tool_schema"
    /// Per-action spend ceiling in US dollars, `{type: "max_spend", usd}`.
    public static let CAVEAT_MAX_SPEND = "max_spend"
    public static let MAX_CAUTION_REASON_LEN = 64
    public static let MIN_SALT_BYTES = 16
    public static let MIN_SALT_DISTINCT_BYTES = 8
    public static let MAX_RATIONALE_LEN = 8192
    public static let MAX_SCHEMA_DEPTH = ToolSchema.MAX_SCHEMA_DEPTH
    public static let MAX_SCHEMA_NODES = ToolSchema.MAX_SCHEMA_NODES
    public static let MAX_OBJECT_PROPS = ToolSchema.MAX_OBJECT_PROPS
    public static let MAX_ENUM_VALUES = ToolSchema.MAX_ENUM_VALUES
    public static let DEFAULT_MAX_ARRAY_ITEMS = Int(ToolSchema.DEFAULT_MAX_ARRAY_ITEMS)
    public static let ABSOLUTE_MAX_ARRAY_ITEMS = Int(ToolSchema.ABSOLUTE_MAX_ARRAY_ITEMS)
    public static let DEFAULT_MAX_STRING_LEN = Int(ToolSchema.DEFAULT_MAX_STRING_LEN)
    public static let ABSOLUTE_MAX_STRING_LEN = Int(ToolSchema.ABSOLUTE_MAX_STRING_LEN)
    public static let MAX_VALUE_NODES = ToolSchema.MAX_VALUE_NODES
    /// Max tolerated skew between a heartbeat's `at` (or the clock vs the last renewal) and server `now`.
    public static let HEARTBEAT_SKEW_MS = 30_000
    /// Longest lease ttl accepted (7 days).
    public static let MAX_LEASE_TTL_MS = 604_800_000

    private static let CAUTION_KEYS = ["action_digest", "caution", "reason", "holder", "sig"]
    private static let HB_KEYS = ["cap_id", "seq", "at", "holder", "lease_issued_at", "sig"]
    private static let RATIONALE_DOMAIN = "atlas-pca/rationale/v1"
    private static let REV = ["reversible", "rate_limited", "irreversible"]

    // ---- helpers ----
    private static func fin(_ v: JSONValue?) -> Double? { ToolSchema.fin(v) }
    private static func nonEmpty(_ v: JSONValue?) -> String? { if case let .string(s)? = v, !s.isEmpty { return s }; return nil }
    private static func clamp01(_ x: Double) -> Double { min(1, max(0, x)) }
    private static func s(_ x: String) -> JSONValue { .string(x) }
    /// A JSON number for a finite double (an integral one as an integer; -0 as 0).
    private static func num(_ d: Double) -> JSONValue { d == d.rounded() && abs(d) <= 9007199254740991 ? .int(d == 0 ? 0 : Int64(d)) : .double(d) }
    private static func utf8Less(_ a: String, _ b: String) -> Bool { a.utf8.lexicographicallyPrecedes(b.utf8) }
    private static func sortedUnique(_ xs: [String]) -> [String] { Array(Set(xs.map { JKey($0) })).map { $0.s }.sorted(by: utf8Less) }
    private static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.string(x)?, .string(y)?): return IV.same(x, y)
        default: return false
        }
    }

    // ======================================================================================
    // 1. Uncertainty attestation
    // ======================================================================================

    /// Verify a caution claim `{action_digest, caution, reason?, holder, sig}`: a plain object with no member outside those five, caution a finite
    /// number in [0,1], a valid Ed25519 signature by `claim.holder` over the domain-separated body, bound to `expectedActionDigest` when given and
    /// signed by `expectedHolder` when given (production callers MUST pass the PCActn's holder, otherwise any key may attest). Total: false on
    /// anything malformed.
    public static func verifyCaution(_ claim: JSONValue?, _ expectedActionDigest: String? = nil, _ expectedHolder: String? = nil) -> Bool {
        guard case let .object(o)? = claim, case let .string(sig)? = o["sig"] else { return false }
        guard o.keys.allSatisfy({ k in CAUTION_KEYS.contains { IV.same($0, k.s) } }), PCASigners.cautionBodyError(o) == nil else { return false }
        if let d = expectedActionDigest, !IV.same(o["action_digest"]?.asString, d) { return false }
        if let h = expectedHolder, !IV.same(o["holder"]?.asString, h) { return false }
        guard let holder = o["holder"]?.asString else { return false }
        var body = o
        body["sig"] = nil
        guard let msg = try? PCASigners.msgOf(PCASigners.CAUTION_DOMAIN, .object(body)) else { return false }
        return Ed25519Strict.verifyB64u(holder, msg, sig)
    }

    /// `effectiveRisk = max(agentDeclaredCaution, serverRisk)`: never below the server risk, so under-reporting gains nothing and a higher
    /// declaration raises friction. An unusable declaration (nil, NaN, infinite) is ignored; an unusable server risk fails closed to 1. Both are
    /// clamped to [0, 1].
    public static func combineCaution(_ agentDeclaredCaution: Double?, _ serverRisk: Double) -> Double {
        let sr = serverRisk.isFinite ? clamp01(serverRisk) : 1
        guard let d = agentDeclaredCaution, d.isFinite else { return sr }
        return max(clamp01(d), sr)
    }

    /// `combineCaution` over a signed claim: only a valid claim bound to `actionDigest` (and, when given, to `expectedHolder`) is honoured; an
    /// invalid, misbound or forged claim degrades to `serverRisk`, never below it. Returns `{effectiveRisk, honoured, escalated}`.
    public static func combineSignedCaution(_ claim: JSONValue?, _ actionDigest: String, _ serverRisk: Double, _ expectedHolder: String? = nil) -> JSONValue {
        let sr = serverRisk.isFinite ? clamp01(serverRisk) : 1
        let ok = claim != nil && verifyCaution(claim, actionDigest, expectedHolder)
        let eff = combineCaution(ok ? fin(claim?.get("caution")) : nil, sr)
        return .object(["effectiveRisk": num(eff), "honoured": .bool(ok), "escalated": .bool(eff > sr)])
    }

    /// The monotonicity property of `combineCaution` over the finite members of `grid`: `{ok: true}`, or `{ok: false, counterexample: [declared, server]}`.
    public static func checkCautionMonotone(_ grid: [Double]) -> JSONValue {
        let g = grid.filter { $0.isFinite }
        for sv in g {
            for d in g {
                let e = combineCaution(d, sv)
                if e < clamp01(sv) { return .object(["ok": .bool(false), "counterexample": .array([num(d), num(sv)])]) }
                for d2 in g where d2 >= d && combineCaution(d2, sv) < e { return .object(["ok": .bool(false), "counterexample": .array([num(d2), num(sv)])]) }
            }
        }
        return .object(["ok": .bool(true)])
    }

    // ======================================================================================
    // 2. Rationale binding
    // ======================================================================================

    /// Entropy floor of a commitment salt: strict base64url (at most 256 characters) that decodes to at least `MIN_SALT_BYTES` bytes holding at least
    /// `MIN_SALT_DISTINCT_BYTES` distinct byte values. A sanity floor, not a proof of randomness.
    public static func isStrongSalt(_ salt: JSONValue?) -> Bool {
        guard case let .string(str)? = salt, !str.isEmpty, str.utf16.count <= 256, let b = Base64URLStrict.decode(str), b.count >= MIN_SALT_BYTES else { return false }
        return Set(b).count >= MIN_SALT_DISTINCT_BYTES
    }

    private static func commitDigest(_ actionDigest: String, _ salt: String, _ rationale: String) -> String? {
        IV.strictHash(.object(["d": s(RATIONALE_DOMAIN), "a": s(actionDigest), "s": s(salt), "r": s(rationale)]))
    }

    /// Commit to a stated reason for `action`: returns `{commitment: {v, action_digest, commitment}, reveal: {rationale, salt}}`. Publish the commitment,
    /// KEEP the reveal. `salt` nil draws 32 random bytes; a given salt must pass `isStrongSalt`. Throws (authoring error) on an oversized rationale
    /// (more than `MAX_RATIONALE_LEN` UTF-16 units), a weak salt and a non-canonicalizable action.
    public static func bindRationale(_ action: JSONValue, _ rationale: String, salt: String? = nil) throws -> JSONValue {
        let salt = salt ?? Base64URLStrict.encode((0..<32).map { _ in UInt8.random(in: 0...255) })
        if rationale.utf16.count > MAX_RATIONALE_LEN { throw PCAProducerError("bindRationale: rationale too long") }
        if !isStrongSalt(.string(salt)) { throw PCAProducerError("bindRationale: salt must be b64u of >=16 bytes with >=8 distinct values") }
        guard let ad = IV.strictHash(action), let cd = commitDigest(ad, salt, rationale) else { throw PCAProducerError("bindRationale: the action is not canonicalizable") }
        return .object(["commitment": .object(["v": .int(1), "action_digest": s(ad), "commitment": s(cd)]), "reveal": .object(["rationale": s(rationale), "salt": s(salt)])])
    }

    private static func commitmentOK(_ c: JObject) -> Bool { fin(c["v"]) == 1 && nonEmpty(c["action_digest"]) != nil && nonEmpty(c["commitment"]) != nil }

    /// Does `reveal` open `commitment`, optionally for this very `action` (`.null` is an action of JSON null; nil = not given)? A salt below the
    /// entropy floor is rejected even if it hashes correctly. Total: false on anything malformed.
    public static func verifyRationale(_ commitment: JSONValue?, _ reveal: JSONValue?, action: JSONValue? = nil) -> Bool {
        guard case let .object(c)? = commitment, case let .object(r)? = reveal, commitmentOK(c) else { return false }
        guard case let .string(rat)? = r["rationale"], rat.utf16.count <= MAX_RATIONALE_LEN, isStrongSalt(r["salt"]), case let .string(salt)? = r["salt"],
              let ad = c["action_digest"]?.asString else { return false }
        if let a = action, !IV.same(IV.strictHash(a), ad) { return false }
        return IV.same(commitDigest(ad, salt, rat), c["commitment"]?.asString)
    }

    /// After-the-fact audit. The resource server never judges the rationale: an auditor supplies `judge(rationale, action)` (a throw is a failure of the
    /// judge, not of the agent). A rationale that opens the commitment and is judged false is attributable (slashable); failing to open it on demand is
    /// slashable too; a throwing judge yields `judge_error` (not slashable). Returns `{verdict, slashable, evidence: {commitment, action_digest,
    /// rationale?}}` with verdict `consistent`, `false_rationale`, `unopened`, `wrong_action`, `malformed` or `judge_error`. Total.
    public static func auditRationale(_ commitment: JSONValue?, _ action: JSONValue, reveal: JSONValue?, judge: (String, JSONValue) throws -> Bool) -> JSONValue {
        let co = commitment?.asObject
        let cm = co?["commitment"]?.asString ?? "", ad = co?["action_digest"]?.asString ?? ""
        func out(_ verdict: String, _ slashable: Bool, _ rationale: String? = nil) -> JSONValue {
            var ev: JObject = ["commitment": s(cm), "action_digest": s(ad)]
            if let r = rationale { ev["rationale"] = s(r) }
            return .object(["verdict": s(verdict), "slashable": .bool(slashable), "evidence": .object(ev)])
        }
        guard let c = co, commitmentOK(c) else { return out("malformed", false) }
        guard let h = IV.strictHash(action) else { return out("malformed", false) }
        if !IV.same(h, ad) { return out("wrong_action", false) }
        guard let rv = reveal, verifyRationale(commitment, rv, action: action), let rat = rv.get("rationale")?.asString else { return out("unopened", true) }
        do { return try judge(rat, action) ? out("consistent", false, rat) : out("false_rationale", true, rat) } catch { return out("judge_error", false, rat) }
    }

    // ======================================================================================
    // 3. Semantic firewall
    // ======================================================================================

    /// Deep clone in canonical form (`JSON.parse(canonicalize(x))`): keys sorted, -0 as 0, a non-finite number refused.
    private static func cloneCanonical(_ v: JSONValue) throws -> JSONValue {
        switch v {
        case let .double(d):
            if !d.isFinite { throw PCAProducerError("canonicalize: non-finite number") }
            return num(d)
        case let .array(a): return .array(try a.map(cloneCanonical))
        case let .object(o):
            var m: JObject = [:]
            for k in o.keys.sorted() { m[o: k.s] = try cloneCanonical(o[k]!) }
            return .object(m)
        default: return v
        }
    }

    /// Build a `tool_schema` caveat: authority exists only for this exact tool, signature and argument schema. `toolSignature` is the tool name or an
    /// object with a string `name`; `argSchema` must pass `ToolSchema.validateArgSchema`. The schema is deep-cloned in canonical form, so later mutation
    /// of the input cannot alter the caveat. Throws on a missing tool name, an invalid schema or anything not canonicalizable.
    public static func toolSchemaCaveat(_ toolSignature: JSONValue, _ argSchema: JSONValue) throws -> JSONValue {
        var tool = ""
        if case let .string(t) = toolSignature { tool = t } else if case let .object(o) = toolSignature, case let .string(t)? = o["name"] { tool = t }
        if tool.isEmpty { throw PCAProducerError("toolSchemaCaveat: tool name required") }
        if let e = ToolSchema.validateArgSchema(argSchema) { throw PCAProducerError("toolSchemaCaveat: \(e)") }
        let schema = try cloneCanonical(argSchema)
        guard let sd = IV.strictHash(toolSignature), let schD = IV.strictHash(schema),
              let bd = IV.strictHash(.object(["tool": s(tool), "signature_digest": s(sd), "schema": schema])) else { throw PCAProducerError("toolSchemaCaveat: not canonicalizable") }
        return .object(["type": s(CAVEAT_TOOL_SCHEMA), "tool": s(tool), "signature_digest": s(sd), "schema": schema, "schema_digest": s(schD), "binding_digest": s(bd)])
    }

    /// Evaluate a tool call `{tool, args, toolSignature?, toolSignatureDigest?}` against a `tool_schema` caveat. It fails AUTHORITY, not just validation:
    /// the caveat must be self-consistent (valid schema, both digests match), the tool and its signature must match, and the possibly nested arguments
    /// must satisfy the closed recursive schema. Returns `(true, nil)` when admitted, else `(false, reason)`. Total.
    public static func evaluateToolSchemaCall(_ caveat: JSONValue?, _ call: JSONValue?) -> (ok: Bool, reason: String?) {
        guard case let .object(c)? = caveat, ToolSchema.eqs(c["type"], CAVEAT_TOOL_SCHEMA), case let .string(tool)? = c["tool"], !tool.isEmpty else {
            return (false, "malformed tool_schema caveat")
        }
        if let e = ToolSchema.validateArgSchema(c["schema"]) { return (false, "malformed tool_schema caveat: \(e)") }
        guard let schema = c["schema"], case let .object(so) = schema, let sd = IV.strictHash(schema) else { return (false, "evaluation error (fail closed)") }
        if !ToolSchema.eqs(c["schema_digest"], sd) { return (false, "schema digest mismatch") }
        let sig = c["signature_digest"].map { IntentV2.jsString($0) } ?? "undefined"
        guard let bd = IV.strictHash(.object(["tool": s(tool), "signature_digest": s(sig), "schema": schema])) else { return (false, "evaluation error (fail closed)") }
        if !ToolSchema.eqs(c["binding_digest"], bd) { return (false, "binding digest mismatch") }
        guard case let .object(cm)? = call, case let .string(ct)? = cm["tool"], case let .object(args)? = cm["args"] else { return (false, "malformed call") }
        if !IV.same(ct, tool) { return (false, "tool \(ToolSchema.show(ct)) not authorized") }
        if let ts = cm["toolSignature"] {
            guard let h = IV.strictHash(ts) else { return (false, "evaluation error (fail closed)") }
            if !ToolSchema.eqs(c["signature_digest"], h) { return (false, "tool signature differs from the authorized signature") }
        }
        if let d = cm["toolSignatureDigest"], !ToolSchema.eqs(c["signature_digest"], d.asString ?? "\u{0}") || d.asString == nil {
            return (false, "signed tool_binding differs from the authorized tool signature")
        }
        if let e = ToolSchema.checkObject(so["props"]?.asObject ?? [:], so["required"], args, "args", 1, ToolSchema.Counter()) { return (false, e) }
        return (true, nil)
    }

    /// The caveat-evaluator extension point for `tool_schema`: `ctx = {toolCall}`. Any other caveat type is unsatisfied.
    public static func toolSchemaEvaluator(_ caveat: JSONValue?, _ ctx: JSONValue?) -> Bool {
        guard case let .object(x)? = ctx, case .object? = x["toolCall"] else { return false }
        return evaluateToolSchemaCall(caveat, x["toolCall"]).ok
    }

    /// The delegated-narrowing caveat `{type: "predicates", allow}` with `allow` deep-cloned in canonical form.
    public static func predicatesCaveat(_ allow: JSONValue) throws -> JSONValue { .object(["type": s(CAVEAT_PREDICATES), "allow": try cloneCanonical(allow)]) }

    /// The action's spend in USD as `max_spend` reads it: the own `action.action.params.amount` (finite, >= 0) with an own `currency`, when present,
    /// of "usd" or "USD". nil = no readable spend.
    public static func actionSpendUsd(_ action: JSONValue?) -> Double? {
        guard case let .object(a)? = action, case let .object(act)? = a["action"], case let .object(params)? = act["params"],
              let amount = fin(params["amount"]), amount >= 0 else { return nil }
        if let cur = params["currency"], !ToolSchema.eqs(cur, "usd"), !ToolSchema.eqs(cur, "USD") { return nil }
        return amount
    }

    /// A superset of the stock envelope caveat evaluator: adds `predicates` (needs `ctx.action`, an action context `{action: {verb, resource,
    /// params}}`), `max_spend` (needs `ctx.action`) and `tool_schema` (needs `ctx.toolCall`). The stock context fields are `now`, `blastRadius`,
    /// `reversibilityClass`, `delegationDepth` and `recentActionTimes`. Anything else is unsatisfied (fail closed). Total.
    public static func agentNativeCaveatEvaluator(_ caveat: JSONValue?, _ ctx: JSONValue?) -> Bool {
        guard case let .object(cv)? = caveat, case let .object(x)? = ctx else { return false }
        let type = cv["type"]?.asString
        if ToolSchema.eqs(cv["type"], CAVEAT_TOOL_SCHEMA) { return toolSchemaEvaluator(caveat, ctx) }
        if ToolSchema.eqs(cv["type"], CAVEAT_PREDICATES) {
            guard let a = x["action"], a.isObject, case let .array(allow)? = cv["allow"] else { return false }
            let budget = SafeRegex.Budget()
            return allow.contains { Predicates.predicateMatches($0, a, budget) }
        }
        if ToolSchema.eqs(cv["type"], CAVEAT_MAX_SPEND) {
            guard let lim = fin(cv["usd"]), let spend = actionSpendUsd(x["action"]) else { return false }
            return spend <= lim
        }
        guard let now = fin(x["now"]), let t = type, t.unicodeScalars.allSatisfy({ $0.isASCII }) else { return false }
        switch t {
        case CAVEAT_EXPIRES: return fin(cv["at"]).map { now < $0 } ?? false
        case CAVEAT_NOT_BEFORE: return fin(cv["at"]).map { now >= $0 } ?? false
        case CAVEAT_RATE:
            guard let mx = fin(cv["max"]), let per = fin(cv["per_secs"]), per > 0, case let .array(times)? = x["recentActionTimes"] else { return false }
            let lo = now - per * 1000
            return Double(times.filter { v in fin(v).map { $0 > lo && $0 <= now } ?? false }.count) < mx
        case CAVEAT_MAX_BLAST_RADIUS:
            guard let mx = fin(cv["max"]), let br = fin(x["blastRadius"]) else { return false }
            return br <= mx
        case CAVEAT_REVERSIBILITY_MAX:
            guard case let .string(l)? = cv["class"], case let .string(c)? = x["reversibilityClass"],
                  let li = REV.firstIndex(where: { IV.same($0, l) }), let ci = REV.firstIndex(where: { IV.same($0, c) }) else { return false }
            return ci <= li
        case CAVEAT_DELEGATION_DEPTH:
            guard let mx = fin(cv["max"]), let d = fin(x["delegationDepth"]) else { return false }
            return d <= mx
        case "budget_alloc": return fin(cv["limit"]).map { $0 >= 0 } ?? false
        case IntentSession.CAVEAT: return IntentSession.caveatError(caveat) == nil
        default: return false
        }
    }

    // ======================================================================================
    // 4. Capability introspection
    // ======================================================================================

    private struct Scope {
        var verbs: [String], resources: [String], wh: [JSONValue]
        var value: JSONValue { .object(["verbs": .array(verbs.map { JSONValue.string($0) }), "resources": .array(resources.map { JSONValue.string($0) }), "where": .array(wh)]) }
    }

    private static func intersectVerbs(_ a: [String], _ b: [String]) -> [String] {
        if a.contains("*") { return sortedUnique(b) }
        if b.contains("*") { return sortedUnique(a) }
        return sortedUnique(a.filter { x in b.contains { IV.same($0, x) } })
    }

    /// Intersect two resource patterns; nil = empty or not decidable symbolically (a regex).
    private static func interRes(_ a: String, _ b: String) -> String? {
        if IV.same(a, b) { return a }
        if a.hasPrefix("re:") || b.hasPrefix("re:") { return nil }
        if a == "*" { return b }
        if b == "*" { return a }
        let ap = a.hasSuffix("*"), bp = b.hasSuffix("*")
        if ap && bp {
            let pa = String(a.dropLast()), pb = String(b.dropLast())
            return pb.hasPrefix(pa) ? b : pa.hasPrefix(pb) ? a : nil
        }
        if ap { return b.hasPrefix(String(a.dropLast())) ? b : nil }
        if bp { return a.hasPrefix(String(b.dropLast())) ? a : nil }
        return nil
    }

    /// Collapse a conjunction of resource patterns; nil = unsatisfiable.
    private static func collapse(_ list: [String]) -> [String]? {
        var lit: String?
        var res: [String] = []
        for p in list {
            if p.hasPrefix("re:") { res.append(p); continue }
            if let l = lit { guard let r = interRes(l, p) else { return nil }; lit = r } else { lit = p }
        }
        var out: [String] = []
        if let l = lit, l != "*" { out.append(l) }
        out += sortedUnique(res)
        return out.isEmpty ? ["*"] : out
    }

    private static func scopeOfPredicate(_ p: JSONValue) -> Scope? {
        guard case let .object(o) = p else { return nil }
        var verbs: [String]
        switch o["verb"] {
        case let .string(v)?: verbs = [v]
        case let .array(a)?:
            let ss = a.compactMap { $0.asString }
            if ss.count != a.count { return nil }
            verbs = ss
        default: return nil
        }
        var resource = "*"
        if let r = o["resource"] { guard case let .string(x) = r else { return nil }; resource = x }
        var wh: [JSONValue] = []
        if let w = o["where"] { guard case let .array(x) = w else { return nil }; wh = x }
        return Scope(verbs: sortedUnique(verbs), resources: [resource], wh: wh)
    }

    private static func intersectScopes(_ a: [Scope], _ b: [Scope]) throws -> [Scope] {
        var out: [String: Scope] = [:]
        for x in a {
            for y in b {
                let verbs = intersectVerbs(x.verbs, y.verbs)
                if verbs.isEmpty { continue }
                guard let resources = collapse(x.resources + y.resources) else { continue }
                let sc = Scope(verbs: verbs, resources: resources, wh: x.wh + y.wh)
                guard let h = IV.strictHash(sc.value) else { throw PCAProducerError("describeEnvelope: a scope is not canonicalizable") }
                out[h] = sc
            }
        }
        return out.keys.sorted().map { out[$0]! }
    }

    private static func wellFormedCaveat(_ cv: JObject, _ t: String) -> Bool {
        switch t {
        case CAVEAT_EXPIRES, CAVEAT_NOT_BEFORE: return fin(cv["at"]) != nil
        case CAVEAT_RATE: return fin(cv["max"]) != nil && (fin(cv["per_secs"]).map { $0 > 0 } ?? false)
        case CAVEAT_MAX_BLAST_RADIUS, CAVEAT_DELEGATION_DEPTH: return fin(cv["max"]) != nil
        case CAVEAT_REVERSIBILITY_MAX: if case let .string(c)? = cv["class"] { return REV.contains { IV.same($0, c) } }; return false
        case CAVEAT_PREDICATES: if case let .array(a)? = cv["allow"] { return a.allSatisfy { scopeOfPredicate($0) != nil } }; return false
        case CAVEAT_TOOL_SCHEMA: return nonEmpty(cv["tool"]) != nil
        case "budget_alloc": return fin(cv["limit"]).map { $0 >= 0 } ?? false
        case CAVEAT_MAX_SPEND: return fin(cv["usd"]).map { $0 >= 0 } ?? false
        default: return false
        }
    }

    private static func emptyEnvelope(_ reason: String? = nil) -> JSONValue {
        var e: JObject = ["ok": .bool(false), "hasEnvelope": .bool(false), "scopes": .array([]), "verbs": .array([]), "resources": .array([]), "opaqueResourceConstraints": .array([]),
                          "tools": .array([]), "toolSchemas": .array([]), "unsatisfiable": .array([]), "caveats": .array([]), "remainingBudgetHints": .object([:])]
        if let r = reason { e["reason"] = s(r) }
        return .object(e)
    }

    /// What an attenuated chain actually permits now, deterministically (`now` is supplied; nil = unknown). The chain is verified first (`expectedRootIssuer`
    /// nil = any root; `policy` is the optional `{allowedSuites, pqPins, trustedRoot}` object); an unverifiable chain gives `ok: false` with the chain's reason
    /// and nothing permitted. Caveats are conjunctive and append-only, so the envelope is the intersection across all hops: the set the verifier would accept,
    /// never wider. A caveat the verifier cannot satisfy (unknown type, malformed fields, a second `envelope`) is listed in `unsatisfiable` and nothing is
    /// permitted. The result is the JSON object of the reference (`ok`, `hasEnvelope`, `scopes`, `verbs`, `resources`, `opaqueResourceConstraints`, `tools`,
    /// `toolSchemas`, `unsatisfiable`, `caveats`, `remainingBudgetHints`, `reason`?); pass it to `envelopePermits` and `envelopePermitsToolCall`. Total.
    public static func describeEnvelope(_ chain: JSONValue?, now: Double? = nil, expectedRootIssuer: String? = nil, policy: JSONValue? = nil) -> JSONValue {
        do { return try describe(chain, now, expectedRootIssuer, policy) } catch { return emptyEnvelope("introspection error (fail closed)") }
    }

    private static func describe(_ chainV: JSONValue?, _ now: Double?, _ issuer: String?, _ policy: JSONValue?) throws -> JSONValue {
        let list = chainV?.asArray ?? []
        let p = policy?.asObject
        let allowed = p?["allowedSuites"]?.asArray.map { $0.map { $0.asString ?? "" } }
        var pins: [String: String]?
        if let m = p?["pqPins"]?.asObject { pins = [:]; for (k, v) in m { pins![k.s] = v.asString ?? "" } }
        let trusted = p?["trustedRoot"].flatMap { $0.isObject ? $0 : nil }
        if let why = Capability.verifyChain(list, expectedRootIssuer: issuer, allowedSuites: allowed, pqPins: pins, trustedRoot: trusted) { return emptyEnvelope(why) }
        let root = list[0], leaf = list[list.count - 1]
        let env0 = PCA.readEnvelope(root)?.asObject
        let all = [Scope(verbs: ["*"], resources: ["*"], wh: [])]
        var bad = Set<String>(), scopes: [Scope]?, tools: [String]?, seenEnvelope = false, toolSchemas: [JSONValue] = []
        var expiresAt: Double?, notBefore: Double?, maxRate: (Double, Double)?, maxBlast: Double?, revMax: Int?, depthRem: Double?, budget: Double?, maxSpend: Double?
        if let e = env0 {
            var base: [Scope] = []
            for pr in e["predicates"]?.asArray ?? [] { if let sc = scopeOfPredicate(pr) { base.append(sc) } else { bad.insert("envelope.predicates") } }
            scopes = try intersectScopes(base, all)
        }
        func fold(_ cvv: JSONValue, _ inEnvelope: Bool) throws {
            guard case let .object(cv) = cvv, case let .string(t)? = cv["type"] else { bad.insert("<malformed>"); return }
            if IV.same(t, CAVEAT_ENVELOPE) {
                // only the root's FIRST envelope caveat is read; the policy VM evaluates any other as unknown => unsatisfied
                if seenEnvelope || inEnvelope { bad.insert(CAVEAT_ENVELOPE) }
                seenEnvelope = true
                return
            }
            if !wellFormedCaveat(cv, t) { bad.insert(t); return }
            func f(_ k: String) -> Double { fin(cv[JKey(k)]) ?? 0 }
            switch t {
            case CAVEAT_PREDICATES:
                scopes = try intersectScopes(scopes ?? all, (cv["allow"]?.asArray ?? []).compactMap(scopeOfPredicate))
            case CAVEAT_TOOL_SCHEMA:
                toolSchemas.append(cvv)
                let tool = cv["tool"]?.asString ?? ""
                var consistent = ToolSchema.validateArgSchema(cv["schema"]) == nil
                if consistent {
                    guard let sch = cv["schema"], let h = IV.strictHash(sch) else { throw PCAProducerError("not canonicalizable") }
                    consistent = ToolSchema.eqs(cv["schema_digest"], h)
                    if consistent {
                        let sig = cv["signature_digest"].map { IntentV2.jsString($0) } ?? "undefined"
                        guard let b = IV.strictHash(.object(["tool": s(tool), "signature_digest": s(sig), "schema": sch])) else { throw PCAProducerError("not canonicalizable") }
                        consistent = ToolSchema.eqs(cv["binding_digest"], b)
                    }
                }
                if !consistent { tools = []; bad.insert(CAVEAT_TOOL_SCHEMA) } else { tools = tools.map { $0.filter { IV.same($0, tool) } } ?? [tool] }
            case CAVEAT_EXPIRES: expiresAt = min(expiresAt ?? f("at"), f("at"))
            case CAVEAT_NOT_BEFORE: notBefore = max(notBefore ?? f("at"), f("at"))
            case CAVEAT_RATE:
                let m = f("max"), per = f("per_secs")
                // the lower sustained rate (max / per_secs) binds; ties are broken by the smaller max
                if let cur = maxRate { if m / per < cur.0 / cur.1 || (m / per == cur.0 / cur.1 && m < cur.0) { maxRate = (m, per) } } else { maxRate = (m, per) }
            case CAVEAT_MAX_BLAST_RADIUS: maxBlast = min(maxBlast ?? f("max"), f("max"))
            case CAVEAT_REVERSIBILITY_MAX:
                if let c = cv["class"]?.asString, let i = REV.firstIndex(where: { IV.same($0, c) }), i < (revMax ?? REV.count) { revMax = i }
            case CAVEAT_DELEGATION_DEPTH:
                let rem = f("max") - Double(list.count - 1)
                depthRem = min(depthRem ?? rem, rem)
            case "budget_alloc": budget = min(budget ?? f("limit"), f("limit"))
            case CAVEAT_MAX_SPEND: maxSpend = min(maxSpend ?? f("usd"), f("usd"))
            default: break
            }
        }
        if let e = env0 { for cv in e["caveats"]?.asArray ?? [] { try fold(cv, true) } }
        for cv in leaf.get("caveats")?.asArray ?? [] { try fold(cv, false) }

        var opaque = Set<String>()
        var scopesV: JSONValue = .null, verbsV: JSONValue = .null, resourcesV: JSONValue = .null
        if let sc = scopes {
            var vs: [String] = [], rs: [String] = []
            for x in sc { vs += x.verbs; for r in x.resources { rs.append(r); if r.hasPrefix("re:") { opaque.insert(r) } } }
            scopesV = .array(sc.map { $0.value })
            verbsV = .array(sortedUnique(vs).map { JSONValue.string($0) })
            resourcesV = .array(sortedUnique(rs).map { JSONValue.string($0) })
        }
        var toolsV: JSONValue = tools.map { .array(sortedUnique($0).map { JSONValue.string($0) }) } ?? .null
        let unsat = bad.sorted(by: utf8Less)
        var reason: String?
        if !unsat.isEmpty {
            scopesV = .array([]); verbsV = .array([]); resourcesV = .array([]); toolsV = .array([])
            reason = "unsatisfiable caveat(s): " + unsat.joined(separator: ", ")
        }
        var h: JObject = [:]
        if let v = expiresAt { h["expiresAt"] = num(v); if let n = now, n.isFinite { h["expiresIn"] = num(v - n) } }
        if let v = notBefore { h["notBefore"] = num(v) }
        if let r = maxRate { h["maxRate"] = .object(["max": num(r.0), "per_secs": num(r.1)]) }
        if let v = maxBlast { h["maxBlastRadius"] = num(v) }
        if let i = revMax { h["reversibilityMax"] = s(REV[i]) }
        if let v = depthRem { h["delegationDepthRemaining"] = num(v) }
        if let v = budget { h["budgetAlloc"] = num(v) }
        if let v = maxSpend { h["maxSpendUsd"] = num(v) }
        var env: JObject = ["ok": .bool(true), "hasEnvelope": .bool(env0 != nil), "scopes": scopesV, "verbs": verbsV, "resources": resourcesV,
                            "opaqueResourceConstraints": .array(sortedUnique(Array(opaque)).map { JSONValue.string($0) }), "tools": toolsV, "toolSchemas": .array(toolSchemas),
                            "unsatisfiable": .array(unsat.map { JSONValue.string($0) }), "caveats": leaf.get("caveats") ?? .null, "remainingBudgetHints": .object(h)]
        if let r = reason { env["reason"] = s(r) }
        return .object(env)
    }

    private static func scopeMatches(_ sc: JSONValue, _ verb: String, _ resource: String, _ params: JSONValue?) -> Bool? {
        guard case let .array(verbs)? = sc.get("verbs"), case let .array(resources)? = sc.get("resources"), case let .array(wh)? = sc.get("where") else { return nil }
        if !verbs.contains(where: { ToolSchema.eqs($0, "*") || ToolSchema.eqs($0, verb) }) { return false }
        var action: JObject = ["verb": s(verb), "resource": s(resource)]
        if let p = params { action["params"] = p }
        let ctx = JSONValue.object(["action": .object(action)])
        let budget = SafeRegex.Budget()
        for r in resources where !Predicates.predicateMatches(.object(["verb": s("*"), "resource": r]), ctx, budget) { return false }
        if params != nil && !wh.isEmpty { return Predicates.predicateMatches(.object(["verb": s("*"), "where": .array(wh)]), ctx, budget) }
        return true
    }

    /// The cheap pre-flight an agent can run before attempting. false is DEFINITIVE (the verifier will refuse); true means the symbolic envelope allows
    /// it. `env` is the result of `describeEnvelope`. When `params` is given, `where` conditions are evaluated too (fail closed); without it, conditional
    /// scopes count as "may permit". `now` nil = not given; a NaN or infinite `now` is refused, and expiry is exclusive. Total.
    public static func envelopePermits(_ env: JSONValue?, verb: String, resource: String, now: Double? = nil, params: JSONValue? = nil) -> Bool {
        guard case let .object(e)? = env, e["ok"] == .bool(true), case let .array(unsat)? = e["unsatisfiable"], unsat.isEmpty else { return false }
        switch e["scopes"] {
        case .null?: break
        case let .array(scopes)?:
            var any = false
            for sc in scopes {
                guard let m = scopeMatches(sc, verb, resource, params) else { return false }
                if m { any = true; break }
            }
            if !any { return false }
        default: return false
        }
        guard let h = e["remainingBudgetHints"] else { return false }
        // a hint that is present but not a finite non-negative number (NaN, an infinity) is refused, never skipped
        if let rv = h.get("delegationDepthRemaining"), rv != .null { guard let d = IV.num(rv), d.isFinite, d >= 0 else { return false } }
        if let lim = fin(h.get("maxSpendUsd")), let p = params {
            guard let spend = actionSpendUsd(.object(["action": .object(["params": p])])), spend <= lim else { return false }
        }
        if let n = now {
            if !n.isFinite { return false }
            if let ev = h.get("expiresAt"), ev != .null { guard let at = IV.num(ev), at.isFinite, n < at else { return false } }
            if let nv = h.get("notBefore"), nv != .null { guard let nb = IV.num(nv), nb.isFinite, n >= nb else { return false } }
        }
        return true
    }

    /// Pre-flight for a tool call: the tool must be in `env.tools` (when that is not null) and satisfy EVERY `tool_schema` caveat of the chain; the first
    /// failure is returned. `env` is the result of `describeEnvelope`. Total.
    public static func envelopePermitsToolCall(_ env: JSONValue?, _ call: JSONValue?) -> (ok: Bool, reason: String?) {
        let failClosed: (Bool, String?) = (false, "evaluation error (fail closed)")
        guard case let .object(e)? = env else { return failClosed }
        let unsat = e["unsatisfiable"]?.asArray
        if e["ok"] != .bool(true) || unsat == nil || !unsat!.isEmpty {
            if e["ok"] == .bool(true) && unsat == nil { return failClosed }
            if let r = JS.present(e["reason"]) { return (false, IntentV2.jsString(r)) }
            return (false, "envelope not usable")
        }
        switch e["tools"] {
        case .null?: break
        case let .array(tools)?:
            guard let c = call, c != .null else { return failClosed }
            let tool = c.get("tool")
            if case let .string(t)? = tool, tools.contains(where: { ToolSchema.eqs($0, t) }) {} else {
                return (false, "tool \(ToolSchema.show(tool.map { IntentV2.jsString($0) } ?? "undefined")) not authorized")
            }
        default: return failClosed
        }
        guard case let .array(schemas)? = e["toolSchemas"] else { return failClosed }
        for tc in schemas {
            let r = evaluateToolSchemaCall(tc, call)
            if !r.ok { return r }
        }
        return (true, nil)
    }

    // ======================================================================================
    // 5. Authority lease
    // ======================================================================================

    private static func isNonNegInt(_ v: JSONValue?) -> Bool { ToolSchema.isInt(v) && (fin(v) ?? -1) >= 0 }

    /// Issue a lease `{cap_id, holder, issued_at, renewed_at, ttl_ms, renewals, last_seq, expires_at, hard_expires_at?, max_renewals?}` from `{cap_id,
    /// holder, now, ttl_ms, hard_expires_at?, max_renewals?}`. Throws (authoring error) unless the ids are non-empty, `now` is finite, `0 < ttl_ms <=
    /// MAX_LEASE_TTL_MS`, `hard_expires_at` (if present) is finite and after `now`, and `max_renewals` (if present) is a non-negative integer. Persist and
    /// update the record atomically (row lock or compare-and-swap on `last_seq`); `renewCapabilityLease` is a pure function returning the next record.
    public static func grantLease(_ args: JSONValue?) throws -> JSONValue {
        guard case let .object(a)? = args, let capId = nonEmpty(a["cap_id"]), let holder = nonEmpty(a["holder"]) else { throw PCAProducerError("grantLease: cap_id and holder required") }
        guard let now = fin(a["now"]), let ttl = fin(a["ttl_ms"]), ttl > 0, ttl <= Double(MAX_LEASE_TTL_MS) else { throw PCAProducerError("grantLease: invalid now/ttl_ms") }
        var hard: Double?
        if let h = a["hard_expires_at"] {
            guard let f = fin(h), f > now else { throw PCAProducerError("grantLease: hard_expires_at must be finite and in the future") }
            hard = f
        }
        if let m = a["max_renewals"], !isNonNegInt(m) { throw PCAProducerError("grantLease: invalid max_renewals") }
        var l: JObject = ["cap_id": s(capId), "holder": s(holder), "issued_at": a["now"]!, "renewed_at": a["now"]!, "ttl_ms": a["ttl_ms"]!, "renewals": .int(0), "last_seq": .int(0),
                          "expires_at": num(hard.map { min(now + ttl, $0) } ?? now + ttl)]
        if hard != nil { l["hard_expires_at"] = a["hard_expires_at"]! }
        if let m = a["max_renewals"] { l["max_renewals"] = m }
        return .object(l)
    }

    private static func leaseError(_ lv: JSONValue?) -> String? {
        let malformed = "malformed lease"
        guard case let .object(l)? = lv, nonEmpty(l["cap_id"]) != nil, nonEmpty(l["holder"]) != nil else { return malformed }
        guard fin(l["issued_at"]) != nil, let renewed = fin(l["renewed_at"]), let ttl = fin(l["ttl_ms"]), let expires = fin(l["expires_at"]) else { return malformed }
        if ttl <= 0 || ttl > Double(MAX_LEASE_TTL_MS) { return malformed }
        if !isNonNegInt(l["renewals"]) || !isNonNegInt(l["last_seq"]) { return malformed }
        if let m = l["max_renewals"], !isNonNegInt(m) { return malformed }
        if let hv = l["hard_expires_at"] {
            guard let hard = fin(hv) else { return malformed }
            if expires > hard { return "lease exceeds hard expiry" }
        }
        // a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
        if expires > renewed + ttl { return malformed }
        return nil
    }

    /// Whether a lease is live at `now`: the record is well-formed, the clock has not rolled back more than `HEARTBEAT_SKEW_MS` past the last renewal, and
    /// `now < expires_at`. Returns `{live: true, expiresIn}` or `{live: false, expiresIn: 0, reason}` (malformed, NaN or rolled-back is not live: fail
    /// closed; a lapsed lease has `expiresIn` 0).
    public static func leaseState(_ lease: JSONValue?, _ now: Double) -> JSONValue {
        func dead(_ r: String) -> JSONValue { .object(["live": .bool(false), "expiresIn": .int(0), "reason": s(r)]) }
        if !now.isFinite { return dead("invalid clock") }
        if let e = leaseError(lease) { return dead(e) }
        let renewed = fin(lease?.get("renewed_at")) ?? 0, expiresIn = (fin(lease?.get("expires_at")) ?? 0) - now
        if !(now >= renewed - Double(HEARTBEAT_SKEW_MS)) { return dead("clock before last renewal") }
        if expiresIn <= 0 { return dead("lease lapsed") }
        return .object(["live": .bool(true), "expiresIn": num(expiresIn)])
    }

    /// Renew a capability lease (the agent-native lease of `grantLease`, not the grants `LeaseRegistry`) on a valid, fresh, in-order, holder-signed heartbeat
    /// for THIS lease grant. A lease that has already lapsed (or is malformed or clock-anomalous) is dead for good: no resurrection by a late heartbeat.
    /// Renewal never extends past `hard_expires_at`, never shortens the lease and consumes the renewal budget. The checks run in this order and the reason
    /// names the first that fails. Returns `{ok: true, lease}` or `{ok: false, reason}`. Pure and total.
    public static func renewCapabilityLease(_ lease: JSONValue?, _ hb: JSONValue?, _ now: Double) -> JSONValue {
        func refuse(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": s(r)]) }
        let st = leaseState(lease, now)
        if st.get("live") != .bool(true) {
            let r = st.get("reason")?.asString ?? ""
            return refuse(r == "lease lapsed" ? "lease lapsed" : "lease not live: \(r)")
        }
        guard case let .object(l)? = lease, case let .object(h)? = hb, case let .string(sig)? = h["sig"], h.keys.allSatisfy({ k in HB_KEYS.contains { IV.same($0, k.s) } }) else { return refuse("malformed heartbeat") }
        let sameNum: (JSONValue?, JSONValue?) -> Bool = { a, b in if let x = fin(a), let y = fin(b) { return x == y }; return false }
        if !same(h["cap_id"], l["cap_id"]) || !same(h["holder"], l["holder"]) || !sameNum(h["lease_issued_at"], l["issued_at"]) { return refuse("heartbeat not for this lease") }
        let lastSeq = fin(l["last_seq"]) ?? 0
        guard let seq = fin(h["seq"]), seq == seq.rounded(.towardZero), abs(seq) <= 9007199254740991, seq > lastSeq else { return refuse("stale or replayed heartbeat") }
        guard let at = fin(h["at"]), abs(at - now) <= Double(HEARTBEAT_SKEW_MS) else { return refuse("heartbeat outside skew window") }
        var body = h
        body["sig"] = nil
        guard let msg = try? PCASigners.msgOf(PCASigners.HEARTBEAT_DOMAIN, .object(body)) else { return refuse("malformed heartbeat") }
        if !Ed25519Strict.verifyB64u(l["holder"]?.asString ?? "", msg, sig) { return refuse("bad heartbeat signature") }
        let renewals = fin(l["renewals"]) ?? 0
        if let mr = fin(l["max_renewals"]), renewals >= mr { return refuse("renewal budget exhausted") }
        var exp = now + (fin(l["ttl_ms"]) ?? 0)
        if let hard = fin(l["hard_expires_at"]) { exp = min(exp, hard) }
        if !exp.isFinite { return refuse("malformed lease") }
        var next = l
        next["renewals"] = num(renewals + 1)
        next["last_seq"] = h["seq"]!
        next["renewed_at"] = num(max(now, fin(l["renewed_at"]) ?? now))
        next["expires_at"] = num(max(exp, fin(l["expires_at"]) ?? exp))
        return .object(["ok": .bool(true), "lease": .object(next)])
    }
}
