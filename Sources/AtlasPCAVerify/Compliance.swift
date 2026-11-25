import Foundation

/// Compliance evidence from PCA proofs: a verified action + its decision become an audit event, audit events map onto the controls of
/// EU AI Act (Art. 12, 50), ISO/IEC 42001 and SOC 2 CC6 as a report with coverage, and a console activity stream maps onto EU AI Act /
/// SOC 2 / GDPR controls. An evidence mapping, not a legal certification: `satisfied` means the evidence a control asks for is present.
///
/// Everything is pure over `JSONValue` and mirrors the reference's JavaScript value semantics (a property read of null / undefined is a
/// TypeError -> `JSError`; templates stringify like JS; `>` coerces). A non-finite number is `null` in the produced JSON.
/// shortcut: a parsed `JSONValue` object has no insertion order, so wherever the reference enumerates a caller's object in insertion
/// order (a caveat's members, a value serialized by `renderJson`) the order comes from `KeyOrder`: index keys ascending, then the report /
/// event schema's own member order, then the rest in code-unit order. Pass a `KeyOrder` that knows the producer's order for exactness.
/// shortcut: `frameworkReportToMarkdown` formats `generatedAt` for a number, null or boolean; a date string (the reference parses it)
/// is refused.
public enum PCACompliance {
    typealias P = PayJS
    public typealias KeyOrder = (JObject) -> [String]

    struct ControlMapping {
        let framework: String, controlId: String, controlTitle: String, clause: String, requirement: String, pcaEvidence: String
        let evidenceFields: [String]
        var json: JSONValue {
            .object(["framework": .string(framework), "controlId": .string(controlId), "controlTitle": .string(controlTitle), "clause": .string(clause),
                     "requirement": .string(requirement), "pcaEvidence": .string(pcaEvidence), "evidenceFields": .array(evidenceFields.map { .string($0) })])
        }
    }

    // MARK: shared JS helpers

    /// Member order of the objects this package produces (consistent across them: report, items, coverage, assurances, timestamps).
    static let schemaOrder = ["schema", "controlId", "controlTitle", "clause", "framework", "status", "pcaEvidence", "evidence", "findings",
                              "generatedAt", "period", "from", "to", "epochMs", "iso", "eventCount", "assurances",
                              "cryptographicallyVerifiable", "explicitDelegationChain", "signedHumanOverrides", "narrative", "items", "coverage",
                              "total", "satisfied", "partial", "notEvidenced", "satisfiedFraction", "satisfiedPercent", "summary"]

    public static func defaultOrder(_ o: JObject) -> [String] {
        let all = o.keys.map { $0.s }
        let idx = all.compactMap { k in JS.indexKey(k).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        let known = schemaOrder.filter { k in o[JKey(k)] != nil && JS.indexKey(k) == nil }
        let rest = all.filter { JS.indexKey($0) == nil && !schemaOrder.contains($0) }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        return idx + known + rest
    }

    /// `JSON.stringify(v)` (compact) or `JSON.stringify(v, null, 2)`.
    static func stringify(_ v: JSONValue, _ order: KeyOrder, pretty: Bool) -> String {
        func pad(_ d: Int) -> String { String(repeating: "  ", count: d) }
        func go(_ v: JSONValue, _ d: Int) -> String {
            switch v {
            case let .array(a):
                if a.isEmpty { return "[]" }
                let items = a.map { go($0, d + 1) }
                return pretty ? "[\n" + items.map { pad(d + 1) + $0 }.joined(separator: ",\n") + "\n" + pad(d) + "]" : "[" + items.joined(separator: ",") + "]"
            case let .object(o):
                if o.isEmpty { return "{}" }
                let members = order(o).compactMap { k -> String? in
                    guard let x = o[JKey(k)] else { return nil }
                    return Canonical.canonicalize(.string(k)) + (pretty ? ": " : ":") + go(x, d + 1)
                }
                return pretty ? "{\n" + members.map { pad(d + 1) + $0 }.joined(separator: ",\n") + "\n" + pad(d) + "}" : "{" + members.joined(separator: ",") + "}"
            default: return JS.stringify(v)
            }
        }
        return go(v, 0)
    }

    static func numberOf(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        default: return nil
        }
    }
    static func finiteOf(_ v: JSONValue?) -> Double? { numberOf(v).flatMap { $0.isFinite ? $0 : nil } }
    static func numJSON(_ d: Double) -> JSONValue { P.num(d) }
    static func nowMs() -> JSONValue { .int(Int64((Date().timeIntervalSince1970 * 1000).rounded(.down))) }

    /// `{epochMs, iso}`: a finite number renders as ISO-8601; a non-number or non-finite value is "(unknown time)"; an unrepresentable one too.
    static func ts(_ v: JSONValue) -> JSONValue {
        var epoch = v
        if case let .double(d) = v, !d.isFinite { epoch = .null }
        let iso: String
        if let d = finiteOf(v) { iso = PCASiem.isoString(d) ?? "(unrepresentable time)" } else { iso = "(unknown time)" }
        return .object(["epochMs": epoch, "iso": .string(iso)])
    }

    /// Abbreviates a long key for display.
    static func short(_ key: JSONValue?, _ n: Int = 12) -> String {
        guard case let .string(s)? = key, !s.isEmpty else { return "(none)" }
        return s.utf16.count <= n + 1 ? s : PCASiem.cut(s, n) + "\u{2026}"
    }

    static func numStr(_ v: JSONValue) -> String {
        guard let x = finiteOf(v) else { return JS.toString(v) }
        if x == x.rounded() { return JS.number(x) }
        return JS.number(P.jsRound(x * 1e4) / 1e4)
    }

    static func str(_ v: JSONValue?) -> String? { v?.asString }
    static func t(_ v: JSONValue?) -> String { JS.toString(v) }

    // MARK: audit event

    /// `isBudgetAllocCaveat`: a budget_alloc caveat with a finite limit >= 0 (the limit).
    static func budgetLimit(_ cv: JSONValue) -> JSONValue? {
        guard case let .object(o) = cv, o[JKey("type")] == .string("budget_alloc"), let l = o[JKey("limit")], let d = finiteOf(l), d >= 0 else { return nil }
        return l
    }

    static func describeCaveat(_ cv: JSONValue, _ order: KeyOrder) -> String {
        guard case let .object(o) = cv, case let .string(type)? = o[JKey("type")] else { return "(malformed caveat)" }
        if type == "envelope" {
            let preds = o[JKey("predicates")]?.asArray?.count ?? 0
            let inner = o[JKey("caveats")]?.asArray?.count ?? 0
            return "policy envelope (\(preds) predicate(s), \(inner) caveat(s))"
        }
        if let l = budgetLimit(cv) { return "budget allocation \u{2264} \(numStr(l))" }
        var parts: [String] = []
        for k in order(o).prefix(8) where k != "type" {
            guard let v = o[JKey(k)] else { continue }
            parts.append("\(k)=\(v.isObject || v.isArray ? stringify(v, order, pretty: false) : numStr(v))")
        }
        return parts.isEmpty ? type : "\(type)(\(parts.joined(separator: ", ")))"
    }

    static func buildDelegationHops(_ chain: [JSONValue], _ order: KeyOrder) throws -> [JSONValue] {
        var hops: [JSONValue] = []
        for (i, cap) in chain.enumerated() {
            if !JS.truthy(cap) { continue }
            let isRoot = i == 0
            var parentLen = 0
            if i > 0, JS.truthy(chain[i - 1]), case let .array(c)? = try P.prop(chain[i - 1], "caveats") { parentLen = c.count }
            var own: [JSONValue] = []
            if case let .array(c)? = try P.prop(cap, "caveats") { own = c }
            let added: [JSONValue] = isRoot ? own : own.count >= parentLen ? Array(own[parentLen...]) : []
            let scope = added.map { describeCaveat($0, order) }
            let budget = added.compactMap { budgetLimit($0) }.first
            let issuer = try P.prop(cap, "issuer"), holder = try P.prop(cap, "holder")
            let joined = scope.joined(separator: "; ")
            let narrative = isRoot
                ? "Principal \(short(issuer)) granted authority to \(short(holder))\(scope.isEmpty ? "" : " under: \(joined)")."
                : "\(short(issuer)) delegated to \(short(holder))\(scope.isEmpty ? " (rebind only, no new constraints)" : ", narrowing scope: \(joined)")."
            var h: JObject = ["index": .int(Int64(i)), "isRoot": .bool(isRoot), "scope": .array(scope.map { .string($0) }), "caveats": .array(added),
                              "narrative": .string(narrative)]
            if let x = issuer { h["issuer"] = x }
            if let x = holder { h["holder"] = x }
            if let b = budget { h["budgetAlloc"] = b }
            hops.append(.object(h))
        }
        return hops
    }

    static func buildHumanOverride(_ threshold: JSONValue?, _ requiredTier: JSONValue, _ check: JSONValue?) throws -> JSONValue? {
        var shares: [JSONValue] = []
        if JS.truthy(threshold), case let .array(s)? = try P.prop(threshold, "shares") { shares = s }
        if shares.isEmpty { return nil }
        // `threshold` sits outside the signed body: its contents prove nothing until a threshold verifier passed
        if check != .string("pass") {
            let shown = (check == nil || check == .null) ? "absent" : t(check)
            return .object(["humanApproved": .bool(false), "approvers": .array([]), "guardianCosigners": .array([]), "roles": .array([]),
                            "requiredTier": requiredTier,
                            "narrative": .string("\(shares.count) co-signature share(s) were presented but NOT verified (threshold check: \(shown)); no human approval is recorded.")])
        }
        var approvers: [String] = [], guardians: [String] = [], roles: [String] = []
        for s in shares {
            guard JS.truthy(s), case let .string(role)? = try P.prop(s, "role") else { continue }
            roles.append(role)
            if role == "principal", case let .string(k)? = try P.prop(s, "publicKey") { approvers.append(k) }
            if role == "guardian", case let .string(k)? = try P.prop(s, "publicKey") { guardians.append(k) }
        }
        let approved = !approvers.isEmpty
        let tier = t(requiredTier)
        let narrative = approved
            ? "Step-up approved by a signed human co-signature from principal \(short(.string(approvers[0])))\(guardians.isEmpty ? "" : " (plus \(guardians.count) guardian co-sign)") at tier t=\(tier)."
            : "Co-signed by \(guardians.count) guardian share(s) at tier t=\(tier) (no human principal signature present)."
        return .object(["humanApproved": .bool(approved), "approvers": .array(approvers.map { .string($0) }), "guardianCosigners": .array(guardians.map { .string($0) }),
                        "roles": .array(roles.map { .string($0) }), "requiredTier": requiredTier, "narrative": .string(narrative)])
    }

    static func firstReasonOr(_ decision: JSONValue?, _ fallback: String) throws -> JSONValue {
        if case let .array(rs)? = try P.prop(decision, "reasons"), case let .string(s)? = rs.first { return .string(s) }
        return .string(fallback)
    }

    static func resolveOutcome(_ verify: JSONValue, _ decision: JSONValue?) throws -> (String, JSONValue) {
        if try !JS.truthy(verify) || (try P.optprop(verify, "allow")) != .bool(true) {
            return ("deny", JS.present(try P.optprop(verify, "reason")) ?? .string("proof failed verification"))
        }
        if !JS.truthy(decision) { return ("allow", .string("proof verified; no policy decision supplied")) }
        if JS.truthy(try P.prop(decision, "admit")) { return ("allow", try firstReasonOr(decision, "auto-admitted within policy and budget")) }
        if JS.truthy(try P.prop(decision, "releaseGuardianShare")) { return ("step-up", try firstReasonOr(decision, "policy satisfied but a co-signature is required")) }
        return ("deny", try firstReasonOr(decision, "policy did not release authority (default-deny)"))
    }

    static func digest(_ p: JSONValue?) -> String {
        guard let p = p, let b = try? Canonical.canonicalBytes(p) else { return "(undigestible)" }
        return Base64URLStrict.encode(Canonical.sha256(b))
    }

    /// One normalized audit event from a PCActn, its verify result and its decision `{pcactn, verify, decision?, now?, session?}`.
    /// Total over malformed members; a null / missing input is refused (a property read of null).
    public static func toAuditEvent(_ input: JSONValue?, order: KeyOrder = PCACompliance.defaultOrder) throws -> JSONValue {
        let p = try P.prop(input, "pcactn")
        let verify: JSONValue = JS.present(try P.prop(input, "verify")) ?? .object(["allow": .bool(false), "checks": .object([:])])
        let now: JSONValue = JS.present(try P.prop(input, "now")) ?? nowMs()
        var chain: [JSONValue] = []
        if case let .array(c)? = try P.optprop(p, "cap_chain") { chain = c }
        let hops = try buildDelegationHops(chain, order)
        let leaf = chain.last, root = chain.first
        let decision = try P.prop(input, "decision")
        let (outcome, reason) = try resolveOutcome(verify, decision)
        let requiredTier: JSONValue = JS.present(try P.optprop(try P.optprop(decision, "requiredThreshold"), "t")) ?? .int(1)
        let humanOverride = try buildHumanOverride(try P.optprop(p, "threshold"), requiredTier, try P.optprop(try P.prop(verify, "checks"), "threshold"))
        let checks: JSONValue = JS.present(try P.prop(verify, "checks")) ?? .object([:])
        let verifiable = try (try P.prop(checks, "wire")) == .string("pass") && (try P.prop(checks, "leaf_signature")) == .string("pass")

        let action = try P.optprop(p, "action")
        func s(_ v: JSONValue?, _ fb: String) -> String { str(v) ?? fb }
        let verb = s(try P.optprop(action, "verb"), "(unknown verb)")
        let resource = s(try P.optprop(action, "resource"), "(unknown resource)")
        let grantRef = s(try P.optprop(p, "grant_ref"), "(none)")
        let paramsDigest = s(try P.optprop(action, "params_digest"), "(none)")

        var evidence: JObject = [
            "pcactnDigest": .string(digest(p)), "leafSignature": .string(s(try P.optprop(p, "sig"), "(unsigned)")),
            "signatureSuite": .string(s(try P.optprop(p, "alg"), "ed25519")), "planRoot": .string(s(try P.optprop(try P.optprop(p, "plan"), "root"), "(none)")),
            "paramsDigest": .string(paramsDigest), "grantRef": .string(grantRef),
            "counter": numberOf(try P.optprop(p, "counter")) != nil ? (try P.optprop(p, "counter"))! : .int(-1),
            "cryptographicallyVerifiable": .bool(verifiable),
        ]
        if case let .string(n)? = try P.optprop(p, "nonce") { evidence["nonce"] = .string(n) }

        var risk = JObject()
        if JS.truthy(decision) {
            if let r = try P.prop(decision, "r") { risk["r"] = r }
            let rt = try P.optprop(decision, "requiredThreshold")
            if let x = try P.optprop(rt, "t") { risk["tier"] = x }
            if let x = try P.optprop(rt, "proof") { risk["proof"] = x }
            if let x = try P.prop(decision, "budget") { risk["budget"] = x }
        }

        let word = outcome == "allow" ? "ALLOWED" : outcome == "deny" ? "DENIED" : "STEP-UP"
        let approved = JS.truthy(try P.optprop(humanOverride, "humanApproved"))
        let narrative = "Agent \(short(try P.optprop(leaf, "holder"))) \(word) to \(verb) on \(resource) "
            + "(\(hops.count)-hop chain rooted at principal \(short(try P.optprop(root, "issuer"))); "
            + (verifiable ? "cryptographically verifiable proof" : "proof not cryptographically verifiable")
            + (approved ? "; human-signed step-up" : "") + "). \(t(reason))"

        var agent: JObject = ["holder": .string(s(try P.optprop(leaf, "holder"), "(none)")),
                              "session": JS.present(try P.prop(input, "session")) ?? .string(grantRef)]
        if case let .string(r)? = try P.optprop(root, "issuer") { agent["principal"] = .string(r) }
        var ev: JObject = [
            "schema": .string("atlas-pca/audit-event/v1"), "recordedAt": ts(now), "agent": .object(agent),
            "delegation": .object(["depth": .int(Int64(max(0, hops.count - 1))), "hops": .array(hops)]),
            "action": .object(["verb": .string(verb), "resource": .string(resource), "paramsDigest": .string(paramsDigest),
                               "reversibilityClass": .string(s(try P.optprop(action, "reversibility_class"), "(unknown)")), "summary": .string("\(verb) on \(resource)")]),
            "decision": .object(["outcome": .string(outcome), "reason": reason, "proofVerified": .bool(try P.optprop(verify, "allow") == .bool(true)), "checks": checks]),
            "risk": .object(risk),
            "timestamps": .object(["issuedAt": ts(numberOf(try P.optprop(p, "iat")) != nil ? (try P.optprop(p, "iat"))! : .double(.nan)),
                                   "expiresAt": ts(numberOf(try P.optprop(p, "exp")) != nil ? (try P.optprop(p, "exp"))! : .double(.nan))]),
            "evidence": .object(evidence), "narrative": .string(narrative),
        ]
        if let h = humanOverride { ev["humanOverride"] = h }
        return .object(ev)
    }

    // MARK: control mappings

    static func assertFramework(_ v: JSONValue?) throws {
        guard let s = v?.asString, frameworks.contains(s) else {
            throw JSError("pca-compliance: unknown framework '\(t(v))' (have: \(frameworks.joined(separator: ", ")))")
        }
    }

    /// The control mappings of one framework (nil = the whole table); an unknown framework is refused.
    public static func controlMappings(_ framework: JSONValue? = nil) throws -> JSONValue {
        if framework == nil { return .array(mappings.map { $0.json }) }
        try assertFramework(framework)
        return .array(mappings.filter { $0.framework == framework?.asString }.map { $0.json })
    }

    /// {COMPLIANCE_FRAMEWORKS, CONTROL_MAPPINGS}.
    public static func constants() -> JSONValue {
        .object(["COMPLIANCE_FRAMEWORKS": .array(frameworks.map { .string($0) }), "CONTROL_MAPPINGS": .array(mappings.map { $0.json })])
    }

    // MARK: compliance report

    struct Stats {
        var total = 0, verifiable = 0, denied = 0, stepUp = 0, allowed = 0, humanOverrides = 0, withChain = 0, withPlanRoot = 0
        var maxDepth: JSONValue = .int(0)
        var agents = 0, principals = 0
        var sampleDigest: JSONValue?
    }

    /// SameValueZero identity of a value in a `Set`: primitives by value, an object or array is its own identity.
    static func setKey(_ v: JSONValue?, _ n: inout Int) -> String {
        switch v {
        case nil: return "u"
        case .null?: return "n"
        case let .bool(b)?: return b ? "bt" : "bf"
        case .int?, .double?: return "d:" + JS.toString(v)
        case let .string(s)?: return "s:" + s.unicodeScalars.map { String($0.value) }.joined(separator: ",")
        default: n += 1; return "o:\(n)"
        }
    }

    static func computeStats(_ events: [JSONValue]) throws -> Stats {
        var s = Stats()
        s.total = events.count
        var agents = Set<String>(), principals = Set<String>()
        var uid = 0
        for e in events {
            if !JS.truthy(e) { continue }
            let evidence = try P.prop(e, "evidence")
            if JS.truthy(try P.prop(evidence, "cryptographicallyVerifiable")) { s.verifiable += 1 }
            let outcome = try P.prop(try P.prop(e, "decision"), "outcome")
            if outcome == .string("deny") { s.denied += 1 } else if outcome == .string("step-up") { s.stepUp += 1 } else { s.allowed += 1 }
            if JS.truthy(try P.optprop(try P.prop(e, "humanOverride"), "humanApproved")) { s.humanOverrides += 1 }
            let delegation = try P.prop(e, "delegation")
            if P.jsGt(try P.length(try P.prop(delegation, "hops")), .int(0)) { s.withChain += 1 }
            if (try P.prop(evidence, "planRoot")) != .string("(none)") { s.withPlanRoot += 1 }
            let depth = try P.prop(delegation, "depth")
            if P.jsGt(depth, s.maxDepth), let d = depth { s.maxDepth = d }
            let agent = try P.prop(e, "agent")
            agents.insert(setKey(try P.prop(agent, "holder"), &uid))
            if let pr = try P.prop(agent, "principal") { principals.insert(setKey(pr, &uid)) }
            if s.sampleDigest == nil {
                let d = try P.prop(evidence, "pcactnDigest")
                if d != .string("(undigestible)") { s.sampleDigest = d }
            }
        }
        s.agents = agents.count
        s.principals = principals.count
        return s
    }

    static func evaluateControl(_ id: String, _ s: Stats) -> (status: String, evidence: String, findings: [String]) {
        var findings: [String] = []
        let digestNote = s.sampleDigest.map { " (e.g. \(short($0, 16)))" } ?? ""
        if s.total == 0 { return ("not-evidenced", "no actions in the reporting period", ["no events supplied \u{2014} nothing to evidence"]) }
        let maxDepth = t(s.maxDepth)
        switch id {
        case "eu-ai-act:art-12":
            if s.verifiable < s.total { findings.append("\(s.total - s.verifiable) of \(s.total) entries are not cryptographically verifiable") }
            return (s.verifiable == s.total ? "satisfied" : "partial",
                    "\(s.total) actions logged; \(s.verifiable)/\(s.total) cite a cryptographically verifiable proof\(digestNote)", findings)
        case "eu-ai-act:art-50":
            return ("satisfied", "\(s.total) actions each disclose the acting agent, the principal (\(s.principals) distinct) and the automated decision outcome", findings)
        case "iso-42001:A.6.2.8":
            return ("satisfied", "\(s.total) actions each carry a decision reason + risk/tier/budget reasoning trace", findings)
        case "iso-42001:A.9.2":
            let status = s.withChain == s.total ? "satisfied" : s.withChain > 0 ? "partial" : "not-evidenced"
            if s.withChain < s.total { findings.append("\(s.total - s.withChain) entries have no delegation chain") }
            return (status, "\(s.withChain)/\(s.total) actions carry an explicit delegation chain (max depth \(maxDepth), \(s.principals) authorizing principal(s))", findings)
        case "iso-42001:A.9.3":
            if s.humanOverrides > 0 {
                return ("satisfied", "\(s.humanOverrides) step-up(s) approved by a signed human co-signature; \(s.stepUp) step-up(s) and \(s.denied) denial(s) show oversight enforced", findings)
            } else if s.stepUp > 0 || s.denied > 0 {
                findings.append("no human step-up co-signature was exercised in this period")
                return ("partial", "oversight boundary enforced (\(s.stepUp) step-up(s), \(s.denied) denial(s)) but no signed human co-signature observed in the period", findings)
            }
            findings.append("no higher-impact action required human oversight in this period")
            return ("partial", "all actions were auto-admitted within policy; no oversight event was triggered in the period", findings)
        case "iso-42001:A.6.2.2":
            let status = s.withPlanRoot == s.total ? "satisfied" : s.withPlanRoot > 0 ? "partial" : "not-evidenced"
            if s.withPlanRoot < s.total { findings.append("\(s.total - s.withPlanRoot) entries are not bound to a committed plan root") }
            return (status, "\(s.withPlanRoot)/\(s.total) actions are bound to a committed plan root (intended-use binding)", findings)
        case "soc2:CC6.1":
            if s.denied > 0 { findings.append("\(s.denied) out-of-scope action(s) denied \u{2014} access control actively enforced") }
            return ("satisfied", "deny-by-default access over \(s.total) actions (\(s.allowed) allowed, \(s.stepUp) step-up, \(s.denied) denied); all gated by signed predicates + attenuation", findings)
        case "soc2:CC6.2":
            let status = s.withChain == s.total ? "satisfied" : s.withChain > 0 ? "partial" : "not-evidenced"
            if s.withChain < s.total { findings.append("\(s.total - s.withChain) entries are not traceable to an authorizing principal") }
            return (status, "\(s.agents) agent identit(ies) traceable to \(s.principals) authorizing principal(s) via signed delegation chains", findings)
        case "soc2:CC6.3":
            let narrowed = JS.toNumber(s.maxDepth) >= 1
            if !narrowed && s.denied == 0 { findings.append("no attenuating hop or denial observed in the period") }
            return (narrowed || s.denied > 0 ? "satisfied" : "partial", "access narrowed by attenuation (max delegation depth \(maxDepth)) and \(s.denied) denied action(s)", findings)
        default:
            return ("not-evidenced", "no evaluator for this control", ["unmapped control"])
        }
    }

    /// The report for a framework (`eu-ai-act` / `iso-42001` / `soc2`) over audit events `{framework, now?}`: each mapped control with its
    /// status, the evidence drawn from these events, the PCA-unique assurances and a coverage summary.
    public static func toComplianceReport(_ events: JSONValue?, _ opts: JSONValue?) throws -> JSONValue {
        let framework = try P.prop(opts, "framework")
        try assertFramework(framework)
        let fw = framework!.asString!
        let list: [JSONValue] = events?.asArray?.filter { JS.truthy($0) } ?? []
        let now: JSONValue = JS.present(try P.prop(opts, "now")) ?? nowMs()
        let s = try computeStats(list)

        var items: [JSONValue] = []
        var counts = ["satisfied": 0, "partial": 0, "not-evidenced": 0]
        for m in mappings where m.framework == fw {
            let r = evaluateControl(m.controlId, s)
            counts[r.status, default: 0] += 1
            items.append(.object(["controlId": .string(m.controlId), "controlTitle": .string(m.controlTitle), "clause": .string(m.clause), "framework": .string(m.framework),
                                  "status": .string(r.status), "pcaEvidence": .string(m.pcaEvidence), "evidence": .string(r.evidence),
                                  "findings": .array(r.findings.map { .string($0) })]))
        }
        let satisfied = counts["satisfied"]!, partial = counts["partial"]!, notEvidenced = counts["not-evidenced"]!
        let total = items.count
        let fraction = total > 0 ? Double(satisfied) / Double(total) : 0

        var iats: [Double] = []
        for e in list {
            if let d = finiteOf(try P.prop(try P.prop(try P.prop(e, "timestamps"), "issuedAt"), "epochMs")) { iats.append(d) }
        }
        let from = iats.min() ?? 0, to = iats.max() ?? 0

        let narrative = s.total == 0 ? "No events in scope."
            : "\(s.verifiable)/\(s.total) entries cite a cryptographically verifiable proof; \(s.withChain)/\(s.total) carry an explicit delegation chain; \(s.humanOverrides) step-up(s) carry a signed human co-signature."
        let summary = "\(fw): \(satisfied)/\(total) controls satisfied" + (partial > 0 ? ", \(partial) partial" : "")
            + (notEvidenced > 0 ? ", \(notEvidenced) not evidenced" : "") + " over \(s.total) action(s)."
        return .object([
            "schema": .string("atlas-pca/compliance-report/v1"), "framework": .string(fw), "generatedAt": ts(now),
            "period": .object(["from": ts(numJSON(from)), "to": ts(numJSON(to))]), "eventCount": .int(Int64(s.total)),
            "assurances": .object(["cryptographicallyVerifiable": .bool(s.total > 0 && s.verifiable == s.total),
                                   "explicitDelegationChain": .bool(s.total > 0 && s.withChain == s.total),
                                   "signedHumanOverrides": .bool(s.humanOverrides > 0), "narrative": .string(narrative)]),
            "items": .array(items),
            "coverage": .object(["total": .int(Int64(total)), "satisfied": .int(Int64(satisfied)), "partial": .int(Int64(partial)), "notEvidenced": .int(Int64(notEvidenced)),
                                 "satisfiedFraction": numJSON(fraction), "satisfiedPercent": numJSON(P.jsRound(fraction * 100))]),
            "summary": .string(summary),
        ])
    }

    // MARK: renderers

    static func glyph(_ status: JSONValue?) throws -> String {
        switch t(status) {
        case "satisfied": return "\u{2713}"
        case "partial": return "\u{25D0}"
        case "not-evidenced": return "\u{00B7}"
        case "constructor", "__proto__", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
             "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__":
            throw JSError("status names an inherited object member (not representable)")
        default: return "undefined"
        }
    }

    /// `x.toUpperCase()`: a TypeError unless x is a string.
    static func upper(_ v: JSONValue?) throws -> String {
        guard case let .string(s)? = v else { throw JSError("toUpperCase is not a function") }
        return s.uppercased()
    }

    /// JSON.stringify(report, null, 2).
    public static func renderJson(_ report: JSONValue?, order: KeyOrder = PCACompliance.defaultOrder) throws -> String {
        guard let r = report else { throw JSError("nothing to serialize (undefined)") }
        return stringify(r, order, pretty: true)
    }

    /// An auditor-facing Markdown document (assurances, coverage, control table and detail) for a report.
    public static func renderMarkdown(_ report: JSONValue?) throws -> String {
        let r = report
        var lines: [String] = []
        lines.append("# PCA compliance evidence \u{2014} \(t(try P.prop(r, "framework")))")
        lines.append("")
        let cov = try P.prop(r, "coverage")
        lines.append("Generated \(t(try P.prop(try P.prop(r, "generatedAt"), "iso"))) \u{00B7} \(t(try P.prop(r, "eventCount"))) action(s) \u{00B7} "
            + "coverage: \(t(try P.prop(cov, "satisfied")))/\(t(try P.prop(cov, "total"))) satisfied (\(t(try P.prop(cov, "satisfiedPercent")))%)")
        if P.jsGt(try P.prop(r, "eventCount"), .int(0)) {
            lines.append("")
            let period = try P.prop(r, "period")
            lines.append("Reporting period: \(t(try P.prop(try P.prop(period, "from"), "iso"))) \u{2192} \(t(try P.prop(try P.prop(period, "to"), "iso")))")
        }
        lines.append("")
        lines.append("## Why this trail is admissible (what PCA uniquely provides)")
        lines.append("")
        let a = try P.prop(r, "assurances")
        lines.append("- **Cryptographically verifiable** \u{2014} \(JS.truthy(try P.prop(a, "cryptographicallyVerifiable")) ? "YES" : "PARTIAL"): every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.")
        lines.append("- **Explicit delegation chain** \u{2014} \(JS.truthy(try P.prop(a, "explicitDelegationChain")) ? "YES" : "PARTIAL"): each action records who authorized what scope, hop by hop, rooted at a principal.")
        lines.append("- **Signed human-overrides** \u{2014} \(JS.truthy(try P.prop(a, "signedHumanOverrides")) ? "YES" : "none in period"): a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.")
        lines.append("")
        lines.append("> \(t(try P.prop(a, "narrative")))")
        lines.append("")
        lines.append("## Coverage summary")
        lines.append("")
        lines.append("| Satisfied | Partial | Not evidenced | Total |")
        lines.append("| --- | --- | --- | --- |")
        lines.append("| \(t(try P.prop(cov, "satisfied"))) | \(t(try P.prop(cov, "partial"))) | \(t(try P.prop(cov, "notEvidenced"))) | \(t(try P.prop(cov, "total"))) |")
        lines.append("")
        lines.append("## Controls")
        lines.append("")
        lines.append("| Control | Clause | Status | Evidence in period |")
        lines.append("| --- | --- | --- | --- |")
        let items = try JS.spread(try P.prop(r, "items"))
        for i in items {
            let status = try P.prop(i, "status")
            lines.append("| \(t(try P.prop(i, "controlTitle"))) (`\(t(try P.prop(i, "controlId")))`) | \(t(try P.prop(i, "clause"))) | \(try glyph(status)) \(try upper(status)) | \(t(try P.prop(i, "evidence"))) |")
        }
        lines.append("")
        lines.append("## Control detail")
        lines.append("")
        for i in items {
            let status = try P.prop(i, "status")
            lines.append("### \(t(try P.prop(i, "controlId"))) \u{2014} \(t(try P.prop(i, "controlTitle")))")
            lines.append("")
            lines.append("- Clause: \(t(try P.prop(i, "clause")))")
            lines.append("- Status: \(try glyph(status)) \(try upper(status))")
            lines.append("- PCA evidence basis: \(t(try P.prop(i, "pcaEvidence")))")
            lines.append("- Evidence in period: \(t(try P.prop(i, "evidence")))")
            let findings = try P.prop(i, "findings")
            if P.jsGt(try P.length(findings), .int(0)) {
                lines.append("- Findings:")
                for f in try JS.spread(findings) { lines.append("  - \(t(f))") }
            }
            lines.append("")
        }
        lines.append("---")
        lines.append("")
        lines.append("_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._")
        return lines.joined(separator: "\n")
    }
}
