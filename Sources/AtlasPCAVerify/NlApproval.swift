import Foundation

/// The approval half of natural-language policy authoring: the model's completion is parsed strictly and grounded in the catalog, the draft is
/// content-addressed and bound to the instruction, the model and the prompt, a reviewer signs it, and only a verified, unexpired approval compiles into an
/// agent. The model is an injected `complete(prompt)`: no model dependency is added. Drafts and approvals are the language-neutral JSON of the wire.
public enum PCANLApproval {
    public static let NL_APPROVAL_DOMAIN = "atlas-pca/nl-approval/v1\u{0}"
    public static let NL_APPROVAL_DOMAIN_V2 = "atlas-pca/nl-approval/v2\u{0}"
    public static let MAX_NL_OUTPUT_BYTES = 16_384
    public static let MAX_NL_APPROVAL_TTL_MS: Double = 24 * 3_600_000
    private static let DEFAULT_NL_APPROVAL_TTL_MS: Double = 3_600_000

    private static func err(_ m: String) -> JSError { JSError(m) }
    private static func nowMs() -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }

    /// The catalog the static analyzer lints against, built from the facade catalog's own actions.
    static func lintCatalog(_ c: PCACatalog) -> Catalog.ActionCatalog {
        if PCA.nlCatalogDigest(c) == PCA.nlCatalogDigest(.default) { return Catalog.DEFAULT_CATALOG }
        let defs: [JSONValue] = c.all().compactMap { a in
            var o: JObject = ["connector": .string(a.connector), "action": .string(a.action), "reversibility": .string(a.reversibility), "blastRadius": PCAFacade.jsNum(a.blastRadius),
                              "description": .string(a.description)]
            if !a.aliases.isEmpty { o["aliases"] = .array(a.aliases.map { .string($0) }) }
            if let f = a.amountField { o["amountField"] = .string(f) }
            return try? Catalog.defineAction(.object(o))
        }
        return Catalog.buildCatalog(defs)
    }

    /// The digest of the catalog vocabulary a draft was grounded against (NOT the connector catalog's own digest).
    public static func catalogDigest(_ catalog: PCACatalog = .default) -> String { PCA.nlCatalogDigest(catalog) }

    /// `{instruction_digest, model, prompt_digest}`: what a draft is bound to.
    public static func draftBinding(_ instruction: String, _ catalog: PCACatalog = .default, model: String? = nil) -> JSONValue {
        .object(["instruction_digest": .string(Canonical.hashCanonical(.object(["d": .string("atlas-pca/nl-instruction/v1"), "text": .string(instruction)]))),
                 "model": model.map { .string($0) } ?? .null,
                 "prompt_digest": .string(Canonical.hashCanonical(.object(["d": .string("atlas-pca/nl-prompt/v1"), "text": .string(PCAIntentCompilers.nlPrompt(instruction, catalog))])))])
    }

    private static func sortedPermissions(_ permissions: JSONValue) -> JSONValue {
        var out = JObject()
        for c in (permissions.asObject ?? [:]).keys.map({ $0.s }).sorted(by: { $0.utf16.lexicographicallyPrecedes($1.utf16) }) {
            out[JKey(c)] = .array((permissions.get(c)?.asArray ?? []).sorted { ($0.asString ?? "").utf16.lexicographicallyPrecedes(($1.asString ?? "").utf16) })
        }
        return .object(out)
    }

    /// base64url(sha256(lenient canonical form)) of `{v: 2, permissions (connectors and actions sorted), limits, catalog_digest, instruction_digest, model,
    /// prompt_digest}`.
    public static func draftDigestV2(_ permissions: JSONValue, _ limits: JSONValue, _ catalogDigest: String, _ binding: JSONValue) -> String {
        Canonical.hashCanonical(.object(["v": .int(2), "permissions": sortedPermissions(permissions), "limits": limits, "catalog_digest": .string(catalogDigest),
                                         "instruction_digest": binding.get("instruction_digest") ?? .null, "model": binding.get("model") ?? .null, "prompt_digest": binding.get("prompt_digest") ?? .null]))
    }

    /// The v1 draft digest (no binding): what a legacy approval signs.
    public static func draftDigest(_ permissions: JSONValue, _ limits: JSONValue, _ catalogDigest: String) -> String {
        Canonical.hashCanonical(.object(["v": .int(1), "permissions": sortedPermissions(permissions), "limits": limits, "catalog_digest": .string(catalogDigest)]))
    }

    private static func permissionList(_ p: JSONValue) -> [(String, [String])] {
        let o = p.asObject ?? [:]
        return JS.keyOrder(o).map { k in (k.s, (o[k]?.asArray ?? []).compactMap { $0.asString }) }
    }

    private static func lintsOf(_ permissions: JSONValue, _ limits: JSONValue, _ catalog: PCACatalog) throws -> [JSONValue] {
        if (permissions.asObject ?? [:]).isEmpty { return [] }
        var lims: [String: String] = [:]
        for (k, v) in limits.asObject ?? [:] { if let s = v.asString { lims[k.s] = s } }
        let cp = try PCAFacade.compilePolicy(permissions: permissionList(permissions), limits: lims, catalog: catalog, now: 0)
        return PolicySim.lintPolicy(cp, catalog: lintCatalog(catalog))
    }

    /// The model's completion parsed and grounded: `{permissions, limits, unknownVerbs, droppedLimits, raw, lints}`. A throwing completion throws.
    public static func policyFromNL(_ instruction: String, complete: (String) throws -> String, catalog: PCACatalog = .default) throws -> JSONValue {
        let raw = try complete(PCAIntentCompilers.nlPrompt(instruction, catalog))
        guard case var .object(p) = PCAIntentCompilers.parseNLPolicy(raw, catalog) else { throw err("parseNLPolicy") }
        p["raw"] = .string(raw)
        p["lints"] = .array(try lintsOf(p["permissions"] ?? .object([:]), p["limits"] ?? .object([:]), catalog))
        return .object(p)
    }

    /// A draft `{status: "draft", instruction, permissions, limits, catalog_digest, binding, digest, unknownVerbs, droppedLimits, lints, analyzerOk}`.
    /// Throws on a completion over 16384 UTF-8 bytes.
    public static func draftPolicyFromNL(_ instruction: String, complete: (String) throws -> String, catalog: PCACatalog = .default, model: String? = nil) throws -> JSONValue {
        let raw = try complete(PCAIntentCompilers.nlPrompt(instruction, catalog))
        if raw.utf8.count > MAX_NL_OUTPUT_BYTES { throw err("draftPolicyFromNL: model output exceeds \(MAX_NL_OUTPUT_BYTES) bytes or is not a string") }
        guard case let .object(p) = PCAIntentCompilers.parseNLPolicy(raw, catalog) else { throw err("parseNLPolicy") }
        let perms = p["permissions"] ?? .object([:]), lims = p["limits"] ?? .object([:])
        let lints = try lintsOf(perms, lims, catalog)
        let cd = catalogDigest(catalog), binding = draftBinding(instruction, catalog, model: model)
        let hasError = lints.contains { $0.get("level") == .string("error") }
        return .object(["status": .string("draft"), "instruction": .string(instruction), "permissions": perms, "limits": lims, "catalog_digest": .string(cd), "binding": binding,
                        "digest": .string(draftDigestV2(perms, lims, cd, binding)), "unknownVerbs": p["unknownVerbs"] ?? .array([]), "droppedLimits": p["droppedLimits"] ?? .array([]),
                        "lints": .array(lints), "analyzerOk": .bool(!(perms.asObject ?? [:]).isEmpty && !hasError)])
    }

    private static func approvalMessage(_ a: JSONValue) -> [UInt8] {
        let body: JSONValue = .object(["v": a.get("v") ?? .null, "digest": a.get("digest") ?? .null, "catalog_digest": a.get("catalog_digest") ?? .null, "reviewer": a.get("reviewer") ?? .null,
                                       "approved_at": a.get("approved_at") ?? .null, "expires_at": a.get("expires_at") ?? .null])
        return Canonical.utf8(a.get("v") == .int(2) ? NL_APPROVAL_DOMAIN_V2 : NL_APPROVAL_DOMAIN) + Canonical.utf8(Canonical.canonicalize(body))
    }

    private static func sign(_ body: JSONValue, _ key: PCAEdKey) throws -> JSONValue {
        guard case var .object(o) = body else { throw err("approval") }
        o["sig"] = .string(Base64URLStrict.encode(try key.sign(approvalMessage(body))))
        return .object(o)
    }

    /// The reviewer's approval `{v: 2, digest, catalog_digest, reviewer, approved_at, expires_at, sig}` of a draft that passed the analyzer and proposed no
    /// unknown verb. `ttlMs` is positive and at most 24 hours (default one hour); `now` defaults to the wall clock.
    public static func approveDraft(_ draft: JSONValue, reviewer: PCAEdKey, now: Double? = nil, ttlMs: Double? = nil) throws -> JSONValue {
        if !JS.truthy(draft.get("analyzerOk")) { throw err("approveDraft: the draft did not pass the static analyzer") }
        guard let uv = draft.get("unknownVerbs") else { throw err("Cannot read properties of undefined (reading 'length')") }
        if let a = uv.asArray, !a.isEmpty { throw err("approveDraft: the draft proposed verbs that are not in the catalog") }
        let n = now ?? nowMs(), ttl = ttlMs ?? DEFAULT_NL_APPROVAL_TTL_MS
        guard n.isFinite, ttl.isFinite, ttl > 0, ttl <= MAX_NL_APPROVAL_TTL_MS else { throw err("approveDraft: invalid time or ttl") }
        let body: JSONValue = .object(["v": .int(2), "digest": draft.get("digest") ?? .null, "catalog_digest": draft.get("catalog_digest") ?? .null,
                                       "reviewer": .string(Base64URLStrict.encode(reviewer.pub)), "approved_at": StoreJ.num(n), "expires_at": StoreJ.num(n + ttl)])
        return try sign(body, reviewer)
    }

    /// The v1 approval of the same draft: its digest has no binding, and it loads with `legacy_unbound_instruction`.
    public static func approveDraftLegacyV1(_ draft: JSONValue, reviewer: PCAEdKey, now: Double? = nil, ttlMs: Double? = nil) throws -> JSONValue {
        let v2 = try approveDraft(draft, reviewer: reviewer, now: now, ttlMs: ttlMs)
        let body: JSONValue = .object(["v": .int(1), "digest": .string(draftDigest(draft.get("permissions") ?? .null, draft.get("limits") ?? .null, draft.get("catalog_digest")?.asString ?? "")),
                                       "catalog_digest": draft.get("catalog_digest") ?? .null, "reviewer": v2.get("reviewer") ?? .null, "approved_at": v2.get("approved_at") ?? .null,
                                       "expires_at": v2.get("expires_at") ?? .null])
        return try sign(body, reviewer)
    }

    private static func isInt(_ v: JSONValue?) -> Double? {
        guard let d = IV.num(v), d.isFinite, d.rounded() == d, abs(d) <= IV.MAX_SAFE, !(d == 0 && d.sign == .minus) else { return nil }
        return d
    }

    /// Whether a draft and its approval load: `{ok: true, permissions, limits, reviewer, instruction, legacy_unbound_instruction}` or `{ok: false, reason}` with
    /// the rejection code (`no_reviewers_pinned`, `not_a_draft`, `catalog_mismatch`, `tampered_draft`, `unknown_verbs`, `empty_permissions`, `analyzer_error`,
    /// `malformed_approval`, `digest_mismatch`, `reviewer_not_pinned`, `ttl_too_long`, `not_yet_valid`, `expired`, `bad_signature`). Never throws.
    public static func loadApprovedPolicy(_ draft: JSONValue, _ approval: JSONValue, reviewers: [String], catalog: PCACatalog = .default, now: Double? = nil) -> JSONValue {
        func fail(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        do {
            let n = now ?? nowMs()
            if reviewers.isEmpty { return fail("no_reviewers_pinned") }
            guard draft.get("status") == .string("draft"), let perms = draft.get("permissions"), perms.isObject, let lims = draft.get("limits"), lims.isObject else { return fail("not_a_draft") }
            let cd = catalogDigest(catalog)
            if !IV.same(draft.get("catalog_digest")?.asString, cd) { return fail("catalog_mismatch") }
            guard let instruction = draft.get("instruction")?.asString else { return fail("not_a_draft") }
            let legacyDraft = draft.get("binding") == nil
            if !legacyDraft && !(draft.get("binding")?.isObject ?? false) { return fail("not_a_draft") }
            if legacyDraft {
                if !IV.same(draftDigest(perms, lims, cd), draft.get("digest")?.asString) { return fail("tampered_draft") }
            } else {
                let b = draft.get("binding")!
                let want = draftBinding(instruction, catalog, model: b.get("model")?.asString)
                let modelSame = (b.get("model") ?? .null) == (want.get("model") ?? .null)
                if !IV.same(b.get("instruction_digest")?.asString, want.get("instruction_digest")?.asString) || !IV.same(b.get("prompt_digest")?.asString, want.get("prompt_digest")?.asString) || !modelSame { return fail("tampered_draft") }
                if !IV.same(draftDigestV2(perms, lims, cd, want), draft.get("digest")?.asString) { return fail("tampered_draft") }
            }
            for (c, acts) in perms.asObject ?? [:] {
                guard case let .array(list) = acts, list.allSatisfy({ $0.asString != nil && catalog.get("\(c.s).\($0.asString!)") != nil }) else { return fail("unknown_verbs") }
            }
            if let uv = draft.get("unknownVerbs")?.asArray, !uv.isEmpty { return fail("unknown_verbs") }
            if (perms.asObject ?? [:]).isEmpty { return fail("empty_permissions") }
            if try lintsOf(perms, lims, catalog).contains(where: { $0.get("level") == .string("error") }) { return fail("analyzer_error") }
            guard let v = approval.get("v"), v == .int(1) || v == .int(2) || IV.num(v) == 1 || IV.num(v) == 2, let sig = approval.get("sig")?.asString, let reviewer = approval.get("reviewer")?.asString,
                  let digest = approval.get("digest")?.asString, let acd = approval.get("catalog_digest")?.asString, let at = isInt(approval.get("approved_at")), let exp = isInt(approval.get("expires_at")) else { return fail("malformed_approval") }
            let legacy = IV.num(v) == 1
            if legacyDraft && !legacy { return fail("digest_mismatch") }
            let wantDigest = legacy ? draftDigest(perms, lims, cd) : (draft.get("digest")?.asString ?? "")
            if !IV.same(digest, wantDigest) || !IV.same(acd, cd) { return fail("digest_mismatch") }
            if !reviewers.contains(where: { IV.same($0, reviewer) }) { return fail("reviewer_not_pinned") }
            if exp - at <= 0 || exp - at > MAX_NL_APPROVAL_TTL_MS { return fail("ttl_too_long") }
            if at > n { return fail("not_yet_valid") }
            if n >= exp { return fail("expired") }
            if !Ed25519Strict.verifyB64u(reviewer, approvalMessage(approval), sig) { return fail("bad_signature") }
            return .object(["ok": .bool(true), "permissions": perms, "limits": lims, "reviewer": .string(reviewer), "instruction": .string(instruction), "legacy_unbound_instruction": .bool(legacy)])
        } catch {
            return fail("malformed_approval")
        }
    }

    /// An agent minted from an approved draft: `loadApprovedPolicy` must accept it, and (unless the approval is the legacy unbound one) the goal must equal the
    /// approved instruction. Throws `agentFromApprovedNL: <code>`.
    public static func agentFromApprovedNL(draft: JSONValue, approval: JSONValue, reviewers: [String], catalog: PCACatalog? = nil, now: Double? = nil, principal: PCASuiteKey, goal: String,
                                           aud: String? = nil, holder: PCASuiteKey? = nil) throws -> (agent: PCAFacadeAgent, reviewer: String, legacyUnboundInstruction: Bool) {
        let loaded = loadApprovedPolicy(draft, approval, reviewers: reviewers, catalog: catalog ?? .default, now: now)
        guard loaded.get("ok") == .bool(true) else { throw err("agentFromApprovedNL: \(loaded.get("reason")?.asString ?? "")") }
        let legacy = loaded.get("legacy_unbound_instruction") == .bool(true)
        if !legacy && !IV.same(goal, loaded.get("instruction")?.asString) { throw err("agentFromApprovedNL: goal_mismatch") }
        var lims: [String: String] = [:]
        for (k, v) in loaded.get("limits")?.asObject ?? [:] { if let s = v.asString { lims[k.s] = s } }
        var o = PCAAgentOptions(principal: principal, goal: goal, permissions: permissionList(loaded.get("permissions") ?? .object([:])), limits: lims, holder: holder, catalog: catalog, aud: aud,
                                now: now.map { Int64($0) })
        o.limits = lims
        return (try PCAAgent.fromPrincipal(o), loaded.get("reviewer")?.asString ?? "", legacy)
    }
}
