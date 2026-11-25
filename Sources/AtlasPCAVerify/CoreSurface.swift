import Foundation

/// TypeScript-named public entry points of the core `pca` package that the native verifiers carry as internal checks: the workflow commitment and receipt
/// chain errors (workflow.ts) and the revocation-set membership proof (revocation.ts).
extension Workflow {
    /// `dagError`: nil when the step graph is sound, else `duplicate step id`, `bad dependency`, `cycle` or `edge does not follow a dependency`.
    static func dagError(_ b: WfBody) -> String? {
        var ids = Set<String>()
        for s in b.steps { if !ids.insert(s.id).inserted { return "duplicate step id" } }
        for s in b.steps { for d in s.deps where d == s.id || !ids.contains(d) { return "bad dependency" } }
        guard let anc = b.ancestors() else { return "cycle" }
        for e in b.edges where !ids.contains(e.fromStep) || !ids.contains(e.toStep) || anc[e.toStep]?.contains(e.fromStep) != true { return "edge does not follow a dependency" }
        return nil
    }

    /// `dagError` over a workflow body value; nil also for a malformed body (the commitment check reports that one first).
    public static func dagError(_ body: JSONValue?) -> String? { WfBody.parse(body).flatMap { dagError($0) } }

    /// Is this a well-formed, DAG-sound, signed (by the pinned `principal`), in-window workflow commitment? nil when it is, else the refusal:
    /// `bad_workflow`, `bad_dag`, `bad_signature`, `not_yet` or `expired`.
    public static func workflowCommitmentError(_ workflow: JSONValue?, principal: JSONValue?, now: JSONValue?) -> String? {
        guard let sw = workflow?.asObject, K5.onlyKeys(sw, ["body", "sig"]), let w = WfBody.parse(sw["body"]), let p = principal?.asString, K5.isB32(p),
              let n = K5.uint(now) else { return "bad_workflow" }
        if dagError(w) != nil { return "bad_dag" }
        if w.principal != p || !K3Sig.verifyBody(WORKFLOW_DOMAIN, w.raw, signer: p, sig: sw["sig"]) { return "bad_signature" }
        if n < w.issuedAt { return "not_yet" }
        if n >= w.expiresAt { return "expired" }
        return nil
    }

    /// Check the receipt chain against the workflow: the index of the offending receipt, or nil. Throws where the reference throws (a body or list it cannot read).
    public static func workflowReceiptError(_ body: JSONValue?, rsSigner: String, receipts list: JSONValue?, now: Int64) throws -> Int? {
        guard let w = WfBody.parse(body), let items = list?.asArray else { throw JSError("workflowReceiptError: a workflow body and a receipt list are required") }
        return try receipts(w, rsSigner, items, now).at
    }
}

extension PCA {
    /// `verifyMembership`: `id` IS in the sorted revocation set `root` commits to (inclusion proof against the size-bound root).
    public static func verifyMembership(root: String, proof: JSONValue?, id: String) -> Bool {
        guard let p = proof?.asObject, let size = IV.int(p["size"]) else { return false }
        return Mesh.leafOK(root, size, id, p)
    }
}

extension Jose {
    /// `isCanonicalCompactJws`: true iff `token` is the one canonical spelling of a compact JWS (3 parts) or JWE (5 parts). Never throws.
    public static func isCanonicalCompactJws(_ token: JSONValue?, parts: Int = 3, maxBytes: Int = DEFAULT_MAX_JWS_BYTES, jsonPayload: Bool = true) -> Bool {
        (try? assertCanonicalCompactJws(token, parts: parts, maxBytes: maxBytes, jsonPayload: jsonPayload)) != nil
    }

    /// `assertCanonicalJwsSegments`: the canonical-spelling gate on the PROTECTED and SIGNATURE segments of a detached JWS; returns the protected header.
    public static func assertCanonicalJwsSegments(_ protectedB64u: JSONValue?, _ signatureB64u: JSONValue?, maxBytes: Int = DEFAULT_MAX_JWS_BYTES) throws -> JObject {
        guard let p = protectedB64u?.asString, let s = signatureB64u?.asString else { throw JSError("non-canonical compact JWS: not-a-string") }
        if JS.length(p) + JS.length(s) > maxBytes { throw JSError("non-canonical compact JWS: too-long") }
        if p.isEmpty || s.isEmpty { throw JSError("non-canonical compact JWS: empty-segment") }
        guard let h = try parseJSONBytes(try decodeCanonicalBase64url(p)).asObject else { throw JSError("non-canonical compact JWS: not-an-object") }
        _ = try decodeCanonicalBase64url(s)
        return h
    }
}

extension PCA {
    /// `goalCommitOf`: the salted commitment to a plaintext goal, `base64url(sha256(canonical({d, goal, salt})))`.
    public static func goalCommitOf(_ goal: String, _ salt: String) throws -> String { try PCAIssue.goalCommit(goal: goal, salt: salt) }

    /// `verifyGoalCommit`: does the revealed (goal, salt) open `commit`?
    public static func verifyGoalCommit(_ commit: String, _ goal: String, _ salt: String) -> Bool { (try? goalCommitOf(goal, salt)) == commit }
}
