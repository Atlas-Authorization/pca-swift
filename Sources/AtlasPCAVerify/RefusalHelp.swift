import Foundation

/// Base of the published PCA docs.
public let PCA_DOCS = "https://github.com/Atlas-Authorization/pca/blob/main/docs"

/// What a refusal means, how to fix it and the page that explains it (`explainRefusal`).
public struct RefusalHelp: Equatable, Sendable {
    /// The check that refused (the reason's leading token), or `unknown`.
    public let check: String
    public let meaning: String
    public let fix: String
    public let docs: String
}

private let REF = "\(PCA_DOCS)/reference/refusals.md"
private let QUICKSTART = "\(PCA_DOCS)/guides/resource-server-quickstart.md"
private let WIRE = "\(PCA_DOCS)/reference/wire-formats.md"
private let CONFIG_MEANING = "The guard was built without a required component, so it refuses every request (fail closed)."
private let CONFIG_FIX = "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults."
private let GRANT_MEANING = "The proof does not name a grant this server knows."
private let GRANT_FIX = "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request."
private let WIRE_FIX = "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn })."

// (check, meaning, fix, docs); the text matches the TypeScript table, first hit wins.
private let TABLE: [(String, String, String, String)] = [
    ("authorize_config", CONFIG_MEANING, CONFIG_FIX, QUICKSTART),
    ("authorize", CONFIG_MEANING, CONFIG_FIX, QUICKSTART),
    ("operation", "The signed action is not the operation this route executes (other verb, resource or params).", "Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.", "\(REF)#operation"),
    ("audience", "The proof was signed for a different server.", "Make the agent sign with the same audience string the server is configured with.", "\(REF)#audience"),
    ("replay", "This proof (or an older counter) was already used.", "Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.", "\(REF)#replay"),
    ("counter_format", "The proof carries no valid anti-replay counter.", "Build the proof with the agent facade (act) or buildPCActn, which set it.", "\(REF)#replay"),
    ("plan_root_authorized", "The plan the action belongs to was not authorized by the principal.", "Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.", "\(REF)#plan_root_authorized"),
    ("plan_state", "The plan is committed but not executable now (not authorized, expired or revoked).", "Check the plan state named in the reason and re-authorize or recommit.", "\(REF)#plan_root_authorized"),
    ("revocation", "The grant, or the revocation source, refused.", "The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).", "\(REF)#revocation"),
    ("validity", "The proof is outside its validity window.", "Check clocks on both sides; request a fresh proof.", "\(REF)#validity"),
    ("grant_ref", GRANT_MEANING, GRANT_FIX, "\(REF)#grant_ref"),
    ("grant_ref_bound", GRANT_MEANING, GRANT_FIX, "\(REF)#grant_ref"),
    ("policy", "The grant does not permit this action or these parameters (a predicate or limit failed).", "Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.", "\(REF)#policy"),
    ("delegated_caveats", "A caveat added by a delegation refused the action.", "The sub-agent was narrowed below this action. Delegate with the caveats you intend.", "\(REF)#policy"),
    ("threshold", "The risk needs a co-signature from the principal (step-up).", "Collect the co-sign through the step-up flow, or lower the risk the server prices.", "\(PCA_DOCS)/concepts/threshold-and-step-up.md"),
    ("risk_inputs", "A risk input the server must vouch for was not supplied.", "Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).", "\(REF)#risk_inputs"),
    ("chain", "The delegation chain does not verify back to the grant.", "Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.", "\(REF)#chain"),
    ("leaf_signature", "The proof signature does not verify.", "The proof was altered, or signed by a key that is not the chain leaf.", "\(REF)#chain"),
    ("wire", "The proof is not well-formed under the strict wire profile.", WIRE_FIX, WIRE),
    ("malformed", "The proof could not be read.", WIRE_FIX, WIRE),
    ("freshness", "The consistency token or revocation epoch is stale.", "Refresh the token from the guardian and retry.", "\(REF)#freshness"),
    ("provenance_flow", "The action, or an argument of it, derives from content the principal did not write (a tool result, a page, an unpinned or missing provenance bundle), or the bundle is forged or unreadable.", "Present the provenance bundle your pinned mediator recorded (PCA-Provenance header), have the principal confirm the escalation, or run the call from a principal-authorized plan.", "\(PCA_DOCS)/guides/prompt-injection-provenance.md"),
    ("undo_window", "The action ran under a veto window: the principal can undo it until the window ends.", "Report the effect to your undo coordinator and let the window run.", "\(PCA_DOCS)/guides/undo-windows.md"),
    ("template", "The grant is not an instantiation of a linked policy template.", "Mint the grant from the template the server requires.", "\(PCA_DOCS)/guides/policy-analysis.md"),
]

/// Guidance for a refusal reason (from `authorize`, `PcaGuard` or `verifyPCActn`), found by the reason's leading check name. The reasons
/// themselves are pinned across the language ports and never reworded. Unknown or nil reasons get a generic entry that links the table.
/// Never fails.
public func explainRefusal(_ reason: String?) -> RefusalHelp {
    let text = reason ?? ""
    let head = String(text.prefix { ($0 >= "a" && $0 <= "z") || $0 == "_" })
    let hit = TABLE.first { $0.0 == head } ?? TABLE.first { text.contains("\($0.0):") }
    if let h = hit { return RefusalHelp(check: h.0, meaning: h.1, fix: h.2, docs: h.3) }
    return RefusalHelp(check: "unknown", meaning: "The guard refused and the reason is not in the table.",
                       fix: "Read the reason as written; every refusal names the check that failed.", docs: REF)
}

/// The `doc` member of a refusal body: the refusals page, anchored at the check when the reason names a known one.
func refusalDocURL(_ reason: String) -> String {
    let c = explainRefusal(reason).check
    return c == "unknown" ? REF : "\(REF)#\(c)"
}
