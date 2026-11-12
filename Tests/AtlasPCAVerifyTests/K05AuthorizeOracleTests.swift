import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of the authorize pipeline's 0.5 additions and its pure pieces (Authorize.swift, ToolSchema.swift) against the TS
/// reference (server/authorize.ts + require-pca.ts, agent-native.ts tool_schema, risk.ts, envelope.ts): test-data/k05-authorize.json.gz
/// (13309 cases). Each `authorize` case is a scenario {grant, config, steps} replayed against ONE replay store with a fixed clock; a step
/// is compared on allow, decision, status, the named checks, the failed ones, this release's reasons (provenance_flow, undo_window,
/// escalation, fresh_at), the escalation (answered / requested) and the undo admission.
final class K05AuthorizeOracleTests: XCTestCase {
    static let file = "k05-authorize.json.gz"
    static let covers = ["Authorize", "ToolSchema", "ArgProvenance", "Undo", "Escalation", "FreshAt", "Caveats", "Capability", "PCActn", "Predicates",
                         "Merkle", "IntentWB", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "Ed25519Strict", "PQ", "Issue", "JSONValue", "Keys",
                         "Agent", "Threshold", "Wire", "Approval", "Actions"]

    static let KEY = ["wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "plan_root_authorized", "leaf_signature",
                      "counter_format", "fresh_at", "attestation", "revocation", "grant_ref", "operation", "params_digest", "delegated_caveats", "policy", "replay",
                      "provenance_flow", "undo_window", "escalation"]
    static let OWN = ["provenance_flow: ", "undo_window: ", "escalation: ", "fresh_at: "]

    func testToolSchemaRiskPolicyEnvelope() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["validateArgSchema", "evaluateToolSchema", "validateRiskPolicy", "readEnvelope", "requiresAttestation"]) { c in
            switch c.fn {
            case "validateArgSchema":
                let got = ToolSchema.validateArgSchema(c.arg(0))
                // the node budget runs out at a property the reference picks in insertion order; a Swift JSON object is unordered, so the
                // path of a "schema too large" refusal is not comparable (the refusal itself is)
                if let g = got, let w = c.out.asString, g.hasSuffix(": schema too large"), w.hasSuffix(": schema too large") { d.add(c, nil); return }
                d.add(c, K05.diff(c, .value(K05.opt(got))))
            case "validateRiskPolicy": d.add(c, K05.diff(c, .value(K05.opt(PCA.validateRiskPolicy(c.arg(0))))))
            case "readEnvelope": d.add(c, K05.diff(c, .value(PCA.readEnvelope(c.arg(0) ?? .null) ?? .null)))
            case "requiresAttestation": d.add(c, K05.diff(c, .value(.bool(PCA.requiresAttestation(c.arg(0))))))
            default:
                var call: PCA.ToolCall?
                if let o = c.arg(1)?.asObject {
                    if o["toolSignature"] != nil { d.skip("evaluateToolSchema: the toolSignature (object) form is not part of the Swift ToolCall"); return }
                    guard let tool = o["tool"]?.asString else { d.skip("evaluateToolSchema: a non-string tool cannot be a ToolCall"); return }
                    if let sd = o["toolSignatureDigest"], sd.asString == nil {
                        // authorize passes the PCActn's tool_binding only when it is a string, exactly as the reference's toolCallOf
                        d.skip("evaluateToolSchema: a present non-string toolSignatureDigest cannot be a ToolCall (String?)"); return
                    }
                    call = PCA.ToolCall(tool: tool, args: o["args"] ?? .null, toolSignatureDigest: o["toolSignatureDigest"]?.asString)
                }
                let r = PCA.evaluateToolSchema(c.arg(0), call: call)
                var o: JObject = ["ok": .bool(r.ok)]
                if let reason = r.reason, !r.ok { o["reason"] = .string(reason) }
                d.add(c, K05.diff(c, .value(.object(o))))
            }
        }
        d.finish(12_000)
    }

    /// An admission as the typed hook returns it; a shape the struct cannot hold is no admission (the reference refuses it too).
    static func admission(_ v: JSONValue?) -> UndoAdmission? {
        guard let o = v?.asObject, let id = o["id"]?.asString, let end = IV.int(o["window_end"]), let comp = o["compensation"]?.asObject,
              let verb = comp["verb"]?.asString, let res = comp["resource"]?.asString else { return nil }
        return UndoAdmission(id: id, windowEnd: end, compensationVerb: verb, compensationResource: res)
    }

    func testAuthorizeScenarios() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["authorize"]) { c in
            guard let sc = c.arg(0), let grant = sc.get("grant"), let cfg = sc.get("config")?.asObject else { d.skip("authorize: malformed scenario"); return }
            let store = MemoryStateStore()
            var revoked = false
            let facts = cfg["actions"]?.asObject
            let observed = cfg["observed"]?.asArray
            var actionsFn: ((PCA.Operation) -> JSONValue?)? = nil
            if let f = facts { actionsFn = { op in f[JKey(op.verb)] } }
            var observedFn: ((JSONValue, PCA.Operation, String?) -> [JSONValue])? = nil
            if let obs = observed { observedFn = { _, _, _ in obs } }
            var input = PCA.AuthorizeInput(
                audience: cfg["audience"]?.asString, resolveGrant: { ref in IV.same(ref, grant.get("id")?.asString) ? grant : nil },
                stateStore: store, isRevoked: { _, _ in revoked }, now: IV.int(cfg["now"]), plan: PCA.SINGLE_STEP,
                argProvenance: ArgProvenanceOptions(mediators: cfg["mediators"]?.asArray ?? [], actions: actionsFn, observed: observedFn), riskSource: PCA.insecureCalmRisk)
            if let fa = cfg["freshAt"] { input.freshAt = FreshAtPolicy(json: fa) }
            if let u = cfg["undo"]?.asObject { input.undo = { req in Self.admission(u[JKey(req.operation.verb)]) } }
            if let e = cfg["escalation"]?.asObject {
                input.escalationPrincipals = (e["principals"]?.asArray ?? []).compactMap { $0.asString.map { PinnedSigner($0) } }
                if let rd = e["render_digest"]?.asString { input.escalationRender = { _ in rd } }
                if e["insecureUnboundApproval"] == .bool(true) { input.insecureUnboundApproval = true }
            }
            var outs: [JSONValue] = []
            for s in sc.get("steps")?.asArray ?? [] {
                revoked = s.get("revoked") == .bool(true)
                var step = input
                if let o = s.get("operation")?.asObject, let verb = o["verb"]?.asString, let res = o["resource"]?.asString {
                    step.operation = PCA.Operation(verb: verb, resource: res, params: o["params"] ?? .null)
                }
                step.provenance = s.get("provenance")
                // the reference reads an answer only when the `escalation` option is configured (Swift has no separate switch)
                step.escalationAnswer = cfg["escalation"] != nil ? s.get("escalationAnswer") : nil
                let r = PCA.authorize(pcactn: s.get("pcactn"), step)
                // Swift names the capability chain check "chain" (the reference "cap_chain")
                let rc = r.checks.reduce(into: [String: PCA.CheckStatus]()) { $0[$1.key == "chain" ? "cap_chain" : $1.key] = $1.value }
                var checks: JObject = [:]
                for k in Self.KEY { if let st = rc[k] { checks[JKey(k)] = .string(st.rawValue) } }
                let esc: JSONValue = r.escalation == nil ? .null : (r.allow ? r.escalation! : .object(["request": .bool(true)]))
                let undo: JSONValue = r.undo.map { u in
                    .object(["id": .string(u.id), "window_end": .int(u.windowEnd),
                             "compensation": .object(["verb": .string(u.compensationVerb), "resource": .string(u.compensationResource)])])
                } ?? .null
                outs.append(.object([
                    "allow": .bool(r.allow), "decision": .string(r.decision), "status": .int(Int64(r.status)), "checks": .object(checks),
                    "failed": .array(Self.KEY.filter { rc[$0] == .fail }.map { .string($0) }),
                    // the escalation-render refusal names the option a caller sets; Swift spells it with its own property name
                    "reasons": .array(r.reasons.filter { x in Self.OWN.contains { x.hasPrefix($0) } }
                        .map { .string($0.replacingOccurrences(of: "(set escalationRender, or insecureUnboundApproval)", with: "(set escalation.render, or insecureUnboundApproval)")) }),
                    "escalation": esc, "undo": undo,
                ]))
            }
            d.add(c, K05.diff(Self.dropUnreported(c, outs), .value(.array(outs))))
        }
        d.finish(850)
    }

    /// The reference reports attestation "not-enforced" on every verdict; Swift reports that check only when it applies (it then fails
    /// closed: there is no attestation verifier in this SDK), so a want check that is "not-enforced" and absent from Swift's verdict is
    /// dropped before the exact comparison (as the .NET suite does). Everything else compares exactly.
    static func dropUnreported(_ c: K05Case, _ have: [JSONValue]) -> K05Case {
        guard case let .array(want) = c.out, want.count == have.count else { return c }
        let kept: [JSONValue] = zip(want, have).map { w, h in
            guard case var .object(wo) = w, case let .object(wc)? = wo["checks"], case let .object(hc)? = h.get("checks") else { return w }
            wo["checks"] = .object(wc.filter { !($0.value == .string("not-enforced") && hc[$0.key] == nil) })
            return .object(wo)
        }
        return K05Case(fn: c.fn, name: c.name, args: c.args, out: .array(kept), suspect: c.suspect, raw: c.raw)
    }
}
