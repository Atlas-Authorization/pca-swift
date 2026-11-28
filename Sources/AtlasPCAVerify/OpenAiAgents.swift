import Foundation

/// OpenAI Agents SDK guard: makes every agent tool call proof-carrying and policy-gated at the LOCAL execution boundary. `withPcaTool` wraps a
/// tool so each `execute(input, runContext)` first REQUIRES a proof-carrying action (pulled from the run context by the PCA-Action convention),
/// VERIFIES it (fail closed: `PcaToolDenied`) and only then runs the original tool; guardrails trip a run that lacks a valid proof.
///
/// Structural, no vendor package: a tool is an `AgentTool` over JSON values, the run context a JSON object whose `context` member is the
/// caller's bag (the proof rides there as `pca` / `pcaProof`).
///
/// Two modes. Full (the default): every call runs `PCA.authorize`: the input must hash to the signed params digest, the grant's predicates,
/// limits and caveats are evaluated, revocation is required and a replay store makes each PCActn single-use; a missing component is a
/// configuration error. Signature-only: the proof's signature, capability chain, plan inclusion, audience and validity window are checked,
/// NOT that the grant permits this call. The guardrails are signature-only pre-filters (a run-level guardrail sees no single tool call to
/// bind); put the authority check on the tool. Either way this does not replace the resource server when a tool makes a remote call: it makes
/// the local boundary refuse to act without a valid PCActn.
///
/// Step-up: `reviewToolCall` / `pendingStepUps` / `pcaNeedsApproval` / `withApproval` map a risky tool to the SDK's `needsApproval`
/// interruption through `PCAApprovals.reviewAction` (auto / deny / tier-2 or tier-3 co-sign).
///
/// Differences from the reference: tools and callbacks are synchronous; the verifier hooks of signature-only mode (`enforce`, `hooks`) are
/// not offered (full mode reaches the same gates through `AuthorizeInput`); the JS attach side (`withPCA` / `withPCATools`) is not ported (use
/// `PCAAdapters`); a proof that is neither an object nor a string is refused as malformed.
public struct PcaToolDenied: Error, CustomStringConvertible {
    /// `missing` | `malformed` | `verify` | `binding` | `policy` | `replay` | `revoked` | `config`. The last four come only from full mode.
    public let kind: String
    /// The PCA verb the proof claimed (or the configured verb / `(tool)` when unknown).
    public let verb: String
    /// The reason alone.
    public let reason: String
    /// The per-check verdicts from the verifier, when the denial was a verification failure.
    public let checks: [String: String]?
    /// `PCA tool denied (<kind>) for <verb>: <reason>`.
    public let message: String

    public init(_ reason: String, verb: String, kind: String, checks: [String: String]? = nil) {
        self.reason = reason
        self.verb = verb
        self.kind = kind
        self.checks = checks
        self.message = "PCA tool denied (\(kind)) for \(verb): \(reason)"
    }

    public var description: String { message }
}

/// A configuration error found when a guard is built (or when a wrapped tool has no `execute`).
public struct PcaToolConfigError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// A tool of the Agents SDK: a name, a description, JSON-schema parameters, the human-approval hook and `execute(input, runContext)`.
/// Everything but `execute` is carried through a guard unchanged.
public final class AgentTool {
    public typealias Execute = (_ input: JSONValue, _ runContext: JSONValue?) throws -> JSONValue
    /// The SDK's `needsApproval(runContext, input)`: a run interrupts (needs a co-sign) when it answers true.
    public typealias NeedsApproval = (_ runContext: JSONValue, _ input: JSONValue) -> Bool

    public let name: String?
    public let description: String?
    public let parameters: JSONValue?
    public let needsApproval: NeedsApproval?
    public let execute: Execute?
    /// Any other member of the SDK's tool object.
    public let extra: JObject

    public init(name: String? = nil, description: String? = nil, parameters: JSONValue? = nil, needsApproval: NeedsApproval? = nil, extra: JObject = [:],
                execute: Execute? = nil) {
        self.name = name
        self.description = description
        self.parameters = parameters
        self.needsApproval = needsApproval
        self.extra = extra
        self.execute = execute
    }

    func with(execute: Execute?) -> AgentTool {
        AgentTool(name: name, description: description, parameters: parameters, needsApproval: needsApproval, extra: extra, execute: execute)
    }

    func with(needsApproval: @escaping NeedsApproval) -> AgentTool {
        AgentTool(name: name, description: description, parameters: parameters, needsApproval: needsApproval, extra: extra, execute: execute)
    }
}

public enum PCAOpenAIAgents {
    // ---- shapes ----

    /// Pull the proof-carrying action for THIS tool call out of `(input, runContext)` (nil fails closed). A proof is a PCActn object, its encoded
    /// JSON, or a base64url `PCA-Action` header value.
    public typealias ProofSource = (_ input: JSONValue, _ runContext: JSONValue) -> JSONValue?
    /// Pull the proof for a whole run out of the guardrail args (nil trips the guardrail).
    public typealias GuardrailProofSource = (_ args: JSONValue) -> JSONValue?
    /// Records a tool result as UNTRUSTED output (see `toolOutputRecorder`).
    public typealias ToolOutputRecorder = (_ verb: String, _ output: JSONValue) throws -> Void

    /// A verification outcome of a verifier.
    public struct VerifyOutcome {
        public var allow: Bool
        public var reason: String?
        /// check name -> `pass` | `fail` | ...
        public var checks: [String: String]
        public init(allow: Bool, reason: String? = nil, checks: [String: String] = [:]) {
            self.allow = allow
            self.reason = reason
            self.checks = checks
        }
    }

    /// Signature-only verification: the grant the proof must chain to. With no `authorizedPlanRoots` (and no explicit opt-out) every call is
    /// refused: a verifier with neither does not know which plans the principal authorized.
    public struct VerifyGrant {
        public var grant: JSONValue
        /// Verifier clock (epoch ms), evaluated per call; default the wall clock.
        public var now: (() -> Int64)?
        public var allowedSuites: [String]?
        /// Merkle plan roots the principal authorized.
        public var authorizedPlanRoots: [String]?
        /// Explicit, loudly named opt-out of the plan-root check.
        public var insecureSkipPlanRootCheck: Bool
        public init(grant: JSONValue, now: (() -> Int64)? = nil, allowedSuites: [String]? = nil, authorizedPlanRoots: [String]? = nil, insecureSkipPlanRootCheck: Bool = false) {
            self.grant = grant
            self.now = now
            self.allowedSuites = allowedSuites
            self.authorizedPlanRoots = authorizedPlanRoots
            self.insecureSkipPlanRootCheck = insecureSkipPlanRootCheck
        }
    }

    /// How a proof is verified in signature-only mode: against a grant, or by a custom function (a throw propagates to the caller).
    public enum Verify {
        case grant(VerifyGrant)
        case fn((JSONValue) throws -> VerifyOutcome)
    }

    /// The operation one call executes: its verb, resource and the params the agent signed. `resource` nil: the proof's own (only the verb is
    /// bound). `provenance` nil: read by the guard's provenance source.
    public struct ExecutionOperation {
        public var verb: String
        public var resource: String?
        public var params: JSONValue
        public var provenance: JSONValue?
        public init(verb: String, resource: String? = nil, params: JSONValue, provenance: JSONValue? = nil) {
            self.verb = verb
            self.resource = resource
            self.params = params
            self.provenance = provenance
        }
    }

    /// Full-policy mode (the default, recommended): `input` is the template of every call's `PCA.authorize` input (the guard sets its audience,
    /// the operation, and the provenance bundle when it carries none); `resolveGrant`, `stateStore` and `isRevoked` are required, a guard built
    /// without one throws. A template with no `plan` and no `context` uses the single-step plan (the proof's own one node, which must be the
    /// operation), and with no `allowedSuites` accepts Ed25519 only.
    public struct AuthorizeOptions {
        public var input: PCA.AuthorizeInput
        /// The operation this call executes. Default: `{verb: <the guard's verb>, params: input}`, which needs the guard's `verb`.
        public var operation: ((_ input: JSONValue, _ runContext: JSONValue) -> ExecutionOperation)?
        public init(input: PCA.AuthorizeInput, operation: ((_ input: JSONValue, _ runContext: JSONValue) -> ExecutionOperation)? = nil) {
            self.input = input
            self.operation = operation
        }
    }

    /// Options of `withPcaTool`. `nil` members are absent.
    public struct WithPcaToolOptions {
        /// How to find the proof for a call. Default `proofFromRunContext`.
        public var require: ProofSource?
        /// `full` (the default) or `signature-only`. A guard needs `authorize` (full) or `verify` (signature-only), never both.
        public var mode: String?
        public var verify: Verify?
        public var authorize: AuthorizeOptions?
        /// This verifier's audience, matched against the PCActn's signed `aud`: `.id` must equal it; `.any` opts out; absent (or `.unset`) fails
        /// closed when the PCActn carries an `aud`. Full mode needs `.id`.
        public var audience: PCA.Audience?
        /// Defense in depth: the proof's `action.verb` must equal this (bind the proof to THIS tool).
        public var verb: String?
        /// Where the provenance bundle of this call is. Default `provenanceFromRunContext`.
        public var provenance: ((_ input: JSONValue, _ runContext: JSONValue) -> JSONValue?)?
        /// When set, every result the tool returns is recorded as UNTRUSTED tool output.
        public var recorder: ToolOutputRecorder?
        public var onDeny: ((PcaToolDenied, JSONValue) -> Void)?
        /// Observe a successful verification (the outcome, the PCActn, the tool input) before the original execute runs.
        public var onVerified: ((VerifyOutcome, JSONValue, JSONValue) -> Void)?
        public init() {}
    }

    // ---- proof sources ----

    /// An encoded string PCActn from a `{pca | pcaProof}` bag; nil when neither is a string.
    static func proofFromBag(_ bag: JSONValue?) -> JSONValue? {
        guard let o = bag?.asObject else { return nil }
        let direct = JS.present(o["pca"]) ?? o["pcaProof"]
        guard let s = direct?.asString else { return nil }
        return .string(s)
    }

    /// Default proof source: `runContext.context.{pca|pcaProof}`, then `runContext.{pca|pcaProof}`.
    public static let proofFromRunContext: ProofSource = { _, runContext in
        proofFromBag(runContext.get("context")) ?? proofFromBag(runContext)
    }

    /// Default provenance source: `{pcaProvenance | pca_provenance | PCA-Provenance}` on `runContext.context`, then on `runContext`.
    public static let provenanceFromRunContext: (_ input: JSONValue, _ runContext: JSONValue) -> JSONValue? = { _, runContext in
        for bag in [runContext.get("context"), runContext] {
            guard let o = bag?.asObject else { continue }
            for k in ["pcaProvenance", "pca_provenance", "PCA-Provenance"] {
                if let v = JS.present(o[JKey(k)]) { return v }
            }
        }
        return nil
    }

    /// A proof source reading a base64url `PCA-Action` header from a headers-like bag on the tool input.
    public static func proofFromInputHeaders(field: String = "headers", header: String = "PCA-Action") -> ProofSource {
        return { input, _ in
            guard let bag = input.get(field)?.asObject, let v = bag[JKey(header)]?.asString else { return nil }
            return .string(v)
        }
    }

    /// The guardrail-side default: the proof from the run context the SDK passes as `args.context`.
    public static let guardrailProofFromContext: GuardrailProofSource = { args in
        let outer = args.get("context")
        return proofFromBag(outer?.get("context")) ?? proofFromBag(outer)
    }

    // ---- the proof pipeline ----

    /// PCActn text -> PCActn (size cap first, strict parse, an object).
    public static func decodePCActn(_ text: String) throws -> JSONValue {
        if text.utf8.count > PCA.MAX_ARTIFACT_BYTES { throw PcaToolConfigError(PCA.ARTIFACT_SIZE_REASON) }
        let v = try StrictJSON.parse(text)
        guard v.isObject else { throw PcaToolConfigError("decodePCActn: not an object") }
        return v
    }

    /// An object as is; a string is tried as raw encoded JSON, then as a `PCA-Action` header value.
    static func toPCActn(_ input: JSONValue) throws -> JSONValue {
        switch input {
        case .object: return input
        case let .string(s):
            do { return try decodePCActn(s) } catch {
                guard let text = PcaGuard.decodeHeader(s) else { throw PcaToolConfigError("PCA-Action header is not strict unpadded base64url") }
                return try decodePCActn(text)
            }
        default: throw PcaToolConfigError("a proof is a PCActn object or an encoded string")
        }
    }

    static func verbOf(_ pcactn: JSONValue) -> String? { pcactn.get("action")?.get("verb")?.asString }

    private static func runVerify(_ verify: Verify, _ pcactn: JSONValue, _ audience: PCA.Audience) throws -> VerifyOutcome {
        switch verify {
        case let .fn(f): return try f(pcactn)
        case let .grant(g):
            let now = g.now?() ?? Int64(Date().timeIntervalSince1970 * 1000)
            let v = PCA.verify(pcactn: pcactn, grant: g.grant, now: now, audience: audience, allowedSuites: g.allowedSuites,
                               authorizedPlanRoots: g.authorizedPlanRoots, insecureSkipPlanRootCheck: g.insecureSkipPlanRootCheck)
            return VerifyOutcome(allow: v.allow, reason: v.reason.isEmpty ? nil : v.reason, checks: v.checks.mapValues { $0 ? "pass" : "fail" })
        }
    }

    /// A full-policy decision: allowed (with the checks), or refused with the kind of the refusal.
    struct FullDecision {
        var allow: Bool
        var kind = ""
        var reason = ""
        var checks: [String: String]? = nil
    }

    /// The bundle a framework carried: the bundle itself, its JSON text, or a `PCA-Provenance` header value (base64url JSON). nil for anything
    /// else (the gate then treats the call as unlabelled: fail closed).
    public static func provenanceFrom(_ v: JSONValue?) -> JSONValue? {
        switch v {
        case nil, .null?: return nil
        case .object?, .array?: return v
        case let .string(s)?:
            if s.isEmpty { return nil }
            if let p = try? StrictJSON.parse(s) { return p }
            guard let text = PcaGuard.decodeHeader(s) else { return nil }
            return try? StrictJSON.parse(text)
        default: return nil
        }
    }

    typealias FullCheck = (_ pcactn: JSONValue, _ input: JSONValue, _ runContext: JSONValue) -> FullDecision

    /// Full mode: checks the configuration once (throws on a missing component) and returns the per-call check; nil in signature-only mode.
    static func fullPolicy(_ options: WithPcaToolOptions, who: String) throws -> FullCheck? {
        let mode = options.mode ?? "full"
        if mode != "full" && mode != "signature-only" { throw PcaToolConfigError("\(who): unknown mode '\(mode)'") }
        if mode == "signature-only" {
            if options.authorize != nil { throw PcaToolConfigError("\(who): `authorize` is the full mode; drop it, or drop mode: 'signature-only'") }
            if options.verify == nil { throw PcaToolConfigError("\(who): mode 'signature-only' needs `verify`") }
            return nil
        }
        guard let auth = options.authorize else {
            throw PcaToolConfigError("\(who): pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only")
        }
        if options.verify != nil {
            throw PcaToolConfigError("\(who): `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`")
        }
        var audience: String?
        if case let .id(a)? = options.audience { audience = a }
        var probe = auth.input
        probe.audience = audience
        var missing = PCA.missingAuthorizeComponents(probe)
        if auth.operation == nil && options.verb == nil { missing.append("operation (or the guard's verb)") }
        guard missing.isEmpty, let aud = audience else { throw PcaToolConfigError("\(who): full policy mode is missing \(missing.joined(separator: ", "))") }
        let template = auth.input
        let verb = options.verb ?? ""
        let opOf = auth.operation ?? { input, _ in ExecutionOperation(verb: verb, params: input.isObject ? input : .object([:])) }
        let prov = options.provenance ?? provenanceFromRunContext
        return { pcactn, input, runContext in
            let op = opOf(input, runContext)
            let signedVerb = verbOf(pcactn)
            let signedResource = pcactn.get("action")?.get("resource")?.asString
            // binding first: a proof presented for another operation is not spent
            if signedVerb != op.verb || (op.resource != nil && signedResource != op.resource) {
                let want = op.resource.map { "\(op.verb) on \($0)" } ?? op.verb
                return FullDecision(allow: false, kind: "binding",
                                    reason: "the proof is for \(signedVerb ?? "undefined") on \(signedResource ?? "undefined"), but this call is \(want)")
            }
            var ai = template
            ai.audience = aud
            ai.operation = PCA.Operation(verb: op.verb, resource: op.resource ?? signedResource ?? "", params: op.params)
            if ai.plan == nil && ai.context == nil { ai.plan = PCA.SINGLE_STEP }
            if ai.allowedSuites == nil { ai.allowedSuites = ["ed25519"] }
            if let p = op.provenance { ai.provenance = p } else if let b = provenanceFrom(prov(input, runContext)) { ai.provenance = b }
            let r = PCA.authorize(pcactn: pcactn, ai)
            var checks: [String: String] = [:]
            for (k, v) in r.checks { checks[k] = v.rawValue }
            if r.allow { return FullDecision(allow: true, checks: checks) }
            let kind: String
            if let m = r.missing, !m.isEmpty { kind = "config" }
            else if r.checks["operation"] == .fail { kind = "binding" }
            else if r.status == 401 { kind = "verify" }
            else if r.checks["revocation"] == .fail { kind = "revoked" }
            else if r.checks["replay"] == .fail { kind = "replay" }
            else { kind = "policy" }
            return FullDecision(allow: false, kind: kind, reason: r.reason ?? "denied", checks: checks)
        }
    }

    /// The shared decode + bind + verify pipeline. Returns the verified PCActn, or throws `PcaToolDenied`.
    private static func assertProof(_ raw: JSONValue?, verify: Verify, audience: PCA.Audience, verb: String?, label: String,
                                    full: ((JSONValue) -> FullDecision)?) throws -> (pcactn: JSONValue, result: VerifyOutcome) {
        guard let raw = raw, raw != .null else { throw PcaToolDenied("no proof-carrying action present on the call", verb: label, kind: "missing") }
        let pcactn: JSONValue
        do { pcactn = try toPCActn(raw) } catch { throw PcaToolDenied("proof could not be decoded: \(error)", verb: label, kind: "malformed") }
        let claimed = verbOf(pcactn)
        if let want = verb, claimed != want {
            throw PcaToolDenied("proof is for '\(claimed ?? "undefined")', not this tool's '\(want)'", verb: claimed ?? "undefined", kind: "binding")
        }
        if let full = full {
            let d = full(pcactn)
            if !d.allow { throw PcaToolDenied(d.reason, verb: claimed ?? label, kind: d.kind, checks: d.checks) }
            return (pcactn, VerifyOutcome(allow: true, checks: d.checks ?? [:]))
        }
        let result = try runVerify(verify, pcactn, audience)
        if !result.allow { throw PcaToolDenied(result.reason ?? "verification failed", verb: claimed ?? "undefined", kind: "verify", checks: result.checks) }
        return (pcactn, result)
    }

    // ---- the execution guard ----

    /// Wrap an Agents-SDK tool so each `execute(input, runContext)` first REQUIRES + VERIFIES a proof-carrying action (fail closed: throws
    /// `PcaToolDenied`), then runs the original `execute`. The result has the same shape and every non-`execute` member of the tool.
    /// Throws `PcaToolConfigError` on a missing or contradictory configuration.
    public static func withPcaTool(_ tool: AgentTool, _ options: WithPcaToolOptions) throws -> AgentTool {
        let source = options.require ?? proofFromRunContext
        let label = options.verb ?? tool.name ?? "(tool)"
        let full = try fullPolicy(options, who: "withPcaTool")
        // signature-only mode (`fullPolicy` returned nil, so `verify` is set)
        let verify = options.verify ?? Verify.fn({ _ in VerifyOutcome(allow: false, reason: "no verifier configured") })
        let audience = options.audience ?? .unset
        return tool.with(execute: { input, runContext in
            let ctx = runContext ?? .object([:])
            let raw = source(input, ctx)
            let verified: (pcactn: JSONValue, result: VerifyOutcome)
            do {
                verified = try assertProof(raw, verify: verify, audience: audience, verb: options.verb, label: label, full: full.map { f -> (JSONValue) -> FullDecision in { p in f(p, input, ctx) } })
            } catch let e as PcaToolDenied {
                options.onDeny?(e, input)
                throw e
            }
            options.onVerified?(verified.result, verified.pcactn, input)
            guard let exec = tool.execute else { throw PcaToolConfigError("withPcaTool: the wrapped tool has no execute()") }
            let out = try exec(input, runContext)
            try options.recorder?(verbOf(verified.pcactn) ?? label, out)
            return out
        })
    }

    /// A recorder that commits each tool result to the agent session's provenance chain as UNTRUSTED output.
    public static func toolOutputRecorder(_ recorder: ProvenanceRecorder) -> ToolOutputRecorder {
        return { verb, output in try recorder.tool(verb, PCAAdapters.recordedText(output)) }
    }

    /// Layer a per-tool override over the shared options: a per-tool `verify` or `authorize` replaces the shared mode (the two are exclusive);
    /// `mode` follows the override, else the shared one.
    static func mergeToolOptions(_ base: WithPcaToolOptions, _ over: WithPcaToolOptions?) -> WithPcaToolOptions {
        guard let over = over else { return base }
        var m = WithPcaToolOptions()
        if over.authorize != nil { m.authorize = over.authorize }
        else if over.verify != nil { m.verify = over.verify }
        else { m.verify = base.verify; m.authorize = base.authorize }
        m.mode = over.mode ?? (over.authorize != nil ? nil : base.mode)
        m.require = over.require ?? base.require
        m.audience = over.audience ?? base.audience
        m.verb = over.verb ?? base.verb
        m.onDeny = over.onDeny ?? base.onDeny
        m.onVerified = over.onVerified ?? base.onVerified
        m.provenance = over.provenance ?? base.provenance
        m.recorder = over.recorder ?? base.recorder
        return m
    }

    /// Guard a whole `{name: tool}` set in one call. Every tool is guarded with the shared options (override per tool via `per`, or limit the set
    /// via `only`; the others pass through unchanged, the same instance).
    public static func pcaTools(_ tools: [String: AgentTool], _ options: WithPcaToolOptions, per: [String: WithPcaToolOptions] = [:], only: Set<String>? = nil) throws -> [String: AgentTool] {
        var out: [String: AgentTool] = [:]
        for (name, tool) in tools {
            if let o = only, !o.contains(name) { out[name] = tool; continue }
            out[name] = try withPcaTool(tool, mergeToolOptions(options, per[name]))
        }
        return out
    }

    // ---- guardrails: reject a run / tool call lacking a valid proof ----

    /// What an Agents-SDK guardrail returns: a tripwire plus free-form info for the trace.
    public struct GuardrailOutput {
        public var tripwireTriggered: Bool
        public var outputInfo: JSONValue
        public init(tripwireTriggered: Bool, outputInfo: JSONValue) {
            self.tripwireTriggered = tripwireTriggered
            self.outputInfo = outputInfo
        }
    }

    /// A guardrail: a name and an execute over the SDK's guardrail args (`{context, ...}`).
    public struct Guardrail {
        public let name: String
        public let execute: (_ args: JSONValue) throws -> GuardrailOutput
    }

    /// Options of `pcaInputGuardrail` / `pcaToolGuard`.
    public struct PcaGuardrailOptions {
        /// How to find the proof. Default `guardrailProofFromContext`.
        public var require: GuardrailProofSource?
        /// How to verify the proof: the grant it must satisfy, or a custom function.
        public var verify: Verify
        public var audience: PCA.Audience?
        /// Bind the proof to a specific verb.
        public var verb: String?
        /// The guardrail's name (shown in traces).
        public var name: String?
        public init(verify: Verify) { self.verify = verify }
    }

    private static func guardrailExecute(_ source: @escaping GuardrailProofSource, _ opts: PcaGuardrailOptions) -> (JSONValue) throws -> GuardrailOutput {
        let audience = opts.audience ?? .unset
        let label = opts.verb ?? "(run)"
        return { args in
            do {
                let (pcactn, _) = try assertProof(source(args), verify: opts.verify, audience: audience, verb: opts.verb, label: label, full: nil)
                return GuardrailOutput(tripwireTriggered: false, outputInfo: .object(["verb": verbOf(pcactn).map { .string($0) } ?? .null]))
            } catch let e as PcaToolDenied {
                var info: JObject = ["kind": .string(e.kind), "verb": .string(e.verb), "reason": .string(e.message)]
                if let c = e.checks { info["checks"] = .object(Dictionary(uniqueKeysWithValues: c.map { (JKey($0.key), JSONValue.string($0.value)) })) }
                return GuardrailOutput(tripwireTriggered: true, outputInfo: .object(info))
            }
        }
    }

    /// An input guardrail: runs once at the top of a run and trips the tripwire (rejecting the run before any step executes) when the run context
    /// carries no valid proof. Signature-only: a run-level guardrail sees no single tool call to bind; put the authority check on the tool.
    public static func pcaInputGuardrail(_ options: PcaGuardrailOptions) -> Guardrail {
        Guardrail(name: options.name ?? "pca-input-guardrail", execute: guardrailExecute(options.require ?? guardrailProofFromContext, options))
    }

    /// A tool guardrail: the same proof gate scoped to a tool call (read the proof from the tool input with `require`).
    public static func pcaToolGuard(_ options: PcaGuardrailOptions) -> Guardrail {
        Guardrail(name: options.name ?? "pca-tool-guard", execute: guardrailExecute(options.require ?? guardrailProofFromContext, options))
    }

    // ---- step-up: map a risky tool to needsApproval / the interruption flow ----

    /// Maps a tool name (and its input) to the PCA action to review; nil treats the tool as unguarded (auto).
    public typealias ToolIntent = (_ tool: String, _ input: JSONValue?) -> (verb: String, resource: String, params: JSONValue?)?

    /// Options of `reviewToolCall`.
    public struct StepUpOptions {
        /// Which PCA (verb, resource, params) a tool call maps to for risk review.
        public var intent: ToolIntent
        /// Standing "approve this class for N hours" grants that downgrade a matching step-up to auto.
        public var standing: [JSONValue]?
        /// Plaintext goal to carry on any step-up request.
        public var goal: String?
        /// Review clock (epoch ms).
        public var now: Int64?
        /// The canonical approval render of the action. A step-up without one is a deny.
        public var renderer: PCAApprovals.Renderer?
        /// The documented INSECURE opt-out: create step-up requests with no render.
        public var insecureUnboundApproval: Bool
        public init(intent: @escaping ToolIntent, standing: [JSONValue]? = nil, goal: String? = nil, now: Int64? = nil,
                    renderer: PCAApprovals.Renderer? = nil, insecureUnboundApproval: Bool = false) {
            self.intent = intent
            self.standing = standing
            self.goal = goal
            self.now = now
            self.renderer = renderer
            self.insecureUnboundApproval = insecureUnboundApproval
        }
    }

    /// The outcome of reviewing one intended tool call: `review` is `{kind: auto}`, `{kind: deny, reason}` or `{kind: step_up, request}`.
    public struct ToolReview {
        public var tool: String
        public var review: JSONValue
        public init(tool: String, review: JSONValue) {
            self.tool = tool
            self.review = review
        }
    }

    /// A step-up a tool call raised (what the approval inbox / co-sign round / SDK interruption receives).
    public struct ToolStepUp {
        public var tool: String
        public var request: JSONValue
        public init(tool: String, request: JSONValue) {
            self.tool = tool
            self.request = request
        }
    }

    /// Review a single intended tool call against the agent's grant: `auto` (no human needed), `deny` (the grant forbids it) or `step_up` with
    /// the request a co-sign round carries to the approver (tier 2 = guardian, tier 3 = human).
    public static func reviewToolCall(_ agent: PCAFacadeAgent, tool: String, input: JSONValue?, _ opts: StepUpOptions) -> ToolReview {
        guard let mapped = opts.intent(tool, input) else { return ToolReview(tool: tool, review: .object(["kind": .string("auto")])) }
        let ro = PCAApprovals.ReviewOptions(now: opts.now, goal: opts.goal, standing: opts.standing, renderer: opts.renderer,
                                            insecureUnboundApproval: opts.insecureUnboundApproval)
        return ToolReview(tool: tool, review: PCAApprovals.reviewAction(agent, verb: mapped.verb, resource: mapped.resource, params: mapped.params ?? input, ro))
    }

    /// The step-up requests from a batch of reviews (auto and deny are filtered out).
    public static func pendingStepUps(_ reviews: [ToolReview]) -> [ToolStepUp] {
        reviews.compactMap { r in
            guard r.review.get("kind") == .string("step_up"), let q = r.review.get("request") else { return nil }
            return ToolStepUp(tool: r.tool, request: q)
        }
    }

    /// Options of `pcaNeedsApproval` / `withApproval`.
    public struct NeedsApprovalOptions {
        public var stepUp: StepUpOptions
        /// The tool name to review (default `(tool)`; `withApproval` uses the tool's own name).
        public var toolName: String?
        /// True when a step-up request has already been co-signed (your FROST / CIBA result): it is then let through.
        public var approved: ((_ request: JSONValue) -> Bool)?
        /// Receives each step-up this call raised: push it to the approval inbox / open the co-sign round.
        public var onStepUp: ((ToolStepUp) -> Void)?
        /// Whether a policy deny also routes to approval (so the run interrupts and the approver rejects it). Default true: fail safe.
        public var denyNeedsApproval: Bool
        public init(stepUp: StepUpOptions, toolName: String? = nil, approved: ((JSONValue) -> Bool)? = nil, onStepUp: ((ToolStepUp) -> Void)? = nil,
                    denyNeedsApproval: Bool = true) {
            self.stepUp = stepUp
            self.toolName = toolName
            self.approved = approved
            self.onStepUp = onStepUp
            self.denyNeedsApproval = denyNeedsApproval
        }
    }

    /// Builds an Agents-SDK `needsApproval` callback from PCA risk review: `auto` answers false; a step-up not yet approved is routed to
    /// `onStepUp` and answers true (the SDK interrupts for a tier-2/3 co-sign); an already approved step-up answers false; a `deny` answers
    /// `denyNeedsApproval` (default true: interrupt so the approver can reject it). A tool with no intent mapping is `auto`.
    public static func pcaNeedsApproval(_ agent: PCAFacadeAgent, _ opts: NeedsApprovalOptions) -> AgentTool.NeedsApproval {
        let toolName = opts.toolName ?? "(tool)"
        return { _, input in
            let review = reviewToolCall(agent, tool: toolName, input: input, opts.stepUp).review
            switch review.get("kind")?.asString {
            case "auto": return false
            case "deny": return opts.denyNeedsApproval
            default:
                guard let request = review.get("request") else { return true }
                if opts.approved?(request) == true { return false }
                opts.onStepUp?(ToolStepUp(tool: toolName, request: request))
                return true
            }
        }
    }

    /// Set a tool's `needsApproval` from PCA risk review (tier 2 guardian / tier 3 human). The tool's name seeds the intent lookup unless
    /// `toolName` is given. Every other member is preserved.
    public static func withApproval(_ tool: AgentTool, _ agent: PCAFacadeAgent, _ opts: NeedsApprovalOptions) -> AgentTool {
        var o = opts
        o.toolName = opts.toolName ?? tool.name ?? "(tool)"
        return tool.with(needsApproval: pcaNeedsApproval(agent, o))
    }
}
