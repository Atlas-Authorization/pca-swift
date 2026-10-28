import Foundation

// `PcaGuard`: the framework-free request guard behind the Vapor and Hummingbird integrations (and any other HTTP stack). It layers the
// transport concerns (where the PCActn comes from, how a failure surfaces) on the offline verifier and the `authorize` pipeline; it
// re-implements no canonicalization, signature or chain logic. Semantics are those of the other native guards:
//
//   * the PCActn is read from the `PCA-Action` header (strict unpadded base64url of UTF-8 JSON) or, failing a header, from a JSON body
//     `{"pcactn": {...}}`; nothing is trimmed or normalized (one PCActn, one spelling);
//   * the DEFAULT is the full `PCA.authorize` path: the request is mapped to the operation the handler will execute (never from the
//     PCActn), the envelope predicates and caveats are enforced against it, revocation must answer `false` and the replay counter is
//     claimed atomically. A missing component (no store, no revocation check, no operation mapper) is a 403 whose reason starts with
//     `authorize_config` and names what is missing: the guard never downgrades;
//   * verifying the signature, chain and freshness only is the explicit opt-in `signatureOnly`; giving it together with authorize options
//     is a configuration error (the initializer throws);
//   * 401 for no, undecodable or unauthenticated proofs (and an unknown grant); 403 for everything else. The ternary decision is carried:
//     an `escalate` is a 403 refusal with `decision` "escalate" and the request for the principal, never an allow, and only a valid signed
//     answer pinned to the configured principals admits the action;
//   * on allow the guard hands back the verified PCActn, the core verdict and (authorize mode) the authorization bound to the operation,
//     which `PCA.executeAuthorized` / `PCAExecutor` can run at most once.

/// A request as the guard sees it. The adapters build it from their framework's request.
public struct PcaGuardRequest: Sendable {
    public var method: String
    public var path: String
    /// Header names are case-insensitive: they are stored lower-cased (a repeated header: its first value).
    public private(set) var headers: [String: String]
    /// At most `PcaGuard.MAX_BODY_BYTES` of the body (empty when there is none).
    public var body: [UInt8]
    /// False when the body was longer than `PcaGuard.MAX_BODY_BYTES` (then `body` is truncated and the operation mapper is not asked).
    public var bodyComplete: Bool

    public init(method: String, path: String, headers: [String: String] = [:], body: [UInt8] = [], bodyComplete: Bool = true) {
        self.method = method
        self.path = path
        var h: [String: String] = [:]
        for (k, v) in headers where h[k.lowercased()] == nil { h[k.lowercased()] = v }
        self.headers = h
        self.body = body
        self.bodyComplete = bodyComplete
    }

    public func header(_ name: String) -> String? { headers[name.lowercased()] }
}

/// The authorize-mode components of `PcaGuardConfig` (all but the optional ones are required: a missing one denies every request with
/// 403 `authorize_config`).
public struct PcaAuthorizeConfig {
    /// The replay store (required).
    public var stateStore: (any PCAStateStore)?
    /// `(pcactn, grant) -> revoked?` (required). Only `false` passes.
    public var isRevoked: ((JSONValue, JSONValue) throws -> Bool?)?
    /// nil (default) = `PCA.SINGLE_STEP`; "context" = the plan must come from `context` (`planAuthorized` true).
    public var plan: String?
    /// The per-request `PCA.AuthorizeContext` (throwing denies).
    public var context: ((PcaGuardRequest, JSONValue) throws -> PCA.AuthorizeContext?)?
    /// Extra check names that must pass.
    public var require: [String]
    /// Maps the request to the operation the handler will execute, from your own routing and the request body, never from the PCActn.
    /// No mapping, a throw, a nil operation or a body over the limit denies (403) before the handler runs.
    public var operation: ((PcaGuardRequest) throws -> PCA.Operation?)?
    public var allowedSuites: [String]?
    /// The pinned keys whose `EscalationAnswer`s count (header `PCA-Escalation-Answer`, or the body member `escalation_answer`). Empty:
    /// every `escalate` is refused. With any pinned, `stateStore` must be a `PCALastStore`.
    public var escalationPrincipals: [PinnedSigner]
    /// K7: recompute the approval render digest from the executed params and your own definition (see `PCA.AuthorizeInput.escalationRender`).
    public var escalationRender: ((JSONValue) -> String?)? = nil
    /// The documented INSECURE opt-out of the default that an escalation answer needs a recomputed, matching approval render.
    public var insecureUnboundApproval: Bool = false
    public var revocationStaleness: RevocationStalenessPolicy?
    public var revocationState: ((PcaGuardRequest, JSONValue, JSONValue) throws -> RevocationState?)?
    public var guardianPublic: String?
    /// Capability ids that need a non-membership proof (default: the PCActn's `cap_chain` ids) and the proof source (missing denies).
    public var revocationIds: ((PcaGuardRequest, JSONValue) -> [String])?
    public var revocationProof: ((PcaGuardRequest, JSONValue, String) -> JSONValue?)?
    public var guardianPins: [String: String]?
    public var plans: PlanRegistry?
    public var requireAssurance: AssuranceRequirement?
    public var assuranceHooks: AssuranceHooks
    /// K5 workflow admission (see `PCA.AuthorizeInput.workflow`; off when nil).
    public var workflow: PCA.WorkflowGate?
    /// The per-request workflow step. nil: the JSON request body member `workflow` {commitment, receipts, step, units, goal_digest}, else none
    /// (refused when `workflow.required`). A present but malformed body member is a call the gate refuses, never "no step".
    public var workflowStep: ((PcaGuardRequest) -> PCA.WorkflowCall?)?

    public init(stateStore: (any PCAStateStore)? = nil, isRevoked: ((JSONValue, JSONValue) throws -> Bool?)? = nil, plan: String? = nil,
                context: ((PcaGuardRequest, JSONValue) throws -> PCA.AuthorizeContext?)? = nil, require: [String] = [],
                operation: ((PcaGuardRequest) throws -> PCA.Operation?)? = nil, allowedSuites: [String]? = nil, escalationPrincipals: [PinnedSigner] = [],
                revocationStaleness: RevocationStalenessPolicy? = nil, revocationState: ((PcaGuardRequest, JSONValue, JSONValue) throws -> RevocationState?)? = nil,
                guardianPublic: String? = nil, guardianPins: [String: String]? = nil, plans: PlanRegistry? = nil,
                requireAssurance: AssuranceRequirement? = nil, assuranceHooks: AssuranceHooks = AssuranceHooks(),
                revocationIds: ((PcaGuardRequest, JSONValue) -> [String])? = nil, revocationProof: ((PcaGuardRequest, JSONValue, String) -> JSONValue?)? = nil,
                workflow: PCA.WorkflowGate? = nil, workflowStep: ((PcaGuardRequest) -> PCA.WorkflowCall?)? = nil) {
        self.workflow = workflow
        self.workflowStep = workflowStep
        self.revocationIds = revocationIds
        self.revocationProof = revocationProof
        self.stateStore = stateStore
        self.isRevoked = isRevoked
        self.plan = plan
        self.context = context
        self.require = require
        self.operation = operation
        self.allowedSuites = allowedSuites
        self.escalationPrincipals = escalationPrincipals
        self.revocationStaleness = revocationStaleness
        self.revocationState = revocationState
        self.guardianPublic = guardianPublic
        self.guardianPins = guardianPins
        self.plans = plans
        self.requireAssurance = requireAssurance
        self.assuranceHooks = assuranceHooks
    }
}

/// Run the allowed request's handler at most once (`PCAExecutor`): the operation record store and the executor options.
public struct PcaGuardExecutorConfig {
    /// REQUIRED: the operation record store (nil refuses every request, fail closed).
    public var operations: OperationStore?
    /// An extra re-check before an irreversible operation (the executor's own revocation / expiry / plan re-check always runs).
    public var recheck: ((ExecutionHandle) async throws -> RecheckResult)?
    /// nil or "irreversible" (default), or "always".
    public var recheckFor: String?
    /// The server's reversibility class for an operation; nil: the signed class only.
    public var reversibilityClassOf: ((PCA.Operation) -> String?)?
    /// An open record older than this is settled (0: `PCA.OPERATION_PENDING_TIMEOUT_MS`).
    public var pendingTimeoutMs: Int64

    public init(operations: OperationStore?, recheck: ((ExecutionHandle) async throws -> RecheckResult)? = nil, recheckFor: String? = nil,
                reversibilityClassOf: ((PCA.Operation) -> String?)? = nil, pendingTimeoutMs: Int64 = 0) {
        self.operations = operations
        self.recheck = recheck
        self.recheckFor = recheckFor
        self.reversibilityClassOf = reversibilityClassOf
        self.pendingTimeoutMs = pendingTimeoutMs
    }
}

/// The downstream handler's response, which is the operation's recorded result (a retry of the same PCActn is answered from it).
public struct PcaRecordedResponse: Sendable {
    public var status: Int
    /// Header name -> values. Hop-by-hop and length headers are not recorded.
    public var headers: [String: [String]]
    public var body: [UInt8]

    public init(status: Int, headers: [String: [String]] = [:], body: [UInt8] = []) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    static func notRecorded(_ name: String) -> Bool {
        ["content-length", "transfer-encoding", "connection", "keep-alive"].contains(name.lowercased())
    }

    var json: JSONValue {
        var h: JObject = [:]
        for (k, v) in headers where !PcaRecordedResponse.notRecorded(k) { h[JKey(k)] = .array(v.map { .string($0) }) }
        return .object(["status": .int(Int64(status)), "headers": .object(h), "body": .string(Data(body).base64EncodedString())])
    }

    /// nil when the record is not a response this type wrote.
    static func from(_ v: JSONValue?) -> PcaRecordedResponse? {
        guard let o = v?.asObject, let st = o["status"]?.safeInt, st >= 100, st <= 599, let hs = o["headers"]?.asObject,
              let b64 = o["body"]?.asString, let data = Data(base64Encoded: b64) else { return nil }
        var headers: [String: [String]] = [:]
        for (k, val) in hs {
            guard let arr = val.asArray else { return nil }
            var vals: [String] = []
            for x in arr {
                guard let t = x.asString else { return nil }
                vals.append(t)
            }
            if !notRecorded(k.s) { headers[k.s] = vals }
        }
        return PcaRecordedResponse(status: Int(st), headers: headers, body: [UInt8](data))
    }
}

/// What the guard answers when it ran (or refused to run) the handler: write status, headers and body as they are.
public struct PcaGuardReply: Sendable {
    public var status: Int
    public var headers: [String: [String]]
    public var body: [UInt8]
}

/// `PcaGuard` configuration.
public struct PcaGuardConfig {
    /// This resource server's id, checked against the PCActn's signed `aud`.
    public var audience: String
    /// `grant_ref -> grant` from your own store (nil or a throw is an unknown grant).
    public var resolveGrant: ((String) throws -> JSONValue?)?
    /// Epoch milliseconds (default: the wall clock).
    public var now: (() -> Int64)?
    public var intentPolicy: IntentPolicy?
    /// The Intent Layer v2 verifier state for this request (throwing denies).
    public var intentV2: ((PcaGuardRequest, JSONValue) throws -> IntentV2Context?)?
    /// The explicit opt-in to verify the signature, chain and freshness only (the core verifier): no policy, no replay, no revocation, no
    /// operation binding. Together with `authorize` it is a configuration error.
    public var signatureOnly: Bool
    /// The authorize-mode components. nil = an empty set: every request is refused with 403 `authorize_config` naming what is missing.
    public var authorize: PcaAuthorizeConfig?
    /// Run the downstream handler inside the executor (at most once per authorization, retries answered from the record). Needs the
    /// authorize path. nil: the handler runs after the allow, as before.
    public var executor: PcaGuardExecutorConfig?

    public init(audience: String, resolveGrant: ((String) throws -> JSONValue?)? = nil, now: (() -> Int64)? = nil, intentPolicy: IntentPolicy? = nil,
                intentV2: ((PcaGuardRequest, JSONValue) throws -> IntentV2Context?)? = nil, signatureOnly: Bool = false, authorize: PcaAuthorizeConfig? = nil,
                executor: PcaGuardExecutorConfig? = nil) {
        self.executor = executor
        self.audience = audience
        self.resolveGrant = resolveGrant
        self.now = now
        self.intentPolicy = intentPolicy
        self.intentV2 = intentV2
        self.signatureOnly = signatureOnly
        self.authorize = authorize
    }
}

/// A configuration the guard refuses at construction.
public struct PcaGuardConfigError: Error, Equatable, CustomStringConvertible {
    public let message: String
    public var description: String { message }
}

/// What a passing request carries to the handler.
public struct PcaGuardAllow {
    /// The verified PCActn.
    public let pcactn: JSONValue
    /// The core verdict.
    public let verdict: PCA.Verdict?
    /// Authorize mode: the full decision. Its `operation` is the operation the request was authorized for.
    public let authorization: PCA.AuthorizeResult?
    /// Executor mode: the operation id, to pass as the idempotency key of the downstream call.
    public var idempotencyKey: String?
    /// Executor mode: the operation the executor authorized (there `authorization` is nil).
    public var authorizedOperation: PCA.AuthorizedOperation?

    /// The operation this request was authorized for (authorize mode).
    public var operation: PCA.AuthorizedOperation? { authorization?.operation ?? authorizedOperation }

    /// True only if the authorization is for exactly this operation (verb, resource, params digest): call it where the side effect runs.
    public func isAuthorized(for operation: PCA.Operation) -> Bool {
        if let a = authorization { return PCA.isAuthorized(a, for: operation) }
        guard let b = authorizedOperation, operation.isValid, let d = IV.strictHash(operation.params) else { return false }
        return IV.same(b.verb, operation.verb) && IV.same(b.resource, operation.resource) && b.paramsDigest == d
    }
}

/// A refused request: the HTTP answer to write.
public struct PcaGuardDenial {
    /// 401 or 403.
    public let status: Int
    /// The error token: `invalid_request`, `unknown_grant`, `invalid_pcactn`, `verification_error`, `insufficient_authority`.
    public let code: String
    /// The `WWW-Authenticate` value (it never carries request-derived text).
    public let wwwAuthenticate: String
    /// The JSON body (UTF-8).
    public let body: [UInt8]
    /// `deny` or `escalate` (authorize mode).
    public let decision: String
    /// `escalate`: the request to put to the principal.
    public let escalation: JSONValue?
    /// The authorize result of a denial (authorize mode).
    public let authorization: PCA.AuthorizeResult?

    public var contentType: String { "application/json" }
    public var bodyText: String { String(decoding: body, as: UTF8.self) }
}

// The decision values cross task boundaries in the HTTP frameworks (request storage, middleware chains). They are values; the
// authorization they carry is immutable once built.
extension PcaGuardAllow: @unchecked Sendable {}
extension PcaGuardDenial: @unchecked Sendable {}

/// The guard's answer.
public enum PcaGuardDecision {
    case allow(PcaGuardAllow)
    case deny(PcaGuardDenial)

    public var allowed: Bool { if case .allow = self { return true } else { return false } }
}

/// The framework-free guard. Safe for concurrent use when its stores are.
public final class PcaGuard: @unchecked Sendable {
    /// The request header carrying a base64url(JSON) PCActn.
    public static let HEADER = "PCA-Action"
    /// The request header carrying the principal's base64url(JSON) escalation answer.
    public static let ESCALATION_HEADER = "PCA-Escalation-Answer"
    /// The most request body the guard reads (the adapters stop at this many bytes plus one).
    public static let MAX_BODY_BYTES = Canonical.MAX_JSON_BYTES

    private let config: PcaGuardConfig

    public init(_ config: PcaGuardConfig) throws {
        if config.signatureOnly && config.authorize != nil {
            throw PcaGuardConfigError(message: "PcaGuard: signatureOnly and authorize are mutually exclusive")
        }
        if let az = config.authorize, !az.escalationPrincipals.isEmpty, let s = az.stateStore, !(s is PCALastStore) {
            throw PcaGuardConfigError(message: "PcaGuard: authorize.escalationPrincipals needs a stateStore that is a PCALastStore (an escalation answer is bound to the holder's history head)")
        }
        if config.executor != nil && (config.signatureOnly || config.authorize == nil) {
            throw PcaGuardConfigError(message: "PcaGuard: executor needs the authorize path (not signatureOnly)")
        }
        self.config = config
    }

    /// True when the downstream handler must run through `handle(_:run:)` (an executor is configured).
    public var executes: Bool { config.executor != nil }

    // ---- extraction ----

    /// Strict unpadded base64url of UTF-8 text (nothing trimmed or normalized); nil on any deviation.
    static func decodeHeader(_ value: String) -> String? {
        guard !value.isEmpty, let bytes = Base64URLStrict.decode(value) else { return nil }
        let text = String(decoding: bytes, as: UTF8.self)
        return Array(text.utf8) == bytes ? text : nil // invalid UTF-8 would have been replaced
    }

    /// The UTF-8 text of `bytes`, or nil when they are not valid UTF-8.
    static func utf8Text(_ bytes: [UInt8]) -> String? {
        let text = String(decoding: bytes, as: UTF8.self)
        return Array(text.utf8) == bytes ? text : nil
    }

    private func extract(_ req: PcaGuardRequest) -> (pcactn: JSONValue?, reason: String) {
        if let h = req.header(PcaGuard.HEADER), !h.isEmpty {
            guard let text = PcaGuard.decodeHeader(h) else { return (nil, "PCA-Action header is not valid base64url") }
            guard text.utf8.count <= PCA.MAX_ARTIFACT_BYTES, let v = try? StrictJSON.parse(text), v.isObject else {
                return (nil, "PCA-Action header is not a valid PCActn JSON object")
            }
            return (v, "")
        }
        if req.body.isEmpty { return (nil, "no PCActn presented (missing PCA-Action header and request body)") }
        guard req.bodyComplete, let text = PcaGuard.utf8Text(req.body), let v = try? StrictJSON.parse(text) else {
            return (nil, "request body is not valid strict JSON")
        }
        guard case let .object(o) = v else { return (nil, "request body is not a JSON object") }
        guard let pv = o["pcactn"] else { return (nil, "request body has no 'pcactn' field") }
        guard pv.isObject else { return (nil, "'pcactn' is not a JSON object") }
        return (pv, "")
    }

    /// The principal's answer: header `PCA-Escalation-Answer`, else the body member `escalation_answer`; nil when absent or unreadable.
    private func escalationAnswer(_ req: PcaGuardRequest) -> JSONValue? {
        if let h = req.header(PcaGuard.ESCALATION_HEADER), !h.isEmpty { return PCA.escalationAnswer(fromHeader: h) }
        guard req.bodyComplete, !req.body.isEmpty, let text = PcaGuard.utf8Text(req.body), case let .object(o)? = try? StrictJSON.parse(text) else { return nil }
        return o["escalation_answer"]
    }

    /// The workflow step of this request: the config callback, else the JSON body member `workflow`; nil when none is carried.
    private func workflowCall(_ req: PcaGuardRequest, _ az: PcaAuthorizeConfig) -> PCA.WorkflowCall? {
        if let f = az.workflowStep { return f(req) }
        guard req.bodyComplete, !req.body.isEmpty, let text = PcaGuard.utf8Text(req.body), case let .object(o)? = try? StrictJSON.parse(text),
              let w = o["workflow"] else { return nil }
        let bad = PCA.WorkflowCall(commitment: .null, receipts: .null, step: "") // the gate refuses it (403 workflow), never reads it as "no step"
        guard case .object = w, let c = w.get("commitment"), let r = w.get("receipts"), let step = w.get("step")?.asString else { return bad }
        var units: [String: String] = [:]
        if let u = w.get("units"), !u.isNull {
            guard let uo = u.asObject else { return bad }
            for (k, v) in uo {
                guard let vs = v.asString else { return bad }
                units[k.s] = vs
            }
        }
        var goal: String?
        if let g = w.get("goal_digest"), !g.isNull {
            guard let gs = g.asString else { return bad }
            goal = gs
        }
        return PCA.WorkflowCall(commitment: c, receipts: r, step: step, units: units, goalDigest: goal)
    }

    // ---- the answer ----

    private static func challenge(_ code: String, _ description: String?) -> String {
        var c = "PCA realm=\"pca\", error=\"\(code)\""
        if let d = description { c += ", error_description=\"\(d)\"" }
        return c
    }

    /// `description` MUST be one of the guard's own fixed strings: it is echoed into the challenge header. Request-derived text goes
    /// through `denial(... reason:)`.
    private static func fixedDenial(_ status: Int, _ code: String, _ description: String) -> PcaGuardDecision {
        let body = JSONValue.object(["error": .string(code), "error_description": .string(description), "doc": .string(refusalDocURL(description))])
        return .deny(PcaGuardDenial(status: status, code: code, wwwAuthenticate: challenge(code, description), body: Array(Canonical.canonicalize(body).utf8),
                                    decision: "deny", escalation: nil, authorization: nil))
    }

    /// A request-derived reason surfaces only in the JSON body (never in the header: header injection).
    private static func reasonDenial(_ status: Int, _ code: String, _ reason: String, checks: JSONValue?) -> PcaGuardDecision {
        var o: JObject = ["error": .string(code), "error_description": .string(reason), "reason": .string(reason), "doc": .string(refusalDocURL(reason))]
        if let c = checks { o["checks"] = c }
        return .deny(PcaGuardDenial(status: status, code: code, wwwAuthenticate: challenge(code, nil), body: Array(Canonical.canonicalize(.object(o)).utf8),
                                    decision: "deny", escalation: nil, authorization: nil))
    }

    private static func authorizeDenial(_ r: PCA.AuthorizeResult) -> PcaGuardDecision {
        let code = r.status == 401 ? "invalid_pcactn" : "insufficient_authority"
        var checks: JObject = [:]
        for (k, v) in r.checks { checks[JKey(k)] = .string(v.rawValue) }
        let reason = r.reason ?? "denied"
        var o: JObject = ["error": .string(code), "error_description": .string(reason), "reason": .string(reason), "checks": .object(checks),
                          "decision": .string(r.decision), "doc": .string(refusalDocURL(reason))]
        if let e = r.escalation { o["escalation"] = e }
        if let m = r.missing { o["missing"] = .array(m.map { .string($0) }) }
        return .deny(PcaGuardDenial(status: r.status, code: code, wwwAuthenticate: challenge(code, nil), body: Array(Canonical.canonicalize(.object(o)).utf8),
                                    decision: r.decision, escalation: r.escalation, authorization: r))
    }

    // ---- the guard ----

    /// Decides one request. Never throws: any failure to decide is a refusal.
    public func handle(_ req: PcaGuardRequest) -> PcaGuardDecision {
        let got = extract(req)
        guard let pcactn = got.pcactn else { return PcaGuard.fixedDenial(401, "invalid_request", got.reason) }
        let now = (config.now ?? { Int64(Date().timeIntervalSince1970 * 1000) })()
        return config.signatureOnly ? verifyOnly(req, pcactn, now) : authorize(req, pcactn, now)
    }

    private func verifyOnly(_ req: PcaGuardRequest, _ pcactn: JSONValue, _ now: Int64) -> PcaGuardDecision {
        guard let grantRef = pcactn.get("grant_ref")?.asString, !grantRef.isEmpty else {
            return PcaGuard.fixedDenial(401, "invalid_request", "PCActn has no grant_ref")
        }
        guard let resolve = config.resolveGrant else { return PcaGuard.fixedDenial(401, "invalid_request", "no grant resolver configured") }
        let grant: JSONValue?
        do { grant = try resolve(grantRef) } catch { grant = nil }
        guard let g = grant else { return PcaGuard.fixedDenial(401, "unknown_grant", "grant_ref does not resolve to a known grant") }
        var v2: IntentV2Context?
        if let f = config.intentV2 {
            do { v2 = try f(req, pcactn) } catch { return PcaGuard.reasonDenial(403, "verification_error", "intent_v2: verifier state unavailable (fail closed)", checks: nil) }
        }
        let verdict = PCA.verify(pcactn: pcactn, grant: g, now: now, audience: .id(config.audience), intentPolicy: config.intentPolicy, intentV2: v2)
        if !verdict.allow {
            var checks: JObject = [:]
            for (k, ok) in verdict.checks { checks[JKey(k)] = .bool(ok) }
            return PcaGuard.reasonDenial(403, "insufficient_authority", verdict.reason, checks: .object(checks))
        }
        return .allow(PcaGuardAllow(pcactn: pcactn, verdict: verdict, authorization: nil))
    }

    private func authorizeInput(_ req: PcaGuardRequest, _ now: Int64) -> PCA.AuthorizeInput {
        let az = config.authorize ?? PcaAuthorizeConfig()
        var op: PCA.Operation?
        if let map = az.operation, req.bodyComplete, let mapped = try? map(req) { op = mapped } // a throw or nil: no operation, which denies
        var plan: String? = PCA.SINGLE_STEP
        if let p = az.plan { plan = IV.same(p, "context") ? nil : p }
        var input = PCA.AuthorizeInput(operation: op, audience: config.audience, resolveGrant: config.resolveGrant, stateStore: az.stateStore,
                                       isRevoked: az.isRevoked, now: now, plan: plan, intentPolicy: config.intentPolicy, allowedSuites: az.allowedSuites,
                                       require: az.require, escalationPrincipals: az.escalationPrincipals)
        if !az.escalationPrincipals.isEmpty { input.escalationAnswer = escalationAnswer(req) }
        input.escalationRender = az.escalationRender
        input.insecureUnboundApproval = az.insecureUnboundApproval
        if let c = az.context { input.context = { p in try c(req, p) } }
        if let f = config.intentV2 { input.intentV2 = .provider { p in try f(req, p) } }
        input.revocationStaleness = az.revocationStaleness
        input.guardianPublic = az.guardianPublic
        input.guardianPins = az.guardianPins
        if let s = az.revocationState { input.revocationState = { p, g in try s(req, p, g) } }
        if let f = az.revocationIds { input.revocationIds = { p in f(req, p) } }
        if let f = az.revocationProof { input.revocationProof = { p, id in f(req, p, id) } }
        input.plans = az.plans
        input.requireAssurance = az.requireAssurance
        input.assuranceHooks = az.assuranceHooks
        if let wg = az.workflow {
            input.workflow = wg
            input.workflowStep = workflowCall(req, az)
        }
        return input
    }

    private func authorize(_ req: PcaGuardRequest, _ pcactn: JSONValue, _ now: Int64) -> PcaGuardDecision {
        let r = PCA.authorize(pcactn: pcactn, authorizeInput(req, now))
        if !r.allow { return PcaGuard.authorizeDenial(r) }
        return .allow(PcaGuardAllow(pcactn: r.pcactn ?? pcactn, verdict: r.verdict, authorization: r))
    }

    // ---- running the handler once ----

    private static func reply(_ d: PcaGuardDenial) -> PcaGuardReply {
        PcaGuardReply(status: d.status, headers: ["WWW-Authenticate": [d.wwwAuthenticate], "Content-Type": ["application/json"]], body: d.body)
    }

    /// An executor-path error answer. `description` may carry request-derived text: it goes in the JSON body only.
    private static func errorReply(_ status: Int, _ code: String, _ description: String) -> PcaGuardReply {
        let body = JSONValue.object(["error": .string(code), "error_description": .string(description), "doc": .string(refusalDocURL(description))])
        var h = ["Content-Type": ["application/json"]]
        if status == 401 || status == 403 { h["WWW-Authenticate"] = [challenge(code, nil)] }
        return PcaGuardReply(status: status, headers: h, body: Array(Canonical.canonicalize(body).utf8))
    }

    /// Decides one request and, when allowed, runs `run` (the downstream handler) at most once through `PCAExecutor`. The handler's
    /// response is the operation's recorded result: a retry of the same PCActn is answered from the record with header
    /// `PCA-Replayed: true` and the handler is not run again. A throw from `run` is recorded as a failure (500 `operation_failed`, no
    /// error text), an execution in flight is 409 `operation_in_progress`, an unknown outcome 409 `operation_uncertain`, a refused re-check
    /// 403 `operation_aborted`. Without an executor configured this is a 403 `authorize_config`.
    public func handle(_ req: PcaGuardRequest, run: (PcaGuardAllow) async throws -> PcaRecordedResponse) async -> PcaGuardReply {
        guard let ex = config.executor else { return PcaGuard.errorReply(403, "authorize_config", "executor: not configured") }
        let got = extract(req)
        guard let pcactn = got.pcactn else {
            if case let .deny(d) = PcaGuard.fixedDenial(401, "invalid_request", got.reason) { return PcaGuard.reply(d) }
            return PcaGuard.errorReply(401, "invalid_request", got.reason)
        }
        let now = (config.now ?? { Int64(Date().timeIntervalSince1970 * 1000) })()
        let input = authorizeInput(req, now)
        let executor = PCAExecutor(ExecutorOptions(operations: ex.operations, authorize: input, recheck: ex.recheck, recheckFor: ex.recheckFor,
                                                   reversibilityClassOf: ex.reversibilityClassOf, pendingTimeoutMs: ex.pendingTimeoutMs, now: config.now))
        let out = await executor.run(pcactn: pcactn, operation: input.operation) { h in
            let allow = PcaGuardAllow(pcactn: h.pcactn, verdict: nil, authorization: nil, idempotencyKey: h.idempotencyKey, authorizedOperation: h.operation)
            return try await run(allow).json
        }
        let x = out.execution
        switch x.status {
        case .committed:
            guard let rec = PcaRecordedResponse.from(x.result) else {
                return PcaGuard.errorReply(409, "operation_uncertain", "the recorded result is unreadable")
            }
            var headers = rec.headers
            if x.replayed { headers["PCA-Replayed"] = ["true"] }
            return PcaGuardReply(status: rec.status, headers: headers, body: rec.body)
        case .denied:
            if let a = out.authorization, case let .deny(d) = PcaGuard.authorizeDenial(a) { return PcaGuard.reply(d) }
            return PcaGuard.errorReply(403, "access_denied", "denied")
        case .failed: return PcaGuard.errorReply(500, "operation_failed", "the operation failed")
        case .aborted: return PcaGuard.errorReply(403, "operation_aborted", x.reason ?? "aborted")
        case .pending: return PcaGuard.errorReply(409, "operation_in_progress", "another execution of this operation is in flight")
        case .uncertain: return PcaGuard.errorReply(409, "operation_uncertain", x.reason ?? "outcome unknown")
        case .refused: return PcaGuard.errorReply(403, "access_denied", x.reason ?? "denied")
        }
    }

    // ---- answering an execution ----

    /// The HTTP status for an execution outcome: 200 for a commit (also when answered from the record), 500 for a failed function, 409 for
    /// an in-flight or uncertain operation (retry later or reconcile), 403 for a refusal, an abort or a denial.
    public static func operationStatus(_ o: ExecuteOutcome) -> Int {
        switch o.status {
        case .committed: return 200
        case .failed: return 500
        case .pending, .uncertain: return 409
        case .aborted, .refused, .denied: return 403
        }
    }

    /// The JSON body for an execution outcome, as the shared vectors write it.
    public static func operationBody(_ o: ExecuteOutcome) -> String { Canonical.canonicalize(o.json) }
}
