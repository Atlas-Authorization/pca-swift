import Foundation

extension PCAGateway {
    public enum DecisionCode: String {
        case allow
        case noProof = "no-proof"
        case invalidProof = "invalid-proof"
        case unknownGrant = "unknown-grant"
        case verifyFailed = "verify-failed"
        case wrongAudience = "wrong-audience"
        case insufficientCapability = "insufficient-capability"
        case unmappedRoute = "unmapped-route"
        case invalidPath = "invalid-path"
        case replayedProof = "replayed-proof"
        case replayGuardUnavailable = "replay-guard-unavailable"
        case requestMismatch = "request-mismatch"
        case proofRejected = "proof-rejected"
    }

    /// The core verdict as the gateway reports it: each check `pass`, `fail` or `not-enforced`.
    public struct GatewayVerdict {
        public var allow: Bool
        public var checks: [(String, String)]
        public var reason: String?
        public func status(_ name: String) -> String? { checks.first { $0.0 == name }?.1 }
        public var json: JSONValue {
            var c = JObject()
            for (k, v) in checks { c[JKey(k)] = .string(v) }
            var o: JObject = ["allow": .bool(allow), "checks": .object(c)]
            if let r = reason { o["reason"] = .string(r) }
            return .object(o)
        }
    }

    public struct Decision {
        public var allow: Bool
        public var status: Int
        public var code: DecisionCode
        public var reason: String
        /// In the order set.
        public var headers: [(String, String)]
        public var verdict: GatewayVerdict?
        public var pcactn: JSONValue?
        public var matched: RequiredCapability?
        /// Full-policy mode: the `PCA.authorize` verdict (`{allow, checks, reason?}`).
        public var policyVerdict: JSONValue?
    }

    /// A revocation source: whether the grant (or the chain) is revoked at `nowEpoch`.
    public enum RevocationResult {
        case notEnforced
        case enforced(ok: Bool, reason: String?)
    }
    public typealias RevocationHook = (_ pcactn: JSONValue, _ grant: JSONValue, _ nowEpoch: Int64) throws -> RevocationResult

    /// What an attestation / threshold / zk hook reports: `enforced: false` is "not enforced"; `t` is the threshold the threshold hook enforced.
    public struct HookOutcome: Equatable {
        public var enforced: Bool
        public var ok: Bool
        public var reason: String?
        public var t: Double?
        public init(enforced: Bool, ok: Bool = false, reason: String? = nil, t: Double? = nil) {
            self.enforced = enforced
            self.ok = ok
            self.reason = reason
            self.t = t
        }
        /// "I did not check": the status stays not-enforced.
        public static let notEnforced = HookOutcome(enforced: false)
    }
    /// A verifier hook (a throw makes the PCActn malformed: the request is denied, fail closed).
    public typealias VerifyHook = (_ pcactn: JSONValue, _ grant: JSONValue, _ nowEpoch: Int64) throws -> HookOutcome

    /// The M5 attestation gate: the verifier runs in the `attestation` slot, and a not-enforced / absent answer is a FAIL unless `required` is false.
    public struct AttestationGate {
        public var verifier: VerifyHook
        public var required: Bool
        public init(verifier: @escaping VerifyHook, required: Bool = true) {
            self.verifier = verifier
            self.required = required
        }
    }

    /// Opt-in enforcement gates of the core verification step (each off by default: its check reports `not-enforced`, or is absent for freshness).
    public struct EnforceGates {
        /// M1 information-flow taint gate (check `taint_gate`).
        public var taint: PCA.TaintGate?
        /// M3 signed freshness anchor gate (check `freshness`).
        public var freshness: PCA.FreshnessGate?
        /// M5 attestation gate (check `attestation`).
        public var attestation: AttestationGate?
        public init(taint: PCA.TaintGate? = nil, freshness: PCA.FreshnessGate? = nil, attestation: AttestationGate? = nil) {
            self.taint = taint
            self.freshness = freshness
            self.attestation = attestation
        }
    }

    public struct ProofContext {
        public var pcactn: JSONValue
        public var grant: JSONValue
        public var verdict: GatewayVerdict
        public var request: GatewayRequest
        public var required: RequiredCapability?
    }

    /// The verifier's own K1 input (caveat language v2): fixed, or a function of the request and the proof.
    public enum K1Source {
        case fixed(K1Input)
        case fn((_ req: GatewayRequest, _ pcactn: JSONValue) throws -> K1Input)
    }

    public enum ProvenanceLogChoice {
        /// An in-memory log per gateway (share one store across nodes for the same guarantee cluster-wide).
        case `default`
        /// No log: the agent's signed chain is then the only evidence.
        case off
        case custom(ProvenanceLog)
    }

    public struct FullPolicy {
        public var params: ParamsSource
        /// The `PCA.authorize` template: `stateStore` and `isRevoked` are required; the gateway sets `operation`, `audience`, `resolveGrant` and `now`.
        public var input: PCA.AuthorizeInput
        /// Caveat language v2 (third-party discharges, `narrow`, `derive`, `max_uses`, `spiffe_bound`): the verifier's own input (pins, revoked
        /// discharges, SPIFFE id, history). The presented artifacts are read from the request (headers `PCA-Discharges` / `PCA-Narrow`; with function
        /// params also the body members `pca_discharges` / `pca_narrow`); a non-empty configured `discharges` and a configured `narrow` win over the
        /// presented ones. Absent: the template's own `k1` applies, and without one every K1 caveat refuses (fail closed).
        public var k1: K1Source?
        public var provenanceLog: ProvenanceLogChoice
        /// The log `.default` resolves to for direct `authorize` calls (shared by copies of this value; `createGateway` gives each gateway its own).
        let defaultLog = MemoryProvenanceLog()
        public init(params: ParamsSource, input: PCA.AuthorizeInput, k1: K1Source? = nil, provenanceLog: ProvenanceLogChoice = .default) {
            self.params = params
            self.input = input
            self.k1 = k1
            self.provenanceLog = provenanceLog
        }
    }

    public enum Policy {
        /// The proof is verified with the core verifier, bound to the request, and spent through the replay guard.
        case signatureOnly
        case full(FullPolicy)
    }

    public struct GatewayOptions {
        public var audience: String
        public var routes: [RouteRule]
        public var resolveGrant: (_ grantRef: String, _ pcactn: JSONValue) throws -> JSONValue?
        public var authorizedPlanRoots: [String]?
        public var insecureSkipPlanRootCheck = false
        /// "deny" (default), "allow", or "require-proof" (an unmapped route still needs a valid proof).
        public var unmatchedRoute = "deny"
        public var replayGuard: ReplayGuard?
        /// Which request attributes the proof binds; `bindRequestOff` disables request binding altogether.
        public var bindRequest = BindRequestOptions()
        public var bindRequestOff = false
        public var revocation: RevocationHook?
        /// The attestation, threshold and zk hooks of the core verification step (each reports `not-enforced` without one). A `zk_compliance`
        /// proof the PCActn carries needs `zk`, else the proof fails closed.
        public var attestation: VerifyHook?
        public var threshold: VerifyHook?
        public var zk: VerifyHook?
        public var enforce = EnforceGates()
        /// Checks that must have PASSED (not merely "not-enforced"). nil: `["revocation"]` in signature-only mode, none in full mode.
        public var requireChecks: [String]?
        public var checkProof: ((ProofContext) throws -> (allow: Bool, reason: String?))?
        /// "strict" (default) refuses an ambiguous path; "off" disables the check.
        public var pathPolicy = "strict"
        public var now: (() -> Int64)?
        public var realm: String?
        public var policy: Policy?
        public init(audience: String, routes: [RouteRule], resolveGrant: @escaping (String, JSONValue) throws -> JSONValue?, policy: Policy?) {
            self.audience = audience
            self.routes = routes
            self.resolveGrant = resolveGrant
            self.policy = policy
        }
    }

    // MARK: matching

    private static func matchMethod(_ rule: RouteRule, _ method: String) -> Bool {
        guard let m = rule.method else { return true }
        return m == "*" || m.uppercased() == "ANY" || m.uppercased() == method.uppercased()
    }

    private static func matchPath(_ pattern: String, _ path: String) -> Bool {
        if pattern == "*" || pattern == "/*" { return true }
        if IV.endsWith(pattern, "/*") {
            let prefix = String(pattern.unicodeScalars.dropLast(2))
            return IV.same(path, prefix) || IV.startsWith(path, prefix + "/")
        }
        if IV.endsWith(pattern, "*") { return IV.startsWith(path, String(pattern.unicodeScalars.dropLast(1))) }
        return IV.same(path, pattern)
    }

    private static let ERROR_TOKEN: [DecisionCode: String] = [
        .noProof: "missing_proof", .invalidProof: "invalid_proof", .unknownGrant: "invalid_proof", .verifyFailed: "invalid_proof", .wrongAudience: "invalid_resource",
        .insufficientCapability: "insufficient_capability", .unmappedRoute: "access_denied", .invalidPath: "invalid_request", .replayedProof: "replayed_proof",
        .replayGuardUnavailable: "temporarily_unavailable", .requestMismatch: "proof_not_bound_to_request", .proofRejected: "access_denied",
    ]

    private static func deny(_ code: DecisionCode, _ status: Int, _ reason: String, _ realm: String, verdict: GatewayVerdict? = nil, pcactn: JSONValue? = nil, matched: RequiredCapability? = nil,
                             policyVerdict: JSONValue? = nil) -> Decision {
        Decision(allow: false, status: status, code: code, reason: reason, headers: [("www-authenticate", "PCA realm=\"\(realm)\", error=\"\(ERROR_TOKEN[code] ?? "access_denied")\"")],
                 verdict: verdict, pcactn: pcactn, matched: matched, policyVerdict: policyVerdict)
    }

    private static func allowDecision(_ reason: String, verdict: GatewayVerdict? = nil, pcactn: JSONValue? = nil, matched: RequiredCapability? = nil, policyVerdict: JSONValue? = nil) -> Decision {
        var h: [(String, String)] = []
        if let v = verdict { h.append(("x-pca-verdict", JS.stringify(v.json, order: ["allow", "checks", "reason"]))) }
        if let p = pcactn {
            h.append(("x-pca-verb", p.get("action")?.get("verb")?.asString ?? ""))
            h.append(("x-pca-grant", p.get("grant_ref")?.asString ?? ""))
        }
        return Decision(allow: true, status: 200, code: .allow, reason: reason, headers: h, verdict: verdict, pcactn: pcactn, matched: matched, policyVerdict: policyVerdict)
    }

    // MARK: configuration

    private static func missingText(_ o: GatewayOptions, _ missing: [String]) -> String {
        var full = false
        if case .full? = o.policy { full = true }
        return "\(full ? "full policy mode" : "the gateway") is missing \(missing.joined(separator: ", "))"
    }

    private static func missingPolicy(_ o: GatewayOptions) -> [String] {
        switch o.policy {
        case nil: return ["policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })"]
        case .signatureOnly?:
            var m: [String] = []
            if o.replayGuard == nil { m.append("replayGuard (signature-only mode needs a single-use guard)") }
            if (o.requireChecks ?? ["revocation"]).contains("revocation"), o.revocation == nil {
                m.append("hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)")
            }
            return m
        case let .full(f)?:
            var m: [String] = []
            if f.input.stateStore == nil { m.append("state") }
            if f.input.isRevoked == nil { m.append("isRevoked") }
            return m
        }
    }

    // MARK: the verdict

    /// The core verdict plus the enforcement gates and hooks, as the reference's `verifyPCActnCore` reports them, in its order: the core checks,
    /// `taint_gate`, `freshness` (gate on), `attestation`, `threshold`, `revocation`, `zk_compliance` (a carried proof), `bond` (a carried ref).
    /// A hook that throws makes the PCActn malformed: the checks after it are not run.
    private static func verifyProof(_ pcactn: JSONValue, _ grant: JSONValue, _ now: Int64, _ o: GatewayOptions) -> GatewayVerdict {
        let core = PCA.verify(pcactn: pcactn, grant: grant, now: now, audience: o.audience, authorizedPlanRoots: o.authorizedPlanRoots, insecureSkipPlanRootCheck: o.insecureSkipPlanRootCheck)
        var checks: [(String, String)] = []
        var done = Set<String>()
        // the core verifier fails a carried zk proof outright; whether a zk hook enforced it is decided below, in the reference's place
        let zkCarried = pcactn.get("zk_compliance") != nil
        for n in PCA.CORE_CHECK_ORDER + core.checks.keys.sorted() where core.checks[n] != nil && !done.contains(n) {
            done.insert(n)
            if n == "zk_compliance" { continue }
            checks.append((n, core.checks[n]! ? "pass" : "fail"))
        }
        if core.checks["wire"] == false { return GatewayVerdict(allow: false, checks: checks, reason: core.reasons.first ?? core.reason) } // terminal
        var reasons = core.reasons.filter { !$0.hasPrefix("zk_compliance:") }
        func set(_ name: String, _ status: String) {
            if let i = checks.firstIndex(where: { $0.0 == name }) { checks[i].1 = status } else { checks.append((name, status)) }
        }
        func fail(_ name: String, _ why: String) {
            set(name, "fail")
            reasons.append("\(name): \(why)")
        }
        func statusOf(_ r: HookOutcome) -> String { r.enforced ? (r.ok ? "pass" : "fail") : "not-enforced" }
        func run(_ name: String, _ hook: VerifyHook?) throws {
            let r = try hook?(pcactn, grant, now) ?? .notEnforced
            let st = statusOf(r)
            if st == "fail" { fail(name, r.reason ?? "rejected") } else { set(name, st) }
        }
        do {
            // M1 taint gate: every declared provenance ref is re-classified from facts the server holds, never from the agent's own label
            if let tg = o.enforce.taint {
                let r = Taint.gate(pcactn.get("provenance"), registry: tg.registry, resourceGraphNode: tg.resourceGraphNode, maxTaint: tg.maxTaint)
                if r.ok { set("taint_gate", "pass") } else { fail("taint_gate", r.reason ?? "rejected") }
            } else {
                set("taint_gate", "not-enforced")
            }
            // M3 freshness gate: a missing, stub, future or stale signed anchor refuses
            if let fg = o.enforce.freshness, let p = pcactn.asObject {
                if let why = PCA.freshnessAnchorError(p, fg, now) { fail("freshness", why) } else { set("freshness", "pass") }
            }
            // M5 attestation: with the gate on, the gate's verifier takes the slot and a not-enforced answer fails closed unless not required
            let gate = o.enforce.attestation
            try run("attestation", gate?.verifier ?? o.attestation)
            if let g = gate, g.required, checks.first(where: { $0.0 == "attestation" })?.1 == "not-enforced" {
                fail("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)")
            }
            try run("threshold", o.threshold)
            if let hook = o.revocation {
                switch try hook(pcactn, grant, now) {
                case .notEnforced: set("revocation", "not-enforced")
                case let .enforced(ok, reason):
                    if ok { set("revocation", "pass") } else { fail("revocation", reason ?? "rejected") }
                }
            } else {
                set("revocation", "not-enforced")
            }
            // a PCActn that CARRIES a zk proof asserts a compliance guarantee: an unverified one is never silently accepted
            if zkCarried {
                try run("zk_compliance", o.zk)
                if checks.first(where: { $0.0 == "zk_compliance" })?.1 == "not-enforced" {
                    fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof")
                }
            }
            if pcactn.get("bond_ref") != nil { set("bond", "unsupported") }
        } catch {
            reasons.append("malformed PCActn: \(errMessage(error))")
            set("malformed", "fail")
        }
        return GatewayVerdict(allow: reasons.isEmpty && !checks.contains { $0.1 == "fail" }, checks: checks, reason: reasons.first)
    }

    /// The verifier's own K1 input with the request's presented artifacts filling what it leaves unset (a configured, non-empty `discharges` and
    /// a configured `narrow` win).
    static func mergedK1(_ own: K1Input, _ presented: (discharges: [JSONValue]?, narrow: JSONValue?)) -> K1Input {
        var k = own
        if k.discharges.isEmpty, let d = presented.discharges { k.discharges = d }
        if k.narrow == nil, let n = presented.narrow { k.narrow = n }
        return k
    }

    /// The provenance log's session key: the grant, the leaf holder and the bundle's first receipt session (`-` when none).
    static func provenanceLogKey(_ pcactn: JSONValue, session: String?) -> String {
        "\(JS.toString(pcactn.get("grant_ref")))\n\(JS.toString(pcactn.get("cap_chain")?.asArray?.last?.get("holder")))\n\(session ?? "-")"
    }

    // MARK: authorize

    private static func extract(_ headers: HeaderMap) -> (pcactn: JSONValue?, code: DecisionCode, reason: String) {
        guard let raw = getHeader(headers, PCA_HEADER), !raw.isEmpty else { return (nil, .noProof, "no \(PCA_HEADER) header") }
        let prefix = "undecodable \(PCA_HEADER) header: "
        guard let bytes = Base64URLStrict.decode(raw) else { return (nil, .invalidProof, prefix + "PCA-Action header is not strict unpadded base64url") }
        let text = String(decoding: bytes, as: UTF8.self)
        guard Array(text.utf8) == bytes else { return (nil, .invalidProof, prefix + "PCA-Action header does not decode to UTF-8 text") }
        if text.utf8.count > PCA.MAX_ARTIFACT_BYTES { return (nil, .invalidProof, prefix + PCA.ARTIFACT_SIZE_REASON) }
        guard let v = try? StrictJSON.parse(text) else { return (nil, .invalidProof, prefix + "not strict JSON") }
        guard v.isObject else { return (nil, .invalidProof, prefix + "decodePCActn: not an object") }
        return (v, .allow, "")
    }

    private static func signedParams(_ req: GatewayRequest, _ policy: FullPolicy, _ o: GatewayOptions) -> (params: JObject?, error: String?) {
        var params: JSONValue?
        switch policy.params {
        case .body:
            guard let b = req.body else { return (nil, "full policy mode reads the params from the body, and the request carries none") }
            do { params = try StrictJSON.parse(b) } catch { return (nil, "the body is not strict JSON: \(error)") }
        case let .fn(f):
            do { params = try f(req).map { .object($0) } } catch { return (nil, "params failed: \(errMessage(error))") }
        }
        guard let obj = params?.asObject else { return (nil, "the request params are not a JSON object") }
        if o.bindRequestOff { return (obj, nil) }
        if obj[JKey("binding")] != nil { return (nil, "the request params carry a 'binding' member (reserved for the request binding)") }
        let b = o.bindRequest
        if (b.authority && (req.authority ?? "").isEmpty) || (b.body == .on && (req.bodySha256 ?? "").isEmpty) { return (nil, "request lacks an attribute the proof must bind (authority / body hash)") }
        do {
            var out = obj
            out[JKey("binding")] = .object(try requestBinding(req, BindRequestOptions(authority: b.authority, body: b.body == .on ? .on : .off)))
            return (out, nil)
        } catch { return (nil, "the request cannot be bound: \(errMessage(error))") }
    }

    /// Decide one request. Throws only when the grant source or the replay guard's own failure handling does (the reference rejects too).
    public static func authorize(_ req: GatewayRequest, _ o: GatewayOptions) throws -> Decision {
        let realm = o.realm ?? o.audience

        if o.pathPolicy == "strict", let bad = ambiguousPathReason(req.path) { return deny(.invalidPath, 400, bad, realm) }

        let rule = o.routes.first { matchMethod($0, req.method) && matchPath($0.path, req.path) }
        if rule == nil {
            if o.unmatchedRoute == "allow" { return allowDecision("route \(req.method) \(req.path) is unmapped (unmatchedRoute=allow)") }
            if o.unmatchedRoute == "deny" { return deny(.unmappedRoute, 403, "no capability mapping for \(req.method) \(req.path) (deny-by-default)", realm) }
        }
        let required = rule?.capability

        let ex = extract(req.headers)
        guard let pcactn = ex.pcactn else { return deny(ex.code, 401, ex.reason, realm) }

        let ref = JS.toString(pcactn.get("grant_ref"))
        guard let grant = try o.resolveGrant(ref, pcactn) else { return deny(.unknownGrant, 401, "unknown grant_ref \(ref)", realm, pcactn: pcactn) }

        let missingCfg = missingPolicy(o)
        if !missingCfg.isEmpty { return deny(.proofRejected, 403, "\(missingText(o, missingCfg)) (fail closed)", realm, pcactn: pcactn) }

        let now = o.now?() ?? Int64((Date().timeIntervalSince1970 * 1000).rounded(.down))
        let verdict = verifyProof(pcactn, grant, now, o)
        if !verdict.allow {
            let audienceFailed = verdict.status("audience") == "fail"
            return deny(audienceFailed ? .wrongAudience : .verifyFailed, audienceFailed ? 403 : 401, verdict.reason ?? "PCActn verification failed", realm, verdict: verdict, pcactn: pcactn)
        }

        let action = pcactn.get("action")
        let actionVerb = action?.get("verb")?.asString ?? ""
        if let r = required {
            if !IV.same(actionVerb, r.verb) {
                return deny(.insufficientCapability, 403, "route requires capability '\(r.verb)' but the proof authorizes '\(actionVerb)'", realm, verdict: verdict, pcactn: pcactn, matched: r)
            }
            if let res = r.resource, !IV.same(action?.get("resource")?.asString, res) {
                return deny(.insufficientCapability, 403, "route is bound to resource '\(res)' but the proof targets '\(JS.toString(action?.get("resource")))'", realm, verdict: verdict, pcactn: pcactn, matched: r)
            }
        }

        var full: FullPolicy?
        if case let .full(f)? = o.policy { full = f }
        let signedDigest = action?.get("params_digest")?.asString
        var fullParams: JObject?
        if let f = full {
            let sp = signedParams(req, f, o)
            if let e = sp.error { return deny(.requestMismatch, 403, e, realm, verdict: verdict, pcactn: pcactn) }
            guard let d = IV.strictHash(.object(sp.params!)), IV.same(signedDigest, d) else {
                return deny(.requestMismatch, 403, "the proof is not bound to this request (params/method/path/query/authority)", realm, verdict: verdict, pcactn: pcactn)
            }
            fullParams = sp.params
        } else if !o.bindRequestOff {
            let b = o.bindRequest
            if (b.authority && (req.authority ?? "").isEmpty) || (b.body == .on && (req.bodySha256 ?? "").isEmpty) {
                return deny(.requestMismatch, 403, "request lacks an attribute the proof must bind (authority / body hash)", realm, verdict: verdict, pcactn: pcactn)
            }
            let bound: String
            do {
                guard let d = IV.strictHash(.object(try requestBinding(req, b))) else { throw GatewayError("binding is not canonicalizable") }
                bound = d
            } catch {
                return deny(.requestMismatch, 403, "the request cannot be bound: \(errMessage(error))", realm, verdict: verdict, pcactn: pcactn)
            }
            if !IV.same(signedDigest, bound) {
                return deny(.requestMismatch, 403, "the proof is not bound to this request (method/path/query/authority/body)", realm, verdict: verdict, pcactn: pcactn)
            }
        }

        for c in o.requireChecks ?? (full == nil ? ["revocation"] : []) where verdict.status(c) != "pass" {
            return deny(.proofRejected, 403, "required check '\(c)' is \(verdict.status(c) ?? "absent")", realm, verdict: verdict, pcactn: pcactn)
        }

        if let check = o.checkProof {
            do {
                let r = try check(ProofContext(pcactn: pcactn, grant: grant, verdict: verdict, request: req, required: required))
                if !r.allow { return deny(.proofRejected, 403, (r.reason?.isEmpty == false ? r.reason! : "rejected by checkProof"), realm, verdict: verdict, pcactn: pcactn) }
            } catch {
                return deny(.proofRejected, 403, "checkProof failed: \(errMessage(error))", realm, verdict: verdict, pcactn: pcactn)
            }
        }

        var policyVerdict: JSONValue?
        if let f = full, let params = fullParams {
            var input = f.input
            input.audience = o.audience
            input.resolveGrant = { _ in grant }
            input.now = now
            // the threshold hook is the gateway's own: it also decides inside the full verifier (revocation is `input.isRevoked`)
            if input.thresholdHook == nil, let th = o.threshold {
                input.thresholdHook = { p in
                    let r = try th(p, grant, now)
                    return PCA.ThresholdOutcome(enforced: r.enforced, ok: r.ok, t: r.t, reason: r.reason)
                }
            }
            // K1: the verifier's own input, the request's presented discharges / narrow block filling what it leaves unset
            if let src = f.k1 {
                do {
                    var k: K1Input
                    switch src {
                    case let .fixed(own): k = own
                    case let .fn(make): k = try make(req, pcactn)
                    }
                    input.k1 = mergedK1(k, presentedArtifacts(req, f.params))
                } catch {
                    return deny(.proofRejected, 403, "k1 input failed: \(errMessage(error)) (fail closed)", realm, verdict: verdict, pcactn: pcactn)
                }
            }
            let bundle = presentedProvenance(req, f.params)
            var bundleSession: String?
            if case let .value(b) = bundle {
                if b.isNull { return deny(.proofRejected, 403, "the provenance bundle is unreadable (fail closed)", realm, verdict: verdict, pcactn: pcactn) }
                input.provenance = b
                bundleSession = b.get("receipts")?.asArray?.first?.get("session")?.asString
            }
            // provenance by default: what this gateway let through to the agent's session is joined into the decision (raise only)
            let log: ProvenanceLog?
            switch f.provenanceLog {
            case .off: log = nil
            case .default: log = f.defaultLog
            case let .custom(l): log = l
            }
            let logKey = provenanceLogKey(pcactn, session: bundleSession)
            if let lg = log {
                let seen: [JSONValue]
                do { seen = try lg.seen(logKey).map { $0.json } } catch {
                    return deny(.proofRejected, 403, "provenance log failed: \(errMessage(error)) (fail closed)", realm, verdict: verdict, pcactn: pcactn)
                }
                let own = input.argProvenance.observed
                input.argProvenance.observed = { p, op, sess in (own?(p, op, sess) ?? []) + seen }
            }
            input.operation = PCA.Operation(verb: required?.verb ?? actionVerb, resource: required?.resource ?? (action?.get("resource")?.asString ?? ""), params: .object(params))
            let res = PCA.authorize(pcactn: pcactn, input)
            var cs = JObject()
            for (k, v) in res.checks { cs[JKey(k)] = .string(v.rawValue) }
            var pv: JObject = ["allow": .bool(res.allow), "checks": .object(cs)]
            if let r = res.reason { pv["reason"] = .string(r) }
            // what this call returns flows back into the agent's context: the session has now seen untrusted content
            if res.allow, let lg = log {
                do { try lg.add(logKey, ProvObservation(origin: .string("tool"), source: action?.get("verb"))) } catch {
                    return deny(.proofRejected, 403, "provenance log failed: \(errMessage(error)) (fail closed)", realm, verdict: verdict, pcactn: pcactn)
                }
            }
            if !res.allow {
                let code: DecisionCode = res.checks["replay"] == .fail ? .replayedProof : res.checks["operation"] == .fail ? .insufficientCapability : res.status == 401 ? .verifyFailed : .proofRejected
                return deny(code, res.status, res.reason ?? "rejected", realm, verdict: verdict, pcactn: pcactn, policyVerdict: .object(pv))
            }
            policyVerdict = .object(pv)
        }

        if let guardian = o.replayGuard {
            let first: Bool
            do {
                first = try guardian.claim("\(ref):\(pcactn.get("sig")?.asString ?? "")", expiresAtMs: IV.num(pcactn.get("exp")) ?? 0, nowMs: Double(now))
            } catch {
                return deny(.replayGuardUnavailable, 503, "replay guard unavailable: \(errMessage(error))", realm, verdict: verdict, pcactn: pcactn)
            }
            if !first { return deny(.replayedProof, 403, "this proof has already been used", realm, verdict: verdict, pcactn: pcactn) }
        }

        return allowDecision(policyVerdict != nil ? "proof-carrying action authorized (full policy)" : "proof-carrying action verified", verdict: verdict, pcactn: pcactn, matched: required,
                             policyVerdict: policyVerdict)
    }

    /// A reusable authorizer over one configuration. Throws `pca-gateway: ... is missing ...` when a required component is absent (fail closed).
    public static func createGateway(_ o: GatewayOptions) throws -> (GatewayRequest) throws -> Decision {
        let missing = missingPolicy(o)
        if !missing.isEmpty { throw GatewayError("pca-gateway: \(missingText(o, missing))") }
        var frozen = o
        // each gateway keeps its own default provenance log
        if case var .full(f)? = frozen.policy, case .default = f.provenanceLog {
            f.provenanceLog = .custom(MemoryProvenanceLog())
            frozen.policy = .full(f)
        }
        let gateway = frozen
        return { try authorize($0, gateway) }
    }
}
