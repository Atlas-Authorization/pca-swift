import Foundation

/// The rest of `@atlasauth/pca-a2a` (index.ts, a2a-auth.ts, a2a-extended-card.ts): proof-carrying Tasks (attach, extract, verify, the server guard),
/// the signed Agent Card entry points, the AP2 payment-mandate envelope and its verification, AUTH_REQUIRED resumption, per-hop delegation, push tokens
/// and the extended Agent Card. The verifier behind `verifyA2ATask` is pluggable (`PcaVerifier`); the default (`A2a.CORE_VERIFIER`) is the core PCActn
/// verifier plus plan authorization, the params digest, revocation and post-quantum pins, and every required check must pass.
extension A2a {
    public static let A2A_AP2_CONTEXT = ["https://www.w3.org/2018/credentials/v1", "https://ap2-protocol.org/context/v0.2"]
    /// The checks `verifyA2ATask` requires to pass unless `requireChecks` says otherwise.
    public static let DEFAULT_REQUIRED_CHECKS = ["counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]

    // ---- JavaScript-ish helpers ----

    /// `{...v}`: an object's own members, an array's or a string's indices; nothing for any other value.
    static func spread(_ v: JSONValue?) -> JObject {
        switch v {
        case let .object(o)?: return o
        case let .array(a)?: var o: JObject = [:]; for (i, x) in a.enumerated() { o[JKey(String(i))] = x }; return o
        case let .string(s)?: var o: JObject = [:]; for (i, c) in s.utf16.enumerated() { o[JKey(String(i))] = .string(String(utf16CodeUnits: [c], count: 1)) }; return o
        default: return [:]
        }
    }

    /// `[...x]`: an array copy or a string by code point; anything else is not iterable.
    static func spreadList(_ v: JSONValue?) throws -> [JSONValue] {
        switch v {
        case let .array(a)?: return a
        case let .string(s)?: return s.unicodeScalars.map { .string(String($0)) }
        default: throw JSError("TypeError: not iterable")
        }
    }

    static func isRecord(_ v: JSONValue?) -> Bool { v?.asObject != nil }

    /// `typeof v === 'object' && v !== null` (an array counts).
    static func isObjectLike(_ v: JSONValue?) -> Bool { v?.asObject != nil || v?.asArray != nil }

    static func safeNat(_ v: JSONValue?) -> Bool { (v?.safeInt).map { $0 >= 0 } ?? false }

    static func isNegZero(_ v: JSONValue?) -> Bool {
        if case let .double(d)? = v { return d == 0 && d.sign == .minus }
        return false
    }

    // ---- 1. proof-carrying Tasks ----

    private static func withPca(_ metadata: JSONValue?, _ pcActn: JSONValue) -> JSONValue {
        var m = (metadata == nil || metadata == .null) ? JObject() : spread(metadata)
        m[JKey(PCA_A2A_EXTENSION_URI)] = pcActn
        return .object(m)
    }

    private static func readPca(_ metadata: JSONValue?) -> JSONValue? {
        guard let v = metadata?.asObject?[JKey(PCA_A2A_EXTENSION_URI)], v.asObject != nil else { return nil }
        return v
    }

    /// Attach a PCActn to a Task (a copy; the input is not mutated).
    public static func attachPcaToA2ATask(_ task: JSONValue?, _ pcActn: JSONValue) throws -> JSONValue {
        // `task.metadata` of null / undefined is a TypeError in the reference
        if task == nil || task == .null { throw JSError("Cannot read properties of \(task == nil ? "undefined" : "null") (reading 'metadata')") }
        var out = spread(task)
        out["metadata"] = withPca(out["metadata"], pcActn)
        return .object(out)
    }

    /// Attach a PCActn to a single Message (a copy).
    public static func attachPcaToA2AMessage(_ message: JSONValue?, _ pcActn: JSONValue) throws -> JSONValue { try attachPcaToA2ATask(message, pcActn) }

    /// The PCActn carried on a Task: task metadata, then the current status message, then the most recent history message. nil when none.
    public static func extractPca(_ task: JSONValue?) -> JSONValue? {
        guard let t = task, !t.isNull else { return nil }
        if let on = readPca(t.get("metadata")) { return on }
        if let st = t.get("status"), isObjectLike(st), let on = readPca(st.get("message")?.get("metadata")) { return on }
        if let h = t.get("history")?.asArray {
            for m in h.reversed() { if let on = readPca(m.get("metadata")) { return on } }
        }
        return nil
    }

    /// The PCActn carried on a single Message (fail-closed).
    public static func extractPcaFromMessage(_ message: JSONValue?) -> JSONValue? {
        guard let m = message, !m.isNull else { return nil }
        return readPca(m.get("metadata"))
    }

    // ---- verification ----

    /// What a `PcaVerifier` is asked.
    public struct PcaRequest {
        public let grant: JObject
        public let aud: String?
        public let now: Int64
        public let context: JObject
        public let allowedSuites: [String]?
        public let pqPins: [String: String]?
        public let require: [String]
        public let isRevoked: ((JSONValue, JSONValue) throws -> Bool)?
        /// True when `grant` is the chain's own root (no stored grant): a post-quantum root is then trusted only under a pin.
        public let grantFromArtifact: Bool
    }

    /// A verifier's verdict: `checks` name to "pass" | "fail" (a check it does not evaluate is absent).
    public struct PcaOutcome {
        public let allow: Bool
        public let checks: [String: String]
        public let reasons: [String]
        public init(allow: Bool, checks: [String: String] = [:], reasons: [String] = []) { self.allow = allow; self.checks = checks; self.reasons = reasons }
        var json: JObject {
            ["allow": .bool(allow), "checks": .object(Dictionary(uniqueKeysWithValues: checks.map { (JKey($0.key), JSONValue.string($0.value)) })), "reasons": .array(reasons.map { .string($0) })]
        }
    }

    /// The full PCActn verifier plugged into the A2A surfaces. A throw is a refusal.
    public typealias PcaVerifier = (_ pcActn: JSONValue, _ request: PcaRequest) throws -> PcaOutcome

    /// The default verifier: the core verifier plus plan authorization, params digest, revocation and PQ pins; every required check must pass.
    public static let CORE_VERIFIER: PcaVerifier = { p, r in
        var checks: [String: String] = [:]
        var reasons: [String] = []
        let root = p.get("plan")?.get("root")?.asString
        var roots: [String]?
        switch r.context["planAuthorized"] {
        case .bool(true)?: roots = root.map { [$0] } ?? []
        case .bool(false)?: roots = []
        default: roots = nil
        }
        let audience: PCA.Audience = r.aud.map { .id($0) } ?? .unset
        let v = PCA.verify(pcactn: p, grant: .object(r.grant), now: r.now, audience: audience, allowedSuites: r.allowedSuites, authorizedPlanRoots: roots,
                           pqPins: r.pqPins, grantFromArtifact: r.grantFromArtifact)
        var allow = v.allow
        for (k, ok) in v.checks { checks[k] = ok ? "pass" : "fail" }
        reasons.append(contentsOf: v.reasons)
        if let pins = r.pqPins {
            let issuer = r.grant["issuer"]?.asString
            let pin = issuer.flatMap { pins[$0] }
            let classical = (r.grant["alg"] == nil || r.grant["alg"] == .null) || r.grant["alg"] == .string("ed25519")
            let ok = pin == nil ? classical : (!classical && pin == r.grant["pq_pk"]?.asString)
            checks["pq_pin"] = ok ? "pass" : "fail"
            if !ok { allow = false; if !reasons.contains(where: { $0.hasPrefix("pq_pin:") }) { reasons.append("pq_pin: the grant's post-quantum key is not the pinned one for its issuer") } }
        }
        if let params = r.context["params"], params.asObject != nil {
            let want = p.get("action")?.get("params_digest")
            let ok = want == .string(Merkle.paramsDigest(params))
            checks["params_digest"] = ok ? "pass" : "fail"
            if !ok { allow = false; reasons.append("params_digest: the params do not open action.params_digest") }
        }
        if let rev = r.isRevoked {
            let ok = (try? !rev(p, .object(r.grant))) ?? false
            checks["revocation"] = ok ? "pass" : "fail"
            if !ok { allow = false; reasons.append("revocation: the proof or its chain is revoked (or the revocation check failed)") }
        }
        for name in r.require where checks[name] != "pass" {
            allow = false
            reasons.append("\(name): required check did not pass (\(checks[name] != nil ? "failed" : "not enforced"))")
        }
        return PcaOutcome(allow: allow, checks: checks, reasons: reasons)
    }

    /// Options shared by every PCActn verification surface. One of `grant` / `expectedRootIssuer` is required.
    public struct VerifyOptions {
        /// This resource server / Atlas instance id; compared against the PCActn's signed aud.
        public var aud: String?
        /// Verification clock (epoch ms); nil: the wall clock.
        public var now: Int64?
        /// The grant from YOUR store: the chain root must be byte-identical to it.
        public var grant: JObject?
        /// The principal the chain must be rooted at (b64u).
        public var expectedRootIssuer: String?
        /// Verifier-side issuer to pq_pk pins.
        public var pqPins: [String: String]?
        public var allowedSuites: [String]?
        /// The resource server's view of the action: `params`, `plan`, `planAuthorized`, ...; per PCActn.
        public var context: ((JSONValue) throws -> JObject?)?
        /// Checks that must PASS; nil: `DEFAULT_REQUIRED_CHECKS`.
        public var requireChecks: [String]?
        /// Revocation predicate `(pcActn, grant) -> revoked?`; absent: the revocation check is not enforced and a default-required run refuses.
        public var isRevoked: ((JSONValue, JSONValue) throws -> Bool)?
        /// The verifier; nil: `CORE_VERIFIER`.
        public var verifier: PcaVerifier?
        /// The human-present signer set of `verifyA2APaymentMandate`.
        public var humanSignerSet: [JSONValue]?
        /// `pcaA2AMiddleware`: false lets a Task with no proof through (a present proof must still verify). Default true: required.
        public var requireProof = true
        public init(aud: String? = nil, now: Int64? = nil, grant: JObject? = nil, expectedRootIssuer: String? = nil) {
            self.aud = aud; self.now = now; self.grant = grant; self.expectedRootIssuer = expectedRootIssuer
        }
    }

    /// Thrown when an A2A verifier is configured without any authority (`grant` or `expectedRootIssuer`).
    public struct A2AAuthorityError: Error, CustomStringConvertible {
        public let code = "authority_required"
        public var description: String { "pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority" }
    }

    private static func assertAuthority(_ o: VerifyOptions) throws {
        if o.grant == nil && (o.expectedRootIssuer ?? "").isEmpty { throw A2AAuthorityError() }
    }

    /// The result of verifying a proof-carrying A2A artifact.
    public struct Verification {
        public let ok: Bool
        public let reason: String?
        /// The verifier's verdict (present once a PCActn was found and evaluated); `reason` joins its reasons on a deny.
        public let result: JObject?
        public let pcActn: JSONValue?
        /// The JSON form: `ok`, then `reason`, `result`, `pcActn` when present.
        public var json: JSONValue {
            var m: JObject = ["ok": .bool(ok)]
            if let r = reason { m["reason"] = .string(r) }
            if let r = result { m["result"] = .object(r) }
            if let p = pcActn { m["pcActn"] = p }
            return .object(m)
        }
    }

    private static func bad(_ reason: String, _ pcActn: JSONValue? = nil) -> Verification { Verification(ok: false, reason: reason, result: nil, pcActn: pcActn) }

    private static func verifyPcActn(_ pcActn: JSONValue?, _ opts: VerifyOptions) throws -> Verification {
        try assertAuthority(opts)
        guard let pc = pcActn, isObjectLike(pc) else { return bad("PCActn is not an object") }
        let root = pc.get("cap_chain")?.asArray?.first
        guard let rt = root, JS.truthy(rt) else { return bad("PCActn carries no capability chain", pc) }
        if let want = opts.expectedRootIssuer, rt.get("issuer") != .string(want) { return bad("chain root issuer does not match the expected principal", pc) }
        // Without a stored grant, the root is admitted only under the pinned principal; a non-Ed25519 root then needs a PQ pin.
        let grant: JObject = opts.grant ?? rt.asObject ?? [:]
        let pqPins: [String: String]? = opts.grant == nil ? (opts.pqPins ?? [:]) : opts.pqPins
        let context = (try opts.context?(pc)) ?? [:]
        let req = PcaRequest(grant: grant, aud: opts.aud, now: opts.now ?? Int64(Date().timeIntervalSince1970 * 1000), context: context, allowedSuites: opts.allowedSuites,
                             pqPins: pqPins, require: opts.requireChecks ?? DEFAULT_REQUIRED_CHECKS, isRevoked: opts.isRevoked, grantFromArtifact: opts.grant == nil)
        let out: PcaOutcome
        do { out = try (opts.verifier ?? CORE_VERIFIER)(pc, req) } catch { out = PcaOutcome(allow: false, checks: [:], reasons: ["verifier error (fail closed): \(type(of: error))"]) }
        let reason: String? = out.allow ? nil : (out.reasons.isEmpty ? "PCActn verification failed" : out.reasons.joined(separator: "; "))
        var result = out.json
        if let r = reason { result["reason"] = .string(r) }
        return Verification(ok: out.allow, reason: reason, result: result, pcActn: pc)
    }

    /// Verify the proof-carrying action on an A2A Task; fail-closed (no PCActn, or one that does not verify, is rejected).
    public static func verifyA2ATask(_ task: JSONValue?, _ opts: VerifyOptions) throws -> Verification {
        try assertAuthority(opts)
        guard let pc = extractPca(task) else { return bad("no proof-carrying action attached to this task") }
        return try verifyPcActn(pc, opts)
    }

    public typealias PcaA2AGuard = (JSONValue?) throws -> Verification

    /// A guard that verifies the proof on each incoming Task. A present but invalid proof is always rejected; `opts.requireProof` false lets a Task with NO proof through.
    public static func pcaA2AMiddleware(_ opts: VerifyOptions) throws -> PcaA2AGuard {
        try assertAuthority(opts)
        let require = opts.requireProof
        return { task in
            guard let pc = extractPca(task) else {
                return require ? bad("proof-carrying action required but none attached to task") : Verification(ok: true, reason: nil, result: nil, pcActn: nil)
            }
            return try verifyPcActn(pc, opts)
        }
    }

    // ---- 2. signed Agent Cards ----

    /// RFC 8785 canonical bytes of a JSON value.
    public static func jcsBytes(_ v: JSONValue?) throws -> [UInt8] { try PCAAgentCard.jcsBytes(v) }

    /// The A2A 1.0 `AgentCard` problems.
    public static func validateAgentCard1(_ card: JSONValue?) -> [String] { PCAAgentCard.validateAgentCard1(card) }

    /// Issue a signed Agent Card: embed the passport reference, sign the canonicalized card (minus `signatures`) with the JWK, append the `{protected, signature}`.
    /// `opts`: alg?, passport?, kid?, profile? ('pca-detached' | 'a2a-1.0'), schema? ('a2a-1.0').
    public static func issueSignedAgentCard(_ card: JSONValue?, _ signingKey: JSONValue?, _ opts: JObject = [:], edSign: PCAAgentCard.EdSign? = nil) throws -> JSONValue {
        try PCAAgentCard.issueSignedAgentCard(card, signingKey, opts, edSign: edSign)
    }

    /// Validate an Agent Card against its signatures. Fail-closed: no signatures, an unresolvable key or ANY signature that does not verify is a refusal.
    /// `opts`: jwks? | key?, alg?, schema? ('a2a-1.0'). A signature entry that is not `{protected: string, signature: string}` is "malformed".
    public static func verifyAgentCard(_ card: JSONValue?, _ opts: JObject) throws -> JSONValue { try PCAAgentCard.verifyCard(card, opts, agentCardPkg: false) }

    // ---- 3. AP2 payment profile ----

    private static func leafOfChain(_ chain: JSONValue?) -> JSONValue? { chain?.asArray?.last }

    private static func leafHolderOf(_ chain: JSONValue?) -> JSONValue? { leafOfChain(chain)?.get("holder") }

    /// True only when the PCActn carries threshold shares that verify at t=3 under `signerSet` (agent + guardian + principal, one distinct key per role).
    /// EVERY explicit share must verify (a stray invalid share refuses), and the agent may be the leaf signature only for an Ed25519 leaf whose signer-set
    /// entry registers no post-quantum key. Never throws.
    static func verifiedHumanPresent(_ p: JObject, _ signerSetV: JSONValue?) -> Bool {
        guard let signerSet = signerSetV?.asArray, Threshold.validatedRegistry(signerSet) != nil, let msg = try? PCA.thresholdMessage(p) else { return false }
        var good = Set<String>()
        for s in p["threshold"]?.get("shares")?.asArray ?? [] {
            guard let so = s.asObject, let role = so["role"]?.asString else { return false }
            let entry: JSONValue = .object(["role": .string(role), "t": .int(3), "signer_set": .array(signerSet), "threshold_message": .string(Base64URLStrict.encode(msg)), "share": s])
            if !Threshold.verifyShare(entry) { return false }
            good.insert(role)
        }
        if !good.contains("agent") && agentLeafBaseline(p, signerSet, msg) { good.insert("agent") }
        return good.contains("agent") && good.contains("guardian") && good.contains("principal")
    }

    private static func agentLeafBaseline(_ p: JObject, _ signerSet: [JSONValue], _ msg: [UInt8]) -> Bool {
        guard let holder = leafHolderOf(p["cap_chain"])?.asString, let sig = p["sig"]?.asString, p["alg"] == nil || p["alg"] == .null || p["alg"] == .string("ed25519") else { return false }
        var registered = false
        for e in signerSet {
            guard let m = e.asObject, m["role"] == .string("agent"), m["publicKey"] == .string(holder) else { continue }
            if m["pq_pk"] != nil { return false }
            registered = true
        }
        return registered && Ed25519Strict.verifyB64u(holder, msg, sig)
    }

    /// Map a PCActn to an AP2 Payment Mandate. `opts`: `amount {currency, value}` (value a non-negative integer in minor units), `paymentMethod`, `merchant`,
    /// `humanPresent`, `humanSignerSet`, `issuerPublic`, `now`. Throws on a bad amount or no issuer.
    public static func a2aPaymentMandateFromPca(_ pcActn: JSONValue, _ opts: JObject) throws -> JSONValue {
        let leaf = leafHolderOf(pcActn.get("cap_chain"))
        let issuerO: JSONValue
        if let i = JS.present(opts["issuerPublic"]) { issuerO = i } else if let l = leaf { issuerO = l } else {
            throw JSError("a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain")
        }
        guard let amount = opts["amount"], !amount.isNull else { throw JSError("TypeError: cannot read properties of undefined (reading 'value')") }
        let value = amount.get("value")
        if !safeNat(value) { throw JSError("a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units") }
        let humanPresent: JSONValue
        if let h = JS.present(opts["humanPresent"]) { humanPresent = h }
        else { humanPresent = .bool(JS.truthy(opts["humanSignerSet"]) && pcActn.asObject.map { verifiedHumanPresent($0, opts["humanSignerSet"]) } == true) }
        let nowMs: Double
        if let n = JS.present(opts["now"]) { guard let d = number(n) else { throw JSError("Invalid time value") }; nowMs = d } else { nowMs = (Date().timeIntervalSince1970 * 1000).rounded(.down) }
        var xpca: JObject = ["pcactn_digest": .string(Canonical.hashCanonical(pcActn))]
        guard let action = pcActn.get("action"), !action.isNull else { throw JSError("TypeError: cannot read properties of undefined (reading 'verb')") }
        for (k, v) in [("aud", pcActn.get("aud")), ("verb", action.get("verb")), ("resource", action.get("resource")), ("params_digest", action.get("params_digest")), ("grant_ref", pcActn.get("grant_ref"))] {
            if let v = v { xpca[JKey(k)] = v }
        }
        xpca["leaf_holder"] = JS.present(leaf) ?? issuerO
        var contents: JObject = ["amount": .object(spread(amount)), "payment_method": .object(spread(opts["paymentMethod"])), "human_present": humanPresent, "x_pca": .object(xpca)]
        if let m = opts["merchant"] { contents["merchant"] = m }
        return .object(["@context": .array(A2A_AP2_CONTEXT.map { .string($0) }), "type": .array([.string("VerifiableCredential"), .string("PaymentMandate")]),
                        "issuer": issuerO, "issuanceDate": .string(try PCAIntentRender.isoString(nowMs)), "credentialSubject": .object(contents)])
    }

    /// Read the PCA binding back out of an AP2 Payment Mandate (the round trip of `x_pca`).
    public static func pcaBindingFromA2APaymentMandate(_ mandate: JSONValue?) throws -> JSONValue {
        guard let cs = mandate?.get("credentialSubject"), !cs.isNull else { throw JSError("TypeError: cannot read properties of undefined (reading 'x_pca')") }
        return .object(spread(cs.get("x_pca")))
    }

    private static func mandateBindingError(_ m: JSONValue?, _ pcActn: JSONValue, _ params: JObject, _ opts: VerifyOptions) -> String? {
        guard let x = m?.get("x_pca")?.asObject else { return "payment mandate carries no x_pca binding" }
        let action = pcActn.get("action")
        let leaf = leafOfChain(pcActn.get("cap_chain"))
        let leafHolder: JSONValue? = leaf?.asObject != nil ? leaf?.get("holder") : nil
        let bound: [(String, JSONValue?)] = [("aud", pcActn.get("aud")), ("verb", action?.get("verb")), ("resource", action?.get("resource")),
                                             ("params_digest", action?.get("params_digest")), ("grant_ref", pcActn.get("grant_ref")), ("leaf_holder", leafHolder)]
        for (k, want) in bound {
            guard let have = x[JKey(k)], have.asString != nil, have == want else { return "payment mandate x_pca.\(k) is not the PCActn's" }
        }
        // amount + currency: the authorized params MUST carry both, and the mandate must state exactly them
        guard let amt = m?.get("amount")?.asObject, safeNat(amt["value"]), !isNegZero(amt["value"]), amt["currency"]?.asString != nil else {
            return "payment mandate amount is malformed (value must be a non-negative integer in minor units)"
        }
        guard let pa = params["amount"], safeNat(pa), !isNegZero(pa) else { return "the PCActn params carry no integer minor-unit amount to bind the mandate amount to" }
        guard let pc = params["currency"]?.asString else { return "the PCActn params carry no currency to bind the mandate currency to" }
        if IV.num(amt["value"]) != IV.num(pa) || amt["currency"]?.asString != pc { return "payment mandate amount / currency differ from the authorized PCActn params" }
        // payee and instrument: bound whenever either side names one (a mandate cannot widen or drop what the action fixed)
        if m?.get("merchant") != params["merchant"] { return "payment mandate merchant differs from the authorized PCActn params" }
        if let ppm = params["payment_method"] {
            guard let mpm = m?.get("payment_method"), Canonical.hashCanonical(mpm) == Canonical.hashCanonical(ppm) else { return "payment mandate payment_method differs from the authorized PCActn params" }
        }
        // human_present is an unsigned claim: true only with a verified t=3 principal co-signature on the PCActn
        guard case let .bool(hp)? = m?.get("human_present") else { return "payment mandate human_present must be a boolean" }
        if hp && !(opts.humanSignerSet != nil && pcActn.asObject.map { verifiedHumanPresent($0, .array(opts.humanSignerSet ?? [])) } == true) {
            return "payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)"
        }
        return nil
    }

    /// Verify an AP2 Payment Mandate against the PCActn it references (the mandate is unsigned: the PCActn must authorize every field a payer acts on).
    /// `opts.context` must yield the action's plaintext `params`; the `params_digest` check is required on this path.
    public static func verifyA2APaymentMandate(_ mandate: JSONValue?, _ pcActn: JSONValue?, _ opts: VerifyOptions) throws -> Verification {
        try assertAuthority(opts)
        // A malformed mandate (no credentialSubject / x_pca) or a PCActn with no strict canonical form is a refusal, not an exception.
        guard let cs = mandate?.get("credentialSubject"), !cs.isNull, let xp = cs.get("x_pca"), !xp.isNull, let pc = pcActn else { // a null PCActn has a canonical form: it is "not bound", not malformed
            return bad("malformed payment mandate or PCActn: TypeError")
        }
        let bound = xp.get("pcactn_digest")
        if bound != .string(Canonical.hashCanonical(pc)) { return bad("payment mandate is not bound to this PCActn (pcactn_digest mismatch)", pc) }
        guard isObjectLike(pc) else { return bad("PCActn is not an object") }
        let context = try opts.context?(pc) ?? [:]
        guard let params = context["params"]?.asObject else { return bad("context.params (the PCActn params plaintext) is required to bind the payment mandate", pc) }
        if let why = mandateBindingError(mandate?.get("credentialSubject"), pc, params, opts) { return bad(why, pc) }
        var require = opts.requireChecks ?? DEFAULT_REQUIRED_CHECKS
        if !require.contains("params_digest") { require.append("params_digest") }
        var o = opts
        o.context = { _ in context }
        o.requireChecks = require
        return try verifyPcActn(pc, o)
    }

    // ---- AUTH_REQUIRED resumption, delegation, push ----

    /// The pure gate of `resumeAuthRequired`, in the order the checks run. `proofAction`: nil for none; a JSON null action throws (the reference dereferences it).
    /// Returns the first refusal code, or nil.
    public static func resumeGateAction(state: JSONValue?, needEncoded: JSONValue?, answerNeedDigest: JSONValue?, proofAction: JSONValue?) throws -> String? {
        if !isAuthRequired(state) { return "task_not_auth_required" }
        guard let ne = needEncoded, let need = decodeNeed(ne).need else { return "no_valid_need" }
        if answerNeedDigest != .string(needDigest(need)) { return "answer_not_bound_to_need" }
        guard let pa = proofAction else { return "no_proof" }
        if pa.isNull { throw JSError("TypeError: cannot read properties of null (reading 'verb')") }
        if pa.get("verb") != need.get("verb") || pa.get("resource") != need.get("resource") { return "action_mismatch" }
        return nil
    }

    /// Resume a Task parked in AUTH_REQUIRED: only when the Task is in AUTH_REQUIRED, its status carries a decodable need, the answer cites that need's digest,
    /// carries a PCActn for the need's exact verb and resource, and that PCActn passes the full verifier. `{ok: true, verification}` or `{ok: false, reason}`.
    public static func resumeAuthRequired(_ task: JSONValue?, _ answer: JSONValue?, _ opts: VerifyOptions) throws -> JSONValue {
        let status = task?.get("status")
        let statusMd = status?.get("message")?.get("metadata")?.asObject ?? [:]
        let md = answer?.get("metadata")?.asObject ?? [:]
        let p = extractPcaFromMessage(answer)
        let refusal = try resumeGateAction(state: status?.get("state"), needEncoded: statusMd[JKey(NEED_KEY)], answerNeedDigest: md[JKey(NEED_KEY)], proofAction: p?.get("action"))
        if let r = refusal { return .object(["ok": .bool(false), "reason": .string(r)]) }
        let t: JSONValue = .object(["id": task?.get("id") ?? .null, "status": .object(["state": .string("TASK_STATE_WORKING")]), "metadata": .object([JKey(PCA_A2A_EXTENSION_URI): p ?? .null])])
        let v = try verifyA2ATask(t, opts)
        return v.ok ? .object(["ok": .bool(true), "verification": v.json]) : .object(["ok": .bool(false), "reason": .string(v.reason ?? "proof_rejected")])
    }

    /// One hop of `verifyA2ADelegation`: the Task and the options (own audience and authority) it is verified under.
    public struct Hop {
        public var task: JSONValue?
        public var opts: VerifyOptions
        public init(task: JSONValue?, opts: VerifyOptions) { self.task = task; self.opts = opts }
    }

    /// Verify a chain of delegated Tasks, one per A2A hop. Every hop is verified on its own; each hop's capability chain must EXTEND the previous hop's.
    /// Stops at the first failure; empty input fails closed. Result: `{ok, failedHop?, reason?, chains}`.
    public static func verifyA2ADelegation(_ hops: [Hop]) throws -> JSONValue {
        var chains: [[JSONValue]] = []
        func json() -> JSONValue { .array(chains.map { .array($0) }) }
        func fail(_ hop: Int, _ reason: String) -> JSONValue { .object(["ok": .bool(false), "failedHop": .int(Int64(hop)), "reason": .string(reason), "chains": json()]) }
        if hops.isEmpty { return .object(["ok": .bool(false), "reason": .string("no_hops"), "chains": json()]) }
        for (i, h) in hops.enumerated() {
            let v = try verifyA2ATask(h.task, h.opts)
            if !v.ok { return fail(i, v.reason ?? "rejected") }
            guard let cc = extractPca(h.task)?.get("cap_chain")?.asArray else { return fail(i, "no_chain") }
            let ids = cc.map { $0.get("id") ?? .null }
            if i > 0, !(ids.count >= chains[i - 1].count && Array(ids.prefix(chains[i - 1].count)) == chains[i - 1]) { return fail(i, "chain_does_not_extend_previous_hop") }
            chains.append(ids)
        }
        return .object(["ok": .bool(true), "chains": json()])
    }

    /// The per-task push token (A2A 3.1.7): a hash of the task id, the digest of the authorizing chain and a secret salt of at least 16 characters (else throws).
    public static func pcaPushToken(_ taskId: String, _ chainIds: [String], salt: String) throws -> String {
        guard let t = pushToken(taskId: taskId, chainIds: chainIds, salt: salt) else { throw JSError("pcaPushToken: the salt must be a secret of at least 16 characters") }
        return t
    }

    /// Receiver-side check of a delivered push notification: the token must equal the one recomputed from the task, chain and salt, and the payload must be about
    /// that task. `{ok: true}` or `{ok: false, reason}` (no_token, token_mismatch, task_mismatch). A short salt with a presented token throws.
    public static func checkPushNotification(taskId: String, chainIds: [String], salt: String?, token: JSONValue?, payload: JSONValue?) throws -> JSONValue {
        func no(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        guard let t = token?.asString, !t.isEmpty else { return no("no_token") }
        guard let salt = salt else { throw JSError("pcaPushToken: the salt must be a secret of at least 16 characters") }
        let want = try pcaPushToken(taskId, chainIds, salt: salt)
        if !constantTimeEq(want, t) { return no("token_mismatch") }
        if let r = checkPush(taskId: taskId, chainIds: chainIds, salt: salt, token: token, payload: payload) { return no(r) }
        return .object(["ok": .bool(true)])
    }

    // ---- extended Agent Card ----

    /// The extended Agent Card from a residual policy (A2A 3.1.11, 13.3): lists the hidden skills a caller may attempt. `o`: `authenticated` (must be true),
    /// `hiddenSkills`, `envelopes` (`verb, status, policyDigest`); `verbOf` maps a skill to its PCA verb (nil: the skill's `pca-verb:<verb>` tag). A verb with no
    /// envelope, or a denied one, reveals nothing. The result is unsigned.
    public static func extendedAgentCard(_ publicCard: JSONValue?, _ o: JObject, verbOf: ((JSONValue) -> String?)? = nil) throws -> JSONValue {
        if o["authenticated"] != .bool(true) { throw JSError("extendedAgentCard: the caller must be authenticated (A2A 13.3)") }
        guard let envelopes = o["envelopes"]?.asArray, let hidden = o["hiddenSkills"]?.asArray else { throw JSError("TypeError: not iterable") }
        var digests: [JSONValue?] = []
        for e in envelopes {
            let d = try needObject(e).get("policyDigest")
            if !digests.contains(where: { $0 == d }) { digests.append(d) }
        }
        if digests.count > 1 { throw JSError("extendedAgentCard: envelopes were computed against different policies") }
        var byVerb: [(JSONValue, JSONValue)] = []
        for e in envelopes {
            let v = try needObject(e).get("verb") ?? .null
            if let i = byVerb.firstIndex(where: { $0.0 == v }) { byVerb[i].1 = e } else { byVerb.append((v, e)) }
        }
        var revealed: [JSONValue] = []
        for s in hidden {
            let verb: String?
            if let f = verbOf { verb = f(s) } else { verb = try defaultVerbOf(s) }
            guard let vb = verb, let env = byVerb.first(where: { $0.0 == .string(vb) })?.1, env.get("status") != .string("denied") else { continue }
            var sk = spread(s)
            let tags = s.get("tags")
            var nt: [JSONValue] = (tags == nil || tags == .null) ? [] : try spreadList(tags)
            nt.append(.string(env.get("status") == .string("autonomous") ? "pca:autonomous" : "pca:needs-approval"))
            sk["tags"] = .array(nt)
            revealed.append(.object(sk))
        }
        guard let pc = publicCard, !pc.isNull else { throw JSError("TypeError: cannot destructure null") }
        var rest = spread(pc)
        rest["signatures"] = nil
        let caps = spread(JS.present(rest["capabilities"]) ?? .object([:]))
        let exts = caps["extensions"]?.asArray ?? []
        var next = exts
        if let pd = digests.first ?? nil {
            next = try exts.map { e in
                if e.isNull { throw JSError("TypeError: cannot read properties of null (reading 'uri')") }
                guard e.get("uri") == .string(PCA_A2A_EXTENSION_URI) else { return e }
                var ne = spread(e)
                var np = spread(e.get("params"))
                np["policy_digest"] = pd
                ne["params"] = .object(np)
                return .object(ne)
            }
        }
        var capsOut = caps
        capsOut["extensions"] = .array(next)
        rest["capabilities"] = .object(capsOut)
        rest["skills"] = .array((rest["skills"]?.asArray ?? []) + revealed)
        return .object(rest)
    }

    private static func needObject(_ e: JSONValue) throws -> JSONValue {
        if e.isNull { throw JSError("TypeError: cannot read properties of null") }
        return e
    }

    private static func defaultVerbOf(_ s: JSONValue) throws -> String? {
        let tags = try needObject(s).get("tags")
        guard let t = tags, !t.isNull else { return nil }
        guard let a = t.asArray else { throw JSError("TypeError: tags.find is not a function") }
        for x in a { if let str = x.asString, IV.startsWith(str, "pca-verb:") { return IV.dropPrefix(str, "pca-verb:".count) } }
        return nil
    }
}
