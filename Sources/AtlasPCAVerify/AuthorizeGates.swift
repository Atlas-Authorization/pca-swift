import Foundation

// The policy gates of `authorize` that the TypeScript `authorize()` offers beyond the core pipeline: `requirePassport`, `forbid`,
// `requireLinkedTemplate`, `contracts`, `enforceFreshness`, `enforceTaint` and `beacon`. Their configuration types and their checks live here;
// `PCA.authorize` runs them (`Authorize.swift`). A gate that is configured and cannot decide denies.

extension PCA {
    /// `requirePassport`: the call must carry a valid signed agent passport (`AuthorizeInput.passport`) whose `sub` is the PCActn's leaf holder.
    /// It is checked before the PCActn is verified or its replay counter advanced, so a refusal never consumes the PCActn.
    public struct RequirePassport {
        public var trustedIssuers: [String]
        /// `(id, iss, sub) -> revoked?`; nil means no revocation source (`revocation_unavailable`). A throw denies.
        public var revoked: ((String, String, String) throws -> Bool)?
        public var pqPins: [String: String]
        public var attest: ((JSONValue, PassportBinding) throws -> PassportAttestation)?
        public var defaultHardware: DefaultHardware?
        public var clockSkewMs: Int64?
        public var maxEvidenceAgeMs: Int64?
        /// Also demand a `hardware_rooted` passport whose evidence verified.
        public var hardware: Bool
        /// The passport clock (epoch ms); default: the wall clock.
        public var now: (() -> Int64)?
        public init(trustedIssuers: [String], revoked: ((String, String, String) throws -> Bool)? = nil, pqPins: [String: String] = [:],
                    attest: ((JSONValue, PassportBinding) throws -> PassportAttestation)? = nil, defaultHardware: DefaultHardware? = nil,
                    clockSkewMs: Int64? = nil, maxEvidenceAgeMs: Int64? = nil, hardware: Bool = false, now: (() -> Int64)? = nil) {
            self.trustedIssuers = trustedIssuers
            self.revoked = revoked
            self.pqPins = pqPins
            self.attest = attest
            self.defaultHardware = defaultHardware
            self.clockSkewMs = clockSkewMs
            self.maxEvidenceAgeMs = maxEvidenceAgeMs
            self.hardware = hardware
            self.now = now
        }
    }

    /// `forbid`: decide the operation against a clause list (the organisation's forbids and the grant's permits) and require `allow`. A matching
    /// forbid refuses whoever signed it. With `requireCertificate` the call must also carry `AuthorizeInput.forbidCertificate`, which is RECOMPUTED
    /// from the clauses and the operation (never trusted) and must agree. Checked before the PCActn, so a refusal never spends its counter.
    public struct ForbidGate {
        /// The clause list `[{id, kind, signer?, when}]` for this operation and the resolved grant (nil when none could be read).
        public var clauses: (Operation, JSONValue?) throws -> JSONValue
        /// Extra context members (`subject`, `env`; a member named `action` replaces the operation's, as the reference's object spread does).
        public var context: ((Operation) -> JObject)?
        public var precedence: [String]
        public var permitSigners: [String]?
        public var requireCertificate: Bool
        public init(clauses: @escaping (Operation, JSONValue?) throws -> JSONValue, context: ((Operation) -> JObject)? = nil, precedence: [String] = [],
                    permitSigners: [String]? = nil, requireCertificate: Bool = false) {
            self.clauses = clauses
            self.context = context
            self.precedence = precedence
            self.permitSigners = permitSigners
            self.requireCertificate = requireCertificate
        }
    }

    /// `requireLinkedTemplate`: the grant must carry a `template_ref` that resolves in this registry (`{templates, overlays?, params?, trusted}`,
    /// signed by a trusted organisation key, with any verified tighten overlay) and its policy must equal the instantiation.
    public struct LinkedTemplateGate {
        public var registry: () throws -> JSONValue
        public init(registry: @escaping () throws -> JSONValue) { self.registry = registry }
        public init(registry: JSONValue) { self.registry = { registry } }
    }

    /// `enforce.freshness`: the signed freshness anchor as a gate (check `freshness_anchor`): a missing, stub, future or stale anchor refuses.
    public struct FreshnessGate {
        /// The oldest an anchor may be (ms).
        public var maxAgeMs: Double
        /// The length of one anchor epoch (default 60 000 ms).
        public var epochMs: Double
        /// The clock the anchor is judged against (epoch ms); default: the call's `now`.
        public var now: Double?
        public var clockSkewMs: Double?
        public init(maxAgeMs: Double, epochMs: Double = 60_000, now: Double? = nil, clockSkewMs: Double? = nil) {
            self.maxAgeMs = maxAgeMs
            self.epochMs = epochMs
            self.now = now
            self.clockSkewMs = clockSkewMs
        }
    }

    /// `enforce.taint`: the information-flow taint of the PCActn's declared provenance as a gate (check `taint_gate`): every declared ref is
    /// re-classified from the server's own facts, so an agent can never forge a clean lineage.
    public struct TaintGate {
        public var registry: any TrustedInputRegistry
        /// `node(id)`: whether the server's committed resource graph holds this node (a first-party source).
        public var resourceGraphNode: ((String) throws -> Bool)?
        /// The largest taint accepted, in [0, 1].
        public var maxTaint: Double
        public init(registry: any TrustedInputRegistry, resourceGraphNode: ((String) throws -> Bool)? = nil, maxTaint: Double) {
            self.registry = registry
            self.resourceGraphNode = resourceGraphNode
            self.maxTaint = maxTaint
        }
    }

    /// What a `beacon` source hands `authorize` for a grant.
    public struct BeaconInput {
        public var beacon: JSONValue
        public var issuers: [String]
        public var instance: String
        public var pqPins: [String: String]?
        /// The highest `seq` the host has already accepted (the store's own pin counts too).
        public var lastAcceptedSeq: Int64?
        public init(beacon: JSONValue, issuers: [String], instance: String, pqPins: [String: String]? = nil, lastAcceptedSeq: Int64? = nil) {
            self.beacon = beacon
            self.issuers = issuers
            self.instance = instance
            self.pqPins = pqPins
            self.lastAcceptedSeq = lastAcceptedSeq
        }
    }

    // ---- the checks ------------------------------------------------------------------------------------------------------------

    /// The leaf holder a PCActn presents (read from the unverified PCActn only to pick the subject: the chain is still verified).
    static func presentedLeaf(_ p: JSONValue?) -> String? {
        guard case let .array(chain)? = p?.get("cap_chain"), let last = chain.last else { return nil }
        return last.get("holder")?.asString
    }

    /// `requirePassport`: no refusal when the passport verifies for the presented leaf holder (a PCActn that cannot be read has no leaf and is left to
    /// the wire refusal), else the refusal reason. The verdict is the verified passport.
    static func passportRefusal(_ p: JSONValue?, _ rp: RequirePassport, _ passport: JSONValue?, _ fallbackNow: Int64) -> (refusal: String?, verdict: PassportVerdict?) {
        guard let leaf = presentedLeaf(p) else { return (nil, nil) }
        let o = PassportOptions(trustedIssuers: rp.trustedIssuers, nowMs: rp.now?() ?? fallbackNow, clockSkewMs: rp.clockSkewMs, maxEvidenceAgeMs: rp.maxEvidenceAgeMs,
                                subject: leaf, pqPins: rp.pqPins, attest: rp.attest, defaultHardware: rp.defaultHardware, revoked: rp.revoked)
        let v = verifyPassport(passport, o)
        if !v.ok { return ("passport: \(v.reason)", nil) }
        if rp.hardware && !v.hardwareVerified { return ("passport: hardware_evidence_missing", nil) }
        return (nil, v)
    }

    /// `passportAssurance`: the assurance entry of a verified passport: `software` unless its hardware evidence verified, then the label of the
    /// verifier that checked it (`unknown` when unlabelled).
    static func passportAssurance(_ v: PassportVerdict, _ rp: RequirePassport) -> CheckAssurance {
        if !v.hardwareVerified { return CheckAssurance(outcome: "pass", level: "software") }
        let label = (rp.defaultHardware?.verifier as? AssuranceLabeled)?.assuranceLabel
        let vendor = label?.vendor
        return CheckAssurance(outcome: "pass", level: label?.level ?? "unknown", vendor: (vendor ?? "").isEmpty ? nil : vendor)
    }

    /// `verifyLinkedPolicy(envelope, registry)`: a grant carrying a `template_ref` must hold exactly the policy the reference denotes.
    public static func verifyLinkedPolicy(_ envelope: JSONValue, registry: JSONValue) -> (ok: Bool, reason: String?, template: String?) {
        guard let ref = envelope.get("template_ref") else { return (true, nil, nil) }
        let r = resolveLink(ref, registry: registry)
        guard let pol = r.policy else { return (false, r.reason, nil) }
        guard let have = IV.strictHash(.object(["predicates": envelope.get("predicates") ?? .null, "caveats": envelope.get("caveats") ?? .null])),
              let want = IV.strictHash(.object(["predicates": pol.get("predicates") ?? .null, "caveats": pol.get("caveats") ?? .array([])])) else {
            return (false, "link verification error (fail closed)", nil)
        }
        if have != want { return (false, "grant policy differs from the linked template instantiation", nil) }
        return (true, nil, ref.get("version_digest")?.asString)
    }

    /// The refusal of a grant that is not the instantiation of its linked template, else nil.
    static func linkError(_ grant: JSONValue?, _ gate: LinkedTemplateGate) throws -> String? {
        guard let g = grant, let env = readEnvelope(g) else { return "template: the grant has no readable envelope" }
        if env.get("template_ref") == nil { return "template: the grant carries no template_ref" }
        let v = verifyLinkedPolicy(env, registry: try gate.registry())
        return v.ok ? nil : "template: \(v.reason ?? "refused")"
    }

    /// The action context a contract judges: `{action: {verb, resource, params}}`.
    static func contractAction(_ op: Operation) -> JSONValue {
        .object(["action": .object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params])])
    }

    /// `contract: <reason>[ (<violated,...>)]`, nil when the enforcer allows.
    static func contractRefusal(_ r: EnforceResult) -> String? {
        if r.allow { return nil }
        return "contract: \(r.reason)\(r.violated.isEmpty ? "" : " (\(r.violated.joined(separator: ",")))")"
    }

    struct ForbidOutcome {
        var refusal: String?
        var certificate: JSONValue?
    }

    /// `forbid`: nil refusal when the clauses allow the operation (and, with `requireCertificate`, the presented certificate matches the recomputed
    /// one). Throws where the reference's `authorize` would catch an error (an unreadable clause source).
    static func forbidGate(_ p: JSONValue?, _ f: ForbidGate, _ op: Operation, _ resolve: (String) throws -> JSONValue?, _ certificate: JSONValue?) throws -> ForbidOutcome {
        var grant: JSONValue?
        if let ref = p?.get("grant_ref")?.asString { grant = (try? resolve(ref)) ?? nil } // no readable grant: the clause source decides, the guard denies the unreadable PCActn
        var ctx: JObject = ["action": .object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params])]
        for (k, v) in f.context?(op) ?? [:] { ctx[k] = v }
        let ctxV: JSONValue = .object(ctx)
        let clauses = try f.clauses(op, grant)
        let d = ForbidClauses.decideClauses(clauses, ctxV, precedence: f.precedence, permitSigners: f.permitSigners)
        if d.decision != "allow" {
            return ForbidOutcome(refusal: "forbid: \(d.decision) by \(d.winnerKind)\(d.winnerId.map { $0.isEmpty ? "" : " " + $0 } ?? "")")
        }
        let cert = try ForbidClauses.certify(clauses, ctxV, precedence: f.precedence, permitSigners: f.permitSigners)
        if f.requireCertificate {
            guard PD.truthy(certificate) else { return ForbidOutcome(refusal: "forbid: the call carries no certificate (fail closed)") }
            let c = ForbidClauses.checkForbidCertificate(certificate, clauses, ctxV, precedence: f.precedence, permitSigners: f.permitSigners)
            if !c.ok { return ForbidOutcome(refusal: "forbid: certificate refused (\(c.reason ?? "mismatch"))") }
        }
        return ForbidOutcome(refusal: nil, certificate: cert)
    }

    /// `enforce.freshness`: nil when the signed anchor `{epoch, beacon_ref}` is present, not in the future and not stale, else the reason.
    static func freshnessAnchorError(_ p: JObject, _ g: FreshnessGate, _ now: Int64) -> String? {
        let fnow = g.now ?? Double(now)
        let skew = (g.clockSkewMs?.isFinite ?? false) ? max(0, g.clockSkewMs!) : 0
        if !(g.epochMs > 0) || !g.maxAgeMs.isFinite || g.maxAgeMs < 0 {
            return "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"
        }
        let fr = p["freshness"]
        guard let ref = fr?.get("beacon_ref")?.asString, !ref.isEmpty, let ev = fr?.get("epoch"), let epoch = IV.safe(ev), epoch > 0 else {
            return "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"
        }
        let anchor = epoch * g.epochMs
        if anchor > fnow + skew { return "freshness anchor is in the future" }
        if fnow - anchor > g.maxAgeMs { return "freshness anchor is stale (older than \(PD.numStr(g.maxAgeMs)) ms)" }
        return nil
    }
}
