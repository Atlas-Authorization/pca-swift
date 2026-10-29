import Foundation

// Assurance labels (T8, B7). A check's status ("pass", "fail", "not-enforced", "unsupported") says WHETHER it held; the assurance
// report says WHAT a pass rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a post-quantum or an
// Ed25519 signature, independent multisig shares or a FROST (awaiting audit) aggregate. It also names the features this verifier does not
// implement ("unsupported": a bond reference), which are reported and never count as a pass.
//
// Labels come from the VERIFIER'S configuration, never from the presented evidence: a hook or verifier carries its label (it conforms
// to `AssuranceLabeled`, or is wrapped with `PCA.withAssuranceLabel`); an unlabelled one is "unknown" and satisfies no requirement. An
// `AssuranceRequirement` turns the report into a gate: when the evidence is weaker, missing, failed, unlabelled, awaiting-audit, degraded or
// unsupported, the `assurance` check fails and the request is denied. Mirrors the reference assurance module; assurance-vectors.json
// pins the report and every reason.

/// What a hook, hardware verifier or SNARK-like backend declares about itself.
public struct AssuranceLabel: Equatable, Sendable {
    /// The level / system / scheme: attestation "software" < "hardware" < "multi_root"; zk "groth16", "policyvm_snark", "stark", "zkvm",
    /// "attested_vm", "attested_vm_hw"; threshold "multisig", "frost", "frost_dkg", "mpc".
    public var level: String
    /// The vendor or root id, for example "amd-sev-snp".
    public var vendor: String?
    /// Crypto awaiting audit (not production): FROST, DKG, MPC.
    public var awaitingAudit: Bool
    /// "single-party" or "multi-party": how a SNARK verifying key was set up.
    public var ceremony: String?

    public init(level: String, vendor: String? = nil, awaitingAudit: Bool = false, ceremony: String? = nil) {
        self.level = level
        self.vendor = vendor
        self.awaitingAudit = awaitingAudit
        self.ceremony = ceremony
    }
}

/// Implemented by a verifier, hook or backend that declares its assurance label.
public protocol AssuranceLabeled {
    var assuranceLabel: AssuranceLabel { get }
}

/// Attaches a label to any hook value (see `PCA.withAssuranceLabel`).
public struct LabeledHook<Hook>: AssuranceLabeled {
    public let hook: Hook
    public let assuranceLabel: AssuranceLabel
}

/// A vendor attestation verifier is hardware evidence of its vendor.
extension VendorVerifier: AssuranceLabeled {
    public var assuranceLabel: AssuranceLabel { AssuranceLabel(level: "hardware", vendor: vendor) }
}

/// One check in the report.
public struct CheckAssurance: Equatable, Sendable {
    /// The check's status: pass, fail, not-enforced or unsupported.
    public var outcome: String
    /// Present only on a pass that rests on labelled evidence.
    public var level: String?
    public var vendor: String?
    public var awaitingAudit: Bool
    public var ceremony: String?
    /// The signature suites involved (leaf, or root + hops).
    public var suites: [String]?
    /// The threshold the hook enforced.
    public var t: Double?
    /// Why the outcome is unsupported, or why a passing check is degraded.
    public var reason: String?
    /// A passing check that rests on a compatibility mode; any high-assurance requirement refuses it.
    public var degraded: Bool

    public init(outcome: String, level: String? = nil, vendor: String? = nil, awaitingAudit: Bool = false, ceremony: String? = nil, suites: [String]? = nil,
                t: Double? = nil, reason: String? = nil, degraded: Bool = false) {
        self.outcome = outcome
        self.level = level
        self.vendor = vendor
        self.awaitingAudit = awaitingAudit
        self.ceremony = ceremony
        self.suites = suites
        self.t = t
        self.reason = reason
        self.degraded = degraded
    }

    /// The entry as the reference writes it (members that are absent are left out).
    public var json: JSONValue {
        var o: JObject = ["outcome": .string(outcome)]
        if let x = level { o["level"] = .string(x) }
        if let x = vendor { o["vendor"] = .string(x) }
        if awaitingAudit { o["awaiting_audit"] = .bool(true) }
        if let x = ceremony { o["ceremony"] = .string(x) }
        if let x = suites { o["suites"] = .array(x.map { .string($0) }) }
        if let x = t { o["t"] = x.isFinite && x.rounded() == x && abs(x) <= IV.MAX_SAFE ? JSONValue.int(Int64(x)) : JSONValue.double(x) }
        if let x = reason { o["reason"] = .string(x) }
        if degraded { o["degraded"] = .bool(true) }
        return .object(o)
    }

    init(json v: JSONValue?) {
        let e = v?.asObject ?? [:]
        self.init(outcome: e["outcome"]?.asString ?? "", level: e["level"]?.asString, vendor: e["vendor"]?.asString,
                  awaitingAudit: (e["awaiting_audit"] == .bool(true) || e["preview"] == .bool(true)), ceremony: e["ceremony"]?.asString,
                  suites: e["suites"]?.asArray.map { $0.map { $0.asString ?? "" } }, t: IV.num(e["t"]), reason: e["reason"]?.asString,
                  degraded: e["degraded"] == .bool(true))
    }
}

/// The per-check report, in the order the checks were decided.
public struct AssuranceReport: Equatable, Sendable {
    public private(set) var names: [String] = []
    private var by: [String: CheckAssurance] = [:]

    public init() {}

    public subscript(name: String) -> CheckAssurance? { by[name] }

    /// Adds or replaces an entry (a replaced entry keeps its position).
    public mutating func set(_ name: String, _ c: CheckAssurance) {
        if by[name] == nil { names.append(name) }
        by[name] = c
    }

    /// The report as the reference writes it.
    public var json: JSONValue {
        var o: JObject = [:]
        for n in names { o[JKey(n)] = by[n]?.json }
        return .object(o)
    }

    /// A report from parsed JSON; `order` lists the member names in the order to keep (members it omits follow, sorted).
    public init(json v: JSONValue?, order: [String] = []) {
        let o = v?.asObject ?? [:]
        var seen: Set<String> = []
        for n in order where o[JKey(n)] != nil && !seen.contains(n) {
            seen.insert(n)
            set(n, CheckAssurance(json: o[JKey(n)]))
        }
        for k in o.keys.map({ $0.s }).sorted() where !seen.contains(k) { set(k, CheckAssurance(json: o[JKey(k)])) }
    }
}

/// One check and its status.
public struct NamedStatus: Sendable {
    public let name: String
    public let status: String
    public init(name: String, status: String) {
        self.name = name
        self.status = status
    }
}

/// The verifier's hooks whose labels the report reads (nil: no such hook; one that is not `AssuranceLabeled` is unlabelled: "unknown").
public struct AssuranceHooks {
    public var attestation: Any?
    public var zk: Any?
    public var threshold: Any?
    public var revocation: Any?
    public init(attestation: Any? = nil, zk: Any? = nil, threshold: Any? = nil, revocation: Any? = nil) {
        self.attestation = attestation
        self.zk = zk
        self.threshold = threshold
        self.revocation = revocation
    }
}

/// What the report is built from: the checks (in order), the presented PCActn, the verifier's hooks and its PQ policy.
public struct AssuranceSources {
    public var checks: [NamedStatus]
    public var pcactn: JSONValue?
    public var hooks: AssuranceHooks
    /// The attestation verifier actually used; it wins over `hooks.attestation`.
    public var attestationHook: Any?
    /// The `t` the threshold hook reported.
    public var thresholdT: Double?
    /// Reports a post-quantum signature whose key is not bound to a verifier-side source as "unbound_pq".
    public var allowUnboundPq: Bool
    /// Passing checks that rest on a compatibility mode: check name -> why.
    public var degraded: [String: String]
    public init(checks: [NamedStatus] = [], pcactn: JSONValue? = nil, hooks: AssuranceHooks = AssuranceHooks(), attestationHook: Any? = nil,
                thresholdT: Double? = nil, allowUnboundPq: Bool = false, degraded: [String: String] = [:]) {
        self.checks = checks
        self.pcactn = pcactn
        self.hooks = hooks
        self.attestationHook = attestationHook
        self.thresholdT = thresholdT
        self.allowUnboundPq = allowUnboundPq
        self.degraded = degraded
    }
}

/// One root of a multi-root attestation policy: its verifier (labelled or not) and whether it is required.
public struct AttestationRoot {
    public var verifier: Any?
    public var required: Bool
    public init(verifier: Any?, required: Bool = false) {
        self.verifier = verifier
        self.required = required
    }
}

/// A high-assurance policy. Every listed dimension must be met by a PASSING check; otherwise the `assurance` check fails.
public struct AssuranceRequirement: Equatable, Sendable {
    /// The minimum attestation level: "software" < "hardware" < "multi_root".
    public var attestation: String?
    /// "attested_vm" accepts any enforced statement; "attested_vm_hardware" a statement whose prover key is bound to hardware evidence (or
    /// any real proof); "proof" a cryptographic proof; "snark" only Groth16 / Policy-VM SNARK.
    public var zk: String?
    /// "pq": the leaf signature and every capability in the chain use a hybrid or pure post-quantum suite.
    public var signature: String?
    /// The accepted threshold schemes; nil: not required.
    public var threshold: [String]?
    /// Accept passing evidence awaiting audit (FROST, DKG, MPC) outside an explicit `threshold` list.
    public var allowAwaitingAudit: Bool
    public init(attestation: String? = nil, zk: String? = nil, signature: String? = nil, threshold: [String]? = nil, allowAwaitingAudit: Bool = false) {
        self.attestation = attestation
        self.zk = zk
        self.signature = signature
        self.threshold = threshold
        self.allowAwaitingAudit = allowAwaitingAudit
    }

    /// From the reference's JSON form `{attestation?, zk?, signature?, threshold?, allowAwaitingAudit?}`.
    public init(json v: JSONValue?) {
        let o = v?.asObject ?? [:]
        self.init(attestation: o["attestation"]?.asString, zk: o["zk"]?.asString, signature: o["signature"]?.asString,
                  threshold: o["threshold"]?.asArray.map { $0.map { $0.asString ?? "" } }, allowAwaitingAudit: o["allowAwaitingAudit"] == .bool(true) || o["allowPreview"] == .bool(true))
    }
}

extension PCA {
    /// Labels `hook` so a requirement can be met by it.
    public static func withAssuranceLabel<Hook>(_ hook: Hook, _ label: AssuranceLabel) -> LabeledHook<Hook> {
        LabeledHook(hook: hook, assuranceLabel: label)
    }

    static func labelOf(_ hook: Any?) -> AssuranceLabel? { (hook as? AssuranceLabeled)?.assuranceLabel }

    static let ATT_RANK: [String: Int] = ["unknown": 0, "software": 1, "hardware": 2, "multi_root": 3]
    static let ZK_RANK: [String: Int] = ["unknown": 0, "attested_vm": 1, "attested_vm_hw": 1, "stark": 2, "zkvm": 2, "groth16": 3, "policyvm_snark": 3]
    static let ZK_NEED: [String: Int] = ["attested_vm": 1, "attested_vm_hardware": 1, "proof": 2, "snark": 3]

    static func isAwaitingAuditScheme(_ s: String) -> Bool { s == "frost" || s == "frost_dkg" || s == "mpc" }

    /// Classifies one signature suite (absent or null = Ed25519): "ed25519", "hybrid", "pq", or "unknown" for an unregistered suite.
    public static func signatureLevel(_ alg: JSONValue?) -> String {
        guard let a = alg, !a.isNull else { return "ed25519" }
        guard case let .string(s) = a else { return "unknown" }
        if IV.same(s, "ed25519") { return "ed25519" }
        guard PCASuites.registered.contains(where: { IV.same($0, s) }) else { return "unknown" }
        return IV.startsWith(s, "hybrid-") ? "hybrid" : "pq"
    }

    /// The weakest level in a chain: any unknown suite, then any Ed25519-only signer, then any hybrid, else pure PQ.
    static func weakestLevel(_ levels: [String]) -> String {
        for l in ["unknown", "ed25519", "hybrid"] where levels.contains(l) { return l }
        return levels.isEmpty ? "unknown" : "pq"
    }

    /// The attestation level an N-of-M multi-root policy guarantees: the fewest hardware roots any accepted subset can contain (all
    /// required roots, filled up to `threshold` with the weakest optional ones). Two or more hardware roots is "multi_root", one is
    /// "hardware", none is the weakest level among the roots that could make up the quorum.
    public static func multiRootLevel(_ roots: [AttestationRoot], threshold: Int) -> String {
        func rank(_ r: AttestationRoot) -> Int { ATT_RANK[labelOf(r.verifier)?.level ?? "unknown"] ?? 0 }
        let req = roots.filter { $0.required }
        // a stable ascending sort (ties keep their order, as the reference's)
        let opt = roots.filter { !$0.required }.enumerated().sorted { a, b in
            let ra = rank(a.element), rb = rank(b.element)
            return ra != rb ? ra < rb : a.offset < b.offset
        }.map { $0.element }
        let take = max(0, min(opt.count, threshold - req.count))
        let chosen = req + opt.prefix(take)
        let hw = chosen.filter { rank($0) >= ATT_RANK["hardware"]! }.count
        if hw >= 2 { return "multi_root" }
        if hw == 1 { return "hardware" }
        let floor = chosen.map(rank).min() ?? Int.max // the minimum of nothing is +Infinity
        return floor >= ATT_RANK["software"]! ? "software" : "unknown"
    }

    /// Builds the per-check assurance report (pure; never traps on odd input).
    public static func buildAssuranceReport(_ src: AssuranceSources) -> AssuranceReport {
        var out = AssuranceReport()
        let p = src.pcactn?.asObject
        for ns in src.checks {
            let name = ns.name
            var e = CheckAssurance(outcome: ns.status)
            if ns.status == "unsupported" { e.reason = "\(name) is not implemented by this verifier" }
            if ns.status == "pass" {
                var hook: Any?
                switch name {
                case "attestation": hook = src.attestationHook ?? src.hooks.attestation
                case "zk_compliance": hook = src.hooks.zk
                case "threshold": hook = src.hooks.threshold
                case "revocation": hook = src.hooks.revocation
                default: hook = nil
                }
                let label = labelOf(hook)
                if name == "attestation" || name == "zk_compliance" || (name == "threshold" && hook != nil) {
                    e.level = (label?.level).flatMap { $0.isEmpty ? nil : $0 } ?? "unknown"
                    e.vendor = label?.vendor
                    if name == "zk_compliance" { e.ceremony = label?.ceremony }
                    if label?.awaitingAudit == true || (name == "threshold" && isAwaitingAuditScheme(e.level ?? "")) { e.awaitingAudit = true }
                    if name == "threshold", let t = src.thresholdT { e.t = t }
                } else if let l = label {
                    e.level = l.level
                    e.vendor = l.vendor
                    e.awaitingAudit = l.awaitingAudit
                }
                if name == "leaf_signature", let p = p {
                    let alg = (p["alg"] == nil || p["alg"] == .null) ? JSONValue.string("ed25519") : p["alg"]!
                    e.suites = [IntentV2.jsString(alg)]
                    e.level = (src.allowUnboundPq && alg != .string("ed25519")) ? "unbound_pq" : signatureLevel(alg)
                }
                if name == "cap_chain", let p = p, case let .array(chain)? = p["cap_chain"] {
                    var levels: [String] = []
                    var suites: [String] = []
                    var unbound = false
                    for c in chain {
                        var a = JSONValue.string("ed25519")
                        if let x = c.get("alg"), !x.isNull { a = x }
                        levels.append(signatureLevel(a))
                        suites.append(IntentV2.jsString(a))
                        unbound = unbound || a != .string("ed25519")
                    }
                    e.suites = suites
                    e.level = (src.allowUnboundPq && unbound) ? "unbound_pq" : weakestLevel(levels)
                }
            }
            out.set(name, e)
        }
        for (name, why) in src.degraded {
            if var c = out[name], c.outcome == "pass" {
                c.degraded = true
                c.reason = why
                out.set(name, c)
            }
        }
        // Features this verifier does not implement: reported, never a pass.
        if let p = p, p["bond_ref"] != nil {
            out.set("bond", CheckAssurance(outcome: "unsupported", reason: "bond verification is not implemented by this verifier"))
        }
        return out
    }

    /// Checks a report against a requirement. Returns the reason of the first unmet dimension (prefixed "assurance: "), or nil when every
    /// listed dimension is met. Missing, failed, not-enforced, unlabelled, weaker, awaiting-audit, degraded and unsupported evidence never
    /// meet a requirement.
    public static func unmetAssurance(_ report: AssuranceReport, _ req: AssuranceRequirement) -> String? {
        func orUnknown(_ s: String?) -> String { (s ?? "").isEmpty ? "unknown" : s! }
        for name in report.names {
            if let e = report[name], e.outcome == "unsupported" {
                return "assurance: unsupported: \(name) (\((e.reason ?? "").isEmpty ? "not implemented" : e.reason!)); a high-assurance policy never accepts it"
            }
        }
        for name in report.names {
            if let e = report[name], e.outcome == "pass", e.degraded {
                return "assurance: \(name) rests on a degraded compatibility mode (\((e.reason ?? "").isEmpty ? "degraded" : e.reason!)); a high-assurance policy never accepts it"
            }
        }
        func need(_ name: String, _ what: String) -> (CheckAssurance?, String?) {
            guard let e = report[name] else { return (nil, "assurance: \(what) required but there is no \(name) evidence") }
            if e.outcome != "pass" { return (nil, "assurance: \(what) required but the \(name) check is \(e.outcome)") }
            return (e, nil)
        }
        if let want = req.attestation {
            let (e, why) = need("attestation", "\(want) attestation")
            if let w = why { return w }
            if (ATT_RANK[orUnknown(e?.level)] ?? 0) < (ATT_RANK[want] ?? 99) {
                return "assurance: \(want) attestation required but the evidence is \(orUnknown(e?.level))"
            }
        }
        if let zk = req.zk {
            let (e, why) = need("zk_compliance", "zk compliance (\(zk))")
            if let w = why { return w }
            let lv = e?.level ?? ""
            if zk == "attested_vm_hardware" && (lv == "attested_vm" || lv == "unknown" || lv.isEmpty) {
                return "assurance: zk compliance (\(zk)) required but the prover key is not bound to hardware evidence"
            }
            if (ZK_RANK[orUnknown(e?.level)] ?? 0) < (ZK_NEED[zk] ?? 99) {
                return "assurance: zk compliance (\(zk)) required but the evidence is \(orUnknown(e?.level))"
            }
        }
        if req.signature == "pq" {
            for name in ["leaf_signature", "cap_chain"] {
                let (e, why) = need(name, "post-quantum signatures")
                if let w = why { return w }
                if e?.level != "pq" && e?.level != "hybrid" { return "assurance: post-quantum signatures required but \(name) is \(orUnknown(e?.level))" }
            }
        }
        if let list = req.threshold {
            let joined = list.joined(separator: " | ")
            let (e, why) = need("threshold", "threshold (\(joined))")
            if let w = why { return w }
            guard let lv = e?.level, !lv.isEmpty else { return "assurance: threshold (\(joined)) required but no threshold verifier enforced it" }
            if !list.contains(lv) { return "assurance: threshold (\(joined)) required but the scheme is \(lv)" }
        }
        if !req.allowAwaitingAudit {
            for name in report.names {
                guard let e = report[name], e.outcome == "pass", e.awaitingAudit else { continue }
                if name == "threshold", let list = req.threshold, list.contains(e.level ?? "") { continue }
                return "assurance: \(name) rests on crypto awaiting audit (\(orUnknown(e.level))); set allowAwaitingAudit or list the scheme to accept it"
            }
        }
        return nil
    }
}
