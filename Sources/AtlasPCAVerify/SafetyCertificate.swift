import Foundation
import CAda

/// A signed, machine-readable statement of the risk-budget bound of a grant. From a `risk_policy` it derives the bound `bMax / kappa`
/// (the total risk of autonomous actions between two human co-signs), a human statement and an optional list of which checks ran, each
/// with an evidence link, signed by the guardian (Ed25519, ML-DSA-65 or the hybrid). `verifySafetyCertificate` RECOMPUTES the bound from
/// the certificate's own parameters and refuses any mismatch, so a consumer never trusts the stated number.
///
/// It is not a claim that the agent or the system is safe: it signs the arithmetic and the list of checks. The verifier does not fetch
/// or judge the evidence; a `passed` entry is the guardian's assertion.
public enum SafetyCertificate {
    /// Domain separation of the guardian signature.
    public static let SAFETY_CERT_DOMAIN = "atlas-pca/safety-cert/v1\0"
    public static let SAFETY_CERT_VERSION = 1
    /// The only thing the bound speaks about; a verifier refuses any other value.
    public static let SAFETY_CERT_SCOPE = "risk-budget-bound"
    public static let MAX_SAFETY_CHECKS = 64
    static let MAX_CHECK_ID = 64
    static let MAX_EVIDENCE_URL = 2048

    /// A WHATWG URL with the https scheme and no username or password (at most 2048 UTF-16 units).
    static func plainHttps(_ ref: String) -> Bool {
        if JS.length(ref) > MAX_EVIDENCE_URL { return false }
        let u = Array(ref.utf8)
        // the serialised URL is at most three bytes per input byte (percent-encoding) plus the separators the parser adds
        let cap = 4 * u.count + 64
        var out = [UInt8](repeating: 0, count: cap)
        var n = 0
        guard atlas_ada_url_part(u, u.count, 3, &out, cap, &n) == 1, n <= cap else { return false }
        let href = String(decoding: out[0..<n], as: UTF8.self)
        guard href.hasPrefix("https://") else { return false }
        // the serialiser writes "user:password@" only when one of them is non-empty, and percent-encodes "@" inside them
        let authority = href.utf8.dropFirst(8).prefix(while: { $0 != UInt8(ascii: "/") && $0 != UInt8(ascii: "?") && $0 != UInt8(ascii: "#") })
        return !authority.contains(UInt8(ascii: "@"))
    }

    /// Nil when the checks are well formed, else the first problem.
    public static func validateSafetyChecks(_ checks: JSONValue?) -> String? {
        guard case let .array(list)? = checks else { return "checks must be an array" }
        if list.count > MAX_SAFETY_CHECKS { return "more than \(MAX_SAFETY_CHECKS) checks" }
        var seen = Set<JKey>()
        for c in list {
            let k: JObject
            switch c {
            case let .object(o): k = o
            case .array: k = [:] // a list is an object without these members
            default: return "check is not an object"
            }
            guard let id = k["id"]?.asString, JS.length(id) >= 1, JS.length(id) <= MAX_CHECK_ID else { return "check id must be a 1..64 char string" }
            if !seen.insert(JKey(id)).inserted { return "duplicate check id '\(id)'" }
            guard let status = k["status"]?.asString, status == "passed" || status == "failed" || status == "not_run" else {
                return "check '\(id)' has an invalid status"
            }
            if IV.nonNeg(k["at"]) == nil { return "check '\(id)' has an invalid time" }
            let e: JObject
            switch k["evidence"] {
            case let .object(o)?: e = o
            case .array?: e = [:]
            default: return "check '\(id)' has no evidence link"
            }
            guard let ref = e["ref"]?.asString else { return "check '\(id)' has no evidence link" }
            let kind = e["kind"]?.asString
            if kind == "sha256" {
                let hex = ref.unicodeScalars
                let ok = hex.count == 64 && hex.allSatisfy { ($0.value >= 0x30 && $0.value <= 0x39) || ($0.value >= 0x61 && $0.value <= 0x66) }
                if !ok { return "check '\(id)' evidence digest is not 64 lowercase hex" }
            } else if kind == "url" {
                if !plainHttps(ref) { return "check '\(id)' evidence URL must be a plain https URL" }
            } else {
                return "check '\(id)' has an invalid evidence kind"
            }
        }
        return nil
    }

    /// The provable bound of a policy: `max(0, bMax) / kappa`, and 0 when kappa is not above 0.
    public static func safetyCertificateBound(bMax: Double, kappa: Double) -> Double {
        guard kappa > 0 else { return 0 }
        return (bMax.isNaN ? Double.nan : (bMax > 0 ? bMax : 0)) / kappa
    }

    /// The same over a policy object (`bMax` and `kappa` members read as numbers).
    public static func safetyCertificateBound(_ policy: JSONValue?) -> Double {
        return safetyCertificateBound(bMax: JS.toNumber(policy?.get("bMax")), kappa: JS.toNumber(policy?.get("kappa")))
    }

    /// The human-readable statement of the bound (advisory; the machine fields are authoritative).
    public static func safetyCertificateStatement(_ bound: Double) -> String {
        return "Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ "
            + JS.toString(JSONValue.double(bound)) + " (= B_max / κ). This is not a claim that the agent or the system is safe."
    }

    /// The lenient canonical form; a value it cannot encode is refused with the reference's wording.
    static func canonical(_ v: JSONValue) throws -> String {
        let s = Canonical.canonicalize(v)
        if s.isEmpty { throw JSError(hasNonFinite(v) ? "canonicalize: non-finite number" : "canonicalize: nesting too deep") }
        return s
    }

    private static func hasNonFinite(_ v: JSONValue) -> Bool {
        switch v {
        case let .double(d): return !d.isFinite
        case let .array(a): return a.contains(where: hasNonFinite)
        case let .object(o): return o.values.contains(where: hasNonFinite)
        default: return false
        }
    }

    /// The exact bytes the guardian signs: the domain, then the canonical claim (the certificate without `sig` and `pq_sig`; `alg` and
    /// `pq_pk` stay and are signed).
    public static func safetyCertificateMessage(_ certOrClaim: JSONValue) throws -> [UInt8] {
        guard case var .object(claim) = certOrClaim else { throw JSError("safetyCertificateMessage: the certificate is not an object") }
        claim["sig"] = nil
        claim["pq_sig"] = nil
        return Array(SAFETY_CERT_DOMAIN.utf8) + Array(try canonical(.object(claim)).utf8)
    }

    /// Issues a signed safety certificate for a `risk_policy`. Throws on a malformed policy or check list. The guardian key carries the
    /// suite (ed25519, ml-dsa-65 or the hybrid) and must hold the guardian's Ed25519 identity. `issuedAt` (epoch ms) defaults to now.
    public static func issueSafetyCertificate(policy: JSONValue?, guardian: PCASuiteKey, grantRef: String? = nil, instance: String? = nil,
                                              checks: JSONValue? = nil, issuedAt: Double? = nil) throws -> JSONValue {
        if let bad = PCA.validateRiskPolicy(policy) { throw JSError("issueSafetyCertificate: \(bad)") }
        guard let ed = guardian.ed else { throw JSError("issueSafetyCertificate: the guardian key needs an Ed25519 identity") }
        if let c = checks, let bad = validateSafetyChecks(c) { throw JSError("issueSafetyCertificate: \(bad)") }
        guard case let .object(p)? = policy, let weights = p["weights"], weights.isObject else { throw JSError("issueSafetyCertificate: risk_policy must be an object") }
        let bound = safetyCertificateBound(policy)
        var base: JObject = [:]
        base[o: "v"] = .int(Int64(SAFETY_CERT_VERSION))
        base[o: "statement"] = .string(safetyCertificateStatement(bound))
        base[o: "scope"] = .string(SAFETY_CERT_SCOPE)
        if case let .array(list)? = checks {
            base[o: "checks"] = .array(list.map { c in
                var e: JObject = [:]
                e[o: "kind"] = c.get("evidence")?.get("kind")
                e[o: "ref"] = c.get("evidence")?.get("ref")
                var row: JObject = [:]
                row[o: "id"] = c.get("id")
                row[o: "status"] = c.get("status")
                row[o: "evidence"] = .object(e)
                row[o: "at"] = c.get("at")
                return .object(row)
            })
        }
        var params: JObject = [:]
        for name in ["bMax", "kappa", "theta1", "theta2", "lambda", "rho"] { params[o: name] = p[JKey(name)] }
        params[o: "weights"] = weights
        base[o: "params"] = .object(params)
        base[o: "bound"] = PD.num(bound)
        base[o: "blastRadiusPerCheckpoint"] = PD.num(bound)
        if let g = grantRef { base[o: "grant_ref"] = .string(g) }
        if let i = instance { base[o: "instance"] = .string(i) }
        base[o: "issued_at"] = PD.num(issuedAt ?? (Date().timeIntervalSince1970 * 1000).rounded(.down))
        base[o: "guardian"] = .string(Base64URLStrict.encode(ed.pub))
        // a non-ed25519 suite binds `alg` and the guardian's `pq_pk` into the signed claim; ed25519 adds nothing
        return .object(try PCAIntentKit.signSuite(base, guardian) { try safetyCertificateMessage(.object($0)) })
    }

    /// The outcome of `verifySafetyCertificate`. `recomputedBound` is derived from the certificate's own parameters, independent of the
    /// stated `bound`.
    public struct Verdict: Equatable, Sendable {
        public var ok: Bool
        public var reason: String?
        public var recomputedBound: Double?

        public var json: JSONValue {
            var o: JObject = [:]
            o[o: "ok"] = .bool(ok)
            if let r = reason { o[o: "reason"] = .string(r) }
            if let b = recomputedBound { o[o: "recomputedBound"] = PD.num(b) }
            return .object(o)
        }
    }

    /// Verifier policy. `guardian` pins the guardian key; `requireChecks` are check ids that must be present with status `passed`;
    /// `maxAgeMs` refuses an older certificate and one issued in the future (`now` defaults to the clock). A non-ed25519 certificate
    /// verifies only under the PQ key pinned for its guardian in `pqPins` (Ed25519 identity -> `pq_pk`). `allowUnboundPq` (default false)
    /// is the migration opt-out that accepts the certificate's own `pq_pk` when no pin exists for the guardian: it voids the identity
    /// binding of the PQ half and should not be set.
    public struct VerifyOptions {
        public var guardian: String?
        public var requireChecks: [String] = []
        public var maxAgeMs: Double?
        public var now: Double?
        public var pqPins: [String: String]?
        public var allowUnboundPq = false
        public init(guardian: String? = nil, requireChecks: [String] = [], maxAgeMs: Double? = nil, now: Double? = nil, pqPins: [String: String]? = nil,
                    allowUnboundPq: Bool = false) {
            self.guardian = guardian; self.requireChecks = requireChecks; self.maxAgeMs = maxAgeMs; self.now = now; self.pqPins = pqPins
            self.allowUnboundPq = allowUnboundPq
        }
    }

    /// The guardian signature under the certificate's suite. The PQ half verifies only under a key the verifier vouches for.
    private static func signatureVerifies(_ cert: JObject, _ alg: String, _ guardian: String, _ sig: String, _ msg: [UInt8], _ opts: VerifyOptions) -> Bool {
        guard let suite = PQ.resolve(alg) else { return false }
        var key: PinnedPQ?
        if suite.needsPqPk {
            guard let pk = cert["pq_pk"]?.asString, !pk.isEmpty else { return false }
            if opts.pqPins?[guardian] != nil {
                key = PQ.resolvePqKey(identity: guardian, artifactPk: pk, pqPins: opts.pqPins)
            } else if opts.allowUnboundPq {
                key = PQ.resolvePqKey(identity: nil, artifactPk: pk, trustedPk: pk)
            }
            if key == nil { return false }
        }
        return PQ.verifySuite(alg: alg, holder: guardian, pq: key, message: msg, sig: sig, pqSig: cert["pq_sig"]?.asString)
    }

    /// Verifies a safety certificate. Never throws. In order: shape, scope, checks and policy well-formedness; the stated `bound` and
    /// `blastRadiusPerCheckpoint` equal the bound recomputed from `params`; the pinned guardian; the guardian signature; then the age
    /// and required-check policy (after the signature, so an unsigned certificate never learns which check was missing).
    public static func verifySafetyCertificate(_ cert: JSONValue?, _ opts: VerifyOptions = VerifyOptions()) -> Verdict {
        guard case let .object(c)? = cert, IV.num(c["v"]) == Double(SAFETY_CERT_VERSION) else { return Verdict(ok: false, reason: "malformed certificate") }
        guard let sig = c["sig"]?.asString, let guardian = c["guardian"]?.asString else { return Verdict(ok: false, reason: "missing guardian/signature") }
        guard let scope = c["scope"]?.asString, scope == SAFETY_CERT_SCOPE else { return Verdict(ok: false, reason: "unknown scope") }
        if let checks = c["checks"], let bad = validateSafetyChecks(checks) { return Verdict(ok: false, reason: "invalid checks: \(bad)") }
        // a `params` that is not an object has none of the policy members
        let params: JSONValue = (c["params"]?.isObject ?? false) ? c["params"]! : .object([:])
        if let bad = PCA.validateRiskPolicy(params) { return Verdict(ok: false, reason: "invalid parameters: \(bad)") }

        let recomputed = safetyCertificateBound(params)
        func no(_ reason: String) -> Verdict { Verdict(ok: false, reason: reason, recomputedBound: recomputed) }
        guard let bound = IV.num(c["bound"]), bound.isFinite, bound == recomputed else {
            return no("stated bound does not equal B_max/κ recomputed from the parameters")
        }
        guard let blast = IV.num(c["blastRadiusPerCheckpoint"]), blast == recomputed else { return no("blastRadiusPerCheckpoint does not equal the recomputed bound") }
        if let pinned = opts.guardian, !IV.same(pinned, guardian) { return no("guardian key is not the pinned key") }
        guard let alg = IV.sigAlg(c["alg"]), PQ.resolve(alg) != nil else { return no("unknown signature alg") }
        let msg: [UInt8]
        do { msg = try safetyCertificateMessage(.object(c)) } catch {
            return Verdict(ok: false, reason: "malformed certificate: \((error as? JSError)?.message ?? "unknown")")
        }
        if !signatureVerifies(c, alg, guardian, sig, msg, opts) { return no("guardian signature does not verify") }
        if let maxAge = opts.maxAgeMs {
            let now = opts.now ?? (Date().timeIntervalSince1970 * 1000).rounded(.down)
            guard maxAge.isFinite, now.isFinite, let issued = IV.num(c["issued_at"]), issued.isFinite else { return no("invalid age policy or issue time") }
            if issued > now { return no("certificate is issued in the future") }
            if now - issued > maxAge { return no("certificate is older than maxAgeMs") }
        }
        let checks = c["checks"]?.asArray ?? []
        for id in opts.requireChecks {
            guard let row = checks.first(where: { IV.same($0.get("id")?.asString, id) }) else { return no("required check '\(id)' is not present") }
            let status = row.get("status")?.asString ?? ""
            if status != "passed" { return no("required check '\(id)' is \(status)") }
        }
        return Verdict(ok: true, reason: nil, recomputedBound: recomputed)
    }

    /// The canonical JSON text of a certificate (the machine-readable artifact).
    public static func encodeSafetyCertificate(_ cert: JSONValue) throws -> String { try canonical(cert) }

    /// Parses a certificate from its JSON text. Shape-guarded and bounded at 1 MiB of UTF-8; never throws, nil on anything else. The result
    /// is NOT verified: pass it to `verifySafetyCertificate`.
    public static func decodeSafetyCertificate(_ text: String) -> JSONValue? {
        if text.utf8.count > Canonical.MAX_JSON_BYTES { return nil }
        guard let parsed = try? StrictJSON.parseLenient(text) else { return nil }
        let v = IV.normalized(parsed)
        guard case let .object(o) = v, IV.num(o["v"]) == Double(SAFETY_CERT_VERSION), o["sig"]?.asString != nil, o["guardian"]?.asString != nil else { return nil }
        switch o["params"] {
        case .object?, .array?: return v
        default: return nil
        }
    }

    /// A compliance-export row of a certificate that verifies under `opts` (which checks ran and where the evidence is), else nil. Not a
    /// safety claim.
    public static func safetyCertificateForCompliance(_ cert: JSONValue?, _ opts: VerifyOptions = VerifyOptions()) -> JSONValue? {
        guard verifySafetyCertificate(cert, opts).ok, case let .object(c)? = cert else { return nil }
        var row: JObject = [:]
        row[o: "control"] = .string(SAFETY_CERT_SCOPE)
        row[o: "guardian"] = c["guardian"]
        row[o: "issued_at"] = c["issued_at"]
        row[o: "bound"] = c["bound"]
        row[o: "checks"] = .array((c["checks"]?.asArray ?? []).map { k in
            let ref = k.get("evidence")?.get("ref")?.asString ?? ""
            var e: JObject = [:]
            e[o: "id"] = k.get("id")
            e[o: "status"] = k.get("status")
            e[o: "evidence"] = .string(k.get("evidence")?.get("kind")?.asString == "sha256" ? "sha256:\(ref)" : ref)
            return .object(e)
        })
        return .object(row)
    }
}
