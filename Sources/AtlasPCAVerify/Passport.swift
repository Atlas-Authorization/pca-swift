import Foundation

// Signed agent passport verification: the native counterpart of `verifyPassport` in @atlasauth/pca. Same reason codes and
// check order. Every signature suite this verifier implements for PCActns (`PCASuites.supported`) is accepted, the
// post-quantum ones only under a PQ key pinned for the issuer (`pqPins`); a suite it does not implement is refused with
// `unsupported_suite`. The hardware branch enforces the evidence age rule, the binding handed to the verifier and the identity
// comparison here; the verifier itself is the integrator's `attest`, or the built-in vendor verifier of `defaultHardware`
// (AMD SEV-SNP, Intel TDX, Azure MAA, Google Confidential Space, NVIDIA GPU; see `VendorVerifier`). With neither, a
// hardware_rooted passport that passes every other check is refused with `hardware_verifier_missing` (never a software pass).

/// What the quote's bound value must equal: holder = the subject key, grant = `passport:<id>`, epoch 0, the evidence nonce.
public struct PassportBinding: Equatable, Sendable {
    public let holderPub: String
    public let grantRef: String
    public let epoch: Int64
    public let nonce: String
}

/// A hardware verifier's answer. `measured` holds model_id, operator, weights_digest, weights_measured, runtime_measurement,
/// system_prompt_digest and tool_manifest_digest as the hardware measured them.
public struct PassportAttestation: Sendable {
    public var ok: Bool
    public var bound: Bool
    public var measured: JObject?
    public init(ok: Bool, bound: Bool, measured: JObject? = nil) {
        self.ok = ok
        self.bound = bound
        self.measured = measured
    }
}

/// The built-in hardware verifier of `verifyPassport`, used when no integrator `attest` is given. `evidence` returns the vendor
/// evidence object for the passport's evidence document (nil: none); when it is nil the evidence document itself is the vendor evidence.
public struct DefaultHardware {
    public let verifier: any HardwareAttestationVerifier
    public let evidence: ((JSONValue) -> JSONValue?)?
    public init(verifier: any HardwareAttestationVerifier, evidence: ((JSONValue) -> JSONValue?)? = nil) {
        self.verifier = verifier
        self.evidence = evidence
    }
}

public struct PassportOptions {
    public var trustedIssuers: [String]
    public var nowMs: Int64
    public var clockSkewMs: Int64?
    public var maxEvidenceAgeMs: Int64?
    /// When set, the passport's `sub` must equal it.
    public var subject: String?
    /// The PQ public key pinned for an issuer key (required for every non-Ed25519 suite).
    public var pqPins: [String: String]
    public var attest: ((JSONValue, PassportBinding) throws -> PassportAttestation)?
    public var defaultHardware: DefaultHardware?
    /// `(id, iss, sub) -> revoked?`; nil means no revocation source (`revocation_unavailable`). A throw denies.
    public var revoked: ((String, String, String) throws -> Bool)?

    public init(trustedIssuers: [String], nowMs: Int64, clockSkewMs: Int64? = nil, maxEvidenceAgeMs: Int64? = nil, subject: String? = nil,
                pqPins: [String: String] = [:], attest: ((JSONValue, PassportBinding) throws -> PassportAttestation)? = nil,
                defaultHardware: DefaultHardware? = nil, revoked: ((String, String, String) throws -> Bool)? = nil) {
        self.trustedIssuers = trustedIssuers
        self.nowMs = nowMs
        self.clockSkewMs = clockSkewMs
        self.maxEvidenceAgeMs = maxEvidenceAgeMs
        self.subject = subject
        self.pqPins = pqPins
        self.attest = attest
        self.defaultHardware = defaultHardware
        self.revoked = revoked
    }
}

/// `ok` with the verified passport, or a distinct `reason` (and an optional `detail`).
public struct PassportVerdict {
    public let ok: Bool
    public let reason: String
    public let detail: String?
    public let passport: JSONValue?
    public let iss: String
    public let sub: String
    public let exp: Int64
    public let hardwareVerified: Bool

    static func bad(_ reason: String, _ detail: String? = nil) -> PassportVerdict {
        PassportVerdict(ok: false, reason: reason, detail: detail, passport: nil, iss: "", sub: "", exp: 0, hardwareVerified: false)
    }
}

extension PCA {
    public static let PASSPORT_SIG_DOMAIN = "atlas-pca/passport-sig/v1\u{0}"
    public static let PASSPORT_VERSION: Int64 = 1
    static let PASSPORT_MAX_SKEW_MS: Int64 = 60_000
    /// Default ceiling on the age of a hardware quote a passport carries (24 h).
    public static let DEFAULT_PASSPORT_EVIDENCE_AGE_MS: Int64 = 24 * 3_600_000

    /// Content fingerprint over the identity fields (stable id; excludes `id` itself). nil where the reference throws.
    public static func passportFingerprint(_ p: JObject) -> String? {
        var o: JObject = ["d": .string("atlas-pca/passport/v1"), "operator": p["operator"] ?? .null, "hardware_rooted": p["hardware_rooted"] ?? .null]
        for k in ["model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"] {
            o[JKey(k)] = p[JKey(k)] ?? .null
        }
        return IV.strictHash(.object(o))
    }

    /// The binding a hardware quote must carry for this passport.
    public static func passportEvidenceBinding(passportId: String, subject: String, nonce: String) -> PassportBinding {
        PassportBinding(holderPub: subject, grantRef: "passport:\(passportId)", epoch: 0, nonce: nonce)
    }

    static func nonEmpty(_ v: JSONValue?) -> String? {
        if let s = v?.asString, !s.isEmpty { return s }
        return nil
    }

    /// Verify a signed passport. Fails closed with a distinct reason; never traps.
    public static func verifyPassport(_ sp: JSONValue?, _ o: PassportOptions) -> PassportVerdict {
        guard case let .object(s)? = sp, IV.same(s["typ"]?.asString, "atlas-pca/passport"), case let .object(p)? = s["passport"] else {
            return .bad("malformed")
        }
        guard let ver = s["ver"]?.safeInt, ver == PASSPORT_VERSION else { return .bad("unsupported_version", s["ver"].map { IntentV2.jsString($0) } ?? "undefined") }
        if let alg = s["alg"], IV.suiteError(alg) != nil { return .bad("unsupported_suite", IntentV2.jsString(alg)) }
        guard let iss = nonEmpty(s["iss"]), let sub = nonEmpty(s["sub"]), nonEmpty(s["sig"]) != nil, let id = nonEmpty(p["id"]),
              nonEmpty(p["model_id"]) != nil, nonEmpty(p["operator"]) != nil, case let .bool(hw)? = p["hardware_rooted"] else {
            return .bad("malformed")
        }
        guard let iat = s["iat"]?.safeInt, let nbf = s["nbf"]?.safeInt, let exp = s["exp"]?.safeInt, iat >= -Canonical.MAX_SAFE,
              o.nowMs <= Canonical.MAX_SAFE, o.nowMs >= -Canonical.MAX_SAFE, exp > nbf else { return .bad("malformed", "times") }
        if !o.trustedIssuers.contains(where: { IV.same($0, iss) }) { return .bad("unknown_issuer") }
        if !IntentWB.verifyArtifactSig(PASSPORT_SIG_DOMAIN, s, iss, pqPin: o.pqPins[iss]) { return .bad("bad_signature") }
        guard let want = passportFingerprint(p) else { return .bad("malformed", "fingerprint") }
        if !IV.same(want, id) { return .bad("id_mismatch") }
        let skew = min(max(o.clockSkewMs ?? 0, 0), PASSPORT_MAX_SKEW_MS)
        if o.nowMs + skew < nbf { return .bad("not_yet_valid") }
        if o.nowMs - skew >= exp { return .bad("expired") }
        if let want = o.subject, !IV.same(want, sub) { return .bad("subject_mismatch") }
        guard let revoked = o.revoked else { return .bad("revocation_unavailable", "no revocation source") }
        do {
            if try revoked(id, iss, sub) { return .bad("revoked") }
        } catch {
            return .bad("revocation_unavailable")
        }
        if hw {
            guard case let .object(ev)? = s["evidence"], let doc = ev["document"], let nonce = nonEmpty(doc.get("nonce")) else {
                return .bad("hardware_evidence_missing")
            }
            guard let at = ev["at"]?.safeInt else { return .bad("hardware_evidence_missing", "evidence.at") }
            let maxAge = o.maxEvidenceAgeMs ?? DEFAULT_PASSPORT_EVIDENCE_AGE_MS
            if maxAge < 0 || o.nowMs - at > maxAge || at - o.nowMs > skew { return .bad("hardware_evidence_stale") }
            var attest = o.attest
            if attest == nil, let d = o.defaultHardware {
                let now = o.nowMs
                attest = { doc, b in
                    var e: JSONValue? = doc
                    if let f = d.evidence { e = f(doc) }
                    let r = d.verifier.verify(evidence: e, expected: AttestationBinding(holderPub: b.holderPub, grantRef: b.grantRef, epoch: Double(b.epoch), nonce: b.nonce), nowMs: now)
                    return PassportAttestation(ok: r.ok, bound: r.bound, measured: r.measured)
                }
            }
            guard let attestFn = attest else { return .bad("hardware_verifier_missing") }
            let r: PassportAttestation
            do { r = try attestFn(doc, passportEvidenceBinding(passportId: id, subject: sub, nonce: nonce)) } catch {
                return .bad("hardware_attestation_failed", "\(error)")
            }
            if !r.ok || !r.bound { return .bad("hardware_attestation_failed") }
            if !passportIdentityMatches(p, r.measured) { return .bad("hardware_identity_mismatch") }
        }
        return PassportVerdict(ok: true, reason: "", detail: nil, passport: .object(p), iss: iss, sub: sub, exp: exp, hardwareVerified: hw)
    }

    /// The hardware-measured identity equals the claims: model and operator always; the optional digests and the runtime
    /// measurement when the passport states them; measured weights when it claims them.
    static func passportIdentityMatches(_ p: JObject, _ m: JObject?) -> Bool {
        guard let m = m else { return false }
        func eq(_ k: String) -> Bool {
            guard let a = p[JKey(k)]?.asString, let b = m[JKey(k)]?.asString else { return false }
            return IV.same(a, b)
        }
        if !eq("model_id") || !eq("operator") { return false }
        for k in ["weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"] where p[JKey(k)] != nil && !eq(k) { return false }
        if p["weights_measured"] == .bool(true) && m["weights_measured"] != .bool(true) { return false }
        return true
    }
}
