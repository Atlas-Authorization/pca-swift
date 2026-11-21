import Foundation

/// The post-quantum software / HSM attestation root: a statement minted under a post-quantum or hybrid suite (domain `atlas-pca/attest-pq/v1\0`) and
/// the verifier that checks it against trusted PQ keys, the binding and a measurement allowlist. Software or HSM attested, NOT silicon-measured: the
/// identity it yields never carries `weights_measured`. The statement is the language-neutral JSON of the wire.
public enum PCAAttestPq {
    public static let PQ_ATTEST_DOMAIN = "atlas-pca/attest-pq/v1\u{0}"

    private static func suiteHasPq(_ s: PQ.Suite) -> Bool { s.pq != nil || s.slh != nil }
    /// An Ed25519 half: plain Ed25519 and every hybrid.
    private static func hasEd25519(_ s: PQ.Suite) -> Bool { s.needsPqSig || s.alg.rawValue == "ed25519" }

    private static func message(_ body: JObject) throws -> [UInt8] { try PCAIntentKit.message(PQ_ATTEST_DOMAIN, .object(body)) }

    // MARK: the attestor

    /// Mints statements under a post-quantum suite. `pqPublicKey` is the b64u PQ key a verifier trusts; `ed25519PublicKey` is present for a hybrid.
    public struct Attestor {
        public let pqPublicKey: String
        public let ed25519PublicKey: String?
        let key: PCASuiteKey

        /// `{measurement, holder_pub, grant_ref, epoch, nonce}` plus the optional `weights_digest`, `system_prompt_digest`, `tool_manifest_digest`,
        /// `model_id`, `operator`. The statement carries the binding to holder, grant, epoch and nonce, the suite and the keys, signed as canonical JSON.
        public func attest(_ claims: JSONValue) throws -> JSONValue {
            let binding = try PCAAttestation.attestationBindingB64u(.object(["holderPub": claims.get("holder_pub") ?? .null, "grantRef": claims.get("grant_ref") ?? .null,
                                                                             "epoch": claims.get("epoch") ?? .null, "nonce": claims.get("nonce") ?? .null]))
            guard let measurement = claims.get("measurement") else { throw JSError("canonicalize: unsupported type undefined") }
            var body: JObject = ["measurement": measurement, "binding": .string(binding), "alg": .string(key.alg)]
            if let pk = key.pqPk { body["pq_pk"] = .string(pk) }
            if let ed = ed25519PublicKey { body["attestor_ed25519"] = .string(ed) }
            for k in ["weights_digest", "system_prompt_digest", "tool_manifest_digest", "model_id", "operator"] { if let v = claims.get(k) { body[JKey(k)] = v } }
            let parts = try key.sign(try message(body))
            var out = body
            out["sig"] = .string(parts.sig)
            if let q = parts.pqSig { out["pq_sig"] = .string(q) }
            return .object(out)
        }
    }

    /// An attestor over `key`: a pure post-quantum suite (ML-DSA, SLH-DSA) or a hybrid with an Ed25519 key. A classical-only suite is refused.
    public static func createPqSoftwareAttestor(_ key: PCASuiteKey) throws -> Attestor {
        guard suiteHasPq(key.suite) else { throw JSError("createPqSoftwareAttestor: '\(key.alg)' is classical; the PQ root requires a post-quantum suite") }
        if key.suite.needsPqPk && key.pqPk == nil { throw JSError("createPqSoftwareAttestor: '\(key.alg)' requires the matching PQ key material") }
        if key.suite.needsPqSig && key.ed == nil { throw JSError("createPqSoftwareAttestor: hybrid suite '\(key.alg)' requires edSecret") }
        return Attestor(pqPublicKey: key.pqPk ?? "", ed25519PublicKey: key.ed.map { Base64URLStrict.encode($0.pub) }, key: key)
    }

    // MARK: the verifier

    public struct Policy {
        /// The allowed launch measurements: NON-EMPTY (accept-all is not permitted).
        public var measurements: [String]
        /// When non-empty, the statement's `weights_digest` must be one of these.
        public var weightsMeasurements: [String]?
        /// Builds the measured identity of a verified statement (default: `defaultIdentity`).
        public var deriveIdentity: ((JSONValue) -> JSONValue)?
        public init(measurements: [String], weightsMeasurements: [String]? = nil, deriveIdentity: ((JSONValue) -> JSONValue)? = nil) {
            self.measurements = measurements; self.weightsMeasurements = weightsMeasurements; self.deriveIdentity = deriveIdentity
        }
    }

    public struct VerifierOptions {
        public var trustedPqPublicKeys: [String]
        public var trustedEd25519PublicKeys: [String]?
        /// Default true: a classical-only suite is refused.
        public var requirePq: Bool
        public var requireHybrid: Bool
        /// When set, only these suites are accepted.
        public var allowedSuites: [String]?
        public var policy: Policy
        /// Finds the statement of an action from its document and context; without it every verification fails closed.
        public var resolveEvidence: ((JSONValue, JSONValue) throws -> JSONValue?)?
        public init(trustedPqPublicKeys: [String], policy: Policy, trustedEd25519PublicKeys: [String]? = nil, requirePq: Bool = true, requireHybrid: Bool = false,
                    allowedSuites: [String]? = nil, resolveEvidence: ((JSONValue, JSONValue) throws -> JSONValue?)? = nil) {
            self.trustedPqPublicKeys = trustedPqPublicKeys; self.policy = policy; self.trustedEd25519PublicKeys = trustedEd25519PublicKeys; self.requirePq = requirePq
            self.requireHybrid = requireHybrid; self.allowedSuites = allowedSuites; self.resolveEvidence = resolveEvidence
        }
    }

    /// The default identity of a statement: the measurement is the runtime measurement; the weights are never marked hardware-measured.
    public static func defaultIdentity(_ st: JSONValue) -> JSONValue {
        var o: JObject = ["model_id": .string(st.get("model_id")?.asString ?? ""), "weights_digest": .string(st.get("weights_digest")?.asString ?? ""),
                          "weights_measured": .bool(false), "runtime_measurement": st.get("measurement") ?? .null, "operator": .string(st.get("operator")?.asString ?? "")]
        for k in ["system_prompt_digest", "tool_manifest_digest"] { if case .string? = st.get(k), let v = st.get(k) { o[JKey(k)] = v } }
        return .object(o)
    }

    /// The verifier, as a hardware verifier (software assurance, vendor `pq-software`).
    public final class Verifier: PCAAttestationHardwareVerifier, AssuranceLabeled {
        private let o: VerifierOptions
        public let assuranceLabel = AssuranceLabel(level: "software", vendor: "pq-software")

        init(_ o: VerifierOptions) { self.o = o }

        public func verify(document: JSONValue, ctx: JSONValue, nowMs: Double, expected: JSONValue) throws -> PCAAttestation.HardwareResult {
            func fail(_ r: String) -> PCAAttestation.HardwareResult { PCAAttestation.HardwareResult(ok: false, reason: r) }
            do {
                guard let resolve = o.resolveEvidence else { return fail("no PQ-software evidence resolver configured (fail closed)") }
                guard let st = try resolve(document, ctx), st.isObject, let alg = st.get("alg")?.asString else { return fail("no PQ-software attestation statement for this action") }
                guard let suite = PQ.resolve(alg) else { return fail("PQ statement declares an unknown signature alg '\(alg)'") }
                let name = suite.alg.rawValue
                if o.requirePq && !PCAAttestPq.suiteHasPq(suite) { return fail("PQ required: a classical-only suite '\(name)' is not accepted by the post-quantum root") }
                if o.requireHybrid && !(suite.needsPqSig && PCAAttestPq.suiteHasPq(suite)) { return fail("hybrid required: suite '\(name)' is not a classical+PQ hybrid") }
                if let allowed = o.allowedSuites, !allowed.contains(where: { IV.same($0, name) }) { return fail("suite '\(name)' is not in the allowed-suites list") }
                let pk = st.get("pq_pk")?.asString
                if suite.needsPqPk, !(pk.map { p in o.trustedPqPublicKeys.contains { IV.same($0, p) } } ?? false) { return fail("PQ attestor key is not trusted") }
                let ed = st.get("attestor_ed25519")?.asString
                if PCAAttestPq.hasEd25519(suite), !(ed.map { e in (o.trustedEd25519PublicKeys ?? []).contains { IV.same($0, e) } } ?? false) { return fail("hybrid Ed25519 attestor key is not trusted") }

                var body = st.asObject ?? [:]
                body["sig"] = nil
                body["pq_sig"] = nil
                let msg = try PCAAttestPq.message(body)
                let ok: Bool
                if case .string? = st.get("sig") {
                    // the trusted key (membership already checked) is the pin of the statement's own key
                    ok = IV.verifyPinned(alg: .string(alg), identity: ed ?? "", artifactPqPk: suite.needsPqPk ? st.get("pq_pk") : nil, msg: msg, sig: st.get("sig"),
                                         pqSig: st.get("pq_sig"), pin: suite.needsPqPk ? pk : nil) == .valid
                } else { ok = false }
                if !ok { return fail("PQ attestation signature does not verify") }

                guard JS.truthy(expected) else { return fail("no expected attestation binding supplied") }
                let want: String
                do { want = try PCAAttestation.attestationBindingB64u(expected) } catch { return fail("binding not constructible: \((error as? JSError)?.message ?? "invalid")") }
                guard let b = st.get("binding")?.asString, !b.isEmpty else { return fail("PQ statement is not bound (binding absent)") }
                if !IV.same(b, want) { return fail("PQ statement binding mismatch (holder/grant/epoch/nonce)") }

                guard let m = st.get("measurement")?.asString, o.policy.measurements.contains(where: { IV.same($0, m) }) else { return fail("measurement not in policy allowlist") }
                if let w = o.policy.weightsMeasurements, !w.isEmpty {
                    guard let d = st.get("weights_digest")?.asString, w.contains(where: { IV.same($0, d) }) else { return fail("measured weights digest not in policy allowlist") }
                }
                let measured = (o.policy.deriveIdentity ?? PCAAttestPq.defaultIdentity)(st)
                return PCAAttestation.HardwareResult(ok: true, measured: measured, bound: true, hostAsserted: ["suite": name])
            } catch {
                return fail("pq-software verification error (fail closed): \((error as? JSError)?.message ?? "unknown")")
            }
        }
    }

    /// Builds the verifier. Throws on an empty measurement allowlist (accept-all is not permitted) and on no trusted PQ key (fail closed).
    public static func createPqSoftwareVerifier(_ o: VerifierOptions) throws -> Verifier {
        if o.policy.measurements.isEmpty { throw JSError("createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)") }
        if o.trustedPqPublicKeys.isEmpty { throw JSError("createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)") }
        return Verifier(o)
    }
}
