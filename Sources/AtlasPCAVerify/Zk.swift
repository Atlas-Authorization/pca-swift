import Foundation

// Zero-knowledge proof of compliance (intent privacy from the resource server). The agent proves "this action is a valid derivation
// under the policy from the committed plan" without showing the policy, the plan or its reasoning: the verifier works on commitments only.
// Two realisations, as in the reference:
//   * a Groth16 proof over a compliance circuit (the first circuit `pca-compliance-v1`, the full Policy-VM circuit `pca-policyvm-v1` on
//     BN254 and on BLS12-381, and the risk-bound `pca-policyvm-v2`), in the snarkjs JSON encoding;
//   * the attested-VM equivalent: a trusted prover VM runs the Policy VM and signs a statement that carries only commitments.
// Everything here is plain logic (hashes, canonical JSON, Ed25519, integer checks). The one thing it does not contain is the pairing
// check and the prover: those come from an engine registered through `PCAZkHook` (the opt-in AtlasPCAZk product registers one). With no
// engine a proof is never accepted: `verifyPolicyVmProof` answers false and a backend that reaches the engine throws.

/// The Groth16 engine behind `PCAZk`. Nothing registers at import: the opt-in AtlasPCAZk product does it through
/// `PCAZkNative.registerCore()`. An engine that throws or answers anything but true is a refusal.
public enum PCAZkHook {
    public struct Engine {
        /// The pairing check of a snarkjs proof: `vkey` is the verification key object, `publicSignals` the decimal strings, `proof` the proof object.
        public let verify: (_ vkey: JSONValue, _ publicSignals: [JSONValue], _ proof: JSONValue) throws -> Bool
        /// Witness generation and proving: `curve` is "bn254" or "bls12-381", `wasm` the circuit's witness program, `zkey` its proving key and
        /// `input` the circuit input object. Returns `{"proof": {...}, "publicSignals": [...]}`.
        public let prove: (_ curve: String, _ wasm: [UInt8], _ zkey: [UInt8], _ input: JSONValue) throws -> JSONValue
        public init(verify: @escaping (_ vkey: JSONValue, _ publicSignals: [JSONValue], _ proof: JSONValue) throws -> Bool,
                    prove: @escaping (_ curve: String, _ wasm: [UInt8], _ zkey: [UInt8], _ input: JSONValue) throws -> JSONValue) {
            self.verify = verify; self.prove = prove
        }
    }
    private static let lock = NSLock()
    private static var engine: Engine?
    public static func register(_ e: Engine) { lock.lock(); engine = e; lock.unlock() }
    public static func unregister() { lock.lock(); engine = nil; lock.unlock() }
    public static var isRegistered: Bool { lock.lock(); defer { lock.unlock() }; return engine != nil }
    static func current() throws -> Engine {
        lock.lock(); defer { lock.unlock() }
        guard let e = engine else { throw JSError("no Groth16 engine is registered (add the AtlasPCAZk product and call PCAZkNative.registerCore())") }
        return e
    }
}

/// A backend that verifies the proof carried in `zk_compliance` against the three commitments. It declares its proof system by also
/// conforming to `AssuranceLabeled` (the library's own backends do); an unlabelled backend is reported as `unknown`.
public protocol PCAZkSnarkBackend {
    func verify(proof: JSONValue?, publicInputs: PCAZk.PublicInputs, ctx: PCAZk.VerifyContext) throws -> Bool
}

public enum PCAZk {
    // ---- commitments, the attested-VM statement -------------------------------------------------------------------------

    static let DOMAIN = "atlas-pca/zk-compliance/v1\u{0}"
    /// `grantRef` of the binding a prover VM's hardware quote carries (see `proverKeyBinding`).
    public static let ZK_PROVER_BINDING_REF = "atlas-pca/zk-prover/v1"

    /// The reference's `hashCanonical`: base64url(sha256(strict canonical JSON)); an absent value is refused.
    static func hash(_ v: JSONValue?) throws -> String {
        guard let v = v else { throw JSError("canonicalize: unsupported type undefined") }
        return Base64URLStrict.encode(Canonical.sha256(Array(try Canonical.canonicalizeStrict(v).utf8)))
    }

    /// Commitment to the policy: the grant's content address (its `id` when it is a string, else the hash of the value).
    public static func policyCommitment(_ grant: JSONValue?) throws -> String {
        if let id = grant?.get("id")?.asString { return id }
        return try hash(grant)
    }

    /// The policy commitment a resource server pins when it may not read the grant.
    public static func pinnedPolicyCommitment(_ grant: JSONValue?) throws -> String { try policyCommitment(grant) }

    /// Commitment to the action: the content address of the PCActn's action descriptor (of null when there is none).
    public static func actionCommitment(_ pcactn: JSONValue?) throws -> String { try hash(JS.present(pcactn?.get("action")) ?? .null) }

    /// The value a prover VM puts in its hardware quote so that the quote vouches for its key, for this epoch and nonce.
    public static func proverKeyBinding(_ proverPublicKey: String, epoch: Double, nonce: String) -> AttestationBinding {
        AttestationBinding(holderPub: proverPublicKey, grantRef: ZK_PROVER_BINDING_REF, epoch: epoch, nonce: nonce)
    }

    static func statementMessage(_ body: JSONValue) throws -> [UInt8] {
        // the reference's strict canonicalizer refuses a lone surrogate (the harness carries one as a sentinel scalar): the verifier fails closed on it
        if IV.hasSentinel(body) { throw JSError("canonicalize: lone surrogate in string") }
        return Array(DOMAIN.utf8) + Array(try Canonical.canonicalizeStrict(body).utf8)
    }

    static func jnum(_ d: Double) -> JSONValue { d.isFinite && d.rounded() == d && abs(d) <= Double(Canonical.MAX_SAFE) ? .int(Int64(d)) : .double(d) }
    static func planRoot(_ pcactn: JSONValue?) -> String { pcactn?.get("plan")?.get("root")?.asString ?? "" }

    /// `a === b` over JSON values: numbers by value, strings code point by code point, and never two arrays or two objects (two parsed
    /// values are never the same object).
    static func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        guard let x = a, let y = b else { return a == nil && b == nil }
        if x.isObject || x.isArray { return false }
        if let p = IV.num(x), let q = IV.num(y) { return p == q }
        return x == y
    }

    /// The attested-VM prover: runs the Policy VM and, only when it releases, signs a statement that commits to the action, policy and plan.
    public struct AttestedComplianceProver {
        /// The base64url public key a resource server lists in `trustedProverKeys`.
        public let publicKey: String
        let key: PCAEdKey

        /// Throws when the action is not compliant: a false statement cannot be made.
        public func prove(pcactn: JSONValue?, decideInput: JSONValue, issuedAt: Double, expiresAt: Double) throws -> JSONValue {
            let decision = try PCAPolicyVm.decide(decideInput)
            guard JS.truthy(decision.get("releaseGuardianShare")) else {
                let reasons = (decision.get("reasons")?.asArray ?? []).map { JS.toString($0) }.joined(separator: "; ")
                throw JSError("createAttestedComplianceProver: action is not compliant, nothing to prove (\(reasons))")
            }
            var body: JObject = [:]
            body[o: "v"] = .int(1)
            body[o: "mode"] = .string("attested-vm")
            body[o: "action_commit"] = .string(try PCAZk.actionCommitment(pcactn))
            body[o: "policy_commit"] = .string(try PCAZk.policyCommitment(decideInput.get("grant")))
            body[o: "plan_commit"] = .string(PCAZk.planRoot(pcactn))
            body[o: "released"] = .bool(true)
            body[o: "r"] = decision.get("r")
            body[o: "issued_at"] = PCAZk.jnum(issuedAt)
            body[o: "expires_at"] = PCAZk.jnum(expiresAt)
            body[o: "prover"] = .string(publicKey)
            let sig = try key.sign(try PCAZk.statementMessage(.object(body)))
            body[o: "sig"] = .string(Base64URLStrict.encode(sig))
            return .object(body)
        }
    }

    public static func createAttestedComplianceProver(_ key: PCAEdKey) -> AttestedComplianceProver { AttestedComplianceProver(publicKey: key.id, key: key) }

    /// The three commitments a backend receives as public inputs.
    public struct PublicInputs {
        public var actionCommit: String
        public var policyCommit: String
        public var planCommit: String
        public init(actionCommit: String, policyCommit: String, planCommit: String) {
            self.actionCommit = actionCommit; self.policyCommit = policyCommit; self.planCommit = planCommit
        }
    }

    /// What the verifier hook was called with.
    public struct VerifyContext {
        public var pcactn: JSONValue?
        public var grant: JSONValue?
        public init(pcactn: JSONValue? = nil, grant: JSONValue? = nil) { self.pcactn = pcactn; self.grant = grant }
    }

    /// One of the library's backends: its check and its assurance label.
    public struct SnarkBackend: PCAZkSnarkBackend, AssuranceLabeled {
        public let assuranceLabel: AssuranceLabel
        let check: (_ proof: JSONValue?, _ publicInputs: PublicInputs) throws -> Bool
        public func verify(proof: JSONValue?, publicInputs: PublicInputs, ctx: VerifyContext) throws -> Bool { try check(proof, publicInputs) }
    }

    /// Binds the attested-VM prover key to hardware evidence of the VM measurement.
    public struct ProverAttestationOpts {
        /// A vendor or multi-root verifier. It must carry a `hardware` or `multi_root` assurance label.
        public var hardwareVerifier: HardwareAttestationVerifier
        /// The prover's hardware evidence, looked up by its public key (nil: none).
        public var evidence: (_ proverPublicKey: String) throws -> JSONValue?
        /// The binding the quote must carry for this prover key. Throwing denies.
        public var expectedBinding: (_ proverPublicKey: String) throws -> AttestationBinding
        /// Accepted runtime measurements; an empty list is refused.
        public var measurements: [String]
        public init(hardwareVerifier: HardwareAttestationVerifier, evidence: @escaping (_ proverPublicKey: String) throws -> JSONValue?,
                    expectedBinding: @escaping (_ proverPublicKey: String) throws -> AttestationBinding, measurements: [String]) {
            self.hardwareVerifier = hardwareVerifier; self.evidence = evidence; self.expectedBinding = expectedBinding; self.measurements = measurements
        }
    }

    public struct ZkVerifierOpts {
        /// Public keys of the prover VMs trusted in attested-VM mode.
        public var trustedProverKeys: [String]
        /// The expected policy commitments, as bare hashes. nil: the commitment is derived from the grant in hand.
        public var policyCommitments: [String]?
        /// Given: the proof is handed to this backend with the three commitments.
        public var snarkBackend: PCAZkSnarkBackend?
        /// Prover keys that are no longer trusted, even when still listed above.
        public var revokedProverKeys: [String]
        /// Attested-VM mode only: require hardware evidence for the prover key.
        public var proverAttestation: ProverAttestationOpts?
        /// The clock, epoch milliseconds.
        public var now: (() -> Double)?
        /// Allowed clock skew in milliseconds (not finite or negative: 0).
        public var clockSkewMs: Double?
        public init(trustedProverKeys: [String] = [], policyCommitments: [String]? = nil, snarkBackend: PCAZkSnarkBackend? = nil, revokedProverKeys: [String] = [],
                    proverAttestation: ProverAttestationOpts? = nil, now: (() -> Double)? = nil, clockSkewMs: Double? = nil) {
            self.trustedProverKeys = trustedProverKeys; self.policyCommitments = policyCommitments; self.snarkBackend = snarkBackend
            self.revokedProverKeys = revokedProverKeys; self.proverAttestation = proverAttestation; self.now = now; self.clockSkewMs = clockSkewMs
        }
    }

    /// The zk verifier hook with its assurance label. `hook` is its form for the gateway options.
    public struct ZkVerifier: AssuranceLabeled {
        public let assuranceLabel: AssuranceLabel
        let run: (_ pcactn: JSONValue?, _ grant: JSONValue?) -> PCAGateway.HookOutcome
        public func verify(pcactn: JSONValue?, grant: JSONValue?) -> PCAGateway.HookOutcome { run(pcactn, grant) }
        public var hook: PCAGateway.VerifyHook {
            let r = run
            return { p, g, _ in r(p, g) }
        }
    }

    /// The verifier hook for the proof carried in `zk_compliance`. With a backend: the three commitments of this PCActn are handed to it.
    /// Without: the proof is an attested-VM statement, checked for a trusted and unrevoked prover, its signature, its validity window and
    /// its commitments (and, when configured, hardware evidence for the prover key). Any error is a refusal.
    public static func createZkVerifier(_ opts: ZkVerifierOpts) throws -> ZkVerifier {
        let pa = opts.snarkBackend == nil ? opts.proverAttestation : nil
        var hwLabel: AssuranceLabel?
        if let pa = pa {
            hwLabel = PCA.labelOf(pa.hardwareVerifier)
            guard hwLabel?.level == "hardware" || hwLabel?.level == "multi_root" else {
                throw JSError("createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label")
            }
            guard !pa.measurements.isEmpty, !pa.measurements.contains("") else { throw JSError("createZkVerifier: proverAttestation.measurements must be a non-empty allowlist") }
        }
        let label: AssuranceLabel
        if let b = opts.snarkBackend {
            label = PCA.labelOf(b) ?? AssuranceLabel(level: "unknown")
        } else if let hw = hwLabel {
            label = AssuranceLabel(level: "attested_vm_hw", vendor: "hardware-bound:\(hw.vendor ?? hw.level)")
        } else {
            label = AssuranceLabel(level: "attested_vm")
        }

        let trusted = Set(opts.trustedProverKeys.map { JKey($0) })
        let revoked = Set(opts.revokedProverKeys.map { JKey($0) })
        let expectedPolicy = opts.policyCommitments.map { Set($0.map { JKey($0) }) }
        let measurements = Set((pa?.measurements ?? []).map { JKey($0) })
        let clock = opts.now ?? { Date().timeIntervalSince1970 * 1000 }
        let skew = (opts.clockSkewMs?.isFinite ?? false) ? max(0, opts.clockSkewMs ?? 0) : 0
        let backend = opts.snarkBackend

        func fail(_ reason: String) -> PCAGateway.HookOutcome { PCAGateway.HookOutcome(enforced: true, ok: false, reason: reason) }
        func check(_ pcactn: JSONValue?, _ grant: JSONValue?) throws -> PCAGateway.HookOutcome {
            guard let proof = JS.present(pcactn?.get("zk_compliance")) else { return fail("no zk_compliance proof present") }
            let actionCommit = try actionCommitment(pcactn)
            let planCommit = planRoot(pcactn)
            let derived: String? = try (expectedPolicy == nil ? policyCommitment(grant) : nil)

            if let backend = backend {
                let policyCommit: String
                if let e = expectedPolicy, e.count == 1, let only = e.first { policyCommit = only.s } else { policyCommit = try derived ?? policyCommitment(grant) }
                let ok = try backend.verify(proof: proof, publicInputs: PublicInputs(actionCommit: actionCommit, policyCommit: policyCommit, planCommit: planCommit),
                                            ctx: VerifyContext(pcactn: pcactn, grant: grant))
                return ok ? PCAGateway.HookOutcome(enforced: true, ok: true) : fail("snark backend rejected the proof")
            }

            func m(_ k: String) -> JSONValue? { JSLoose.get(proof, k) }
            guard IV.num(m("v")) == 1, m("mode") == .string("attested-vm") else { return fail("unrecognized compliance statement") }
            guard m("released") == .bool(true) else { return fail("statement does not assert release") }
            guard let prover = m("prover")?.asString, trusted.contains(JKey(prover)) else { return fail("prover key is not trusted") }
            if revoked.contains(JKey(prover)) { return fail("prover key is revoked") }

            guard let sig = m("sig")?.asString else { return fail("compliance statement signature does not verify") }
            var body = proof.asObject ?? [:]
            body.removeValue(forKey: "sig")
            let message = try statementMessage(.object(body))
            guard Ed25519Strict.verifyB64u(prover, message, sig) else { return fail("compliance statement signature does not verify") }

            guard let issued = IV.num(m("issued_at")), let expires = IV.num(m("expires_at")), issued.isFinite, expires.isFinite, !(expires < issued) else {
                return fail("malformed statement validity window")
            }
            let nowMs = clock()
            if !(nowMs.isFinite && skew.isFinite) { return fail("compliance statement cannot be dated: the clock is not a finite number") }
            if !(nowMs + skew >= issued) { return fail("compliance statement not yet valid") }
            if !(nowMs - skew <= expires) { return fail("compliance statement expired") }

            if !strictEq(m("action_commit"), .string(actionCommit)) { return fail("statement does not bind to this action") }
            if !strictEq(m("plan_commit"), .string(planCommit)) { return fail("statement does not bind to this plan commitment") }
            guard let policy = m("policy_commit")?.asString, expectedPolicy?.contains(JKey(policy)) ?? IV.same(policy, derived) else {
                return fail("statement policy commitment is not an expected policy")
            }

            // the hardware binding of the prover key comes last (the expensive check); anything but a bound, measured, allowlisted identity denies
            if let pa = pa {
                let expected = try pa.expectedBinding(prover)
                guard nowMs.isFinite, let at = Int64(exactly: nowMs.rounded(.towardZero)) else { throw JSError("the clock is not a time") }
                let evidence = try pa.evidence(prover)
                let hw = pa.hardwareVerifier.verify(evidence: evidence, expected: expected, nowMs: at)
                if !hw.ok { return fail("prover hardware evidence invalid: \(hw.reason.isEmpty ? "no reason given" : hw.reason)") }
                if !hw.bound { return fail("prover hardware evidence does not bind the prover key") }
                guard let measured = hw.measured?["runtime_measurement"]?.asString else { return fail("prover hardware evidence carries no measured identity") }
                if !measurements.contains(JKey(measured)) { return fail("prover VM measurement is not allowlisted") }
            }
            return PCAGateway.HookOutcome(enforced: true, ok: true)
        }
        return ZkVerifier(assuranceLabel: label, run: { pcactn, grant in
            do { return try check(pcactn, grant) } catch { return fail("zk verification error (fail closed): \(error)") }
        })
    }

    // ---- the binding tag and the canonical envelope gate ------------------------------------------------------------------

    /// BN254 scalar field modulus (the field the public signals live in).
    static let BN254_FR = BigUInt(decimal: "21888242871839275222246405745257275088548364400416034343698204186575808495617")
    static let BN254_FQ = BigUInt(decimal: "21888242871839275222246405745257275088696311157297823662689037894645226208583")
    static let BLS12381_FQ = JSBigInt.parse("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")!.mag
    static let BLS12381_FR = JSBigInt.parse("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")!.mag

    /// Big-endian bytes of any length, reduced modulo `m`.
    static func mod(_ bytes: [UInt8], _ m: BigUInt) -> BigUInt {
        var acc = BigUInt()
        for b in bytes {
            acc = (acc << 8) + BigUInt(UInt64(b))
            // acc < 256 m here: one conditional subtraction per bit brings it back below m
            for k in stride(from: 7, through: 0, by: -1) {
                let s = m << k
                if !(acc < s) { acc = acc - s }
            }
        }
        return acc
    }

    /// A base64url commitment as a BN254 scalar, in decimal: the circuit's public binding tag. The decoded bytes (of any length) are
    /// reduced modulo the field. Throws when the text is not strict base64url.
    public static func commitmentField(_ b64uCommit: String) throws -> String {
        guard let bytes = Base64URLStrict.decode(b64uCommit) else { throw JSError("commitmentField: the commitment is not base64url") }
        return mod(bytes, BN254_FR).ratchetDecimal
    }

    /// `^(0|[1-9][0-9]*)$`: ASCII digits, no leading zero.
    static func canonDec(_ s: String) -> Bool {
        let b = Array(s.utf8)
        guard !b.isEmpty, b.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return false }
        return b.count == 1 || b[0] != 0x30
    }

    static func canonDecBelow(_ v: JSONValue?, _ bound: BigUInt) -> Bool {
        guard let s = v?.asString, s.utf8.count <= 120, canonDec(s) else { return false }
        return BigUInt(decimal: s) < bound
    }

    static func sameKeys(_ o: JObject, _ keys: [String]) -> Bool { o.count == keys.count && keys.allSatisfy { o[JKey($0)] != nil } }

    /// True only for the one canonical Groth16 envelope of `curve` ("bn254", anything else is read as BLS12-381): the exact member sets,
    /// canonical decimals below the field, z == 1. A proof has many encodings an arithmetic verifier accepts; this gate admits one.
    public static func isCanonicalGroth16Envelope(_ env: JSONValue?, _ curve: String?) -> Bool {
        guard let e = env?.asObject, sameKeys(e, ["system", "circuit", "proof", "publicSignals"]) else { return false }
        let bn = curve.map { IV.same($0, "bn254") } ?? false
        let fq = bn ? BN254_FQ : BLS12381_FQ
        let fr = bn ? BN254_FR : BLS12381_FR
        guard let ps = e["publicSignals"]?.asArray, ps.allSatisfy({ canonDecBelow($0, fr) }) else { return false }
        guard let pr = e["proof"]?.asObject, sameKeys(pr, ["pi_a", "pi_b", "pi_c", "protocol", "curve"]) else { return false }
        guard pr["protocol"] == .string("groth16"), pr["curve"] == .string(bn ? "bn128" : "bls12381") else { return false }
        func g1(_ v: JSONValue?) -> Bool {
            guard let a = v?.asArray, a.count == 3 else { return false }
            return canonDecBelow(a[0], fq) && canonDecBelow(a[1], fq) && a[2] == .string("1")
        }
        guard g1(pr["pi_a"]), g1(pr["pi_c"]) else { return false }
        guard let b = pr["pi_b"]?.asArray, b.count == 3 else { return false }
        for row in [b[0], b[1]] {
            guard let r = row.asArray, r.count == 2, canonDecBelow(r[0], fq), canonDecBelow(r[1], fq) else { return false }
        }
        guard let z = b[2].asArray, z.count == 2 else { return false }
        return z[0] == .string("1") && z[1] == .string("0")
    }

    // ---- the first circuit (pca-compliance-v1, BN254) -------------------------------------------------------------------

    /// Where the reference package keeps its circuit files, relative to the package root. The `build` ones are development setup
    /// output and ship nowhere; the committed Policy-VM keys are in this package's resources (`policyVmVerificationKey`).
    public static let DEFAULT_VKEY_PATH = "circuits/build/verification_key.json"
    public static let DEFAULT_WASM_PATH = "circuits/build/compliance_js/compliance.wasm"
    public static let DEFAULT_ZKEY_PATH = "circuits/build/compliance_final.zkey"
    public static let POLICYVM_VKEY_PATH = "circuits/policyvm_vkey.json"
    public static let POLICYVM_SAMPLE_PROOF_PATH = "circuits/policyvm_sample_proof.json"
    public static let POLICYVM_WASM_PATH = "circuits/build/policyvm_js/policyvm.wasm"
    public static let POLICYVM_ZKEY_PATH = "circuits/build/policyvm_final.zkey"
    public static let POLICYVM_BLS12381_VKEY_PATH = "circuits/policyvm_bls12381_vkey.json"
    public static let POLICYVM_BLS12381_SAMPLE_PROOF_PATH = "circuits/policyvm_bls12381_sample_proof.json"
    public static let POLICYVM_BOUND_VKEY_PATH = "circuits/build/policyvm_bound_vkey.json"
    public static let POLICYVM_BOUND_SAMPLE_PROOF_PATH = "circuits/build/policyvm_bound_sample_proof.json"
    public static let POLICYVM_BOUND_WASM_PATH = "circuits/build/policyvm_bound_js/policyvm_bound.wasm"
    public static let POLICYVM_BOUND_ZKEY_PATH = "circuits/build/policyvm_bound_final.zkey"

    /// A file of the package's zk resources (byte copies of the reference package's committed circuit files).
    static func bundled(_ name: String) throws -> JSONValue {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "zk"), let data = try? Data(contentsOf: url) else {
            throw JSError("zk: \(name).json is missing from the package resources")
        }
        return try StrictJSON.parseLenient(String(decoding: data, as: UTF8.self))
    }

    /// The committed `pca-policyvm-v1` verifying key on BN254 (a development, single-party setup).
    public static func policyVmVerificationKey() throws -> JSONValue { try bundled("policyvm_vkey") }
    /// The committed `pca-policyvm-v1` verifying key on BLS12-381 (a development, single-party setup).
    public static func policyVmVerificationKeyBls12381() throws -> JSONValue { try bundled("policyvm_bls12381_vkey") }

    static func noBundledKey(_ circuit: String) -> JSError {
        JSError("zk: there is no bundled verifying key for \(circuit) (its key is a development build): pass verificationKey")
    }

    /// The options of the four backends. `expectRiskHash` is read by the risk-bound backend only.
    public struct SnarkBackendOpts {
        /// The verifying key (snarkjs JSON). nil or null: the bundled key of the backend's circuit, where there is one.
        public var verificationKey: JSONValue?
        /// Ceremony evidence `{transcript, sha256, r1csSha256?}` for `verificationKey`; without it the label says `single-party`.
        public var ceremony: JSONValue?
        /// The context the proof must have been made for.
        public var expect: PolicyVmExpectSource?
        /// The struct-hash halves the proof's public signals must equal (`policyVmStructHash` over the fields the verifier expects).
        public var expectActionHash: DigestHalves?
        public var expectPolicyHash: DigestHalves?
        public var expectPlanHash: DigestHalves?
        /// The attested risk commitment (`policyVmRiskHash`).
        public var expectRiskHash: DigestHalves?
        public init(verificationKey: JSONValue? = nil, ceremony: JSONValue? = nil, expect: PolicyVmExpectSource? = nil, expectActionHash: DigestHalves? = nil,
                    expectPolicyHash: DigestHalves? = nil, expectPlanHash: DigestHalves? = nil, expectRiskHash: DigestHalves? = nil) {
            self.verificationKey = verificationKey; self.ceremony = ceremony; self.expect = expect; self.expectActionHash = expectActionHash
            self.expectPolicyHash = expectPolicyHash; self.expectPlanHash = expectPlanHash; self.expectRiskHash = expectRiskHash
        }
    }

    /// `multi-party` only for an explicit verifying key backed by pinned ceremony evidence that names this circuit.
    static func ceremonyLabel(_ opts: SnarkBackendOpts, _ circuit: String) -> String {
        guard JS.truthy(opts.ceremony) else { return ceremonyOf(opts.verificationKey, nil) }
        var evidence = opts.ceremony?.asObject ?? [:]
        evidence["circuit"] = .string(circuit)
        return ceremonyOf(opts.verificationKey, .object(evidence))
    }

    /// The backend of the first circuit: the envelope must be a `pca-compliance-v1` proof on BN254 with 7 signals and allow == 1, its three
    /// binding tags must equal `commitmentField` of this request's commitments, it must be the canonical encoding, and the pairing check
    /// must pass under the verifying key (which must be given: this circuit has no bundled key).
    public static func createGroth16SnarkBackend(_ opts: SnarkBackendOpts = SnarkBackendOpts()) -> SnarkBackend {
        SnarkBackend(assuranceLabel: AssuranceLabel(level: "groth16", ceremony: ceremonyLabel(opts, "pca-compliance-v1"))) { proof, inputs in
            guard let env = proof?.asObject else { return false }
            guard env["system"] == .string("groth16-bn254"), env["circuit"] == .string("pca-compliance-v1") else { return false }
            guard let ps = env["publicSignals"]?.asArray, ps.count == 7, let g16 = JS.present(env["proof"]) else { return false }
            if ps[6] != .string("1") { return false }
            let policyTag = try commitmentField(inputs.policyCommit)
            if ps[3] != .string(policyTag) { return false }
            let planTag = try commitmentField(inputs.planCommit)
            if ps[4] != .string(planTag) { return false }
            let actionTag = try commitmentField(inputs.actionCommit)
            if ps[5] != .string(actionTag) { return false }
            if !isCanonicalGroth16Envelope(proof, "bn254") { return false }
            let engine = try PCAZkHook.current()
            guard let vkey = JS.present(opts.verificationKey) else { throw noBundledKey("pca-compliance-v1") }
            return try engine.verify(vkey, ps, g16)
        }
    }

    // ---- the Policy-VM circuits ---------------------------------------------------------------------------------------------

    /// The public-signal layout of a Policy-VM circuit (circuit outputs first, then the public inputs).
    public struct PublicSignalLayout: Sendable {
        public let actionHi = 0, actionLo = 1, policyHi = 2, policyLo = 3, planHi = 4, planLo = 5, r = 6, t = 7, admit = 8
        /// The risk commitment halves (the risk-bound circuit only).
        public let riskHi: Int?, riskLo: Int?
        public let allow: Int, now: Int, blast: Int, delegationDepth: Int, recentCount: Int, allocChild: Int
        public let count: Int

        init(bound: Bool) {
            let base = bound ? 11 : 9
            riskHi = bound ? 9 : nil; riskLo = bound ? 10 : nil
            allow = base; now = base + 1; blast = base + 2; delegationDepth = base + 3; recentCount = base + 4; allocChild = base + 5
            count = base + 6
        }

        /// Signal names and indices, in index order.
        public var entries: [(name: String, index: Int)] {
            var names = ["actionHi", "actionLo", "policyHi", "policyLo", "planHi", "planLo", "r", "t", "admit"]
            if riskHi != nil { names += ["riskHi", "riskLo"] }
            names += ["allow", "now", "blast", "delegationDepth", "recentCount", "allocChild"]
            return names.enumerated().map { (name: $0.element, index: $0.offset) }
        }
    }

    /// Layout of `pca-policyvm-v1` (15 signals).
    public static let POLICYVM_PUBLIC_SIGNAL = PublicSignalLayout(bound: false)
    public static let POLICYVM_PUBLIC_SIGNAL_COUNT = 15
    /// Layout of the risk-bound `pca-policyvm-v2` (17 signals: the v1 statement plus the risk commitment).
    public static let POLICYVM_BOUND_PUBLIC_SIGNAL = PublicSignalLayout(bound: true)
    public static let POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT = 17
    /// The risk magnitudes the v2 circuit commits to, in struct order.
    public static let POLICYVM_BOUND_RISK_FIELDS = ["revScore", "taint", "conf", "age", "rFloorIn"]
    /// The reversibility-class order of the circuit's `reversibility` field and `revMax` caveat.
    public static let POLICYVM_REVERSIBILITY_ORDER = ["reversible", "rate_limited", "irreversible"]

    /// A sha256 digest as the circuit's two 128-bit big-endian halves (decimal strings).
    public struct DigestHalves: Equatable, Sendable {
        public var hi: String
        public var lo: String
        public init(hi: String, lo: String) { self.hi = hi; self.lo = lo }
    }

    /// An integer argument of the struct hashes and the quantizers, as the reference takes it: a JSON value (what a number, a digit
    /// string, a boolean or anything else means is each function's rule) or an integer beyond JSON's safe range.
    public enum Num {
        case value(JSONValue?)
        case big(PCABigInt)
        public static func u64(_ v: UInt64) -> Num { .big(PCABigInt(String(v))!) }
    }

    /// `BigInt(x)`: nil where it throws.
    static func bigOf(_ n: Num) -> PCABigInt? {
        switch n {
        case let .big(b): return b
        case let .value(v): return PCABigInt.js(v)
        }
    }

    static func u64Of(_ b: PCABigInt) -> UInt64? { (!b.neg && b.mag.bitLength <= 64) ? b.mag.ratchetLow64 : nil }

    /// The circuit's struct commitment: each field as a 64-bit unsigned big-endian integer, concatenated, sha256, split into the two
    /// halves the circuit exposes. Throws on a field that is not an integer in [0, 2^64).
    public static func policyVmStructHash(_ fields: [Num]) throws -> DigestHalves {
        var bytes: [UInt8] = []
        for f in fields {
            guard let b = bigOf(f) else { throw JSError("policyVmStructHash: a field is not an integer") }
            guard let v = u64Of(b) else { throw JSError("policyVmStructHash: field out of uint64 range") }
            for shift in stride(from: 56, through: 0, by: -8) { bytes.append(UInt8(truncatingIfNeeded: v >> UInt64(shift))) }
        }
        let d = Canonical.sha256(bytes)
        return DigestHalves(hi: BigUInt(bytesLE: Array(d[0..<16].reversed())).ratchetDecimal, lo: BigUInt(bytesLE: Array(d[16..<32].reversed())).ratchetDecimal)
    }

    /// The risk commitment of the v2 circuit: the struct hash of exactly the five risk magnitudes, in `POLICYVM_BOUND_RISK_FIELDS` order.
    public static func policyVmRiskHash(_ fields: [Num]) throws -> DigestHalves {
        guard fields.count == POLICYVM_BOUND_RISK_FIELDS.count else { throw JSError("policyVmRiskHash: need exactly 5 risk fields") }
        return try policyVmStructHash(fields)
    }

    static func decode(_ ps: [JSONValue], _ L: PublicSignalLayout) -> JSONValue {
        func s(_ i: Int) -> JSONValue? { i < ps.count ? ps[i] : nil }
        func halves(_ hi: Int, _ lo: Int) -> JSONValue {
            var o: JObject = [:]
            o[o: "hi"] = s(hi)
            o[o: "lo"] = s(lo)
            return .object(o)
        }
        var o: JObject = [:]
        o[o: "actionHash"] = halves(L.actionHi, L.actionLo)
        o[o: "policyHash"] = halves(L.policyHi, L.policyLo)
        o[o: "planHash"] = halves(L.planHi, L.planLo)
        if let hi = L.riskHi, let lo = L.riskLo { o[o: "riskHash"] = halves(hi, lo) }
        o[o: "r"] = s(L.r)
        o[o: "t"] = s(L.t)
        o[o: "admit"] = s(L.admit)
        o[o: "allow"] = s(L.allow)
        o[o: "now"] = s(L.now)
        o[o: "blast"] = s(L.blast)
        o[o: "delegationDepth"] = s(L.delegationDepth)
        o[o: "recentCount"] = s(L.recentCount)
        o[o: "allocChild"] = s(L.allocChild)
        return .object(o)
    }

    /// The proven statement of a v1 proof: `{actionHash, policyHash, planHash, r, t, admit, allow, now, blast, delegationDepth,
    /// recentCount, allocChild}` (a signal the array does not have is left out).
    public static func decodePolicyVmPublic(_ publicSignals: [JSONValue]) -> JSONValue { decode(publicSignals, POLICYVM_PUBLIC_SIGNAL) }
    /// The proven statement of a v2 proof: the v1 statement plus `riskHash`.
    public static func decodePolicyVmBoundPublic(_ publicSignals: [JSONValue]) -> JSONValue { decode(publicSignals, POLICYVM_BOUND_PUBLIC_SIGNAL) }

    // ---- action / plan / policy quantization --------------------------------------------------------------------------------

    /// How the verb and resource strings map to the circuit's uint64 codes. It must be the map the prover used.
    public struct QuantizeOpts {
        /// Verb string to code. A verb that is not listed is content-addressed, unless `strictCatalog`.
        public var verbCodes: [String: Num]?
        public var resourceCodes: [String: Num]?
        /// Refuse a verb or resource that is not in the maps.
        public var strictCatalog: Bool
        /// The action param whose non-negative integer value is the circuit's param scalar (absent or empty: 0).
        public var paramScalarField: String?
        public init(verbCodes: [String: Num]? = nil, resourceCodes: [String: Num]? = nil, strictCatalog: Bool = false, paramScalarField: String? = nil) {
            self.verbCodes = verbCodes; self.resourceCodes = resourceCodes; self.strictCatalog = strictCatalog; self.paramScalarField = paramScalarField
        }
    }

    /// The plan node the plan struct commits (the semantic distance and the hiding salt are the prover's).
    public struct QuantizablePlan {
        public var verb: JSONValue?
        public var resource: JSONValue?
        public var semanticDist: Num
        public var planSalt: Num
        public init(verb: JSONValue?, resource: JSONValue?, semanticDist: Num, planSalt: Num) {
            self.verb = verb; self.resource = resource; self.semanticDist = semanticDist; self.planSalt = planSalt
        }
    }

    /// The policy laid out as the circuit's 20-field struct (weights, thresholds and bounds are the policy's own scaled integers).
    public struct QuantizablePolicy {
        public var alpha: Num, beta: Num, gamma: Num, delta: Num, epsilon: Num, zeta: Num
        public var theta1: Num, theta2: Num, kappa: Num, budgetB: Num
        public var policyVerb: JSONValue?, policyResource: JSONValue?
        public var policyParamBound: Num, expiresAt: Num, notBefore: Num, maxBlast: Num, maxDepth: Num
        public var revMax: JSONValue?
        public var rateMax: Num, allocParent: Num
        public init(alpha: Num, beta: Num, gamma: Num, delta: Num, epsilon: Num, zeta: Num, theta1: Num, theta2: Num, kappa: Num, budgetB: Num, policyVerb: JSONValue?,
                    policyResource: JSONValue?, policyParamBound: Num, expiresAt: Num, notBefore: Num, maxBlast: Num, maxDepth: Num, revMax: JSONValue?, rateMax: Num,
                    allocParent: Num) {
            self.alpha = alpha; self.beta = beta; self.gamma = gamma; self.delta = delta; self.epsilon = epsilon; self.zeta = zeta
            self.theta1 = theta1; self.theta2 = theta2; self.kappa = kappa; self.budgetB = budgetB; self.policyVerb = policyVerb; self.policyResource = policyResource
            self.policyParamBound = policyParamBound; self.expiresAt = expiresAt; self.notBefore = notBefore; self.maxBlast = maxBlast; self.maxDepth = maxDepth
            self.revMax = revMax; self.rateMax = rateMax; self.allocParent = allocParent
        }
    }

    /// The quantized struct field arrays, ready for `policyVmStructHash`.
    public struct QuantizedStructs: Equatable {
        public var action: [UInt64]
        public var plan: [UInt64]?
        public var policy: [UInt64]?
    }

    /// uint64 content address of a domain-tagged string: the top 8 bytes of its sha256, big-endian.
    static func contentAddressU64(_ domain: String, _ value: String) -> UInt64 {
        Canonical.sha256(Array("atlas-pca/policyvm-quantize/\(domain):\(value)".utf8)).prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    /// A code or numeric field as a uint64: an integral number or a big integer in range, nothing else (never a string or a boolean).
    static func toU64(_ n: Num, _ what: String) throws -> UInt64 {
        var b: PCABigInt?
        switch n {
        case let .big(x): b = x
        case let .value(v):
            if let d = IV.num(v), d.isFinite, d.rounded(.towardZero) == d { b = PCABigInt.js(v) }
        }
        guard let x = b, let u = u64Of(x) else { throw JSError("policyvm quantize: \(what) is not a uint64") }
        return u
    }

    static func codeFor(_ domain: String, _ value: JSONValue?, _ map: [String: Num]?, _ strict: Bool) throws -> UInt64 {
        guard let s = value?.asString else { throw JSError("policyvm quantize: \(domain) must be a string") }
        // an exact (code point) match: two spellings of one text are two entries
        if let hit = map?.first(where: { IV.same($0.key, s) }) { return try toU64(hit.value, "\(domain) code") }
        if strict { throw JSError("policyvm quantize: \(domain) \"\(s)\" is not in the catalog (strict)") }
        return contentAddressU64(domain, s)
    }

    /// Names every object inherits: read as a member they are functions or objects, never an integer.
    static let INHERITED: Set<String> = ["constructor", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
                                         "__proto__", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"]

    static func paramScalarFrom(_ params: JSONValue?, _ field: String?) throws -> UInt64 {
        guard let field = field, !field.isEmpty, JS.truthy(params) else { return 0 }
        let refused = JSError("policyvm quantize: paramScalar is not a non-negative integer")
        // shortcut: only the names every object inherits are refused here; the extra methods of an array or a string given as `params` are read as absent (0). Upgrade if params may be a non-object.
        guard let v = JS.present(JSLoose.get(params, field)) else {
            if JSLoose.get(params, field) == nil && INHERITED.contains(field) { throw refused }
            return 0
        }
        switch v {
        case .int, .double:
            guard let d = IV.num(v), d.isFinite, d.rounded(.towardZero) == d, d >= 0, d.sign == .plus else {
                throw JSError("policyvm quantize: paramScalar must be a non-negative integer")
            }
            return try toU64(.value(v), "paramScalar")
        case let .string(s):
            guard !s.isEmpty, s.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let b = PCABigInt(s) else { throw refused }
            return try toU64(.big(b), "paramScalar")
        default:
            throw refused
        }
    }

    static func reversibilityIndex(_ rc: JSONValue?, _ what: String) throws -> UInt64 {
        guard let s = rc?.asString, let idx = POLICYVM_REVERSIBILITY_ORDER.firstIndex(where: { IV.same($0, s) }) else {
            throw JSError("policyvm quantize: unknown \(what) class \"\(JS.toString(rc))\"")
        }
        return UInt64(idx)
    }

    /// The live action as the circuit's 4-field struct: verb code, resource code, reversibility-class index, param scalar. Throws on
    /// anything that cannot be quantized.
    public static func quantizeActionStruct(_ action: JSONValue?, _ opts: QuantizeOpts = QuantizeOpts()) throws -> [UInt64] {
        guard let a = action, a.isObject || a.isArray else { throw JSError("policyvm quantize: action is missing") }
        let verb = try codeFor("verb", JSLoose.get(a, "verb"), opts.verbCodes, opts.strictCatalog)
        let resource = try codeFor("resource", JSLoose.get(a, "resource"), opts.resourceCodes, opts.strictCatalog)
        let rev = try reversibilityIndex(JS.present(JSLoose.get(a, "reversibility_class")) ?? .string("reversible"), "reversibility")
        let scalar = try paramScalarFrom(JSLoose.get(a, "params"), opts.paramScalarField)
        return [verb, resource, rev, scalar]
    }

    /// The plan node as the circuit's 4-field plan struct.
    public static func quantizePlanStruct(_ plan: QuantizablePlan, _ opts: QuantizeOpts = QuantizeOpts()) throws -> [UInt64] {
        let verb = try codeFor("verb", plan.verb, opts.verbCodes, opts.strictCatalog)
        let resource = try codeFor("resource", plan.resource, opts.resourceCodes, opts.strictCatalog)
        let dist = try toU64(plan.semanticDist, "semanticDist")
        let salt = try toU64(plan.planSalt, "planSalt")
        return [verb, resource, dist, salt]
    }

    /// The policy as the circuit's 20-field policy struct.
    public static func quantizePolicyStruct(_ p: QuantizablePolicy, _ opts: QuantizeOpts = QuantizeOpts()) throws -> [UInt64] {
        var out: [UInt64] = []
        for (n, what) in [(p.alpha, "wAlpha"), (p.beta, "wBeta"), (p.gamma, "wGamma"), (p.delta, "wDelta"), (p.epsilon, "wEpsilon"), (p.zeta, "wZeta"),
                          (p.theta1, "theta1"), (p.theta2, "theta2"), (p.kappa, "kappa"), (p.budgetB, "budgetB")] { out.append(try toU64(n, what)) }
        out.append(try codeFor("verb", p.policyVerb, opts.verbCodes, opts.strictCatalog))
        out.append(try codeFor("resource", p.policyResource, opts.resourceCodes, opts.strictCatalog))
        for (n, what) in [(p.policyParamBound, "policyParamBound"), (p.expiresAt, "expiresAt"), (p.notBefore, "notBefore"), (p.maxBlast, "maxBlast"),
                          (p.maxDepth, "maxDepth")] { out.append(try toU64(n, what)) }
        out.append(try reversibilityIndex(p.revMax, "revMax"))
        out.append(try toU64(p.rateMax, "rateMax"))
        out.append(try toU64(p.allocParent, "allocParent"))
        return out
    }

    /// The action struct and, when given, the plan and policy structs.
    public static func quantizePolicyVmInputs(action: JSONValue?, plan: QuantizablePlan? = nil, policy: QuantizablePolicy? = nil,
                                              _ opts: QuantizeOpts = QuantizeOpts()) throws -> QuantizedStructs {
        let a = try quantizeActionStruct(action, opts)
        let pl = try plan.map { try quantizePlanStruct($0, opts) }
        let po = try policy.map { try quantizePolicyStruct($0, opts) }
        return QuantizedStructs(action: a, plan: pl, policy: po)
    }

    /// The circuit's action commitment recomputed from the live action. A verifier binds a Policy-VM proof to this action by requiring
    /// the proof's action halves to equal it.
    public static func policyVmCommitmentFromAction(_ action: JSONValue?, _ opts: QuantizeOpts = QuantizeOpts()) throws -> DigestHalves {
        try policyVmStructHash(try quantizeActionStruct(action, opts).map { Num.u64($0) })
    }

    // ---- context pins ----------------------------------------------------------------------------------------------------------

    /// The context a proof must have been made for: an object `{now?, blast?, delegationDepth?, recentCount?, allocChild?, r?, t?,
    /// requireAdmit?, requireTier1?}` whose pins are an exact value (number or decimal string) or an inclusive `{min, max}` window, given
    /// as a value or as a function evaluated at each verification (so `now` can follow a clock).
    public enum PolicyVmExpectSource {
        case value(JSONValue)
        case thunk(() throws -> JSONValue?)
    }

    /// A pin bound as an integer: a number must be a safe integer; nil where `BigInt(x)` throws.
    static func pinBigint(_ v: JSONValue?) -> JSBigInt? {
        if let x = v, x.isNumber, x.safeInt == nil { return nil }
        return JSBigInt.of(v)
    }

    static func signalMatchesPin(_ signal: JSONValue?, _ pin: JSONValue) throws -> Bool {
        guard let sig = signal, canonDec(JS.toString(sig)), let big = PCABigInt.js(sig) else { return false }
        let x = JSBigInt(neg: false, mag: big.mag)
        if pin.isNull { throw JSError("cannot read 'min' of null") }
        if pin.isObject || pin.isArray {
            guard let lo = pinBigint(JSLoose.get(pin, "min")), let hi = pinBigint(JSLoose.get(pin, "max")) else { return false }
            return !(hi < lo) && !(x < lo) && !(hi < x)
        }
        guard let want = pinBigint(pin) else { return false }
        return x == want
    }

    /// Do the public signals satisfy `expect`? Even with no pins a context signal that is not a canonical decimal below 2^64 is refused:
    /// the circuit compares un-range-checked public inputs, so a field-negative `now` would pass its comparisons. A null pin throws.
    public static func policyVmContextMatches(_ ps: [JSONValue], _ expect: PolicyVmExpectSource? = nil, layout L: PublicSignalLayout = POLICYVM_PUBLIC_SIGNAL) throws -> Bool {
        func s(_ i: Int) -> JSONValue? { i < ps.count ? ps[i] : nil }
        let bound = BigUInt(1) << 64
        for idx in [L.now, L.blast, L.delegationDepth, L.recentCount, L.allocChild] {
            // 2^64 has 20 digits: a longer canonical decimal is out of range without being parsed
            guard let sig = s(idx)?.asString, sig.utf8.count <= 20, canonDec(sig), BigUInt(decimal: sig) < bound else { return false }
        }
        guard let src = expect else { return true }
        var e: JSONValue?
        switch src {
        case let .value(v): e = v
        case let .thunk(f):
            do { e = try f() } catch { return false }
        }
        guard let ev = e, ev.isObject || ev.isArray else { return false }
        for (k, idx) in [("now", L.now), ("blast", L.blast), ("delegationDepth", L.delegationDepth), ("recentCount", L.recentCount), ("allocChild", L.allocChild),
                         ("r", L.r), ("t", L.t)] {
            if let pin = JSLoose.get(ev, k), !(try signalMatchesPin(s(idx), pin)) { return false }
        }
        if JS.truthy(JSLoose.get(ev, "requireAdmit")) && s(L.admit) != .string("1") { return false }
        if JS.truthy(JSLoose.get(ev, "requireTier1")) && s(L.t) != .string("1") { return false }
        return true
    }

    // ---- Policy-VM proof verification and its backends ---------------------------------------------------------------------

    public struct PolicyVmVerifyOpts {
        /// The verifying key (snarkjs JSON). nil or null: the bundled key of the proof's curve (the risk-bound circuit has none).
        public var verificationKey: JSONValue?
        /// Pins on the public context signals; a mismatch makes verification answer false.
        public var expect: PolicyVmExpectSource?
        /// Pins the risk commitment; only a v2 proof carries one, so a v1 proof is then refused.
        public var expectRiskHash: DigestHalves?
        public init(verificationKey: JSONValue? = nil, expect: PolicyVmExpectSource? = nil, expectRiskHash: DigestHalves? = nil) {
            self.verificationKey = verificationKey; self.expect = expect; self.expectRiskHash = expectRiskHash
        }
    }

    /// Verifies a full Policy-VM Groth16 proof envelope (`groth16-bn254` or `groth16-bls12-381`; the risk-bound circuit is BN254 only):
    /// shape, circuit and system tags, 15 or 17 signals, allow == 1, the risk pin, the canonical encoding and the context pins, then the
    /// pairing check through the registered engine in the reference's mode. Anything malformed is false; an engine that is missing or
    /// throws is false. Throws only where the reference does: a null pin, or the risk-bound circuit without a verifying key.
    public static func verifyPolicyVmProof(_ env: JSONValue?, _ opts: PolicyVmVerifyOpts = PolicyVmVerifyOpts()) throws -> Bool {
        guard let p = env?.asObject else { return false }
        let bound = p["circuit"] == .string("pca-policyvm-v2")
        if p["circuit"] != .string("pca-policyvm-v1") && !bound { return false }
        let isBls = p["system"] == .string("groth16-bls12-381")
        if p["system"] != .string("groth16-bn254") && !(isBls && !bound) { return false }
        let L = bound ? POLICYVM_BOUND_PUBLIC_SIGNAL : POLICYVM_PUBLIC_SIGNAL
        guard let ps = p["publicSignals"]?.asArray, ps.count == L.count, let proof = JS.present(p["proof"]) else { return false }
        if ps[L.allow] != .string("1") { return false }
        if let want = opts.expectRiskHash {
            guard let hi = L.riskHi, let lo = L.riskLo, ps[hi] == .string(want.hi), ps[lo] == .string(want.lo) else { return false }
        }
        if !isCanonicalGroth16Envelope(env, isBls ? "bls12-381" : "bn254") { return false }
        if !(try policyVmContextMatches(ps, opts.expect, layout: L)) { return false }
        let vkey: JSONValue
        if let k = JS.present(opts.verificationKey) { vkey = k } else if bound { throw noBundledKey("pca-policyvm-v2") } else {
            vkey = try (isBls ? policyVmVerificationKeyBls12381() : policyVmVerificationKey())
        }
        do { return try PCAZkHook.current().verify(vkey, ps, proof) } catch { return false }
    }

    static func halvesMatch(_ ps: [JSONValue], _ hi: Int, _ lo: Int, _ want: DigestHalves?) -> Bool {
        guard let w = want else { return true }
        return hi < ps.count && lo < ps.count && ps[hi] == .string(w.hi) && ps[lo] == .string(w.lo)
    }

    /// `policyvm_snark` only when the proof is bound to this action, policy and plan; else a valid proof may be for another action.
    static func policyVmLabel(_ opts: SnarkBackendOpts) -> AssuranceLabel {
        let ceremony = ceremonyLabel(opts, "pca-policyvm-v1")
        return opts.expectActionHash != nil && opts.expectPolicyHash != nil && opts.expectPlanHash != nil
            ? AssuranceLabel(level: "policyvm_snark", ceremony: ceremony) : AssuranceLabel(level: "unknown", vendor: "policyvm-unbound", ceremony: ceremony)
    }

    static func policyVmBackend(_ opts: SnarkBackendOpts, bls: Bool) -> SnarkBackend {
        SnarkBackend(assuranceLabel: policyVmLabel(opts)) { proof, _ in
            guard proof?.get("circuit") == .string("pca-policyvm-v1") else { return false }
            if let ps = proof?.get("publicSignals")?.asArray {
                let P = POLICYVM_PUBLIC_SIGNAL
                guard halvesMatch(ps, P.actionHi, P.actionLo, opts.expectActionHash), halvesMatch(ps, P.policyHi, P.policyLo, opts.expectPolicyHash),
                      halvesMatch(ps, P.planHi, P.planLo, opts.expectPlanHash) else { return false }
            }
            // the backend's own key (explicit, else the bundled one of its curve), whatever curve the proof names
            let vkey = try JS.present(opts.verificationKey) ?? (bls ? policyVmVerificationKeyBls12381() : policyVmVerificationKey())
            return try verifyPolicyVmProof(proof, PolicyVmVerifyOpts(verificationKey: vkey, expect: opts.expect))
        }
    }

    /// A backend over the full Policy-VM circuit on BN254. It checks the proof and allow == 1 and, when expected struct hashes are given,
    /// binds the proof's public halves to them. It does not bind the canonical-JSON commitments it is handed: the circuit commits to a
    /// fixed-layout struct, so the binding is `expectActionHash` / `expectPolicyHash` / `expectPlanHash`.
    public static func createPolicyVmSnarkBackend(_ opts: SnarkBackendOpts = SnarkBackendOpts()) -> SnarkBackend { policyVmBackend(opts, bls: false) }

    /// The BLS12-381 counterpart: the same checks, with the bundled BLS12-381 key as the default.
    public static func createPolicyVmSnarkBackendBls12381(_ opts: SnarkBackendOpts = SnarkBackendOpts()) -> SnarkBackend { policyVmBackend(opts, bls: true) }

    /// A backend over the risk-bound circuit (`pca-policyvm-v2`, BN254): the v1 checks plus the risk commitment. `policyvm_snark` only
    /// when all four commitments are pinned. There is no bundled key: pass `verificationKey`.
    public static func createPolicyVmBoundSnarkBackend(_ opts: SnarkBackendOpts = SnarkBackendOpts()) -> SnarkBackend {
        let ceremony = ceremonyLabel(opts, "pca-policyvm-v2")
        let bound = opts.expectActionHash != nil && opts.expectPolicyHash != nil && opts.expectPlanHash != nil && opts.expectRiskHash != nil
        let label = bound ? AssuranceLabel(level: "policyvm_snark", ceremony: ceremony) : AssuranceLabel(level: "unknown", vendor: "policyvm-unbound", ceremony: ceremony)
        return SnarkBackend(assuranceLabel: label) { proof, _ in
            guard proof?.get("circuit") == .string("pca-policyvm-v2"), let ps = proof?.get("publicSignals")?.asArray else { return false }
            let P = POLICYVM_BOUND_PUBLIC_SIGNAL
            guard halvesMatch(ps, P.actionHi, P.actionLo, opts.expectActionHash), halvesMatch(ps, P.policyHi, P.policyLo, opts.expectPolicyHash),
                  halvesMatch(ps, P.planHi, P.planLo, opts.expectPlanHash), halvesMatch(ps, 9, 10, opts.expectRiskHash) else { return false }
            guard let vkey = JS.present(opts.verificationKey) else { throw noBundledKey("pca-policyvm-v2") }
            return try verifyPolicyVmProof(proof, PolicyVmVerifyOpts(verificationKey: vkey, expect: opts.expect, expectRiskHash: opts.expectRiskHash))
        }
    }

    // ---- circuit versions --------------------------------------------------------------------------------------------------

    /// The version record of one circuit, from the bundled version table.
    public struct CircuitVersion: Equatable, Sendable {
        public var circuit: String
        /// SHA-256 over the circuit's whole source set plus the pinned compiler.
        public var sourceSha256: String
        public var circom: String
        public var circomlib: String
    }

    /// The committed version of a circuit id (`pca-compliance-v1`, `pca-policyvm-v1`, `pca-policyvm-v2`); throws on an unknown id.
    public static func circuitVersion(_ id: String) throws -> CircuitVersion {
        let v = try bundled("circuit-versions")
        guard let c = v.get("circuits")?.asObject?[JKey(id)], let src = c.get("source_sha256")?.asString, let circom = v.get("circom")?.asString,
              let lib = v.get("circomlib")?.asString else { throw JSError("circuitVersion: unknown circuit \"\(id)\"") }
        return CircuitVersion(circuit: id, sourceSha256: src, circom: circom, circomlib: lib)
    }

    // ---- provers (through the registered engine) -----------------------------------------------------------------------------

    static func envelope(_ circuit: String, _ proved: JSONValue) -> JSONValue {
        var o: JObject = [:]
        o[o: "system"] = .string("groth16-bn254")
        o[o: "circuit"] = .string(circuit)
        o[o: "proof"] = proved.get("proof")
        o[o: "publicSignals"] = proved.get("publicSignals")
        return .object(o)
    }

    /// The witness as the circuit input: every member through `String(x)`, in the object's own order.
    static func stringInput(_ witness: JSONValue) throws -> JObject {
        guard let w = witness.asObject else { throw JSError("the witness must be an object") }
        var input: JObject = [:]
        for k in JS.keyOrder(w) { input[o: k.s] = .string(JS.toString(w[k])) }
        return input
    }

    /// Proves the first circuit. `inp` holds the commitments to bind (`action_commit`, `policy_commit`, `plan_commit`, base64url) and
    /// the private witness (`verb`, `resource`, `planVerb`, `policySalt`, `planSalt`, `actionSalt`, `risk`, `budget`); `wasm` and `zkey`
    /// are the circuit's witness program and proving key. Throws on a witness that is not compliant: a false statement has no proof.
    public static func proveGroth16Compliance(_ inp: JSONValue, wasm: [UInt8], zkey: [UInt8]) throws -> JSONValue {
        var input: JObject = [:]
        for k in ["verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget"] { input[o: k] = .string(JS.toString(JSLoose.get(inp, k))) }
        for (name, member) in [("shaPolicy", "policy_commit"), ("shaPlan", "plan_commit"), ("shaAction", "action_commit")] {
            guard let commit = JSLoose.get(inp, member)?.asString else { throw JSError("proveGroth16Compliance: \(member) must be a string") }
            input[o: name] = .string(try commitmentField(commit))
        }
        input[o: "allow"] = .string("1")
        return envelope("pca-compliance-v1", try PCAZkHook.current().prove("bn254", wasm, zkey, .object(input)))
    }

    /// Proves the full Policy-VM circuit from the complete fixed-point witness (every circuit input, the division witnesses included).
    /// Throws on a witness that is not compliant.
    public static func provePolicyVmCompliance(_ witness: JSONValue, wasm: [UInt8], zkey: [UInt8]) throws -> JSONValue {
        envelope("pca-policyvm-v1", try PCAZkHook.current().prove("bn254", wasm, zkey, .object(try stringInput(witness))))
    }

    /// Proves the risk-bound circuit (`pca-policyvm-v2`); the same witness inputs as `provePolicyVmCompliance`.
    public static func provePolicyVmBoundCompliance(_ witness: JSONValue, wasm: [UInt8], zkey: [UInt8]) throws -> JSONValue {
        envelope("pca-policyvm-v2", try PCAZkHook.current().prove("bn254", wasm, zkey, .object(try stringInput(witness))))
    }
}
