import Foundation

/// Attest the mediator, not the weights. The trusted computing base is this small orchestration harness, not an opaque model: the model
/// is an UNTRUSTED ORACLE that proposes a candidate action, and the harness enforces plan inclusion, the taint fold and the trust budget
/// before any candidate becomes a signed PCActn. The oracle holds no signing key. Also the resource-server hook that admits an
/// allowlisted harness measurement.
public enum PCAHarness {
    /// The ordered manifest of checks the harness enforces before signing; folded into the measurement.
    public static let ENFORCED_CHECKS = ["plan_inclusion_before_signing", "taint_provenance_fold", "trust_budget_debit", "pcactn_sign"]
    /// The semantic version of the harness's policy-relevant surface; a bump changes the measurement.
    public static let HARNESS_VERSION = "0.1.0"
    /// The model id stamped into an emitted PCActn's attestation when attestation is enabled (the mediator, not an LLM).
    public static let HARNESS_MODEL_ID = "@atlasauth/pca-harness"

    public struct HarnessError: Error, CustomStringConvertible {
        public let description: String
        init(_ d: String) { description = d }
    }

    /// The pure self-measurement: base64url SHA-256 over the harness version, the enforced-checks manifest and the risk-policy identity
    /// (weights, theta1, theta2, kappa). A policy missing one of those is refused, as the strict canonical form refuses an undefined member.
    public static func computeHarnessMeasurement(_ version: JSONValue, _ enforcedChecks: JSONValue, _ policy: JSONValue) throws -> String {
        guard let p = policy.asObject else { throw HarnessError("computeHarnessMeasurement: policy is not an object") }
        var rp = JObject()
        for k in ["weights", "theta1", "theta2", "kappa"] {
            guard let v = p[JKey(k)] else { throw HarnessError("canonicalize: unsupported type undefined") }
            rp[JKey(k)] = v
        }
        guard let h = IV.strictHash(.object(["harness": .string(HARNESS_MODEL_ID), "version": version, "enforces": enforcedChecks, "risk_policy": .object(rp)])) else {
            throw HarnessError("computeHarnessMeasurement: not canonicalizable")
        }
        return h
    }

    // MARK: the allowlisting verifier

    /// `{enforced: false}` or `{enforced: true, ok, reason?}`, the hook result the core verifier folds into the `attestation` check.
    public struct HookResult: Equatable {
        public var enforced: Bool
        public var ok: Bool?
        public var reason: String?
        public var json: JSONValue {
            var o: JObject = ["enforced": .bool(enforced)]
            if let k = ok { o["ok"] = .bool(k) }
            if let r = reason { o["reason"] = .string(r) }
            return .object(o)
        }
    }

    /// The resource-server hook over `ctx.pcactn.attestation`. Fail closed: an empty allowlist accepts nothing; an absent measurement fails
    /// unless `required` is false (then not enforced); a pinned `expectedModelId` must match; a present measurement outside the allowlist
    /// ALWAYS fails. `config`: `measurements` (the allowlisted strings; others are ignored), `required` (default true; only `false` turns it off),
    /// `expectedModelId` (`true` for the harness id, or a non-empty string). The measurement's integrity rests on the surrounding verdict
    /// requiring the leaf signature to verify. Throws for a config that is not an object.
    public static func createHarnessAttestationVerifier(_ config: JSONValue?) throws -> (JSONValue?) -> HookResult {
        guard let c = config?.asObject else { throw HarnessError("createHarnessAttestationVerifier: config is not an object") }
        let allow = (c[JKey("measurements")]?.asArray ?? []).compactMap { $0.asString }.filter { !$0.isEmpty }
        let required = c[JKey("required")] != .bool(false)
        var expected: String?
        if c[JKey("expectedModelId")] == .bool(true) { expected = HARNESS_MODEL_ID } else if let s = c[JKey("expectedModelId")]?.asString, !s.isEmpty { expected = s }

        return { ctx in
            if allow.isEmpty { return HookResult(enforced: true, ok: false, reason: "harness attestation configured with an empty measurement allowlist (fail closed)") }
            let att = ctx?.get("pcactn")?.get("attestation")
            let measurement = att?.get("measurement")?.asString ?? ""
            if measurement.isEmpty {
                return required ? HookResult(enforced: true, ok: false, reason: "harness attestation required but the PCActn carries no harness measurement (fail closed)") : HookResult(enforced: false)
            }
            if let e = expected, !IV.same(att?.get("model_id")?.asString, e) {
                return HookResult(enforced: true, ok: false, reason: "attestation.model_id '\(JS.toString(att?.get("model_id")))' is not the required harness identity '\(e)'")
            }
            if !IV.contains(allow, measurement) { return HookResult(enforced: true, ok: false, reason: "harness measurement is not in the allowlisted set (unattested or unknown mediator)") }
            return HookResult(enforced: true, ok: true)
        }
    }

    // MARK: the harness

    /// What a step produced: a signed PCActn with its inclusion proof, or a refusal.
    public enum StepResult {
        case ok(pcactn: JSONValue, inclusionProof: JSONValue, riskR: Double, riskInputs: JObject, taint: Int, t: Int, budget: Risk.Budget)
        case refused(reason: String, detail: String, requiredT: Int?, budget: Risk.Budget?)

        public var json: JSONValue {
            switch self {
            case let .ok(p, ip, r, inputs, taint, t, b):
                return .object(["ok": .bool(true), "pcactn": p, "inclusionProof": ip, "budget": b.json,
                                "risk": .object(["r": PCASandbox.num(r), "inputs": .object(inputs), "taint": .int(Int64(taint)), "t": .int(Int64(t))])])
            case let .refused(reason, detail, rt, b):
                var o: JObject = ["ok": .bool(false), "reason": .string(reason), "detail": .string(detail)]
                if let t = rt { o["requiredT"] = .int(Int64(t)) }
                if let b = b { o["budget"] = b.json }
                return .object(o)
            }
        }
    }

    static let DEFAULT_BASE_RISK: JObject = ["semanticDistance": .double(0.1), "reversibility": .int(1), "blastRadius": .double(0.1), "taint": .int(0), "confidence": .int(1), "age": .int(0)]

    /// JavaScript `Number.prototype.toFixed(4)` of a finite non-negative number: the larger of two equally near decimals (an exact tie).
    static func toFixed4(_ x: Double) -> String {
        guard x.isFinite else { return JS.toString(.double(x)) }
        let y = x * 20000, exact = fma(x, 20000, -y) == 0
        if exact, y == y.rounded(), y < 9e15, Int64(y) % 2 != 0 {
            let n = (Int64(y) + 1) / 2
            return "\(n / 10000)." + String(format: "%04d", n % 10000)
        }
        return String(format: "%.4f", x)
    }

    /// `Math.round`: the nearest integer, ties toward +infinity.
    static func jsRound(_ x: Double) -> Double {
        let f = x.rounded(.down)
        return x - f >= 0.5 ? f + 1 : f
    }

    /// The attested orchestration harness: one agent key, one committed plan, one trust budget. The caller's oracle proposes candidates;
    /// only a candidate that is in the plan, inside the budget and well formed is signed. Not safe for concurrent use.
    public final class Harness {
        private let grant: JSONValue
        private let chain: [JSONValue]
        private let signer: PCASuiteKey
        private let plan: PCAIssue.Plan
        private let planIndex: [JKey: JObject]
        private let audience: String
        private let policy: JObject
        private let baseRisk: JObject
        private let now: () -> Int64
        private let ttlMs: Int64?
        private let manifest: [String]
        private let nonce: () -> String
        private let attestation: (operator: String, epoch: Int64?)?
        public private(set) var budget: Risk.Budget
        public private(set) var counter = 0

        /// Throws for an empty audience, a seed that is not 32 bytes, an empty plan or duplicate node ids, a budget that is not finite with
        /// B >= 0, or a plan that cannot be committed.
        public init(grant: JSONValue, chain: [JSONValue]? = nil, agentSeed: [UInt8], plan nodes: [JObject], audience: String, budget: Risk.Budget, policy: JObject? = nil,
                    baseRisk: JObject? = nil, now: (() -> Int64)? = nil, ttlMs: Int64? = nil, measurementManifest: [String]? = nil, nonce: (() -> String)? = nil,
                    attestation: (operator: String, epoch: Int64?)? = nil) throws {
            guard !audience.isEmpty else { throw HarnessError("Harness: `audience` is required (the resource-server / instance id PCActns are for)") }
            guard agentSeed.count == 32 else { throw HarnessError("Harness: `agentSecret` must be a 32-byte Ed25519 secret key") }
            guard !nodes.isEmpty else { throw HarnessError("Harness: `plan` must be a non-empty array (an empty plan authorises nothing)") }
            var ids = Set<JKey>()
            for n in nodes { guard let id = n["id"]?.asString, ids.insert(JKey(id)).inserted else { throw HarnessError("Harness: plan node ids must be unique") } }
            guard budget.b.isFinite, budget.b >= 0, budget.tau.isFinite, let asOf = budget.asOf, asOf.isFinite else { throw HarnessError("Harness: `budget` must have finite B >= 0, tau and asOf") }
            self.grant = grant
            self.chain = chain ?? [grant]
            self.signer = PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: agentSeed))
            self.plan = try PCAIssue.commitPlan(nodes)
            var idx: [JKey: JObject] = [:]
            for n in nodes { idx[JKey(n["id"]!.asString!)] = n }
            self.planIndex = idx
            self.audience = audience
            self.policy = policy ?? PCAFacade.DEFAULT_RISK_POLICY
            var br = DEFAULT_BASE_RISK
            for (k, v) in baseRisk ?? [:] { br[k] = v }
            self.baseRisk = br
            self.now = now ?? { Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) }
            self.ttlMs = ttlMs
            self.manifest = measurementManifest ?? ENFORCED_CHECKS
            self.nonce = nonce ?? { (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined() }
            self.attestation = attestation
            self.budget = budget
        }

        /// The Merkle root of the committed plan.
        public var planRoot: String { plan.root }

        /// The measurement of this harness: version, enforced-checks manifest and risk-policy identity.
        public func harnessMeasurement() -> String {
            (try? computeHarnessMeasurement(.string(HARNESS_VERSION), .array(manifest.map { .string($0) }), .object(policy))) ?? ""
        }

        private func num(_ k: String) -> Double { IV.num(policy[JKey(k)]) ?? .nan }

        /// Ask the oracle for a candidate `{verb, resource, nodeId, params?, inputs?: [{ref, provenance}]}` and, if it is in the committed
        /// plan, inside the budget and well formed, sign it. A refusal (`out_of_plan`, `over_budget`, `bad_candidate`) signs nothing; an
        /// over-budget refusal keeps the leaked budget.
        public func step(_ propose: () throws -> JSONValue) -> StepResult {
            let candidate: JSONValue
            do { candidate = try propose() } catch { return .refused(reason: "bad_candidate", detail: "oracle failed: \((error as? JSError)?.message ?? "\(error)")", requiredT: nil, budget: nil) }
            guard let c = candidate.asObject, let nodeId = c[JKey("nodeId")]?.asString, let verb = c[JKey("verb")]?.asString, let resource = c[JKey("resource")]?.asString else {
                return .refused(reason: "bad_candidate", detail: "oracle returned a malformed candidate", requiredT: nil, budget: nil)
            }
            guard let node = planIndex[JKey(nodeId)] else { return .refused(reason: "out_of_plan", detail: "node '\(nodeId)' is not in the committed plan", requiredT: nil, budget: nil) }
            if !IV.same(node["verb"]?.asString, verb) || !IV.same(node["resource"]?.asString, resource) {
                return .refused(reason: "out_of_plan", detail: "action \(verb) \(resource) does not match committed node '\(nodeId)' (\(JS.toString(node["verb"])) \(JS.toString(node["resource"])))", requiredT: nil, budget: nil)
            }
            let inclusionProof: JSONValue
            do { inclusionProof = try plan.proofFor(nodeId) } catch { return .refused(reason: "out_of_plan", detail: "no inclusion proof for '\(nodeId)': \(error)", requiredT: nil, budget: nil) }

            var inputs: [(ref: String, trusted: Bool)] = []
            if let iv = c[JKey("inputs")] {
                guard let list = iv.asArray else { return .refused(reason: "bad_candidate", detail: "candidate.inputs is not an array", requiredT: nil, budget: nil) }
                for i in list {
                    let ref = i.get("ref")?.asString
                    if i.isObject, i.get("provenance")?.asString == "trusted", let r = ref { inputs.append((r, true)) } else { inputs.append((ref ?? "", false)) }
                }
            }
            let taint = inputs.contains { !$0.trusted } ? 1 : 0
            var riskInputs = baseRisk
            riskInputs[JKey("taint")] = .int(Int64(taint))
            let vals = Risk.KEYS.map { IV.num(riskInputs[JKey($0)]) }
            let r = Self.round6(Risk.riskScore(vals, weights: policy[JKey("weights")]?.asObject ?? [:]))
            let irreversible = IV.same(node["reversibility_class"]?.asString, "irreversible")
            let rt = Risk.requiredThreshold(r, theta1: num("theta1"), theta2: num("theta2"), irreversible: irreversible)

            let nowMs = now()
            let leaked = Risk.leak(budget, now: Double(nowMs), lambda: num("lambda"))
            let cost = Risk.cost(r, kappa: num("kappa"))
            if rt.t < 3, !(leaked.b >= cost) {
                budget = leaked
                return .refused(reason: "over_budget", detail: "budget \(PCAHarness.toFixed4(leaked.b)) < cost \(PCAHarness.toFixed4(cost)); step up to a human co-sign", requiredT: 3, budget: leaked)
            }

            var extras: JObject = [
                "provenance": .object(["causal_hash": .string(IV.strictHash(.array(inputs.map { .object(["ref": .string($0.ref), "provenance": .string($0.trusted ? "trusted" : "untrusted")]) })) ?? ""),
                                       "taint_level": .int(Int64(taint)), "trusted_refs": .array(inputs.filter { $0.trusted }.map { .string($0.ref) })]),
                "risk_claim": .object(["r": PCASandbox.num(r), "inputs": .object(riskInputs)]),
            ]
            let n = nonce()
            extras["nonce"] = .string(n)
            if let a = attestation {
                extras["attestation"] = .object(["quote_digest": .string(""), "epoch": .int(a.epoch ?? 0), "model_id": .string(HARNESS_MODEL_ID), "measurement": .string(harnessMeasurement()), "operator": .string(a.operator)])
            }
            let pcactn: JSONValue
            do {
                pcactn = try PCAIssue.buildPCActn(PCAIssue.ActSpec(grant: grant, chain: chain, plan: plan, nodeId: nodeId, params: c[JKey("params")], counter: Int64(counter + 1), signer: signer,
                                                                   aud: audience, iat: nowMs, ttlMs: ttlMs, extras: extras))
            } catch { return .refused(reason: "bad_candidate", detail: "could not build PCActn: \((error as? PCAProducerError)?.message ?? "\(error)")", requiredT: nil, budget: nil) }

            budget = rt.t < 3 ? Risk.debit(leaked, cost) : leaked
            counter += 1
            return .ok(pcactn: pcactn, inclusionProof: inclusionProof, riskR: r, riskInputs: riskInputs, taint: taint, t: rt.t, budget: budget)
        }

        private static func round6(_ x: Double) -> Double { PCAHarness.jsRound(x * 1e6) / 1e6 }
    }
}
