import Foundation

/// The signing side of the semantic judge: the signed message, the verdict digest, verdict signing under Ed25519 / ML-DSA / the hybrid, the judge's hardware
/// attestation gate, the verifier hook over an action context and the risk contribution of an aggregate score. The legacy unbound post-quantum opt-out
/// does not exist: a post-quantum verdict verifies only under a pinned key.
extension PCAIntentSemantic {
    /// The signed message: the domain, then the strict canonical JSON of the statement (throws on a non-integer, negative-zero or non-finite member).
    public static func semanticJudgeMessage(_ statement: JSONValue) throws -> [UInt8] { try PCAIntentKit.message(SEMANTIC_JUDGE_DOMAIN, statement) }

    /// base64url(sha256(strict canonical form of the verdict)).
    public static func verdictDigest(_ verdict: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(verdict))) }

    /// A judge verdict `{judge, actionDigest, goalCommitment, faithful, score, judgeMeasurement, sig, alg?, pq_pk?, pq_sig?}` signed by `key` (an Ed25519
    /// identity, optionally with a post-quantum suite) over `v = {actionDigest, goalCommitment, faithful, score, judgeMeasurement?}`. The score is quantised
    /// to parts per million inside the signed statement, so a float never reaches the signature.
    public static func signJudgeVerdict(_ key: PCASuiteKey, _ v: JSONValue) throws -> JSONValue {
        guard let ed = key.ed else { throw JSError("signJudgeVerdict: needs an Ed25519 identity key") }
        let jm = JS.present(v.get("judgeMeasurement")).map { JS.toString($0) } ?? ""
        var s = v.asObject ?? [:]
        s["judgeMeasurement"] = .string(jm)
        if key.alg != "ed25519" { s["alg"] = .string(key.alg); if let pk = key.pqPk { s["pq_pk"] = .string(pk) } }
        let parts = try key.sign(try semanticJudgeMessage(try statementOf(.object(s))))
        var out: JObject = ["judge": .string(Base64URLStrict.encode(ed.pub)), "actionDigest": v.get("actionDigest") ?? .null, "goalCommitment": v.get("goalCommitment") ?? .null,
                            "faithful": .bool(v.get("faithful") == .bool(true)), "score": v.get("score") ?? .null, "judgeMeasurement": .string(jm), "sig": .string(parts.sig)]
        if key.alg != "ed25519" { out["alg"] = .string(key.alg); if let pk = key.pqPk { out["pq_pk"] = .string(pk) } }
        if let q = parts.pqSig { out["pq_sig"] = .string(q) }
        return .object(out)
    }

    /// Whether a judge's hardware attestation `{ok, bound, measured, reason?}` is verified, bound to a TEE report, names an identity whose runtime
    /// measurement equals the verdict's signed `judgeMeasurement` and satisfies the approved agent binding. `{ok, reason?, measured?}`.
    public static func verifyJudgeAttestation(_ judgeMeasurement: JSONValue?, _ attestation: JSONValue?, _ approved: JSONValue? = nil) -> JSONValue {
        func no(_ r: JSONValue) -> JSONValue { .object(["ok": .bool(false), "reason": r]) }
        guard let a = attestation, a.isObject, a.get("ok") == .bool(true) else {
            return no(JS.present(attestation?.get("reason")) ?? .string("no verified attestation for this judge (fail-closed)"))
        }
        if a.get("bound") != .bool(true) { return no(.string("judge attestation not bound to a TEE report (report_data binding unconfirmed)")) }
        guard let measured = a.get("measured"), measured.isObject else { return no(.string("judge attestation carries no measured identity")) }
        guard case let .string(jm)? = judgeMeasurement, !jm.isEmpty else { return no(.string("verdict carries no judgeMeasurement to bind to the attested identity")) }
        if !(measured.get("runtime_measurement")?.asString.map { IV.same($0, jm) } ?? false) { return no(.string("attested enclave measurement does not match the signed judgeMeasurement")) }
        if let appraisal = try? PCAAttestation.matchAgentBinding(measured, approved) { return no(.string(appraisal)) }
        return .object(["ok": .bool(true), "measured": measured])
    }

    /// The attestation seam of the ensemble: how to find a verdict's judge attestation, the approved agent binding, and whether it is required.
    public struct Attestation {
        public var resolve: (JSONValue) -> JSONValue?
        public var approved: JSONValue?
        public var require: Bool
        public init(resolve: @escaping (JSONValue) -> JSONValue?, approved: JSONValue? = nil, require: Bool) { self.resolve = resolve; self.approved = approved; self.require = require }

        /// The gate `verifySemanticThreshold` takes: nil when attestation is not required.
        public var gate: ((JSONValue) -> Bool)? {
            require ? { v in PCAIntentSemantic.verifyJudgeAttestation(v.get("judgeMeasurement"), self.resolve(v), self.approved).get("ok") == .bool(true) } : nil
        }
    }

    public struct VerifierOptions {
        public var judgeKeys: JSONValue
        public var k: JSONValue
        public var calibration: JSONValue?
        public var verdicts: (JSONValue) -> JSONValue?
        public var goalCommitment: (JSONValue) -> JSONValue?
        /// Default: the strict canonical hash of the context's `pcactn.action`.
        public var actionDigest: ((JSONValue) throws -> String)?
        public var optionalWhenAbsent: Bool
        public var attestation: ((JSONValue) -> Attestation?)?
        public init(judgeKeys: JSONValue, k: JSONValue, verdicts: @escaping (JSONValue) -> JSONValue?, goalCommitment: @escaping (JSONValue) -> JSONValue?, calibration: JSONValue? = nil,
                    actionDigest: ((JSONValue) throws -> String)? = nil, optionalWhenAbsent: Bool = false, attestation: ((JSONValue) -> Attestation?)? = nil) {
            self.judgeKeys = judgeKeys; self.k = k; self.verdicts = verdicts; self.goalCommitment = goalCommitment; self.calibration = calibration; self.actionDigest = actionDigest
            self.optionalWhenAbsent = optionalWhenAbsent; self.attestation = attestation
        }
    }

    /// The semantic hook: `{enforced, ok?, reason?}` per action context. Without an ensemble it fails closed, or is not enforced when `optionalWhenAbsent`.
    public static func createSemanticVerifier(_ o: VerifierOptions) -> (JSONValue) throws -> JSONValue {
        { ctx in
            guard let goal = o.goalCommitment(ctx), goal.asString != nil, let verdicts = o.verdicts(ctx) else {
                if o.optionalWhenAbsent { return .object(["enforced": .bool(false)]) }
                return .object(["enforced": .bool(true), "ok": .bool(false), "reason": .string("no semantic ensemble available for this action (fail-closed)")])
            }
            let digest = try (o.actionDigest ?? { c in
                guard let a = c.get("pcactn")?.get("action") else { throw JSError("canonicalize: unsupported type undefined") }
                return Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(a)))
            })(ctx)
            var opts: JObject = ["judgeKeys": o.judgeKeys, "k": o.k, "goalCommitment": goal, "actionDigest": .string(digest)]
            if let c = o.calibration { opts["calibration"] = c }
            let res = verifySemanticThreshold(verdicts, .object(opts), o.attestation?(ctx)?.gate)
            if res.get("ok") == .bool(true) { return .object(["enforced": .bool(true), "ok": .bool(true)]) }
            return .object(["enforced": .bool(true), "ok": .bool(false), "reason": .string(res.get("reason")?.asString ?? "semantic threshold not met")])
        }
    }

    /// The risk an aggregate score leaves: 1 - score, clamped to [0, 1]; a non-finite score is full risk.
    public static func semanticRiskContribution(_ aggregateScore: Double) -> Double {
        if !aggregateScore.isFinite { return 1 }
        let r = 1 - aggregateScore
        return r < 0 ? 0 : (r > 1 ? 1 : r)
    }
}
