import Foundation

// The binding of the objective-risk functional to the live decision path, without touching the signed PCActn. The facts live in the signed grant
// envelope as an optional `objective_risk` member (covered by the root signature); the registry, resource graph and calibration set are INSTANCE-held
// configuration whose digests must equal the committed ones, or the result is a mismatch (fail closed per `on_mismatch`).
public extension PCAObjectiveRisk {
    /// Resolves the objective risk inputs for `action` under `grant`. Total: it never throws.
    ///  - nothing committed: `{mode: "none"}` (the caller keeps the heuristic);
    ///  - committed and reproduced: `{mode: "objective", inputs: {reversibility, blastRadius, semanticDistance}, r, evidenceDigest}`;
    ///  - committed but not reproducible or invalid: `{mode: "mismatch", reasons, onMismatch}` (`onMismatch` is `deny` unless the grant asks for `heuristic`
    ///    AND the instance config sets `allow_heuristic_fallback: true`: a grant cannot downgrade the verifier's objective risk on its own say-so).
    /// `instance` is `{registry?: {trusted_verifiers?, entries?: [{verb, inverse_kind, fidelity, verification?: {verifier_id, evidence_digest}}]},
    /// graph?: {nodes?, edges?}, calibration?: [number], allow_heuristic_fallback?}`. `taint` and `age` are the verifier's own (default 1, the worst).
    static func resolveObjectiveRisk(grant: JSONValue, action: JSONValue?, instance: JSONValue?, taint: Double? = nil, age: Double? = nil) -> JSONValue {
        let read = PCA.readObjectiveCommitment(grant)
        func mismatch(_ reasons: [String], _ on: String) -> JSONValue {
            .object(["mode": .string("mismatch"), "reasons": .array(reasons.map { .string($0) }), "onMismatch": .string(on)])
        }
        if let m = read.malformed { return mismatch([m], "deny") }
        guard let c = read.commitment else { return .object(["mode": .string("none")]) }
        let requested = c.get("on_mismatch")?.asString ?? "deny"
        let onMismatch = requested == "heuristic" && instance?.get("allow_heuristic_fallback") == .bool(true) ? "heuristic" : "deny"
        func miss(_ reasons: [String]) -> JSONValue { mismatch(reasons, onMismatch) }
        do {
            guard let env = PCA.readEnvelope(grant) else { return miss(["grant carries no valid envelope"]) }
            guard let inst = instance, !inst.isNull else { return miss(["the grant commits objective-risk facts but the instance holds no objective-risk config"]) }
            let reg = inst.get("registry")
            guard let trusted = (JS.present(reg?.get("trusted_verifiers")) ?? .array([])).asArray?.map({ $0.asString }), !trusted.contains(where: { $0 == nil }) else {
                throw JSError("registry trusted_verifiers must be a list of strings")
            }
            let registry = InverseRegistry(trustedVerifiers: trusted.compactMap { $0 })
            for e in (JS.present(reg?.get("entries")) ?? .array([])).asArray ?? [] {
                guard let verb = e.get("verb")?.asString else { throw JSError("a registry entry needs a string verb") }
                var entry: JObject = ["inverseKind": e.get("inverse_kind") ?? .null, "fidelity": e.get("fidelity") ?? .null]
                if let v = JS.present(e.get("verification")) {
                    entry["verification"] = .object(["verifierId": v.get("verifier_id") ?? .null, "evidenceDigest": v.get("evidence_digest") ?? .null])
                }
                registry.register(verb, .object(entry))
            }
            let graph = ResourceGraph()
            let g = inst.get("graph")
            for n in (JS.present(g?.get("nodes")) ?? .array([])).asArray ?? [] { try graph.addNode(n) }
            for e in (JS.present(g?.get("edges")) ?? .array([])).asArray ?? [] { try graph.addEdge(e) }
            let embedder = try nativeHashEmbedder(c.get("embedder")?.get("config"))
            if embedder.modelId != (c.get("embedder")?.get("model_id") ?? .null) { return miss(["embedder model_id does not match the committed one"]) }
            let calibration: [Double]? = inst.get("calibration")?.asArray?.map { IV.num($0) ?? .nan }
            let committedCalibration = c.get("calibration_digest")
            if let cd = committedCalibration {
                guard let cal = calibration, .string(try calibrationDigest(cal)) == cd else { return miss(["calibration set does not match the committed digest"]) }
            }
            var commitments: JObject = ["registryDigest": c.get("registry_digest") ?? .null, "graphDigest": c.get("graph_digest") ?? .null]
            if let cd = committedCalibration { commitments["calibrationDigest"] = cd }
            let ctx = Context(registry: registry, authorizedKinds: c.get("authorized_kinds")?.asArray?.compactMap { $0.asString } ?? [], graph: graph, scope: JS.present(c.get("scope")),
                              embedder: embedder, goal: c.get("goal") ?? .null, commitments: .object(commitments), denominations: c.get("denominations")?.asArray ?? [],
                              weights: env.get("risk_policy")?.get("weights") ?? .null, taint: taint ?? 1, age: age ?? 1,
                              calibration: committedCalibration != nil ? calibration : nil)
            let res = try objectiveRisk(action, ctx)
            if res.get("valid") != .bool(true) { return miss((res.get("reasons")?.asArray ?? []).map { $0.asString ?? "" }) }
            let inputs = res.get("inputs")
            return .object(["mode": .string("objective"),
                            "inputs": .object(["reversibility": inputs?.get("reversibility") ?? .null, "blastRadius": inputs?.get("blastRadius") ?? .null,
                                               "semanticDistance": inputs?.get("semanticDistance") ?? .null]),
                            "r": res.get("r") ?? .null, "evidenceDigest": res.get("evidenceDigest") ?? .null])
        } catch {
            return miss(["objective risk evaluation error (fail closed): \((error as? JSError)?.message ?? "\(error)")"])
        }
    }
}
