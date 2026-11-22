import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAZk)
import AtlasPCAZk
#endif

/// The zk module against the reference corpus (ref-zk.json.gz, every case): commitments, the binding tag, struct hashes, quantization, context
/// pins, the canonical envelope gate, Policy-VM proof verification, the SNARK backends, the attested-VM prover and verifier hook, circuit
/// versions and the ceremony checks.
///
/// Where the package's Groth16 library is linked, it is registered and every case is compared. Without it, an engine that only records
/// that the pairing question was reached is registered: such a case is listed (its answer is the library's), every other case is compared.
final class RefZkTests: XCTestCase {
    typealias Z = PCAZk

    /// An argument the typed API cannot receive. The reference refuses it too; a case where it does not is reported as a divergence.
    struct Unrepresentable: Error {}
    /// The prove case needs the circuit's witness program and proving key (development builds, given through the environment).
    struct NeedsArtifacts: Error {}
    final class Probe { var reached = false }

    static let fns: Set<String> = [
        "constants", "commitmentField", "policyCommitment", "pinnedPolicyCommitment", "actionCommitment", "proverKeyBinding", "policyVmStructHash", "policyVmRiskHash",
        "quantizeActionStruct", "policyVmCommitmentFromAction", "quantizePlanStruct", "quantizePolicyStruct", "quantizePolicyVmInputs", "decodePolicyVmPublic",
        "decodePolicyVmBoundPublic", "policyVmContextMatches", "isCanonicalGroth16Envelope", "verifyPolicyVmProof", "createPolicyVmSnarkBackend",
        "createPolicyVmSnarkBackendBls12381", "createGroth16SnarkBackend", "createPolicyVmBoundSnarkBackend", "createAttestedComplianceProver", "createZkVerifier",
        "circuitVersion", "vkId", "circuitProvenance", "checkCircuitProvenance", "transcriptSha256", "checkTranscript", "ceremonyOf", "provePolicyVmCompliance",
    ]
    /// The cases whose answer is the pairing check's (counted from the reference's gates over the corpus).
    static let pairingCases = 128

    // ---- corpus argument conventions ----------------------------------------------------------------------------------------

    private func obj(_ v: JSONValue?) throws -> JObject {
        guard let o = v?.asObject else { throw Unrepresentable() }
        return o
    }

    private func arr(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw Unrepresentable() }
        return a
    }

    private func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw Unrepresentable() }
        return s
    }

    private func special(_ v: JSONValue?) -> Double? {
        guard let o = v?.asObject, o.count == 1, let s = o["$num"]?.asString else { return nil }
        return s == "NaN" ? .nan : (s == "Infinity" ? .infinity : -.infinity)
    }

    /// A number, or {"$num": "NaN" | "Infinity" | "-Infinity"}.
    private func dbl(_ v: JSONValue?) throws -> Double {
        if let d = special(v) { return d }
        guard let d = IV.num(v) else { throw Unrepresentable() }
        return d
    }

    /// {"$bigint": "<decimal>"} is that integer, {"$num": ...} that double, anything else the JSON value itself (absent stays absent).
    private func zn(_ v: JSONValue?) -> Z.Num {
        if let o = v?.asObject, o.count == 1, let s = o["$bigint"]?.asString, let b = PCABigInt(s) { return .big(b) }
        if let d = special(v) { return .value(.double(d)) }
        return .value(v)
    }

    /// An action document: a JSON document cannot carry a BigInt, so {"$bigint"} becomes the digit string, which the reference's param
    /// scalar reads through the same conversion and range check.
    private func action(_ v: JSONValue) -> JSONValue {
        if let d = special(v) { return .double(d) }
        switch v {
        case let .array(a): return .array(a.map(action))
        case let .object(o):
            if o.count == 1, let s = o["$bigint"]?.asString { return .string(s) }
            return .object(o.mapValues(action))
        default: return v
        }
    }

    private func halves(_ v: JSONValue?) throws -> Z.DigestHalves? {
        guard let v = v else { return nil }
        return Z.DigestHalves(hi: try str(v.get("hi")), lo: try str(v.get("lo")))
    }

    private func json(_ h: Z.DigestHalves) -> JSONValue { .object(["hi": .string(h.hi), "lo": .string(h.lo)]) }
    private func json(_ a: [UInt64]) -> JSONValue { .array(a.map { .object(["$bigint": .string(String($0))]) }) }

    private func quantizeOpts(_ v: JSONValue?) throws -> Z.QuantizeOpts {
        guard let v = v else { return Z.QuantizeOpts() }
        let o = try obj(v)
        func codes(_ k: String) throws -> [String: Z.Num]? {
            guard let m = o[JKey(k)] else { return nil }
            return try obj(m).reduce(into: [String: Z.Num]()) { $0[$1.key.s] = zn($1.value) }
        }
        var field: String?
        if let f = o["paramScalarField"] { field = try str(f) }
        return Z.QuantizeOpts(verbCodes: try codes("verbCodes"), resourceCodes: try codes("resourceCodes"), strictCatalog: o["strictCatalog"] == .bool(true),
                              paramScalarField: field)
    }

    private func plan(_ v: JSONValue?) throws -> Z.QuantizablePlan {
        let o = try obj(v)
        return Z.QuantizablePlan(verb: o["verb"], resource: o["resource"], semanticDist: zn(o["semanticDist"]), planSalt: zn(o["planSalt"]))
    }

    private func policy(_ v: JSONValue?) throws -> Z.QuantizablePolicy {
        let o = try obj(v), w = try obj(o["weights"])
        return Z.QuantizablePolicy(
            alpha: zn(w["alpha"]), beta: zn(w["beta"]), gamma: zn(w["gamma"]), delta: zn(w["delta"]), epsilon: zn(w["epsilon"]), zeta: zn(w["zeta"]),
            theta1: zn(o["theta1"]), theta2: zn(o["theta2"]), kappa: zn(o["kappa"]), budgetB: zn(o["budgetB"]), policyVerb: o["policyVerb"],
            policyResource: o["policyResource"], policyParamBound: zn(o["policyParamBound"]), expiresAt: zn(o["expiresAt"]), notBefore: zn(o["notBefore"]),
            maxBlast: zn(o["maxBlast"]), maxDepth: zn(o["maxDepth"]), revMax: o["revMax"], rateMax: zn(o["rateMax"]), allocParent: zn(o["allocParent"]))
    }

    /// "$absent" = not given; {"$expectThunk": X} = a function returning X ("throw": one that throws).
    private func expectOf(_ e: JSONValue?) -> Z.PolicyVmExpectSource? {
        guard let e = e, e != .string("$absent") else { return nil }
        if let x = e.asObject?["$expectThunk"] {
            return .thunk {
                if x == .string("throw") { throw Unrepresentable() }
                return x
            }
        }
        return .value(e)
    }

    private func verifyOpts(_ v: JSONValue?) throws -> Z.PolicyVmVerifyOpts {
        guard let o = v?.asObject else { return Z.PolicyVmVerifyOpts() }
        return Z.PolicyVmVerifyOpts(verificationKey: o["verificationKey"], expect: expectOf(o["expect"]), expectRiskHash: try halves(o["expectRiskHash"]))
    }

    private func backend(_ kind: String, _ v: JSONValue?) throws -> Z.SnarkBackend {
        var opts = Z.SnarkBackendOpts()
        if let o = v?.asObject {
            opts = Z.SnarkBackendOpts(verificationKey: o["verificationKey"], ceremony: o["ceremony"], expect: expectOf(o["expect"]),
                                      expectActionHash: try halves(o["expectActionHash"]), expectPolicyHash: try halves(o["expectPolicyHash"]),
                                      expectPlanHash: try halves(o["expectPlanHash"]), expectRiskHash: try halves(o["expectRiskHash"]))
        }
        switch kind {
        case "createGroth16SnarkBackend", "groth16": return Z.createGroth16SnarkBackend(opts)
        case "createPolicyVmSnarkBackend", "policyvm": return Z.createPolicyVmSnarkBackend(opts)
        case "createPolicyVmSnarkBackendBls12381", "policyvm-bls": return Z.createPolicyVmSnarkBackendBls12381(opts)
        case "createPolicyVmBoundSnarkBackend", "policyvm-bound": return Z.createPolicyVmBoundSnarkBackend(opts)
        default: throw JSError("unknown backend \(kind)")
        }
    }

    private func label(_ target: Any) -> JSONValue {
        guard let l = PCA.assuranceLabelOf(target) else { return .null }
        var o: JObject = ["level": .string(l.level)]
        if let v = l.vendor { o["vendor"] = .string(v) }
        if l.awaitingAudit { o["awaitingAudit"] = .bool(true) }
        if let c = l.ceremony { o["ceremony"] = .string(c) }
        return .object(o)
    }

    private func layout(_ l: Z.PublicSignalLayout) -> JSONValue {
        var o: JObject = [:]
        for e in l.entries { o[JKey(e.name)] = .int(Int64(e.index)) }
        return .object(o)
    }

    private func constants() -> JSONValue {
        var paths: JObject = [:]
        for (k, v) in [("DEFAULT_VKEY_PATH", Z.DEFAULT_VKEY_PATH), ("DEFAULT_WASM_PATH", Z.DEFAULT_WASM_PATH), ("DEFAULT_ZKEY_PATH", Z.DEFAULT_ZKEY_PATH),
                       ("POLICYVM_VKEY_PATH", Z.POLICYVM_VKEY_PATH), ("POLICYVM_SAMPLE_PROOF_PATH", Z.POLICYVM_SAMPLE_PROOF_PATH), ("POLICYVM_WASM_PATH", Z.POLICYVM_WASM_PATH),
                       ("POLICYVM_ZKEY_PATH", Z.POLICYVM_ZKEY_PATH), ("POLICYVM_BLS12381_VKEY_PATH", Z.POLICYVM_BLS12381_VKEY_PATH),
                       ("POLICYVM_BLS12381_SAMPLE_PROOF_PATH", Z.POLICYVM_BLS12381_SAMPLE_PROOF_PATH), ("POLICYVM_BOUND_VKEY_PATH", Z.POLICYVM_BOUND_VKEY_PATH),
                       ("POLICYVM_BOUND_SAMPLE_PROOF_PATH", Z.POLICYVM_BOUND_SAMPLE_PROOF_PATH), ("POLICYVM_BOUND_WASM_PATH", Z.POLICYVM_BOUND_WASM_PATH),
                       ("POLICYVM_BOUND_ZKEY_PATH", Z.POLICYVM_BOUND_ZKEY_PATH)] { paths[JKey(k)] = .string(v) }
        var o: JObject = [:]
        o["ZK_PROVER_BINDING_REF"] = .string(Z.ZK_PROVER_BINDING_REF)
        o["POLICYVM_PUBLIC_SIGNAL"] = layout(Z.POLICYVM_PUBLIC_SIGNAL)
        o["POLICYVM_PUBLIC_SIGNAL_COUNT"] = .int(Int64(Z.POLICYVM_PUBLIC_SIGNAL_COUNT))
        o["POLICYVM_BOUND_PUBLIC_SIGNAL"] = layout(Z.POLICYVM_BOUND_PUBLIC_SIGNAL)
        o["POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT"] = .int(Int64(Z.POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT))
        o["POLICYVM_BOUND_RISK_FIELDS"] = .array(Z.POLICYVM_BOUND_RISK_FIELDS.map { .string($0) })
        o["POLICYVM_REVERSIBILITY_ORDER"] = .array(Z.POLICYVM_REVERSIBILITY_ORDER.map { .string($0) })
        o["paths"] = .object(paths)
        return .object(o)
    }

    private func zkVerifier(_ specV: JSONValue?, _ ctxV: JSONValue?) throws -> JSONValue {
        let spec = try obj(specV), ctx = try obj(ctxV)
        var o = Z.ZkVerifierOpts()
        // a list that is not an array is no list
        o.trustedProverKeys = (spec["trustedProverKeys"]?.asArray ?? []).compactMap { $0.asString }
        if let p = spec["policyCommitments"] { o.policyCommitments = try arr(p).map { try str($0) } }
        if let r = spec["revokedProverKeys"] { o.revokedProverKeys = try arr(r).map { try str($0) } }
        if let s = spec["clockSkewMs"] { o.clockSkewMs = try dbl(s) }
        let nowMs = try dbl(spec["nowMs"])
        o.now = { nowMs }
        if let snark = spec["snark"], !snark.isNull { o.snarkBackend = try backend(try str(snark.get("kind")), snark.get("opts")) }
        let hook = try Z.createZkVerifier(o)
        let r = hook.verify(pcactn: ctx["pcactn"], grant: ctx["grant"])
        var result: JObject = ["enforced": .bool(r.enforced), "ok": .bool(r.ok)]
        if var reason = r.reason {
            // the text after this prefix is the engine's own and is cut in the corpus
            let cut = "zk verification error (fail closed)"
            if let at = reason.range(of: cut + ": ") { reason = String(reason[..<at.lowerBound]) + cut }
            result["reason"] = .string(reason)
        }
        return .object(["result": .object(result), "label": label(hook)])
    }

    private func prover(_ secret: JSONValue?, _ poV: JSONValue?) throws -> JSONValue {
        guard let seedLabel = secret?.get("$bytes")?.get("$seed")?.asString else { throw Unrepresentable() }
        let seed = Canonical.sha256(Array("atlas-pca-conformance/\(seedLabel)".utf8))
        // RFC 8032 deterministic signatures, as the corpus records them (the platform signer hedges)
        let key = try PCAEdKey(seed: seed, signer: { Ed25519Deterministic.sign(seed: seed, $0) })
        let p = Z.createAttestedComplianceProver(key)
        let po = try obj(poV)
        guard let input = po["decideInput"] else { throw Unrepresentable() }
        let issued = try dbl(po["issued_at"]), expires = try dbl(po["expires_at"])
        let statement = try p.prove(pcactn: po["pcactn"], decideInput: input, issuedAt: issued, expiresAt: expires)
        return .object(["publicKey": .string(p.publicKey), "statement": statement])
    }

    /// The prove case records a contract, not a proof: the committed sample witness must give exactly these public signals and a proof that
    /// verifies under the bundled key. It runs when the artifacts are given and the library is linked.
    private func proveRoundTrip(_ witness: JSONValue?, native: Bool) throws -> JSONValue {
        let env = ProcessInfo.processInfo.environment
        guard native, let w = witness, let wasm = env["PCA_ZK_POLICYVM_WASM"], let zkey = env["PCA_ZK_POLICYVM_ZKEY"], !wasm.isEmpty, !zkey.isEmpty else { throw NeedsArtifacts() }
        let wasmBytes = [UInt8](try Data(contentsOf: URL(fileURLWithPath: wasm))), zkeyBytes = [UInt8](try Data(contentsOf: URL(fileURLWithPath: zkey)))
        let proved = try Z.provePolicyVmCompliance(w, wasm: wasmBytes, zkey: zkeyBytes)
        let key = try Z.policyVmVerificationKey()
        guard try Z.verifyPolicyVmProof(proved, Z.PolicyVmVerifyOpts(verificationKey: key)) else { throw JSError("the fresh proof does not verify under the bundled key") }
        return .object(["publicSignals": proved.get("publicSignals") ?? .null, "verifiesUnder": .string("VK_BN"), "sampleProofCircuit": proved.get("circuit") ?? .null])
    }

    private func text(_ s: String?) -> JSONValue { s.map { JSONValue.string($0) } ?? JSONValue.null }

    private func call(_ c: BaseCase, native: Bool) throws -> JSONValue {
        let a0 = c.arg(0), a1 = c.arg(1)
        switch c.fn {
        case "constants": return constants()
        case "commitmentField": return .string(try Z.commitmentField(try str(a0)))
        case "policyCommitment": return .string(try Z.policyCommitment(a0))
        case "pinnedPolicyCommitment": return .string(try Z.pinnedPolicyCommitment(a0))
        case "actionCommitment": return .string(try Z.actionCommitment(a0))
        case "proverKeyBinding":
            let b = Z.proverKeyBinding(try str(a0), epoch: try dbl(a1), nonce: try str(c.arg(2)))
            return .object(["holderPub": .string(b.holderPub), "grantRef": .string(b.grantRef), "epoch": Z.jnum(b.epoch), "nonce": .string(b.nonce)])
        case "policyVmStructHash": return json(try Z.policyVmStructHash(try arr(a0).map { zn($0) }))
        case "policyVmRiskHash": return json(try Z.policyVmRiskHash(try arr(a0).map { zn($0) }))
        case "quantizeActionStruct": return json(try Z.quantizeActionStruct(a0.map(action), try quantizeOpts(a1)))
        case "policyVmCommitmentFromAction": return json(try Z.policyVmCommitmentFromAction(a0.map(action), try quantizeOpts(a1)))
        case "quantizePlanStruct": return json(try Z.quantizePlanStruct(try plan(a0), try quantizeOpts(a1)))
        case "quantizePolicyStruct": return json(try Z.quantizePolicyStruct(try policy(a0), try quantizeOpts(a1)))
        case "quantizePolicyVmInputs":
            let inp = try obj(a0)
            var pl: Z.QuantizablePlan?, po: Z.QuantizablePolicy?
            if JS.truthy(inp["plan"]) { pl = try plan(inp["plan"]) }
            if JS.truthy(inp["policy"]) { po = try policy(inp["policy"]) }
            let q = try Z.quantizePolicyVmInputs(action: inp["action"].map(action), plan: pl, policy: po, try quantizeOpts(a1))
            var o: JObject = ["action": json(q.action)]
            if let x = q.plan { o["plan"] = json(x) }
            if let x = q.policy { o["policy"] = json(x) }
            return .object(o)
        case "decodePolicyVmPublic": return Z.decodePolicyVmPublic(try arr(a0))
        case "decodePolicyVmBoundPublic": return Z.decodePolicyVmBoundPublic(try arr(a0))
        case "policyVmContextMatches":
            let bound = c.arg(2) == .string("bound")
            return .bool(try Z.policyVmContextMatches(try arr(a0), expectOf(a1), layout: bound ? Z.POLICYVM_BOUND_PUBLIC_SIGNAL : Z.POLICYVM_PUBLIC_SIGNAL))
        case "isCanonicalGroth16Envelope": return .bool(Z.isCanonicalGroth16Envelope(a0, a1?.asString))
        case "verifyPolicyVmProof": return .bool(try Z.verifyPolicyVmProof(a0, try verifyOpts(a1)))
        case "createPolicyVmSnarkBackend", "createPolicyVmSnarkBackendBls12381", "createGroth16SnarkBackend", "createPolicyVmBoundSnarkBackend":
            let b = try backend(c.fn, a0)
            let inp = try obj(a1), pi = try obj(inp["publicInputs"])
            let inputs = Z.PublicInputs(actionCommit: try str(pi["action_commit"]), policyCommit: try str(pi["policy_commit"]), planCommit: try str(pi["plan_commit"]))
            let verified = try b.verify(proof: inp["proof"], publicInputs: inputs, ctx: Z.VerifyContext())
            return .object(["verified": .bool(verified), "label": label(b)])
        case "createZkVerifier": return try zkVerifier(a0, a1)
        case "createAttestedComplianceProver": return try prover(a0, a1)
        case "circuitVersion":
            let v = try Z.circuitVersion(try str(a0))
            return .object(["circuit": .string(v.circuit), "sourceSha256": .string(v.sourceSha256), "circom": .string(v.circom), "circomlib": .string(v.circomlib)])
        case "vkId": return .string(try Z.vkId(a0))
        case "circuitProvenance": return try Z.circuitProvenance(a0)
        case "checkCircuitProvenance": return text(try Z.checkCircuitProvenance(a0, expect: a1))
        case "transcriptSha256": return .string(try Z.transcriptSha256(a0))
        case "checkTranscript":
            let o = a1?.asObject ?? [:]
            var need: Double?
            if let m = o["minContributions"] { need = try dbl(m) }
            return text(Z.checkTranscript(a0, minContributions: need, r1csSha256: o["r1csSha256"], circuit: o["circuit"]))
        case "ceremonyOf": return .string(Z.ceremonyOf(a0, a1))
        case "provePolicyVmCompliance": return try proveRoundTrip(a0, native: native)
        default: throw JSError("unhandled fn \(c.fn)")
        }
    }

    func testTheZkCorpusMatchesTheReference() throws {
        let probe = Probe()
        #if canImport(AtlasPCAZk)
        let native = true
        PCAZkNative.registerCore()
        #else
        let native = false
        PCAZkHook.register(PCAZkHook.Engine(verify: { _, _, _ in probe.reached = true; throw Unrepresentable() },
                                            prove: { _, _, _, _ in probe.reached = true; throw Unrepresentable() }))
        #endif
        defer { PCAZkHook.unregister() }

        var bad: [String] = [], pairing: [String] = [], artifacts: [String] = []
        var seen = Set<String>()
        var compared = 0
        let total = try Base.each("ref-zk.json.gz") { c in
            seen.insert(c.fn)
            guard Self.fns.contains(c.fn) else { bad.append("\(c.name): unhandled fn \(c.fn)"); return }
            probe.reached = false
            let got: BaseGot
            do { got = .value(try call(c, native: native)) } catch is NeedsArtifacts { artifacts.append(c.name); return } catch { got = .threw(nil) }
            if probe.reached { pairing.append(c.name); return }
            compared += 1
            if let d = Base.diff(c, got) { bad.append(d) }
        }
        XCTAssertEqual(total, 1429)
        XCTAssertEqual(seen, Self.fns)
        XCTAssertEqual(compared + pairing.count + artifacts.count, 1429)
        XCTAssertTrue(artifacts.allSatisfy { $0.hasPrefix("provePolicyVmCompliance/") }, "listed for artifacts: \(artifacts)")
        XCTAssertLessThanOrEqual(artifacts.count, 1)
        if native {
            XCTAssertTrue(pairing.isEmpty, "with the library linked every case is compared: \(pairing.prefix(5))")
        } else {
            XCTAssertEqual(pairing.count, Self.pairingCases, "cases that end at the pairing check")
            let owners = ["verifyPolicyVmProof/", "createPolicyVmSnarkBackend", "createGroth16SnarkBackend/", "createPolicyVmBoundSnarkBackend/", "createZkVerifier/snark/"]
            XCTAssertTrue(pairing.allSatisfy { name in owners.contains { name.hasPrefix($0) } })
        }
        K042.report(bad, compared)
    }

    /// The bundled keys are the reference's committed ones (the corpus carries them by value), and each layout has its declared size.
    func testTheBundledKeysAreTheReferenceKeys() throws {
        var keys: [String: JSONValue] = [:]
        try Base.each("ref-zk.json.gz", ["verifyPolicyVmProof"]) { c in
            if c.name == "verifyPolicyVmProof/bn/valid" || c.name == "verifyPolicyVmProof/bls/valid" { keys[c.name] = c.arg(1)?.get("verificationKey") }
        }
        XCTAssertEqual(Base.canon(try Z.policyVmVerificationKey()), Base.canon(keys["verifyPolicyVmProof/bn/valid"]))
        XCTAssertEqual(Base.canon(try Z.policyVmVerificationKeyBls12381()), Base.canon(keys["verifyPolicyVmProof/bls/valid"]))
        XCTAssertEqual(Z.POLICYVM_PUBLIC_SIGNAL.count, Z.POLICYVM_PUBLIC_SIGNAL_COUNT)
        XCTAssertEqual(Z.POLICYVM_BOUND_PUBLIC_SIGNAL.count, Z.POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT)
    }

    /// With no engine registered a proof is never accepted: the Policy-VM check answers false, a backend that reaches the engine throws,
    /// and the verifier hook turns that into a refusal.
    func testNoEngineFailsClosed() throws {
        PCAZkHook.unregister()
        XCTAssertFalse(PCAZkHook.isRegistered)
        var valid: JSONValue?, compliance: BaseCase?
        try Base.each("ref-zk.json.gz", ["verifyPolicyVmProof", "createGroth16SnarkBackend"]) { c in
            if c.name == "verifyPolicyVmProof/bn/valid" { valid = c.arg(0) }
            if c.name == "createGroth16SnarkBackend/bound-wrong-key" { compliance = c }
        }
        let proof = try XCTUnwrap(valid)
        XCTAssertTrue(Z.isCanonicalGroth16Envelope(proof, "bn254"))
        XCTAssertFalse(try Z.verifyPolicyVmProof(proof))
        XCTAssertFalse(try Z.createPolicyVmSnarkBackend().verify(proof: proof, publicInputs: Z.PublicInputs(actionCommit: "", policyCommit: "", planCommit: ""), ctx: Z.VerifyContext()))

        let c = try XCTUnwrap(compliance)
        let inp = try obj(c.arg(1)), pi = try obj(inp["publicInputs"])
        let inputs = Z.PublicInputs(actionCommit: try str(pi["action_commit"]), policyCommit: try str(pi["policy_commit"]), planCommit: try str(pi["plan_commit"]))
        XCTAssertThrowsError(try backend(c.fn, c.arg(0)).verify(proof: inp["proof"], publicInputs: inputs, ctx: Z.VerifyContext()))

        let hook = try Z.createZkVerifier(Z.ZkVerifierOpts(policyCommitments: [inputs.policyCommit], snarkBackend: Z.createPolicyVmSnarkBackend()))
        let out = hook.verify(pcactn: .object(["zk_compliance": proof]), grant: .null)
        XCTAssertTrue(out.enforced)
        XCTAssertFalse(out.ok)
        XCTAssertEqual(out.reason, "snark backend rejected the proof")
        XCTAssertThrowsError(try Z.provePolicyVmCompliance(.object([:]), wasm: [], zkey: []))
    }
}
