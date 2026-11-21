import XCTest
@testable import AtlasPCAVerify

/// Assurance pinned to the reference assurance.ts: the rank tables, the awaiting-audit schemes, multiRootLevel's stable weakest-first
/// fill, the documented defaults (allowUnboundPq / required / allowAwaitingAudit false), the report JSON, and unmetAssurance's rank
/// comparisons (an unknown level ranks 0). Stricter than the reference on purpose: a requirement value the tables do not know is
/// never met (the reference's ZK_NEED lookup gives undefined, and `x < undefined` passes).
final class AssuranceKill2Tests: XCTestCase {
    private func hook(_ level: String) -> LabeledHook<String> { PCA.withAssuranceLabel("h", AssuranceLabel(level: level)) }
    private func root(_ level: String, required: Bool = false) -> AttestationRoot { AttestationRoot(verifier: hook(level), required: required) }

    func testRankTablesAreTheReference() {
        XCTAssertEqual(PCA.ATT_RANK, ["unknown": 0, "software": 1, "hardware": 2, "multi_root": 3])
        XCTAssertEqual(PCA.ZK_RANK, ["unknown": 0, "attested_vm": 1, "attested_vm_hw": 1, "stark": 2, "zkvm": 2, "groth16": 3, "policyvm_snark": 3])
        XCTAssertEqual(PCA.ZK_NEED, ["attested_vm": 1, "attested_vm_hardware": 1, "proof": 2, "snark": 3])
    }

    func testAwaitingAuditSchemes() {
        for s in ["frost", "frost_dkg", "mpc"] { XCTAssertTrue(PCA.isAwaitingAuditScheme(s), s) }
        for s in ["multisig", "", "FROST", "unknown"] { XCTAssertFalse(PCA.isAwaitingAuditScheme(s), s) }
    }

    func testDefaults() {
        XCTAssertFalse(AssuranceSources().allowUnboundPq)
        XCTAssertFalse(AttestationRoot(verifier: nil).required)
        XCTAssertFalse(AssuranceRequirement().allowAwaitingAudit)
    }

    func testMultiRootLevel() {
        XCTAssertEqual(PCA.multiRootLevel([root("foo")], threshold: 1), "unknown") // an unknown label ranks 0
        XCTAssertEqual(PCA.multiRootLevel([root("software")], threshold: 1), "software")
        XCTAssertEqual(PCA.multiRootLevel([root("hardware"), root("software")], threshold: 1), "software") // weakest optional first
        XCTAssertEqual(PCA.multiRootLevel([root("hardware"), root("foo"), root("software")], threshold: 2), "unknown") // foo + software
        XCTAssertEqual(PCA.multiRootLevel([root("software", required: true), root("hardware")], threshold: 2), "hardware")
        XCTAssertEqual(PCA.multiRootLevel([root("software", required: true), root("hardware"), root("software")], threshold: 2), "software")
        // the default is optional: two optional hardware roots with threshold 1 guarantee one
        XCTAssertEqual(PCA.multiRootLevel([AttestationRoot(verifier: hook("hardware")), AttestationRoot(verifier: hook("hardware"))], threshold: 1), "hardware")
        XCTAssertEqual(PCA.multiRootLevel([root("hardware"), root("multi_root")], threshold: 2), "multi_root")
    }

    func testTMemberIsAnIntegerOnlyForASafeInteger() {
        func t(_ x: Double) -> JSONValue? { CheckAssurance(outcome: "pass", t: x).json.get("t") }
        XCTAssertEqual(t(3), .int(3))
        XCTAssertEqual(t(-3), .int(-3))
        XCTAssertEqual(t(2.5), .double(2.5))
        XCTAssertEqual(t(-0.5), .double(-0.5))
        XCTAssertEqual(t(9_007_199_254_740_991), .int(9_007_199_254_740_991))
        XCTAssertEqual(t(9_007_199_254_740_992), .double(9_007_199_254_740_992))
        XCTAssertEqual(t(.infinity), .double(.infinity))
    }

    func testReportOrderKeepsListedPresentMembersThenTheRestSorted() {
        let j: JSONValue = .object(["b": .object(["outcome": .string("pass")]), "a": .object(["outcome": .string("fail")]),
                                    "c": .object(["outcome": .string("pass")])])
        XCTAssertEqual(AssuranceReport(json: j, order: ["zz", "c", "c"]).names, ["c", "a", "b"])
        XCTAssertEqual(AssuranceReport(json: j).names, ["a", "b", "c"])
    }

    func testUnboundPqOnlyWhenAllowedAndANonEd25519SuiteIsPresent() {
        let leaf = [NamedStatus(name: "leaf_signature", status: "pass")]
        let p: JSONValue = .object(["alg": .string("x-unregistered")])
        XCTAssertEqual(PCA.buildAssuranceReport(AssuranceSources(checks: leaf, pcactn: p))["leaf_signature"]?.level, "unknown")
        let chain = [NamedStatus(name: "cap_chain", status: "pass")]
        let ed: JSONValue = .object(["cap_chain": .array([.object([:]), .object(["alg": .null])])])
        XCTAssertEqual(PCA.buildAssuranceReport(AssuranceSources(checks: chain, pcactn: ed, allowUnboundPq: true))["cap_chain"]?.level, "ed25519")
        let empty: JSONValue = .object(["cap_chain": .array([])])
        XCTAssertEqual(PCA.buildAssuranceReport(AssuranceSources(checks: chain, pcactn: empty, allowUnboundPq: true))["cap_chain"]?.level, "unknown")
        let mixed: JSONValue = .object(["cap_chain": .array([.object([:]), .object(["alg": .string("x-unregistered")])])])
        XCTAssertEqual(PCA.buildAssuranceReport(AssuranceSources(checks: chain, pcactn: mixed, allowUnboundPq: true))["cap_chain"]?.level, "unbound_pq")
    }

    private func report(_ name: String, _ level: String?, awaiting: Bool = false) -> AssuranceReport {
        var r = AssuranceReport()
        r.set(name, CheckAssurance(outcome: "pass", level: level, awaitingAudit: awaiting))
        return r
    }

    func testAwaitingAuditRefusedByDefault() {
        XCTAssertEqual(PCA.unmetAssurance(report("attestation", "hardware", awaiting: true), AssuranceRequirement()),
                       "assurance: attestation rests on crypto awaiting audit (hardware); set allowAwaitingAudit or list the scheme to accept it")
        XCTAssertNil(PCA.unmetAssurance(report("attestation", "hardware", awaiting: true), AssuranceRequirement(allowAwaitingAudit: true)))
    }

    func testAttestationRanks() {
        func un(_ have: String?, _ want: String) -> String? { PCA.unmetAssurance(report("attestation", have), AssuranceRequirement(attestation: want)) }
        XCTAssertEqual(un("foo", "software"), "assurance: software attestation required but the evidence is foo")
        XCTAssertEqual(un(nil, "software"), "assurance: software attestation required but the evidence is unknown")
        XCTAssertNil(un("software", "software"))
        XCTAssertNil(un("hardware", "software"))
        XCTAssertNil(un("multi_root", "multi_root"))
        XCTAssertEqual(un("hardware", "multi_root"), "assurance: multi_root attestation required but the evidence is hardware")
        XCTAssertEqual(un("multi_root", "bogus"), "assurance: unknown attestation requirement \"bogus\" (fail closed)")
    }

    func testZkRanks() {
        func un(_ have: String?, _ zk: String) -> String? { PCA.unmetAssurance(report("zk_compliance", have), AssuranceRequirement(zk: zk)) }
        let hwMsg = "assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence"
        XCTAssertEqual(un("foo", "attested_vm"), "assurance: zk compliance (attested_vm) required but the evidence is foo")
        XCTAssertNil(un("attested_vm", "attested_vm"))
        XCTAssertEqual(un("foo", "attested_vm_hardware"), "assurance: zk compliance (attested_vm_hardware) required but the evidence is foo")
        XCTAssertEqual(un("unknown", "attested_vm_hardware"), hwMsg)
        XCTAssertEqual(un(nil, "attested_vm_hardware"), hwMsg)
        XCTAssertEqual(un("attested_vm", "attested_vm_hardware"), hwMsg)
        XCTAssertNil(un("attested_vm_hw", "attested_vm_hardware"))
        XCTAssertEqual(un("attested_vm_hw", "proof"), "assurance: zk compliance (proof) required but the evidence is attested_vm_hw")
        XCTAssertNil(un("zkvm", "proof"))
        XCTAssertNil(un("stark", "proof"))
        XCTAssertEqual(un("zkvm", "snark"), "assurance: zk compliance (snark) required but the evidence is zkvm")
        XCTAssertNil(un("groth16", "snark"))
        XCTAssertNil(un("policyvm_snark", "snark"))
        XCTAssertEqual(un("groth16", "bogus"), "assurance: unknown zk requirement \"bogus\" (fail closed)")
    }

    func testUnknownRequirementsFailClosedInEveryForm() throws {
        func why(_ r: AssuranceRequirement) -> String? { PCA.unmetAssurance(AssuranceReport(), r) }
        func json(_ s: String) throws -> String? { why(AssuranceRequirement(json: try StrictJSON.parse(s))) }
        XCTAssertEqual(why(AssuranceRequirement(signature: "PQ")), "assurance: unknown signature requirement \"PQ\" (fail closed)")
        // "unknown" is a rank, never a requirement; a known level is accepted and asks for evidence
        XCTAssertEqual(why(AssuranceRequirement(attestation: "unknown")), "assurance: unknown attestation requirement \"unknown\" (fail closed)")
        XCTAssertEqual(why(AssuranceRequirement(zk: "bogus")), "assurance: unknown zk requirement \"bogus\" (fail closed)")
        XCTAssertEqual(why(AssuranceRequirement(attestation: "software")), "assurance: software attestation required but there is no attestation evidence")
        XCTAssertEqual(why(AssuranceRequirement(threshold: ["multisig", "bls"])), "assurance: unknown threshold requirement [\"multisig\",\"bls\"] (fail closed)")
        // every listed scheme is known, so the refusal is only the missing evidence, never "unknown requirement"
        XCTAssertEqual(why(AssuranceRequirement(threshold: ["multisig", "frost_dkg", "mpc", "frost"])), "assurance: threshold (multisig | frost_dkg | mpc | frost) required but there is no threshold evidence")
        // the alphabetically first unknown key is named, and it wins over a bad value
        XCTAssertEqual(try json("{\"zzz\":1,\"aaa\":2,\"zk\":\"bogus\"}"), "assurance: unknown requirement aaa (fail closed)")
        // the first bad value wins over a later one
        XCTAssertEqual(try json("{\"attestation\":\"tpm\",\"zk\":\"bogus\",\"signature\":\"x\"}"), "assurance: unknown attestation requirement \"tpm\" (fail closed)")
        XCTAssertEqual(try json("{\"zk\":\"bogus\",\"signature\":\"x\"}"), "assurance: unknown zk requirement \"bogus\" (fail closed)")
        XCTAssertEqual(try json("{\"threshold\":[1]}"), "assurance: unknown threshold requirement [1] (fail closed)")
        XCTAssertNil(AssuranceRequirement(json: try StrictJSON.parse("{\"attestation\":\"software\",\"zk\":\"snark\",\"signature\":\"pq\",\"threshold\":[\"mpc\"],\"allowPreview\":true}")).invalid)
    }
}
