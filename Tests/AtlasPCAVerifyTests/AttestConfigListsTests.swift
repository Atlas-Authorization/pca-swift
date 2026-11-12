import XCTest
@testable import AtlasPCAVerify

/// A malformed allowlist or floor in a verifier configuration is never "no list" (hardware-sevsnp.ts:702-708, attest-intel-tdx.ts:636-645, attest-azure-maa.ts:765,809 throw on a non-string entry;
/// the status lists keep the strings and stay the gate). Stricter than TS: a non-array list (TS skips the check) and a non-numeric floor (hardware-sevsnp.ts:680 and attest-intel-collateral.ts:462 drop it).
final class AttestConfigListsTests: XCTestCase {
    private let hex = String(repeating: "ab", count: 48)
    private let mixed: JSONValue = .array([.string("aa"), .int(1)])

    private func refusal(_ vendor: String, _ cfg: JObject) -> String? {
        do { _ = try VendorVerifier(vendor: vendor, config: cfg) } catch { return (error as? AttestationConfigError)?.message }
        return nil
    }
    private func amd(_ p: JObject) -> JObject {
        var pol: JObject = ["measurements": .array([.string(hex)])]
        for (k, v) in p { pol[k] = v }
        return ["family": .string("milan"), "binding": .string("report-data"), "policy": .object(pol)]
    }
    private func intel(_ p: JObject) -> JObject {
        var pol: JObject = ["mrtds": .array([.string(hex)])]
        for (k, v) in p { pol[k] = v }
        return ["binding": .string("report-data"), "policy": .object(pol)]
    }
    private func maa(_ p: JObject) -> JObject {
        var pol: JObject = ["sevSnpMeasurements": .array([.string("aa")])]
        for (k, v) in p { pol[k] = v }
        return ["trustedIssuers": .array([.string("https://x")]), "trustAnchors": .object(["rootSpkiSha256": .array([.string("ab")])]), "policy": .object(pol)]
    }
    private func gcp(_ p: JObject) -> JObject {
        var pol: JObject = ["imageDigests": .array([.string("sha256:aa")])]
        for (k, v) in p { pol[k] = v }
        return ["trustedIssuers": .array([.string("https://x")]), "trustAnchors": .object(["trustedKeySpki": .array([.string("ab")])]), "policy": .object(pol)]
    }

    func testAmd() {
        let p = "createAmdSnpVerifier: policy."
        for k in ["hostData", "chipIds"] {
            XCTAssertEqual(refusal("amd-sev-snp", amd([JKey(k): mixed])), p + k + " must be an array of strings")
            XCTAssertEqual(refusal("amd-sev-snp", amd([JKey(k): .string("aa")])), p + k + " must be an array of strings")
            XCTAssertNil(refusal("amd-sev-snp", amd([JKey(k): .array([.string("AA")])])))
            XCTAssertNil(refusal("amd-sev-snp", amd([JKey(k): .null])))
        }
        XCTAssertEqual(refusal("amd-sev-snp", amd(["minGuestSvn": .string("5")])), p + "minGuestSvn must be a number")
        XCTAssertNil(refusal("amd-sev-snp", amd(["minGuestSvn": .int(5)])))
        XCTAssertNil(refusal("amd-sev-snp", amd(["minGuestSvn": .null])))
    }

    func testIntelLists() {
        let p = "createIntelDcapVerifier: policy."
        for k in ["fmspcs", "rtmrs"] {
            XCTAssertEqual(refusal("intel-tdx-dcap", intel([JKey(k): mixed])), p + k + " must be an array of strings")
            XCTAssertNil(refusal("intel-tdx-dcap", intel([JKey(k): .array([.string("AA")])])))
        }
        XCTAssertEqual(refusal("intel-tdx-dcap", intel(["collateral": .string("x")])), p + "collateral must be an object")
        XCTAssertNil(refusal("intel-tdx-dcap", intel(["collateral": .null])))
        XCTAssertEqual(refusal("intel-tdx-dcap", intel(["collateral": .object(["acceptStatuses": .string("UpToDate")])])), p + "collateral.acceptStatuses must be an array")
    }

    func testIntelStatusListStaysTheGate() throws {
        let v = try DcapVerifier(intel(["collateral": .object(["acceptStatuses": .array([.string("SWHardeningNeeded"), .int(1)])])]))
        XCTAssertTrue(v.collateralPol.hasAccept)
        XCTAssertEqual(v.collateralPol.acceptStatuses, ["SWHardeningNeeded"])
        let none = try DcapVerifier(intel(["collateral": .object(["acceptStatuses": .null])]))
        XCTAssertFalse(none.collateralPol.hasAccept)
    }

    func testMinTcbEvaluationDataNumberCoercesAsTheComparison() throws {
        func floor(_ v: JSONValue) throws -> DcapVerifier { try DcapVerifier(intel(["collateral": .object(["minTcbEvaluationDataNumber": v])])) }
        let cases: [(JSONValue, Double)] = [(.int(5), 5), (.string("5"), 5), (.string(" 0x10 "), 16), (.string(""), 0), (.double(1.5), 1.5)]
        for (v, want) in cases {
            let c = try floor(v).collateralPol
            XCTAssertTrue(c.hasMinEval, "\(v)")
            XCTAssertEqual(c.minEval, want, "\(v)")
        }
        XCTAssertFalse(try floor(.null).collateralPol.hasMinEval)
        let msg = "createIntelDcapVerifier: policy.collateral.minTcbEvaluationDataNumber must be a number"
        for bad in [JSONValue.string("abc"), .bool(true), .array([]), .object([:])] {
            XCTAssertEqual(refusal("intel-tdx-dcap", intel(["collateral": .object(["minTcbEvaluationDataNumber": bad])])), msg, "\(bad)")
        }
    }

    func testMaa() throws {
        let p = "createAzureMaaVerifier: policy."
        for k in ["sevSnpHostData", "tdxRtmrs", "tdxMrtds"] {
            XCTAssertEqual(refusal("azure-maa", maa([JKey(k): mixed])), p + k + " must be an array of strings")
        }
        XCTAssertEqual(refusal("azure-maa", ["trustedIssuers": .array([.string("https://x")]), "trustAnchors": .object(["rootSpkiSha256": .array([.string("ab")])]), "policy": .object(["sevSnpMeasurements": mixed, "tdxMrtds": .array([.string("aa")])])]),
                       p + "sevSnpMeasurements must be an array of strings")
        XCTAssertEqual(refusal("azure-maa", maa(["tdxAllowedTcbStatuses": .string("UpToDate")])), p + "tdxAllowedTcbStatuses must be an array")
        let v = try MaaVerifier(maa(["tdxAllowedTcbStatuses": .array([.string("SWHardeningNeeded"), .int(1)])]))
        XCTAssertTrue(v.policy.hasTdxStatuses)
        XCTAssertEqual(v.policy.tdxStatuses, ["SWHardeningNeeded"])
        XCTAssertFalse(try MaaVerifier(maa(["tdxAllowedTcbStatuses": .null])).policy.hasTdxStatuses)
    }

    func testGcp() throws {
        XCTAssertEqual(refusal("gcp-confidential-space", gcp(["allowedSwVersions": .string("1")])), "createGcpConfidentialSpaceVerifier: policy.allowedSwVersions must be an array")
        XCTAssertNil(refusal("gcp-confidential-space", gcp(["allowedSwVersions": .null])))
        let v = try GcpVerifier(gcp(["allowedSwVersions": .array([.string("1"), .int(2)])]))
        XCTAssertEqual(v.swVersions, ["1"])
    }

    func testNvidiaRequireCrlIssuers() throws {
        let col: JObject = ["rimRootSpkiSha256": .array([.string("ab")])]
        func make(_ v: JSONValue) throws -> NvidiaHook { var c = col; c["requireCrlIssuers"] = v; return try NvidiaHook(c) }
        XCTAssertThrowsError(try make(.array([.int(1)])))
        XCTAssertThrowsError(try make(.string("x")))
        XCTAssertEqual(try make(.array([.string("CN=a")])).requireIssuers, ["CN=a"])
        XCTAssertEqual(try make(.null).requireIssuers, [])
    }

    /// The ARK pin is the root of trust: `trustAnchorArkSpkiSha384` in a production configuration is not read (attest-amd-snp.ts:83,108 has no such option).
    func testAProductionConfigurationCannotReplaceTheArkPin() throws {
        let doc = try AttestVectorTests.loadVectors()
        let blobs = doc.get("blobs")?.asObject ?? [:]
        let rows = (doc.get("attestation_vectors")?.asArray ?? []).map { AttestVectorTests.hydrate($0, blobs) }
        let row = try XCTUnwrap(rows.first { $0.get("vendor")?.asString == "amd-sev-snp" && $0.get("config")?.get("trustAnchorArkSpkiSha384") != nil && $0.get("expect")?.get("ok") == .bool(true) })
        let cfg = row.get("config")?.asObject
        let now = Int64(Attest.asFinite(row.get("now")) ?? 0), want = AttestVectorTests.binding(row.get("expected_binding"))
        XCTAssertTrue(try VendorVerifier.forConformance(vendor: "amd-sev-snp", config: cfg).verify(evidence: row.get("evidence"), expected: want, nowMs: now).ok)
        let r = try VendorVerifier(vendor: "amd-sev-snp", config: cfg).verify(evidence: row.get("evidence"), expected: want, nowMs: now)
        XCTAssertFalse(r.ok)
        XCTAssertTrue(r.reason.contains("cert chain invalid"), r.reason)
    }
}
