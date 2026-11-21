import XCTest
@testable import AtlasPCAVerify

/// The strict chain profile at the NVIDIA device chain site (packages/pca/src/attest-nvidia-spdm.ts:224): after the link loop, before the root and
/// pin checks. The issuer rows of the profile are pre-empted there by the older per-link CA check (as in the reference), so they get that exact
/// reason at the site; the profile's own wording for them is pinned in AttestDERStrictChainTests.
final class AttestNvidiaStrictChainTests: XCTestCase {
    typealias F = StrictChainForge

    lazy var pins = [F.pin(F.rootKey)]

    func reason(_ c: F.Chain, pins p: [String]? = nil) -> String { Nvidia.verifyDeviceChain(c.pem, p ?? pins, F.NOW).1 }

    func testControlAndEkuPass() {
        let (chain, why) = Nvidia.verifyDeviceChain(F.chain().pem, pins, F.NOW)
        XCTAssertEqual(why, "")
        XCTAssertEqual(chain?.count, 3)
        XCTAssertEqual(reason(F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_EKU]))), "")
        XCTAssertEqual(reason(F.chain(F.Shape(root: [F.bc(true, pathLen: 1), F.KU_CERT_SIGN]))), "")
    }

    func testProfileViolationsAreRefusedAtTheSite() {
        let cases: [(F.Shape, String)] = [
            (F.Shape(leaf: [F.bc(true), F.KU_SIGN]), F.LEAF_CA_TRUE),
            (F.Shape(root: [F.bc(true, pathLen: 0), F.KU_CERT_SIGN]), "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"),
            (F.Shape(leaf: F.LEAF + [F.CRITICAL_UNKNOWN]), "certificate at depth 0 has an unrecognised critical extension 1.2.3.4"),
            (F.Shape(mid: F.CA + [F.CRITICAL_UNKNOWN]), "certificate at depth 1 has an unrecognised critical extension 1.2.3.4"),
        ]
        for (shape, want) in cases {
            let (chain, why) = Nvidia.verifyDeviceChain(F.chain(shape).pem, pins, F.NOW)
            XCTAssertNil(chain, want)
            XCTAssertEqual(why, "device chain profile: " + want)
        }
    }

    func testIssuerViolationsArePreemptedByThePerLinkCaCheck() {
        let notCA = "device chain cert #1 issues a certificate but is not a CA"
        XCTAssertEqual(reason(F.chain(F.Shape(mid: [F.bc(false), F.KU_CERT_SIGN]))), notCA)
        XCTAssertEqual(reason(F.chain(F.Shape(mid: [F.KU_CERT_SIGN]))), notCA)
        XCTAssertEqual(reason(F.chain(F.Shape(mid: [F.bc(true), F.KU_SIGN]))), notCA)
    }

    func testTheProfileRunsAfterTheLinksAndBeforeTheRootAndPinChecks() {
        let badLeaf = F.Shape(leaf: [F.bc(true), F.KU_SIGN])
        let profile = "device chain profile: " + F.LEAF_CA_TRUE
        XCTAssertEqual(reason(F.chain(badLeaf, leafSigner: F.strangerKey)), "device chain link #0 signature does not verify under its issuer")
        XCTAssertEqual(reason(F.chain(topSigner: F.externalKey)), "device chain root is not a self-signed CA")
        XCTAssertEqual(reason(F.chain(badLeaf, topSigner: F.externalKey)), profile)
        XCTAssertEqual(reason(F.chain(), pins: [F.pin(F.strangerKey)]), "chain root is not a pinned NVIDIA root")
        XCTAssertEqual(reason(F.chain(badLeaf), pins: [F.pin(F.strangerKey)]), profile)
    }

    func testABareRootIsStillJudgedForCriticalExtensions() {
        XCTAssertEqual(Nvidia.verifyDeviceChain(F.pem(F.selfSigned(F.rootKey, "Bare")), pins, F.NOW).1, "")
        XCTAssertEqual(Nvidia.verifyDeviceChain(F.pem(F.selfSigned(F.rootKey, "Bare", exts: F.CA + [F.CRITICAL_UNKNOWN])), pins, F.NOW).1,
                       "device chain profile: certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    }

    func testTheVerifierRefusesWithTheSiteReason() throws {
        let v = try NvidiaVerifier(["rootSpkiSha256": .array([.string(pins[0])]), "policy": .object(["measurements": .object(["1": .string("aa")])])])
        let ev: JObject = ["evidence": .string("AA=="), "certChainPem": .string(F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN])).pem)]
        let r = v.verify(evidence: .object(ev), expected: nil, nowMs: F.NOW)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "device chain profile: " + F.LEAF_CA_TRUE)
    }

    func testRealVectorChainsStillPass() throws {
        try F.assertAcceptedRowsStillPass("nvidia-gpu-spdm", idPrefix: "nv-real-")
    }
}
