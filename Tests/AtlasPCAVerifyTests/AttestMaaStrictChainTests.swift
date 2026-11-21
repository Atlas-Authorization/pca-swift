import XCTest
@testable import AtlasPCAVerify

/// The strict chain profile at both MAA x5c sites (packages/pca/src/attest-azure-maa.ts:395 in-chain anchor, sliced to the anchor; :411 external
/// root, whole chain). The chains are really signed and anchored, so every refusal below comes from the profile.
final class AttestMaaStrictChainTests: XCTestCase {
    typealias F = StrictChainForge

    func verifier(pins: [F.Key] = [], rootsPem: [String] = []) throws -> MaaVerifier {
        try MaaVerifier([
            "trustedIssuers": .array([.string("https://maa.example")]),
            "trustAnchors": .object(["rootSpkiSha256": .array(pins.map { JSONValue.string(F.pin($0)) }), "rootCertsPem": .array(rootsPem.map { JSONValue.string($0) })]),
            "policy": .object(["sevSnpMeasurements": .array([.string("ab")])]),
        ])
    }

    func reason(_ v: MaaVerifier, _ c: F.Chain) -> String { v.verifyX5cChain(c.x5c, F.NOW, 0).1 }

    // ---- in-chain anchor (:395) ----

    func testRootAnchoredControlAndEkuPass() throws {
        let v = try verifier(pins: [F.rootKey])
        let c = F.chain() // ECDSA signatures are randomised: one chain, compared with itself
        let (leaf, why) = v.verifyX5cChain(c.x5c, F.NOW, 0)
        XCTAssertEqual(why, "")
        XCTAssertEqual(leaf?.raw, c.ders[0])
        XCTAssertEqual(reason(v, F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_EKU]))), "")
    }

    func testRootAnchoredEveryViolationIsRefused() throws {
        let v = try verifier(pins: [F.rootKey])
        for row in F.bad {
            let (leaf, why) = v.verifyX5cChain(F.chain(row.shape).x5c, F.NOW, 0)
            XCTAssertNil(leaf, row.name)
            XCTAssertEqual(why, "x5c chain profile: " + row.reason, row.name)
        }
    }

    func testIntermediateAnchorJudgesOnlyTheChainUpToIt() throws {
        let v = try verifier(pins: [F.midKey])
        // above the anchor: never consulted
        XCTAssertEqual(reason(v, F.chain(F.Shape(root: [F.bc(false), F.CRITICAL_UNKNOWN]))), "")
        // at and below the anchor: judged
        XCTAssertEqual(reason(v, F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN]))), "x5c chain profile: " + F.LEAF_CA_TRUE)
        XCTAssertEqual(reason(v, F.chain(F.Shape(mid: [F.bc(true), F.KU_SIGN]))), "x5c chain profile: issuer certificate at depth 1 keyUsage lacks keyCertSign")
        XCTAssertEqual(reason(v, F.chain(F.Shape(mid: F.CA + [F.CRITICAL_UNKNOWN]))), "x5c chain profile: certificate at depth 1 has an unrecognised critical extension 1.2.3.4")
    }

    func testLeafAnchorIsABareCertificateForRolesButNotForExtensions() throws {
        let v = try verifier(pins: [F.leafKey])
        XCTAssertEqual(reason(v, F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN]))), "")
        XCTAssertEqual(reason(v, F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_UNKNOWN]))), "x5c chain profile: certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    }

    func testABrokenLinkIsReportedBeforeTheProfile() throws {
        let v = try verifier(pins: [F.rootKey])
        let c = F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN]), leafSigner: F.strangerKey)
        XCTAssertEqual(reason(v, c), "x5c link 0 is not signed by the certificate above it")
    }

    // ---- external root (:411) ----

    func testExternalRootControlAndEkuPass() throws {
        let v = try verifier(rootsPem: [F.pem(F.selfSigned(F.externalKey, "Strict External Root"))])
        let (leaf, why) = v.verifyX5cChain(F.chain(topSigner: F.externalKey).x5c, F.NOW, 0)
        XCTAssertEqual(why, "")
        XCTAssertNotNil(leaf)
        XCTAssertEqual(reason(v, F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_EKU]), topSigner: F.externalKey)), "")
    }

    func testExternalRootEveryViolationIsRefused() throws {
        let v = try verifier(rootsPem: [F.pem(F.selfSigned(F.externalKey, "Strict External Root"))])
        for row in F.bad {
            let (leaf, why) = v.verifyX5cChain(F.chain(row.shape, topSigner: F.externalKey).x5c, F.NOW, 0)
            XCTAssertNil(leaf, row.name)
            XCTAssertEqual(why, "x5c chain profile: " + row.reason, row.name)
        }
    }

    func testAnUnanchoredChainIsReportedBeforeTheProfile() throws {
        let v = try verifier(rootsPem: [F.pem(F.selfSigned(F.strangerKey, "Stranger"))])
        XCTAssertEqual(reason(v, F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN]), topSigner: F.externalKey)), "x5c chain does not anchor in a configured MAA trust root")
    }

    // ---- through the verifier ----

    func testTheVerifierRefusesWithTheSiteReason() throws {
        let v = try verifier(pins: [F.rootKey])
        let token = F.es256Token(x5c: F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN])).b64)
        let r = v.verify(evidence: .object(["token": .string(token)]), expected: nil, nowMs: F.NOW)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "MAA signing chain invalid: x5c chain profile: " + F.LEAF_CA_TRUE)
    }

    func testRealVectorChainsStillPass() throws {
        try F.assertAcceptedRowsStillPass("azure-maa")
    }
}
