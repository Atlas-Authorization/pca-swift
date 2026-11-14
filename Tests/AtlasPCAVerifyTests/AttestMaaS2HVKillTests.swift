import XCTest
@testable import AtlasPCAVerify

/// Heavy-fixture kill test (heavy-brief item 6, AttestMaa.swift line 143): the SPKI of a configured root CERTIFICATE is an anchor
/// fingerprint, exactly like a pinned `rootSpkiSha256`, so a chain that runs on above it is judged only up to it.
final class AttestMaaS2HVKillTests: XCTestCase {
    typealias F = StrictChainForge

    func testAConfiguredRootCertificateAnchorsTheChainInPlace() throws {
        let midPem = F.pem(F.chain().ders[1])
        let v = try MaaVerifier([
            "trustedIssuers": .array([.string("https://maa.example")]),
            "trustAnchors": .object(["rootSpkiSha256": .array([]), "rootCertsPem": .array([.string(midPem)])]),
            "policy": .object(["sevSnpMeasurements": .array([.string("ab")])]),
        ])
        // the certificate above the anchor is never consulted (it is not even signed by the configured root)
        let c = F.chain(F.Shape(root: [F.bc(false), F.CRITICAL_UNKNOWN]))
        let (leaf, why) = v.verifyX5cChain(c.x5c, F.NOW, 0)
        XCTAssertEqual(why, "", "line 143")
        XCTAssertEqual(leaf?.raw, c.ders[0])
        // at and below the anchor the profile still applies
        let bad = F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN]))
        XCTAssertEqual(v.verifyX5cChain(bad.x5c, F.NOW, 0).1, "x5c chain profile: " + F.LEAF_CA_TRUE)
    }
}
