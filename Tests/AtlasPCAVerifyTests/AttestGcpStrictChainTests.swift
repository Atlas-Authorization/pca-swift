import XCTest
@testable import AtlasPCAVerify

/// The strict chain profile at the GCP JWK x5c site (packages/pca/src/attest-gcp-confidential-space.ts:384): the whole chain, after the links and
/// BEFORE the anchor lookup. The chains are really signed, so every refusal below comes from the profile.
final class AttestGcpStrictChainTests: XCTestCase {
    typealias F = StrictChainForge

    func verifier(pins: [F.Key] = [], rootsPem: [String] = []) throws -> GcpVerifier {
        try GcpVerifier([
            "trustedIssuers": .array([.string("https://gcp.example")]),
            "trustAnchors": .object(["trustedKeySpki": .array(pins.map { JSONValue.string(F.pin($0)) }), "rootCertsPem": .array(rootsPem.map { JSONValue.string($0) })]),
            "policy": .object(["imageDigests": .array([.string("sha256:aa")])]),
        ])
    }

    func testPinnedControlAndEkuPass() throws {
        let v = try verifier(pins: [F.rootKey])
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain().x5c, F.NOW), "")
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_EKU])).x5c, F.NOW), "")
    }

    func testPinnedEveryViolationIsRefused() throws {
        let v = try verifier(pins: [F.rootKey])
        for row in F.bad { XCTAssertEqual(v.verifyJwkX5cChain(F.chain(row.shape).x5c, F.NOW), "x5c chain profile: " + row.reason, row.name) }
    }

    func testRootPemControlAndEveryViolation() throws {
        let v = try verifier(rootsPem: [F.pem(F.selfSigned(F.externalKey, "Strict External Root"))])
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain(topSigner: F.externalKey).x5c, F.NOW), "")
        for row in F.bad { XCTAssertEqual(v.verifyJwkX5cChain(F.chain(row.shape, topSigner: F.externalKey).x5c, F.NOW), "x5c chain profile: " + row.reason, row.name) }
    }

    /// Unlike MAA the reference does not slice: a pinned intermediate still has the whole presented chain judged.
    func testAPinnedIntermediateStillHasTheWholeChainJudged() throws {
        let v = try verifier(pins: [F.midKey])
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain().x5c, F.NOW), "")
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain(F.Shape(root: [F.bc(false)])).x5c, F.NOW), "x5c chain profile: issuer certificate at depth 2 is not a CA (BasicConstraints CA:FALSE)")
    }

    func testTheProfileRunsAfterTheLinksAndBeforeTheAnchorLookup() throws {
        let v = try verifier(pins: [F.strangerKey])
        let badLeaf = F.Shape(leaf: [F.bc(true), F.KU_SIGN])
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain().x5c, F.NOW), "x5c chain does not anchor in a configured GCP trust root")
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain(badLeaf).x5c, F.NOW), "x5c chain profile: " + F.LEAF_CA_TRUE)
        XCTAssertEqual(v.verifyJwkX5cChain(F.chain(badLeaf, leafSigner: F.strangerKey).x5c, F.NOW), "x5c link 0 is not signed by the certificate above it")
    }

    func testTheSigningKeyLookupRefusesWithTheSiteReason() throws {
        let v = try verifier(pins: [F.rootKey])
        var tok = JwtParsed()
        tok.hasX5c = true
        tok.x5c = F.chain().b64
        let (key, why) = v.signingKey(tok, nil, F.NOW)
        XCTAssertEqual(why, "")
        XCTAssertEqual(key?.spkiSHA256, F.pin(F.leafKey))
        tok.x5c = F.chain(F.Shape(mid: F.CA + [F.CRITICAL_UNKNOWN])).b64
        let (key2, why2) = v.signingKey(tok, nil, F.NOW)
        XCTAssertNil(key2)
        XCTAssertEqual(why2, "signing key not trusted: x5c chain profile: certificate at depth 1 has an unrecognised critical extension 1.2.3.4")
    }

    func testTheVerifierRefusesWithTheSiteReason() throws {
        let v = try verifier(pins: [F.rootKey])
        let token = F.es256Token(x5c: F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN])).b64)
        let r = v.verify(evidence: .object(["token": .string(token)]), expected: nil, nowMs: F.NOW)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "Confidential Space signing key invalid: signing key not trusted: x5c chain profile: " + F.LEAF_CA_TRUE)
    }

    func testVectorChainsStillPass() throws {
        try F.assertAcceptedRowsStillPass("gcp-confidential-space")
    }

    /// A JWK's own key material is not certified by the x5c it carries: a genuine chain must not anchor an attacker's x / y, under either anchor kind
    /// (attest-gcp-confidential-space.ts, the `x5c chain to a configured root?` branch).
    func testAGenuineChainDoesNotAnchorAnotherKey() throws {
        let chain = F.chain()
        func jwk(_ k: F.Key) -> JSONValue {
            let p = Array(k.publicKey.x963Representation.dropFirst())
            return .object(["keys": .array([.object(["kty": .string("EC"), "crv": .string("P-384"), "x": .string(Base64URLStrict.encode(Array(p.prefix(48)))),
                                                     "y": .string(Base64URLStrict.encode(Array(p.suffix(48)))), "x5c": .array(chain.x5c)])])])
        }
        for v in [try verifier(pins: [F.rootKey]), try verifier(rootsPem: [F.pem(F.selfSigned(F.rootKey, "Strict Root"))])] {
            let (forged, why) = v.signingKey(JwtParsed(), jwk(F.strangerKey), F.NOW)
            XCTAssertNil(forged)
            XCTAssertEqual(why, "signing key not trusted: the JWK key is not the key of its x5c leaf")
            let (honest, why2) = v.signingKey(JwtParsed(), jwk(F.leafKey), F.NOW)
            XCTAssertEqual(why2, "")
            XCTAssertEqual(honest?.spkiSHA256, F.pin(F.leafKey))
        }
    }
}
