import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Confidential Space boundaries, pinned to packages/pca/src/attest-gcp-confidential-space.ts: anchors :647, kid :427/:437/:443, key type :497, time window :700-707.
final class AttestGcpK05Tests: XCTestCase {
    typealias F = StrictChainForge

    static let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x66, count: 32))
    static let jwk: JObject = {
        let p = Array(AttestGcpK05Tests.key.publicKey.x963Representation.dropFirst())
        return ["kty": .string("EC"), "crv": .string("P-256"), "x": .string(Base64URLStrict.encode(Array(p.prefix(32)))), "y": .string(Base64URLStrict.encode(Array(p.suffix(32))))]
    }()

    static let nowSec = F.NOW / 1000
    static let PASSED = "token carries no submods.confidential_space (not a Confidential Space token)" // the first check after the time window

    func verifier(_ anchors: JObject, skew: Int64 = 0) throws -> GcpVerifier {
        try GcpVerifier([
            "trustedIssuers": .array([.string("https://gcp.example")]),
            "trustAnchors": .object(anchors),
            "policy": .object(["imageDigests": .array([.string("sha256:aa")])]),
            "clockSkewMs": .int(skew),
        ])
    }

    var trusted: JObject { ["trustedJwks": .object(["keys": .array([.object(Self.jwk)])])] }

    func reason(skew: Int64, exp: Int64? = nil, nbf: Int64? = nil, iat: Int64? = nil) throws -> String {
        var claims = "{\"iss\":\"https://gcp.example\",\"exp\":\(exp ?? Self.nowSec + 100)"
        if let n = nbf { claims += ",\"nbf\":\(n)" }
        if let i = iat { claims += ",\"iat\":\(i)" }
        claims += "}"
        let input = Base64URLStrict.encode(Array("{\"alg\":\"ES256\"}".utf8)) + "." + Base64URLStrict.encode(Array(claims.utf8))
        let sig = try! Self.key.signature(for: Data(input.utf8)).rawRepresentation
        let token = input + "." + Base64URLStrict.encode(Array(sig))
        return try verifier(trusted, skew: skew).verify(evidence: .object(["token": .string(token)]), expected: nil, nowMs: F.NOW).reason
    }

    // ---- constructor ----

    func testTheAnchorCountIsASum() {
        let one = JSONValue.array([.string("x")])
        XCTAssertNoThrow(try verifier(["trustedJwks": .object(["keys": .array([.object(Self.jwk)])]), "trustedKeySpki": one]))
        XCTAssertNoThrow(try verifier(["trustedKeySpki": one, "rootCertsPem": one]))
    }

    // ---- kid ----

    func emptyKid() -> JwtParsed {
        var tok = JwtParsed()
        tok.hasKid = true
        tok.kid = ""
        return tok
    }

    func testAnEmptyKidPicksTheSoleKey() {
        XCTAssertEqual(GcpVerifier.pickJwk(emptyKid(), [Self.jwk]), Self.jwk)
    }

    func testAnEmptyKidIsReportedAsNoKid() throws {
        let v = try verifier(["trustedKeySpki": .array([.string("x")])])
        let (key, why) = v.signingKey(emptyKid(), nil, F.NOW)
        XCTAssertNil(key)
        XCTAssertEqual(why, "no kid on the token and no unambiguous single signing key available")
    }

    /// The header's x5c is only a fallback: it never replaces a key the JWKS supplied.
    func testAHeaderX5cDoesNotReplaceAJwksKey() throws {
        let v = try verifier(trusted)
        var tok = JwtParsed()
        tok.hasX5c = true
        tok.x5c = F.chain().b64
        let (key, why) = v.signingKey(tok, .object(["keys": .array([.object(Self.jwk)])]), F.NOW)
        XCTAssertEqual(why, "")
        XCTAssertEqual(key?.ecName, "P-256")
    }

    func testEs256NeedsP256() throws {
        let p = Array(F.externalKey.publicKey.x963Representation.dropFirst())
        let k = try JWS.jwkECKey("P-384", Base64URLStrict.encode(Array(p.prefix(48))), Base64URLStrict.encode(Array(p.suffix(48))))
        var tok = JwtParsed()
        tok.alg = "ES256"
        XCTAssertEqual(try verifier(trusted).jwsSignature(tok, k), "ES256 token but signing key is EC/P-384 (not EC P-256)")
    }

    // ---- time window: skewSec = ceil(skew / 1000) ----

    func testExpWithSkew() throws {
        let now = Self.nowSec
        XCTAssertEqual(try reason(skew: 1000, exp: now - 1), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1000, exp: now - 2), "Confidential Space token expired")
        XCTAssertEqual(try reason(skew: 1001, exp: now - 2), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1001, exp: now - 3), "Confidential Space token expired")
    }

    func testNbfWithSkew() throws {
        let now = Self.nowSec
        XCTAssertEqual(try reason(skew: 0, nbf: now), Self.PASSED)
        XCTAssertEqual(try reason(skew: 0, nbf: now + 1), "Confidential Space token not yet valid (nbf)")
        XCTAssertEqual(try reason(skew: 1000, nbf: now + 1), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1000, nbf: now + 2), "Confidential Space token not yet valid (nbf)")
    }

    func testIatWithSkew() throws {
        let now = Self.nowSec
        XCTAssertEqual(try reason(skew: 0, iat: now), Self.PASSED)
        XCTAssertEqual(try reason(skew: 0, iat: now + 1), "Confidential Space token issued in the future (iat)")
        XCTAssertEqual(try reason(skew: 1000, iat: now + 1), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1000, iat: now + 2), "Confidential Space token issued in the future (iat)")
    }
}
