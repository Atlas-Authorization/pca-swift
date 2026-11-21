import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// MAA boundaries, pinned to packages/pca/src/attest-azure-maa.ts: anchors :646, signing x5c :588/:599, key type :428, time window :702-709.
final class AttestMaaK05Tests: XCTestCase {
    typealias F = StrictChainForge

    static let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x66, count: 32))
    static let spki: [UInt8] = {
        let p256: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        return F.seq(F.seq(F.oid(F.OID_EC) + F.oid(p256)) + DERB.tlv(0x03, [0x00] + Array(AttestMaaK05Tests.key.publicKey.x963Representation)))
    }()
    /// A P-256 leaf (ES256 needs one; the forge's keys are P-384), pinned itself so its issuer's signature is never consulted.
    static let leaf: [UInt8] = {
        let alg = F.seq(F.oid(F.OID_ECDSA_SHA384))
        var body: [UInt8] = DERB.tlv(0xa0, DERB.tlv(0x02, [0x02]))
        body += DERB.tlv(0x02, [7])
        body += alg
        body += F.name("Strict Root")
        body += F.seq(DERB.tlv(0x17, Array("250101000000Z".utf8)) + DERB.tlv(0x17, Array("350101000000Z".utf8)))
        body += F.name("P-256 Leaf")
        body += AttestMaaK05Tests.spki
        body += DERB.tlv(0xa3, F.seq(F.LEAF.flatMap { $0 }))
        let tbs = F.seq(body)
        let signature = try! F.rootKey.signature(for: Data(tbs))
        return F.seq(tbs + alg + DERB.tlv(0x03, [0x00] + Array(signature.derRepresentation)))
    }()

    static let nowSec = F.NOW / 1000
    static let PASSED = "no expected attestation binding supplied" // the first check after the time window and the attestation type

    func verifier(skew: Int64 = 0, policy: JObject = ["sevSnpMeasurements": .array([.string("ab")])]) throws -> MaaVerifier {
        try MaaVerifier([
            "trustedIssuers": .array([.string("https://maa.example")]),
            "trustAnchors": .object(["rootSpkiSha256": .array([.string(ACrypto.hex(ACrypto.sha256(Self.spki)))])]),
            "policy": .object(policy),
            "clockSkewMs": .int(skew),
        ])
    }

    func token(exp: Int64, iat: Int64? = nil) -> String {
        let header = "{\"alg\":\"ES256\",\"x5c\":[\"" + Attest.base64StdEncode(Self.leaf) + "\"]}"
        var claims = "{\"iss\":\"https://maa.example\",\"x-ms-attestation-type\":\"sevsnpvm\",\"exp\":\(exp)"
        if let i = iat { claims += ",\"iat\":\(i)" }
        claims += "}"
        let input = Base64URLStrict.encode(Array(header.utf8)) + "." + Base64URLStrict.encode(Array(claims.utf8))
        let sig = try! Self.key.signature(for: Data(input.utf8)).rawRepresentation
        return input + "." + Base64URLStrict.encode(Array(sig))
    }

    func reason(skew: Int64, exp: Int64, iat: Int64? = nil) throws -> String {
        try verifier(skew: skew).verify(evidence: .object(["token": .string(token(exp: exp, iat: iat))]), expected: nil, nowMs: F.NOW).reason
    }

    // ---- constructor ----

    func testTheAnchorCountIsASum() throws {
        let cfg: JObject = [
            "trustedIssuers": .array([.string("https://maa.example")]),
            "trustAnchors": .object(["rootCertsPem": .array([.string("x")]), "rootSpkiSha256": .array([.string("y")])]),
            "policy": .object(["sevSnpMeasurements": .array([.string("ab")])]),
        ]
        XCTAssertNoThrow(try MaaVerifier(cfg))
    }

    /// Inserted in byte order, so the reference's Object.entries reports the first too (a JObject keeps no insertion order, hence the sort).
    func testTheFirstUnknownTcbFieldIsReported() throws {
        var m: JObject = [:]
        for i in 100..<300 { m[JKey("k\(i)")] = .int(1) }
        XCTAssertThrowsError(try verifier(policy: ["sevSnpMeasurements": .array([.string("ab")]), "sevSnpMinTcb": .object(m)])) {
            XCTAssertEqual(($0 as? AttestError)?.message, "createAzureMaaVerifier: policy.sevSnpMinTcb.k100 is not a known field (bootloader | snp | microcode | tee)")
        }
    }

    // ---- signing x5c ----

    func testAnEmptyKidIsNoKid() {
        var tok = JwtParsed()
        tok.hasKid = true
        tok.kid = ""
        let jwks: JSONValue = .object(["keys": .array([.object(["x5c": .array([.string("c")])])])])
        let (x5c, why) = MaaVerifier.resolveSigningX5c(tok, jwks)
        XCTAssertEqual(x5c, [JSONValue.string("c")])
        XCTAssertEqual(why, "")
    }

    func testAnEmptyHeaderX5cIsNoX5c() {
        var tok = JwtParsed()
        tok.hasX5c = true
        let (x5c, why) = MaaVerifier.resolveSigningX5c(tok, nil)
        XCTAssertNil(x5c)
        XCTAssertEqual(why, "no signing x5c available (no JWKS and no header x5c)")
    }

    func testEs256NeedsP256() throws {
        var tok = JwtParsed()
        tok.alg = "ES256"
        tok.signature = [UInt8](repeating: 1, count: 64)
        let p384Leaf = try Cert.parseDER(F.chain().ders[0])
        XCTAssertEqual(try verifier().jwsSignature(tok, p384Leaf), "ES256 token but signing key is EC/P-384 (not EC P-256)")
    }

    // ---- time window: skewSec = ceil(skew / 1000) ----

    func testExpWithSkew() throws {
        let now = Self.nowSec
        XCTAssertEqual(try reason(skew: 0, exp: now), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1000, exp: now - 1), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1000, exp: now - 2), "MAA token expired")
        XCTAssertEqual(try reason(skew: 1001, exp: now - 2), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1001, exp: now - 3), "MAA token expired")
    }

    func testIatWithSkew() throws {
        let now = Self.nowSec
        XCTAssertEqual(try reason(skew: 1000, exp: now + 100, iat: now + 1), Self.PASSED)
        XCTAssertEqual(try reason(skew: 1000, exp: now + 100, iat: now + 2), "MAA token issued in the future (iat)")
    }

    // ---- SEV-SNP TCB claims ----

    func testTcbClaims() throws {
        let v = try verifier(policy: ["sevSnpMeasurements": .array([.string("ab")]), "sevSnpMinTcb": .object(["bootloader": .int(1)])])
        let m = "x-ms-sevsnpvm-launchmeasurement", c = "x-ms-sevsnpvm-bootloader-svn"
        XCTAssertEqual(v.sevSnpResult([JKey(m): .string("ab"), JKey(c): .int(2)]).hostAsserted?["bootloader_svn"], "2")
        XCTAssertEqual(v.sevSnpResult([JKey(m): .string("ab"), JKey(c): .int(0)]).reason, "SEV-SNP bootloader SVN 0 is below the policy minimum 1")
        let missing = "SEV-SNP bootloader SVN claim '\(c)' is missing or not a non-negative integer (policy requires a minimum)"
        XCTAssertEqual(v.sevSnpResult([JKey(m): .string("ab")]).reason, missing)
        XCTAssertEqual(v.sevSnpResult([JKey(m): .string("ab"), JKey(c): .double(-0.0)]).reason, missing)
    }
}
