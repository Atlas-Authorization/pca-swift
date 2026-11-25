import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A JSON member repeated in a signed or digested document is refused where the reference refuses it (`JSON.parse` keeps the last one, so a signer and a verifier
/// could read different claims from the same bytes). Fixtures are built from raw text so that the duplicate survives, and signed with keys generated here.
final class DuplicateMemberKillTests: XCTestCase {
    private func b64u(_ s: String) -> String { Base64URLStrict.encode(Array(s.utf8)) }

    private func message(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch let e as JSError { return e.message } catch { return "\(error)" }
    }

    // ---- the shared check ----

    func testDuplicateOnlyCheck() throws {
        XCTAssertEqual(NoDuplicateKeys.duplicateKey(#"{"a":1,"a":2}"#), "a")
        XCTAssertEqual(NoDuplicateKeys.duplicateKey(#"{"x":{"k":1,"k":2}}"#), "k")
        XCTAssertEqual(NoDuplicateKeys.duplicateKey(#"{"a":1,"a":2}"#), "a", "keys compare after unescaping")
        XCTAssertEqual(NoDuplicateKeys.duplicateKey(#"{"a":[{"b":1},{"b":2}]}"#), nil, "the same name in two objects is no duplicate")
        XCTAssertEqual(NoDuplicateKeys.duplicateKey(#"{"a":"x","b":"a"}"#), nil, "a value is not a key")
        XCTAssertEqual(NoDuplicateKeys.duplicateKey("{\"\u{e9}\":1,\"e\u{301}\":2}"), nil, "keys are compared scalar by scalar")
        XCTAssertEqual(message { _ = try NoDuplicateKeys.parse(#"{"kind":"x","kind":"y"}"#) }, #"duplicate key "kind""#)
        // numbers are left as written
        XCTAssertNoThrow(try NoDuplicateKeys.parse(#"{"n":8.0,"e":1e3}"#))
    }

    // ---- Stripe webhook body ----

    func testStripeWebhookBodyWithADuplicateMemberIsBadJson() {
        let secret = "whsec_" + String(repeating: "k", count: 24), now = 1_700_000_000.0
        func reply(_ body: String) -> JSONValue {
            PCAPayments.stripeIssuingWebhook(body, signature: PCAPayments.signStripePayload(body, secret, now), secret: secret, nowSec: now, authorize: { _ in .object(["approved": .bool(true)]) })
        }
        let dup = reply(#"{"type":"issuing_authorization.request","type":"other","data":{}}"#)
        XCTAssertEqual(dup.get("status"), .int(400))
        XCTAssertEqual(dup.get("body"), .string(#"{"error":"bad_json"}"#))
        // the same text without the repeat, and non-canonical numbers, are read (an event of another type is acknowledged)
        XCTAssertEqual(reply(#"{"type":"other","n":8.0,"e":1e3}"#).get("status"), .int(200))
    }

    // ---- AP2 SD-JWT JSON ----

    func testAp2JsonRefusesADuplicateMemberWithTheReferenceReason() {
        XCTAssertEqual(message { _ = try PCAAp2.parseJson(.string(#"{"a":1,"a":2}"#), "disclosure") }, #"disclosure: duplicate key "a""#)
        XCTAssertNoThrow(try PCAAp2.parseJson(.string(#"{"a":1000.0}"#), "disclosure"))
    }

    // ---- SD-JWT issuer payload ----

    func testSdJwtIssuerPayloadWithADuplicateMemberIsRefused() {
        func sdjwt(_ payload: String) -> String { "\(b64u(#"{"alg":"EdDSA"}"#)).\(b64u(payload)).\(Base64URLStrict.encode([UInt8](repeating: 1, count: 64)))~" }
        // the strict gate on the issuer JWT refuses it first, naming the key and where it was repeated
        XCTAssertEqual(message { _ = try PCASdJwt.present(sdjwt(#"{"_sd":[],"_sd":["x"]}"#), []) },
                       #"non-canonical compact JWS: bad-json (strict JSON: duplicate key "_sd" (at offset 15))"#)
        XCTAssertNoThrow(try PCASdJwt.present(sdjwt(#"{"a":1,"_sd":[]}"#), []))
    }

    // ---- VC disclosures ----

    func testVcDisclosureWithADuplicateMemberIsMalformed() throws {
        let key = try PCAEdKey.generate()
        func vc(_ disclosureText: String) throws -> String {
            let disclosure = b64u(disclosureText)
            let digest = PCASdJwt.sha(disclosure)
            let header: JSONValue = .object(["alg": .string("EdDSA"), "typ": .string("vc+sd-jwt")])
            let subject: JSONValue = .object(["id": .string("did:example:s"), "_sd": .array([.string(digest)])])
            let payload: JSONValue = .object(["iss": .string("did:example:i"), "sub": .string("did:example:s"), "_sd_alg": .string("sha-256"),
                                              "vc": .object(["@context": .array([.string(PCAVc.VC_CONTEXT), .string(PCAVc.AGENT_PASSPORT_CONTEXT)]),
                                                             "type": .array([.string("VerifiableCredential"), .string(PCAVc.AGENT_PASSPORT_VC_TYPE)]), "credentialSubject": subject])])
            let jwt = try Jose.sign(header: header, headerOrder: ["alg", "typ"], payload: payload, payloadOrder: ["iss", "sub", "_sd_alg", "vc"], signer: { try key.sign($0) })
            return jwt + "~" + disclosure + "~"
        }
        let m = message { _ = try PCAVc.verifyPassportVC(try vc(#"["s","weights_digest",{"a":1,"a":2}]"#), issuerPublicKey: key.pub) }
        XCTAssertEqual(m, "pca-vc: malformed disclosure")
    }

    // ---- EAT header and payload ----

    func testEatHeaderAndPayloadWithADuplicateMemberAreRefused() throws {
        let key = try PCAEdKey.generate()
        func eat(_ header: String, _ payload: String) throws -> String {
            let input = b64u(header) + "." + b64u(payload)
            return input + "." + Base64URLStrict.encode(try key.sign(Array(input.utf8)))
        }
        let typ = PCAAttestEat.EAT_TYP
        func refusal(_ h: String, _ p: String) throws -> String? {
            let t = try eat(h, p)
            return message { _ = try PCAAttestEat.verifyEAT(.string(t), key: .ed25519(key.pub)) }
        }
        // the strict canonical-spelling gate refuses first (before the signature), naming the key and where it was repeated
        XCTAssertEqual(try refusal(#"{"alg":"EdDSA","typ":"\#(typ)"}"#, #"{"iss":"a","iss":"b","iat":1}"#),
                       #"EAT invalid: non-canonical compact JWS: bad-json (strict JSON: duplicate key "iss" (at offset 16))"#)
        XCTAssertEqual(try refusal(#"{"alg":"EdDSA","alg":"none","typ":"\#(typ)"}"#, #"{"iss":"a","iat":1}"#),
                       #"EAT invalid: non-canonical compact JWS: bad-json (strict JSON: duplicate key "alg" (at offset 20))"#)
        XCTAssertNil(try refusal(#"{"alg":"EdDSA","typ":"\#(typ)"}"#, #"{"iss":"a","iat":1}"#))
    }

    // ---- Web Bot Auth key directory ----

    func testKeyDirectoryWithADuplicateMemberIsRefusedByName() {
        let jwk = #"{"kty":"OKP","crv":"Ed25519","x":"nyhMxDazvaOFgheJPwoXUUeByeYzQY0CCEXGg1KRPZg","kid":"ka"}"#
        XCTAssertEqual(message { _ = try PCAWebBotAuth.parseKeyDirectory(#"{"keys":[\#(jwk)],"keys":[]}"#) }, #"duplicate key "keys""#)
        XCTAssertNoThrow(try PCAWebBotAuth.parseKeyDirectory(#"{"keys":[\#(jwk)]}"#))
    }
}
