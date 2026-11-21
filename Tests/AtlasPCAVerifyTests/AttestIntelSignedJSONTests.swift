import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// The signature covers the FIRST member; a later duplicate must never become the body (attest-intel-collateral.test.ts "reads the signed body").
/// The parser refuses every duplicate, escaped spellings included, so this verifier refuses the document where TS reads the signed member.
final class AttestIntelSignedJSONTests: XCTestCase {
    private let sk = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))
    private var key: CertKey {
        var k = CertKey()
        k.typ = "ec"
        k.ecName = "P-256"
        k.point = Array(sk.publicKey.x963Representation)
        return k
    }
    private let genuine = "{\"status\":\"Revoked\"}", forged = "{\"status\":\"UpToDate\"}"
    private func sig() -> String { ACrypto.hex(Array(try! sk.signature(for: Data(genuine.utf8)).rawRepresentation)) }

    func testTheHonestDocumentReadsTheSignedBody() {
        for name in ["tcbInfo", "enclaveIdentity"] {
            let r = IntelCollateral.verifySignedJSON("{\"\(name)\":\(genuine),\"signature\":\"\(sig())\"}", name, key)
            XCTAssertEqual(r.0?[JKey("status")]?.asString, "Revoked")
            XCTAssertEqual(r.1, "")
        }
    }

    func testALaterDuplicateIsRefused() {
        for name in ["tcbInfo", "enclaveIdentity"] {
            let spellings = ["\"\(name)\"", "\"\\u\(String(format: "%04x", name.utf8.first!))\(name.dropFirst())\""]
            for dup in spellings {
                let r = IntelCollateral.verifySignedJSON("{\"\(name)\":\(genuine),\(dup):\(forged),\"signature\":\"\(sig())\"}", name, key)
                XCTAssertNil(r.0, dup)
                XCTAssertEqual(r.1, name + " document is not valid JSON", dup)
            }
        }
    }
}
