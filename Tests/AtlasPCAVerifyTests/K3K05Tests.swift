import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Bundle, cursor and authority limits and the failure values, against packages/pca-grants/src/bundle.ts, list-authorized.ts, grant-resource.ts.
final class K3K05Tests: XCTestCase {
    private func bundle(sigs: Int) -> JSONValue {
        .object(["v": .int(1), "kind": .string("pca-policy-bundle"), "revision": .int(1), "issued_at": .int(1), "grants": .array([]), "template_digests": .array([]),
                 "min_verifier_version": .string("1"), "sigs": .array(Array(repeating: .object([:]), count: sigs))])
    }
    private func options(_ threshold: Int64?) -> K3.BundleOptions { K3.BundleOptions(signers: [], threshold: threshold, verifierVersion: "1") }

    func testSignatureCountAndThresholdBounds() {
        let at64 = K3.verifyBundle(bundle(sigs: 64), options(1))
        XCTAssertEqual(at64.code, "below_threshold")
        XCTAssertEqual(at64.reason, "0 valid pinned signature(s), need 1")
        XCTAssertEqual(K3.verifyBundle(bundle(sigs: 65), options(1)).reason, "bad sigs or threshold")
        XCTAssertEqual(K3.verifyBundle(bundle(sigs: 0), options(0)).reason, "bad sigs or threshold")
        XCTAssertEqual(K3.verifyBundle(bundle(sigs: 0), options(0)).code, "malformed")
    }

    func testFailureValuesCarryNothing() {
        XCTAssertEqual(K3.verifyBatch(nil, state: nil, signer: "").next, 0)
        XCTAssertEqual(K3.verifyListCursor(nil, signer: "").skip, 0)
        let rv = K3.verifyRevokeSignature(nil, scope: nil, sig: nil)
        XCTAssertEqual(rv.code, "bad_request")
        XCTAssertFalse(rv.widens)
    }

    func testACursorNeedsBothParts() {
        let p = Base64URLStrict.encode(Array(#"{"v":1,"bind":"b","skip":0,"signer":"S"}"#.utf8))
        XCTAssertEqual(K3.verifyListCursor(.string(p + "."), signer: "S").reason, "malformed")
        XCTAssertEqual(K3.verifyListCursor(.string(".AAAA"), signer: "S").reason, "malformed")
        XCTAssertEqual(K3.verifyListCursor(.string(p + ".AAAA"), signer: "S").reason, "signature")
    }

    private func strings(_ n: Int, _ len: Int = 1) -> JSONValue { .array(Array(repeating: .string(String(repeating: "a", count: len)), count: n)) }
    private func authority(verbs: JSONValue = .array([]), resources: JSONValue = .array([]), extra: JObject = [:]) -> K3.Authority? {
        var o: JObject = ["verbs": verbs, "resources": resources]
        for (k, v) in extra { o[k] = v }
        return K3.Authority(.object(o))
    }

    func testAuthorityBounds() {
        XCTAssertNotNil(authority(verbs: strings(256)))
        XCTAssertNil(authority(verbs: strings(257)))
        XCTAssertNotNil(authority(resources: strings(1024)))
        XCTAssertNil(authority(resources: strings(1025)))
        XCTAssertNotNil(authority(verbs: strings(1, 128)))
        XCTAssertNil(authority(verbs: strings(1, 129)))
        XCTAssertNotNil(authority(resources: strings(1, 512)))
        XCTAssertNil(authority(resources: strings(1, 513)))
    }

    func testOneBadListIsEnough() {
        XCTAssertNil(authority(verbs: .array([.string("v"), .int(1)]), resources: strings(1)))
        XCTAssertNil(authority(verbs: strings(1), resources: .array([.string("r"), .int(1)])))
    }

    func testZeroLimitsAndExpiryAreAllowed() {
        XCTAssertEqual(authority(extra: ["limits": .object(["a": .int(0)])])?.limits["a"], 0)
        XCTAssertNil(authority(extra: ["limits": .object(["a": .int(-1)])]))
        XCTAssertEqual(authority(extra: ["expires_at": .int(0)])?.expiresAt, 0)
        XCTAssertNil(authority(extra: ["expires_at": .int(-1)]))
    }

    func testARevocationNeverWidens() {
        let k = V2F.key("k3-k05-principal")
        let msg: JObject = ["scope": .string("grant"), "grant": .string("g1")]
        let sig = V2F.sign(k, IV.message(K3.GRANT_REVOKE_DOMAIN, .object(msg))!)
        let root: JSONValue = .object(["id": .string("g1"), "principal": .string(V2F.pub(k))])
        let v = K3.verifyRevokeSignature(root, scope: .string("grant"), sig: .string(sig))
        XCTAssertTrue(v.ok, v.code)
        XCTAssertFalse(v.widens)
        XCTAssertEqual(v.scope, "grant")
    }
}
