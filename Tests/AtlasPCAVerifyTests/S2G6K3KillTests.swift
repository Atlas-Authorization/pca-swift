import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kill tests (mutation sheet swift-k05 group 6) for K3.swift: version syntax, bundle shape bounds, the list-cursor inner member and
/// the need-approval merge.
final class S2G6K3KillTests: XCTestCase {
    // ---------------------------------------------------------------- versions (lines 32, 37, 38, 47)

    func testValidVersion() {
        for s in ["0", "9", "123456", "1.2", "1.2.3.4", "999999.999999.999999.999999"] { XCTAssertTrue(K3.validVersion(s), s) }
        for s in ["", "/", ":", "1234567", "1.2.3.4.5", "1..2", ".1", "1.", "1.a", "a", "1.2.3.1234567", "1/", "1:"] { XCTAssertFalse(K3.validVersion(s), s) }
    }

    func testVersionOk() {
        for s in ["0", "9", "123456", "1.2", "1.2.3.4"] { XCTAssertTrue(K3.versionOk(s), s) }
        for s in ["", "/", ":", "1234567", "1.2.3.4.5", "1..2", ".1", "1.", "1/", "1:", "0/", "9:"] { XCTAssertFalse(K3.versionOk(s), s) }
    }

    func testCompareVersion() {
        XCTAssertEqual(K3.compareVersion("1.2", "1.2"), 0, "line 47 equal versions")
        XCTAssertEqual(K3.compareVersion("1", "1.0"), 0)
        XCTAssertEqual(K3.compareVersion("1.0", "1.1"), -1)
        XCTAssertEqual(K3.compareVersion("1.2", "1.1"), 1)
        XCTAssertEqual(K3.compareVersion("2", "1.9"), 1)
        XCTAssertEqual(K3.compareVersion("1.9", "2"), -1)
    }

    // ---------------------------------------------------------------- bundle shape (lines 54-60)

    private func bundle(_ over: JObject = [:]) -> JSONValue {
        var b: JObject = ["v": .int(1), "kind": .string("pca-policy-bundle"), "revision": .int(1), "issued_at": .int(1),
                          "grants": .array([]), "template_digests": .array([]), "min_verifier_version": .string("1")]
        for (k, v) in over { b[k] = v }
        return .object(b)
    }
    private func text(_ n: Int) -> JSONValue { .string(String(repeating: "a", count: n)) }

    func testBundleShapeBounds() {
        XCTAssertNil(K3.bundleShapeError(bundle()), "control")
        XCTAssertEqual(K3.bundleShapeError(bundle(["revision": .int(0)])), "bad revision or time", "line 54 revision 0")
        XCTAssertNil(K3.bundleShapeError(bundle(["revision": .int(2), "prev": text(128)])), "line 55 a 128-character prev")
        XCTAssertEqual(K3.bundleShapeError(bundle(["revision": .int(2), "prev": text(129)])), "prev must be absent at revision 1 and present after", "line 55")
        XCTAssertEqual(K3.bundleShapeError(bundle(["revision": .int(2)])), "prev must be absent at revision 1 and present after")
        XCTAssertEqual(K3.bundleShapeError(bundle(["prev": text(5)])), "prev must be absent at revision 1 and present after")
        let many = JSONValue.array([JSONValue](repeating: .string("g"), count: 4096))
        XCTAssertNil(K3.bundleShapeError(bundle(["grants": many])), "line 58 4096 grants")
        XCTAssertEqual(K3.bundleShapeError(bundle(["grants": .array([JSONValue](repeating: .string("g"), count: 4097))])), "bad grants", "line 58 4097 grants")
        XCTAssertNil(K3.bundleShapeError(bundle(["template_digests": many])))
        XCTAssertNil(K3.bundleShapeError(bundle(["grants": .array([text(128)])])), "line 58 a 128-character grant")
        XCTAssertEqual(K3.bundleShapeError(bundle(["grants": .array([text(129)])])), "bad grants", "line 58 a 129-character grant")
        XCTAssertEqual(K3.bundleShapeError(bundle(["template_digests": .array([text(129)])])), "bad template_digests")
        for k in ["schema_digest", "constitution_digest", "flow_rules_digest"] {
            XCTAssertNil(K3.bundleShapeError(bundle([JKey(k): text(128)])), "line 60 \(k) of 128 characters")
            XCTAssertEqual(K3.bundleShapeError(bundle([JKey(k): text(129)])), "bad \(k)", "line 60 \(k) of 129 characters")
        }
    }

    func testBundleRefusalCarriesRevisionZero() {
        let v = K3.verifyBundle(nil, K3.BundleOptions(signers: [], threshold: 1, verifierVersion: "1"))
        XCTAssertFalse(v.ok)
        XCTAssertEqual(v.revision, 0, "line 94")
        XCTAssertEqual(v.digest, "")
        XCTAssertEqual(v.signers, [])
    }

    // ---------------------------------------------------------------- list cursor (line 236)

    func testCursorInnerMustBeAString() {
        let raw = #"{"v":1,"bind":"b","skip":0,"inner":5,"signer":"s"}"#
        let tok = Base64URLStrict.encode(Array(raw.utf8)) + ".AAAA"
        let v = K3.verifyListCursor(.string(tok), signer: "s")
        XCTAssertFalse(v.ok)
        XCTAssertEqual(v.reason, "malformed", "line 236 a non-string inner is malformed before the signature is read")
        let good = #"{"v":1,"bind":"b","skip":0,"inner":"x","signer":"s"}"#
        XCTAssertEqual(K3.verifyListCursor(.string(Base64URLStrict.encode(Array(good.utf8)) + ".AAAA"), signer: "s").reason, "signature")
    }

    // ---------------------------------------------------------------- need approval (lines 428-439)

    private static let key = V2F.key("s2g6-k3-principal")

    private func num(_ d: Double) -> JSONValue { d == d.rounded() ? .int(Int64(d)) : .double(d) }

    private func approve(needLimit: Double, given: Double, adjustable: Bool, gaLimit: Double = 0.5) -> (K3.GrantVerdict, String?) {
        var want: JObject = ["verb": .string("write"), "resource": .string("r2"), "limits": .object(["k": num(needLimit)])]
        if adjustable { want["adjustable"] = .bool(true) }
        let need: JSONValue = .object(["status": .string("pending"), "id": .string("n1"), "grant_id": .string("g1"), "needs": .array([.object(want)])])
        let authority: JSONValue = .object(["verbs": .array([.string("read")]), "resources": .array([.string("r1")]), "limits": .object(["k": num(gaLimit)])])
        let grant: JSONValue = .object(["principal": .string(V2F.pub(Self.key)), "rev": .int(3), "authority": authority])
        let approved: JSONValue = .array([.object(["verb": .string("write"), "resource": .string("r2"), "limits": .object(["k": num(given)])])])
        let msg: JSONValue = .object(["need": .string("n1"), "grant": .string("g1"), "rev": .int(3), "approved": approved])
        let sig = JSONValue.string(V2F.sign(Self.key, IV.message(K3.NEED_APPROVE_DOMAIN, msg)!))
        let verdict = K3.verifyNeedApproval(need, grant: grant, approved: approved, sig: sig, stepUpOk: true)
        let merged: JSONValue = .object(["verbs": .array([.string("read"), .string("write")]), "resources": .array([.string("r1"), .string("r2")]),
                                         "limits": .object(["k": .double(max(gaLimit, given))])])
        return (verdict, K3.authorityDigest(merged))
    }

    func testNeedApprovalMergesVerbsResourcesAndLimits() {
        // line 428: a limit equal to the need is not "lowered", so a non-adjustable need accepts it
        let eq = approve(needLimit: 1, given: 1, adjustable: false, gaLimit: 0.5)
        XCTAssertTrue(eq.0.ok, eq.0.code)
        XCTAssertTrue(eq.0.widens, "line 439")
        XCTAssertEqual(eq.0.digest, eq.1)
        // lowered below the need is refused when the need is not adjustable
        XCTAssertEqual(approve(needLimit: 1, given: 0, adjustable: false).0.code, "need_not_adjustable")
        // lines 430 and 432: a lowered limit of 0 (adjustable), merged by union of verbs / resources and max of limits
        let low = approve(needLimit: 1, given: 0, adjustable: true, gaLimit: 0.5)
        XCTAssertTrue(low.0.ok, low.0.code)
        XCTAssertTrue(low.0.widens)
        XCTAssertEqual(low.0.digest, low.1, "the merged authority holds both verbs, both resources and max(0.5, 0)")
        XCTAssertEqual(approve(needLimit: 1, given: 2, adjustable: true).0.code, "need_not_lowered_only")
    }
}
