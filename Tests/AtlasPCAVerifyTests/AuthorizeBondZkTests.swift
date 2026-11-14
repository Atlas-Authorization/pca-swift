import XCTest
@testable import AtlasPCAVerify

/// A carried `bond_ref` denies unless allowed (server/verify.ts:531-533); a carried `zk_compliance` fails at the core (pcactn.ts:838-841), so also without `authorize`.
final class AuthorizeBondZkTests: XCTestCase {
    private static let ZK = "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof"
    private static let BOND = "bond: unsupported: the PCActn carries a feature this verifier does not implement"

    func testBondDeniesUnlessAllowed() {
        XCTAssertTrue(AZ.run(AZ.signed()).allow)
        XCTAssertNil(AZ.run(AZ.signed()).checks["bond"])
        let s = AZ.signed(extra: ["bond_ref": .string("b")])
        let r = AZ.run(s)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "deny")
        XCTAssertEqual(r.checks["bond"], .unsupported)
        XCTAssertEqual(r.reason, Self.BOND + " (list it in allowUnsupported to accept it)")
        let ok = AZ.run(s) { $0.allowUnsupported = ["bond"] }
        XCTAssertTrue(ok.allow, ok.reason ?? "")
        XCTAssertEqual(ok.checks["bond"], .unsupported) // reported, never a pass
        XCTAssertFalse(AZ.run(s) { $0.allowUnsupported = ["other"] }.allow)
    }

    func testZkFailsAtTheCore() {
        let plain = AZ.signed()
        XCTAssertNil(PCA.verify(pcactn: plain.pcactn, grant: plain.grant, now: AZ.NOW, audience: AZ.AUD, insecureSkipPlanRootCheck: true).checks["zk_compliance"])
        let s = AZ.signed(extra: ["zk_compliance": .object(["x": .int(1)])])
        let v = PCA.verify(pcactn: s.pcactn, grant: s.grant, now: AZ.NOW, audience: AZ.AUD, insecureSkipPlanRootCheck: true)
        XCTAssertFalse(v.allow)
        XCTAssertEqual(v.checks["zk_compliance"], false)
        XCTAssertEqual(v.reason, Self.ZK)
        let r = AZ.run(s)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["zk_compliance"], .fail)
        XCTAssertEqual(r.reasons.filter { $0.hasPrefix("zk_compliance:") }, [Self.ZK]) // reported once
    }
}

/// Signature-only guards have neither `authorize` nor its `bond` check: they refuse both too.
extension PcaGuardTests {
    func testSignatureOnlyRefusesBondAndZk() throws {
        let cases: [(JObject, String)] = [(["bond_ref": .string("b")], "bond: unsupported"), (["zk_compliance": .object(["x": .int(1)])], "zk_compliance")]
        for (extra, needle) in cases {
            let s = AZ.signed(extra: extra)
            let g = try Self.guardFor(s) { cfg, _ in cfg.signatureOnly = true; cfg.insecureSkipPlanRootCheck = true }
            let d = try XCTUnwrap(denial(g.handle(Self.request(s))))
            XCTAssertEqual(d.status, 403)
            XCTAssertTrue(String(decoding: d.body, as: UTF8.self).contains(needle), needle)
        }
    }
}
