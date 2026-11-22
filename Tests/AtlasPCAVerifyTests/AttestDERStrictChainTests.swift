import XCTest
@testable import AtlasPCAVerify

/// `DER.strictChainError` against the reference's strictChainError (packages/pca/src/x509-strict.ts:266): same order, same reason text.
final class AttestDERStrictChainTests: XCTestCase {
    typealias F = StrictChainForge

    func testControlPasses() {
        XCTAssertEqual(DER.strictChainError(F.chain().ders), "")
    }

    func testEveryViolationHasTheExactReason() {
        for row in F.bad { XCTAssertEqual(DER.strictChainError(F.chain(row.shape).ders), row.reason, row.name) }
    }

    func testRespectedPathLenAndCriticalEkuPass() {
        XCTAssertEqual(DER.strictChainError(F.chain(F.Shape(root: [F.bc(true, pathLen: 1), F.KU_CERT_SIGN])).ders), "")
        XCTAssertEqual(DER.strictChainError(F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_EKU])).ders), "")
        XCTAssertEqual(DER.strictChainError(F.chain(F.Shape(mid: F.CA + [F.CRITICAL_EKU])).ders), "")
    }

    func testRolesAreJudgedBeforeCriticalExtensions() {
        let both = F.chain(F.Shape(leaf: [F.bc(true), F.CRITICAL_UNKNOWN]))
        XCTAssertEqual(DER.strictChainError(both.ders), F.LEAF_CA_TRUE)
    }

    func testTheFirstCertificateWithAnUnknownCriticalExtensionIsNamed() {
        let both = F.chain(F.Shape(mid: F.CA + [F.CRITICAL_UNKNOWN], leaf: F.LEAF + [F.CRITICAL_UNKNOWN]))
        XCTAssertEqual(DER.strictChainError(both.ders), "certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    }

    func testANonCriticalUnknownExtensionPasses() {
        let c = F.chain(F.Shape(leaf: F.LEAF + [F.ext(F.OID_UNKNOWN, critical: false, F.seq([]))]))
        XCTAssertEqual(DER.strictChainError(c.ders), "")
    }

    func testTheEkuAllowanceDoesNotWidenTheAmdIntelSet() throws {
        let leaf = F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_EKU])).ders[0]
        XCTAssertEqual(try DER.unrecognisedCriticalExtension(leaf), "2.5.29.37")
        XCTAssertEqual(DER.RECOGNISED_CRITICAL, ["2.5.29.19", "2.5.29.15"])
        XCTAssertEqual(DER.CHAIN_CRITICAL_OK, ["2.5.29.19", "2.5.29.15", "2.5.29.37"])
    }

    func testABareCertificateHasNoRolesButItsExtensionsAreJudged() {
        XCTAssertEqual(DER.strictChainError([]), "")
        XCTAssertEqual(DER.strictChainError([F.selfSigned(F.rootKey, "Bare")]), "")
        XCTAssertEqual(DER.strictChainError([F.selfSigned(F.rootKey, "Bare", exts: F.CA + [F.CRITICAL_UNKNOWN])]),
                       "certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    }

    func testGarbageIsAFailureNeverAPass() {
        XCTAssertEqual(DER.strictChainError([[1, 2, 3]]), "certificate extension parse failed: DER: element overruns its parent")
    }

    /// The role reader takes an explicit FALSE critical flag; the strict table does not, so this reaches the profile's own parse-failure branch.
    func testAStrictTableFailureAfterTheRolesPass() {
        let flag: [UInt8] = [0x01, 0x01, 0x00]
        let nonDer: F.Ext = F.seq(F.oid(F.OID_UNKNOWN) + flag + DERB.tlv(0x04, F.seq([])))
        let c = F.chain(F.Shape(leaf: F.LEAF + [nonDer]))
        XCTAssertEqual(DER.checkChainRoles(c.ders), "")
        XCTAssertEqual(DER.strictChainError(c.ders), "certificate extension parse failed: extension 1.2.3.4 has a non-DER critical flag")
    }
}
