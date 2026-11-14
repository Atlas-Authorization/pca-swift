import XCTest
import Foundation
@testable import AtlasPCAVerify

/// NVIDIA CRL coverage (nvidia-crl-coverage-spec.md): by default every non-root chain certificate that names a CRL distribution point needs a
/// verified CRL from its issuer; one fresh CRL from the root no longer satisfies the whole chain. Chain: leaf (0) <- mid (1) <- root (2).
final class A0DeadlineAttestNvidiaRimCrlCoverageTests: XCTestCase {
    private typealias F = StrictChainForge
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func chain(cdp: [Int]) throws -> [AttCert] {
        var c = try F.chain().ders.map { try Cert.parseDER($0) }
        for i in cdp { c[i].raw += RIM.CDP_OID_DER } // the reference scans the certificate bytes for the OID
        return c
    }

    private func walk(_ c: [AttCert], _ crls: [[UInt8]], _ req: RIM.CrlRequirement) -> String {
        S2Deadline.within(20, "checkChainRevocation") { RIM.checkChainRevocation(c, crls, F.NOW, [], req) } ?? "timeout"
    }

    private func rootCrl() -> [UInt8] { AttestNvidiaRimK05Tests.crl(signer: F.rootKey) }
    private func midCrl(revoked: [UInt8] = []) -> [UInt8] { AttestNvidiaRimK05Tests.crl(signer: F.midKey, revoked: revoked) }

    /// 1: the kill. Only the root's CRL: the leaf (issuer = mid) is never checked.
    func testARootCrlAloneLeavesTheLeafUncovered() throws {
        let c = try chain(cdp: [0, 1])
        XCTAssertEqual(walk(c, [rootCrl()], .cdp), "no verified CRL from the issuer of chain certificate '\(Nvidia.subjectLine(c[0]))'")
        XCTAssertEqual(walk(c, [rootCrl()], .notRequired), "", "today's behaviour without a coverage demand")
    }

    /// 2: the mid's CRL covers the leaf and the root's CRL covers the mid.
    func testEveryIssuerCoveredPasses() throws {
        let c = try chain(cdp: [0, 1])
        XCTAssertEqual(walk(c, [midCrl(), rootCrl()], .cdp), "")
        XCTAssertEqual(walk(c, [rootCrl(), midCrl()], .all), "")
        // a leaf with no CDP of its own needs no CRL under cdp: only the mid (covered by the root's CRL) is demanded
        let c1 = try chain(cdp: [1])
        XCTAssertEqual(walk(c1, [rootCrl()], .cdp), "")
    }

    /// 3: a revoked leaf on the mid's CRL still fails as revoked.
    func testARevokedLeafStillFails() throws {
        let c = try chain(cdp: [0, 1])
        XCTAssertEqual(walk(c, [midCrl(revoked: [3]), rootCrl()], .cdp), "chain certificate '\(Nvidia.subjectLine(c[0]))' is revoked")
    }

    /// 4: 'all' demands a CRL for a certificate that names no CDP; 'cdp' does not.
    func testAllDemandsWhatCdpDoesNot() throws {
        let c = try chain(cdp: [0])           // only the leaf names a CDP
        XCTAssertEqual(walk(c, [midCrl()], .cdp), "")
        XCTAssertEqual(walk(c, [midCrl()], .all), "no verified CRL from the issuer of chain certificate '\(Nvidia.subjectLine(c[1]))'")
        XCTAssertEqual(walk(c, [midCrl(), rootCrl()], .all), "")
    }

    /// 5: explicit indices; an out-of-range or root index is refused with the spec's message.
    func testIndexListAndItsBounds() throws {
        let c = try chain(cdp: [])
        XCTAssertEqual(walk(c, [rootCrl()], .indices([5])), "requireCrlFor index 5 is not a non-root chain certificate")
        XCTAssertEqual(walk(c, [rootCrl()], .indices([2])), "requireCrlFor index 2 is not a non-root chain certificate", "the root is not a non-root certificate")
        XCTAssertEqual(walk(c, [rootCrl()], .indices([-1])), "requireCrlFor index -1 is not a non-root chain certificate")
        XCTAssertEqual(walk(c, [rootCrl()], .indices([0])), "no verified CRL from the issuer of chain certificate '\(Nvidia.subjectLine(c[0]))'")
        XCTAssertEqual(walk(c, [rootCrl()], .indices([1])), "")
        XCTAssertEqual(walk(c, [rootCrl()], .indices([])), "")
    }

    /// 6: with CRLs not required (OCSP-only, requireCrls: false) the hook demands no coverage; in crl / both modes it does.
    func testTheDemandAppliesOnlyWhereCrlsAreRequired() throws {
        let pins: JSONValue = .array([.string("ab")])
        func hook(_ extra: [String: JSONValue]) throws -> NvidiaHook {
            var o: JObject = ["rimRootSpkiSha256": pins]
            for (k, v) in extra { o[JKey(k)] = v }
            return try NvidiaHook(o)
        }
        XCTAssertEqual(try hook([:]).crlRequirement(), .cdp, "default: cdp, mode crl")
        XCTAssertEqual(try hook(["revocation": .string("both")]).crlRequirement(), .cdp)
        XCTAssertEqual(try hook(["revocation": .string("ocsp")]).crlRequirement(), .notRequired)
        XCTAssertEqual(try hook(["requireCrls": .bool(false)]).crlRequirement(), .notRequired)
        XCTAssertEqual(try hook(["requireCrlFor": .string("all")]).crlRequirement(), .all)
        XCTAssertEqual(try hook(["requireCrlFor": .array([.int(0), .int(1)])]).crlRequirement(), .indices([0, 1]))
        for bad: JSONValue in [.string("some"), .int(1), .bool(true), .array([.string("0")]), .array([.int(-1)]), .array([.double(0.5)])] {
            XCTAssertThrowsError(try hook(["requireCrlFor": bad]), "\(bad)")
        }
    }
}
