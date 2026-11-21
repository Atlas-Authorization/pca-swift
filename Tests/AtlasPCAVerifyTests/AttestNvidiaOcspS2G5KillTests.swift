import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the AttestNvidiaOcsp.swift survivors of group 5: the exact reason of each delegated-responder refusal and of a response that matches
/// no chain certificate. Pinned to packages/pca/src/attest-nvidia-ocsp.ts (:266-308 responder, checkChain).
final class S2G5AttestNvidiaOcspKillTests: XCTestCase {
    typealias F = StrictChainForge
    typealias S = AttestOcspStrictTests
    typealias K = AttestNvidiaOcspK05Tests

    // computed, not stored: XCTest builds every test instance while listing the tests, and a mutant that breaks Cert.parse must not crash that listing
    private var root: AttCert { AttestOcspStrictTests.root() }
    private var leaf: AttCert { AttestOcspStrictTests.leaf }

    private func ask(_ der: [UInt8]) -> OcspResult { OCSP.verifyResponse(der, leaf, root, [leaf, root], F.NOW) }
    private func id() -> [UInt8] { K.certID(root) }

    func testEmbeddedCertificatesThatDoNotNameTheResponder() {
        let tbs = K.tbs([K.single(id())], rid: DERB.tlv(0xa1, F.name("other")))
        let der = K.signed(tbs, signer: F.midKey, certs: DERB.tlv(0xa0, F.seq(S.responder())))
        XCTAssertEqual(ask(der).reason, "embedded certificates do not match the responderID", "line 226")
    }

    func testADelegatedResponderWithoutTheOcspSigningEku() {
        let tbs = K.tbs([K.single(id())], rid: DERB.tlv(0xa1, F.name("resp")))
        let der = K.signed(tbs, signer: F.midKey, certs: DERB.tlv(0xa0, F.seq(S.responder(exts: [F.bc(false)]))))
        XCTAssertEqual(ask(der).reason, "delegated responder certificate lacks the id-kp-OCSPSigning EKU", "line 230")
    }

    func testAResponseSignedByAnotherKeyThanTheDelegatedResponder() {
        let tbs = K.tbs([K.single(id())], rid: DERB.tlv(0xa1, F.name("resp")))
        let der = K.signed(tbs, signer: F.strangerKey, certs: DERB.tlv(0xa0, F.seq(S.responder())))
        XCTAssertEqual(ask(der).reason, "OCSP response signature does not verify under the delegated responder key", "line 247")
    }

    func testAResponseForNoChainCertificateKeepsTheLastMatchReason() {
        let der = K.signed(K.tbs([K.single(K.certID(root, serial: 6))]))
        XCTAssertEqual(OCSP.checkChain([leaf, root], [der], F.NOW), "OCSP response #0 rejected: \(K.NO_MATCH)", "line 302")
    }

    func testGeneralizedTimeBoundsMatchTheGuards() {
        // 14 digits and no Z: too short either way, never a trap (lines 74, 81)
        XCTAssertNil(OCSP.timeMs(Array("20270115070000".utf8), false))
        XCTAssertNil(OCSP.timeMs(Array("2027011507000".utf8), false))
        XCTAssertNotNil(OCSP.timeMs(Array("20270115070000Z".utf8), false))
        XCTAssertNil(OCSP.timeMs(Array("20270115070000.Z".utf8), false))
    }
}
