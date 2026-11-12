import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the AttestGcp.swift survivor of group 2: a trust root given as a bare public key (PEM SubjectPublicKeyInfo), not a certificate.
final class S2G2AttestGcpKillTests: XCTestCase {
    func testABareEd25519PublicKeyPEMIsATrustRoot() {
        let raw = [UInt8](repeating: 7, count: 32)
        let der: [UInt8] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00] + raw
        let pem = "-----BEGIN PUBLIC KEY-----\n" + Data(der).base64EncodedString() + "\n-----END PUBLIC KEY-----\n"
        let k = GcpVerifier.rootKeyFromPEM(pem)
        XCTAssertNotNil(k, "line 98: the bare-key fallback")
        XCTAssertEqual(k?.typ, "ed25519")
        XCTAssertEqual(k?.ed ?? [], raw)
        XCTAssertEqual(k?.spki ?? [], der)
    }

    func testNeitherACertificateNorAKeyIsNil() {
        XCTAssertNil(GcpVerifier.rootKeyFromPEM("not a pem"))
        XCTAssertNil(GcpVerifier.rootKeyFromPEM("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"))
    }
}
