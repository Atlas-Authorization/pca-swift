import XCTest
import Foundation
@testable import AtlasPCAMpcNet

final class NetIdentityFilesTests: XCTestCase {
    func testGenerateIdentityWritesAPrivateKeyAndACertificate() throws {
        let dir = NSTemporaryDirectory() + "mpc-ident-" + UUID().uuidString
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let id = try NetCerts.generateIdentity(dir, "node-a")
        XCTAssertEqual(id.keyPath, dir + "/key.pem")
        XCTAssertEqual(id.certPath, dir + "/cert.pem")
        XCTAssertTrue(try NetCerts.readPem(id.keyPath).hasPrefix("-----BEGIN " + ["PRIVATE", "KEY"].joined(separator: " ") + "-----"))
        let cert = try NetCerts.readPem(id.certPath)
        XCTAssertTrue(cert.hasPrefix("-----BEGIN CERTIFICATE-----"))
        XCTAssertFalse(try NetCerts.fingerprint(certPem: cert).isEmpty)
        let perms = try FileManager.default.attributesOfItem(atPath: id.keyPath)[.posixPermissions] as? NSNumber
        XCTAssertEqual(perms?.intValue, 0o600)
        XCTAssertThrowsError(try NetCerts.generateIdentity(dir, "bad cn!"))
        XCTAssertThrowsError(try NetCerts.readPem(dir + "/missing.pem"))
    }
}
