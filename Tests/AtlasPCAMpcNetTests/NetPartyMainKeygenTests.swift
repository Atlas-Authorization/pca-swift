import XCTest
import Foundation
@testable import AtlasPCAMpcNet

/// `pca-mpc-party keygen <dir> [cn]` writes <dir>/key.pem and <dir>/cert.pem (the mixed-mesh harness relies on the file names; cn defaults to mpc-node).
final class NetPartyMainKeygenTests: XCTestCase {
    func testKeygenWritesKeyAndCertWithAndWithoutCn() throws {
        for args in [["keygen", "", "node-a"], ["keygen", ""]] {
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("party-keygen-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: dir) }
            var a = args
            a[1] = dir.path
            XCTAssertEqual(NetPartyMain.run(a, env: [:]), 0)
            let key = try String(contentsOf: dir.appendingPathComponent("key.pem"), encoding: .utf8)
            let cert = try String(contentsOf: dir.appendingPathComponent("cert.pem"), encoding: .utf8)
            XCTAssertTrue(key.contains("PRIVATE KEY"))
            XCTAssertTrue(cert.contains("BEGIN CERTIFICATE"))
        }
    }
}
