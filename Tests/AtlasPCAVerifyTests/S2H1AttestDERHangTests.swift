import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for AttestDER.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1AttestDERHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testDerWalkersAdvance() {
        XCTAssertEqual(dl("readCertRoleInfo") { (try? DER.readCertRoleInfo([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01])) == nil ? "threw" : "ok" }, "ok", "AttestDER.swift:94")
        XCTAssertEqual(dl("parseTbsExtensions") { (try? DER.parseTbsExtensions([0x30, 0x03, 0x02, 0x01, 0x01])) == nil ? "threw" : "ok" }, "ok", "AttestDER.swift:239")
        XCTAssertEqual(dl("decimalOfBase128 1") { "\(DER.decimalOfBase128([1]))" }, "[1]", "AttestDER.swift:173,175")
        XCTAssertEqual(dl("decimalOfBase128 128") { "\(DER.decimalOfBase128([1, 0]))" }, "[1, 2, 8]", "AttestDER.swift:173,175 carry")
    }
}
