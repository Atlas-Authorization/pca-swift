import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for AttestCert.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1AttestCertHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(2, what) { body() } ?? "timeout"
    }

    func testCertWalkersAdvance() {
        XCTAssertEqual(dl("kids") {
            let b: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x05]
            return "\(String(describing: (try? Cert.kids(b, CertElem(tag: 0x30, hdr: 0, start: 2, end: 5)))?.count))"
        }, "Optional(1)", "AttestCert.swift:79")
        XCTAssertEqual(dl("pemBlocks") { "\(Cert.pemBlocks(Cert.BEGIN + "\nAAAA\n" + Cert.END + "\n" + Cert.BEGIN + "\nBBBB\n" + Cert.END).count)" }, "2", "AttestCert.swift:224")
    }
}
