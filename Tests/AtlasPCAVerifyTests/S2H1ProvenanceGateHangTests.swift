import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for ProvenanceGate.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1ProvenanceGateHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testInclusionProofOfTheLastLeafOfAThreeLeafTree() {
        let a = Canonical.sha256([1]), b = Canonical.sha256([2]), c = Canonical.sha256([3])
        let n01 = Canonical.sha256([1] + a + b)
        let root = Canonical.sha256([1] + n01 + c)
        let got = dl("inclusion") { "\(PCA.verifyRfc9162Inclusion(leafHash: c, index: 2, size: 3, proof: [n01], root: root))" }
        XCTAssertEqual(got, "true", "ProvenanceGate.swift:77,78")
    }
}
