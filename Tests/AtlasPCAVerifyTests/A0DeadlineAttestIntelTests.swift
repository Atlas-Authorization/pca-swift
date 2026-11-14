import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Runs FIRST for AttestIntel.swift mutants (the name sorts before every other class containing AttestIntel).
final class A0DeadlineAttestIntelTests: XCTestCase {
    func testIndexOfAdvancesPastNonMatchingPositions() {
        // AttestIntel.swift line 88: i += 1 (a mutant never leaves position 0 when the needle is not there)
        let got: [Int]? = S2Deadline.within(10, "DcapVerifier.indexOf") { () -> [Int] in
            let hay: [UInt8] = [0, 0, 1, 2, 3]
            return [DcapVerifier.indexOf(hay, [1, 2]), DcapVerifier.indexOf(hay, [3]), DcapVerifier.indexOf(hay, [9]), DcapVerifier.indexOf(hay, [2, 3, 4])]
        }
        XCTAssertEqual(got, [2, 4, -1, -1])
    }
}
