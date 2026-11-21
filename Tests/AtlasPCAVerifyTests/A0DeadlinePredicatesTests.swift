import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Predicates.swift 98 (parseGlob loop step: a mutant appends a literal forever, so a small deadline fires before the memory cap),
/// 110, 111, 119, 120, 125 (globMatch loops): the unmutated code finishes each call in microseconds.
final class A0DeadlinePredicatesTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func u(_ s: String) -> [UInt16] { Array(s.utf16) }

    func testGlobsEndWhateverTheyHold() {
        let parsed: [Predicates.GlobTok]?? = S2Deadline.within(2, "Predicates.parseGlob") { Predicates.parseGlob(Array("ab".utf16)) }
        XCTAssertEqual(parsed ?? nil, [.lit(0x61), .lit(0x62)], "line 98")
        let g1 = u("a"), g2 = u("*a"), g3 = u("a*"), g4 = u("a*b"), g5 = u("\\*a")
        let s1 = u("a"), s2 = u("ba"), s3 = u("xa"), s4 = u("axxb"), s5 = u("*a")
        let got: [Bool?]? = S2Deadline.within(10, "Predicates.globMatch") {
            [Predicates.globMatch(g1, s1),
             Predicates.globMatch(g1, s2),
             Predicates.globMatch(g2, s2),
             Predicates.globMatch(g2, s3),
             Predicates.globMatch(g3, s1),
             Predicates.globMatch(g4, s4),
             Predicates.globMatch(g5, s5)]
        }
        XCTAssertEqual(got, [true, false, true, true, true, true, true])
    }

}
