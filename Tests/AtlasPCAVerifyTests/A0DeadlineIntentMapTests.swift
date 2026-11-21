import XCTest
import Foundation
@testable import AtlasPCAVerify

/// IntentMap.swift split / treeRoot: loops and recursions a mutant can make endless, under a deadline; wrong-value assertions first.
final class A0DeadlineIntentMapTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func h(_ b: UInt8) -> [UInt8] { [UInt8](repeating: b, count: 32) }

    func testA1SplitIsTheLargestPowerOfTwoBelowN() {
        let got: [Int]? = S2Deadline.within(10, "IntentMap.split") { [1, 2, 3, 4, 5, 8, 9].map { IntentMap.split($0) } }
        XCTAssertEqual(got, [1, 1, 2, 2, 4, 4, 8], "lines 46-47")
    }

    func testA2TreeRootOfTwoAndThree() {
        let a = h(1), b = h(2), c = h(3)
        let two: [UInt8]? = S2Deadline.within(10, "treeRoot of 2") { IntentMap.treeRoot([a, b][...]) }
        XCTAssertEqual(two, IntentMap.nodeHash(a, b), "line 51: two nodes are hashed together")
        let three: [UInt8]? = S2Deadline.within(10, "treeRoot of 3") { IntentMap.treeRoot([a, b, c][...]) }
        XCTAssertEqual(three, IntentMap.nodeHash(IntentMap.nodeHash(a, b), c), "line 51: three nodes split 2 + 1")
    }

    func testA3TreeRootOfOneIsThatNode() {
        let a = h(1)
        let one: [UInt8]? = S2Deadline.within(10, "treeRoot of 1") { IntentMap.treeRoot([a][...]) }
        XCTAssertEqual(one, a, "line 51")
    }
}
