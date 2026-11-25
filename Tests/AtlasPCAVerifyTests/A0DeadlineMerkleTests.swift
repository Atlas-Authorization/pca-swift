import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Merkle.swift split / build / pathShape: loops and recursions a mutant can make endless. Every call that reaches a mutated line runs
/// under a deadline; the wrong-value assertions come first so a mutant that would crash is decided by a failed assertion.
final class A0DeadlineMerkleTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testA1SplitIsTheLargestPowerOfTwoBelowN() {
        let got: [UInt64]? = S2Deadline.within(10, "Merkle.split") { [1, 2, 3, 4, 5, 8, 9].map { Merkle.split($0) } }
        XCTAssertEqual(got, [1, 1, 2, 2, 4, 4, 8], "lines 23-24: largest power of two strictly below n")
    }

    func testA2BuildTwoAndThreeLeaves() {
        let two: String? = S2Deadline.within(10, "merkleRoot of 2") { Merkle.merkleRoot([.string("a"), .string("b")]) ?? "" }
        XCTAssertEqual(two, "_GktHH8fbqZ1mqq_MFD4ratNJbZf2RmPBYMgh_4cNdI", "line 29: two leaves are hashed together")
        let three: String? = S2Deadline.within(10, "merkleRoot of 3") { Merkle.merkleRoot([.string("a"), .string("b"), .string("c")]) ?? "" }
        XCTAssertEqual(three, "Fn02TABbmCVqHK4ySaABQ0YPCE36aBk5LnDwvZKCG9U", "line 29: three leaves split 2 + 1")
    }

    func testA3BuildOneLeafIsItsLeafHash() {
        let one: String? = S2Deadline.within(10, "merkleRoot of 1") { Merkle.merkleRoot([.string("a")]) ?? "" }
        XCTAssertEqual(one, "5ENkfwW3F6bNjOYJW4O2HyJy8aGMAiC-ZLf9WE9IUb4", "line 29: one leaf is the root")
    }

    func testA4PathShapeTerminates() {
        let one: [UInt8]? = S2Deadline.within(2, "pathShape(0, 1)") { Merkle.pathShape(0, 1) }
        XCTAssertEqual(one, [], "line 44: a one-leaf tree has an empty path")
        let two: [UInt8]? = S2Deadline.within(2, "pathShape(1, 2)") { Merkle.pathShape(1, 2) }
        XCTAssertEqual(two, [UInt8(ascii: "L")], "line 44: two leaves")
        let five: [UInt8]? = S2Deadline.within(2, "pathShape(4, 5)") { Merkle.pathShape(4, 5) }
        XCTAssertEqual(five, [UInt8(ascii: "L")], "line 44: leaf 4 of 5 is the lone right subtree")
    }
}
