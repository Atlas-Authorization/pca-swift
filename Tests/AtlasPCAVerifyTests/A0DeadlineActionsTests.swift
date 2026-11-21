import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Actions.swift closure (516, 520) and packProof (727): loops a mutant can make endless. Every call runs under a deadline.
final class A0DeadlineActionsTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func trait(_ id: String, _ implies: [String]) -> JSONValue {
        .object(["id": .string(id), "implies": .array(implies.map { JSONValue.string($0) }), "floor": Profile.bottom.json, "card_phrase": .string("p")])
    }

    /// Eight levels of eight traits, each implying all eight below: 64 visits with the seen set, about 8^8 without it.
    func testA1ClosureVisitsEachTraitOnce() throws {
        func id(_ l: Int, _ w: Int) -> String { "lv\(l).w\(w)" }
        var defs: [JSONValue] = []
        for l in 0..<8 {
            for w in 0..<8 { defs.append(trait(id(l, w), l == 0 ? [] : (0..<8).map { id(l - 1, $0) })) }
        }
        let reg = try Actions.buildRegistry(defs)
        let tops = (0..<8).map { id(7, $0) }
        var expected: [String] = []
        for l in 0..<8 { for w in 0..<8 { expected.append(id(l, w)) } }
        expected.sort()
        let got: [String]? = S2Deadline.within(3, "closure") { (try? Actions.closure(reg, tops)) ?? [] }
        XCTAssertEqual(got, expected, "lines 516, 520")
    }

    /// Two digests, proof for the smaller (index 0 < k = 1): the left half is cut away, so the loop ends after one step.
    func testA2PackProofShrinksTheSegment() {
        let lo = String(repeating: "A", count: 43), hi = String(repeating: "B", count: 43)
        let got: JSONValue? = S2Deadline.within(2, "packProof") { (try? Actions.packProof([hi, lo], lo)) ?? .null }
        let leafHi = Merkle.leafHash(.object(["d": .string(Actions.PACK_DIGEST_DOMAIN), "def": .string(hi)]))
        let want: JSONValue = .object(["index": .int(0), "size": .int(2),
                                       "path": .array([.object(["side": .string("R"), "hash": .string(Base64URLStrict.encode(leafHi))])])])
        XCTAssertEqual(got, want, "line 727")
    }
}
