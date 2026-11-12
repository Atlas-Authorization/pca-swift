import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// Round 2, sheet hang2: mutants that loop or recurse forever (or recurse to a crash after a wrong value). Each test uses an input the
/// original finishes in milliseconds and asserts the exact result under S2Deadline (a never-ending mutant fails the deadline), or
/// asserts a wrong-value-first distinction before a crash can happen.

/// RFC 6962 reference built here, independent of the code under test.
enum S2H2Tree {
    static func leaf(_ i: Int) -> [UInt8] { Canonical.sha256([UInt8(i)]) }
    static func split(_ n: Int) -> Int { var k = 1; while k * 2 < n { k *= 2 }; return k }
    static func mth(_ hs: [[UInt8]]) -> [UInt8] {
        if hs.count == 1 { return hs[0] }
        let k = split(hs.count)
        return Merkle.nodeHash(mth(Array(hs[0..<k])), mth(Array(hs[k...])))
    }
    static func subproof(_ m: Int, _ hs: [[UInt8]], _ b: Bool) -> [[UInt8]] {
        let n = hs.count
        if m == n { return b ? [] : [mth(hs)] }
        let k = split(n)
        if m <= k { return subproof(m, Array(hs[0..<k]), b) + [mth(Array(hs[k...]))] }
        return subproof(m - k, Array(hs[k...]), false) + [mth(Array(hs[0..<k]))]
    }
}

final class S2H2IntentMapHangTests: XCTestCase {
    typealias M = IntentMap
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// IntentMap.swift 46-47: split is the largest power of two strictly below n.
    func testSplitIsTheLargestPowerOfTwoBelowN() {
        let got: [Int]? = S2Deadline.within(3, "IntentMap.split") { (1...9).map { M.split($0) } }
        XCTAssertEqual(got, [1, 1, 2, 2, 4, 4, 4, 4, 8], "lines 46-47")
    }

    /// IntentMap.swift 51: a two-leaf tree is node(l0, l1) (a mutated count test returns the first leaf), a three-leaf tree is node(node(l0,l1), l2).
    func testTreeRootShapes() {
        let a = S2H2Tree.leaf(1), b = S2H2Tree.leaf(2), c = S2H2Tree.leaf(3)
        let two: [UInt8]? = S2Deadline.within(3, "treeRoot 2") { M.treeRoot(ArraySlice([a, b])) }
        XCTAssertEqual(two, M.nodeHash(a, b), "line 51: two leaves")
        let one: [UInt8]? = S2Deadline.within(3, "treeRoot 1") { M.treeRoot(ArraySlice([a])) }
        XCTAssertEqual(one, a, "line 51: one leaf is its own root")
        let three: [UInt8]? = S2Deadline.within(3, "treeRoot 3") { M.treeRoot(ArraySlice([a, b, c])) }
        XCTAssertEqual(three, M.nodeHash(M.nodeHash(a, b), c), "line 51: three leaves")
    }

    /// IntentMap.swift 66: leaf index 2 of 3 reaches the `fn % 2 == 0` fold; the original stops at fn == 1, a mutant never ends.
    func testRootFromPathEvenLastLeaf() {
        let a = S2H2Tree.leaf(1), b = S2H2Tree.leaf(2), c = S2H2Tree.leaf(3)
        let n01 = M.nodeHash(a, b)
        let r: [UInt8]?? = S2Deadline.within(3, "rootFromPath") { M.rootFromPath(2, 3, c, [n01]) }
        let got: [UInt8]? = r ?? nil
        XCTAssertEqual(got, M.nodeHash(n01, c), "line 66")
    }
}

final class S2H2Ed25519TorsionHangTests: XCTestCase {
    typealias T = Ed25519Torsion
    typealias Fe = Ed25519Torsion.Fe
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// Ed25519Torsion.swift 17: every limb setter writes its own limb.
    func testLimbSetters() {
        var f = Fe(0)
        f[0] = 11; f[1] = 22; f[2] = 33; f[3] = 44
        XCTAssertEqual(f, Fe(11, 22, 33, 44), "line 17")
        XCTAssertEqual([f[0], f[1], f[2], f[3]], [11, 22, 33, 44], "getter")
        var g = Fe(1, 2, 3, 4)
        g[2] = 99
        XCTAssertEqual(g, Fe(1, 2, 99, 4), "line 17: only limb 2")
    }

    /// Ed25519Torsion.swift 107: fpow walks all 256 exponent bits; x * x^-1 == 1.
    func testInverseTerminates() {
        let ok: Bool? = S2Deadline.within(10, "finv") { T.fmul(T.finv(Fe(2)), Fe(2)) == T.one }
        XCTAssertEqual(ok, true, "line 107")
    }

    /// Ed25519Torsion.swift 163-181: the loop of isPrimeOrder ends (174), and the cache lock is released on the miss path (165) and at the end (181).
    /// A fresh key (never in the cache) takes the miss path; the repeats take the hit path.
    func testPrimeOrderTerminatesAndReleasesTheLock() {
        let pk = [UInt8](Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let got: [Bool]? = S2Deadline.within(10, "isPrimeOrder") { [T.isPrimeOrder(pk), T.isPrimeOrder(pk), T.isPrimeOrder(pk)] }
        XCTAssertEqual(got, [true, true, true], "lines 165, 174, 181")
        let id: [Bool]? = S2Deadline.within(10, "isPrimeOrder identity") { [T.isPrimeOrder([1] + [UInt8](repeating: 0, count: 31)), T.isPrimeOrder(pk)] }
        XCTAssertEqual(id, [false, true], "the lock is free again")
    }
}

final class S2H2LedgerHangTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func verify(_ m: Int, _ n: Int) -> Bool? {
        let hs = (0..<n).map { S2H2Tree.leaf($0) }
        let old = Base64URLStrict.encode(S2H2Tree.mth(Array(hs[0..<m])))
        let new = Base64URLStrict.encode(S2H2Tree.mth(hs))
        let path = S2H2Tree.subproof(m, hs, true).map { JSONValue.string(Base64URLStrict.encode($0)) }
        let p: JObject = ["oldSize": .int(Int64(m)), "newSize": .int(Int64(n)), "path": .array(path)]
        return S2Deadline.within(3, "verifyConsistency \(m)->\(n)") { Ledger.verifyConsistency(.string(old), .string(new), .object(p)) }
    }

    /// Ledger.swift 78-79: old size 1 has fn == 0 (an odd test never loops), old size 2 has fn == 1 (one shift ends it).
    func testConsistencyShiftLoopEnds() {
        XCTAssertEqual(verify(1, 2), true, "line 78: fn = 0")
        XCTAssertEqual(verify(2, 4), true, "lines 78-79: fn = 1")
    }

    /// Ledger.swift 88-89: old 5, new 6 folds an even non-zero fn == sn (2) down to 1 and stops there.
    func testConsistencyFoldLoopEnds() {
        XCTAssertEqual(verify(5, 6), true, "lines 88-89")
        XCTAssertEqual(verify(3, 7), true, "lines 88-89 (3 -> 7)")
    }
}

final class S2H2ActionsHangTests: XCTestCase {
    func trait(_ id: String, _ implies: [String]) -> JSONValue {
        .object(["id": .string(id), "implies": .array(implies.map { JSONValue.string($0) }), "floor": Profile.bottom.json, "card_phrase": .string("p")])
    }

    /// Actions.swift 516 and 520: closure visits every trait once. Eight levels of eight traits, each implying all eight below (depth 8,
    /// the allowed maximum): 64 visits with the seen set, about 8^8 without it (a dropped insert also returns an empty closure).
    func testClosureVisitsEachTraitOnce() throws {
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
}

final class S2H2ArgProvenanceHangTests: XCTestCase {
    /// ArgProvenance.swift 524: the clip halves a long source until it fits.
    func testClipHalvesLongSources() {
        let long = String(repeating: "a", count: 300)
        let got: String? = S2Deadline.within(3, "clip") { (try? ProvenanceRecorder.clip(long)) ?? "" }
        XCTAssertEqual(got, String(repeating: "a", count: 150), "line 524")
    }

}

final class S2H2StrictJSONHangTests: XCTestCase {
    /// StrictJSON.swift 40: the byte compare advances past equal bytes.
    func testCompareUtf8AdvancesPastEqualBytes() {
        let got: [Int]? = S2Deadline.within(3, "compareUtf8") { [Canonical.compareUtf8("ab", "ac"), Canonical.compareUtf8("abc", "abc"), Canonical.compareUtf8("a", "ab")] }
        XCTAssertEqual(got, [-1, 0, -1], "line 40")
    }

}

final class S2H2UndoHangTests: XCTestCase {
    /// Undo.swift 276: a compensation_failed reason is cut to exactly 512 UTF-16 units (the note to 128).
    func testCompensationFailedReasonIsCutAt512() {
        let rec: JSONValue = .object(["state": .string("vetoed"), "window_end": .int(1000), "ver": .int(3), "attempt": .int(0)])
        let ev: JSONValue = .object(["kind": .string("compensation_failed"), "reason": .string(String(repeating: "r", count: 600))])
        let t = Undo.transition(rec, ev, now: 5)
        XCTAssertEqual(t.event, "compensation_failed")
        XCTAssertEqual(t.record?.get("outcome")?.get("reason")?.asString?.utf16.count, 512, "line 276")
        XCTAssertEqual(t.note?.utf16.count, 128)
        let exact = Undo.transition(rec, .object(["kind": .string("compensation_failed"), "reason": .string(String(repeating: "r", count: 512))]), now: 5)
        XCTAssertEqual(exact.record?.get("outcome")?.get("reason")?.asString?.utf16.count, 512)
    }
}
