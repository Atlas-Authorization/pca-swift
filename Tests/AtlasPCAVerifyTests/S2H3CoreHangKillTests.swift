import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Round-2 hang sheet 3, core parts. Every call that a mutant makes loop or allocate forever runs under S2Deadline.within (3 s); the
/// unmutated code finishes each in microseconds.
final class S2H3MerkleHangTests: XCTestCase {
    /// merkle.ts: split = the largest power of two strictly below n (1 for n = 1).
    func testSplitIsTheLargestPowerOfTwoBelowN() {
        let got: [UInt64]? = S2Deadline.within(3, "Merkle.split 1...9") { (1...9).map { Merkle.split(UInt64($0)) } }
        XCTAssertEqual(got, [1, 1, 2, 2, 4, 4, 4, 4, 8], "lines 23-24")
    }

    /// Two leaves: the root is exactly node(l, r). Not a single-leaf or three-leaf call: under the line-29 mutants those recurse forever.
    func testTwoHashesJoinIntoOneNode() {
        let a = [UInt8](repeating: 1, count: 32), b = [UInt8](repeating: 2, count: 32)
        let want = Canonical.sha256([0x01] + a + b)
        XCTAssertEqual(Merkle.nodeHash(a, b), want)
        let got: [UInt8]? = S2Deadline.within(3, "Merkle.build of two hashes") { Merkle.build([a, b]) }
        XCTAssertEqual(got, want, "line 29: a two-element list is a node, not its first element")
    }

    /// The path of a one-leaf tree is empty and ends at once; with n >= 1 as the loop condition it appends forever.
    func testPathShapeOfASingleLeafIsEmpty() {
        let got: [[UInt8]]? = S2Deadline.within(3, "Merkle.pathShape") { [Merkle.pathShape(0, 1), Merkle.pathShape(0, 2), Merkle.pathShape(1, 2), Merkle.pathShape(2, 3)] }
        XCTAssertEqual(got, [[], [UInt8(ascii: "R")], [UInt8(ascii: "L")], [UInt8(ascii: "L")]], "line 44")
    }
}

final class S2H3BigUIntHangTests: XCTestCase {
    func testConstructionFromAnIntegerEndsAtItsTopLimb() {
        let got: [[UInt32]]? = S2Deadline.within(3, "BigUInt(UInt64)") {
            [BigUInt(0).limbs, BigUInt(1).limbs, BigUInt(1 << 40).limbs, BigUInt(0xffff_ffff_ffff_ffff).limbs]
        }
        XCTAssertEqual(got, [[], [1], [0, 256], [0xffff_ffff, 0xffff_ffff]], "line 18")
    }

    func testLittleEndianBytesLandInTheirOwnShifts() {
        XCTAssertEqual(BigUInt(bytesLE: [1]).limbs, [1], "line 32: byte 0 sits at shift 0")
        XCTAssertEqual(BigUInt(bytesLE: [1, 2]).limbs, [0x0201], "line 32: byte 1 sits at shift 8")
        XCTAssertEqual(BigUInt(bytesLE: [1, 2, 3, 4, 5]).limbs, [0x0403_0201, 5], "line 32: byte 4 starts the next limb")
    }

    func testLessThanWalksDownToTheFirstDifferingLimb() {
        let lo = BigUInt(0x1_0000_0001), hi = BigUInt(0x1_0000_0002)
        let got: [Bool]? = S2Deadline.within(3, "BigUInt <") { [lo < hi, hi < lo, lo < lo, BigUInt(5) < BigUInt(5), BigUInt(0) < BigUInt(0)] }
        XCTAssertEqual(got, [true, false, false, false, false], "line 74")
    }
}

final class S2H3PCALockHangTests: XCTestCase {
    /// lock/unlock/lock/unlock on one thread: a lock that is not given back (count, branch or dropped unlock) blocks the second lock().
    func testALockIsGivenBackEachTime() {
        let got: [Int]? = S2Deadline.within(3, "PCALock lock/unlock twice") {
            let l = PCALock()
            l.lock(); let d1 = l.depth
            l.unlock()
            l.lock(); let d2 = l.depth
            l.unlock()
            return [d1, d2, l.depth, l.acquisitions, l.imbalance]
        }
        XCTAssertEqual(got, [1, 1, 0, 2, 0], "PCALock.swift lines 15, 20, 22, 23")
    }
}

final class S2H3AttestXMLHangTests: XCTestCase {
    func testNamespaceLookupWalksUpTheParents() {
        let got: [String?]? = S2Deadline.within(3, "XmlNode.lookupNS") {
            let p = XmlNode(elem: true), c = XmlNode(elem: true)
            p.decls.append(XmlDecl(prefix: "x", uri: "urn:x"))
            c.parent = p
            return withExtendedLifetime(p) { [c.lookupNS("x"), c.lookupNS("zz"), p.lookupNS("x")] }
        }
        XCTAssertEqual(got, ["urn:x", nil, "urn:x"], "AttestXML.swift line 37")
    }

    func testScopeCollectsEveryAncestor() {
        let got: [String: String]? = S2Deadline.within(3, "XmlNode.scope") {
            let p = XmlNode(elem: true), c = XmlNode(elem: true)
            p.decls.append(XmlDecl(prefix: "x", uri: "urn:x"))
            c.decls.append(XmlDecl(prefix: "y", uri: "urn:y"))
            c.parent = p
            return withExtendedLifetime(p) { c.scope() }
        }
        XCTAssertEqual(got, ["x": "urn:x", "y": "urn:y"], "AttestXML.swift line 98")
    }

    func testDecodeStepsOverPlainBytes() {
        let got: [String?]? = S2Deadline.within(3, "XML.decode") {
            [try? XML.decode(Array("a&amp;b".utf8)[...]), try? XML.decode(Array("x&lt;y&#65;z".utf8)[...])]
        }
        XCTAssertEqual(got, ["a&b", "x<yAz"], "AttestXML.swift line 129")
    }
}

final class S2H3AttestIntelHangTests: XCTestCase {
    func testIndexOfAdvancesPastANonMatch() {
        let got: [Int]? = S2Deadline.within(3, "DcapVerifier.indexOf") {
            [DcapVerifier.indexOf([1, 2, 3], [2]), DcapVerifier.indexOf([1, 2, 3], [3]), DcapVerifier.indexOf([1, 2, 3], [9]), DcapVerifier.indexOf([1, 2, 3], [1])]
        }
        XCTAssertEqual(got, [1, 2, -1, 0], "AttestIntel.swift line 88")
    }
}
