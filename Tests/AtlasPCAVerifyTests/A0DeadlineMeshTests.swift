import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mesh.swift consistency (RFC 9162 2.1.4.2): the two shift loops a mutated condition can make endless. Every call runs under a deadline.
/// Real proofs (built here from the RFC 6962 definitions) for every pair of sizes 1 <= old < new <= 9.
private enum A0MeshProofGen {
    typealias J = JSONValue

    static func leaf(_ i: Int) -> [UInt8] { [UInt8](repeating: UInt8(i + 1), count: 32) }

    static func pow2Below(_ n: Int) -> Int {
        var k = 1
        while k * 2 < n { k *= 2 }
        return k
    }

    static func mth(_ d: [[UInt8]]) -> [UInt8] {
        if d.count == 1 { return d[0] }
        let k = pow2Below(d.count)
        return Merkle.nodeHash(mth(Array(d[..<k])), mth(Array(d[k...])))
    }

    static func subproof(_ m: Int, _ d: [[UInt8]], _ b: Bool) -> [[UInt8]] {
        let n = d.count
        if m == n { return b ? [] : [mth(d)] }
        let k = pow2Below(n)
        if m <= k { return subproof(m, Array(d[..<k]), b) + [mth(Array(d[k...]))] }
        return subproof(m - k, Array(d[k...]), false) + [mth(Array(d[..<k]))]
    }

    /// The pairs "old->new" for which Mesh.consistency gave the wrong answer (`tamper`: the new root is wrong, so false is right).
    static func wrong(tamper: Bool) -> [String] {
        var out: [String] = []
        let leaves = (0..<9).map { leaf($0) }
        for n in 2...9 {
            for m in 1..<n {
                let d = Array(leaves[..<n])
                let oldRoot = Base64URLStrict.encode(mth(Array(leaves[..<m])))
                let newRoot = tamper ? Base64URLStrict.encode(leaf(99)) : Base64URLStrict.encode(mth(d))
                let path = J.array(subproof(m, d, true).map { J.string(Base64URLStrict.encode($0)) })
                let p: JObject = ["oldSize": J.int(Int64(m)), "newSize": J.int(Int64(n)), "path": path]
                if Mesh.consistency(oldRoot, newRoot, p) == tamper { out.append("\(m)->\(n)") }
            }
        }
        return out
    }
}

final class A0DeadlineMeshTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testA1GenuineConsistencyProofsVerify() {
        let bad: [String]? = S2Deadline.within(10, "Mesh.consistency over genuine proofs") { A0MeshProofGen.wrong(tamper: false) }
        XCTAssertEqual(bad, [], "lines 235-245: every genuine proof verifies")
    }

    func testA2ConsistencyWithAWrongNewRootIsRefused() {
        let bad: [String]? = S2Deadline.within(10, "Mesh.consistency over tampered proofs") { A0MeshProofGen.wrong(tamper: true) }
        XCTAssertEqual(bad, [], "lines 235-245: a wrong new root is refused")
    }
}
