import XCTest
import Foundation
@testable import AtlasPCAVerify

/// ProvenanceGate.swift (mutation round 2, survivors sheet 3): the refusal level and the size bound of the RFC 9162 inclusion check.
final class S2R3ProvenanceGateKillTests: XCTestCase {
    func testRefusalCarriesLevelZeroAndNoClaims() {
        let r = PCA.provenanceGate(nil)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.level, 0, "line 18: a refusal is level 0")
        XCTAssertEqual(r.code, "malformed_facts")
        XCTAssertTrue(r.claims.isEmpty)
    }

    func testInclusionAcceptsTheLargestSafeTreeSize() {
        // index 0 in a tree of 2^53 - 1 leaves: sn = 2^53 - 2 has 53 bits, so exactly 53 proof nodes, all taken as right siblings
        let leaf = PCA.rfc9162LeafHash([1, 2, 3])
        var r = leaf
        var proof: [[UInt8]] = []
        for k in 0..<53 {
            let p = [UInt8](repeating: UInt8(k + 1), count: 32)
            proof.append(p)
            r = Canonical.sha256([1] + r + p)
        }
        XCTAssertTrue(PCA.verifyRfc9162Inclusion(leafHash: leaf, index: 0, size: Canonical.MAX_SAFE, proof: proof, root: r), "line 68: size 2^53 - 1 is allowed (<=)")
        XCTAssertFalse(PCA.verifyRfc9162Inclusion(leafHash: leaf, index: 0, size: Canonical.MAX_SAFE + 1, proof: proof, root: r), "size 2^53 is refused")
    }
}
