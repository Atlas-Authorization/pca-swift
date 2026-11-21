import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAEvidence against the reference (@atlasauth/pca-evidence): shape validation, normal form, commitments-only
/// form, digest, reference and anchor leaf, accumulator cap reader and trust-input validators. A reference throw requires a native
/// refusal; the validators' absent argument is the no-argument case. Not covered by the corpus: the full replay, the signed statement.
final class RefEvidenceTests: XCTestCase {
    static let file = "ref-evidence.json.gz"

    func testEvidence() throws {
        try K042.requireCovers(["Evidence", "JSLoose"])
        let d = Base.Diffs()
        var seen = Set<String>()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0)
            let got: BaseGot
            seen.insert(c.fn)
            switch c.fn {
            case "bundleShapeError": got = .value(Base.opt(PCAEvidence.bundleShapeError(a0)))
            case "normalizeBundle": got = Ref.v { try PCAEvidence.normalizeBundle(a0) }
            case "buildEvidenceBundle": got = Ref.v { try PCAEvidence.buildEvidenceBundle(a0) }
            case "commitmentForm": got = Ref.v { try PCAEvidence.commitmentForm(a0) }
            case "evidenceDigest": got = Ref.s { try PCAEvidence.evidenceDigest(a0) }
            case "evidenceRef": got = Ref.v { try PCAEvidence.evidenceRef(a0) }
            case "evidenceAnchorCommit": got = Ref.s { try PCAEvidence.evidenceAnchorCommit(a0) }
            case "anchorCommit": got = Ref.s { try PCAEvidence.anchorCommit(a0, c.arg(1)) }
            case "capOf": got = Ref.v { try PCAEvidence.capOf(a0, c.arg(1), c.arg(2)) }
            case "principalsTrustError": got = .value(Base.opt(PCAEvidence.principalsTrustError(a0)))
            case "accTrustError": got = .value(Base.opt(PCAEvidence.accTrustError(a0)))
            case "consts":
                got = .value(.object(["EVIDENCE_DOMAIN": .string(PCAEvidence.EVIDENCE_DOMAIN), "EVIDENCE_REPORT_DOMAIN": .string(PCAEvidence.EVIDENCE_REPORT_DOMAIN),
                                      "EVIDENCE_CONTENT_TYPE": .string(PCAEvidence.EVIDENCE_CONTENT_TYPE)]))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen.count, 12)
        d.finish(1700)
    }

    func testEvidenceFailClosed() throws {
        XCTAssertThrowsError(try PCAEvidence.normalizeBundle(nil))
        XCTAssertThrowsError(try PCAEvidence.normalizeBundle(.null))
        XCTAssertThrowsError(try PCAEvidence.buildEvidenceBundle(.object([:])))
        XCTAssertEqual(PCAEvidence.bundleShapeError(.null), "bundle must be an object")
        XCTAssertNotNil(PCAEvidence.principalsTrustError(.array([])))
        XCTAssertNotNil(PCAEvidence.accTrustError(.null))
    }
}
