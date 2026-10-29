import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED runtime-class claim vectors (packages/pca/conformance/runtime-claim-vectors.json).
final class RuntimeClaimVectorTests: XCTestCase {
    func testRuntimeClaimVectors() throws {
        let doc = try ConformanceTests.load("runtime-claim-vectors.json")
        let t = doc.get("trust")
        let pinned = (t?.get("pinnedAttestors")?.asArray ?? []).compactMap { $0.asString }
        let evidence = (t?.get("verifiedEvidenceDigests")?.asArray ?? []).compactMap { $0.asString }
        let pd = t?.get("passportDigest")?.asString ?? ""
        let cases = doc.get("cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 8)
        for c in cases {
            let got = RuntimeClaim.verifiedClass(c.get("claim"), pinnedAttestors: pinned, passportDigest: pd, verifiedEvidence: evidence, now: c.get("now"))
            XCTAssertEqual(got, c.get("expect")?.asString, c.get("name")?.asString ?? "?")
        }
        let first = cases[0]
        XCTAssertEqual(RuntimeClaim.verifiedClass(first.get("claim"), pinnedAttestors: [], passportDigest: pd, verifiedEvidence: evidence, now: first.get("now")), "none")
        XCTAssertEqual(RuntimeClaim.verifiedClass(first.get("claim"), pinnedAttestors: pinned, passportDigest: pd, verifiedEvidence: [], now: first.get("now")), "none")
        XCTAssertEqual(RuntimeClaim.verifiedClass(nil, pinnedAttestors: pinned, passportDigest: pd, verifiedEvidence: evidence, now: nil), "none")
    }
}
