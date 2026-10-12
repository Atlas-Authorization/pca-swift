import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Shared hard limits (all PCA verifiers): 512 KiB raw PCActn document, checked before parsing; 256 caveats per hop and
/// 1024 per chain, checked on raw list sizes before any hashing or signature work.
final class LimitsTests: XCTestCase {
    private func hop(_ n: Int) -> JSONValue {
        .object([JKey("caveats"): .array(Array(repeating: .object([JKey("type"): .string("note")]), count: n))])
    }

    func testArtifactSizeCap() {
        XCTAssertEqual(PCA.ARTIFACT_SIZE_REASON, "artifact exceeds size limit (max 524288 bytes)")
        let grant = JSONValue.object([:])
        let pad = { (n: Int) in "{}" + String(repeating: " ", count: n - 2) }
        for n in [PCA.MAX_ARTIFACT_BYTES - 1, PCA.MAX_ARTIFACT_BYTES] {
            XCTAssertFalse(PCA.verify(json: pad(n), grant: grant, now: 0, audience: "a").reason.contains(PCA.ARTIFACT_SIZE_REASON), "\(n) bytes must reach the parser")
        }
        let t0 = Date()
        let v = PCA.verify(json: "x" + pad(PCA.MAX_ARTIFACT_BYTES), grant: grant, now: 0, audience: "a") // garbage: the SIZE reason proves it precedes parsing
        XCTAssertFalse(v.allow)
        XCTAssertEqual(v.checks, ["wire": false])
        XCTAssertTrue(v.reason.contains(PCA.ARTIFACT_SIZE_REASON))
        XCTAssertLessThan(Date().timeIntervalSince(t0), 0.1)
        // UTF-8 bytes, not characters: 174763 euro signs are 524289 bytes
        XCTAssertTrue(PCA.verify(json: String(repeating: "\u{20AC}", count: 174763), grant: grant, now: 0, audience: "a").reason.contains(PCA.ARTIFACT_SIZE_REASON))
    }

    func testInt64MinIsNotSafeAndDoesNotTrap() {
        // abs(Int64.min) traps in Swift; the range check must reject it (and Int64.max) without crashing.
        XCTAssertNil(JSONValue.int(Int64.min).safeInt)
        XCTAssertNil(JSONValue.int(Int64.max).safeInt)
        XCTAssertNil(JSONValue.int(-9_007_199_254_740_992).safeInt)
        XCTAssertEqual(JSONValue.int(-9_007_199_254_740_991).safeInt, -9_007_199_254_740_991)
        XCTAssertEqual(JSONValue.int(9_007_199_254_740_991).safeInt, 9_007_199_254_740_991)
        XCTAssertNotNil(Canonical.intError(Int64.min))
        XCTAssertNil(Canonical.intError(-9_007_199_254_740_991))
    }

    func testCaveatCaps() {
        XCTAssertEqual(Capability.verifyChain([hop(257)], expectedRootIssuer: nil), Capability.CAVEAT_LIMIT_REASON)
        XCTAssertEqual(Capability.verifyChain(Array(repeating: hop(205), count: 5), expectedRootIssuer: nil), Capability.CAVEAT_LIMIT_REASON)
        XCTAssertFalse(Capability.caveatLimitExceeded([hop(204), hop(205), hop(205), hop(205), hop(205)]))
        XCTAssertFalse(Capability.caveatLimitExceeded([hop(256)]))
    }
}
