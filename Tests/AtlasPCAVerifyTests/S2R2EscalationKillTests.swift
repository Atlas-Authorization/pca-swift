import XCTest
import Foundation
@testable import AtlasPCAVerify

/// buildEscalationRequest (packages/pca/src/escalation.ts:60): default ttl 3_600_000 ms, reasons clipped to 512 UTF-16 units.
final class S2R2EscalationKillTests: XCTestCase {
    typealias J = JSONValue

    private func build(_ reasons: [String]) -> JObject? {
        let grant = J.object(["g": J.int(1)])
        let pcactn = J.object(["action": J.object(["verb": J.string("v"), "resource": J.string("r")])])
        guard case let .object(o)? = PCA.buildEscalationRequest(aud: "a", grant: grant, pcactn: pcactn, lastCounter: nil, reasons: reasons, now: 1000) else { return nil }
        return o
    }

    func testDefaultTtlIsOneHour() throws {
        let o = try XCTUnwrap(build([]))
        XCTAssertEqual(IV.safe(o["expires_at"]), 1000.0 + 3_600_000.0, "line 68: ttl default")
    }

    func testReasonsClipAt512() throws {
        let o = try XCTUnwrap(build([String(repeating: "a", count: 512), String(repeating: "b", count: 513), "short"]))
        guard case let .array(rs)? = o["reasons"] else { return XCTFail("reasons") }
        XCTAssertEqual(rs.count, 3)
        XCTAssertEqual(rs[0].asString, String(repeating: "a", count: 512))
        XCTAssertEqual(rs[1].asString, String(repeating: "b", count: 512), "line 73: 513 units clip to 512")
        XCTAssertEqual(rs[2].asString, "short")
    }
}
