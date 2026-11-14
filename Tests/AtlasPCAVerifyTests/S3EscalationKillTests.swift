import XCTest
import Foundation
@testable import AtlasPCAVerify

/// buildEscalationRequest (packages/pca/src/escalation.ts): v is 1, at most 16 reasons, render_digest carried when given.
final class S3EscalationKillTests: XCTestCase {
    typealias J = JSONValue

    private func build(_ reasons: [String], render: String? = nil) -> JObject? {
        let grant = J.object(["g": J.int(1)])
        let pcactn = J.object(["action": J.object(["verb": J.string("v"), "resource": J.string("r")])])
        guard case let .object(o)? = PCA.buildEscalationRequest(aud: "a", grant: grant, pcactn: pcactn, lastCounter: nil, reasons: reasons, now: 1000, renderDigest: render) else { return nil }
        return o
    }

    func testRequestVersionIsOne() throws {
        let o = try XCTUnwrap(build([]))
        XCTAssertEqual(o["v"], J.int(1), "line 75")
        XCTAssertEqual(o["kind"], J.string("pca-escalation-request"))
    }

    func testAtMostSixteenReasons() throws {
        let many = (0..<20).map { "r\($0)" }
        let o = try XCTUnwrap(build(many))
        guard case let .array(rs)? = o["reasons"] else { return XCTFail("reasons") }
        XCTAssertEqual(rs.count, 16, "line 77")
        XCTAssertEqual(rs.last?.asString, "r15")
        let exact = try XCTUnwrap(build(Array(many.prefix(16))))
        guard case let .array(re)? = exact["reasons"] else { return XCTFail("reasons") }
        XCTAssertEqual(re.count, 16)
    }

    func testRenderDigestIsCarriedWhenGiven() throws {
        let o = try XCTUnwrap(build([], render: "RD"))
        XCTAssertEqual(o["render_digest"], J.string("RD"), "line 80")
        let none = try XCTUnwrap(build([]))
        XCTAssertNil(none["render_digest"])
    }
}
