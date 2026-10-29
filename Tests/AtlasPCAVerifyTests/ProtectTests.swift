import XCTest
import Foundation
@testable import AtlasPCAVerify

/// `explainRefusal`, `protect(...)` and the `doc` member of refusal bodies.
final class ProtectTests: XCTestCase {
    func testExplainRefusalMapsTheLeadingCheck() {
        let h = explainRefusal("replay: counter 3 <= last 3")
        XCTAssertEqual(h.check, "replay")
        XCTAssertEqual(h.docs, "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay")
        XCTAssertEqual(h.meaning, "This proof (or an older counter) was already used.")
        XCTAssertEqual(explainRefusal("authorize_config: missing required component(s): stateStore").check, "authorize_config")
        XCTAssertEqual(explainRefusal("grant_ref_bound: x").check, "grant_ref_bound")
        // a reason that does not lead with the check still matches `check:` inside the text
        XCTAssertEqual(explainRefusal("PCActn refused (audience: mismatch)").check, "audience")
    }

    func testExplainRefusalUnknownAndNilNeverFail() {
        XCTAssertEqual(explainRefusal("no PCActn presented").check, "unknown")
        XCTAssertEqual(explainRefusal(nil).check, "unknown")
        XCTAssertEqual(explainRefusal("").docs, "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md")
    }

    func testRefusalBodiesCarryADocLinkAndKeepTheReason() throws {
        let s = AZ.signed()
        let g = try PcaGuardTests.guardFor(s)
        XCTAssertTrue(g.handle(PcaGuardTests.request(s)).allowed) // consumes the counter
        guard case let .deny(d) = g.handle(PcaGuardTests.request(s)) else { return XCTFail("replay must be refused") }
        let body = JSONValue.parse(d.bodyText)
        XCTAssertTrue(body?.get("reason")?.asString?.hasPrefix("replay") ?? false, d.bodyText)
        XCTAssertEqual(body?.get("doc")?.asString, "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay")
        // a 401 without a proof also links the table
        guard case let .deny(none) = g.handle(PcaGuardRequest(method: "GET", path: "/")) else { return XCTFail("expected 401") }
        XCTAssertEqual(JSONValue.parse(none.bodyText)?.get("doc")?.asString, "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md")
    }

    func testProtectAllowsOnceRefusesReplayAndRevokes() throws {
        let s = AZ.signed()
        let grantId = try XCTUnwrap(s.grant.get("id")?.asString)
        let p = protect(audience: AZ.AUD, operation: PcaGuardTests.mapper, grants: [s.grant], now: { AZ.NOW }, configure: { $0.authorize?.pinProvHarness() })
        let g = try PcaGuard(p.config)
        guard case .allow = g.handle(PcaGuardTests.request(s)) else { return XCTFail("first use must pass") }
        guard case let .deny(replay) = g.handle(PcaGuardTests.request(s)) else { return XCTFail("replay must be refused") }
        XCTAssertEqual(replay.status, 403)
        // revocation: a fresh store would accept the proof again, so the refusal is the revocation
        let p2 = protect(audience: AZ.AUD, operation: PcaGuardTests.mapper, grants: [s.grant], now: { AZ.NOW }, configure: { $0.authorize?.pinProvHarness() })
        let g2 = try PcaGuard(p2.config)
        p2.revoke(grantId)
        guard case let .deny(revoked) = g2.handle(PcaGuardTests.request(s)) else { return XCTFail("a revoked grant must be refused") }
        XCTAssertTrue(revoked.bodyText.contains("revocation"), revoked.bodyText)
    }

    func testProtectGrantsComeFromTheListNotTheRequestAndCallerOptionsWin() throws {
        let s = AZ.signed()
        // no grants registered: the proof's grant_ref resolves to nothing
        let none = try PcaGuard(protect(audience: AZ.AUD, operation: PcaGuardTests.mapper, now: { AZ.NOW }).config)
        guard case .deny = none.handle(PcaGuardTests.request(s)) else { return XCTFail("an unknown grant must be refused") }
        // a caller-supplied isRevoked is consulted, and `configure` has the last word
        let p = protect(audience: AZ.AUD, operation: PcaGuardTests.mapper, grants: [s.grant], isRevoked: { _, _ in true }, now: { AZ.NOW },
                        configure: { $0.audience = "other" })
        XCTAssertEqual(p.config.audience, "other")
        let g = try PcaGuard(protect(audience: AZ.AUD, operation: PcaGuardTests.mapper, grants: [s.grant], isRevoked: { _, _ in true }, now: { AZ.NOW }).config)
        guard case .deny = g.handle(PcaGuardTests.request(s)) else { return XCTFail("the caller's revocation source must refuse") }
    }
}
