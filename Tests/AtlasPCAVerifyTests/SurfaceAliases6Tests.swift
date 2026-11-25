import XCTest
@testable import AtlasPCAVerify

final class SurfaceAliases6Tests: XCTestCase {
    func req(headers: [String: String] = [:], body: String = "") -> PcaGuardRequest {
        PcaGuardRequest(method: "POST", path: "/x", headers: headers, body: Array(body.utf8), bodyComplete: true)
    }

    func testDefaultExtractReadsTheHeaderThenTheBody() {
        let json = "{\"grant_ref\":\"g\"}"
        let viaHeader = PcaGuard.defaultExtract(req(headers: ["pca-action": Base64URLStrict.encode(Array(json.utf8))]))
        XCTAssertEqual(viaHeader.pcactn?.get("grant_ref"), .string("g"))
        let viaBody = PcaGuard.defaultExtract(req(body: "{\"pcactn\":\(json)}"))
        XCTAssertEqual(viaBody.pcactn?.get("grant_ref"), .string("g"))
        XCTAssertNil(PcaGuard.defaultExtract(req()).pcactn)
        XCTAssertFalse(PcaGuard.defaultExtract(req()).reason.isEmpty)
        XCTAssertNil(PcaGuard.defaultExtract(req(headers: ["pca-action": "not base64url!"])).pcactn)
        XCTAssertNil(PcaGuard.defaultExtract(req(body: "{\"pcactn\":1}")).pcactn)
        XCTAssertNil(PcaGuard.defaultExtract(req(body: "[]")).pcactn)
    }

    func testTheFetchGuardAliasValidatesLikeTheGuard() {
        let cfg = RequirePcaOptions(audience: "")
        XCTAssertThrowsError(try PCAFetch.createPcaFetchGuard(PCAFetch.Options(config: cfg)))
    }
}
