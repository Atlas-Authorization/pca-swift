import XCTest
@testable import AtlasPCAVerify

/// `verifyFreshAt` (packages/pca/src/fresh-at.ts:73): scope at most 256 and policy_digest at most 128 UTF-16 units, each bound
/// exercised with a genuine signature so only the bound can refuse.
final class FreshAtK05Tests: XCTestCase {
    static let signerKey = V2F.key("fresh-at-k05")

    static func token(scope: String = "ins_1", digest: String = "d") -> JSONValue {
        var body: JObject = ["v": .int(1), "scope": .string(scope), "revocation_epoch": .int(0), "ledger_tree_size": .int(0), "budget_version": .int(0),
                             "policy_revision": .int(0), "policy_digest": .string(digest), "issued_at": .int(1), "signer": .string(V2F.pub(signerKey))]
        body["sig"] = .string(V2F.sign(signerKey, IV.message(FreshAt.DOMAIN, .object(body))!))
        return .object(body)
    }

    private func s(_ n: Int) -> String { String(repeating: "s", count: n) }

    func testScopeAndDigestBounds() {
        let pk = V2F.pub(Self.signerKey)
        XCTAssertTrue(FreshAt.verify(Self.token(), signer: pk))
        XCTAssertTrue(FreshAt.verify(Self.token(scope: s(256)), signer: pk))
        XCTAssertFalse(FreshAt.verify(Self.token(scope: s(257)), signer: pk))
        XCTAssertTrue(FreshAt.verify(Self.token(digest: s(128)), signer: pk))
        XCTAssertFalse(FreshAt.verify(Self.token(digest: s(129)), signer: pk))
    }
}
