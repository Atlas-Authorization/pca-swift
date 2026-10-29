import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import AtlasPCAVerify

/// `PCA.authorize` forwards `AuthorizeInput.freshAt` to the core verifier and reads the side-carried `pca-fresh-at` header.
final class FreshAtAuthorizeTests: XCTestCase {
    static let FIX: JSONValue = (try? K042.json("authorize-fixtures.json")) ?? .null
    static var NOW: Int64 { FIX.get("now")?.safeInt ?? 0 }
    static let key = Curve25519.Signing.PrivateKey()
    static var signer: String { Base64URLStrict.encode(Array(key.publicKey.rawRepresentation)) }

    /// A signed token whose counters are all `n`.
    static func token(_ n: Int64) -> JSONValue {
        var o: JObject = ["v": .int(1), "scope": .string("inst_1"), "revocation_epoch": .int(n), "ledger_tree_size": .int(n),
                          "budget_version": .int(n), "policy_revision": .int(1), "policy_digest": .string("pd"),
                          "issued_at": .int(Self.NOW), "signer": .string(signer)]
        let msg = IV.message(FreshAt.DOMAIN, .object(o))!
        o["sig"] = .string(Base64URLStrict.encode(Array(try! key.signature(for: Data(msg)))))
        return .object(o)
    }
    static func policy(local n: Int64, require: Bool = false) -> FreshAtPolicy {
        FreshAtPolicy(signer: signer, scope: "inst_1",
                      local: FreshAt.State(revocationEpoch: n, ledgerTreeSize: n, budgetVersion: n, policyRevision: 1, policyDigest: "pd"), require: require)
    }
    static func text(_ v: JSONValue) -> String { try! Canonical.canonicalizeStrict(v) }

    func run(_ policy: FreshAtPolicy?, header: String? = nil) -> PCA.AuthorizeResult {
        let fix = Self.FIX
        let c = fix.get("cases")?.asArray?.first { $0.get("name")?.asString == "envelope-predicate-within" } ?? .null
        let step = c.get("steps")?.asArray?[0] ?? .null
        let g = c.get("grant") ?? .null
        let o = step.get("operation")
        let op = PCA.Operation(verb: o?.get("verb")?.asString ?? "", resource: o?.get("resource")?.asString ?? "", params: o?.get("params") ?? .null)
        return PCA.authorize(pcactn: step.get("pcactn"), PCA.AuthorizeInput(
            operation: op, audience: fix.get("audience")?.asString, resolveGrant: { _ in g }, stateStore: MemoryStateStore(),
            isRevoked: { _, _ in false }, now: Self.NOW, plan: PCA.SINGLE_STEP, freshAt: policy, freshAtHeader: header).withProv())
    }

    func testNoPolicyIsUnchanged() {
        let r = run(nil)
        XCTAssertTrue(r.allow)
        XCTAssertNil(r.verdict?.checks["fresh_at"])
    }

    func testOkWithSideCarriedHeader() {
        let r = run(Self.policy(local: 5), header: Self.text(Self.token(5)))
        XCTAssertTrue(r.allow, r.reason ?? "")
        XCTAssertEqual(r.verdict?.checks["fresh_at"], true)
    }

    func testStaleVerifierEscalates() {
        let r = run(Self.policy(local: 4), header: Self.text(Self.token(5)))
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "escalate")
        XCTAssertTrue((r.reason ?? "").contains("escalate: stale_state"), r.reason ?? "")
    }

    func testRequiredButNoToken() {
        let r = run(Self.policy(local: 5, require: true))
        XCTAssertFalse(r.allow)
        XCTAssertTrue((r.reason ?? "").contains("a consistency token is required"), r.reason ?? "")
    }

    func testUnparseableHeaderIsBadToken() {
        let r = run(Self.policy(local: 5), header: "{not json")
        XCTAssertFalse(r.allow)
        XCTAssertTrue((r.reason ?? "").contains("bad_token"), r.reason ?? "")
    }

    func testHeaderWithoutPolicyIsIgnored() {
        XCTAssertTrue(run(nil, header: "{not json").allow)
    }
}
