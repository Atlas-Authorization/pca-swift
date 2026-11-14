import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// Heavy-fixture kill test (heavy-brief item 4, Authorize.swift line 848): a two-hop chain whose delegated hop adds a K1 caveat. The
/// stock caveat evaluator refuses K1 types, so they must be filtered out of what it sees and judged by evaluateK1.
final class AuthorizeS2HVKillTests: XCTestCase {
    private func signedDelegated() throws -> AZ.Signed {
        let holder1 = PCASuiteKey.ed25519(try PCAEdKey(seed: Array(V2F.stranger.rawRepresentation)))
        let g = V2F.cap(issuer: AZ.principal, holder: V2F.stranger, caveats: [AZ.envelope()])
        let hop = try PCAIssue.delegate(parent: g, toHolder: V2F.pub(AZ.agent), added: [.object(["type": .string("sealed")])], signer: holder1)
        let p = AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD, extra: ["cap_chain": .array([g, hop])])
        return AZ.Signed(grant: g, pcactn: p, params: AuthorizeTests.P50)
    }

    func testAK1CaveatOnADelegatedHopIsJudgedByTheK1Evaluator() throws {
        let s = try signedDelegated()
        let r = AZ.run(s) { $0.k1 = K1Input() }
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(r.checks["delegated_caveats"], .pass, "line 848 the stock evaluator never sees the K1 caveat; \(r.reasons)")
    }
}
