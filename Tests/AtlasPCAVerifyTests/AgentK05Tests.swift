import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The agent client's contract: the `Date.now` clock, a slot nonce wins over the stamped one, `nonces = false` stamps none, 16 random
/// bytes per nonce (base64url, as the reference and every other SDK), and a delegate's counter starts at 0.
final class AgentK05Tests: XCTestCase {
    private func envelope() -> JObject {
        ["predicates": .array([.object(["verb": .string("*")])]), "caveats": .array([]),
         "risk_policy": .object(["weights": .object(["alpha": .double(0.25), "beta": .double(0), "gamma": .double(0), "delta": .double(0), "epsilon": .double(0), "zeta": .double(0)]), "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1)])]
    }

    private func agent() throws -> PCAAgent {
        let principal = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 0, count: 32)))
        let me = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 1, count: 32)))
        let g = try PCAIssue.mintGrant(principal: principal, holder: me.id!, envelope: envelope(), goal: "g")
        let a = try PCAAgent(signer: me, aud: "ins_t", grant: g.grant)
        a.clock = { 1_800_000_000_000 }
        return a
    }

    func testDefaultClockIsEpochMilliseconds() throws {
        let me = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 1, count: 32)))
        let a = try PCAAgent(signer: me, aud: "ins_t", grant: .object([:]))
        let want = Int64(Date().timeIntervalSince1970 * 1000)
        XCTAssertLessThan(abs(a.clock() - want), 60_000)
    }

    func testStampedNonceIsSixteenRandomBytes() throws {
        let nonce = try agent().act(verb: "read", resource: "x").get("nonce")?.asString
        XCTAssertEqual(nonce?.count, 22) // 16 bytes as unpadded base64url
        XCTAssertEqual(Base64URLStrict.decode(nonce ?? "", length: 16).map { Base64URLStrict.encode($0) }, nonce)
    }

    func testSlotNonceWinsOverTheStampedOne() throws {
        let p = try agent().act(verb: "read", resource: "x", slots: ["nonce": .string("mine")])
        XCTAssertEqual(p.get("nonce")?.asString, "mine")
    }

    func testNoncesOffStampsNone() throws {
        let a = try agent()
        a.nonces = false
        XCTAssertNil(try a.act(verb: "read", resource: "x").get("nonce"))
        // an explicit slot still goes through
        XCTAssertEqual(try a.act(verb: "read", resource: "x", slots: ["nonce": .string("mine")]).get("nonce")?.asString, "mine")
    }

    func testDelegateCounterStartsAtZero() throws {
        let a = try agent()
        _ = try a.act(verb: "read", resource: "x")
        _ = try a.act(verb: "read", resource: "x")
        XCTAssertEqual(a.counter, 2)
        let sub = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 2, count: 32)))
        let child = try a.delegate(to: sub)
        XCTAssertEqual(child.counter, 0)
        XCTAssertEqual(try child.act(verb: "read", resource: "x").get("counter")?.safeInt, 1)
    }
}
