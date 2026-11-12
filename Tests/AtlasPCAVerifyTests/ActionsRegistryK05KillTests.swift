import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import AtlasPCAVerify

/// ActionsRegistry.swift pinned to the reference packages/pca/src/action-pin.ts: an accepted pin never escalates (:259), fail-closed helpers.
final class ActionsRegistryK05KillTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }
    private lazy var d0 = Base64URLStrict.encode([UInt8](repeating: 3, count: 32))
    private lazy var d1 = Base64URLStrict.encode([UInt8](repeating: 4, count: 32))
    private let key = Curve25519.Signing.PrivateKey()

    private func keys() -> JSONValue {
        .array([.object(["kid": s("k"), "alg": s("ed25519"), "pk": s(Base64URLStrict.encode(Array(key.publicKey.rawRepresentation)))])])
    }

    private func record() throws -> JSONValue {
        let body: JObject = ["v": .int(1), "kind": s(Actions.EVOLUTION_RECORD_KIND), "ns": s("ns"), "verb": s("a.b"), "from": s(d0), "to": s(d1), "class": s("narrow"), "reasons": .array([])]
        let msg = try XCTUnwrap(IV.message(Actions.EVOLUTION_DOMAIN, .object(body)))
        var r = body
        r["sig"] = .object(["alg": s("ed25519"), "kid": s("k"), "value": s(Base64URLStrict.encode(Array(try key.signature(for: Data(msg)))))])
        return .object(r)
    }

    private func decide(defs: JSONValue? = nil, presented: String, records: [JSONValue] = []) -> PinDecision {
        var pin: JObject = ["pack": .object(["ns": s("ns"), "root": s(d0)]), "on_new_action": s("deny")]
        if let d = defs { pin["defs"] = d }
        let doc: JSONValue = .object(["verbs": .array([.object(["verb": s("a.b"), "def": s(presented)])]), "pack": .object(["ns": s("ns"), "root": s(d0)])])
        return Actions.decidePin(pin: .object(pin), doc: doc, verb: "a.b", records: records, keys: keys(), reapprovals: [], grantId: "g", issuer: "i")
    }
    private func accepted(_ via: String) -> PinDecision { PinDecision(ok: true, via: via, code: nil, escalate: false, reason: "", needsReapproval: nil) }

    func testAnAcceptedPinDoesNotEscalate() throws {
        XCTAssertEqual(decide(presented: d0), accepted("pack"))
        let defs: JSONValue = .object(["a.b": s(d0)])
        XCTAssertEqual(decide(defs: defs, presented: d0), accepted("exact"))
        XCTAssertEqual(decide(defs: defs, presented: d1, records: [try record()]), accepted("chain"))
    }

    func testAnUnknownVerbIsDenied() {
        let pin: JSONValue = .object(["pack": .object(["ns": s("ns"), "root": s(d0)]), "on_new_action": s("deny")])
        let doc: JSONValue = .object(["verbs": .array([.int(1), .object(["verb": s("c.d")])]), "pack": .object(["ns": s("ns"), "root": s(d0)])])
        XCTAssertEqual(Actions.decidePin(pin: pin, doc: doc, verb: "a.b", records: [], keys: keys(), reapprovals: [], grantId: "g", issuer: "i").code, "unknown_verb")
    }

    func testVerifyEvolutionRecord() throws {
        XCTAssertTrue(Actions.verifyEvolutionRecord(try record(), keys()))
        XCTAssertFalse(Actions.verifyEvolutionRecord(.int(1), keys()))
        XCTAssertFalse(Actions.verifyEvolutionRecord(nil, keys()))
    }

    /// A body outside the strict profile has no signing message.
    func testRegistrySigOverAnUnhashableBody() {
        let pk = Base64URLStrict.encode([UInt8](repeating: 7, count: 32))
        let k: JSONValue = .array([.object(["kid": s("k"), "pk": s(pk)])])
        XCTAssertFalse(Actions.verifyRegistrySig("d", ["x": .double(-0.0)], ["kid": s("k")], k))
    }

    func testFullMatchRefusesAPatternThatDoesNotCompile() {
        XCTAssertTrue(Actions.fullMatch("a+", "aa"))
        XCTAssertFalse(Actions.fullMatch("(", "("))
    }
}
