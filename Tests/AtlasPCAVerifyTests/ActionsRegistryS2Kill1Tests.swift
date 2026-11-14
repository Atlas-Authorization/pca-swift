import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the ActionsRegistry.swift survivors of group 2: the strict-canonical checks of record and pack shapes, the first-edge-wins evolution
/// search, and the pack def-count bound. Pinned to packages/pca/src/action-pin.ts and packages/pca-actions/src/pack.ts:276.
final class S2G2ActionsRegistryKillTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }
    // computed (see AttestNvidiaOcspS2G5KillTests): no SDK call while XCTest lists the tests
    private var d0: String { Base64URLStrict.encode([UInt8](repeating: 3, count: 32)) }
    private var d1: String { Base64URLStrict.encode([UInt8](repeating: 4, count: 32)) }
    private static let key = V2F.key("s2g2-registry")
    /// U+FDD0 is the harness's stand-in for a lone surrogate: strict canonical JSON refuses it.
    private let lone = String(Unicode.Scalar(0xFDD0)!)

    private func keys() -> JSONValue {
        .array([.object(["kid": s("k"), "alg": s("ed25519"), "pk": s(V2F.pub(Self.key))])])
    }

    private func recordBody(reasons: [JSONValue]) -> JObject {
        ["v": .int(1), "kind": s(Actions.EVOLUTION_RECORD_KIND), "ns": s("ns"), "verb": s("a.b"), "from": .string(d0), "to": .string(d1),
         "class": s("widen"), "reasons": .array(reasons)]
    }

    private func signedRecord(reason: String) -> JSONValue {
        let body = recordBody(reasons: [s(reason)])
        var r = body
        r["sig"] = .object(["alg": s("ed25519"), "kid": s("k"), "value": s(V2F.sign(Self.key, IV.message(Actions.EVOLUTION_DOMAIN, .object(body))!))])
        return .object(r)
    }

    func testEvolutionRecordCanonicalErrorIsReported() {
        XCTAssertNil(Actions.evolutionRecordError(.object(recordBody(reasons: [s("fine")])), signed: false))
        XCTAssertEqual(Actions.evolutionRecordError(.object(recordBody(reasons: [s(lone)])), signed: false),
                       "evolution record: canonicalize: lone surrogate in string", "line 75")
    }

    private func packBody(licenceNotes: String) -> JObject {
        ["v": .int(1), "kind": s("pca-action-pack"), "ns": s("ns"), "version": s("1.0.0"), "stability": s("draft"), "traits_digest": .string(d0),
         "roles_digest": .string(d0), "rules_digest": .string(d0), "root": .string(d0), "prev": .null,
         "source": .object(["kind": s("k"), "uri": s("u"), "spec_digest": s("sd"), "licence": s("MIT"), "licence_notes": s(licenceNotes)]),
         "defs": .object(["shards": .array([.object(["name": s("s1"), "digest": .string(d0), "uri": s("u")])])]),
         "evolution": .array([]), "sig": .object(["alg": s("ed25519"), "kid": s("k"), "value": s("v")])]
    }

    func testPackCanonicalErrorIsReported() {
        XCTAssertNil(Actions.packShapeError(.object(packBody(licenceNotes: "n"))))
        XCTAssertEqual(Actions.packShapeError(.object(packBody(licenceNotes: lone))), "pack: canonicalize: lone surrogate in string", "line 266")
    }

    func testTwoEdgesToOneDefinitionKeepTheFirst() {
        let r1 = signedRecord(reason: "first")
        let r2 = signedRecord(reason: "second")
        XCTAssertTrue(Actions.verifyEvolutionRecord(r1, keys()))
        XCTAssertTrue(Actions.verifyEvolutionRecord(r2, keys()))
        let want = Actions.evolutionDiffDigest(r1)
        XCTAssertNotNil(want)
        XCTAssertNotEqual(want, Actions.evolutionDiffDigest(r2))
        let pin: JSONValue = .object(["pack": .object(["ns": s("ns"), "root": .string(d0)]), "on_new_action": s("deny"), "defs": .object(["a.b": .string(d0)])])
        let doc: JSONValue = .object(["verbs": .array([.object(["verb": s("a.b"), "def": .string(d1)])]), "pack": .object(["ns": s("ns"), "root": .string(d0)])])
        let got = Actions.decidePin(pin: pin, doc: doc, verb: "a.b", records: [r1, r2], keys: keys(), reapprovals: [], grantId: "g", issuer: "i")
        XCTAssertFalse(got.ok)
        XCTAssertEqual(got.code, "def_changed")
        XCTAssertEqual(got.needsReapproval, want, "line 182: a definition already reached is not revisited, so the first edge's diff is the one asked about")
    }

    func testPackDefCountBounds() {
        XCTAssertFalse(Actions.packDefsCountOk(0))
        XCTAssertTrue(Actions.packDefsCountOk(1))
        XCTAssertTrue(Actions.packDefsCountOk(2))
        XCTAssertTrue(Actions.packDefsCountOk(999_999))
        XCTAssertTrue(Actions.packDefsCountOk(1_000_000))
        XCTAssertFalse(Actions.packDefsCountOk(1_000_001))
        XCTAssertFalse(Actions.packDefsCountOk(-1))
    }
}
