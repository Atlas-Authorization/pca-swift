import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// A signed, zero-slot policy template whose instantiation is exactly the AZ envelope's policy (`[ANY]`, no caveats), and the registry that holds it.
enum LinkedTemplateFixture {
    static let def: JSONValue = .object([
        "v": .int(1), "kind": .string("pca-policy-template"), "id": .string("t1"), "version": .string("1"), "slots": .object([:]),
        "body": .object(["predicates": .array([AZ.ANY]), "caveats": .array([])]),
    ])

    /// `(registry, template_ref, version digest)`.
    static func make() throws -> (registry: JSONValue, ref: JSONValue, digest: String) {
        let k = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        let pub = Base64URLStrict.encode(Array(k.publicKey.rawRepresentation))
        let digest = try XCTUnwrap(PCA.templateDigest(def))
        let msg = Array("atlas-pca/policy-template/v1\u{0}".utf8) + Canonical.sha256(Array(digest.utf8))
        let sig = Base64URLStrict.encode(Array(try k.signature(for: Data(msg))))
        let signed: JSONValue = .object(["def": def, "signer": .string(pub), "sig": .string(sig)])
        let reg: JSONValue = .object(["templates": .object([JKey(digest): signed]), "trusted": .array([.string(pub)])])
        let ref: JSONValue = .object(["template_id": .string("t1"), "version_digest": .string(digest), "slots": .object([:])])
        return (reg, ref, digest)
    }

    /// The registry that holds nothing.
    static let empty: JSONValue = .object(["templates": .object([:]), "trusted": .array([])])

    /// The AZ envelope that carries `ref`.
    static func envelope(ref: JSONValue) -> JSONValue {
        var o = AZ.envelope().asObject ?? [:]
        o["template_ref"] = ref
        return .object(o)
    }
}

final class AuthorizeGatesSurvivorKillTests: XCTestCase {
    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }

    // ---- verifyLinkedPolicy ----

    func testALinkedPolicyThatIsTheInstantiationVerifies() throws {
        let t = try LinkedTemplateFixture.make()
        let ok = PCA.verifyLinkedPolicy(LinkedTemplateFixture.envelope(ref: t.ref), registry: t.registry)
        XCTAssertTrue(ok.ok, ok.reason ?? "")
        XCTAssertNil(ok.reason)
        XCTAssertEqual(ok.template, t.digest)
    }

    func testAPolicyThatDiffersFromTheInstantiationIsRefused() throws {
        let t = try LinkedTemplateFixture.make()
        var o = LinkedTemplateFixture.envelope(ref: t.ref).asObject ?? [:]
        o["predicates"] = .array([.object(["verb": .string("payments.refund"), "resource": .string("payments/*")])])
        let r = PCA.verifyLinkedPolicy(.object(o), registry: t.registry)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "grant policy differs from the linked template instantiation")
        XCTAssertNil(r.template)
        var c = LinkedTemplateFixture.envelope(ref: t.ref).asObject ?? [:]
        c["caveats"] = .array([.object(["type": .string("x")])])
        XCTAssertEqual(PCA.verifyLinkedPolicy(.object(c), registry: t.registry).reason, "grant policy differs from the linked template instantiation")
    }

    func testAPolicyOutsideTheStrictProfileFailsClosed() throws {
        let t = try LinkedTemplateFixture.make()
        var o = LinkedTemplateFixture.envelope(ref: t.ref).asObject ?? [:]
        o["predicates"] = .array([.object(["limit": .double(.infinity)])])
        let r = PCA.verifyLinkedPolicy(.object(o), registry: t.registry)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "link verification error (fail closed)")
        XCTAssertNil(r.template)
    }

    func testAnUnresolvableReferenceNamesTheRegistrysReason() throws {
        let t = try LinkedTemplateFixture.make()
        let r = PCA.verifyLinkedPolicy(LinkedTemplateFixture.envelope(ref: t.ref), registry: LinkedTemplateFixture.empty)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "template version is not in the registry")
        XCTAssertNil(r.template)
    }

    // ---- forbid: the grant handed to the clause source ----

    func testTheClauseSourceReceivesTheResolvedGrant() throws {
        final class Seen: @unchecked Sendable { var grant: JSONValue?; var calls = 0 }
        let seen = Seen()
        let gate = PCA.ForbidGate(clauses: { _, g in seen.grant = g; seen.calls += 1; return .array([]) })
        let op = PCA.Operation(verb: "v", resource: "r", params: .object([:]))
        let pcactn: JSONValue = .object(["grant_ref": .string("g1")])
        _ = try? PCA.forbidGate(pcactn, gate, op, { ref in ref == "g1" ? .string("the-grant") : nil }, nil)
        XCTAssertEqual(seen.calls, 1)
        XCTAssertEqual(seen.grant, .string("the-grant"))
        struct Boom: Error {}
        seen.grant = .null
        _ = try? PCA.forbidGate(pcactn, gate, op, { _ in throw Boom() }, nil)
        XCTAssertNil(seen.grant, "a grant that cannot be read is handed over as none")
        seen.grant = .null
        _ = try? PCA.forbidGate(.object([:]), gate, op, { _ in .string("never") }, nil)
        XCTAssertNil(seen.grant, "no grant_ref: no grant is looked up")
    }

    // ---- the freshness anchor ----

    private func anchor(_ fr: String?, _ g: PCA.FreshnessGate, now: Int64 = 0) -> String? {
        var p: JObject = [:]
        if let f = fr { p["freshness"] = J(f) }
        return PCA.freshnessAnchorError(p, g, now)
    }

    func testTheClockSkewDefaultsToNoneAndNeverGoesNegative() {
        let future = #"{"beacon_ref":"r","epoch":1001}"#
        XCTAssertEqual(anchor(future, PCA.FreshnessGate(maxAgeMs: 100, epochMs: 1, now: 1000)), "freshness anchor is in the future")
        XCTAssertEqual(anchor(future, PCA.FreshnessGate(maxAgeMs: 100, epochMs: 1, now: 1000, clockSkewMs: 0)), "freshness anchor is in the future")
        XCTAssertEqual(anchor(future, PCA.FreshnessGate(maxAgeMs: 100, epochMs: 1, now: 1000, clockSkewMs: -50)), "freshness anchor is in the future")
        XCTAssertEqual(anchor(future, PCA.FreshnessGate(maxAgeMs: 100, epochMs: 1, now: 1000, clockSkewMs: .nan)), "freshness anchor is in the future")
        XCTAssertNil(anchor(future, PCA.FreshnessGate(maxAgeMs: 100, epochMs: 1, now: 1000, clockSkewMs: 1)))
    }

    func testTheGateBoundsAreInclusiveWhereTheyShouldBe() {
        let at = #"{"beacon_ref":"r","epoch":1000}"#
        XCTAssertNil(anchor(at, PCA.FreshnessGate(maxAgeMs: 0, epochMs: 1, now: 1000)), "a zero maximum age is valid")
        XCTAssertNil(anchor(at, PCA.FreshnessGate(maxAgeMs: 1, epochMs: 1, now: 1000)), "an epoch length of one millisecond is valid")
        XCTAssertEqual(anchor(at, PCA.FreshnessGate(maxAgeMs: -1, epochMs: 1, now: 1000)),
                       "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)")
        XCTAssertEqual(anchor(at, PCA.FreshnessGate(maxAgeMs: 1, epochMs: 0, now: 1000)),
                       "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)")
        XCTAssertEqual(anchor(at, PCA.FreshnessGate(maxAgeMs: .infinity, epochMs: 1, now: 1000)),
                       "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)")
    }

    func testEpochOneIsAValidAnchor() {
        XCTAssertNil(anchor(#"{"beacon_ref":"r","epoch":1}"#, PCA.FreshnessGate(maxAgeMs: 10, epochMs: 60_000, now: 60_000)))
        XCTAssertEqual(anchor(#"{"beacon_ref":"r","epoch":0}"#, PCA.FreshnessGate(maxAgeMs: 10, epochMs: 60_000, now: 60_000)),
                       "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
    }
}
