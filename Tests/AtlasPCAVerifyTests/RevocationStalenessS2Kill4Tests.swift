import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Revocation staleness (T9): policy validation and parsing, the epoch registry check, non-membership shape, and the
/// `authorize` freshness gate (packages/pca/src/revocation.ts).
final class S2G4RevocationKillTests: XCTestCase {
    typealias J = JSONValue

    func testWindowsMustBePositive() {
        let msg = "maxRevocationAgeMs must be a positive number of milliseconds"
        XCTAssertNil(RevocationStalenessPolicy(maxRevocationAgeMs: 1).validate())
        XCTAssertNil(RevocationStalenessPolicy(maxRevocationAgeMs: 0.5).validate())
        XCTAssertEqual(RevocationStalenessPolicy(maxRevocationAgeMs: 0).validate(), msg)
        XCTAssertEqual(RevocationStalenessPolicy(maxRevocationAgeMs: -1).validate(), msg)
        XCTAssertEqual(RevocationStalenessPolicy(maxRevocationAgeMs: Double.infinity).validate(), msg)
    }

    func testFromJSONReadsTheUnsignedRootFlag() {
        func flag(_ v: JSONValue?) -> Bool? {
            var o: JObject = [:]
            if let x = v { o["allowUnsignedRootForIrreversible"] = x }
            return RevocationStalenessPolicy.fromJSON(JSONValue.object(o))?.allowUnsignedRootForIrreversible
        }
        XCTAssertEqual(flag(J.bool(true)), true)
        XCTAssertEqual(flag(J.bool(false)), false)
        XCTAssertEqual(flag(nil), false)
        XCTAssertEqual(flag(J.string("true")), false)
    }

    func testEpochBodyDefaults() {
        let b = RevocationEpochBody(instanceId: "i", grantRef: "g", root: "r", issuedAt: 1, notAfter: 2)
        XCTAssertEqual(b.epoch, 0)
        XCTAssertEqual(b.setSize, 0)
    }

    func testANaNWindowKeepsTheCapNaN() {
        let p = RevocationStalenessPolicy(maxRevocationAgeMs: 1000, staleness: StalenessWindows(irreversible: Double.nan, costly: nil))
        XCTAssertTrue(PCA.revocationMaxAgeMs(p, class: "irreversible").isNaN, "a NaN class window stays NaN (fail closed)")
        let q = RevocationStalenessPolicy(maxRevocationAgeMs: Double.nan)
        XCTAssertTrue(PCA.revocationMaxAgeMs(q, class: "irreversible").isNaN)
        XCTAssertEqual(PCA.revocationMaxAgeMs(RevocationStalenessPolicy(maxRevocationAgeMs: 1000), class: "irreversible"), 1000)
    }

    // ---- signed epochs ----

    let seed = [UInt8](repeating: 9, count: 32)

    func epoch(_ n: Int64, issuedAt: Int64, root: String = "r") throws -> JSONValue {
        try XCTUnwrap(PCA.signRevocationEpoch(guardianSeed: seed, RevocationEpochBody(instanceId: "i", grantRef: "g1", epoch: n, setSize: 0, root: root,
                                                                                    issuedAt: issuedAt, notAfter: issuedAt + 100_000)))
    }

    func testARegisteredAlgIsAccepted() throws {
        let ep = try epoch(5, issuedAt: 1000)
        let g = try XCTUnwrap(ep.get("guardian")?.asString)
        let o = EpochCheckOptions(guardianPublic: g, now: 1500)
        XCTAssertTrue(PCA.checkRevocationEpoch(ep, o).ok)
        var named = try XCTUnwrap(ep.asObject)
        named["alg"] = J.string("ed25519")
        XCTAssertTrue(PCA.checkRevocationEpoch(JSONValue.object(named), o).ok, "an explicit registered alg")
        named["alg"] = J.string("rot13")
        XCTAssertFalse(PCA.checkRevocationEpoch(JSONValue.object(named), o).ok, "an unregistered alg")
        named["alg"] = J.int(1)
        XCTAssertFalse(PCA.checkRevocationEpoch(JSONValue.object(named), o).ok, "a non-string alg")
    }

    // ---- non-membership shape ----

    func testAMalformedNeighbourIsRefused() throws {
        let root = try XCTUnwrap(IntentRevocation.bindRoot(JSONValue.int(0), IntentRevocation.EMPTY_TREE))
        XCTAssertTrue(PCA.verifyNonMembership(root: root, proof: JSONValue.object(["size": J.int(0)]), id: "b"))
        XCTAssertTrue(PCA.verifyNonMembership(root: root, proof: JSONValue.object(["size": J.int(0), "lo": J.null, "hi": J.null]), id: "b"), "null neighbours are absent")
        XCTAssertFalse(PCA.verifyNonMembership(root: root, proof: JSONValue.object(["size": J.int(0), "lo": J.string("x")]), id: "b"), "a string neighbour")
        XCTAssertFalse(PCA.verifyNonMembership(root: root, proof: JSONValue.object(["size": J.int(0), "hi": J.int(1)]), id: "b"), "a number neighbour")
        XCTAssertFalse(PCA.verifyNonMembership(root: root, proof: JSONValue.object(["size": J.int(0), "lo": J.object(["id": J.string("a")])]), id: "b"), "no proof")
    }

    // ---- the freshness gate of authorize ----

    let now: Int64 = 1_000_000

    func pcactn(_ cls: String, freshnessEpoch: Int64? = nil) -> JObject {
        var p: JObject = ["grant_ref": J.string("g1"), "action": J.object(["reversibility_class": J.string(cls)])]
        if let e = freshnessEpoch { p["freshness"] = J.object(["epoch": J.int(e)]) }
        return p
    }

    func fresh(_ policy: RevocationStalenessPolicy, guardian: String? = nil, _ p: JObject, _ st: RevocationState?) -> String? {
        let input = PCA.AuthorizeInput(revocationStaleness: policy, guardianPublic: guardian, riskSource: PCA.insecureCalmRisk)
        return PCA.revocationFreshness(input, PCA.AuthorizeContext(), p, st, now)
    }

    func testThePCActnEpochMustNotPredateTheRevocationEpoch() throws {
        let ep = try epoch(5, issuedAt: now - 10)
        let g = try XCTUnwrap(ep.get("guardian")?.asString)
        let pol = RevocationStalenessPolicy(maxRevocationAgeMs: 100_000)
        XCTAssertEqual(fresh(pol, guardian: g, pcactn("reversible", freshnessEpoch: 3), RevocationState(epoch: ep)),
                       "PCActn freshness.epoch 3 predates the revocation epoch 5")
        XCTAssertNil(fresh(pol, guardian: g, pcactn("reversible", freshnessEpoch: 5), RevocationState(epoch: ep)))
        XCTAssertNil(fresh(pol, guardian: g, pcactn("reversible"), RevocationState(epoch: ep)), "no freshness.epoch: nothing to compare")
    }

    func testTheLastAcceptedEpochIsPassedToTheGate() throws {
        let ep = try epoch(5, issuedAt: now - 10)
        let g = try XCTUnwrap(ep.get("guardian")?.asString)
        let pol = RevocationStalenessPolicy(maxRevocationAgeMs: 100_000)
        XCTAssertEqual(fresh(pol, guardian: g, pcactn("reversible"), RevocationState(epoch: ep, lastAcceptedEpoch: 7)),
                       "revocation epoch 5 is older than the last accepted 7 (rollback)")
        XCTAssertNil(fresh(pol, guardian: g, pcactn("reversible"), RevocationState(epoch: ep, lastAcceptedEpoch: 5)))
    }

    func testTheStateRootAndItsIssueTimeReachTheGate() throws {
        let pol = RevocationStalenessPolicy(maxRevocationAgeMs: 100_000)
        XCTAssertNil(fresh(pol, pcactn("reversible"), RevocationState(root: "abc", rootIssuedAt: Double(now) - 10)), "a fresh unsigned root")
        let ep = try epoch(5, issuedAt: now - 10, root: "signed-root")
        let g = try XCTUnwrap(ep.get("guardian")?.asString)
        XCTAssertEqual(fresh(pol, guardian: g, pcactn("reversible"), RevocationState(epoch: ep, root: "other")), "revocation root does not match the signed epoch")
        XCTAssertNil(fresh(pol, guardian: g, pcactn("reversible"), RevocationState(epoch: ep, root: "signed-root")))
    }

    func testNoStateRefusesWithTheClassSpecificReason() {
        let pol = RevocationStalenessPolicy(maxRevocationAgeMs: 100_000)
        XCTAssertEqual(fresh(pol, pcactn("reversible"), nil), "no signed revocation epoch")
        XCTAssertEqual(fresh(pol, pcactn("irreversible"), nil), "no verifiable (guardian-signed) revocation state for an irreversible action")
        let lax = RevocationStalenessPolicy(maxRevocationAgeMs: 100_000, allowUnsignedRootForIrreversible: true)
        XCTAssertEqual(fresh(lax, pcactn("irreversible"), nil), "no signed revocation epoch")
        XCTAssertEqual(fresh(lax, pcactn("reversible"), nil), "no signed revocation epoch")
    }
}
