import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Heavy-fixture kill tests (heavy-brief item 5) for IntentWB.swift: the three W-B checks hand their products to the composed
/// result (`singleSource`, `prov`, `cls`), and a classifier content outside the strict profile has its own refusal text.
final class IntentWBS2HVKillTests: XCTestCase {
    typealias T = IntentWBKillTests
    typealias F = V2F

    func testComposedResultCarriesTheSingleSourceWorlds() {
        let fs = T.facts([.int(5)])
        let session: JSONValue = .object(["facts": T.refs(fs)])
        let policy: JSONValue = .object(["world": .object(["worlds": .array([T.world(min: 1, faulty: 0)])])])
        let r = IntentWB.decide(now: F.NOW, aud: F.AUD, session: F.SESSION, action: T.ACTION, intentSession: session,
                                artifacts: .object(["facts": .array(fs)]), policy: policy)
        XCTAssertEqual(r.outcome, "admit", r.reason ?? "")
        XCTAssertEqual(r.checks.map { "\($0.0):\($0.1)" }, ["facts:pass"])
        XCTAssertEqual(r.world?["fare"], .int(5))
        XCTAssertEqual(r.singleSource, ["fare"], "line 758")
    }

    func testComposedResultCarriesTheProvenanceEnvironment() {
        let session: JSONValue = .object(["prov": .object([:])])
        let provPolicy: JSONValue = .object(["params": .object([:])])
        let r = IntentWB.decide(now: F.NOW, aud: F.AUD, session: F.SESSION, action: T.ACTION, intentSession: session, artifacts: nil,
                                policy: .object(["provenance": provPolicy]))
        XCTAssertEqual(r.outcome, "admit")
        let direct = IntentWB.decideProvenance(aud: F.AUD, session: F.SESSION, params: T.ACTION.get("params"), prov: .object([:]), committedLabels: nil,
                                               labels: nil, policy: provPolicy)
        XCTAssertNotNil(r.prov, "line 766")
        XCTAssertEqual(r.prov, direct.env)
    }

    func testComposedResultCarriesTheClassifierLabels() {
        let vs = [T.verdict(T.j1, "apologetic"), T.verdict(T.j2, "apologetic")]
        let committed: JSONValue = .array(vs.map { .string(F.ref(IntentWB.CLASSIFIER_REF_DOMAIN, "c", $0)) })
        let session: JSONValue = .object(["classes": committed])
        let action: JSONValue = .object(["verb": .string("air.book"), "resource": .string("skyair.example/bookings"), "params": .object(["body": T.BODY])])
        let r = IntentWB.decide(now: F.NOW, aud: F.AUD, session: F.SESSION, action: action, intentSession: session,
                                artifacts: .object(["verdicts": .array(vs)]), policy: T.clsPolicy())
        XCTAssertEqual(r.outcome, "admit", r.reason ?? "")
        XCTAssertEqual(r.checks.map { "\($0.0):\($0.1)" }, ["classes:pass"])
        XCTAssertEqual(r.cls, ["tone": .string("apologetic")], "line 775")
    }

    func testAClassifierContentOutsideTheStrictProfileHasItsOwnReason() {
        let vs = [T.verdict(T.j1, "apologetic"), T.verdict(T.j2, "apologetic")]
        let committed: JSONValue = .array(vs.map { .string(F.ref(IntentWB.CLASSIFIER_REF_DOMAIN, "c", $0)) })
        let r = IntentWB.decideClassifiers(session: F.SESSION, params: .object(["body": .double(-0.0)]), committed: committed, verdicts: .array(vs), policy: T.clsPolicy())
        XCTAssertFalse(r.ok)
        XCTAssertTrue(r.reason.hasPrefix("classes: evaluation error (fail closed): "), r.reason)
        XCTAssertEqual(r.reason, "classes: evaluation error (fail closed): " + (IV.strictCanonError(.double(-0.0)) ?? "?"), "line 700")
        XCTAssertNotEqual(r.reason, "classes: evaluation error (fail closed): content is not strictly canonical")
    }
}
