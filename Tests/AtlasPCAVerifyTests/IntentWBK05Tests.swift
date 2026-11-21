import XCTest
@testable import AtlasPCAVerify

/// `isParamPath` (packages/pca/src/intent-artifacts.ts:163-167) and `decideParamProvenance` (packages/pca/src/param-provenance.ts): a nested
/// prov key is refused on the wire (only action.params.<name>), and a ref the registry vouches for keeps its own label.
final class IntentWBK05Tests: XCTestCase {
    private func decide(_ prov: JObject, registry: JObject = [:]) -> IntentWB.ProvenanceDecision {
        IntentWB.decideProvenance(aud: V2F.AUD, session: V2F.SESSION, params: .object(["a": .object(["b": .int(1)])]), prov: .object(prov), committedLabels: .array([]), labels: .array([]),
                                  policy: .object(["params": .object([:]), "registry": .object(registry)]))
    }

    func testParamPathSegments() {
        XCTAssertFalse(IntentWB.isParamPath(.string("action.params.")))
        XCTAssertTrue(IntentWB.isParamPath(.string("action.params.a")))
        XCTAssertTrue(IntentWB.isParamPath(.string("action.params.a.b.c.d.e.f.g.h")))
        XCTAssertFalse(IntentWB.isParamPath(.string("action.params.a.b.c.d.e.f.g.h.i")))
    }

    func testANestedProvKeyIsRefusedOnTheWire() {
        let d = decide(["action.params.a": .array([.string("x")]), "action.params.a.b": .array([.string("x")])])
        XCTAssertEqual(d.outcome, "deny")
        XCTAssertEqual(d.reason, "provenance: 'prov' key 'action.params.a.b' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)")
    }

    func testLabelIsTheJoinOfTheRefs() {
        let reg: JObject = ["r0": .string("trusted"), "r2": .string("tool")]
        let trusted = decide(["action.params.a": .array([.string("r0")])], registry: reg)
        XCTAssertEqual(trusted.outcome, "pass", trusted.reason)
        XCTAssertEqual(trusted.labels, ["action.params.a": "trusted"])
        XCTAssertEqual(decide(["action.params.a": .array([.string("r0"), .string("r2")])], registry: reg).labels, ["action.params.a": "tool"])
        XCTAssertEqual(decide(["action.params.a": .array([.string("unvouched")])], registry: reg).labels, ["action.params.a": "agent"])
    }
}
