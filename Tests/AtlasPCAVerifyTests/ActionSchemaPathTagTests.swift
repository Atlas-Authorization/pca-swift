import XCTest
@testable import AtlasPCAVerify

/// v2 parameter paths and tags, pinned to the reference action-schema.ts: PARAM_PATH_RE_V2
/// `^action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$` and the tags rule (an array of at most
/// SCHEMA_V2_TAGS.length distinct known tags).
final class ActionSchemaPathTagTests: XCTestCase {
    func testParamPathV2() {
        let g64 = String(repeating: "a", count: 64)
        for ok in ["action.params.a", "action.params.a.b", "action.params.a.b.c", "action.params.\(g64)", "action.params.0", "action.params.9",
                   "action.params.A", "action.params.Z", "action.params.z", "action.params._", "action.params.09AZaz_.Zz.x9"] {
            XCTAssertTrue(ActionSchema.isParamPathV2(ok), ok)
        }
        for bad in ["", "action.params.", "action.params", "params.a", "xaction.params.a", "Action.params.a", "action.params.a.b.c.d",
                    "action.params.\(g64)a", "action.params.a..b", "action.params.a.", "action.params.a-b", "action.params./",
                    "action.params.:", "action.params.@", "action.params.[", "action.params.`", "action.params.{", "action.params.a.@",
                    "action.params.a.b.c.d.e"] {
            XCTAssertFalse(ActionSchema.isParamPathV2(bad), bad)
        }
    }

    private func tags(_ t: [String]) -> String? {
        ActionSchema.paramDeclError("action.params.x", .object(["type": .string("string"), "semantic": .string("x"), "sensitivity": .string("free"),
                                                              "tags": .array(t.map { .string($0) })]), nil, v2: true)
    }

    func testEveryKnownTagAtOnceIsAccepted() {
        XCTAssertNil(tags(ActionSchema.V2_TAGS))
        XCTAssertNil(tags(["pii"]))
        XCTAssertNil(tags([]))
        let e = "action.params.x: tags must be distinct known tags"
        XCTAssertEqual(tags(ActionSchema.V2_TAGS + ["pii"]), e)
        XCTAssertEqual(tags(["pii", "pii"]), e)
        XCTAssertEqual(tags(["PII"]), e)
    }
}
