import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Approval.swift pinned to the reference packages/pca-actions/src/approval-render.ts (:38 valueOk, :77 unreviewed) and
/// approval-profiles.ts (:111 batch total).
final class ApprovalK05KillTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }
    private lazy var d32 = Base64URLStrict.encode([UInt8](repeating: 3, count: 32))

    private func def(type: String) -> JObject {
        ["v": .int(1), "kind": s("pca-action-def"), "verb": s("a.b"), "title": s("t"), "effects": .array([s("read")]),
         "resource": .object(["type": s("t"), "id": s("*"), "scope": s("one")]), "params": .object(["p": .object(["type": s(type)])])]
    }

    func testAnUnknownParameterTypeIsABadValue() {
        XCTAssertThrowsError(try Approval.render(def: def(type: "zzz"), params: .object(["p": s("x")]))) {
            XCTAssertEqual(($0 as? ActionKitError)?.code, "render_bad_value")
        }
    }

    func testARenderIsUnreviewedUnlessToldOtherwise() throws {
        let params: JSONValue = .object(["p": s("x")])
        XCTAssertEqual(try Approval.render(def: def(type: "string"), params: params).get("unreviewed"), JSONValue.bool(true))
        XCTAssertEqual(try Approval.render(def: def(type: "string"), params: params, confirmed: true).get("unreviewed"), JSONValue.bool(false))
    }

    private func payment(_ minor: Int64) -> JSONValue {
        let fields: [JSONValue] = [
            .object(["id": s("amt"), "class": s("money.amount"), "value": .int(minor), "unit": .object(["kind": s("money"), "ccy": s("USD"), "exp": .int(2)])]),
            .object(["id": s("to"), "class": s("party.payee"), "value": s("bob")]),
        ]
        return .object(["action_digest": s(d32),
                        "render": .object(["v": .int(1), "kind": s("pca-approval-render"), "verb": s("a.b"), "def_digest": s(d32), "unreviewed": .bool(false), "fields": .array(fields)])])
    }

    /// The sum passes 2^53-1 without overflowing an Int64: refused for the total, not later for the digest.
    func testABatchTotalAboveTheSafeRange() {
        XCTAssertNoThrow(try Approval.batch([payment(Canonical.MAX_SAFE)]))
        XCTAssertThrowsError(try Approval.batch([payment(Canonical.MAX_SAFE), payment(1)])) {
            XCTAssertEqual(($0 as? ActionKitError)?.code, "psd2_unlinkable")
            XCTAssertEqual(($0 as? ActionKitError)?.message, "the batch total exceeds the safe integer range")
        }
    }
}
