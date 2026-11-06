import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Limits, defaults and exact refusals of break-glass grants, against packages/pca-grants/src/breakglass.ts.
final class BreakGlassK05Tests: XCTestCase {
    private static let authority = V2F.key("bg-authority"), reviewer = V2F.key("bg-reviewer")
    private static let HOLDER = "holder-1"
    private static let T: Int64 = 1_000_000

    private func text(_ n: Int) -> JSONValue { .string(String(repeating: "a", count: n)) }

    private func body() -> JObject {
        ["v": .int(1), "id": .string("g1"), "holder": .string(Self.HOLDER), "grant_ref": .string("ref"), "reason_digest": .string("rd"), "max_uses": .int(2),
         "issued_at": .int(Self.T), "expires_at": .int(Self.T + 1000), "review_within": .int(5000), "notify_to": .string("n"), "authority": .string(V2F.pub(Self.authority))]
    }

    private func reviewBody(at: Int64) -> JObject {
        ["v": .int(1), "id": .string("g1"), "outcome": .string("justified"), "notes_digest": .string("nd"), "at": .int(at), "reviewer": .string(V2F.pub(Self.reviewer))]
    }

    private func signedGrant() -> JSONValue {
        var b = body()
        b["sig"] = .string(V2F.sign(Self.authority, IV.message(BreakGlass.DOMAIN, .object(b))!))
        return .object(b)
    }

    private func signedReview(at: Int64) -> JSONValue {
        var r = reviewBody(at: at)
        r["sig"] = .string(V2F.sign(Self.reviewer, IV.message(BreakGlass.REVIEW_DOMAIN, .object(r))!))
        return .object(r)
    }

    private func registry() -> BreakGlass.Registry {
        BreakGlass.Registry(policy: BreakGlass.Policy(authorities: [V2F.pub(Self.authority)], reviewers: [V2F.pub(Self.reviewer)]))
    }

    private func wellFormed(_ edit: (inout JObject) -> Void) -> Bool {
        var b = body()
        edit(&b)
        return BreakGlass.wellFormed(.object(b)) != nil
    }

    func testConstantsMatchTheReference() {
        XCTAssertEqual(BreakGlass.MAX_WINDOW_MS, 86_400_000)
        XCTAssertEqual(BreakGlass.MAX_USES, 16)
        XCTAssertEqual(BreakGlass.MAX_REVIEW_WITHIN_MS, 2_592_000_000)
    }

    func testAnUnreadableNumberIsZero() {
        XCTAssertEqual(BreakGlass.num([:], "x"), 0)
        XCTAssertEqual(BreakGlass.num(["x": .string("y")], "x"), 0)
        XCTAssertEqual(BreakGlass.num(["x": .int(7)], "x"), 7)
        // a record without a readable review clock freezes at the first use
        let e = BreakGlass.Entry(rec: [:], uses: [5], review: nil)
        XCTAssertTrue(BreakGlass.isFrozen(["g": e], 5))
        XCTAssertFalse(BreakGlass.isFrozen(["g": e], 4))
    }

    func testStringBoundsOfARecord() {
        for (k, n) in [("id", 128), ("holder", 128), ("grant_ref", 256), ("reason_digest", 128), ("notify_to", 256), ("authority", 128)] {
            XCTAssertTrue(wellFormed { $0[JKey(k)] = text(n) }, "\(k) at \(n)")
            XCTAssertFalse(wellFormed { $0[JKey(k)] = text(n + 1) }, "\(k) at \(n + 1)")
        }
    }

    func testBudgetWindowAndReviewBounds() {
        XCTAssertTrue(wellFormed { $0["max_uses"] = .int(1) })
        XCTAssertTrue(wellFormed { $0["max_uses"] = .int(16) })
        XCTAssertFalse(wellFormed { $0["max_uses"] = .int(0) })
        XCTAssertFalse(wellFormed { $0["max_uses"] = .int(17) })
        XCTAssertFalse(wellFormed { $0["expires_at"] = .int(Self.T) })
        XCTAssertTrue(wellFormed { $0["expires_at"] = .int(Self.T + 1) })
        XCTAssertTrue(wellFormed { $0["expires_at"] = .int(Self.T + 86_400_000) })
        XCTAssertFalse(wellFormed { $0["expires_at"] = .int(Self.T + 86_400_001) })
        XCTAssertTrue(wellFormed { $0["review_within"] = .int(1) })
        XCTAssertFalse(wellFormed { $0["review_within"] = .int(0) })
        XCTAssertTrue(wellFormed { $0["review_within"] = .int(2_592_000_000) })
        XCTAssertFalse(wellFormed { $0["review_within"] = .int(2_592_000_001) })
    }

    func testStringBoundsOfAReview() {
        for k in ["id", "notes_digest", "reviewer"] {
            var ok = reviewBody(at: 1)
            ok[JKey(k)] = text(128)
            XCTAssertNotNil(BreakGlass.reviewWellFormed(.object(ok)), k)
            ok[JKey(k)] = text(129)
            XCTAssertNil(BreakGlass.reviewWellFormed(.object(ok)), k)
        }
    }

    func testAMalformedRecordOrReviewDoesNotVerify() {
        XCTAssertFalse(BreakGlass.verifyBreakGlass(nil))
        XCTAssertFalse(BreakGlass.verifyBreakGlass(.object([:])))
        XCTAssertFalse(BreakGlass.verifyBreakGlassReview(nil))
        XCTAssertFalse(BreakGlass.verifyBreakGlassReview(.object([:])))
        XCTAssertTrue(BreakGlass.verifyBreakGlass(signedGrant()))
        XCTAssertTrue(BreakGlass.verifyBreakGlassReview(signedReview(at: 1)))
    }

    func testRefusalsCarryNoAllowFields() {
        let reg = registry()
        let a = reg.accept(nil, now: .int(1))
        XCTAssertEqual(a.code, "bad_record")
        XCTAssertFalse(a.ok)
        XCTAssertFalse(a.replaced)
        let d = reg.use(id: nil, holder: nil, actionDigest: nil, now: nil, notified: nil)
        XCTAssertEqual(d.decision, "deny")
        XCTAssertEqual(d.code, "bad_input")
        XCTAssertEqual(d.use, 0)
        XCTAssertEqual(d.remaining, 0)
        XCTAssertEqual(d.reviewDue, 0)
    }

    func testUseInputBounds() {
        let reg = registry()
        func code(_ id: JSONValue, _ holder: JSONValue, _ digest: JSONValue) -> String? {
            reg.use(id: id, holder: holder, actionDigest: digest, now: .int(Self.T), notified: .bool(true)).code
        }
        XCTAssertEqual(code(text(128), text(1), text(1)), "unknown_break_glass")
        XCTAssertEqual(code(text(129), text(1), text(1)), "bad_input")
        XCTAssertEqual(code(text(1), text(128), text(1)), "unknown_break_glass")
        XCTAssertEqual(code(text(1), text(129), text(1)), "bad_input")
        XCTAssertEqual(code(text(1), text(1), text(128)), "unknown_break_glass")
        XCTAssertEqual(code(text(1), text(1), text(129)), "bad_input")
    }

    func testReviewHolderBound() {
        let reg = registry()
        XCTAssertEqual(reg.review(signedReview(at: 1), holder: text(128), now: .int(2)).code, "unknown_break_glass")
        XCTAssertEqual(reg.review(signedReview(at: 1), holder: text(129), now: .int(2)).code, "bad_record")
    }

    func testAReviewMayBeDatedAtTheFirstUseNotBefore() {
        let reg = registry()
        XCTAssertEqual(reg.accept(signedGrant(), now: .int(Self.T)), BreakGlass.Result(ok: true, replaced: true))
        let first = Self.T + 10
        let used = reg.use(id: .string("g1"), holder: .string(Self.HOLDER), actionDigest: .string("d"), now: .int(first), notified: .bool(true))
        XCTAssertEqual(used.decision, "allow")
        XCTAssertEqual(reg.review(signedReview(at: first - 1), holder: .string(Self.HOLDER), now: .int(first)).code, "bad_time")
        XCTAssertEqual(reg.review(signedReview(at: first + 1), holder: .string(Self.HOLDER), now: .int(first)).code, "bad_time")
        XCTAssertEqual(reg.review(signedReview(at: first), holder: .string(Self.HOLDER), now: .int(first)), BreakGlass.Result(ok: true, replaced: true))
    }

    func testFrozenFailsClosedOnBadInput() {
        let reg = registry()
        XCTAssertTrue(reg.frozen(holder: nil, now: .int(1)))
        XCTAssertTrue(reg.frozen(holder: .string("h"), now: nil))
        XCTAssertTrue(reg.frozen(holder: text(129), now: .int(1)))
        XCTAssertFalse(reg.frozen(holder: text(128), now: .int(1)))
    }
}
