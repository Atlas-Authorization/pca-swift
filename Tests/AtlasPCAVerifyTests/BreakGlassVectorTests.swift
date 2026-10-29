import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED break-glass vectors (packages/pca/conformance/break-glass-vectors.json). A missing file fails.
final class BreakGlassVectorTests: XCTestCase {
    func testBreakGlassVectors() throws {
        let doc = try ConformanceTests.load("break-glass-vectors.json")
        let grants = doc.get("grants")?.asArray ?? []
        let reviews = doc.get("reviews")?.asArray ?? []
        let authority = doc.get("authority")?.asString ?? ""
        let reviewer = doc.get("reviewer")?.asString ?? ""
        let scenarios = doc.get("scenarios")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(scenarios.count, 10)
        var f: [String] = []
        for s in scenarios {
            let name = s.get("name")?.asString ?? "?"
            let extra = (s.get("extra_reviewers")?.asArray ?? []).compactMap { $0.asString }
            let reg = BreakGlass.Registry(policy: BreakGlass.Policy(authorities: [authority], reviewers: [reviewer] + extra))
            for (i, st) in (s.get("steps")?.asArray ?? []).enumerated() {
                let at = "\(name) step \(i)"
                let e = st.get("expect")
                switch st.get("op")?.asString ?? "" {
                case "accept", "review":
                    let got: BreakGlass.Result
                    if st.get("op")?.asString == "accept" {
                        got = reg.accept(grants[Int(st.get("grant")?.safeInt ?? 0)], now: st.get("now"))
                    } else {
                        got = reg.review(reviews[Int(st.get("review")?.safeInt ?? 0)], holder: st.get("holder"), now: st.get("now"))
                    }
                    var ok = got.ok == (e?.get("ok") == .bool(true))
                    if ok && got.ok { ok = got.replaced == (e?.get("replaced") == .bool(true)) }
                    if ok && !got.ok { ok = got.code == e?.get("code")?.asString }
                    if !ok { f.append("\(at): \(got)") }
                case "use":
                    let got = reg.use(id: st.get("id"), holder: st.get("holder"), actionDigest: st.get("action_digest"), now: st.get("now"), notified: st.get("notified"))
                    var ok = got.decision == e?.get("decision")?.asString && got.code == e?.get("code")?.asString && got.id == e?.get("id")?.asString
                    if ok && got.decision == "allow" {
                        ok = got.use == e?.get("use")?.safeInt && got.remaining == e?.get("remaining")?.safeInt && got.reviewDue == e?.get("review_due")?.safeInt
                    }
                    if !ok { f.append("\(at): use \(got)") }
                case "frozen":
                    let got = reg.frozen(holder: st.get("holder"), now: st.get("now"))
                    if got != (st.get("expect") == .bool(true)) { f.append("\(at): frozen \(got)") }
                default:
                    f.append("\(at): unknown op")
                }
            }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }
}
