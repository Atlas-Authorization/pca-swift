import XCTest
import Foundation
@testable import AtlasPCAVerify

/// F1: the core `plan_root_authorized` check, over packages/pca/conformance/plan-root-vectors.json (reference: pcactn.ts).
final class A0F1PlanRootVectorsTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testPlanRootVectors() throws {
        let doc = try ConformanceTests.load("plan-root-vectors.json")
        let core = try ConformanceTests.load("vectors.json")
        let cases = try XCTUnwrap(doc.get("plan_root_authorized")?.asArray)
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let vname = c.get("vector")?.asString ?? ""
            let v = try XCTUnwrap(core.get("vectors")?.asArray?.first { $0.get("name")?.asString == vname }, "vector \(vname)")
            let pcactn = try XCTUnwrap(v.get("pcactn"))
            let root = try XCTUnwrap(pcactn.get("plan")?.get("root")?.asString)
            let now = try XCTUnwrap(v.get("context")?.get("now")?.safeInt)
            let aud = try XCTUnwrap(v.get("context")?.get("aud")?.asString)
            let opts = c.get("options")?.asObject ?? [:]
            let roots: [String]? = opts[JKey("authorizedPlanRoots")]?.asArray?.compactMap { $0.asString == "$plan_root" ? root : $0.asString }
            var skip = false
            if case .bool(true)? = opts[JKey("insecureSkipPlanRootCheck")] { skip = true }
            let verdict: PCA.Verdict = S2Deadline.within(20, "verify \(name)") {
                PCA.verify(pcactn: pcactn, grant: v.get("grant") ?? .null, now: now, audience: aud, authorizedPlanRoots: roots, insecureSkipPlanRootCheck: skip)
            } ?? PCA.Verdict(allow: false, checks: [:], reason: "timeout")
            let expect = try XCTUnwrap(c.get("expect"), name)
            XCTAssertEqual(verdict.allow, expect.get("allow") == .bool(true), "\(name): \(verdict.reasons)")
            switch expect.get("check")?.asString {
            case "pass": XCTAssertEqual(verdict.checks["plan_root_authorized"], true, name)
            case "fail": XCTAssertEqual(verdict.checks["plan_root_authorized"], false, name)
            case "not-enforced": XCTAssertNil(verdict.checks["plan_root_authorized"], "\(name): a skipped check is not reported")
            default: XCTFail("\(name): unknown check status")
            }
            if let want = expect.get("reason")?.asString { XCTAssertEqual(verdict.reason, want, name) }
        }
    }
}
