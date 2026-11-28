import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The networked agent client (pca-agent createAgent): configuration refusals, the plan echo check, the step-up poll and the fail-closed answer handling.
final class AgentClientTests: XCTestCase {
    typealias C = PCAAgentClient

    func client(_ f: @escaping C.Fetch, signer: PCASuiteKey? = nil, now: @escaping () -> Int64 = { 1_800_000_000_000 }) throws -> C {
        try C(grant: .object(["id": .string("g1")]), signer: signer, rsBaseUrl: "https://rs.example/", audience: "ins_1", now: now, fetch: f)
    }

    static let node: JObject = ["id": .string("n1"), "verb": .string("pay"), "resource": .string("r/1"), "params_digest": .string(Merkle.paramsDigest(nil))]

    func testConfigurationRefusals() {
        let f: C.Fetch = { _, _, _, _ in C.FetchResponse(status: 200, json: nil) }
        XCTAssertThrowsError(try C(grant: .null, rsBaseUrl: "https://x", audience: "", fetch: f)) { XCTAssertEqual(($0 as? PCAAgentError)?.code, "build_failed") }
        XCTAssertThrowsError(try C(grant: .null, rsBaseUrl: "ftp://x", audience: "a", fetch: f)) { XCTAssertEqual(($0 as? PCAAgentError)?.code, "build_failed") }
        XCTAssertThrowsError(try C(grant: .null, rsBaseUrl: "not a url", audience: "a", fetch: f))
    }

    func testPlanRootMustBeEchoed() throws {
        let local = try PCAIssue.commitPlan([Self.node]).root
        let good = try client { _, url, _, _ in
            XCTAssertEqual(url, "https://rs.example/v1/pca/plans")
            return C.FetchResponse(status: 200, json: .object(["plan_root": .string(local)]))
        }
        XCTAssertEqual(try good.commitPlan([Self.node]), local)
        XCTAssertEqual(good.planRoot, local)
        for json in [JSONValue.object([:]), .object(["plan_root": .string("other")])] {
            let bad = try client { _, _, _, _ in C.FetchResponse(status: 200, json: json) }
            XCTAssertThrowsError(try bad.commitPlan([Self.node])) { XCTAssertEqual(($0 as? PCAAgentError)?.code, "bad_response") }
        }
        let down = try client { _, _, _, _ in C.FetchResponse(status: 500, json: nil) }
        XCTAssertThrowsError(try down.commitPlan([Self.node]))
    }

    func testActRefusalsBeforeAnyRequest() throws {
        var calls = 0
        let c = try client { _, _, _, _ in calls += 1; return C.FetchResponse(status: 200, json: nil) }
        guard case let .error(e) = c.act("n1") else { return XCTFail("no plan must refuse") }
        XCTAssertEqual(e.code, "no_plan")
        XCTAssertEqual(calls, 0)
    }

    func testStepUpPollingIsFailClosed() throws {
        var answers: [C.FetchResponse] = [
            C.FetchResponse(status: 200, json: .object(["status": .string("pending")])),
            C.FetchResponse(status: 200, json: .object(["status": .string("approved"), "note": .string("ok")])),
        ]
        var t: Int64 = 1_800_000_000_000
        let c = try client({ _, url, _, _ in
            XCTAssertTrue(url.contains("/v1/pca/stepups/su%201"))
            return answers.removeFirst()
        }, now: { t })
        let out = try c.awaitStepUp("su 1", pollMs: 10, timeoutMs: 60_000, sleep: { t += $0 })
        guard case let .approved(j) = out else { return XCTFail("\(out)") }
        XCTAssertEqual(j.get("note")?.asString, "ok")
        // a non-2xx answer that says approved is not an approval, and a final 4xx stops the poll
        let notFound = try client({ _, _, _, _ in C.FetchResponse(status: 404, json: .object(["status": .string("approved")])) })
        guard case .denied = try notFound.awaitStepUp("x", pollMs: 1, timeoutMs: 5) else { return XCTFail("a 404 must deny") }
        // a deadline that cannot fit another poll times out
        let slow = try client({ _, _, _, _ in C.FetchResponse(status: 200, json: .object(["status": .string("pending")])) }, now: { 1 })
        XCTAssertEqual(try slow.awaitStepUp("x", pollMs: 10, timeoutMs: 5, sleep: { _ in }), .timeout)
    }
}
