import XCTest
import Foundation
@testable import AtlasPCAVerify

final class A0DeadlineWorkflowTests: XCTestCase {
    typealias J = JSONValue
    func b32(_ n: UInt8) -> String { Base64URLStrict.encode([UInt8](repeating: n, count: 32)) }
    func step(_ id: String, deps: [String]) -> JSONValue {
        J.object(["id": J.string(id), "verb": J.string("v"), "resource": J.string("r"), "params_digest": J.null, "deps": J.array(deps.map { J.string($0) }),
                  "sink": J.null, "deny_labels": J.array([]), "escalate_labels": J.array([]), "fresh_ms": J.null, "cost": J.object([:])])
    }

    /// Workflow.swift 182 and 193: a finished step is memoised. 64 steps each depending on the two before it: linear with the memo,
    /// about 2^40 visits without it (a mutated memo marker never matches).
    func testAncestorsAreMemoised() throws {
        let names = (0..<64).map { "s" + ($0 < 10 ? "0" : "") + String($0) }
        var steps: [JSONValue] = []
        for i in 0..<64 {
            var deps: [String] = []
            if i >= 2 { deps.append(names[i - 2]) }
            if i >= 1 { deps.append(names[i - 1]) }
            steps.append(step(names[i], deps: deps))
        }
        let body = J.object([
            "v": J.int(1), "id": J.string("wf1"), "principal": J.string(b32(1)), "goal_digest": J.null, "plan_root": J.null, "issued_at": J.int(100),
            "expires_at": J.int(1000), "steps": J.array(steps), "edges": J.array([]),
            "budget": J.object(["max_steps": J.int(10), "caps": J.object([:])]),
        ])
        let w = try XCTUnwrap(WfBody.parse(body))
        let counts: [Int]? = S2Deadline.within(10, "ancestors") { [w.ancestors()?[names[63]]?.count ?? -1, w.ancestors()?[names[1]]?.count ?? -1] }
        XCTAssertEqual(counts, [63, 1], "lines 182, 193")
    }
}
