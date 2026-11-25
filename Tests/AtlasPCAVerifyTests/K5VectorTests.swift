import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED K5 vectors (packages/pca/conformance/workflow-vectors.json and readside-vectors.json). A missing file FAILS (load throws).
final class K5VectorTests: XCTestCase {
    private func now(_ v: JSONValue?) -> Int64 { if case let .int(i)? = v { return i }; return -1 }

    func testWorkflowVectors() throws {
        let W = try ConformanceTests.load("workflow-vectors.json")
        let wfs = W.get("workflows")
        var f: [String] = []
        XCTAssertEqual(Workflow.workflowDigest(wfs?.get("main")?.get("body") ?? .null), W.get("digests")?.get("workflow")?.asString)
        for v in W.get("digests")?.get("values")?.asArray ?? [] {
            if Workflow.valueDigest(v.get("value") ?? .null) != v.get("digest")?.asString { f.append("value digest") }
        }
        XCTAssertEqual(W.get("digests")?.get("receipt_refs")?.asArray?.count, 4)
        var seen = Set<String>()
        func run(_ kind: String, _ bind: Bool) {
            let cases = W.get(kind)?.asArray ?? []
            if cases.isEmpty { f.append("\(kind): no cases") }
            for c in cases {
                let name = c.get("name")?.asString ?? "?"
                let name2 = c.get("workflow")?.asString ?? ""
                let args = (wfs?.get(name2), c.get("principal")?.asString ?? "", c.get("rs_signer")?.asString ?? "", c.get("receipts"), now(c.get("now")), c.get("request"))
                let got = bind
                    ? Workflow.bindPromises(workflow: args.0, principal: args.1, rsSigner: args.2, receipts: args.3, now: args.4, request: args.5)
                    : Workflow.admitStep(workflow: args.0, principal: args.1, rsSigner: args.2, receipts: args.3, now: args.4, request: args.5)
                if let code = got.code { seen.insert(code) }
                if got.json != c.get("expect") { f.append("\(kind) \(name): got \(got.json)") }
            }
        }
        run("admit", false)
        run("bind", true)
        let pr = W.get("plan_root")?.asArray ?? []
        if pr.isEmpty { f.append("plan_root: no cases") }
        for c in pr {
            let got = Workflow.planRootAuthorized(workflow: wfs?.get(c.get("workflow")?.asString ?? ""), principal: c.get("principal")?.asString ?? "", now: now(c.get("now")), root: c.get("root")?.asString ?? "")
            if .bool(got) != c.get("expect") { f.append("plan_root \(c.get("name")?.asString ?? "?")") }
        }
        for code in ["bad_workflow", "bad_dag", "bad_signature", "not_yet", "expired", "goal_mismatch", "plan_root_mismatch", "bad_receipt", "unplanned_step", "step_mismatch", "params_mismatch", "already_done", "budget_exceeded", "deps_unmet", "dep_failed", "stale_dep", "edge_missing", "edge_unit", "edge_digest", "edge_value", "edge_relation", "taint_flow", "pipeline_unconstrained", "taint_escalate"] where !seen.contains(code) {
            f.append("code never exercised: \(code)")
        }
        // never traps / always denies on hostile input
        let keys = W.get("keys")
        let p = keys?.get("principal")?.asString ?? "", rs = keys?.get("rs")?.asString ?? ""
        let hostile: [JSONValue?] = [nil, .null, .int(1), .string("x"), .array([]), .object([:]), .object(["body": .null]), .object(["body": .object([:]), "sig": .int(1)])]
        for x in hostile {
            if Workflow.admitStep(workflow: x, principal: p, rsSigner: rs, receipts: .array([]), now: 1, request: x).decision != "deny" { f.append("hostile admit") }
            if Workflow.bindPromises(workflow: x, principal: p, rsSigner: rs, receipts: .array([]), now: 1, request: x).decision != "deny" { f.append("hostile bind") }
        }
        if Workflow.admitStep(workflow: wfs?.get("main"), principal: p, rsSigner: rs, receipts: .string("x"), now: 1, request: .object([:])).decision != "deny" { f.append("receipts not an array") }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }

    func testReadSideVectors() throws {
        let R = try ConformanceTests.load("readside-vectors.json")
        let grants = R.get("grants")
        var f: [String] = []
        let red = R.get("redact")?.asArray ?? []
        if red.isEmpty { f.append("redact: no cases") }
        for c in red {
            let got = ReadSide.redactRead(grant: grants?.get(c.get("grant")?.asString ?? ""), input: c.get("input"))
            if got.json != c.get("expect") { f.append("redact \(c.get("name")?.asString ?? "?"): got \(got.json)") }
        }
        let sinks = R.get("sinks")?.asArray ?? []
        if sinks.isEmpty { f.append("sinks: no cases") }
        for c in sinks {
            let got = ReadSide.checkSink(grant: grants?.get(c.get("grant")?.asString ?? ""), principal: c.get("principal"), rsSigner: c.get("rs_signer"), now: c.get("now"), sink: c.get("sink"), receipts: c.get("receipts"))
            if got.json != c.get("expect") { f.append("sink \(c.get("name")?.asString ?? "?"): got \(got.json)") }
        }
        let main = grants?.get("main")?.get("body") ?? .null
        let gd = ReadSide.readGrantDigest(main)
        XCTAssertEqual(gd, R.get("digests")?.get("grant")?.asString)
        let chain = sinks.first { $0.get("name")?.asString == "chain-of-two-public-reads" }
        let got = ReadSide.readChainLabels(receipts: chain?.get("receipts"), rsSigner: R.get("keys")?.get("rs")?.asString ?? "", grantDigest: gd ?? "", now: 1_800_000_000_000)
        let want = (R.get("digests")?.get("chain_labels")?.get("labels")?.asArray ?? []).compactMap { $0.asString }
        if got != .labels(want) { f.append("chain labels: \(got)") }
        // the masked view never contains a dropped value
        if let c = red.first(where: { $0.get("name")?.asString == "support-view" }) {
            let text = "\(c.get("expect")?.get("view") ?? .null)"
            for secret in ["sk_live_x", "123-45-6789", "dev-1", "c_77", "not in the schema"] where text.contains(secret) { f.append("view leaks \(secret)") }
        } else { f.append("support-view missing") }
        // hostile input never traps
        let hostile: [JSONValue?] = [nil, .null, .int(1), .string("x"), .array([]), .object([:])]
        for x in hostile {
            if ReadSide.redactRead(grant: x, input: x).decision != "deny" { f.append("hostile redact") }
            if ReadSide.checkSink(grant: x, principal: x, rsSigner: x, now: x, sink: x, receipts: x).decision != "deny" { f.append("hostile sink") }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }
}
