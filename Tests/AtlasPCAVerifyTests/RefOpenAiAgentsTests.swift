import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAOpenAIAgents against the reference (@atlasauth/pca-openai-agents): proof sources, the guard pipeline, per-tool
/// option merging, guardrails and the step-up helpers. Tools, verifiers and hooks are rebuilt from the declarative descriptors of the corpus.
/// Messages are compared as the reference's oracle normalizes them (the decode cause cut, `withPcaTool` spelled `with_pca_tool`); a build
/// error is compared by its occurrence, not its wording (the reference splits TypeError from Error and names its own components).
final class RefOpenAiAgentsTests: XCTestCase {
    static let file = "ref-openai-agents.json.gz"
    typealias OA = PCAOpenAIAgents

    struct TestError: Error { let message: String }

    final class Calls {
        var items: [JSONValue] = []
        func add(_ v: JSONValue...) { items.append(.array(v)) }
        var json: JSONValue { .array(items) }
    }

    static func str(_ v: String?) -> JSONValue { v.map { .string($0) } ?? .null }

    static func norm(_ s: String) -> String {
        var t = s.replacingOccurrences(of: "withPcaTool", with: "with_pca_tool")
        if let r = t.range(of: "proof could not be decoded: ") { t = String(t[..<r.upperBound]) }
        return t
    }

    /// The comparable form of a value: messages normalized, build errors reduced to their occurrence, SDK-object extras dropped.
    static func clean(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .string(s): return .string(norm(s))
        case let .array(a): return .array(a.map(clean))
        case let .object(o):
            if o["build"] == .bool(true) { return .object(["err": .string("Error"), "calls": clean(o["calls"] ?? .null), "build": .bool(true)]) }
            var out: JObject = [:]
            for (k, x) in o where k.s != "extra" && k.s != "hasNeedsApproval" { out[k] = clean(x) }
            return .object(out)
        default: return v
        }
    }

    static func diff(_ c: BaseCase, _ got: JSONValue, _ want: JSONValue) -> String? {
        Base.canon(got) == Base.canon(want) ? nil : "\(c.name): want \(Base.firstDiff(want, got, "@")) || want \(Base.canon(want).prefix(300)) got \(Base.canon(got).prefix(300))"
    }

    // ---- proof sources ----

    func testProofSources() throws {
        let d = Base.Diffs()
        try Base.each(Self.file, ["proofFromRunContext", "guardrailProofFromContext", "provenanceFromRunContext", "proofFromInputHeaders"]) { c in
            let x = c.arg(0) ?? .null
            let got: JSONValue
            switch c.fn {
            case "proofFromRunContext": got = OA.proofFromRunContext(x.get("input") ?? .null, x.get("runContext") ?? .null) ?? .null
            case "guardrailProofFromContext": got = OA.guardrailProofFromContext(x.get("args") ?? .null) ?? .null
            case "provenanceFromRunContext": got = OA.provenanceFromRunContext(.object([:]), x.get("runContext") ?? .null) ?? .null
            default:
                let src = OA.proofFromInputHeaders(field: x.get("field")?.asString ?? "headers", header: x.get("header")?.asString ?? "PCA-Action")
                got = src(x.get("input") ?? .null, .object([:])) ?? .null
            }
            d.add(c, Base.diff(c, .value(got)))
        }
        d.finish(60)
    }

    // ---- descriptors -> native objects ----

    static func on(_ v: JSONValue?) -> Bool { v != nil && v != .null && v != .bool(false) }

    static func stub(_ d: JSONValue, _ calls: Calls) -> OA.Verify {
        .fn({ p in
            calls.add(.string("verify"), d.get("stub") ?? .null, str(OA.verbOf(p)))
            if let m = d.get("throws")?.asString { throw TestError(message: m) }
            let allow = d.get("allow") == .bool(true)
            return OA.VerifyOutcome(allow: allow, reason: d.get("reason")?.asString, checks: ["sig": allow ? "pass" : "fail"])
        })
    }

    static func require(_ d: JSONValue) -> OA.ProofSource? {
        guard let r = d.get("require"), r.isObject else { return nil }
        if let h = r.get("headers")?.asArray {
            return OA.proofFromInputHeaders(field: h.first?.asString ?? "headers", header: h.count > 1 ? (h[1].asString ?? "PCA-Action") : "PCA-Action")
        }
        let c = r.get("const")
        return { _, _ in c.flatMap { $0 == .null ? nil : $0 } }
    }

    static func opts(_ d: JSONValue, _ calls: Calls) -> OA.WithPcaToolOptions {
        var w = OA.WithPcaToolOptions()
        w.mode = d.get("mode")?.asString
        w.verb = d.get("verb")?.asString
        w.require = require(d)
        if let a = d.asObject?["audience"] { w.audience = a.asString.map { .id($0) } ?? .any }
        if let v = d.get("verify"), v.isObject { w.verify = stub(v, calls) }
        if let a = d.get("authorize"), a != .null { w.authorize = OA.AuthorizeOptions(input: PCA.AuthorizeInput()) }
        if on(d.get("onDeny")) { w.onDeny = { e, i in calls.add(.string("onDeny"), .string(e.kind), i) } }
        if on(d.get("onVerified")) { w.onVerified = { _, p, i in calls.add(.string("onVerified"), .bool(true), str(OA.verbOf(p)), i) } }
        if on(d.get("recorder")) { w.recorder = { name, out in calls.add(.string("recorded"), .string(name), out) } }
        return w
    }

    static func tool(_ td: JSONValue, _ calls: Calls) -> AgentTool {
        let name = td.get("name")?.asString
        if td.get("noExecute") == .bool(true) { return AgentTool(name: name) }
        return AgentTool(name: name, execute: { input, _ in
            calls.add(.string("exec"), str(name), input)
            if let m = td.get("throws")?.asString { throw TestError(message: m) }
            return .object(["echo": input, "tool": str(name)])
        })
    }

    static func errOf(_ e: Error, _ calls: Calls) -> JSONValue {
        var out: JObject = ["calls": calls.json]
        if let p = e as? PcaToolDenied {
            out["err"] = .string("PcaToolDenied")
            out["message"] = .string(p.message)
            out["kind"] = .string(p.kind)
            out["verb"] = .string(p.verb)
            if let c = p.checks { out["checks"] = .object(Dictionary(uniqueKeysWithValues: c.map { (JKey($0.key), JSONValue.string($0.value)) })) }
        } else {
            out["err"] = .string("Error")
            out["message"] = .string((e as? TestError)?.message ?? (e as? PcaToolConfigError)?.message ?? "\(e)")
        }
        return .object(out)
    }

    static func buildErr(_ calls: Calls) -> JSONValue { .object(["err": .string("Error"), "calls": calls.json, "build": .bool(true)]) }

    static func outcome(_ t: AgentTool, _ input: JSONValue, _ rc: JSONValue?, _ calls: Calls) -> JObject {
        do {
            guard let exec = t.execute else { throw PcaToolConfigError("withPcaTool: the wrapped tool has no execute()") }
            let out = try exec(input, rc)
            return ["ok": .bool(true), "out": out, "calls": calls.json, "name": str(t.name)]
        } catch {
            guard case var .object(o) = errOf(error, calls) else { return [:] }
            o["calls"] = calls.json
            return o
        }
    }

    func testWithPcaTool() throws {
        let d = Base.Diffs()
        try Base.each(Self.file, ["withPcaTool"]) { c in
            let x = c.arg(0) ?? .null
            let calls = Calls()
            let got: JSONValue
            do {
                let t = try OA.withPcaTool(Self.tool(x.get("tool") ?? .null, calls), Self.opts(x.get("options") ?? .null, calls))
                let rc: JSONValue? = x.get("noRunContext") == .bool(true) ? nil : x.get("runContext")
                got = .object(Self.outcome(t, x.get("input") ?? .null, rc, calls))
            } catch { got = Self.buildErr(calls) }
            d.add(c, Self.diff(c, Self.clean(got), Self.clean(c.out)))
        }
        d.finish(40)
    }

    func testPcaTools() throws {
        let d = Base.Diffs()
        try Base.each(Self.file, ["pcaTools"]) { c in
            let x = c.arg(0) ?? .null
            let calls = Calls()
            var tools: [String: AgentTool] = [:]
            for (k, v) in x.get("tools")?.asObject ?? [:] { tools[k.s] = Self.tool(v, calls) }
            let options = x.get("options") ?? .null
            var per: [String: OA.WithPcaToolOptions] = [:]
            for (k, v) in options.get("per")?.asObject ?? [:] { per[k.s] = Self.opts(v, calls) }
            let only: Set<String>? = options.get("only")?.asArray.map { Set($0.compactMap { $0.asString }) }
            let got: JSONValue
            do {
                let g = try OA.pcaTools(tools, Self.opts(options, calls), per: per, only: only)
                var res: JObject = [:]
                for (name, t) in g {
                    var r = Self.outcome(t, x.get("input") ?? .null, x.get("runContext"), calls)
                    r["same"] = .bool(t === tools[name])
                    res[JKey(name)] = .object(r)
                }
                got = .object(res)
            } catch { got = Self.buildErr(calls) }
            d.add(c, Self.diff(c, Self.clean(got), Self.clean(c.out)))
        }
        d.finish(10)
    }

    func testGuardrails() throws {
        let d = Base.Diffs()
        try Base.each(Self.file, ["guardrail"]) { c in
            let x = c.arg(0) ?? .null
            let calls = Calls()
            let od = x.get("options") ?? .null
            let wo = Self.opts(od, calls)
            guard let verify = wo.verify else { d.skip("guardrail without verify"); return }
            var go = OA.PcaGuardrailOptions(verify: verify)
            go.audience = wo.audience
            go.verb = wo.verb
            go.name = od.get("name")?.asString
            if let r = wo.require { go.require = { args in r(args, .object([:])) } }
            let g = x.get("kind") == .string("input") ? OA.pcaInputGuardrail(go) : OA.pcaToolGuard(go)
            let got: JSONValue
            do {
                let r = try g.execute(x.get("args") ?? .null)
                got = .object(["name": .string(g.name), "result": .object(["tripwireTriggered": .bool(r.tripwireTriggered), "outputInfo": r.outputInfo]), "calls": calls.json])
            } catch {
                got = .object(["err": .string("Error"), "message": .string((error as? TestError)?.message ?? "\(error)"), "calls": calls.json])
            }
            d.add(c, Self.diff(c, Self.clean(got), Self.clean(c.out)))
        }
        d.finish(20)
    }

    // ---- step-up (the corpus intent always answers "unguarded", so the agent is never consulted) ----

    func agent() throws -> PCAFacadeAgent {
        try PCAAgent.fromPrincipal(PCAAgentOptions(principal: .ed25519(try PCAEdKey.generate()), goal: "refunds", permissions: [("stripe", ["refund"])]))
    }

    static func recording(_ calls: Calls) -> OA.ToolIntent {
        return { t, i in
            calls.add(.string("intent"), .string(t), i ?? .null)
            return nil
        }
    }

    func testStepUp() throws {
        let a = try agent()
        let d = Base.Diffs()
        try Base.each(Self.file, ["reviewToolCall", "pendingStepUps", "needsApproval"]) { c in
            let x = c.arg(0) ?? .null
            let calls = Calls()
            let got: JSONValue
            switch c.fn {
            case "reviewToolCall":
                let r = OA.reviewToolCall(a, tool: x.get("tool")?.asString ?? "", input: x.get("input"), OA.StepUpOptions(intent: Self.recording(calls)))
                got = .object(["r": .object(["tool": .string(r.tool), "review": r.review]), "calls": calls.json])
            case "pendingStepUps":
                let reviews = (c.arg(0)?.asArray ?? []).map { OA.ToolReview(tool: $0.get("tool")?.asString ?? "", review: $0.get("review") ?? .null) }
                got = .array(OA.pendingStepUps(reviews).map { .object(["tool": .string($0.tool), "request": $0.request]) })
            default:
                var no = OA.NeedsApprovalOptions(stepUp: OA.StepUpOptions(intent: Self.recording(calls)))
                no.toolName = x.get("toolName")?.asString
                let f: AgentTool.NeedsApproval
                if x.get("via") == .string("direct") { f = OA.pcaNeedsApproval(a, no) }
                else {
                    let t = OA.withApproval(AgentTool(name: x.get("tool")?.get("name")?.asString, execute: { i, _ in i }), a, no)
                    guard let n = t.needsApproval else { d.skip("withApproval left no needsApproval"); return }
                    f = n
                }
                got = .object(["value": .bool(f(.object([:]), x.get("input") ?? .null)), "calls": calls.json])
            }
            var want = Self.clean(c.out)
            if c.fn == "needsApproval", var o = want.asObject { o = o.filter { $0.key.s == "value" || $0.key.s == "calls" }; want = .object(o) }
            d.add(c, Self.diff(c, Self.clean(got), want))
        }
        d.finish(10)
    }

    // ---- standing approvals (pure) ----

    func testStandingApprovalCoversVerbResourceAndWindow() {
        let a = PCAApprovals.approveClass(["stripe.refund"], ttlMs: 1_000, by: "p", now: 100, resource: "charge:*")
        XCTAssertTrue(PCAApprovals.classApprovalCovers(a, verb: "stripe.refund", resource: "charge:7", now: 100))
        XCTAssertTrue(PCAApprovals.classApprovalCovers(a, verb: "stripe.refund", resource: "charge:7", now: 1_099))
        XCTAssertFalse(PCAApprovals.classApprovalCovers(a, verb: "stripe.refund", resource: "charge:7", now: 1_100))
        XCTAssertFalse(PCAApprovals.classApprovalCovers(a, verb: "stripe.refund", resource: "charge:7", now: 99))
        XCTAssertFalse(PCAApprovals.classApprovalCovers(a, verb: "stripe.refund", resource: "order:7", now: 200))
        XCTAssertFalse(PCAApprovals.classApprovalCovers(a, verb: "gmail.send", resource: "charge:7", now: 200))
        XCTAssertTrue(PCAApprovals.coveredByAny([a], verb: "stripe.refund", resource: "charge:1", now: 500))
    }
}
