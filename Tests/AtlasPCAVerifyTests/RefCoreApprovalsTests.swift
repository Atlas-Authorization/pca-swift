import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the approval layer of core pca against the TypeScript reference: review, goal lineage, batch review and time-boxing (ref-core-approvals-java),
/// and the approval channels: payload builders, channels over an injected transport and the dispatcher (ref-core-approval-channels).
final class RefCoreApprovalsTests: XCTestCase {
    typealias C = PCAApprovalChannels

    func key(_ label: JSONValue?) throws -> PCASuiteKey {
        .ed25519(try PCAEdKey(seed: Canonical.sha256(Array("atlas-pca-conformance/approvals/\(label?.asString ?? "")".utf8))))
    }

    func agent(_ spec: JSONValue?) throws -> PCAFacadeAgent {
        guard let s = spec, s.isObject else { throw JSError("spec expected") }
        var perms: [(String, [String])] = []
        if let p = s.get("permissions")?.asObject { for k in JS.keyOrder(p) { perms.append((k.s, p[k]?.asArray?.compactMap { $0.asString } ?? [])) } }
        var limits: [String: String]?
        if let l = s.get("limits")?.asObject { limits = l.reduce(into: [:]) { $0[$1.key.s] = $1.value.asString } }
        return try PCAAgent.fromPrincipal(PCAAgentOptions(
            principal: try key(s.get("principal")), goal: s.get("goal")?.asString ?? "", permissions: perms, limits: limits, holder: try key(s.get("holder")),
            riskPolicy: s.get("riskPolicy")?.asObject, budgetModel: s.get("budgetModel")?.asString, aud: s.get("aud")?.asString,
            now: s.get("now")?.safeInt, goalSalt: s.get("goalSalt")?.asString))
    }

    func renderer(_ mode: String) -> PCAApprovals.Renderer {
        { verb, resource, _ in
            if mode == "throw" { throw JSError("boom") }
            if mode == "badshape" { return .object(["v": .int(2)]) }
            return .object(["v": .int(1), "kind": .string("pca-approval-render"), "verb": .string(verb), "def_digest": .string(String(repeating: "A", count: 43)),
                            "unreviewed": .bool(true), "fields": .array([.object(["id": .string("resource"), "class": .string("param"), "value": .string(resource)])])])
        }
    }

    func opts(_ o: JSONValue?) -> PCAApprovals.ReviewOptions {
        guard let x = o, x.isObject else { return PCAApprovals.ReviewOptions() }
        return PCAApprovals.ReviewOptions(now: x.get("now")?.safeInt, goal: x.get("goal")?.asString, standing: x.get("standing")?.asArray,
                                          renderer: x.get("renderer")?.asString.map(renderer), insecureUnboundApproval: x.get("insecure") == .bool(true))
    }

    func testApprovalsAgainstTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-core-approvals-java.json.gz") { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "reviewAction":
                    return try PCAApprovals.reviewActionThrowing(try agent(c.arg(0)), verb: c.arg(1)?.asString ?? "", resource: c.arg(2)?.asString ?? "", params: JS.present(c.arg(3)), opts(c.arg(4)))
                case "buildGoalLineage":
                    return PCAApprovals.buildGoalLineage(try agent(c.arg(0)), verb: c.arg(1)?.asString ?? "", resource: c.arg(2)?.asString ?? "", params: JS.present(c.arg(3)),
                                                         goal: c.arg(4)?.get("goal")?.asString)
                case "describeGoalLineage": return .array(try PCAApprovals.describeGoalLineage(c.arg(0)))
                case "batchReview":
                    let calls = (c.arg(1)?.asArray ?? []).map { PCAApprovals.IntendedCall(verb: $0.get("verb")?.asString ?? "", resource: $0.get("resource")?.asString ?? "", params: JS.present($0.get("params"))) }
                    return .array(PCAApprovals.batchReview(try agent(c.arg(0)), calls, opts(c.arg(2))))
                case "timeBox":
                    guard let a2 = c.arg(1), let ttl = c.arg(2), let now = c.arg(3) else { throw JSError("args expected") }
                    return try PCAApprovals.timeBox(c.arg(0) ?? .null, holder: key(a2), ttlMs: JS.toNumber(ttl), now: JS.toNumber(now))
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 2000)
        d.finish(2000)
    }

    func transport(_ mode: String) -> C.Transport {
        { _, _, _ in
            switch mode {
            case "ok": return 200
            case "http500": return 500
            default: throw JSError(mode == "throw" ? "boom" : "")
            }
        }
    }

    func channel(_ kind: String, _ cfg: JSONValue?) throws -> C.ApprovalChannel {
        let configured = cfg?.get("configured") == .bool(true)
        let t = cfg?.get("transport")?.asString ?? "ok"
        let url: String? = configured ? "https://hooks.example/secret" : nil
        switch kind {
        case "slack": return C.slackApprovalChannel(webhookUrl: url, transport: transport(t))
        case "webhook":
            var h: [String: String] = [:]
            for (k, v) in cfg?.get("headers")?.asObject ?? [:] { h[k.s] = v.asString }
            return C.webhookApprovalChannel(url: url, transport: transport(t), headers: h)
        default:
            return try C.textApprovalChannel(kind, send: configured ? { _, _ in if t == "ok" { return "m1" }; throw JSError(t == "throw-empty" ? "" : "boom") } : nil)
        }
    }

    func testApprovalChannelsAgainstTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-core-approval-channels.json.gz") { c in
            let got: BaseGot = Base.run {
                let req = c.arg(0) ?? .null
                switch c.fn {
                case "actionSummary": return .string(C.actionSummary(req))
                case "lineageLines": return .array(try C.lineageLines(req).map { .string($0) })
                case "renderLines": return .array(try C.renderLines(req).map { .string($0) })
                case "buildSlackMessage": return try C.buildSlackMessage(req, c.arg(1))
                case "buildWebhookBody": return try C.buildWebhookBody(req, c.arg(1))
                case "buildTextBody": return try C.buildTextBody(req, c.arg(1))
                case "notify": return try channel(c.arg(0)?.asString ?? "", c.arg(3)).notify(c.arg(1) ?? .null, c.arg(2))
                case "notifyAll":
                    let chans = try (c.arg(2)?.asArray ?? []).map { try channel($0.get("kind")?.asString ?? "", $0) }
                    return .array(try C.createApprovalDispatcher(chans).notifyAll(req, c.arg(1)))
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 400)
        d.finish(400)
    }

    func testRiskToFixedTiesAwayFromZero() {
        XCTAssertEqual(C.toFixed2(0.125), "0.13")
        XCTAssertEqual(C.toFixed2(0.455), "0.46")
        XCTAssertEqual(C.toFixed2(0.375), "0.38")
        XCTAssertEqual(C.toFixed2(1), "1.00")
    }
}
