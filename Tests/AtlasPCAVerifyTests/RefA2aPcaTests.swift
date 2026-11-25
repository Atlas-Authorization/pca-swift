import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the rest of pca-a2a against the TypeScript reference: proof-carrying Tasks (attach, extract, the verify entry points that refuse
/// before the full verifier, the guard), the signed Agent Card, the AP2 payment mandate, AUTH_REQUIRED resumption and its gate, per-hop delegation, push
/// notifications, the receipt chain and the extended Agent Card. A reference throw requires a native refusal.
final class RefA2aPcaTests: XCTestCase {
    static let file = "ref-a2a.json.gz"

    /// Reasons that quote the JOSE library, or a runtime message, are compared up to the first colon (the reference oracle does the same).
    static func norm(_ v: JSONValue) -> JSONValue {
        guard var o = v.asObject, let r = o["reason"]?.asString,
              let m = r.range(of: #"^(signature \d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): "#, options: .regularExpression) else { return v }
        o["reason"] = .string(String(r[m].dropLast(2)))
        return .object(o)
    }

    static func opts(_ v: JSONValue?) throws -> A2a.VerifyOptions {
        // absent (or any non-object) options are the reference's empty ones: the verifier then refuses for want of an authority
        guard let x = v?.asObject else { return A2a.VerifyOptions() }
        var o = A2a.VerifyOptions(aud: x["aud"]?.asString, now: IV.safe(x["now"]).map { Int64($0) }, grant: x["grant"]?.asObject, expectedRootIssuer: x["expectedRootIssuer"]?.asString)
        o.requireProof = x["require"] != .bool(false)
        o.humanSignerSet = x["humanSignerSet"]?.asArray
        if let ctx = x["context"]?.asObject { o.context = { _ in ctx } }
        return o
    }

    static func strs(_ v: JSONValue?) throws -> [String] { try RefA2aTests.strs(v) }

    func testA2aRestAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["constants", "jcsBytes", "validateAgentCard1", "attachPcaToA2ATask", "attachPcaToA2AMessage", "extractPca", "extractPcaFromMessage",
                                "verifyA2ATask", "middleware", "resumeAuthRequired", "resumeGate", "verifyA2ADelegation", "checkPushNotification", "checkReceiptChain",
                                "mayTriggerNext", "extendedAgentCard", "issueSignedAgentCard", "verifyAgentCard", "a2aPaymentMandateFromPca",
                                "pcaBindingFromA2APaymentMandate", "verifyA2APaymentMandate"]
        let n = try Base.each(Self.file, fns, seeds: true) { c in
            let got: BaseGot = Base.run({ ($0 as? A2a.A2AAuthorityError)?.code ?? ($0 as? JSError)?.code }) {
                switch c.fn {
                case "constants":
                    return .object(["PCA_A2A_EXTENSION_URI": .string(A2a.PCA_A2A_EXTENSION_URI), "TASK_STATE_AUTH_REQUIRED": .string(A2a.TASK_STATE_AUTH_REQUIRED),
                                    "TASK_STATE_INPUT_REQUIRED": .string(A2a.TASK_STATE_INPUT_REQUIRED), "A2A_AP2_CONTEXT": .array(A2a.A2A_AP2_CONTEXT.map { .string($0) }),
                                    "A2A_RECEIPT_DOMAIN": .string(A2a.A2A_RECEIPT_DOMAIN), "RECEIPT_KEY": .string(A2a.RECEIPT_KEY)])
                case "jcsBytes": return Base.bytesValue(try A2a.jcsBytes(c.arg(0)))
                case "validateAgentCard1": return .array(A2a.validateAgentCard1(c.arg(0)).map { .string($0) })
                case "attachPcaToA2ATask": return try A2a.attachPcaToA2ATask(c.arg(0), c.arg(1) ?? .null)
                case "attachPcaToA2AMessage": return try A2a.attachPcaToA2AMessage(c.arg(0), c.arg(1) ?? .null)
                case "extractPca": return A2a.extractPca(c.arg(0)) ?? .null
                case "extractPcaFromMessage": return A2a.extractPcaFromMessage(c.arg(0)) ?? .null
                case "verifyA2ATask": return Self.norm(try A2a.verifyA2ATask(c.arg(0), try Self.opts(c.arg(1))).json)
                case "middleware": return Self.norm(try A2a.pcaA2AMiddleware(try Self.opts(c.arg(1)))(c.arg(0)).json)
                case "resumeAuthRequired": return Self.norm(try A2a.resumeAuthRequired(c.arg(0), c.arg(1), try Self.opts(c.arg(2))))
                case "resumeGate":
                    let o = c.arg(0)?.asObject ?? [:]
                    return try A2a.resumeGateAction(state: o["state"], needEncoded: o["needEncoded"], answerNeedDigest: o["answerNeedDigest"], proofAction: o["proofAction"]).map { .string($0) } ?? .null
                case "verifyA2ADelegation":
                    let hops = try (c.arg(0)?.asArray ?? []).map { A2a.Hop(task: $0.get("task"), opts: try Self.opts($0.get("opts"))) }
                    return Self.norm(try A2a.verifyA2ADelegation(hops))
                case "checkPushNotification":
                    guard let e = c.arg(0)?.asObject, let d = c.arg(1)?.asObject, let tid = e["taskId"]?.asString else { throw JSError("malformed") }
                    return try A2a.checkPushNotification(taskId: tid, chainIds: try Self.strs(e["chainIds"]), salt: e["salt"]?.asString, token: d["token"], payload: d["payload"])
                case "checkReceiptChain", "mayTriggerNext":
                    guard let o = c.arg(1)?.asObject, let signer = o["signer"]?.asString, let tid = o["taskId"]?.asString else { throw JSError("malformed") }
                    let rs = c.arg(0)?.asArray ?? []
                    let ids = try Self.strs(o["chainIds"])
                    if c.fn == "mayTriggerNext" { return .bool(A2a.mayTriggerNext(rs, signer: signer, taskId: tid, chainIds: ids)) }
                    let r = A2a.checkReceiptChain(rs, signer: signer, taskId: tid, chainIds: ids)
                    if !r.ok {
                        var m: JObject = ["ok": .bool(false), "code": .string(r.code ?? "")]
                        if r.at >= 0 { m["at"] = .int(Int64(r.at)) }
                        return .object(m)
                    }
                    return .object(["ok": .bool(true), "last": rs.last ?? .null, "terminal": .bool(r.terminal)])
                case "extendedAgentCard": return try A2a.extendedAgentCard(c.arg(0), try RefGrantsTests.obj(c.arg(1)))
                case "issueSignedAgentCard":
                    var io: JObject = [:]
                    if c.args.count > 2 { io = try RefGrantsTests.obj(c.arg(2)) }
                    return try A2a.issueSignedAgentCard(c.arg(0), c.arg(1), io)
                case "verifyAgentCard": return Self.norm(try A2a.verifyAgentCard(c.arg(0), try RefGrantsTests.obj(c.arg(1))))
                case "a2aPaymentMandateFromPca": return try A2a.a2aPaymentMandateFromPca(c.arg(0) ?? .null, try RefGrantsTests.obj(c.arg(1)))
                case "pcaBindingFromA2APaymentMandate": return try A2a.pcaBindingFromA2APaymentMandate(c.arg(0))
                case "verifyA2APaymentMandate": return Self.norm(try A2a.verifyA2APaymentMandate(c.arg(0), c.arg(1), try Self.opts(c.arg(2))).json)
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 4000)
        d.finish(4000)
    }

    /// What the oracle cannot cover: a PCActn that reaches the verifier is judged by it, a plug-in verifier decides, and a throwing one is a refusal.
    func testVerifierPlugAndFailClosed() throws {
        let cap: JSONValue = .object(["id": .string("g1"), "issuer": .string("ROOT"), "holder": .string("H1")])
        let task = try A2a.attachPcaToA2ATask(.object([:]), .object(["cap_chain": .array([cap])]))
        var o = A2a.VerifyOptions(aud: "rs", now: 1, grant: nil, expectedRootIssuer: "ROOT")
        XCTAssertFalse(try A2a.verifyA2ATask(task, o).ok) // the core verifier refuses a PCActn with no signature
        o.verifier = { _, _ in A2a.PcaOutcome(allow: true) }
        XCTAssertTrue(try A2a.verifyA2ATask(task, o).ok)
        o.verifier = { _, _ in throw JSError("boom") }
        XCTAssertFalse(try A2a.verifyA2ATask(task, o).ok) // a throwing verifier is a refusal
        XCTAssertThrowsError(try A2a.verifyA2ATask(task, A2a.VerifyOptions(aud: "rs"))) // no authority at all
        // the guard: a missing proof is refused unless the proof is optional; a present proof is always judged
        var g = A2a.VerifyOptions(aud: "rs", now: 1, grant: nil, expectedRootIssuer: "ROOT")
        XCTAssertFalse(try A2a.pcaA2AMiddleware(g)(.object([:])).ok)
        g.requireProof = false
        XCTAssertTrue(try A2a.pcaA2AMiddleware(g)(.object([:])).ok)
        XCTAssertFalse(try A2a.pcaA2AMiddleware(g)(task).ok)
    }
}
