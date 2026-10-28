import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED A2A binding vectors (packages/pca/conformance/a2a-vectors.json).
final class A2aVectorTests: XCTestCase {
    private func strs(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    func testA2aVectors() throws {
        let doc = try ConformanceTests.load("a2a-vectors.json")
        var f: [String] = []
        for c in doc.get("need")?.asArray ?? [] {
            let name = c.get("name")?.asString ?? "?"
            let (need, code) = A2a.decodeNeed(c.get("input"))
            let exp = c.get("expect")
            if (code == nil) != (exp?.get("ok") == .bool(true)) { f.append("need \(name): \(code ?? "ok")"); continue }
            if let n = need { if A2a.needDigest(n) != exp?.get("digest")?.asString { f.append("need \(name): digest") } }
            else if code != exp?.get("code")?.asString { f.append("need \(name): \(code ?? "")") }
        }
        let push = doc.get("push")
        for t in push?.get("tokens")?.asArray ?? [] {
            if A2a.pushToken(taskId: t.get("task_id")?.asString ?? "", chainIds: strs(t.get("chain_ids")), salt: t.get("salt")?.asString ?? "") != t.get("token")?.asString { f.append("push token") }
        }
        for s in strs(push?.get("weak_salts")) { if A2a.pushToken(taskId: "t", chainIds: ["a"], salt: s) != nil { f.append("weak salt \(s)") } }
        for c in push?.get("checks")?.asArray ?? [] {
            let e = c.get("expected"), d = c.get("delivered"), exp = c.get("expect")
            let got = A2a.checkPush(taskId: e?.get("task_id")?.asString ?? "", chainIds: strs(e?.get("chain_ids")), salt: e?.get("salt")?.asString ?? "", token: d?.get("token"), payload: d?.get("payload"))
            let ok = (got == nil) == (exp?.get("ok") == .bool(true)) && (got == nil || got == exp?.get("reason")?.asString)
            if !ok { f.append("push \(c.get("name")?.asString ?? "?"): \(got ?? "ok")") }
        }
        for c in doc.get("chains")?.asArray ?? [] {
            let got = A2a.checkChainExtension((c.get("chains")?.asArray ?? []).map { strs($0) })
            let exp = c.get("expect")
            let ok = (got == nil) == (exp?.get("ok") == .bool(true)) && (got == nil || (got!.reason == exp?.get("reason")?.asString && Int64(got!.failedHop) == exp?.get("failedHop")?.safeInt))
            if !ok { f.append("chains \(c.get("name")?.asString ?? "?")") }
        }
        for c in doc.get("resume")?.asArray ?? [] {
            let pa = c.get("proof_action")
            let got = A2a.resumeGate(state: c.get("state")?.asString, needEncoded: c.get("need_encoded"), answerDigest: c.get("answer_need_digest")?.asString,
                                     proofVerb: pa?.get("verb")?.asString, proofResource: pa?.get("resource")?.asString)
            if got != c.get("expect")?.asString { f.append("resume \(c.get("name")?.asString ?? "?"): \(got ?? "nil")") }
        }
        let R = doc.get("receipts")
        let signer = R?.get("signer")?.asString ?? ""
        let recs = R?.get("records")?.asArray ?? []
        for v in R?.get("verify")?.asArray ?? [] {
            if A2a.verifyReceipt(recs[Int(v.get("record")?.safeInt ?? 0)], signer: signer) != (v.get("ok") == .bool(true)) { f.append("verify \(v.get("record")?.safeInt ?? -1)") }
        }
        for d in R?.get("digests")?.asArray ?? [] {
            if A2a.receiptDigest(recs[Int(d.get("record")?.safeInt ?? 0)]) != d.get("digest")?.asString { f.append("digest") }
        }
        for s in R?.get("scenarios")?.asArray ?? [] {
            let name = s.get("name")?.asString ?? "?"
            let list = (s.get("indices")?.asArray ?? []).map { recs[Int($0.safeInt ?? 0)] }
            let tid = s.get("task_id")?.asString ?? "", ids = strs(s.get("chain_ids"))
            let got = A2a.checkReceiptChain(list, signer: signer, taskId: tid, chainIds: ids)
            let exp = s.get("expect")
            var ok = got.ok == (exp?.get("ok") == .bool(true))
            if ok && got.ok { ok = got.terminal == (exp?.get("terminal") == .bool(true)) && got.lastState == exp?.get("last_state")?.asString }
            if ok && !got.ok { ok = got.code == exp?.get("code")?.asString && (exp?.get("at") == nil || Int64(got.at) == exp?.get("at")?.safeInt) }
            if A2a.mayTriggerNext(list, signer: signer, taskId: tid, chainIds: ids) != (s.get("may_trigger_next") == .bool(true)) { ok = false }
            if !ok { f.append("receipts \(name): \(got)") }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }
}
