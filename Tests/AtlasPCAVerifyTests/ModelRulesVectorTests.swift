import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Rules 20 (units) and 21 (tighten-only) END TO END through `PCA.authorize`: the shared vectors
/// packages/pca/conformance/model-rules-vectors.json (signed grants, decided by the TypeScript reference). A grant's tighten[] rules,
/// unit tags and polarity are signed policy: ignoring them would let a model move a decision up, so every case must decide the
/// same as the reference, reason text included, over the FULL per-check result set.
final class ModelRulesVectorTests: XCTestCase {
    static func vectors() throws -> JSONValue { try ConformanceTests.load("model-rules-vectors.json") }

    static func isModelReason(_ r: String) -> Bool {
        ["units: ", "tighten: ", "schema: ", "intent_session: "].contains { IV.startsWith(r, $0) }
    }

    func run(_ d: JSONValue, _ c: JSONValue) -> PCA.AuthorizeResult {
        let grant = c.get("grant") ?? .null
        let op = c.get("operation")
        let operation = PCA.Operation(verb: op?.get("verb")?.asString ?? "", resource: op?.get("resource")?.asString ?? "", params: op?.get("params") ?? .null)
        var input = PCA.AuthorizeInput(operation: operation, audience: d.get("audience")?.asString, resolveGrant: { _ in grant },
                                       stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: d.get("now")?.safeInt, plan: PCA.SINGLE_STEP)
        if let v2 = c.get("intent_v2") { input.intentV2 = .context(IntentV2Context(v2)) }
        if let cx = c.get("context")?.asObject {
            let env = cx["env"]
            input.context = { _ in PCA.AuthorizeContext(env: env) }
        }
        return PCA.authorize(pcactn: c.get("pcactn"), input.withProv())
    }

    func testModelRulesVectors() throws {
        let d = try Self.vectors()
        XCTAssertEqual(d.get("format")?.asString, "pca-model-rules-vectors/1")
        var decisions = Set<String>()
        var bad: [String] = []
        let cases = d.get("cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 32)
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let e = c.get("expect")
            decisions.insert(e?.get("decision")?.asString ?? "")
            let r = run(d, c)
            if r.allow != (e?.get("allow") == .bool(true)) || r.decision != e?.get("decision")?.asString || Int64(r.status) != e?.get("status")?.safeInt {
                bad.append("\(name): got allow=\(r.allow) decision=\(r.decision) status=\(r.status) want \(Canonical.canonicalize(e ?? .null)): \(r.reasons)")
                continue
            }
            let wantFailed = (e?.get("failed")?.asArray ?? []).compactMap { $0.asString }
            if r.failedChecks != wantFailed { bad.append("\(name): failed checks \(r.failedChecks), want \(wantFailed) (\(r.reasons))") }
            let got = r.reasons.filter(Self.isModelReason)
            let want = (e?.get("reasons")?.asArray ?? []).compactMap { $0.asString }
            if got != want { bad.append("\(name): model reasons \(got), want \(want)") }
            for k in ["units", "tighten"] {
                let w = e?.get(k)?.asString
                let g = r.checks[k]?.rawValue
                if g != w { bad.append("\(name): check \(k) = \(g ?? "nil"), want \(w ?? "nil")") }
            }
            var wantDeg: [String: String] = [:]
            for (k, v) in e?.get("degraded")?.asObject ?? [:] { wantDeg[k.s] = v.asString ?? "" }
            if r.degraded != wantDeg { bad.append("\(name): degraded \(r.degraded), want \(wantDeg)") }
        }
        for dec in ["allow", "escalate", "deny"] where !decisions.contains(dec) { bad.append("no \(dec) case in the vectors") }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }
}
