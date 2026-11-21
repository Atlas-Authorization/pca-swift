import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The stateful layer (packages/pca/conformance/stateful-vectors.json) replayed through `PCA.authorize`: each sequence runs against ONE state
/// store (replay counters, revocation mid-sequence, the trust budget depleting across calls, expiry, separate holder streams). Compared: the
/// sorted names of the checks that failed (the provenance gate is a Swift default the reference sequences do not exercise).
final class A0F2StatefulVectorsTests: XCTestCase {
    func testEverySequence() throws {
        let doc = try ConformanceTests.load("stateful-vectors.json")
        let seqs = try XCTUnwrap(doc.get("stateful")?.asArray)
        XCTAssertEqual(seqs.count, 20)
        var failures: [String] = []
        for seq in seqs { failures += run(seq) }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }

    private func run(_ seq: JSONValue) -> [String] {
        let name = seq.get("name")?.asString ?? "?"
        guard let setup = seq.get("setup") else { return ["\(name): no setup"] }
        var grants: [String: JSONValue] = [:]
        for g in setup.get("grants")?.asArray ?? [] { if let id = g.get("id")?.asString { grants[id] = g } }
        let store = MemoryStateStore()
        let revoked = A0F2RevokedBox((setup.get("revoked")?.asArray ?? []).compactMap { $0.asString })
        let steps = seq.get("steps")?.asArray ?? []
        if let b = setup.get("initial_budget"), let bv = ToolSchema.fin(b.get("B")), let tau = ToolSchema.fin(b.get("tau")) {
            for s in steps where s.get("op")?.asString == "present" {
                let chain = s.get("pcactn")?.get("cap_chain")?.asArray ?? []
                if let ref = s.get("pcactn")?.get("grant_ref")?.asString, let holder = chain.last?.get("holder")?.asString {
                    store.putBudget(key: PCA.stateKey(grantId: ref, leafHolder: holder), Risk.Budget(b: bv, tau: tau, asOf: nil))
                }
            }
        }
        let risk: JObject? = setup.get("risk")?.asObject
        let planNodes = setup.get("plan_nodes")?.asArray
        let audience = setup.get("audience")?.asString ?? ""
        var out: [String] = []
        for (i, s) in steps.enumerated() {
            let label = "\(name) step \(i)"
            if s.get("op")?.asString == "revoke" {
                if let id = s.get("id")?.asString { revoked.add(id) }
                continue
            }
            guard let p = s.get("pcactn"), let action = p.get("action"), let now = s.get("now")?.safeInt else { out.append("\(label): malformed step"); continue }
            var input = PCA.AuthorizeInput(
                operation: PCA.Operation(verb: action.get("verb")?.asString ?? "", resource: action.get("resource")?.asString ?? "", params: s.get("params") ?? .null),
                audience: audience, resolveGrant: { ref in grants[ref] }, stateStore: store,
                isRevoked: { pc, _ in (pc.get("cap_chain")?.asArray ?? []).contains { c in revoked.contains(c.get("id")?.asString ?? "") } },
                now: now,
                context: { _ in PCA.AuthorizeContext(plan: planNodes, planAuthorized: true, risk: risk) })
            input.seedBudget = false
            let r = PCA.authorize(pcactn: p, input.withProv())
            var failed: [String] = []
            for (n, st) in r.checks where st == .fail && n != "provenance_flow" { failed.append(n == "chain" ? "cap_chain" : n) }
            failed.sort()
            let want = (s.get("expect")?.get("failed")?.asArray ?? []).compactMap { $0.asString }
            if failed != want { out.append("\(label): failed checks \(failed), want \(want) (reasons: \(r.reasons.joined(separator: "; ")))") }
            if (s.get("expect")?.get("allow") == .bool(true)) != failed.isEmpty { out.append("\(label): allow mismatch") }
        }
        return out
    }
}

final class A0F2RevokedBox: @unchecked Sendable {
    private let l = NSLock()
    private var ids: [String]
    init(_ ids: [String]) { self.ids = ids }
    func add(_ x: String) { l.lock(); ids.append(x); l.unlock() }
    func contains(_ x: String) -> Bool { l.lock(); defer { l.unlock() }; return ids.contains(x) }
}
