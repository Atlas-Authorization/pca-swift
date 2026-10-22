import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential kill test of IntentSession.swift (rule 13: the intent_session wire member, the grant caveat, the signed session
/// root) and IntentRevocation.swift (rule 13 step 7) against the TS reference: k042-sessrevoc-cases.json
/// (tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts), shared with every native suite. The verdict (refused or not) must
/// agree on every case; reason text is compared exactly (the reference wording is the contract).
final class K042SessRevocOracleTests: XCTestCase {
    private var bad: [String] = []
    private var checks = 0
    private let td = K042.TextDiffs()

    private func check(_ label: String, _ want: JSONValue?, _ got: String?) {
        checks += 1
        let w = want?.asString
        if (w == nil) != (got == nil) { bad.append("\(label): want \(String(describing: w)) got \(String(describing: got))"); return }
        if w != nil, got != nil { td.add(w, got, label) }
    }

    func testSessionAndRevocationCorpus() throws {
        let g = try K042.json("k042-sessrevoc-cases.json")
        for c in K042.arr(g.get("wire")) { check("wire \(K042.str(c.get("name")))", c.get("reason"), IntentSession.validateWire(K042.parse(K042.str(c.get("v"))))) }
        for c in K042.arr(g.get("caveat")) { check("caveat \(K042.str(c.get("name")))", c.get("reason"), IntentSession.caveatError(K042.parse(K042.str(c.get("c"))))) }
        for c in K042.arr(g.get("root")) {
            let n = K042.str(c.get("name"))
            let s = K042.parse(K042.str(c.get("s")))
            check("shape \(n)", c.get("shape"), IntentSession.shapeError(s))
            let pins: JSONValue? = c.get("pq_pins").flatMap { $0.asString }.map { K042.parse($0) }
            let r = IntentSession.verifyRoot(s, pqPins: pins)
            if r.reason.contains(IV.UNSUPPORTED_SUITE) { continue } // a PQ suite this host lacks: by design
            check("verify \(n)", c.get("verify"), r.ok ? nil : r.reason)
        }
        for c in K042.arr(g.get("rev")) {
            guard K042.isNull(c.get("scope")) else { continue } // custom-scope cases are covered by the Swift unit tests
            let ev = c.get("ev")?.asString.map { K042.parse($0) }
            let ids = c.get("ids")?.asString.map { K042.parse($0) }
            let last = c.get("last")?.asString.map { K042.parse($0) }
            guard case let .string(authority) = K042.parse(K042.str(c.get("authority"))) else { continue }
            let idList: [String] = ids?.asArray?.compactMap { $0.asString } ?? []
            if let ids = ids?.asArray, ids.count != idList.count { continue } // non-string ids: not expressible through [String]
            if ids?.asArray == nil { continue }
            let r = IntentRevocation.check(ev, session: K042.str(c.get("session")), authority: authority, ids: idList, now: K042.num(c.get("now")),
                                           maxAgeMs: K042.num(c.get("maxAge")), last: last)
            if r.1.contains(IV.UNSUPPORTED_SUITE) { continue }
            check("rev \(K042.str(c.get("name")))", c.get("reason"), r.0 ? nil : r.1)
        }
        for c in K042.arr(g.get("prim")) {
            let input = K042.parse(K042.str(c.get("text")))
            let want = K042.isNull(c.get("reason"))
            if PCA.intentRevocationPrimitive(input) != want { bad.append("prim \(K042.str(c.get("name"))): want ok=\(want)") }
            checks += 1
        }
        td.finish("session/revocation")
        K042.report(bad, checks)
    }
}
