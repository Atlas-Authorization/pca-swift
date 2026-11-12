import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED K4 vectors (packages/pca/conformance/k4-vectors.json). A missing file fails.
final class K4VectorTests: XCTestCase {
    func testK4Vectors() throws {
        let doc = try ConformanceTests.load("k4-vectors.json")
        var failures: [String] = []
        let esc = doc.get("escalation")
        let cfg = esc?.get("config")
        let cc = esc?.get("config_cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cc.count, 6)
        for c in cc where K4.pricingConfigError(c.get("config")) != c.get("expect")?.asString { failures.append("config \(c.get("name")?.asString ?? "?")") }
        let ds = esc?.get("decisions")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(ds.count, 14)
        for c in ds {
            let g = K4.decide(config: cfg, calibration: c.get("calibration"), risk: c.get("risk"))
            if g.ask != (c.get("expect")?.get("ask") == .bool(true)) || g.reason != c.get("expect")?.get("reason")?.asString { failures.append("decision \(g)") }
        }
        for c in esc?.get("calibration")?.asArray ?? [] {
            var risks: [String: JSONValue] = [:]
            for (k, v) in c.get("risks")?.asObject ?? [:] { risks[k.s] = v }
            let start = c.get("start")
            let g = K4.updateCalibration(config: c.get("config"), mult: start?.get("multiplierPpm")?.safeInt ?? 0, seen: (start?.get("seen")?.asArray ?? []).compactMap { $0.asString },
                                         answers: c.get("answers")?.asArray ?? [], risks: risks)
            if g.multiplierPpm != c.get("expect")?.get("multiplierPpm")?.safeInt || g.seen != (c.get("expect")?.get("seen")?.asArray ?? []).compactMap({ $0.asString }) { failures.append("calibration \(c.get("name")?.asString ?? "?")") }
        }
        let bs = doc.get("network_binding")?.get("cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(bs.count, 15)
        for c in bs {
            let e = c.get("expect_in")
            let got = K4.verifyBinding(c.get("binding"), grant: e?.get("grant") ?? .null, holder: e?.get("holder")?.asString ?? "", issuerNonce: e?.get("issuer_nonce")?.asString ?? "", provider: e?.get("provider")?.asString)
            if got != c.get("expect")?.asString { failures.append("binding \(c.get("name")?.asString ?? "?"): \(got ?? "nil")") }
        }
        let es = doc.get("erc7715")?.get("cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(es.count, 24)
        for c in es {
            let o = c.get("opts")
            let ctxs = o?.get("contexts")
            let got = K4.verifyGranted(g: c.get("envelope") ?? .null, sent: c.get("sent") ?? .null, got: c.get("got"),
                                       allowedManagers: (o?.get("allowedManagers")?.asArray ?? []).compactMap { $0.asString }, contextOwner: { ctxs?.get($0)?.asString })
            if got != c.get("expect")?.asString { failures.append("erc7715 \(c.get("name")?.asString ?? "?"): \(got ?? "nil")") }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }
}
