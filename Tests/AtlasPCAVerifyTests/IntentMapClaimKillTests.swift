import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A map whose metric or cell probability claim is missing, not a number or NaN is refused (the closeness test fails closed: NaN compares false, so it is written as
/// the negation of "within 2 ppm"). The reference had the fail-open form until its own fix; the port was already closed and is pinned here with its exact reasons.
final class IntentMapClaimKillTests: XCTestCase {
    private func emitted() throws -> JObject {
        var found: JObject?
        _ = try Base.each("ref-intent-map.json.gz", ["mapScenario"]) { c in
            guard found == nil else { return }
            let a = c.args
            let l = try RefIntentMultiRenderTests.learnerOf(a[0], a[1], a[2])
            found = WJ.plain(try PCAIntentMap.emit(l, intentRef: RefIntentMultiRenderTests.opt(a[3])?.asString)).asObject
        }
        return try XCTUnwrap(found)
    }

    private func verdict(_ mutate: (inout JObject) -> Void) throws -> (ok: Bool, problems: [String]) {
        var m = try emitted()
        mutate(&m)
        return PCAIntentMap.verify(.object(m))
    }

    func testTheUntouchedMapVerifies() throws {
        XCTAssertTrue(PCAIntentMap.verify(.object(try emitted())).ok)
    }

    func testAMetricClaimThatIsMissingNotANumberOrNaNIsRefused() throws {
        for key in ["residual_risk_ppm", "burden_ppm", "questions"] {
            for bad: JSONValue? in [nil, .string("7"), .double(.nan), .bool(true)] {
                let r = try verdict { m in var mt = m[JKey("metrics")]?.asObject ?? [:]; mt[JKey(key)] = bad; m[JKey("metrics")] = .object(mt) }
                XCTAssertFalse(r.ok, "\(key) = \(String(describing: bad))")
                XCTAssertTrue(r.problems.contains { $0.hasPrefix("metric \(key) differs (") }, "\(key): \(r.problems)")
            }
        }
    }

    func testAMissingNullMetricAndANullClaimAreDifferent() throws {
        // a replayed value that is null and a claim that is absent are a mismatch too (null !== undefined)
        let r = try verdict { m in var mt = m[JKey("metrics")]?.asObject ?? [:]; mt[JKey("log2_vs_mbits")] = nil; m[JKey("metrics")] = .object(mt) }
        let replaysNull = (try emitted()[JKey("metrics")]?.asObject?[JKey("log2_vs_mbits")] ?? .null) == .null
        // a replay that computes one: the deleted claim is refused with its reason; a replay that is null: null and absent still differ
        XCTAssertFalse(r.ok, "a deleted log2_vs_mbits claim is never accepted (replay null: \(replaysNull))")
        XCTAssertTrue(r.problems.contains { $0.hasPrefix("metric log2_vs_mbits differs (undefined claimed, ") }, "\(r.problems)")
    }

    func testACellClaimThatIsMissingNotANumberOrNaNIsRefused() throws {
        for bad: JSONValue? in [nil, .string("3"), .double(.nan), .null] {
            let r = try verdict { m in
                var cs = m[JKey("cells")]?.asArray ?? []
                guard !cs.isEmpty else { return }
                var c = cs[0].asObject ?? [:]
                c[JKey("p_ppm")] = bad
                cs[0] = .object(c)
                m[JKey("cells")] = .array(cs)
            }
            XCTAssertFalse(r.ok, "p_ppm = \(String(describing: bad))")
            XCTAssertTrue(r.problems.contains("cell 0 differs"), "\(r.problems)")
        }
    }
}
