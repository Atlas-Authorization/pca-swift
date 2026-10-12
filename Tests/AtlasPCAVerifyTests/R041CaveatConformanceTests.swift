import XCTest
import Foundation
@testable import AtlasPCAVerify

/// PCA 0.4.1 policy-layer helpers (reference: policyCaveats in packages/pca/src/policy-vm.ts and agentNativeCaveatEvaluator /
/// envelopeCaveatEvaluator): `PCA.evaluateCaveats(PCA.policyCaveats(grant:chain:), context:)` over `primitives.caveat_eval`
/// (caveats on the ROOT grant outside the envelope are evaluated like delegated ones, incl. `max_spend`), plus totality /
/// fail-closed unit cases. The core verifier (`PCA.verify`) still does not evaluate caveats.
final class R041CaveatConformanceTests: XCTestCase {
    private func o(_ d: [String: JSONValue]) -> JSONValue { .object(JObject(uniqueKeysWithValues: d.map { (JKey($0.key), $0.value) })) }

    func testCaveatEvalCorpus() throws {
        let doc = try ConformanceTests.loadCorpus()
        guard let cases = doc.get("primitives")?.get("caveat_eval")?.asArray else { return XCTFail("no caveat_eval primitives") }
        XCTAssertGreaterThanOrEqual(cases.count, 40)
        var byName: [String: JSONValue] = [:]
        var failures: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "<unnamed>"
            byName[name] = c
            guard case let .bool(wantOk)? = c.get("expect")?.get("allow"),
                  let wantFailed = c.get("expect")?.get("failed")?.asArray?.compactMap({ $0.asString }) else {
                failures.append("\(name): malformed expect"); continue
            }
            let r = PCA.evaluateCaveats(PCA.policyCaveats(grant: c.get("grant") ?? .null, chain: c.get("chain")),
                                        context: c.get("context") ?? .null)
            if r.ok != wantOk || r.failed != wantFailed {
                failures.append("\(name): got (\(r.ok), \(r.failed)) want (\(wantOk), \(wantFailed))")
            }
        }
        XCTAssertEqual(byName["r041-root-max-spend-exceeded"]?.get("expect")?.get("allow"), .bool(false))
        XCTAssertEqual(byName["r041-root-max-spend-within"]?.get("expect")?.get("allow"), .bool(true))
        XCTAssertTrue(failures.isEmpty, "\(failures.count) of \(cases.count) caveat_eval cases failed:\n" + failures.joined(separator: "\n"))
        if failures.isEmpty { print("PCA conformance caveat_eval: \(cases.count)/\(cases.count) pass") }
    }

    func testEvaluateCaveatsIsTotalAndFailsClosed() {
        let ctx = o(["now": .int(1_800_000_000_000), "action": o(["params": o(["amount": .int(5)])])])
        let ms = { (usd: JSONValue) in self.o(["type": .string("max_spend"), "usd": usd]) }
        func ev(_ cs: JSONValue?, _ c: JSONValue) -> (Bool, [String]) { let r = PCA.evaluateCaveats(cs, context: c); return (r.ok, r.failed) }
        XCTAssert(ev(nil, ctx) == (false, ["<malformed caveats>"]))
        XCTAssert(ev(o([:]), ctx) == (false, ["<malformed caveats>"]))
        XCTAssert(ev(.string("x"), ctx) == (false, ["<malformed caveats>"]))
        XCTAssert(ev(.array([]), ctx) == (true, []))
        let mixed = ev(.array([.string("max_spend"), .array([]), o(["type": .int(1)]), o(["type": .string("note")]), o(["type": .string("predicates")])]), ctx)
        XCTAssert(mixed == (false, ["<malformed>", "<malformed>", "<malformed>", "note", "predicates"]), "\(mixed)")
        XCTAssertTrue(ev(.array([ms(.int(5))]), ctx).0)
        XCTAssertTrue(ev(.array([ms(.double(5.5))]), ctx).0)
        XCTAssertFalse(ev(.array([ms(.double(4.99))]), ctx).0)
        XCTAssertFalse(ev(.array([ms(.bool(true))]), ctx).0)
        XCTAssertFalse(ev(.array([ms(.double(.infinity))]), ctx).0)
        XCTAssertFalse(ev(.array([ms(.double(.nan))]), ctx).0)
        XCTAssertFalse(ev(.array([ms(.string("5"))]), ctx).0)
        XCTAssertFalse(ev(.array([ms(.int(5))]), o(["now": .int(1), "action": o(["params": o(["amount": .bool(true)])])])).0)
        let noNow = o(["action": o(["params": o(["amount": .int(1)])])])
        XCTAssertTrue(ev(.array([ms(.int(5))]), noNow).0, "max_spend needs no now")
        XCTAssertFalse(ev(.array([o(["type": .string("budget_alloc"), "limit": .int(1)])]), noNow).0, "budget_alloc needs now")
        XCTAssert(ev(.array([ms(.int(5))]), .null) == (false, ["max_spend"]))
        XCTAssertFalse(ev(.array([ms(.int(5))]), o(["now": .int(1), "params": o(["amount": .int(1)])])).0, "top-level params are not the action's")
        // currency: exactly "usd" / "USD"; a decomposed or other spelling is not
        let cur = { (c: JSONValue) in self.o(["now": .int(1), "action": self.o(["params": self.o(["amount": .int(1), "currency": c])])]) }
        XCTAssertTrue(ev(.array([ms(.int(5))]), cur(.string("USD"))).0)
        XCTAssertFalse(ev(.array([ms(.int(5))]), cur(.string("Usd"))).0)
        XCTAssertFalse(ev(.array([ms(.int(5))]), cur(.null)).0)
        let rv = JSONValue.array([o(["type": .string("reversibility_max"), "class": .string("irreversible")])])
        XCTAssertFalse(ev(rv, o(["now": .int(1), "action": o(["reversibility_class": .string("reversible")])])).0, "reads ctx.reversibility_class only")
        XCTAssertTrue(ev(rv, o(["now": .int(1), "reversibility_class": .string("rate_limited")])).0)
        XCTAssertFalse(ev(rv, o(["now": .int(1), "reversibility_class": .string("unknown")])).0)
    }

    func testPolicyCaveatsShapes() {
        let env = o(["type": .string("envelope")])
        let a = o(["type": .string("max_spend"), "usd": .int(1)])
        let b = o(["type": .string("expires"), "at": .int(2)])
        let grant = o(["caveats": .array([a, env, env])])
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: nil), .array([a, env]))
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: .string("nope")), .array([a, env]))
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: .array([])), .array([a, env]))
        let leaf = o(["caveats": .array([a, env, env, b])])
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: .array([grant, leaf])), .array([a, env, b]))
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: .array([grant, o(["caveats": .string("x")])])), .array([a, env]))
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: .array([grant, .string("leaf")])), .array([a, env]))
        XCTAssertNil(PCA.policyCaveats(grant: o([:]), chain: .array([leaf])))
        XCTAssertEqual(PCA.policyCaveats(grant: o(["caveats": .string("x")]), chain: .array([leaf])), .string("x"))
        XCTAssertNil(PCA.policyCaveats(grant: .string("grant"), chain: .array([leaf])))
        XCTAssertEqual(PCA.evaluateCaveats(PCA.policyCaveats(grant: o([:]), chain: .array([leaf])), context: o(["now": .int(1)])).failed, ["<malformed caveats>"])
    }
}
