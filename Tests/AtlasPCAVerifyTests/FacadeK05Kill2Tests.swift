import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The agent facade pinned to the TypeScript reference (facade.ts, catalog.ts) at its edges: catalog resolution, the limit grammar and
/// its periods, the JS number helpers, the dollars risk policy, the wall-clock defaults, the dry run's budget tie and the counter lock.
final class FacadeK05Kill2Tests: XCTestCase {
    private func spec(_ connector: String, _ action: String, _ verb: String, _ rev: String = "reversible", blast: Double = 0.1, amount: String? = nil,
                      aliases: [String] = []) -> PCACatalogAction {
        PCACatalogAction(connector: connector, action: action, verb: verb, reversibility: rev, blastRadius: blast, amountField: amount, description: verb, aliases: aliases)
    }

    /// One reversible money-moving action with blast radius 0.9.
    private var pay: PCACatalog { PCACatalog([spec("pay", "send", "pay.send", blast: 0.9, amount: "amount")]) }

    private func edKey(_ b: UInt8) throws -> PCASuiteKey { .ed25519(try PCAEdKey(seed: [UInt8](repeating: b, count: 32))) }

    private func agent(limits: [String: String], now: Int64?, holder: PCASuiteKey? = nil) throws -> PCAFacadeAgent {
        try PCAAgent.fromPrincipal(PCAAgentOptions(principal: try edKey(9), goal: "pay", permissions: [("pay", ["send"])], limits: limits,
                                                   holder: try holder ?? edKey(8), catalog: pay, aud: "ins_t", now: now))
    }

    private func wall() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    private func rp(_ p: PCACompiledPolicy, _ k: String) -> Double? { IV.num(p.riskPolicy[JKey(k)]) }

    private func limitError(_ s: String) -> String {
        do { _ = try PCAFacade.parseLimit(s); return "ok" } catch { return "\(error)" }
    }

    // ---- catalog ----

    func testResolveAndSpecForEdges() {
        let cat = PCACatalog([
            spec("x", "y", "x.y"),
            spec("x", "z", "x.z", aliases: ["y"]),
            spec("solo", "solo", "solo"),
            spec("solo2", "q", "solo2.q", aliases: [""]),
            spec("", "v", "zz", aliases: ["y"]),
        ])
        // the exact verb wins over another action's alias
        XCTAssertEqual(cat.resolve(connector: "x", action: "y")?.verb, "x.y")
        // a catalogued verb without a dot is found as is
        XCTAssertEqual(cat.specFor("solo").reversibility, "reversible")
        // split('.') keeps empty parts: 'a..b' is connector 'a', action '.b'
        let ab = cat.specFor("a..b")
        XCTAssertEqual(ab.connector, "a")
        XCTAssertEqual(ab.action, ".b")
        // a leading dot: connector '', action 'x', and no alias lookup (the reference needs a dot at index > 0)
        let lead = cat.specFor(".x")
        XCTAssertEqual(lead.connector, "")
        XCTAssertEqual(lead.action, "x")
        let ly = cat.specFor(".y")
        XCTAssertEqual(ly.verb, ".y")
        XCTAssertEqual(ly.reversibility, "irreversible")
        // no dot: no alias lookup, even for an alias ""
        let s2 = cat.specFor("solo2")
        XCTAssertEqual(s2.verb, "solo2")
        XCTAssertEqual(s2.action, "solo2")
        XCTAssertEqual(s2.reversibility, "irreversible")
        // an uncatalogued verb: irreversible, blast radius 0.8, connector = the part before the first dot
        let u = cat.specFor("p.q")
        XCTAssertEqual(u.connector, "p")
        XCTAssertEqual(u.action, "q")
        XCTAssertEqual(u.blastRadius, 0.8)
        XCTAssertEqual(u.description, "(uncatalogued) p.q")
    }

    // ---- parseLimit ----

    func testEveryPeriodNameHasTheReferenceWindow() throws {
        let want: [String: Int64] = [
            "s": 1000, "sec": 1000, "second": 1000, "seconds": 1000,
            "m": 60_000, "min": 60_000, "minute": 60_000, "minutes": 60_000,
            "h": 3_600_000, "hr": 3_600_000, "hour": 3_600_000, "hours": 3_600_000,
            "d": 86_400_000, "day": 86_400_000, "days": 86_400_000,
            "w": 604_800_000, "week": 604_800_000, "weeks": 604_800_000,
            "mo": 2_592_000_000, "month": 2_592_000_000, "months": 2_592_000_000,
        ]
        for (name, ms) in want {
            XCTAssertEqual(try PCAFacade.parseLimit("1/\(name)").periodMs, ms, name)
        }
        XCTAssertEqual(try PCAFacade.parseLimit("1/DAY").periodMs, 86_400_000)
    }

    func testLimitLengthAndCharacterClassBoundaries() throws {
        // at most 64 UTF-16 units, counted before trimming
        let at64 = String(repeating: " ", count: 63) + "7"
        XCTAssertEqual(try PCAFacade.parseLimit(at64), PCAParsedLimit(amount: 7, unit: "count", periodMs: nil))
        XCTAssertEqual(limitError(" " + at64), "parseLimit: limit is longer than 64 characters")
        // digits are 0-9 inclusive
        XCTAssertEqual(try PCAFacade.parseLimit("9").amount, 9)
        XCTAssertEqual(try PCAFacade.parseLimit("0").amount, 0)
        XCTAssertEqual(limitError("1:"), "parseLimit: cannot parse limit '1:'")
        XCTAssertEqual(limitError("1/"), "parseLimit: cannot parse limit '1/'")
        // period letters are A-Z and a-z inclusive; the neighbours are not letters
        for c in ["A", "Z", "a", "z"] {
            XCTAssertEqual(limitError("1/\(c)"), "parseLimit: unknown period '\(c)' in '1/\(c)'", c)
        }
        for c in ["@", "[", "`", "{"] {
            XCTAssertEqual(limitError("1/\(c)"), "parseLimit: cannot parse limit '1/\(c)'", c)
        }
    }

    /// Each scanner loop advances: whitespace after '$' and around '/', the integer digits and the fraction digits.
    func testLimitScannersAdvance() {
        let got = S2Deadline.within(5, "parseLimit over whitespace, digits and a fraction") { () -> String in
            guard let l = try? PCAFacade.parseLimit("$ 12.5 / day") else { return "error" }
            return "\(l.amount) \(l.unit) \(l.periodMs ?? -1)"
        }
        XCTAssertEqual(got, "12.5 usd 86400000")
    }

    // ---- number helpers ----

    func testJsNumIsAnIntegerOnlyForASafeIntegerOtherThanNegativeZero() {
        XCTAssertEqual(PCAFacade.jsNum(5), .int(5))
        XCTAssertEqual(PCAFacade.jsNum(0.5), .double(0.5))
        guard case .double = PCAFacade.jsNum(-0.0) else { return XCTFail("-0 stays a double") }
    }

    func testJsNumberTextMatchesNumberToString() {
        XCTAssertEqual(PCAFacade.jsNumberText(0), "0")
        XCTAssertEqual(PCAFacade.jsNumberText(1e-6), "0.000001")
        XCTAssertEqual(PCAFacade.jsNumberText(5e-6), "0.000005")
        XCTAssertEqual(PCAFacade.jsNumberText(5e-7), "5e-7")
        XCTAssertEqual(PCAFacade.jsNumberText(1e-7), "1e-7")
        XCTAssertEqual(PCAFacade.jsNumberText(1e21), "1e+21")
        XCTAssertEqual(PCAFacade.jsNumberText(1.5e21), "1.5e+21")
        XCTAssertEqual(PCAFacade.jsNumberText(12.5), "12.5")
    }

    func testJsToNumberFollowsNumber() {
        func n(_ v: JSONValue) -> Double { PCAFacade.jsToNumber(v) }
        XCTAssertTrue(PCAFacade.jsToNumber(nil).isNaN)
        XCTAssertEqual(n(.null), 0)
        XCTAssertEqual(n(.bool(true)), 1)
        XCTAssertEqual(n(.bool(false)), 0)
        XCTAssertEqual(n(.array([])), 0)
        XCTAssertEqual(n(.array([.int(5)])), 5)
        XCTAssertEqual(n(.array([.null])), 0)
        XCTAssertEqual(n(.array([.string("7")])), 7)
        // Number([[5]]) is Number(String([5])) = 5; Number([[]]) is 0
        XCTAssertEqual(n(.array([.array([.int(5)])])), 5)
        XCTAssertEqual(n(.array([.array([])])), 0)
        XCTAssertEqual(n(.array([.array([.null])])), 0)
        XCTAssertTrue(n(.array([.int(1), .int(2)])).isNaN)
        XCTAssertTrue(n(.array([.bool(true)])).isNaN)
        XCTAssertTrue(n(.array([.array([.int(1), .int(2)])])).isNaN)
        XCTAssertTrue(n(.object([:])).isNaN)
    }

    // ---- compilePolicy ----

    func testCompilePolicyWindowsStartAtTheWallClock() throws {
        let before = wall()
        let p = try PCAFacade.compilePolicy(permissions: [("pay", ["send"])], limits: ["send": "5/day"], catalog: pay)
        let after = wall()
        guard let exp = p.caveats.first(where: { $0.get("type")?.asString == "expires" }), let at = IV.num(exp.get("at")) else {
            return XCTFail("an expires caveat")
        }
        XCTAssertGreaterThanOrEqual(at, Double(before + 86_400_000))
        XCTAssertLessThanOrEqual(at, Double(after + 86_400_000))
    }

    func testARepeatedActionKeepsOneLimitEntry() throws {
        let p = try PCAFacade.compilePolicy(permissions: [("pay", ["send", "send"])], limits: ["send": "$100"], catalog: pay, now: 1_000)
        XCTAssertEqual(p.limits.count, 1)
        XCTAssertEqual(rp(p, "bMax"), 100)
        XCTAssertEqual(rp(p, "kappa"), 100)
    }

    func testAPerSecondRateIsOneSecond() throws {
        let p = try PCAFacade.compilePolicy(permissions: [("pay", ["send"])], limits: ["send": "5/s"], catalog: pay, now: 1_000)
        guard let rate = p.caveats.first(where: { $0.get("type")?.asString == "rate" }) else { return XCTFail("a rate caveat") }
        XCTAssertEqual(IV.num(rate.get("per_secs")), 1)
        XCTAssertEqual(IV.num(rate.get("max")), 5)
    }

    func testDollarsModelTiersAndFloors() throws {
        // nothing irreversible granted: within-cap actions auto-approve (theta1 = theta2 = 1)
        let p = try PCAFacade.compilePolicy(permissions: [("pay", ["send"])], limits: ["send": "$100"], catalog: pay, now: 1_000)
        XCTAssertEqual(p.budgetModel, "dollars")
        XCTAssertEqual(rp(p, "theta1"), 1)
        XCTAssertEqual(rp(p, "theta2"), 1)
        // a sub-unit cap is kept as is
        let half = try PCAFacade.compilePolicy(permissions: [("pay", ["send"])], limits: ["send": "$0.5"], catalog: pay, now: 1_000)
        XCTAssertEqual(rp(half, "kappa"), 0.5)
        XCTAssertEqual(rp(half, "bMax"), 0.5)
        // a zero cap falls back to 1 for both kappa and bMax
        let zero = try PCAFacade.compilePolicy(permissions: [("pay", ["send"])], limits: ["send": "$0"], catalog: pay, now: 1_000)
        XCTAssertEqual(rp(zero, "kappa"), 1)
        XCTAssertEqual(rp(zero, "bMax"), 1)
    }

    func testRiskPolicyWeightsMergeMemberByMember() throws {
        let p = try PCAFacade.compilePolicy(permissions: [("pay", ["send"])], limits: ["send": "5/day"], catalog: pay,
                                            riskPolicy: ["weights": .object(["alpha": .double(0.3)])], now: 1_000)
        guard let w = p.riskPolicy[JKey("weights")]?.asObject else { return XCTFail("weights") }
        let want: [String: Double] = ["alpha": 0.3, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05]
        XCTAssertEqual(w.count, want.count)
        for (k, v) in want { XCTAssertEqual(IV.num(w[JKey(k)]), v, k) }
    }

    // ---- the agent ----

    func testAutonomyBoundAndAmountRiskUnderASubUnitCap() throws {
        let fa = try agent(limits: ["send": "$0.5"], now: 1_000)
        XCTAssertEqual(fa.autonomyBound, 0.5)
        let s = fa.policy.actions[0]
        XCTAssertEqual(fa.riskFor(s, .object(["amount": .double(0.25)]), nil), 0.5)
    }

    func testRiskOverrideIsClampedAndWins() throws {
        let fa = try agent(limits: ["send": "5/day"], now: 1_000)
        let s = fa.policy.actions[0]
        XCTAssertEqual(fa.riskFor(s, nil, 0.3), 0.3)
        XCTAssertEqual(fa.riskFor(s, nil, 1.5), 1)
        XCTAssertEqual(fa.riskFor(s, nil, nil), 0.9)
    }

    func testDryRunDefaultsToTheWallClock() throws {
        let day: Int64 = 86_400_000
        let stale = try agent(limits: ["send": "5/day"], now: wall() - 2 * day)
        XCTAssertEqual(stale.dryRun(verb: "pay.send", resource: "r"), PCADryRun(allowed: false, reason: "caveat(s) failed: expires", t: nil))
        let fresh = try agent(limits: ["send": "5/day"], now: wall())
        XCTAssertEqual(fresh.dryRun(verb: "pay.send", resource: "r"), PCADryRun(allowed: true, reason: nil, t: 3))
    }

    func testDryRunBudgetCoversACostEqualToIt() throws {
        let fa = try agent(limits: ["send": "$100"], now: 1_000)
        XCTAssertEqual(fa.budget.b, 100)
        XCTAssertEqual(fa.dryRun(verb: "pay.send", resource: "r", params: .object(["amount": .int(100)]), now: 2_000), PCADryRun(allowed: true, reason: nil, t: 1))
    }

    /// One act on an agent built at the wall clock: the budget starts now, the action is issued now, caution is signed, and the counter
    /// lock is taken once and released (a single act per agent here, so a lock left held cannot hang this class).
    func testActDefaultsAndTheCounterLock() throws {
        let before = wall()
        let fa = try agent(limits: ["send": "5/day"], now: nil)
        let r = try fa.act(verb: "pay.send", resource: "r", options: PCAActOptions(caution: 0.4))
        let after = wall()
        XCTAssertGreaterThanOrEqual(fa.budget.tau, Double(before))
        XCTAssertLessThanOrEqual(fa.budget.tau, Double(after))
        guard case let .int(iat)? = r.pcactn.get("iat") else { return XCTFail("iat") }
        XCTAssertGreaterThanOrEqual(iat, before)
        XCTAssertLessThanOrEqual(iat, after)
        XCTAssertEqual(r.pcactn.get("caution"), .double(0.4))
        XCTAssertEqual(r.pcactn.get("counter"), .int(1))
        XCTAssertEqual(fa.lock.acquisitions, 1)
        XCTAssertEqual(fa.lock.depth, 0)
        XCTAssertEqual(fa.lock.imbalance, 0)
    }

    func testSubAgentOfAHybridHolderGetsItsOwnKeyInTheSameSuite() throws {
        guard PCAPQKey.signingAvailable else { throw XCTSkip("ML-DSA signing is not available on this platform") }
        let holder = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: try PCAEdKey(seed: [UInt8](repeating: 4, count: 32)),
                                     pq: try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 5, count: 32)))
        let fa = try agent(limits: [:], now: 1_000, holder: holder)
        let sub = try fa.subAgent()
        XCTAssertEqual(sub.holder.alg, "hybrid-ed25519-ml-dsa-65")
        XCTAssertNotNil(sub.holder.pqPk)
        XCTAssertNotEqual(sub.holder.pqPk, holder.pqPk)
        XCTAssertEqual(sub.chain.count, 2)
    }
}
