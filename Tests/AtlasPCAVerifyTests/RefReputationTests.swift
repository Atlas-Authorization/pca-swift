import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Reputation, coverage pricing, the signed coverage quote and the insurance pool against the reference: the module's own corpus (the validator
/// and the fail-closed edges) in full, and its cases of the shared sweep corpus (scoring, pricing, quotes, pool scripts, the policy recommender).
final class RefReputationTests: XCTestCase {
    typealias A = RefAnalyzer
    typealias R = Reputation

    private static func d(_ v: JSONValue?) -> Double { IV.num(v) ?? Double.nan }
    private static func opts(_ v: JSONValue?) -> R.PricingOptions {
        R.PricingOptions(baseRate: IV.num(v?.get("baseRate")), riskLoad: IV.num(v?.get("riskLoad")), minScore: IV.num(v?.get("minScore")))
    }

    private static func pool(_ ops: [JSONValue]) -> JSONValue {
        var pool: InsuranceCapitalPool?
        return .array(ops.map { item in
            let op = item.asArray ?? []
            func arg(_ i: Int) -> JSONValue? { i < op.count ? op[i] : nil }
            do {
                if arg(0)?.asString == "new" {
                    // `new InsuranceCapitalPool(undefined)` starts at 0; anything else must be a number
                    pool = try InsuranceCapitalPool(initial: arg(1) == nil ? 0 : d(arg(1)))
                    return A.out(pool!.state())
                }
                guard let p = pool else { throw PCAProducerError("no pool") }
                switch arg(0)?.asString {
                case "quote": return A.out(p.quote(score: d(arg(1)?.get("score")), exposure: d(arg(2)), opts(arg(3))).json)
                case "collect":
                    let r = try p.collectPremium(score: d(arg(1)?.get("score")), exposure: d(arg(2)), opts(arg(3)))
                    return A.out(.object(["pricing": r.pricing.json, "state": r.state]))
                case "canCover": return .bool(p.canCover(d(arg(1))))
                case "pay": return A.out(try p.payClaim(d(arg(1))))
                case "state": return A.out(p.state())
                default: throw PCAProducerError("op")
                }
            } catch { return RefCoreSweepTests.err }
        })
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3), a4 = A.arg(c, 4)
        switch c.fn {
        case "constants":
            return .value(.object(["MAX_REPUTATION_RECORDS": .int(Int64(R.MAX_REPUTATION_RECORDS)), "COVERAGE_QUOTE_DOMAIN": .string(R.COVERAGE_QUOTE_DOMAIN)]))
        case "validateReputationInput": return .value(Base.opt(R.validateReputationInput(a0)))
        case "reputation": return A.run { R.reputation(a0) }
        case "priceCoverage": return A.run { R.priceCoverage(score: d(a0?.get("score")), exposure: d(a1), opts(a2)).json }
        case "issueCoverageQuote":
            return A.run {
                try R.issueCoverageQuote(rep: a0 ?? .null, exposure: d(a1), underwriter: try A.key("sweep/underwriter"), now: d(a2), ttlMs: d(a3), opts(JS.present(a4)))
            }
        case "verifyCoverageQuote":
            return A.run {
                let pinned = a1?.asString == "@u" ? Base64URLStrict.encode(try A.key("sweep/underwriter").pub) : (a1?.asString ?? "")
                return R.verifyCoverageQuote(a0, underwriter: pinned, now: d(JS.present(a2)))
            }
        case "pool": return .value(pool(a0?.asArray ?? []))
        case "recommendPolicy", "autonomyBoundOf": return RefBudgetForecastTests.call(c)
        default: return nil
        }
    }

    func testEveryCaseOfTheModuleCorpus() throws {
        let diffs = Base.Diffs()
        let n = try Base.each("ref-reputation.json.gz") { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            diffs.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 85)
        diffs.finish(85)
    }

    /// The reputation, pricing, quote, pool and recommender cases of the shared sweep corpus (the chain, receipt, budget and approval cases are replayed
    /// by RefCoreSweepTests, the signal cases by the frontier-signals replay).
    func testTheSweepCorpusCases() throws {
        let fns: Set<String> = ["reputation", "priceCoverage", "issueCoverageQuote", "verifyCoverageQuote", "pool", "recommendPolicy", "autonomyBoundOf"]
        let diffs = Base.Diffs()
        let n = try Base.each(RefCoreSweepTests.file, fns) { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            diffs.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 473) // 48 + 226 + 43 + 27 + 9 + 110 + 10
        diffs.finish(473)
    }

    func testTheRecordCapAndThePool() throws {
        let event = K042.parse(#"{"agent":"a","outcome":"auto"}"#)
        let many: JSONValue = .object(["subject": .string("s"), "events": .array([JSONValue](repeating: event, count: R.MAX_REPUTATION_RECORDS + 1))])
        XCTAssertEqual(R.validateReputationInput(many), "too many records")
        XCTAssertEqual(R.reputation(many).get("score"), .int(0))
        let pool = try InsuranceCapitalPool(initial: 100)
        XCTAssertTrue(try pool.collectPremium(score: 0.1, exposure: 1000).pricing.declined)
        XCTAssertEqual(pool.balance, 100)
        _ = try pool.collectPremium(score: 1, exposure: 1000)
        XCTAssertEqual(pool.balance, 110)
        XCTAssertThrowsError(try pool.payClaim(111))
        XCTAssertFalse(pool.canCover(111))
        XCTAssertThrowsError(try InsuranceCapitalPool(initial: -1))
        let quote = try R.issueCoverageQuote(rep: R.reputation(K042.parse(#"{"subject":"s"}"#)), exposure: 10, underwriter: try PCAEdKey(seed: [UInt8](repeating: 3, count: 32)), now: 5, ttlMs: 10)
        let uw = quote.get("underwriter")?.asString ?? ""
        XCTAssertEqual(R.verifyCoverageQuote(quote, underwriter: uw, now: 6).get("ok"), .bool(true))
        XCTAssertEqual(R.verifyCoverageQuote(quote, underwriter: uw, now: 15).get("reason"), .string("expired"))
    }
}
