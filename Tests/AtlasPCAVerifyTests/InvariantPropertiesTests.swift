import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Runs the seeded safety-invariant property suite over the real core at the default seed and run count.
final class InvariantPropertiesTests: XCTestCase {
    func testEveryInvariantHoldsAtTheDefaultSeed() throws {
        let results = try PCAInvariants.checkInvariants()
        XCTAssertEqual(results.count, PCAInvariants.INVARIANT_NAMES.count)
        for (i, res) in results.enumerated() {
            XCTAssertEqual(res.get("name")?.asString, PCAInvariants.INVARIANT_NAMES[i])
            XCTAssertEqual(res.get("ok"), .bool(true), "\(res.get("name")?.asString ?? ""): \(res.get("error")?.asString ?? "")")
            XCTAssertEqual(res.get("numRuns"), .int(Int64(PCAInvariants.DEFAULT_NUM_RUNS)))
            XCTAssertEqual(res.get("seed"), .int(Int64(PCAInvariants.DEFAULT_SEED)))
        }
    }

    func testTheRegistryMatchesTheNameList() { XCTAssertEqual(PCAInvariants.INVARIANTS.map { $0.name }, PCAInvariants.INVARIANT_NAMES) }

    func testTheSameSeedGeneratesTheSameCases() {
        let a = PCAInvariantRng(Int64(PCAInvariants.DEFAULT_SEED)), b = PCAInvariantRng(Int64(PCAInvariants.DEFAULT_SEED))
        for _ in 0..<100 { XCTAssertEqual(a.next(), b.next()) }
        XCTAssertEqual(PCAInvariantRng(1).string(0, 10), PCAInvariantRng(1).string(0, 10))
        XCTAssertEqual(PCAInvariantRng(7).bytes(32), PCAInvariantRng(7).bytes(32))
    }

    /// mulberry32's first outputs for seed 1 (the reference generator's well-known sequence).
    func testTheGeneratorIsMulberry32() {
        let r = PCAInvariantRng(1)
        XCTAssertEqual(r.next(), 0.6270739405881613)
        XCTAssertEqual(r.next(), 0.002735721180215478)
    }

    func testAViolatedPropertyFailsTheRunWithItsIndex() throws {
        XCTAssertThrowsError(try PCAInvariants.run({ $0.next() < 0.5 }, numRuns: 1000, seed: 1)) {
            XCTAssertTrue("\($0)".contains("Property failed after"))
        }
        try PCAInvariants.run({ _ in true }, numRuns: 10, seed: 1)
    }

    func testAPropertyThatThrowsFails() {
        XCTAssertThrowsError(try PCAInvariants.run({ _ in throw JSError("boom") }, numRuns: 5, seed: 1))
    }

    func testACheckOfZeroCasesIsRefused() {
        XCTAssertThrowsError(try PCAInvariants.checkInvariants(numRuns: 0))
        XCTAssertThrowsError(try PCAInvariants.checkInvariants(numRuns: -3))
        XCTAssertThrowsError(try PCAInvariants.checkInvariants(numRuns: 5, seed: 9007199254740992))
    }

    func testBailStopsAtTheFirstFailure() throws {
        let all = try PCAInvariants.checkInvariants(numRuns: 5, seed: 3, bail: true)
        XCTAssertFalse(all.isEmpty)
        XCTAssertLessThanOrEqual(all.count, PCAInvariants.INVARIANT_NAMES.count)
    }

    func testTheGeneratorsAreDeterministicPerSeed() throws {
        XCTAssertEqual(PCAInvariants.arbPredicateList(PCAInvariantRng(9)), PCAInvariants.arbPredicateList(PCAInvariantRng(9)))
        XCTAssertEqual(try PCAInvariants.arbChain(PCAInvariantRng(9)).rootIssuer, try PCAInvariants.arbChain(PCAInvariantRng(9)).rootIssuer)
    }
}
