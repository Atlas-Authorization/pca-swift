import XCTest
@testable import AtlasPCAVerify

final class PqThresholdLatticeTests: XCTestCase {
    typealias L = PCALatticeThresholdToy
    let ok = L.OptIn(iUnderstandThisIsNotProduction: true)

    func testSharesSumToTheKeyAndEveryShareIsNeeded() throws {
        let key: [Int64] = [5, -3, 8_380_417 + 9, 0]
        var ctr: UInt64 = 0
        let sampler: L.Sampler = { q in ctr += 1_234_567; return ctr % q }
        let shares = try L.additiveShareLatticeKey(key, n: 3, optIn: ok, sampler: sampler)
        XCTAssertEqual(shares.count, 3)
        let q = L.Params.default.q
        let want: [UInt64] = key.map { $0 >= 0 ? UInt64($0) % q : (q - $0.magnitude % q) % q }
        XCTAssertEqual(try L.reconstructLatticeKey(shares, optIn: ok), want)
        XCTAssertNotEqual(try L.reconstructLatticeKey(Array(shares[..<2]), optIn: ok), want)
        XCTAssertThrowsError(try L.reconstructLatticeKey([shares[0], shares[0]], optIn: ok)) { XCTAssertTrue("\($0)".contains("duplicate")) }
    }

    func testNothingRunsWithoutTheOptInAndBadShapesAreRefused() {
        let no = L.OptIn()
        XCTAssertThrowsError(try L.additiveShareLatticeKey([0, 0, 0, 0], n: 2, optIn: no)) { XCTAssertTrue("\($0)".hasPrefix("EXPERIMENTAL")) }
        XCTAssertThrowsError(try L.reconstructLatticeKey([], optIn: no)) { XCTAssertTrue("\($0)".hasPrefix("EXPERIMENTAL")) }
        XCTAssertThrowsError(try L.additiveShareLatticeKey([0, 0, 0, 0], n: 0, optIn: ok))
        XCTAssertThrowsError(try L.additiveShareLatticeKey([0, 0, 0, 0], n: 1025, optIn: ok))
        XCTAssertThrowsError(try L.additiveShareLatticeKey([0, 0, 0], n: 2, optIn: ok))
        XCTAssertNoThrow(try L.additiveShareLatticeKey([0, 0, 0, 0], n: 2, optIn: ok))
    }
}
