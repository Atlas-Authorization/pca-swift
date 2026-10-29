import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The pca-goal conformance corpus (packages/pca-conformance/vectors/goal; vendored as conformance/goal in the mirrors) and the
/// selector corpus next to it (goal-select): goal digest, lowered policy digest, decision + witness of every probe, the helper
/// vectors, and the native expansion of trait selectors. The semantics are the shared runner
/// (packages/pca-conformance/runners/goal/swift/GoalReplay.swift; GoalReplay.swift in this directory is its generated copy), so
/// every language replays one reference.
final class GoalVectorTests: XCTestCase {
    /// The mirrors vendor the corpus at <conformance>/goal; the monorepo keeps it at packages/pca-conformance/vectors/goal.
    static let goalDir: URL = {
        let vendored = ConformanceTests.conformanceDir.appendingPathComponent("goal", isDirectory: true)
        if FileManager.default.fileExists(atPath: vendored.appendingPathComponent("index.json").path) { return vendored }
        return ConformanceTests.conformanceDir.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("packages/pca-conformance/vectors/goal", isDirectory: true)
    }()

    func testIndexMatchesTheFiles() throws {
        let idx = try StrictJSON.parseLenient(ConformanceTests.readText(Self.goalDir.appendingPathComponent("index.json")))
        XCTAssertEqual(idx.get("format")?.asString, "pca-goal-vectors/2")
        let names = try FileManager.default.contentsOfDirectory(atPath: Self.goalDir.path).filter { $0.hasSuffix(".json") && $0 != "index.json" }
        let counts = idx.get("counts")?.asObject ?? [:]
        let total = counts.values.reduce(Int64(0)) { $0 + ($1.safeInt ?? 0) }
        XCTAssertEqual(Int64(names.count), total, "index.json counts do not match the vector files")
        XCTAssertEqual(idx.get("cases")?.asArray?.count, names.count)
    }

    func testGoalDigestsDecisionsAndHelperVectors() throws {
        let (n, probes, bad) = try goalReplay(Self.goalDir.path)
        XCTAssertGreaterThanOrEqual(n, 240)
        XCTAssertGreaterThan(probes, 6000)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) disagreements:\n" + bad.prefix(30).joined(separator: "\n"))
    }

    func testSelectorVectorsExpandAndDecideAsTheReference() throws {
        let dir = Self.goalDir.deletingLastPathComponent().appendingPathComponent("goal-select", isDirectory: true)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path), "the selector vectors are missing: \(dir.path)")
        let (n, probes, bad) = try goalReplay(dir.path)
        XCTAssertGreaterThanOrEqual(n, 48)
        XCTAssertGreaterThan(probes, 1000)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) disagreements:\n" + bad.prefix(30).joined(separator: "\n"))
    }
}
