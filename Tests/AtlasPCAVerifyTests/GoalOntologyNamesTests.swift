import XCTest
import AtlasPCAVerify // public surface only

/// The reference's `ALL_ONTOLOGIES` and its five named exports.
final class GoalOntologyNamesTests: XCTestCase {
    static func m(_ v: JSONValue?, _ k: String) -> JSONValue? { if case let .object(o)? = v { return o[JKey(k)] }; return nil }

    func testAllOntologiesAndNamedExports() throws {
        let all = try PCAGoalOntologies.ALL_ONTOLOGIES
        XCTAssertEqual(Set(all.keys), ["payments", "email", "calendar_travel", "code_repos", "data_access"])
        XCTAssertEqual(try PCAGoalOntologies.data(), all["data_access"])
        XCTAssertEqual(try PCAGoalOntologies.payments(), all["payments"])
        XCTAssertEqual(try PCAGoalOntologies.email(), all["email"])
        XCTAssertEqual(try PCAGoalOntologies.travel(), all["calendar_travel"])
        XCTAssertEqual(try PCAGoalOntologies.code(), all["code_repos"])
        XCTAssertEqual(Self.m(try PCAGoalOntologies.data(), "id"), .string("atlas.data"))
        XCTAssertEqual(Self.m(try PCAGoalOntologies.data(), "domain"), .string("data_access"))
        for (name, o) in all { XCTAssertEqual(Self.m(o, "domain"), .string(name), "each ontology is keyed by its own domain") }
    }
}
