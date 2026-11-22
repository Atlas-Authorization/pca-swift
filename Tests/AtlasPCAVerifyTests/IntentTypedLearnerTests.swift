import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The learner over the typed outcome space: the typed entry point and the learner's own space agree with the JSON one.
final class IntentTypedLearnerTests: XCTestCase {
    let omegaJSON = #"{"v":1,"verbs":[{"verb":"pay","reversibility":"reversible","weight":1,"dims":[{"kind":"num","path":"amount","lo":0,"hi":100,"cuts":[10,50],"dist":"uniform"}]}],"approximate":[]}"#

    func testTheTypedEntryPointBuildsTheSameLearner() throws {
        let json = try StrictJSON.parse(omegaJSON)
        let typed = try PCAIntentOmega.omegaFromJson(json)
        let a = try PCAIntentLearner(omega: json)
        let b = try PCAIntentLearner(typed: typed)
        XCTAssertEqual(a.synthesize(), b.synthesize())
        XCTAssertEqual(PCAIntentOmega.omegaToJson(try b.typedOmega()), PCAIntentOmega.omegaToJson(typed))
        XCTAssertEqual(try b.typedOmega().verbs.map { $0.verb }, ["pay"])
    }

    func testTheTypedRefinementEqualsTheJsonOne() throws {
        let json = try StrictJSON.parse(omegaJSON)
        var r = PCAIntentRefine.Refinement(verb: "pay", path: "amount")
        r.cuts = [25]
        let typed = try PCAIntentRefine.refineOmega(typed: try PCAIntentOmega.omegaFromJson(json), r)
        XCTAssertEqual(PCAIntentOmega.omegaToJson(typed), PCAIntentOmega.omegaToJson(try PCAIntentOmega.omegaFromJson(try PCAIntentRefine.refineOmega(json, r))))
    }
}
