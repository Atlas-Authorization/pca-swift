import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the executable examples and property checks of an action pack.
final class RefActionsRunnerTests: XCTestCase {
    func testRunner() throws {
        try K042.requireCovers(["ActionTestRunner", "ActionSchema", "ActionAuthor"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each("ref-actions-test-runner.json.gz") { c in
            let a0 = c.arg(0)
            let got: BaseGot
            switch c.fn {
            case "decideExample": got = RefActions.v { try ActionTestRunner.decideExample(RefActions.obj(a0), RefActions.obj(c.arg(1)), core, RefActions.list(c.arg(2))) }
            case "runDefTests": got = RefActions.v { try ActionTestRunner.runDefTests(RefActions.list(a0), core, c.arg(1).flatMap { IV.int($0) }.map { Int($0) }, nil) }
            case "testText": got = .value(.string(ActionTestRunner.testText(RefActions.obj(a0))))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(45)
    }
}
