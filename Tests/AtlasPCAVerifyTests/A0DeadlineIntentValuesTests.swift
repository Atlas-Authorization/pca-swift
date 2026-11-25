import XCTest
import Foundation
@testable import AtlasPCAVerify

final class A0DeadlineIntentValuesTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// IntentValues.swift 44: the digit scanner advances one byte per digit.
    func testJsNumberScansDigits() {
        let got: [Double]? = S2Deadline.within(10, "jsNumber") { [IV.jsNumber("123"), IV.jsNumber("12.5e1"), IV.jsNumber("-7"), IV.jsNumber(".5")] }
        XCTAssertEqual(got, [123, 125, -7, 0.5], "line 44")
    }

}
