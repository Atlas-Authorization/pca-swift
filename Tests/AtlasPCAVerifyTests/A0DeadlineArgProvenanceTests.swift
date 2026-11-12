import XCTest
import Foundation
@testable import AtlasPCAVerify

/// ArgProvenance.swift 524: the clip halves a long source until it fits (a dropped cut never ends).
final class A0DeadlineArgProvenanceTests: XCTestCase {
    func testA1ClipHalvesLongSources() {
        let long = String(repeating: "a", count: 300)
        let got: String? = S2Deadline.within(10, "clip") { (try? ProvenanceRecorder.clip(long)) ?? "" }
        XCTAssertEqual(got, String(repeating: "a", count: 150), "line 524")
    }
}
