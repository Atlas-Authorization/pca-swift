import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for AttestJWS.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1AttestJWSHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testV8JsonValidatorTerminates() {
        XCTAssertEqual(dl("v8 valid document") { V8JSON.error(" {\"a\": [12.5e+3, \"x\\n\", true]} ") }, "", "AttestJWS.swift:232,269,305,345")
        XCTAssertEqual(dl("v8 number") { V8JSON.error("12") }, "", "AttestJWS.swift:269 isDigit at the end of input")
        XCTAssertEqual(dl("v8 exponent") { V8JSON.error("1e5") }, "", "AttestJWS.swift:305")
        XCTAssertEqual(dl("v8 location") { let p = V8JSON(src: Array("ab\ncd".utf16)); let l = p.location(4); return "\(l.0),\(l.1)" }, "2,2", "AttestJWS.swift:190")
    }
}
