import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for Authorize.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1AuthorizeHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testMemoryStateStoreClaimTakesItsLock() {
        let s = MemoryStateStore()
        XCTAssertTrue(S2LK.check(s.lock, "MemoryStateStore.claim") { s.claim(key: "k", counter: 1) }.ok)
        XCTAssertFalse(S2LK.check(s.lock, "MemoryStateStore.claim (replay)") { s.claim(key: "k", counter: 1) }.ok)
    }
}
