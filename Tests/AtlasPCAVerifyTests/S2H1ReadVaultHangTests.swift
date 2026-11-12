import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for ReadVault.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1ReadVaultHangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testBernExpSmallCounterAdvances() {
        let got = dl("bernExpSmall") { "\((try? ReadVault.bernExpSmall(ReadVault.seededDraws("s2h1"), 1, 1)) != nil)" }
        XCTAssertEqual(got, "true", "ReadVault.swift:313")
    }

    func testMemoryVaultTakesItsLock() {
        let v = MemoryVault()
        S2LK.check(v.lock, "MemoryVault.put") { v.put("t", VaultEntry(cls: "c", value: .string("v"), grant: "g", exp: 1)) }
        XCTAssertEqual(S2LK.check(v.lock, "MemoryVault.get") { v.get("t") }?.cls, "c")
    }
}
