import XCTest
@testable import AtlasPCAVerify

/// chipInSubject refuses an empty chip name explicitly. The reference's `(^|[^A-Za-z0-9])CHIP([^A-Za-z0-9]|$)` with an empty CHIP
/// matches any subject holding a separator (or the empty subject); Swift stays strict, as before the rewrite.
final class AttestNvidiaRimChipGuardRestoreTests: XCTestCase {
    func testAnEmptyChipNameMatchesNoSubject() {
        for s in ["", " ", ",", "/:", "CN=GH100, O=NVIDIA"] { XCTAssertFalse(NvidiaHook.chipInSubject(s, ""), s) }
    }

    func testANonEmptyChipStillMatches() {
        XCTAssertTrue(NvidiaHook.chipInSubject("CN=GH100, O=NVIDIA", "GH100"))
    }
}
