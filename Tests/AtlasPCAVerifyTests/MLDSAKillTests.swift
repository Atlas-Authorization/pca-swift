import XCTest
@testable import AtlasPCAVerify

/// Right-length garbage is never a valid ML-DSA signature, on every platform: below OS 26 (no CryptoKit ML-DSA: the fall-through
/// refusal), on OS 26 (CryptoKit) and on Linux (liboqs).
final class MLDSAKillTests: XCTestCase {
    func testRightLengthGarbageIsRefusedAtBothLevels() {
        for level in [MLDSA.Level.mlDsa65, .mlDsa87] {
            let (pkLen, sigLen) = MLDSA.lens(level)
            for fill: UInt8 in [0, 0x5a, 0xff] {
                XCTAssertFalse(MLDSA.verify(level, publicKey: [UInt8](repeating: fill, count: pkLen), message: [1, 2, 3],
                                            signature: [UInt8](repeating: fill, count: sigLen)), "\(level) fill \(fill)")
            }
        }
    }
}
