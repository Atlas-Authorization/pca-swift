import XCTest
@testable import AtlasPCAVerify

/// RFC 9496: a ristretto255 encoding with bit 255 set is a non-canonical alias; libsodium 1.0.18 ignores that bit, so the lane refuses it itself.
final class RistrettoBit255Tests: XCTestCase {
    private let gen: [UInt8] = [0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
                                0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76]

    func testHighBitAliasIsRefused() throws {
        var alias = gen
        alias[31] |= 0x80
        XCTAssertTrue(RatchetGroup.isValid(gen))
        XCTAssertFalse(RatchetGroup.isValid(alias))
        XCTAssertEqual(try PCAOprf.deserializeElement(gen), gen)
        XCTAssertThrowsError(try PCAOprf.deserializeElement(alias))
    }
}
