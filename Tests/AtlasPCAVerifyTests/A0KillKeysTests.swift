import XCTest
@testable import AtlasPCAVerify

/// Keys.swift 73 / 78: the signing test seam is off by default, and on it reports no ML-DSA signing.
final class A0KillKeysTests: XCTestCase {
    func testSeamIsOffByDefault() {
        XCTAssertFalse(PCAPQKey.signingDisabledForTests, "line 78")
        #if canImport(CryptoKit)
        XCTAssertEqual(PCAPQKey.signingAvailable, MLDSA.available, "line 78: the platform decides by default")
        #elseif canImport(COQS)
        XCTAssertTrue(PCAPQKey.signingAvailable, "line 78: liboqs signs by default")
        #endif
    }

    func testSeamOnReportsNoSigning() {
        let before = PCAPQKey.signingDisabledForTests
        PCAPQKey.signingDisabledForTests = true
        defer { PCAPQKey.signingDisabledForTests = before }
        XCTAssertFalse(PCAPQKey.signingAvailable, "line 73")
        XCTAssertThrowsError(try PCAPQKey.generate(.mlDsa65), "line 73: no key is made")
    }

    /// Keys.swift 112 (liboqs): the secret key is kept at its full length, so a signature from a generated key verifies.
    func testGeneratedKeySignsAVerifiableSignature() throws {
        #if !os(Linux)
        try XCTSkipUnless(PCAPQKey.signingAvailable, "ML-DSA signing needs OS 26")
        #endif
        let msg: [UInt8] = [1, 2, 3, 4]
        let k65 = try PCAPQKey.generate(.mlDsa65)
        let sig65 = try k65.signFn(msg)
        XCTAssertTrue(MLDSA.verify(.mlDsa65, publicKey: k65.pk, message: msg, signature: sig65), "line 112: ML-DSA-65 round trip")
        let k87 = try PCAPQKey.generate(.mlDsa87)
        let sig87 = try k87.signFn(msg)
        XCTAssertTrue(MLDSA.verify(.mlDsa87, publicKey: k87.pk, message: msg, signature: sig87), "line 112: ML-DSA-87 round trip")
    }
}
