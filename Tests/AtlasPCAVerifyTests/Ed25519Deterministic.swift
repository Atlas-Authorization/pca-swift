import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

final class Ed25519DeterministicTests: XCTestCase {
    private func hex(_ s: String) -> [UInt8] {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return out
    }

    /// RFC 8032 section 7.1, TEST 1 (empty message).
    func testRfc8032Vector1() throws {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        XCTAssertEqual(Ed25519Deterministic.publicKey(seed: seed), hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
        XCTAssertEqual(Ed25519Deterministic.sign(seed: seed, []),
                       hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"))
        XCTAssertEqual(try PCAEdKey(seed: seed).pub, Ed25519Deterministic.publicKey(seed: seed))
    }

    /// The platform signer and the deterministic one both verify under the strict verifier, for the same key.
    func testPlatformSignaturesVerify() throws {
        let seed = [UInt8](repeating: 9, count: 32)
        let k = try PCAEdKey(seed: seed)
        let msg = Array("atlas".utf8)
        XCTAssertTrue(Ed25519Strict.verify(publicKey: k.pub, message: msg, signature: try k.sign(msg)))
        XCTAssertTrue(Ed25519Strict.verify(publicKey: k.pub, message: msg, signature: Ed25519Deterministic.sign(seed: seed, msg)))
        XCTAssertFalse(Ed25519Strict.verify(publicKey: k.pub, message: msg + [0], signature: Ed25519Deterministic.sign(seed: seed, msg)))
    }
}
