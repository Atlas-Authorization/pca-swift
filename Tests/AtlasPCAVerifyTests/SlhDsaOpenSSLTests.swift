import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL

/// SLH-DSA through libcrypto 3.5+ (ATLAS_PCA_OPENSSL=1): every SLH-DSA case of producer-pq-vectors.json (key generation from the FIPS 205 seed, then the
/// deterministic signatures of the suites, hybrids, PCActns, minted roots, delegations and artifacts) reproduces the reference byte for byte, and a
/// signed PCActn verifies through the core verifier. Without the backend the suites are refused (the core tests cover that).
final class SlhDsaOpenSSLTests: XCTestCase {
    override func setUpWithError() throws {
        PCASlhDsaHook.unregister()
        guard PCAOpenSSL.registerSlhDsa() else {
            if ProcessInfo.processInfo.environment["CI"] != nil { XCTFail("libcrypto without SLH-DSA (needs 3.5+)") }
            throw XCTSkip("libcrypto without SLH-DSA (needs 3.5+)")
        }
    }

    override func tearDown() { PCASlhDsaHook.unregister() }

    func testProducerVectorsMatchTheReferenceByteForByte() throws {
        let f = try ProducerVectorsTests.VectorFile("producer-pq-vectors.json")
        var n = 0
        var failures: [String] = []
        for (i, c) in f.cases.enumerated() {
            let alg = c.get("args")?.get("alg")?.asString ?? c.get("args")?.get("family")?.asString ?? ""
            guard alg.contains("slh-dsa") else { continue }
            n += 1
            do {
                let got = try f.produce(i)
                if ProducerVectorsTests.canon(got) != ProducerVectorsTests.canon(c.get("expect") ?? .null) { failures.append("\(c.get("name")?.asString ?? "?"): output differs") }
            } catch { failures.append("\(c.get("name")?.asString ?? "?"): \(error)") }
        }
        XCTAssertGreaterThanOrEqual(n, 30)
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }

    func testSignedHybridPCActnVerifiesAndTamperingFails() throws {
        for fam in PCASlhDsaHook.families {
            let seed = [UInt8](repeating: 7, count: PCASlhDsaHook.seedBytes[fam]!)
            let key = try PCASlhDsaKey.fromSeed(fam, seed: seed)
            XCTAssertEqual(key.vk.count, PCASlhDsaHook.pkBytes[fam])
            let msg = Array("slh-dsa message".utf8)
            let sig = try PCASlhDsaHook.currentSigner!.sign(fam, key.sk, msg)
            XCTAssertEqual(sig.count, PCASlhDsaHook.sigBytes[fam])
            XCTAssertTrue(PCASlhDsaHook.verify(fam, vk: key.vk, msg: msg, sig: sig))
            // deterministic: the same key and message give the same bytes
            XCTAssertEqual(sig, try PCASlhDsaHook.currentSigner!.sign(fam, key.sk, msg))
            // the empty message is signable and verifiable
            let e = try PCASlhDsaHook.currentSigner!.sign(fam, key.sk, [])
            XCTAssertTrue(PCASlhDsaHook.verify(fam, vk: key.vk, msg: [], sig: e))
            var bad = sig
            bad[bad.count / 2] ^= 1
            XCTAssertFalse(PCASlhDsaHook.verify(fam, vk: key.vk, msg: msg, sig: bad))
            XCTAssertFalse(PCASlhDsaHook.verify(fam, vk: key.vk, msg: Array("other".utf8), sig: sig))
            XCTAssertFalse(PCASlhDsaHook.verify(fam, vk: key.vk, msg: msg, sig: Array(sig.dropLast())))
            XCTAssertFalse(PCASlhDsaHook.verify(fam, vk: Array(key.vk.dropLast()), msg: msg, sig: sig))
        }
    }

    func testSuiteRefusedAgainAfterUnregister() throws {
        PCASlhDsaHook.unregister()
        XCTAssertNil(PQ.resolve("slh-dsa-sha2-128f"))
        XCTAssertThrowsError(try PCASlhDsaKey.fromSeed("SLH-DSA-SHA2-128f", seed: [UInt8](repeating: 1, count: 48))) {
            XCTAssertEqual("\($0)", "unsupported_suite: slh-dsa-sha2-128f")
        }
    }
}
#endif
