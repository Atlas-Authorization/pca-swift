import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Both ML-DSA backends (CryptoKit where the OS has it, the vendored CMLDSA target on every platform) must give the reference's verdict on the reference's own signatures:
/// the ML-DSA-65 quorum signatures the TypeScript reference made (`signPqQuorum` cases of ref-frost-net), each over its quorum representative.
final class MlDsaBackendsTests: XCTestCase {
    private struct Vector { let name: String; let pk: [UInt8]; let msg: [UInt8]; let sig: [UInt8] }

    private func vectors() throws -> [Vector] {
        var out: [Vector] = []
        try Base.each("ref-frost-net.json.gz", ["signPqQuorum"], seeds: true) { c in
            guard let message = Base.bytes(c.arg(0)), let signers = c.out.get("signers")?.asArray else { return }
            let rep = PCAFrostPq.pqQuorumRepresentative(message)
            for (i, s) in signers.enumerated() {
                guard let pk = s.get("pk")?.asString.flatMap({ Base64URLStrict.decode($0) }), let sig = s.get("sig")?.asString.flatMap({ Base64URLStrict.decode($0) }) else { continue }
                out.append(Vector(name: "\(c.name)#\(i)", pk: pk, msg: rep, sig: sig))
            }
        }
        return out
    }

    func testEveryBackendAcceptsTheReferenceSignaturesAndRefusesAnEditedOne() throws {
        let vs = try vectors()
        XCTAssertGreaterThan(vs.count, 5)
        var cryptoKit = 0, vendored = 0
        for v in vs {
            var bad = v.sig; bad[0] ^= 1
            var otherMsg = v.msg; otherMsg[otherMsg.count - 1] ^= 1
            if let ck = MLDSA.verifyCryptoKit(.mlDsa65, publicKey: v.pk, message: v.msg, signature: v.sig) {
                cryptoKit += 1
                XCTAssertTrue(ck, "CryptoKit: \(v.name)")
                XCTAssertEqual(MLDSA.verifyCryptoKit(.mlDsa65, publicKey: v.pk, message: v.msg, signature: bad), false, "CryptoKit edited signature: \(v.name)")
                XCTAssertEqual(MLDSA.verifyCryptoKit(.mlDsa65, publicKey: v.pk, message: otherMsg, signature: v.sig), false, "CryptoKit edited message: \(v.name)")
            }
            vendored += 1
            XCTAssertTrue(MLDSA.verifyVendored(.mlDsa65, publicKey: v.pk, message: v.msg, signature: v.sig), "vendored: \(v.name)")
            XCTAssertFalse(MLDSA.verifyVendored(.mlDsa65, publicKey: v.pk, message: v.msg, signature: bad), "vendored edited signature: \(v.name)")
            XCTAssertFalse(MLDSA.verifyVendored(.mlDsa65, publicKey: v.pk, message: otherMsg, signature: v.sig), "vendored edited message: \(v.name)")
            XCTAssertTrue(MLDSA.verify(.mlDsa65, publicKey: v.pk, message: v.msg, signature: v.sig), "the dispatching verify: \(v.name)")
        }
        // the vendored backend is on every platform, so it runs every vector everywhere; CryptoKit also does on OS 26
        XCTAssertEqual(vendored, vs.count, "the vendored backend must run every vector")
        if cryptoKit > 0 { XCTAssertEqual(cryptoKit, vs.count, "CryptoKit must run every vector") }
    }

    /// The vendored target keys and signs at both levels on every platform: the seed fixes the key (and, where CryptoKit has ML-DSA, is the same key CryptoKit
    /// derives), a random key differs, its signatures verify on every present backend and fail once edited, and a short secret key is refused.
    func testVendoredKeysAndSignaturesAtBothLevels() throws {
        let msg: [UInt8] = Array("backend cross-check".utf8)
        let seed = [UInt8](repeating: 0x2a, count: 32)
        for (level, plevel, pkLen, skLen, sigLen) in [(MLDSA.Level.mlDsa65, PCAMLDSALevel.mlDsa65, 1952, 4032, 3309), (.mlDsa87, .mlDsa87, 2592, 4896, 4627)] {
            let a = try XCTUnwrap(MLDSA.vendoredKeyPair(level, seed: seed), "\(level)")
            let b = try XCTUnwrap(MLDSA.vendoredKeyPair(level, seed: seed), "\(level)")
            XCTAssertEqual(a.pk, b.pk, "\(level): the seed fixes the public key")
            var lastByte = seed; lastByte[31] ^= 1
            var firstByte = seed; firstByte[0] ^= 1
            XCTAssertNotEqual(try XCTUnwrap(MLDSA.vendoredKeyPair(level, seed: lastByte)).pk, a.pk, "\(level): every seed byte counts (last)")
            XCTAssertNotEqual(try XCTUnwrap(MLDSA.vendoredKeyPair(level, seed: firstByte)).pk, a.pk, "\(level): every seed byte counts (first)")
            XCTAssertEqual(a.sk, b.sk, "\(level): the seed fixes the secret key")
            XCTAssertEqual([a.pk.count, a.sk.count], [pkLen, skLen], "\(level) sizes")
            let r1 = try XCTUnwrap(MLDSA.vendoredKeyPair(level, seed: nil)), r2 = try XCTUnwrap(MLDSA.vendoredKeyPair(level, seed: nil))
            XCTAssertNotEqual(r1.pk, r2.pk, "\(level): random keys differ")
            XCTAssertNotEqual(r1.pk, a.pk, "\(level): a random key is not the seeded one")
            if MLDSA.verifyCryptoKit(level, publicKey: a.pk, message: msg, signature: [UInt8](repeating: 0, count: sigLen)) != nil {
                XCTAssertEqual(try PCAPQKey.fromSeed(plevel, seed: seed).pk, a.pk, "\(level): CryptoKit derives the same key from the seed")
            }
            let sig = try XCTUnwrap(MLDSA.vendoredSign(level, secretKey: a.sk, message: msg), "\(level)")
            XCTAssertEqual(sig.count, sigLen, "\(level) signature size")
            XCTAssertNotEqual(sig, MLDSA.vendoredSign(level, secretKey: a.sk, message: msg), "\(level): signing is hedged")
            var bad = sig; bad[0] ^= 1
            XCTAssertTrue(MLDSA.verifyVendored(level, publicKey: a.pk, message: msg, signature: sig), "\(level) vendored")
            XCTAssertFalse(MLDSA.verifyVendored(level, publicKey: a.pk, message: msg, signature: bad), "\(level) vendored edited")
            XCTAssertFalse(MLDSA.verifyVendored(level, publicKey: r1.pk, message: msg, signature: sig), "\(level) vendored other key")
            XCTAssertFalse(MLDSA.verifyVendored(level, publicKey: a.pk, message: [], signature: sig), "\(level) vendored other message")
            XCTAssertFalse(MLDSA.verifyVendored(level, publicKey: Array(a.pk.dropLast()), message: msg, signature: sig), "\(level) short key")
            XCTAssertFalse(MLDSA.verifyVendored(level, publicKey: a.pk, message: msg, signature: Array(sig.dropLast())), "\(level) short signature")
            if let ck = MLDSA.verifyCryptoKit(level, publicKey: a.pk, message: msg, signature: sig) { XCTAssertTrue(ck, "\(level) CryptoKit") }
            if let ck = MLDSA.verifyCryptoKit(level, publicKey: a.pk, message: msg, signature: bad) { XCTAssertFalse(ck, "\(level) CryptoKit edited") }
            XCTAssertNil(MLDSA.vendoredSign(level, secretKey: Array(a.sk.dropLast()), message: msg), "\(level): a short secret key is refused")
            XCTAssertNotNil(MLDSA.vendoredSign(level, secretKey: a.sk, message: []), "\(level): the empty message signs")
        }
    }
}
