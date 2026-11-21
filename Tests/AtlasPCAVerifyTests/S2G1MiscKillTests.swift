import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kill tests (mutation sheet swift-k05 group 1) for Keys.swift (key generation and suite-key validation), Blueprint.wellFormed
/// and the edwards25519 point decoder.
final class S2G1KeysKillTests: XCTestCase {
    private func producerMessage(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch let e as PCAProducerError { return e.message } catch { return "other: \(error)" }
    }

    private static func pq(_ level: PCAMLDSALevel, sig: [UInt8] = [1, 2, 3]) -> PCAPQKey {
        PCAPQKey(level: level, pk: [UInt8](repeating: 0, count: 1952), signFn: { _ in sig })
    }

    // ---------------------------------------------------------------- generate (lines 36, 37)

    func testGenerateFillsEveryByteOfTheSeed() throws {
        var lastByteSet = false
        for _ in 0..<64 {
            let k = try PCAEdKey.generate()
            XCTAssertEqual(k.seed.count, 32)
            if k.seed[31] != 0 { lastByteSet = true }
        }
        XCTAssertTrue(lastByteSet, "line 37: the 32nd seed byte is random")
    }

    // ---------------------------------------------------------------- PCAPQKey.make (line 81)

    func testPQGenerateNamesTheLevelItCannotProvide() throws {
        if PCAPQKey.signingAvailable { XCTAssertNoThrow(try PCAPQKey.generate(.mlDsa65), "line 81 guard") }
        PCAPQKey.signingDisabledForTests = true
        defer { PCAPQKey.signingDisabledForTests = false }
        let reason = PCASuites.unsupportedSuiteReason
        XCTAssertEqual(producerMessage { _ = try PCAPQKey.generate(.mlDsa65) }, "\(reason): ml-dsa-65", "line 81 level 65")
        XCTAssertEqual(producerMessage { _ = try PCAPQKey.generate(.mlDsa87) }, "\(reason): ml-dsa-87", "line 81 level 87")
        XCTAssertEqual(producerMessage { _ = try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 1, count: 32)) }, "\(reason): ml-dsa-65")
    }

    // ---------------------------------------------------------------- PCASuiteKey.init (lines 108-112)

    func testEd25519SuiteNeedsTheEdKey() throws {
        XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: "ed25519", ed: nil) }, "'ed25519' requires an Ed25519 key", "line 109")
        let ed = try PCAEdKey(seed: [UInt8](repeating: 9, count: 32))
        XCTAssertNoThrow(try PCASuiteKey(alg: "ed25519", ed: ed))
        XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: "no-such-suite", ed: ed) }, PQ.refusal("no-such-suite"))
    }

    func testPQSuiteRefusedWhereSigningIsUnavailable() throws {
        let pqKeys = Self.pq(.mlDsa65)
        PCAPQKey.signingDisabledForTests = true
        defer { PCAPQKey.signingDisabledForTests = false }
        let ed = try PCAEdKey(seed: [UInt8](repeating: 9, count: 32))
        for alg in ["ml-dsa-65", "ml-dsa-87", "hybrid-ed25519-ml-dsa-65"] {
            XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: alg, ed: ed, pq: pqKeys) }, PQ.refusal(alg), "line 108 \(alg)")
        }
    }

    func testPQSuiteKeyChecks() throws {
        try XCTSkipUnless(PCAPQKey.signingAvailable, "needs a platform that can sign ML-DSA")
        let ed = try PCAEdKey(seed: [UInt8](repeating: 9, count: 32))
        // line 108: an available platform builds the suite key
        XCTAssertNoThrow(try PCASuiteKey(alg: "ml-dsa-65", ed: nil, pq: Self.pq(.mlDsa65)), "line 108 and 109: a pure PQ suite needs no Ed25519 key")
        XCTAssertNoThrow(try PCASuiteKey(alg: "ml-dsa-87", ed: nil, pq: Self.pq(.mlDsa87)), "line 112 level 87 matches")
        XCTAssertNoThrow(try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed, pq: Self.pq(.mlDsa65)))
        XCTAssertNoThrow(try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-87", ed: ed, pq: Self.pq(.mlDsa87)))
        // line 109: a hybrid needs the Ed25519 key
        XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: nil, pq: Self.pq(.mlDsa65)) },
                       "'hybrid-ed25519-ml-dsa-65' requires an Ed25519 key")
        // lines 110, 111: a PQ suite needs the ML-DSA key
        XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: "ml-dsa-65", ed: ed, pq: nil) }, "'ml-dsa-65' requires an ML-DSA key")
        // line 112: the ML-DSA level must match the suite
        XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: "ml-dsa-65", ed: ed, pq: Self.pq(.mlDsa87)) }, "'ml-dsa-65' needs a different ML-DSA level")
        XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: "ml-dsa-87", ed: ed, pq: Self.pq(.mlDsa65)) }, "'ml-dsa-87' needs a different ML-DSA level")
        XCTAssertEqual(producerMessage { _ = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-87", ed: ed, pq: Self.pq(.mlDsa65)) },
                       "'hybrid-ed25519-ml-dsa-87' needs a different ML-DSA level")
    }

    func testPQSuiteSignRouting() throws {
        try XCTSkipUnless(PCAPQKey.signingAvailable, "needs a platform that can sign ML-DSA")
        let ed = try PCAEdKey(seed: [UInt8](repeating: 9, count: 32))
        let msg: [UInt8] = [10, 20, 30]
        // line 127: a pure PQ suite signs with the ML-DSA key alone
        let pure = try PCASuiteKey(alg: "ml-dsa-65", ed: nil, pq: Self.pq(.mlDsa65, sig: [1, 2, 3]))
        let p = try pure.sign(msg)
        XCTAssertEqual(p.sig, Base64URLStrict.encode([1, 2, 3]))
        XCTAssertNil(p.pqSig)
        // line 127: a hybrid signs with both halves
        let hybrid = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed, pq: Self.pq(.mlDsa65, sig: [4, 5, 6]))
        let h = try hybrid.sign(msg)
        XCTAssertEqual(h.pqSig, Base64URLStrict.encode([4, 5, 6]))
        XCTAssertEqual(Base64URLStrict.decode(h.sig)?.count, 64)
    }
}

final class S2G1BlueprintKillTests: XCTestCase {
    private func body(_ over: JObject = [:]) -> JObject {
        var b: JObject = ["v": .int(1), "id": .string("bp1"), "key": .string("BP"), "ceiling": .array([]), "epoch": .int(1), "status": .string("active"),
                          "issued_at": .int(1), "operator": .string("op")]
        for (k, v) in over { b[k] = v }
        return b
    }

    func testExpiresAtMustBeASafeInteger() {
        XCTAssertNotNil(Blueprint.wellFormed(.object(body())))
        XCTAssertNotNil(Blueprint.wellFormed(.object(body(["expires_at": .int(5)]))))
        XCTAssertNil(Blueprint.wellFormed(.object(body(["expires_at": .string("x")]))), "line 19")
        XCTAssertNil(Blueprint.wellFormed(.object(body(["expires_at": .int(-1)]))), "line 19")
        XCTAssertNil(Blueprint.wellFormed(.object(body(["expires_at": .double(1.5)]))), "line 19")
    }
}

final class S2G1TorsionDecodeKillTests: XCTestCase {
    typealias T = Ed25519Torsion

    func testSignBitSelectsTheRootOfX() {
        let base: [UInt8] = [0x58] + [UInt8](repeating: 0x66, count: 31)
        var neg = base
        neg[31] |= 0x80
        guard let p = T.decode(base), let n = T.decode(neg) else { return XCTFail("the base point and its negation decode") }
        XCTAssertEqual(n.y, p.y)
        XCTAssertNotEqual(n.x, p.x, "line 136: bit 255 of the encoding is the sign of x")
        XCTAssertEqual(n.x, T.fsub(T.zero, p.x), "line 136: the sign bit selects -x")
        XCTAssertEqual(p.x.a0 & 1, 0, "the base point x is even")
    }

    func testZeroXWithTheSignBitIsRefused() {
        let identity: [UInt8] = [1] + [UInt8](repeating: 0, count: 31)
        var signed = identity
        signed[31] = 0x80
        XCTAssertNotNil(T.decode(identity), "line 151: (0, 1) with sign 0 is canonical")
        XCTAssertNil(T.decode(signed), "line 151: x = 0 with the sign bit set is not canonical")
    }
}
