import AtlasPCAVerify
import Foundation
import XCTest
@testable import AtlasPCAFnDsa

/// The real FN-DSA primitive (libfndsa, Pornin's fn-dsa 0.4.0) against the cross-implementation known-answer file (test-data/ref-fndsa-kat.json): keygen
/// and signing from the recorded seeds must reproduce the recorded bytes exactly, and every recorded signature must verify. The workflow sets
/// ATLAS_PCA_LIBFNDSA_REQUIRED=1, so a library that does not load fails instead of skipping.
final class FnDsaNativeTests: XCTestCase {
    typealias Row = [String: Any]

    override func setUpWithError() throws {
        guard FnDsaNative.sizesMatch() else {
            if ProcessInfo.processInfo.environment["ATLAS_PCA_LIBFNDSA_REQUIRED"] == "1" { XCTFail("libfndsa must load") }
            throw XCTSkip("libfndsa not available")
        }
    }

    /// The reference's `sizes`: the lengths the wasm reference reports (verifying key, signing key, signature) for both variants.
    func testSizesAreTheReferences() throws {
        let a = try FnDsaNative.sizes("fn-dsa-512"), b = try FnDsaNative.sizes("fn-dsa-1024")
        XCTAssertEqual([a.verifyingKey, a.signingKey, a.signature], [897, 1345, 666])
        XCTAssertEqual([b.verifyingKey, b.signature], [1793, 1280])
        XCTAssertEqual(b.signingKey, try FnDsaNative.secretKeyBytes("fn-dsa-1024"))
        XCTAssertThrowsError(try FnDsaNative.sizes("fn-dsa-256")) { XCTAssertEqual($0 as? FnDsaError, .invalid("unknown FN-DSA variant fn-dsa-256")) }
    }

    override func tearDown() { FnDsa.resetBackend() }

    static func hex(_ s: Any?) -> [UInt8] {
        let t = Array((s as! String).utf8)
        return stride(from: 0, to: t.count, by: 2).map { UInt8(String(decoding: t[$0..<$0 + 2], as: UTF8.self), radix: 16)! }
    }

    /// SHAKE256(UTF-8 label) cut to 32 bytes (FIPS 202 Keccak-f[1600], rate 136).
    static func shakeSeed(_ label: String) -> [UInt8] {
        let rc: [UInt64] = [0x1, 0x8082, 0x800000000000808a, 0x8000000080008000, 0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
                            0x8a, 0x88, 0x80008009, 0x8000000a, 0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                            0x8000000000008002, 0x8000000000000080, 0x800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080,
                            0x80000001, 0x8000000080008008]
        let rot: [UInt64] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
        let pi = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
        func rol(_ x: UInt64, _ n: UInt64) -> UInt64 { (x << n) | (x >> (64 - n)) }
        var a = [UInt64](repeating: 0, count: 25)
        var m = Array(label.utf8)
        m.append(0x1f)
        while m.count % 136 != 0 { m.append(0) }
        m[m.count - 1] |= 0x80
        for off in stride(from: 0, to: m.count, by: 136) {
            for i in 0..<17 { for j in 0..<8 { a[i] ^= UInt64(m[off + i * 8 + j]) << UInt64(8 * j) } }
            for r in 0..<24 {
                var c = [UInt64](repeating: 0, count: 5)
                for i in 0..<5 { var x: UInt64 = a[i] ^ a[i + 5]; x ^= a[i + 10]; x ^= a[i + 15]; x ^= a[i + 20]; c[i] = x }
                for i in 0..<5 { let d = c[(i + 4) % 5] ^ rol(c[(i + 1) % 5], 1); for j in stride(from: 0, to: 25, by: 5) { a[j + i] ^= d } }
                var t = a[1]
                for i in 0..<24 { let j = pi[i]; let b = a[j]; a[j] = rol(t, rot[i]); t = b }
                for j in stride(from: 0, to: 25, by: 5) { for i in 0..<5 { c[i] = a[j + i] }; for i in 0..<5 { a[j + i] ^= ~c[(i + 1) % 5] & c[(i + 2) % 5] } }
                a[0] ^= rc[r]
            }
        }
        return (0..<32).map { UInt8(truncatingIfNeeded: a[$0 / 8] >> UInt64(8 * ($0 % 8))) }
    }

    static func kat(_ key: String) throws -> [Row] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/ref-fndsa-kat.json").standardized
        let o = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! Row
        return o[key] as! [Row]
    }

    static let variants = ["fn-dsa-512", "fn-dsa-1024"]
    /// The bytes with one bit flipped; an input too short to hold index `i` (the zero-length message) gets one byte appended, so it still differs.
    static func flip(_ b: [UInt8], _ i: Int) -> [UInt8] { var c = b; if i < c.count { c[i] ^= 1 } else { c.append(1) }; return c }
    static func seed(_ n: UInt8) -> [UInt8] { (0..<32).map { UInt8($0) &+ n } }

    func testWasmSignedReplaysByteForByte() throws {
        let rows = try Self.kat("wasm_signed")
        XCTAssertFalse(rows.isEmpty)
        for r in rows {
            let v = r["variant"] as! String, vk = Self.hex(r["vk"]), msg = Self.hex(r["msg"]), sig = Self.hex(r["sig"])
            let k = try FnDsaNative.keygen(v, seed: Self.shakeSeed(r["keygen_seed_label"] as! String))
            XCTAssertEqual(k.vk, vk, "\(v): keygen vk")
            XCTAssertEqual(try FnDsaNative.sign(v, sk: k.sk, msg: msg, seed: Self.shakeSeed(r["sign_seed_label"] as! String)), sig, "\(v): sign bytes")
            XCTAssertTrue(try FnDsaNative.verify(v, vk: vk, msg: msg, sig: sig), "\(v): verify")
        }
    }

    func testReferenceSignedVerifies() throws {
        let rows = try Self.kat("c_signed")
        XCTAssertFalse(rows.isEmpty)
        for r in rows {
            XCTAssertTrue(try FnDsaNative.verify(r["variant"] as! String, vk: Self.hex(r["vk"]), msg: Self.hex(r["msg"]), sig: Self.hex(r["sig"])))
        }
    }

    func testTamperedAndMalformedInputsAreRefused() throws {
        for v in Self.variants {
            let k = try FnDsaNative.keygen(v, seed: Self.seed(1))
            let msg = Array("hello".utf8)
            let sig = try FnDsaNative.sign(v, sk: k.sk, msg: msg, seed: Self.seed(2))
            XCTAssertTrue(try FnDsaNative.verify(v, vk: k.vk, msg: msg, sig: sig))
            XCTAssertFalse(try FnDsaNative.verify(v, vk: k.vk, msg: msg, sig: Self.flip(sig, sig.count / 2)), "\(v): sig byte")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: k.vk, msg: Self.flip(msg, 0), sig: sig), "\(v): msg byte")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: Self.flip(k.vk, 5), msg: msg, sig: sig), "\(v): vk byte")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: k.vk, msg: msg, sig: Array(sig.dropLast())), "\(v): short sig")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: k.vk, msg: msg, sig: sig + [0]), "\(v): long sig")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: Array(k.vk.dropLast()), msg: msg, sig: sig), "\(v): short vk")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: [], msg: msg, sig: sig), "\(v): empty vk")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: k.vk, msg: msg, sig: []), "\(v): empty sig")
            let big = [UInt8](repeating: 7, count: FnDsaNative.messageCap + 1)
            XCTAssertFalse(try FnDsaNative.verify(v, vk: k.vk, msg: big, sig: sig), "\(v): over-cap message verifies false")
            XCTAssertThrowsError(try FnDsaNative.sign(v, sk: k.sk, msg: big), "\(v): over-cap message is refused, never truncated")
            XCTAssertThrowsError(try FnDsaNative.sign(v, sk: Array(k.sk.dropLast()), msg: msg), "\(v): short sk")
            XCTAssertThrowsError(try FnDsaNative.sign(v, sk: [], msg: msg), "\(v): empty sk")
            XCTAssertThrowsError(try FnDsaNative.sign(v, sk: k.sk, msg: msg, seed: [1, 2, 3]), "\(v): short seed")
            XCTAssertThrowsError(try FnDsaNative.keygen(v, seed: []), "\(v): empty keygen seed")
            XCTAssertThrowsError(try FnDsaNative.keygen(v, seed: Self.seed(1) + [0]), "\(v): long keygen seed")
            // a message exactly at the cap is fine
            let cap = [UInt8](repeating: 9, count: FnDsaNative.messageCap)
            XCTAssertTrue(try FnDsaNative.verify(v, vk: k.vk, msg: cap, sig: try FnDsaNative.sign(v, sk: k.sk, msg: cap)), "\(v): message at the cap")
        }
    }

    func testUnknownVariantIsRefused() throws {
        XCTAssertThrowsError(try FnDsaNative.keygen("fn-dsa-768", seed: Self.seed(1)))
        XCTAssertThrowsError(try FnDsaNative.sign("fn-dsa-768", sk: [1], msg: []))
        XCTAssertFalse(try FnDsaNative.verify("fn-dsa-768", vk: [1], msg: [], sig: [1]))
        XCTAssertFalse(try FnDsaNative.verify("hybrid-ed25519-fn-dsa-512", vk: [1], msg: [], sig: [1]))
    }

    func testZeroLengthMessageIsValid() throws {
        for v in Self.variants {
            let k = try FnDsaNative.keygen(v, seed: Self.seed(3))
            let sig = try FnDsaNative.sign(v, sk: k.sk, msg: [], seed: Self.seed(4))
            XCTAssertTrue(try FnDsaNative.verify(v, vk: k.vk, msg: [], sig: sig), "\(v): empty message")
            XCTAssertFalse(try FnDsaNative.verify(v, vk: k.vk, msg: [0], sig: sig), "\(v): empty-message signature on one byte")
        }
    }

    func testRandomSeedRoundTrip() throws {
        for v in Self.variants {
            let k = try FnDsaNative.keygen(v, seed: Self.seed(5))
            XCTAssertEqual(k.sk.count, try FnDsaNative.secretKeyBytes(v))
            let msg = Array("round trip".utf8)
            let a = try FnDsaNative.sign(v, sk: k.sk, msg: msg), b = try FnDsaNative.sign(v, sk: k.sk, msg: msg)
            XCTAssertNotEqual(a, b, "\(v): two fresh seeds must give two signatures")
            XCTAssertTrue(try FnDsaNative.verify(v, vk: k.vk, msg: msg, sig: a))
            XCTAssertTrue(try FnDsaNative.verify(v, vk: k.vk, msg: msg, sig: b))
        }
    }

    func testFramingWithTheRealBackend() throws {
        FnDsa.setBackend(try FnDsaNative.backend())
        let leaf: JSONValue = .object([JKey("ver"): .int(2), JKey("counter"): .int(7), JKey("action"): .object([JKey("verb"): .string("revoke"), JKey("resource"): .string("sess/1")])])
        let ed = try PCAEdKey(seed: Self.seed(9))
        for alg in FnDsa.suites.keys.sorted() {
            let s = FnDsa.suites[alg]!
            let k = try FnDsaNative.keygen(s.variant, seed: Self.seed(6))
            let out = try FnDsa.signPca(alg: alg, leaf: leaf, pk: k.vk, sk: k.sk, edSecret: s.hasEd25519 ? ed.seed : nil)
            XCTAssertEqual(out.pqSig != nil, s.hasEd25519)
            func check(_ sig: String? = nil, _ pqSig: String? = nil, pqPk: String? = nil, leaf l: JSONValue? = nil) throws -> Bool {
                try FnDsa.verifyPca(alg: alg, leaf: l ?? leaf, holder: s.hasEd25519 ? ed.id : nil, pqPk: pqPk ?? out.pqPk, sig: sig ?? out.sig, pqSig: pqSig ?? out.pqSig)
            }
            XCTAssertTrue(try check(), "\(alg): sign then verify")
            let tampered: JSONValue = .object([JKey("ver"): .int(2), JKey("counter"): .int(8), JKey("action"): .object([:])])
            XCTAssertFalse(try check(leaf: tampered), "\(alg): tampered leaf")
            let other = try FnDsaNative.keygen(s.variant, seed: Self.seed(7))
            XCTAssertFalse(try check(pqPk: PCAWire.b64uEncode(other.vk)), "\(alg): another public key")
            let flipped = PCAWire.b64uEncode(Self.flip(PCAWire.b64uDecode(s.hasEd25519 ? out.pqSig! : out.sig)!, 10))
            XCTAssertFalse(try s.hasEd25519 ? check(nil, flipped) : check(flipped), "\(alg): FN-DSA half flipped")
        }
    }
}
