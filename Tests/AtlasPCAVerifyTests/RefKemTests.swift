import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
@testable import AtlasPCAOpenSSL

/// The hybrid KEM (X25519 + ML-KEM-768 / 1024, X-Wing) through libcrypto 3.5+ (ATLAS_PCA_OPENSSL=1): every case of the reference corpus, including the
/// draft-09 X-Wing vectors, the refusals and the implicit-rejection secrets, byte for byte. The corpus pins the random stream, so the randomised calls
/// are replayed through their derandomised entry points; a round trip covers the randomised ones.
final class RefKemTests: XCTestCase {
    typealias K = PCAKem
    struct BadArg: Error {}

    override func setUpWithError() throws {
        guard K.available() else {
            if ProcessInfo.processInfo.environment["CI"] != nil { XCTFail("libcrypto without ML-KEM (needs 3.5+)") }
            throw XCTSkip("libcrypto without ML-KEM (needs 3.5+)")
        }
    }

    private func levelOf(_ v: JSONValue?) throws -> Int {
        if let s = v?.asString, let n = Int(s) { return n }
        guard let n = IV.int(v) else { throw BadArg() }
        return Int(n)
    }

    /// The corpus byte forms: literal bytes, a seed label, a list of parts, a hybrid secret key or an expanded decapsulation key built from seeds.
    private func bytes(_ v: JSONValue?) throws -> [UInt8] {
        if case let .array(parts)? = v { return try parts.flatMap { try bytes($0) } }
        guard case let .object(o)? = v else { throw BadArg() }
        if let b = o["$bytes"] {
            if let s = b.asString { guard let d = Base64URLStrict.decode(s) else { throw BadArg() }; return d }
            guard let label = b.get("$seed")?.asString else { throw BadArg() }
            return Canonical.sha256(Array("atlas-pca-conformance/\(label)".utf8))
        }
        func patch(_ b: inout [UInt8], _ set: JSONValue?) throws {
            for e in set?.asArray ?? [] {
                guard let off = IV.int(e.asArray?.first), let val = IV.int(e.asArray?.last), Int(off) < b.count else { throw BadArg() }
                b[Int(off)] = UInt8(val)
            }
        }
        if let h = o["$hybridSk"] {
            let l = try K.level(try levelOf(h.get("level")))
            var sk = try bytes(h.get("x")) + (try K.mlKemKeygen(l, try bytes(h.get("d")) + (try bytes(h.get("z"))))).dk
            if let t = IV.int(h.get("trim")) { sk.removeLast(Int(t)) }
            if let p = IV.int(h.get("pad")) { sk += [UInt8](repeating: 0, count: Int(p)) }
            try patch(&sk, h.get("set"))
            return sk
        }
        if let m = o["$mlkemDk"] {
            let l = try K.level(try levelOf(m.get("level")))
            var dk = try K.mlKemKeygen(l, try bytes(m.get("d")) + (try bytes(m.get("z")))).dk
            try patch(&dk, m.get("set"))
            if m.get("rehash") == .bool(true) {
                let h = try K.sha3_256(Array(dk[(384 * l.k)..<(768 * l.k + 32)]))
                dk.replaceSubrange((768 * l.k + 32)..<(768 * l.k + 64), with: h)
            }
            return dk
        }
        throw BadArg()
    }

    private func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw BadArg() }
        return s
    }

    private func pair(_ k: K.KeyPair) -> JSONValue {
        .object(["publicKey": Base.bytesValue(k.publicKey), "secretKeySha256": .string(Canonical.sha256(k.secretKey).map { String(format: "%02x", $0) }.joined()),
                 "secretKeyLen": .int(Int64(k.secretKey.count))])
    }

    private func enc(_ e: K.Encapsulation) -> JSONValue { .object(["ciphertext": Base.bytesValue(e.ciphertext), "sharedSecret": Base.bytesValue(e.sharedSecret)]) }

    private func call(_ c: BaseCase) throws -> JSONValue? {
        let a = c.arg(0), b = c.arg(1)
        switch c.fn {
        case "constants":
            return .object([
                "HYBRID_PUBLIC_KEY_LEN": .int(Int64(K.HYBRID_PUBLIC_KEY_LEN)), "HYBRID_CIPHERTEXT_LEN": .int(Int64(K.HYBRID_CIPHERTEXT_LEN)),
                "HYBRID_SHARED_SECRET_LEN": .int(Int64(K.HYBRID_SHARED_SECRET_LEN)), "HYBRID_KEM_SUITE": .string(K.HYBRID_KEM_SUITE), "XWING_SUITE": .string(K.XWING_SUITE),
                "XWING_SEED_LEN": .int(Int64(K.XWING_SEED_LEN)), "XWING_SECRET_KEY_LEN": .int(Int64(K.XWING_SECRET_KEY_LEN)), "XWING_PUBLIC_KEY_LEN": .int(Int64(K.XWING_PUBLIC_KEY_LEN)),
                "XWING_CIPHERTEXT_LEN": .int(Int64(K.XWING_CIPHERTEXT_LEN)), "XWING_SHARED_SECRET_LEN": .int(Int64(K.XWING_SHARED_SECRET_LEN)), "XWING_ESEED_LEN": .int(Int64(K.XWING_ESEED_LEN)),
                "XWING_LABEL": Base.bytesValue(K.XWING_LABEL), "HYBRID1024_PUBLIC_KEY_LEN": .int(Int64(K.HYBRID1024_PUBLIC_KEY_LEN)),
                "HYBRID1024_CIPHERTEXT_LEN": .int(Int64(K.HYBRID1024_CIPHERTEXT_LEN)), "HYBRID1024_SHARED_SECRET_LEN": .int(Int64(K.HYBRID1024_SHARED_SECRET_LEN)),
                "HYBRID1024_KEM_SUITE": .string(K.HYBRID1024_KEM_SUITE),
            ])
        case "hybridKemKeygen": return pair(try K.hybridKeygenDerand(K.L768, try bytes(a)))
        case "hybridKem1024Keygen": return pair(try K.hybridKeygenDerand(K.L1024, try bytes(a)))
        case "hybridEncapsulate": return enc(try K.hybridEncapsulateDerand(K.L768, try bytes(a), try bytes(b)))
        case "hybridEncapsulate1024": return enc(try K.hybridEncapsulateDerand(K.L1024, try bytes(a), try bytes(b)))
        case "hybridDecapsulate": return Base.bytesValue(try K.hybridDecapsulate(try bytes(a), try bytes(b)))
        case "hybridDecapsulate1024": return Base.bytesValue(try K.hybridDecapsulate1024(try bytes(a), try bytes(b)))
        case "xwingKeygen": return pair(try K.xwingKeygen(try bytes(a)))
        case "xwingEncapsulateDerand", "xwingEncapsulate": return enc(try K.xwingEncapsulateDerand(try bytes(a), try bytes(b)))
        case "xwingDecapsulate": return Base.bytesValue(try K.xwingDecapsulate(try bytes(a), try bytes(b)))
        case "encodeHybridPublicKey": return .string(K.encodeHybridPublicKey(try bytes(a)))
        case "encodeHybridCiphertext": return .string(K.encodeHybridCiphertext(try bytes(a)))
        case "encodeXWingPublicKey": return .string(K.encodeXWingPublicKey(try bytes(a)))
        case "encodeXWingCiphertext": return .string(K.encodeXWingCiphertext(try bytes(a)))
        case "decodeHybridPublicKey": return Base.bytesValue(try K.decodeHybridPublicKey(try str(a)))
        case "decodeHybridCiphertext": return Base.bytesValue(try K.decodeHybridCiphertext(try str(a)))
        case "decodeXWingPublicKey": return Base.bytesValue(try K.decodeXWingPublicKey(try str(a)))
        case "decodeXWingCiphertext": return Base.bytesValue(try K.decodeXWingCiphertext(try str(a)))
        case "mlKemEncapsulationKeyCheck", "mlKemDecapsulationKeyCheck":
            // the level is a number in the reference (a string or null is refused there); a key that is not bytes is `false` at a valid level
            // the reference looks the level up as an object key, so the exact strings "768" / "1024" name the same level as the numbers
            let levelNumber: Int64? = IV.int(a) ?? (a?.asString == "768" ? 768 : a?.asString == "1024" ? 1024 : nil)
            guard let n = levelNumber else { throw BadArg() }
            _ = try K.level(Int(n))
            guard let key = try? bytes(b) else { return .bool(false) }
            return .bool(try (c.fn == "mlKemEncapsulationKeyCheck" ? K.mlKemEncapsulationKeyCheck(Int(n), key) : K.mlKemDecapsulationKeyCheck(Int(n), key)))
        default: return nil
        }
    }

    func testEveryCaseMatchesTheReference() throws {
        let d = Base.Diffs()
        var unhandled = Set<String>()
        let n = try Base.each("ref-kem.json.gz") { c in
            var known = true
            let got = Base.run { () throws -> JSONValue in
                guard let v = try self.call(c) else { known = false; return .null }
                return v
            }
            if !known { unhandled.insert(c.fn); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(unhandled, [], "corpus functions without a native entry point")
        XCTAssertEqual(n, 464)
        d.finish(464)
    }

    func testTheRandomisedCallsRoundTrip() throws {
        let a = try K.hybridKemKeygen(), a2 = try K.hybridKemKeygen()
        XCTAssertNotEqual(a.secretKey, a2.secretKey)
        XCTAssertEqual([a.publicKey.count, a.secretKey.count], [K.HYBRID_PUBLIC_KEY_LEN, 2432])
        let e = try K.hybridEncapsulate(a.publicKey)
        XCTAssertEqual(try K.hybridDecapsulate(e.ciphertext, a.secretKey), e.sharedSecret)
        XCTAssertNotEqual(try K.hybridDecapsulate(e.ciphertext, a2.secretKey), e.sharedSecret)
        XCTAssertNotEqual(try K.hybridEncapsulate(a.publicKey).ciphertext, e.ciphertext)
        XCTAssertTrue(try K.mlKemEncapsulationKeyCheck(768, Array(a.publicKey[32...])))
        XCTAssertTrue(try K.mlKemDecapsulationKeyCheck(768, Array(a.secretKey[32...])))

        let b = try K.hybridKem1024Keygen()
        XCTAssertEqual([b.publicKey.count, b.secretKey.count], [K.HYBRID1024_PUBLIC_KEY_LEN, 3200])
        let e2 = try K.hybridEncapsulate1024(b.publicKey)
        XCTAssertEqual(try K.hybridDecapsulate1024(e2.ciphertext, b.secretKey), e2.sharedSecret)
        // a 1024 key never works under the 768 suite
        XCTAssertThrowsError(try K.hybridEncapsulate(b.publicKey))
        XCTAssertThrowsError(try K.hybridDecapsulate(e2.ciphertext, b.secretKey))

        let x = try K.xwingKeygen()
        XCTAssertEqual([x.publicKey.count, x.secretKey.count], [K.XWING_PUBLIC_KEY_LEN, K.XWING_SECRET_KEY_LEN])
        let e3 = try K.xwingEncapsulate(x.publicKey)
        XCTAssertEqual(e3.ciphertext.count, K.XWING_CIPHERTEXT_LEN)
        XCTAssertEqual(try K.xwingDecapsulate(e3.ciphertext, x.secretKey), e3.sharedSecret)
        XCTAssertEqual(try K.xwingKeygen(x.secretKey).publicKey, x.publicKey)
        XCTAssertThrowsError(try K.mlKemEncapsulationKeyCheck(512, []))
    }
}
#endif
