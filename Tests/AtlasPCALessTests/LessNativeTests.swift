import AtlasPCAVerify
import Foundation
import XCTest
@testable import AtlasPCALess
@testable import AtlasPCAVerify

/// The LESS verifier (the patched reference C compiled as CLess) through the core suite dispatch: the shared known answers (packages/pca/conformance/less-vectors.json,
/// including the seed-padding malleations every verifier must refuse), the wire rule for the variable-length signature, and the fail-closed edges.
final class LessNativeTests: XCTestCase {
    override func setUpWithError() throws {
        PCALessHook.unregister()
        XCTAssertTrue(LessNative.sizesMatch(), "the checked-in C sources must report the sizes the suite tables assume")
        try LessNative.registerCoreSuites()
    }

    func testSizesAreTheReferences() throws {
        let z = try LessNative.sizes()
        XCTAssertEqual(z.publicKey, 97_484)
        XCTAssertEqual(z.signatureMax, 1_329)
        XCTAssertEqual(z.seed, 16)
        XCTAssertGreaterThan(z.secretKey, 0)
        XCTAssertGreaterThan(z.publicKey, z.secretKey)
    }

    override func tearDown() { PCALessHook.unregister() }

    /// The repository root (…/sdks/swift-pca/Tests/AtlasPCALessTests/<this file>).
    static var root: URL {
        var u = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { u.deleteLastPathComponent() }
        return u
    }

    func testKnownAnswersThroughTheSuiteDispatch() throws {
        let url = Self.root.appendingPathComponent("packages/pca/conformance/less-vectors.json")
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("the shared conformance directory is not present") }
        let doc = try PCAWire.parseLenient(String(contentsOf: url, encoding: .utf8))
        let keys = try XCTUnwrap(doc.get("keys"))
        var bad: [String] = []
        var n = 0
        for v in try XCTUnwrap(doc.get("vectors")?.asArray) {
            let name = v.get("name")?.asString ?? "?"
            let key = try XCTUnwrap(keys.get(v.get("key")?.asString ?? ""), name)
            let pk = try XCTUnwrap((v.get("pq_pk_override") ?? key.get("pq_pk"))?.asString, name)
            let alg = try XCTUnwrap(v.get("alg")?.asString, name)
            let holder = try XCTUnwrap(key.get("ed_pub")?.asString, name)
            let sig = try XCTUnwrap(v.get("sig")?.asString, name)
            let pqSig = v.get("pq_sig")?.asString
            var art: JObject = ["alg": .string(alg), "sig": .string(sig), "pq_pk": .string(pk)]
            if let ps = pqSig { art["pq_sig"] = .string(ps) }
            let text = try XCTUnwrap(v.get("message")?.asString, name)
            var msg: [UInt8] = []
            if !text.isEmpty { msg = try XCTUnwrap(PCAWire.b64uDecode(text), name) }
            let exp = try XCTUnwrap(v.get("expect"), name)
            let wireOK = PQ.validateSignatureWire(art) == nil
            let verify = PQ.verifySuite(alg: alg, holder: holder, pq: PQ.resolvePqKey(identity: nil, artifactPk: pk, trustedPk: pk), message: msg, sig: sig, pqSig: pqSig)
            if wireOK != (exp.get("wire_ok") == .bool(true)) { bad.append("\(name): wire \(wireOK)") }
            if (wireOK && verify) != (exp.get("allow") == .bool(true)) { bad.append("\(name): allow \(wireOK && verify)") }
            n += 1
        }
        XCTAssertGreaterThanOrEqual(n, 20)
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    func testSuitesResolveOnlyWhileTheBackendIsRegistered() {
        XCTAssertTrue(PCASuites.supported.contains("less-cat1"))
        XCTAssertTrue(PCASuites.supported.contains("hybrid-ed25519-less-cat1"))
        PCALessHook.unregister()
        XCTAssertFalse(PCASuites.supported.contains("less-cat1"))
        XCTAssertNil(PQ.resolve("hybrid-ed25519-less-cat1"))
        XCTAssertEqual(PQ.refusal("less-cat1"), "unsupported_suite: less-cat1")
    }

    func testEveryNonSignatureLengthIsRefusedWithoutTheLibrary() {
        let vk = [UInt8](repeating: 7, count: LessNative.publicKeyBytes)
        for n in 0...(LessNative.signatureMaxBytes + 40) where !PCALessHook.sigLenOK(n) {
            XCTAssertFalse(LessNative.verify(vk: vk, msg: [1], sig: [UInt8](repeating: 0, count: n)), "length \(n)")
        }
        XCTAssertFalse(LessNative.verify(vk: Array(vk.dropLast()), msg: [1], sig: [UInt8](repeating: 0, count: LessNative.signatureMaxBytes)))
        XCTAssertFalse(LessNative.verify(vk: vk + [0], msg: [1], sig: [UInt8](repeating: 0, count: LessNative.signatureMaxBytes)))
    }

    func testGarbageSignaturesOfEveryLengthAreRefused() {
        let vk = [UInt8](repeating: 7, count: LessNative.publicKeyBytes)
        var n = LessNative.signatureMinBytes
        while n <= LessNative.signatureMaxBytes {
            XCTAssertFalse(LessNative.verify(vk: vk, msg: [], sig: [UInt8](repeating: 0, count: n)), "length \(n), empty message")
            XCTAssertFalse(LessNative.verify(vk: vk, msg: Array("m".utf8), sig: [UInt8](repeating: 0xFF, count: n)), "length \(n)")
            n += PCALessHook.sigStep
        }
    }

    /// The generator's seed scheme: the label's ASCII bytes, zero-padded to 32.
    private static func labelSeed(_ label: String) -> [UInt8] {
        var s = [UInt8](repeating: 0, count: 32)
        for (i, b) in label.utf8.prefix(32).enumerated() { s[i] = b }
        return s
    }

    private static func vectorDoc() throws -> JSONValue {
        let url = root.appendingPathComponent("packages/pca/conformance/less-vectors.json")
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("the shared conformance directory is not present") }
        return try PCAWire.parseLenient(String(contentsOf: url, encoding: .utf8))
    }

    /// Signing known answers: the shared vectors were made by the reference with seeded keygen / signing (label seeds), and the native signer fed the
    /// same seeds must reproduce the public keys and the valid signatures byte for byte.
    func testSigningReproducesTheSharedKnownAnswers() throws {
        let doc = try Self.vectorDoc()
        let msg = Array("atlas-pca/less-conformance/code-based-leaf-message".utf8)
        for (name, vecName) in [("main", "less-cat1-valid"), ("other", "less-cat1-valid-other-key")] {
            let key = try LessNative.keyFromSeed(Self.labelSeed("less-kg-\(name)"), signSeed: Self.labelSeed("less-sign-\(name)"))
            XCTAssertEqual(key.pkB64u, doc.get("keys")?.get(name)?.get("pq_pk")?.asString, "public key \(name)")
            let vec = try XCTUnwrap(doc.get("vectors")?.asArray?.first { $0.get("name")?.asString == vecName })
            let sig = try LessNative.sign(sk: key.sk, msg: msg, seed: key.signSeed)
            XCTAssertEqual(Base64URLStrict.encode(sig), vec.get("sig")?.asString, "signature \(name)")
            XCTAssertTrue(LessNative.verify(vk: key.vk, msg: msg, sig: sig))
        }
    }

    func testFreshSeedSignaturesVerifyAndDiffer() throws {
        let key = try LessNative.keyFromSeed(Self.labelSeed("swift-less-roundtrip"))
        let a = try LessNative.sign(sk: key.sk, msg: [1, 2, 3])
        let b = try LessNative.sign(sk: key.sk, msg: [1, 2, 3])
        XCTAssertTrue(PCALessHook.sigLenOK(a.count) && PCALessHook.sigLenOK(b.count))
        XCTAssertNotEqual(a, b, "a fresh seed per signature gives a fresh salt")
        for sig in [a, b] {
            XCTAssertTrue(LessNative.verify(vk: key.vk, msg: [1, 2, 3], sig: sig))
            XCTAssertFalse(LessNative.verify(vk: key.vk, msg: [1, 2, 4], sig: sig))
        }
        XCTAssertTrue(LessNative.verify(vk: key.vk, msg: [], sig: try LessNative.sign(sk: key.sk, msg: [])))
    }

    func testShortSeedsAndWrongSizesAreRefused() throws {
        XCTAssertThrowsError(try LessNative.keygen(seed: [UInt8](repeating: 1, count: 31)))
        let key = try LessNative.keyFromSeed(Self.labelSeed("swift-less-refusals"))
        XCTAssertThrowsError(try LessNative.sign(sk: key.sk, msg: [1], seed: [UInt8](repeating: 1, count: 31)))
        XCTAssertThrowsError(try LessNative.sign(sk: Array(key.sk.dropLast()), msg: [1]))
        XCTAssertThrowsError(try LessNative.keyFromSeed(Self.labelSeed("x"), signSeed: [1, 2, 3]))
    }

    /// The core agent-side signer: both LESS suites sign through `PCASuiteKey(alg:ed:less:)` and the result verifies through the suite dispatch.
    func testCoreSuiteKeySignsBothSuites() throws {
        let key = try LessNative.keyFromSeed(Self.labelSeed("swift-less-suite"))
        let ed = try PCAEdKey.generate()
        let msg = Array("suite message".utf8)
        let pure = try PCASuiteKey(alg: "less-cat1", ed: nil, less: key)
        let ps = try pure.sign(msg)
        XCTAssertNil(ps.pqSig)
        let pin = PQ.resolvePqKey(identity: nil, artifactPk: key.pkB64u, trustedPk: key.pkB64u)
        XCTAssertTrue(PQ.verifySuite(alg: "less-cat1", holder: "", pq: pin, message: msg, sig: ps.sig, pqSig: nil))
        let hyb = try PCASuiteKey(alg: "hybrid-ed25519-less-cat1", ed: ed, less: key)
        let hs = try hyb.sign(msg)
        XCTAssertNotNil(hs.pqSig)
        XCTAssertTrue(PQ.verifySuite(alg: "hybrid-ed25519-less-cat1", holder: try XCTUnwrap(hyb.id), pq: pin, message: msg, sig: hs.sig, pqSig: hs.pqSig))
        XCTAssertThrowsError(try PCASuiteKey(alg: "hybrid-ed25519-less-cat1", ed: nil, less: key))
        XCTAssertThrowsError(try PCASuiteKey(alg: "ed25519", ed: ed, less: key))
        XCTAssertThrowsError(try PCASuiteKey(alg: "less-cat1", ed: ed, pq: nil), "the ML-DSA initialiser never builds a LESS suite")
        PCALessHook.unregister()
        XCTAssertThrowsError(try PCASuiteKey(alg: "less-cat1", ed: nil, less: key), "no backend: unsupported_suite")
    }

    /// Sources/CLess must be byte-identical to the canonical sdks/pca-less-c (in the repository; skipped in a published copy).
    func testCopyMatchesCanonical() throws {
        let canon = Self.root.appendingPathComponent("sdks/pca-less-c", isDirectory: true)
        guard FileManager.default.fileExists(atPath: canon.appendingPathComponent("atlas_less.c").path) else { throw XCTSkip("canonical sdks/pca-less-c not present") }
        let mine = Self.root.appendingPathComponent("sdks/swift-pca/Sources/CLess", isDirectory: true)
        var pairs = [("atlas_less.c", "atlas_less.c"), ("atlas_less.h", "include/atlas_less.h"), ("LICENSE", "LICENSE")]
        for f in try FileManager.default.contentsOfDirectory(atPath: canon.appendingPathComponent("include").path) where f.hasSuffix(".h") { pairs.append(("include/" + f, "ref/" + f)) }
        for f in try FileManager.default.contentsOfDirectory(atPath: canon.appendingPathComponent("lib").path) where f.hasSuffix(".c") { pairs.append(("lib/" + f, "lib/" + f)) }
        XCTAssertGreaterThanOrEqual(pairs.count, 31)
        for (from, to) in pairs {
            XCTAssertEqual(try Data(contentsOf: canon.appendingPathComponent(from)), try Data(contentsOf: mine.appendingPathComponent(to)),
                           "CLess/\(to) differs from sdks/pca-less-c/\(from) (run Sources/CLess/sync.sh)")
        }
        let have = try FileManager.default.contentsOfDirectory(atPath: mine.appendingPathComponent("lib").path).filter { $0.hasSuffix(".c") }
        XCTAssertEqual(have.count, try FileManager.default.contentsOfDirectory(atPath: canon.appendingPathComponent("lib").path).filter { $0.hasSuffix(".c") }.count)
    }
}
