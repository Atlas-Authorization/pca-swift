import AtlasPCAVerify
import Foundation
import XCTest
@testable import AtlasPCAFnDsa
@testable import AtlasPCAVerify

/// FN-DSA end to end through the core's public paths, with libfndsa registered (FnDsaNative.registerCoreSuites): the agent-side signer reproduces the
/// reference's PCActn byte for byte, the public PCA.verify entry point agrees with every fixture case, the fn-dsa cases of producer-pq-vectors.json
/// replay byte for byte, and with NO backend every case denies. ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails (never skips) when libfndsa does not load.
final class FnDsaPcactnE2ETests: XCTestCase {
    override func setUpWithError() throws {
        PCAFnDsaHook.unregister()
        guard FnDsaNative.sizesMatch() else {
            if ProcessInfo.processInfo.environment["ATLAS_PCA_LIBFNDSA_REQUIRED"] == "1" { XCTFail("libfndsa must load") }
            throw XCTSkip("libfndsa not available")
        }
    }
    override func tearDown() { PCAFnDsaHook.unregister() }

    static func fixture() throws -> [JSONValue] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/ref-fndsa-pcactn.json").standardized
        let doc = try PCAWire.parseLenient(String(decoding: try Data(contentsOf: url), as: UTF8.self))
        let cases = doc.get("cases")?.asArray ?? []
        XCTAssertEqual(cases.count, 12)
        return cases
    }

    static func labelSeed(_ label: String) -> [UInt8] { Canonical.sha256(Canonical.utf8("atlas-pca-conformance/" + label)) }

    static func verdict(_ c: JSONValue) -> PCA.Verdict {
        PCA.verify(pcactn: c.get("pcactn") ?? .null, grant: c.get("grant") ?? .null, now: c.get("now_epoch")?.safeInt ?? 0,
                   audience: c.get("audience")?.asString ?? "", insecureSkipPlanRootCheck: true)
    }

    func testSignedBodyMatchesTheReferenceByteForByte() throws {
        try FnDsaNative.registerCoreSuites()
        var n = 0
        for c in try Self.fixture() where c.get("body") != nil {
            let alg = c.get("alg")?.asString ?? "", labels = c.get("key_labels") ?? .null
            let key = try FnDsaNative.keyFromSeed(alg, seed: Self.labelSeed(labels.get("fndsa_keygen")?.asString ?? ""),
                                                  signSeed: Self.labelSeed(labels.get("fndsa_sign_seed")?.asString ?? ""))
            XCTAssertEqual(key.pkB64u, c.get("pq_pk")?.asString, "\(alg): keygen from the label seed")
            let signed = try PCAIssue.signPCActn(c.get("body") ?? .null, signer: try PCASuiteKey(alg: alg, fnDsa: key))
            XCTAssertEqual(Canonical.canonicalize(signed), Canonical.canonicalize(c.get("pcactn") ?? .null), "\(alg): signed PCActn")
            n += 1
        }
        XCTAssertEqual(n, 2)
    }

    func testEveryFixtureCaseVerifiesAsTheReferenceSays() throws {
        try FnDsaNative.registerCoreSuites()
        for c in try Self.fixture() {
            let want = c.get("expect_allow") == .bool(true)
            XCTAssertEqual(Self.verdict(c).allow, want, "\(c.get("name")?.asString ?? "?"): \(Self.verdict(c).reason)")
        }
    }

    func testWithNoBackendEveryCaseDenies() throws {
        for c in try Self.fixture() {
            let name = c.get("name")?.asString ?? "?", v = Self.verdict(c)
            XCTAssertFalse(v.allow, name)
            if name.hasSuffix("/valid") { XCTAssertTrue(v.reason.contains("unsupported_suite"), "\(name): \(v.reason)") }
        }
        // a signer without the verify backend (or the reverse) is no backend either
        PCAFnDsaHook.registerSigner(PCAFnDsaHook.Signer(keygen: { v, s in try FnDsaNative.keygen(v, seed: s) }, sign: { v, k, m, s in try FnDsaNative.sign(v, sk: k, msg: m, seed: s) }))
        for c in try Self.fixture() { XCTAssertFalse(Self.verdict(c).allow, c.get("name")?.asString ?? "?") }
        XCTAssertThrowsError(try PCASuiteKey(alg: "fn-dsa-512", fnDsa: try FnDsaNative.keyFromSeed("fn-dsa-512", seed: Self.labelSeed("x"))))
        PCAFnDsaHook.unregister()
        XCTAssertFalse(PCAFnDsaHook.isSignerRegistered)
        XCTAssertThrowsError(try PCASuiteKey(alg: "fn-dsa-512", fnDsa: try FnDsaNative.keyFromSeed("fn-dsa-512", seed: Self.labelSeed("x")))) {
            XCTAssertEqual("\($0)", "unsupported_suite: fn-dsa-512")
        }
    }

    func testProducerPqVectorsFnDsaCasesReplayByteForByte() throws {
        try FnDsaNative.registerCoreSuites()
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("packages/pca/conformance/producer-pq-vectors.json")
        let text = String(decoding: try Data(contentsOf: url), as: UTF8.self)
        let doc = try PCAWire.parseLenient(text)
        let orders = PCAProducerVectors.objectKeyOrders(text)
        var failures: [String] = [], n = 0
        for (i, c) in (doc.get("cases")?.asArray ?? []).enumerated() {
            let args = c.get("args") ?? .null
            guard (args.get("alg")?.asString ?? args.get("family")?.asString ?? "").hasPrefix("fn-dsa") else { continue }
            let name = c.get("name")?.asString ?? "?"
            do {
                let got = try PCAProducerVectors.produce(op: c.get("op")?.asString ?? "", args: args, keys: doc.get("keys") ?? doc.get("ed_keys") ?? .null,
                                                         pqKeys: doc.get("pq_keys"), keyOrders: PCAProducerVectors.keyOrders(orders, under: "/cases/\(i)/args"))
                if Canonical.canonicalize(got) != Canonical.canonicalize(c.get("expect") ?? .null) { failures.append("\(name): output differs") }
                n += 1
            } catch { failures.append("\(name): \(error)") }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
        XCTAssertEqual(n, 16)
    }
}
