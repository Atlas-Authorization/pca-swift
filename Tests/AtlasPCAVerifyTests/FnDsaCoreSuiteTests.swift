import XCTest
@testable import AtlasPCAVerify

/// fn-dsa-512 / fn-dsa-1024 are registered suites of the core dispatch. With NO backend registered (the default; nothing registers at import)
/// they resolve to nothing: the wire refuses `unsupported_suite` and a signature never verifies, whatever the bytes.
final class FnDsaCoreSuiteTests: XCTestCase {
    override func setUp() { PCAFnDsaHook.unregister() }
    override func tearDown() { PCAFnDsaHook.unregister() }

    static func hex(_ s: String) -> [UInt8] {
        let t = Array(s.utf8)
        return stride(from: 0, to: t.count, by: 2).map { UInt8(String(decoding: t[$0..<$0 + 2], as: UTF8.self), radix: 16)! }
    }

    static func kat() throws -> [[String: Any]] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/ref-fndsa-kat.json").standardized
        return (try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any])["c_signed"] as! [[String: Any]]
    }

    func testRegisteredSizes() {
        for (alg, pk, sig) in [("fn-dsa-512", 897, 666), ("fn-dsa-1024", 1793, 1280)] {
            XCTAssertTrue(PCASuites.registered.contains(alg))
            let s = PQ.suites[alg]!
            XCTAssertEqual(s.sigBytes, sig); XCTAssertEqual(s.pqPkBytes, pk)
            XCTAssertTrue(s.needsPqPk); XCTAssertFalse(s.needsPqSig); XCTAssertNil(s.pq)
        }
    }

    func testNoBackendDenies() throws {
        XCTAssertFalse(PCAFnDsaHook.isRegistered)
        XCTAssertFalse(PCASuites.supported.contains("fn-dsa-512"))
        for r in try Self.kat() {
            let alg = r["variant"] as! String, vk = PCAWire.b64uEncode(Self.hex(r["vk"] as! String)), sig = PCAWire.b64uEncode(Self.hex(r["sig"] as! String))
            XCTAssertEqual(PQ.refusal(alg), "unsupported_suite: \(alg)")
            XCTAssertFalse(PQ.verifySuite(alg: alg, holder: "", pq: PQ.resolvePqKey(identity: nil, artifactPk: vk, trustedPk: vk),
                                          message: Self.hex(r["msg"] as! String), sig: sig, pqSig: nil), alg)
            let leaf: JObject = [JKey("alg"): .string(alg), JKey("sig"): .string(sig), JKey("pq_pk"): .string(vk)]
            XCTAssertEqual(PQ.validateSignatureWire(leaf), "unsupported_suite: \(alg)")
        }
    }

    func testBackendRegisteredIsCalledAfterLengthChecksAndFailsClosed() throws {
        var calls = 0
        PCAFnDsaHook.register { _, _, _, _ in calls += 1; return true }
        let r = try Self.kat().first!
        let alg = r["variant"] as! String, vkB = Self.hex(r["vk"] as! String), sigB = Self.hex(r["sig"] as! String), msg = Self.hex(r["msg"] as! String)
        func run(_ vk: [UInt8], _ sig: [UInt8]) -> Bool {
            PQ.verifySuite(alg: alg, holder: "", pq: PQ.resolvePqKey(identity: nil, artifactPk: PCAWire.b64uEncode(vk), trustedPk: PCAWire.b64uEncode(vk)),
                           message: msg, sig: PCAWire.b64uEncode(sig), pqSig: nil)
        }
        XCTAssertTrue(run(vkB, sigB)); XCTAssertEqual(calls, 1)
        XCTAssertFalse(run(Array(vkB.dropLast()), sigB)); XCTAssertFalse(run(vkB, Array(sigB.dropLast()))); XCTAssertEqual(calls, 1, "lengths are checked before the backend")
        PCAFnDsaHook.register { _, _, _, _ in throw NSError(domain: "x", code: 1) }
        XCTAssertFalse(run(vkB, sigB), "a throwing backend denies")
        PCAFnDsaHook.register { _, _, _, _ in false }
        XCTAssertFalse(run(vkB, sigB))
    }
}
