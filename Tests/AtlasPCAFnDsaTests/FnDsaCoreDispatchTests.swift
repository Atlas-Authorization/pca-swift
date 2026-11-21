import AtlasPCAVerify
import Foundation
import XCTest
@testable import AtlasPCAFnDsa
@testable import AtlasPCAVerify

/// With libfndsa registered into the core's FN-DSA hook, the core suite dispatch verifies fn-dsa-512 / fn-dsa-1024 for real. Same env gating as
/// FnDsaNativeTests (ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping).
final class FnDsaCoreDispatchTests: XCTestCase {
    override func setUpWithError() throws {
        guard FnDsaNative.sizesMatch() else {
            if ProcessInfo.processInfo.environment["ATLAS_PCA_LIBFNDSA_REQUIRED"] == "1" { XCTFail("libfndsa must load") }
            throw XCTSkip("libfndsa not available")
        }
        PCAFnDsaHook.unregister()
        try FnDsaNative.registerCoreSuites()
    }
    override func tearDown() { PCAFnDsaHook.unregister() }

    func dispatch(_ alg: String, _ vk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        let k = PCAWire.b64uEncode(vk)
        return PQ.verifySuite(alg: alg, holder: "", pq: PQ.resolvePqKey(identity: nil, artifactPk: k, trustedPk: k),
                              message: msg, sig: PCAWire.b64uEncode(sig), pqSig: nil)
    }

    func testKatVerifiesThroughCoreDispatchAndTamperDenies() throws {
        let rows = try FnDsaNativeTests.kat("c_signed")
        XCTAssertFalse(rows.isEmpty)
        for r in rows {
            let alg = r["variant"] as! String, vk = FnDsaNativeTests.hex(r["vk"]), msg = FnDsaNativeTests.hex(r["msg"]), sig = FnDsaNativeTests.hex(r["sig"])
            XCTAssertTrue(PCASuites.supported.contains(alg))
            XCTAssertNil(PQ.validateSignatureWire([JKey("alg"): .string(alg), JKey("sig"): .string(PCAWire.b64uEncode(sig)), JKey("pq_pk"): .string(PCAWire.b64uEncode(vk))]))
            XCTAssertTrue(dispatch(alg, vk, msg, sig), alg)
            XCTAssertFalse(dispatch(alg, vk, msg, FnDsaNativeTests.flip(sig, 10)), "\(alg): tampered sig")
            XCTAssertFalse(dispatch(alg, vk, FnDsaNativeTests.flip(msg, 0), sig), "\(alg): tampered msg")
            XCTAssertFalse(dispatch(alg, FnDsaNativeTests.flip(vk, 5), msg, sig), "\(alg): tampered pq_pk")
            XCTAssertFalse(dispatch(alg, Array(vk.dropLast()), msg, sig), "\(alg): wrong-length pq_pk")
        }
    }

    func testSignThenCoreVerifyRoundTrip() throws {
        for v in FnDsaNativeTests.variants {
            let kp = try FnDsaNative.keygen(v, seed: FnDsaNativeTests.seed(3)), msg = Array("round trip".utf8)
            XCTAssertTrue(dispatch(v, kp.vk, msg, try FnDsaNative.sign(v, sk: kp.sk, msg: msg)), v)
        }
    }
}
