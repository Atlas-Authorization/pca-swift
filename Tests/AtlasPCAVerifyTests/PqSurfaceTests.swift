import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The public post-quantum surface of pq.ts: the constants agree with the suite tables, the guards are fail-closed, and the LAMPS composite
/// (ML-DSA-65 + Ed25519) round-trips and refuses every tamper.
final class PqSurfaceTests: XCTestCase {
    func testConstantsMatchTheSuiteTables() {
        XCTAssertEqual(PCAPq.ML_DSA_65_PUBLIC_KEY_BYTES, MLDSA.lens(.mlDsa65).pk)
        XCTAssertEqual(PCAPq.ML_DSA_65_SIGNATURE_BYTES, MLDSA.lens(.mlDsa65).sig)
        XCTAssertEqual(PCAPq.ML_DSA_87_PUBLIC_KEY_BYTES, MLDSA.lens(.mlDsa87).pk)
        XCTAssertEqual(PCAPq.ML_DSA_87_SIGNATURE_BYTES, MLDSA.lens(.mlDsa87).sig)
        XCTAssertEqual(PCAPq.FN_DSA_512_PUBLIC_KEY_BYTES, PCAFnDsaHook.pkBytes["fn-dsa-512"])
        XCTAssertEqual(PCAPq.FN_DSA_1024_SIGNATURE_BYTES, PCAFnDsaHook.sigBytes["fn-dsa-1024"])
        XCTAssertEqual(PCAPq.SLH_DSA_SHA2_128F_SIGNATURE_BYTES, PCASlhDsaHook.sigBytes["SLH-DSA-SHA2-128f"])
        XCTAssertEqual(PCAPq.SLH_DSA_SHA2_256S_SEED_BYTES, PCASlhDsaHook.seedBytes["SLH-DSA-SHA2-256s"])
        XCTAssertEqual(PCAPq.LESS_CAT1_PUBLIC_KEY_BYTES, PCALessHook.pkBytes)
        XCTAssertEqual(PCAPq.LESS_CAT1_SIGNATURE_MAX_BYTES, PCALessHook.sigMax)
        XCTAssertEqual(PCAPq.COMPOSITE_SIGNATURE_BYTES, 3373)
    }

    func testKnownSigAlgIsAClosedRegistry() {
        XCTAssertTrue(PCAPq.isKnownSigAlg(.string("slh-dsa-sha2-128f")))
        XCTAssertFalse(PCAPq.isKnownSigAlg(.string("slh-dsa-sha2-128F")))
        XCTAssertFalse(PCAPq.isKnownSigAlg(.int(1)))
        XCTAssertFalse(PCAPq.isKnownSigAlg(nil))
        XCTAssertEqual(PCAPq.resolveSigAlg(nil), "ed25519")
        XCTAssertNil(PCAPq.resolveSigAlg("nope"))
    }

    func testWellFormedPqPublicKeyChecksLengthAndCanonicalForm() {
        for n in [1952, 32, 2592, 64, 897, 1793, 97484] {
            XCTAssertTrue(PCAPq.isWellFormedPqPublicKey(.string(Base64URLStrict.encode([UInt8](repeating: 1, count: n)))), "\(n)")
        }
        XCTAssertFalse(PCAPq.isWellFormedPqPublicKey(.string(Base64URLStrict.encode([UInt8](repeating: 1, count: 33)))))
        XCTAssertFalse(PCAPq.isWellFormedPqPublicKey(.string("AAAA=")))
        XCTAssertFalse(PCAPq.isWellFormedPqPublicKey(.int(0)))
    }

    func testCompositeRepresentativeAndLimits() throws {
        let m = try PCAPq.compositeRepresentative(Array("m".utf8), ctx: [1, 2])
        XCTAssertEqual(m.count, 32 + 30 + 1 + 2 + 64)
        XCTAssertEqual(Array(m.prefix(32)), Array("CompositeAlgorithmSignatures2025".utf8))
        XCTAssertThrowsError(try PCAPq.compositeRepresentative([], ctx: [UInt8](repeating: 0, count: 256)))
        XCTAssertFalse(PCAPq.compositeVerify(ed25519Pub: [], mlDsaPub: [], message: [], signature: [UInt8](repeating: 0, count: 10)))
    }

    func testCompositeRoundTrip() throws {
        guard PCAPQKey.signingAvailable else { throw XCTSkip("no ML-DSA signing on this OS") }
        let ml = try PCAPq.mlDsa65Keygen([UInt8](repeating: 3, count: 32))
        let ed = try Ed25519Deterministic.key(seed: [UInt8](repeating: 4, count: 32))
        let msg = Array("composite".utf8)
        let sig = try PCAPq.compositeSign(ed25519: ed, mlDsa: ml, message: msg, ctx: [9])
        XCTAssertEqual(sig.count, PCAPq.COMPOSITE_SIGNATURE_BYTES)
        let edPub = ed.pub
        XCTAssertTrue(PCAPq.compositeVerify(ed25519Pub: edPub, mlDsaPub: ml.pk, message: msg, signature: sig, ctx: [9]))
        XCTAssertFalse(PCAPq.compositeVerify(ed25519Pub: edPub, mlDsaPub: ml.pk, message: msg, signature: sig, ctx: [8]))
        XCTAssertFalse(PCAPq.compositeVerify(ed25519Pub: edPub, mlDsaPub: ml.pk, message: Array("other".utf8), signature: sig, ctx: [9]))
        var t1 = sig; t1[10] ^= 1
        var t2 = sig; t2[sig.count - 1] ^= 1
        XCTAssertFalse(PCAPq.compositeVerify(ed25519Pub: edPub, mlDsaPub: ml.pk, message: msg, signature: t1, ctx: [9]))
        XCTAssertFalse(PCAPq.compositeVerify(ed25519Pub: edPub, mlDsaPub: ml.pk, message: msg, signature: t2, ctx: [9]))
    }
}
