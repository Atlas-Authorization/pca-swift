import XCTest
@testable import AtlasPCAVerify

/// The suite table of PQ.swift pinned field by field (the verification paths read only the fields a suite needs, so a wrong
/// `nested` flag on a non-hybrid suite or a wrong constant would otherwise go unnoticed).
final class PQSuiteTableTests: XCTestCase {
    func testConstants() {
        XCTAssertEqual(PQ.ML_DSA_65_PUBLIC_KEY_BYTES, 1952)
        XCTAssertEqual(PQ.ML_DSA_65_SIGNATURE_BYTES, 3309)
        XCTAssertEqual(PQ.ED25519_SIGNATURE_BYTES, 64)
        XCTAssertEqual(MLDSA.lens(.mlDsa65).pk, PQ.ML_DSA_65_PUBLIC_KEY_BYTES)
        XCTAssertEqual(MLDSA.lens(.mlDsa65).sig, PQ.ML_DSA_65_SIGNATURE_BYTES)
    }

    func testEverySuiteFlag() {
        // name: (needsPqPk, needsPqSig, nested, has a PQ half)
        let want: [String: (Bool, Bool, Bool, Bool)] = [
            "ed25519": (false, false, false, false),
            "ml-dsa-65": (true, false, false, true),
            "hybrid-ed25519-ml-dsa-65": (true, true, false, true),
            "hybrid-nested-ed25519-ml-dsa-65": (true, true, true, true),
            "ml-dsa-87": (true, false, false, true),
            "hybrid-ed25519-ml-dsa-87": (true, true, false, true),
        ]
        XCTAssertEqual(Set(PQ.suites.keys), Set(want.keys))
        for (name, w) in want {
            let s = PQ.suites[name]!
            XCTAssertEqual(s.needsPqPk, w.0, name)
            XCTAssertEqual(s.needsPqSig, w.1, name)
            XCTAssertEqual(s.nested, w.2, name)
            XCTAssertEqual(s.pq != nil, w.3, name)
            XCTAssertEqual(s.alg.rawValue, name, name)
        }
        XCTAssertEqual(PQ.suites["ed25519"]!.sigBytes, 64)
        XCTAssertEqual(PQ.suites["ml-dsa-65"]!.sigBytes, 3309)
        XCTAssertEqual(PQ.suites["ml-dsa-87"]!.sigBytes, MLDSA.lens(.mlDsa87).sig)
    }
}
