import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The core's LESS suites with a STUB backend (no C library): resolution only while a backend is registered, the variable-length signature wire rule
/// (1,153..1,329 bytes in steps of 16, as `sig` of the pure suite and as `pq_sig` of the hybrid), the Ed25519-first hybrid order and the fail-closed
/// handling of a backend that throws. The real verifier is covered by AtlasPCALess against the shared known answers.
final class LessCoreSuiteTests: XCTestCase {
    override func setUp() { PCALessHook.unregister() }
    override func tearDown() { PCALessHook.unregister() }

    static let pk = Base64URLStrict.encode([UInt8](repeating: 1, count: PCALessHook.pkBytes))
    static func sig(_ n: Int) -> String { Base64URLStrict.encode([UInt8](repeating: 2, count: n)) }
    static func pure(_ n: Int) -> JObject { ["alg": .string("less-cat1"), "sig": .string(sig(n)), "pq_pk": .string(pk)] }
    static func hybrid(_ edLen: Int, _ n: Int) -> JObject {
        ["alg": .string("hybrid-ed25519-less-cat1"), "sig": .string(sig(edLen)), "pq_pk": .string(pk), "pq_sig": .string(sig(n))]
    }

    func testRefusedAsUnsupportedWithoutABackend() {
        XCTAssertNil(PQ.resolve("less-cat1"))
        XCTAssertNil(PQ.resolve("hybrid-ed25519-less-cat1"))
        XCTAssertFalse(PCASuites.supported.contains("less-cat1"))
        XCTAssertEqual(PQ.validateSignatureWire(Self.pure(1329)), "unsupported_suite: less-cat1")
        XCTAssertFalse(PQ.verifySuite(alg: "less-cat1", holder: "", pq: PQ.resolvePqKey(identity: nil, artifactPk: Self.pk, trustedPk: Self.pk), message: [], sig: Self.sig(1329), pqSig: nil))
    }

    func testSignatureWireRuleIsTheVariableLengthSet() {
        PCALessHook.register { _, _, _ in true }
        for n in stride(from: 1153, through: 1329, by: 16) {
            XCTAssertNil(PQ.validateSignatureWire(Self.pure(n)), "pure \(n)")
            XCTAssertNil(PQ.validateSignatureWire(Self.hybrid(64, n)), "hybrid \(n)")
        }
        for n in [0, 1, 1137, 1152, 1154, 1168, 1328, 1330, 1345, 2000] {
            XCTAssertEqual(PQ.validateSignatureWire(Self.pure(n)), "'sig' is not canonical base64url (1153..1329 bytes) for alg 'less-cat1'", "pure \(n)")
            XCTAssertEqual(PQ.validateSignatureWire(Self.hybrid(64, n)), "'pq_sig' is not canonical base64url (1153..1329 bytes) for alg 'hybrid-ed25519-less-cat1'", "hybrid \(n)")
        }
        // the halves swapped: a LESS-length `sig` where the hybrid wants the 64-byte Ed25519 one
        XCTAssertNotNil(PQ.validateSignatureWire(Self.hybrid(1329, 1329)))
        var short = Self.pure(1329)
        short["pq_pk"] = .string(Base64URLStrict.encode([UInt8](repeating: 1, count: PCALessHook.pkBytes - 1)))
        XCTAssertNotNil(PQ.validateSignatureWire(short))
        var extra = Self.pure(1329)
        extra["pq_sig"] = .string(Self.sig(1329))
        XCTAssertEqual(PQ.validateSignatureWire(extra), "'pq_sig' must be absent for alg 'less-cat1'")
    }

    func testBackendSeesTheKeyMessageAndSignatureAndAThrowDenies() {
        let key = PQ.resolvePqKey(identity: nil, artifactPk: Self.pk, trustedPk: Self.pk)
        var seen: (Int, [UInt8], Int)?
        PCALessHook.register { vk, msg, sig in seen = (vk.count, msg, sig.count); return true }
        XCTAssertTrue(PQ.verifySuite(alg: "less-cat1", holder: "", pq: key, message: [9, 8], sig: Self.sig(1169), pqSig: nil))
        XCTAssertEqual(seen?.0, PCALessHook.pkBytes)
        XCTAssertEqual(seen?.1, [9, 8])
        XCTAssertEqual(seen?.2, 1169)
        // a length the parameter set cannot produce never reaches the backend
        seen = nil
        XCTAssertFalse(PQ.verifySuite(alg: "less-cat1", holder: "", pq: key, message: [], sig: Self.sig(1170), pqSig: nil))
        XCTAssertNil(seen)
        // a missing pinned key
        XCTAssertFalse(PQ.verifySuite(alg: "less-cat1", holder: "", pq: nil, message: [], sig: Self.sig(1329), pqSig: nil))
        struct Boom: Error {}
        PCALessHook.register { _, _, _ in throw Boom() }
        XCTAssertFalse(PQ.verifySuite(alg: "less-cat1", holder: "", pq: key, message: [], sig: Self.sig(1329), pqSig: nil))
        PCALessHook.register { _, _, _ in false }
        XCTAssertFalse(PQ.verifySuite(alg: "less-cat1", holder: "", pq: key, message: [], sig: Self.sig(1329), pqSig: nil))
    }

    func testHybridChecksEd25519BeforeTheBackendAndNeedsPqSig() {
        let key = PQ.resolvePqKey(identity: nil, artifactPk: Self.pk, trustedPk: Self.pk)
        var calls = 0
        PCALessHook.register { _, _, _ in calls += 1; return true }
        // a holder that is not an Ed25519 key, or a 64-byte signature that does not verify: the backend is never asked
        XCTAssertFalse(PQ.verifySuite(alg: "hybrid-ed25519-less-cat1", holder: "not-a-key", pq: key, message: [], sig: Self.sig(64), pqSig: Self.sig(1329)))
        XCTAssertFalse(PQ.verifySuite(alg: "hybrid-ed25519-less-cat1", holder: "not-a-key", pq: key, message: [], sig: Self.sig(64), pqSig: nil))
        XCTAssertEqual(calls, 0)
    }

    func testTheAgentSideCannotSignWithLess() {
        PCALessHook.register { _, _, _ in true }
        XCTAssertThrowsError(try PCASuiteKey(alg: "less-cat1", ed: nil))
        XCTAssertThrowsError(try PCASuiteKey(alg: "hybrid-ed25519-less-cat1", ed: nil))
    }
}
