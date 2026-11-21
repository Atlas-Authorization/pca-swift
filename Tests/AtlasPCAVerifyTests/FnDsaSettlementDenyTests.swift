import XCTest
@testable import AtlasPCAVerify

/// settlementWireCheck with fn-dsa-512 / fn-dsa-1024: the suites are KNOWN to the core table (PQ.suites) but only a registered verify backend
/// makes them usable. With none registered, a record is never "ok": the check answers `suite`, whatever the bytes and pins. With a backend the
/// backend alone decides (and a pin is still required). Teardown unregisters, so nothing leaks into other tests.
final class FnDsaSettlementDenyTests: XCTestCase {
    override func setUp() { PCAFnDsaHook.unregister() }
    override func tearDown() { PCAFnDsaHook.unregister() }

    static let variants: [(alg: String, pk: Int, sig: Int)] = [("fn-dsa-512", 897, 666), ("fn-dsa-1024", 1793, 1280)]

    static func record(_ alg: String, pk: [UInt8], sig: [UInt8]) -> JSONValue {
        .object([
            "claimId": .string("c1"), "action": .string("open"), "from": .string("a"), "to": .string("b"), "at": .int(1), "amount": .int(5),
            "evidenceDigest": .string(""), "alg": .string(alg), "pq_pk": .string(Base64URLStrict.encode(pk)), "sig": .string(Base64URLStrict.encode(sig)),
        ])
    }

    func testKnownSuiteWithNoBackendDeniesAsSuite() {
        XCTAssertFalse(PCAFnDsaHook.isRegistered)
        for v in Self.variants {
            XCTAssertNotNil(PQ.suites[v.alg], "the table knows \(v.alg)")
            let pk = [UInt8](repeating: 7, count: v.pk), r = Self.record(v.alg, pk: pk, sig: [UInt8](repeating: 9, count: v.sig))
            let pins = ["guardian": Base64URLStrict.encode(pk)]
            XCTAssertEqual(Optimistic.settlementWireCheck(r, guardianPublic: "guardian", pins: pins), "suite", v.alg)
            XCTAssertEqual(Optimistic.settlementWireCheck(r, guardianPublic: "guardian"), "suite", "\(v.alg): no pins")
        }
    }

    func testSignerOnlyIsNotAVerifyBackend() {
        PCAFnDsaHook.registerSigner(PCAFnDsaHook.Signer(keygen: { _, _ in ([], []) }, sign: { _, _, _, _ in [] }))
        XCTAssertFalse(PCAFnDsaHook.isRegistered)
        for v in Self.variants {
            let pk = [UInt8](repeating: 7, count: v.pk)
            let r = Self.record(v.alg, pk: pk, sig: [UInt8](repeating: 9, count: v.sig))
            XCTAssertEqual(Optimistic.settlementWireCheck(r, guardianPublic: "guardian", pins: ["guardian": Base64URLStrict.encode(pk)]), "suite", v.alg)
        }
    }

    func testBackendDecidesAndAPinIsStillRequired() {
        var calls = 0
        PCAFnDsaHook.register { _, _, _, _ in calls += 1; return true }
        for v in Self.variants {
            let before = calls
            let pk = [UInt8](repeating: 7, count: v.pk), r = Self.record(v.alg, pk: pk, sig: [UInt8](repeating: 9, count: v.sig))
            XCTAssertEqual(Optimistic.settlementWireCheck(r, guardianPublic: "guardian"), "signature", "\(v.alg): no pin never verifies")
            XCTAssertEqual(Optimistic.settlementWireCheck(r, guardianPublic: "guardian", pins: ["guardian": Base64URLStrict.encode([UInt8](repeating: 8, count: v.pk))]),
                           "signature", "\(v.alg): a different pin")
            XCTAssertEqual(calls, before, "the backend is not reached without a matching pin")
            XCTAssertEqual(Optimistic.settlementWireCheck(r, guardianPublic: "guardian", pins: ["guardian": Base64URLStrict.encode(pk)]), "ok", v.alg)
        }
        XCTAssertEqual(calls, 2)
        PCAFnDsaHook.register { _, _, _, _ in false }
        let v = Self.variants[0], pk = [UInt8](repeating: 7, count: v.pk)
        XCTAssertEqual(Optimistic.settlementWireCheck(Self.record(v.alg, pk: pk, sig: [UInt8](repeating: 9, count: v.sig)), guardianPublic: "guardian",
                                                      pins: ["guardian": Base64URLStrict.encode(pk)]), "signature")
        PCAFnDsaHook.unregister()
        XCTAssertEqual(Optimistic.settlementWireCheck(Self.record(v.alg, pk: pk, sig: [UInt8](repeating: 9, count: v.sig)), guardianPublic: "guardian",
                                                      pins: ["guardian": Base64URLStrict.encode(pk)]), "suite", "unregistered again: denied again")
    }

    func testFnDsaSignerKeyIsRefusedWithoutASigner() {
        for v in Self.variants {
            let k = PCAFnDsaKey(variant: v.alg, vk: [UInt8](repeating: 1, count: v.pk), sk: [1])
            XCTAssertThrowsError(try PCASuiteKey(alg: v.alg, fnDsa: k)) { XCTAssertEqual("\($0)", "unsupported_suite: \(v.alg)") }
            XCTAssertThrowsError(try PCASuiteKey(alg: v.alg, ed: nil)) { XCTAssertEqual("\($0)", "unsupported_suite: \(v.alg)") }
            XCTAssertThrowsError(try PCAFnDsaKey.fromSeed(v.alg, seed: [UInt8](repeating: 0, count: 32)))
        }
        PCAFnDsaHook.register { _, _, _, _ in true } // a verify-only backend still cannot sign
        let v = Self.variants[0]
        XCTAssertThrowsError(try PCASuiteKey(alg: v.alg, fnDsa: PCAFnDsaKey(variant: v.alg, vk: [UInt8](repeating: 1, count: v.pk), sk: [1])))
    }
}
