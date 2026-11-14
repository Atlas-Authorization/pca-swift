import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Boundaries of dead-man liveness beacons, against packages/pca/src/beacons.ts: issue-time limits, the hard maximum validity, the
/// seq floor, strict-canonical refusal, and the durable acceptor's reading of stored state.
final class SwC2BeaconsTests: XCTestCase {
    private lazy var key = try! PCAEdKey(seed: [UInt8](repeating: 9, count: 32))
    private let MAX: Int64 = 3_600_000

    private func issue(seq: Int64 = 1, at: Int64 = 1_700_000_000_000, validity: Int64? = nil) throws -> JSONValue {
        try Beacons.issueLivenessBeacon(issuer: PCASuiteKey.ed25519(key), instance: "inst", seq: seq, issuedAt: at, validityMs: validity)
    }

    /// A correctly signed beacon whose window is chosen freely (the issuer API refuses an out-of-range one).
    private func forge(seq: Int64 = 1, issuedAt: Int64, notAfter: Int64) throws -> JSONValue {
        let body: JSONValue = .object(["v": .int(2), "instance": .string("inst"), "scope": .string("*"), "epoch": .int(issuedAt / 60_000), "seq": .int(seq),
                                       "issued_at": .int(issuedAt), "not_after": .int(notAfter), "issuer": .string(key.id)])
        return .object(try PCAIssue.signArtifact(domain: Beacons.LIVENESS_DOMAIN, body: body, signer: PCASuiteKey.ed25519(key)))
    }

    private func verify(_ b: JSONValue, now: Int64) -> BeaconVerdict {
        Beacons.verifyLivenessBeacon(b, issuers: [key.id], now: now, instance: "inst")
    }

    func testTheHardMaximumIsOneHour() throws {
        XCTAssertEqual(Beacons.BEACON_MAX_VALIDITY_MS, 3_600_000)
        let t: Int64 = 1_700_000_000_000
        let b = try issue(at: t, validity: MAX)
        XCTAssertEqual(verify(b, now: t), .pass)
        XCTAssertEqual(verify(b, now: t + MAX), .pass)
        XCTAssertEqual(verify(b, now: t + MAX + 1).reason, "expired")
    }

    func testIssueLimits() throws {
        // seq and issuedAt may be zero, a negative is refused
        XCTAssertNoThrow(try issue(seq: 0))
        XCTAssertThrowsError(try issue(seq: -1))
        XCTAssertNoThrow(try issue(at: 0))
        XCTAssertThrowsError(try issue(at: -1))
        // validity: (0, MAX]
        XCTAssertThrowsError(try issue(validity: 0))
        XCTAssertThrowsError(try issue(validity: -1))
        XCTAssertNoThrow(try issue(validity: 1))
        XCTAssertNoThrow(try issue(validity: MAX))
        XCTAssertThrowsError(try issue(validity: MAX + 1))
    }

    func testSeqZeroAndIssuedAtZeroVerify() throws {
        XCTAssertEqual(verify(try issue(seq: 0), now: 1_700_000_000_000), .pass)
        XCTAssertEqual(verify(try issue(at: 0, validity: 100), now: 0), .pass)
    }

    func testTheWindowBoundsOfAForgedBeacon() throws {
        let t: Int64 = 1_700_000_000_000
        let hard = "validity exceeds the hard maximum"
        XCTAssertEqual(verify(try forge(issuedAt: t, notAfter: t), now: t).reason, hard)
        XCTAssertEqual(verify(try forge(issuedAt: t, notAfter: t - 1), now: t).reason, hard)
        XCTAssertEqual(verify(try forge(issuedAt: t, notAfter: t + 1), now: t), .pass)
        XCTAssertEqual(verify(try forge(issuedAt: t, notAfter: t + MAX), now: t), .pass)
        XCTAssertEqual(verify(try forge(issuedAt: t, notAfter: t + MAX + 1), now: t).reason, hard)
        XCTAssertEqual(verify(try forge(issuedAt: t, notAfter: t + 10 * MAX), now: t).reason, hard)
    }

    func testANonCanonicalBodyIsMalformedBeforeTheSignatureIsLookedAt() throws {
        guard case var .object(m) = try issue() else { return XCTFail() }
        m["issued_at"] = .int(Canonical.MAX_SAFE + 1)
        XCTAssertEqual(verify(.object(m), now: 1_700_000_000_000).reason, "malformed beacon")
    }

    func testAcceptBeaconSeqRange() {
        func next(_ seq: Int64) -> JSONValue { .object(["seq": .int(seq)]) }
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: nil, next: next(0)), .pass)
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: nil, next: next(Canonical.MAX_SAFE)), .pass)
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: nil, next: next(Canonical.MAX_SAFE + 1)).reason, "malformed beacon")
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: nil, next: next(-1)).reason, "malformed beacon")
    }

    // ---- the durable acceptor ----

    private func stored(_ b: JSONValue) -> String {
        guard case let .object(m) = b else { return "" }
        return Beacons.Acceptor.key(m)
    }

    func testAStoredZeroIsAValidSequence() throws {
        let kv = MemoryAtomicKV()
        let b = try issue(seq: 1)
        kv.update(stored(b)) { _ in .int(0) }
        XCTAssertEqual(Beacons.Acceptor(kv: kv).accept(b, issuers: [key.id], now: 1_700_000_000_000, instance: "inst"), .pass)
    }

    func testAStoredMaximumSequenceIsAReplayNotJunk() throws {
        let kv = MemoryAtomicKV()
        let b = try issue(seq: Canonical.MAX_SAFE)
        kv.update(stored(b)) { _ in .int(Canonical.MAX_SAFE) }
        let v = Beacons.Acceptor(kv: kv).accept(b, issuers: [key.id], now: 1_700_000_000_000, instance: "inst")
        XCTAssertFalse(v.ok)
        XCTAssertTrue(v.reason?.hasPrefix("replayed beacon: seq ") == true, v.reason ?? "nil")
    }

    func testJunkOnDiskIsRefusedAsUnavailable() throws {
        let b = try issue(seq: 5)
        let junk: [JSONValue] = [.int(-1), .string("x"), .double(1.5), .int(Canonical.MAX_SAFE + 1), .bool(true), .array([])]
        for j in junk {
            let kv = MemoryAtomicKV()
            kv.update(stored(b)) { _ in j }
            let v = Beacons.Acceptor(kv: kv).accept(b, issuers: [key.id], now: 1_700_000_000_000, instance: "inst")
            XCTAssertEqual(v, BeaconVerdict.no("beacon state unavailable"), "\(j)")
            XCTAssertEqual(kv.get(stored(b)), j, "junk is left untouched")
        }
    }
}
