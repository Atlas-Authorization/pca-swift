import XCTest
import Foundation
@testable import AtlasPCAVerify

/// H13: the revocation-epoch rollback pin is automatic (stored `<grant id>:epoch`, raised only after an allow); H16: a store declares its scope
/// and `multiInstance` over a process-scoped store is refused at construction.
final class A0H13PinStoreTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testAPinOnlyRises() throws {
        let s = MemoryStateStore()
        XCTAssertNil(s.pin(key: "g:epoch"))
        s.raisePin(key: "g:epoch", value: 7)
        s.raisePin(key: "g:epoch", value: 6)
        XCTAssertEqual(s.pin(key: "g:epoch"), 7)
        s.raisePin(key: "g:epoch", value: 8)
        XCTAssertEqual(s.pin(key: "g:epoch"), 8)
        XCTAssertNil(s.pin(key: "other:epoch"))
    }

    func testConcurrentRaisesEndAtTheMaximum() {
        let s = MemoryStateStore()
        let done: Bool? = S2Deadline.within(20, "concurrent raisePin") {
            let g = DispatchGroup()
            for v in [7.0, 6.0, 9.0, 3.0, 8.0, 1.0] {
                g.enter()
                DispatchQueue.global().async { s.raisePin(key: "g:epoch", value: v); g.leave() }
            }
            g.wait()
            return true
        }
        XCTAssertEqual(done, true)
        XCTAssertEqual(s.pin(key: "g:epoch"), 9)
    }
}

final class A0H13RollbackPinTests: XCTestCase {
    private let seed = [UInt8](repeating: 9, count: 32)
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func epoch(_ n: Int64, grantRef: String) throws -> JSONValue {
        let root = try XCTUnwrap(IntentRevocation.bindRoot(JSONValue.int(0), IntentRevocation.EMPTY_TREE))
        return try XCTUnwrap(PCA.signRevocationEpoch(guardianSeed: seed, RevocationEpochBody(instanceId: "i", grantRef: grantRef, epoch: n, setSize: 0, root: root,
                                                                                         issuedAt: AZ.NOW - 10, notAfter: AZ.NOW + 100_000)))
    }

    private func run(_ store: MemoryStateStore, epochNumber: Int64, hostLast: Double? = nil, guardianOverride: String? = nil) throws -> (PCA.AuthorizeResult, String) {
        // the PCActn carries a freshness epoch at least as new as every revocation epoch used here
        let s = AZ.signed(extra: ["freshness": .object(["epoch": .int(100), "beacon_ref": .string("b"), "accumulator_witness": .string("w")])])
        let gref = try XCTUnwrap(s.pcactn.get("grant_ref")?.asString)
        let ep = try epoch(epochNumber, grantRef: gref)
        let guardian = try XCTUnwrap(ep.get("guardian")?.asString)
        let r = AZ.run(s) {
            $0.stateStore = store
            $0.revocationStaleness = RevocationStalenessPolicy(maxRevocationAgeMs: 100_000)
            $0.guardianPublic = guardianOverride ?? guardian
            $0.revocationState = { _, _ in RevocationState(epoch: ep, lastAcceptedEpoch: hostLast) }
            $0.revocationProof = { _, _ in JSONValue.object(["size": JSONValue.int(0)]) }
        }
        return (r, gref)
    }

    func testAnAllowedFreshnessPassRaisesThePin() throws {
        let store = MemoryStateStore()
        let (r, gref) = try run(store, epochNumber: 6)
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(store.pin(key: "\(gref):epoch"), 6)
    }

    func testAValidOlderEpochIsARollbackOnceThePinIsHigher() throws {
        let store = MemoryStateStore()
        let gref = try XCTUnwrap(AZ.signed().pcactn.get("grant_ref")?.asString)
        store.raisePin(key: "\(gref):epoch", value: 5)
        let (r, _) = try run(store, epochNumber: 4)
        XCTAssertFalse(r.allow)
        XCTAssertTrue(r.reasons.contains { $0.contains("revocation epoch 4 is older than the last accepted 5 (rollback)") }, "\(r.reasons)")
        XCTAssertEqual(store.pin(key: "\(gref):epoch"), 5, "a denied action never moves the pin")
        let (ok, _) = try run(MemoryStateStore(), epochNumber: 4)
        XCTAssertTrue(ok.allow, "no pin, no host value: epoch 4 stands: \(ok.reasons)")
    }

    func testTheEffectiveFloorIsTheLargerOfHostAndPin() throws {
        let store = MemoryStateStore()
        let gref = try XCTUnwrap(AZ.signed().pcactn.get("grant_ref")?.asString)
        store.raisePin(key: "\(gref):epoch", value: 5)
        let (r, _) = try run(store, epochNumber: 6, hostLast: 9)
        XCTAssertFalse(r.allow)
        XCTAssertTrue(r.reasons.contains { $0.contains("older than the last accepted 9 (rollback)") }, "\(r.reasons)")
        let (ok, _) = try run(MemoryStateStore(), epochNumber: 6, hostLast: 5)
        XCTAssertTrue(ok.allow, "\(ok.reasons)")
    }

    func testADeniedRequestLeavesNoPin() throws {
        let store = MemoryStateStore()
        let (r, gref) = try run(store, epochNumber: 6, guardianOverride: "not-the-guardian")
        XCTAssertFalse(r.allow)
        XCTAssertNil(store.pin(key: "\(gref):epoch"))
    }

    func testAStoreWithoutPinsIsRefusedWhenStalenessIsConfigured() throws {
        struct NoPins: PCAStateStore {
            func claim(key: String, counter: Int64) throws -> ClaimResult { ClaimResult(ok: true) }
        }
        var az = PcaAuthorizeConfig(stateStore: NoPins(), isRevoked: { _, _ in false }, plan: PCA.SINGLE_STEP, riskSource: PCA.insecureCalmRisk)
        az.revocationStaleness = RevocationStalenessPolicy(maxRevocationAgeMs: 1000)
        XCTAssertThrowsError(try PcaGuard(PcaGuardConfig(audience: "a", authorize: az))) {
            XCTAssertEqual(($0 as? PcaGuardConfigError)?.message, "revocation staleness needs a state store that implements pins (rollback protection)")
        }
        az.revocationStaleness = nil
        XCTAssertNoThrow(try PcaGuard(PcaGuardConfig(audience: "a", authorize: az)))
        az.stateStore = MemoryStateStore()
        az.revocationStaleness = RevocationStalenessPolicy(maxRevocationAgeMs: 1000)
        XCTAssertNoThrow(try PcaGuard(PcaGuardConfig(audience: "a", authorize: az)))
    }
}

final class A0H16MultiInstanceTests: XCTestCase {
    private struct SharedStore: PCAStateStore {
        func claim(key: String, counter: Int64) throws -> ClaimResult { ClaimResult(ok: true) }
    }
    private static let message = "multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)"

    func testScopes() {
        XCTAssertEqual(MemoryStateStore().scope, .process)
        XCTAssertEqual(SharedStore().scope, .shared, "a store that does not say is shared")
    }

    func testAProcessStoreWithMultiInstanceIsRefusedAndASharedOneIsFine() {
        var az = PcaAuthorizeConfig(stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, riskSource: PCA.insecureCalmRisk)
        az.multiInstance = true
        XCTAssertThrowsError(try PcaGuard(PcaGuardConfig(audience: "a", authorize: az))) { XCTAssertEqual(($0 as? PcaGuardConfigError)?.message, Self.message) }
        az.multiInstance = false
        XCTAssertNoThrow(try PcaGuard(PcaGuardConfig(audience: "a", authorize: az)))
        az.multiInstance = nil
        XCTAssertNoThrow(try PcaGuard(PcaGuardConfig(audience: "a", authorize: az)))
        az.stateStore = SharedStore()
        az.multiInstance = true
        XCTAssertNoThrow(try PcaGuard(PcaGuardConfig(audience: "a", authorize: az)))
    }

    func testTheDefaultFollowsTheStoreScope() {
        var az = PcaAuthorizeConfig()
        XCTAssertTrue(az.effectiveMultiInstance(SharedStore()), "default with a shared store: on")
        XCTAssertFalse(az.effectiveMultiInstance(MemoryStateStore()), "default with a process store: off")
        az.multiInstance = false
        XCTAssertFalse(az.effectiveMultiInstance(SharedStore()))
        az.multiInstance = true
        XCTAssertTrue(az.effectiveMultiInstance(SharedStore()))
    }
}
