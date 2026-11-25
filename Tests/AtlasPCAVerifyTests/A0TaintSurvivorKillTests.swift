import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Taint.swift: the registry takes its lock exactly once per call and gives it back (a dropped lock or unlock shows as a count or a held
/// depth before a second call could block), the label JSON, the join of equal ranks, the id length bound and the gate on an invalid lineage.
final class A0TaintSurvivorKillTests: XCTestCase {
    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testTheRegistryLocksOncePerCall() {
        let r = InMemoryTrustedInputRegistry()
        _ = S2LK.check(r.lock, "record") { r.record("d1", TaintLabel(kind: "web")) }
        _ = S2LK.check(r.lock, "record (empty digest, ignored)", expect: 0) { r.record("", TaintLabel(kind: "web")) }
        _ = S2LK.check(r.lock, "record (unknown kind, ignored)", expect: 0) { r.record("d2", TaintLabel(kind: "bogus")) }
        XCTAssertEqual(S2LK.check(r.lock, "lookup") { r.lookup("d1") }, TaintLabel(kind: "web"))
        XCTAssertNil(S2LK.check(r.lock, "lookup (absent)") { r.lookup("d2") })
        XCTAssertEqual(S2LK.check(r.lock, "size") { r.size }, 1)
    }

    func testRecordIgnoresAnEmptyDigestAndAnUnknownKind() {
        let r = InMemoryTrustedInputRegistry()
        r.record("", TaintLabel(kind: "trusted"))
        r.record("d", TaintLabel(kind: "bogus"))
        r.record("d", TaintLabel(kind: "agent "))
        XCTAssertEqual(r.size, 0)
        continueAfterFailure = false
        r.record("d", TaintLabel(kind: "tool", id: "t"))
        XCTAssertEqual(r.lock.depth, 0, "record gives the lock back")
        XCTAssertEqual(r.size, 1)
        XCTAssertEqual(r.lookup("d"), TaintLabel(kind: "tool", id: "t"))
    }

    func testLabelJSON() {
        XCTAssertEqual(TaintLabel(kind: "tool", id: "x").json, .object(["kind": .string("tool"), "id": .string("x")]))
        XCTAssertEqual(TaintLabel(kind: "web").json, .object(["kind": .string("web")]))
    }

    func testIsLevelOfNothingIsFalse() {
        XCTAssertFalse(Taint.isLevel(nil))
        XCTAssertTrue(Taint.isLevel("agent"))
        XCTAssertFalse(Taint.isLevel("Agent"))
    }

    func testJoinOfEqualRanksKeepsTheIdOnlyWhenBothAgree() {
        let withId = TaintLabel(kind: "tool", id: "x"), bare = TaintLabel(kind: "tool")
        XCTAssertEqual(Taint.join(withId, bare), bare, "one side has an id the other lacks: the generic representative")
        XCTAssertEqual(Taint.join(bare, withId), bare)
        XCTAssertEqual(Taint.join(bare, bare), bare)
        XCTAssertEqual(Taint.join(withId, withId), withId)
    }

    func testTheIdOfAnUnverifiedRefIsKeptUpToOneHundredTwentyEightCodeUnits() {
        let reg = EmptyTrustedInputRegistry()
        func label(_ n: Int) -> TaintLabel? {
            let ref = String(repeating: "r", count: n)
            let t = Taint.computeTaint(.object(["trusted_refs": .array([.string(ref)])]), registry: reg)
            XCTAssertTrue(t.valid)
            return t.refs.first?.label
        }
        XCTAssertEqual(label(127)?.id?.count, 127)
        XCTAssertEqual(label(128)?.id?.count, 128)
        XCTAssertNil(label(129)?.id)
        XCTAssertEqual(label(129)?.kind, "agent")
    }

    func testAnInvalidLineageNeverPassesTheGate() {
        let reg = InMemoryTrustedInputRegistry()
        let r = Taint.gate(nil, registry: reg, maxTaint: 1)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "taint: provenance is absent or malformed")
        let none = Taint.gate(.object([:]), registry: nil, maxTaint: 1)
        XCTAssertFalse(none.ok)
        XCTAssertEqual(none.reason, "taint: no trusted-input registry")
    }
}
