import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The durable contract enforcer: exact results of its fail-closed paths, the stored document version and the defaults of `open`.
final class SwC1EnforcerTests: XCTestCase {
    lazy var key = try! PCAEdKey(seed: [UInt8](repeating: 3, count: 32))
    let NOW = 1_700_000_000_000.0
    let ORDER = #"{"id":"order","kind":"precedes","p":{"verb":"review"},"q":{"verb":"deploy"}}"#
    let NEVER_DELETE = #"{"id":"no-delete","kind":"never","p":{"verb":"delete"}}"#

    func testAnEd25519SeedIsExactly32Bytes() throws {
        for n in [31, 33, 0] {
            XCTAssertThrowsError(try PCAEdKey(seed: [UInt8](repeating: 7, count: n))) {
                XCTAssertEqual(($0 as? PCAProducerError)?.message, "an Ed25519 seed is 32 bytes")
            }
        }
        XCTAssertEqual(try PCAEdKey(seed: [UInt8](repeating: 7, count: 32)).seed.count, 32)
    }

    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }
    func act(_ verb: String) -> JSONValue { .object(["action": .object(["verb": .string(verb), "resource": .string("/r")])]) }
    func signed(_ clauses: String) throws -> JSONValue {
        try Contracts.signContract(J(#"{"version":1,"principal":"\#(key.id)","clauses":[\#(clauses)]}"#), principal: key)
    }
    func docKey(_ c: JSONValue) -> String { "contract/" + (c.get("id")?.asString ?? "") }
    func store(_ kv: MemoryAtomicKV,_ k: String, _ v: JSONValue) { kv.update(k) { _ in v } }
    func stateJSON() -> String { #"{"now":1700000000000,"seq":0,"parent":null,"ledger":{},"latched":{}}"# }

    /// An `AtomicKV` whose `update` never runs the closure and never throws.
    final class NoopKV: AtomicKV, @unchecked Sendable {
        func get(_ key: String) throws -> JSONValue? { nil }
        func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws {}
    }
    final class BrokenKV: AtomicKV, @unchecked Sendable {
        struct Boom: Error {}
        func get(_ key: String) throws -> JSONValue? { throw Boom() }
        func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws { throw Boom() }
    }
    final class Clock: @unchecked Sendable { var t: Double; init(_ t: Double) { self.t = t } }

    let storeError = EnforceResult(allow: false, reason: "store-error", violated: [], reasons: ["store error (fail closed)"], seq: 0)

    func testStoreThatDoesNothingDeniesAsUnavailable() throws {
        let e = try ContractEnforcer.open(kv: NoopKV(), contract: try signed(ORDER), principal: key.id, now: { self.NOW })
        XCTAssertEqual(e.check(act("review")), EnforceResult(allow: false, reason: "store-error", violated: [], reasons: ["store unavailable"], seq: 0))
    }

    func testBrokenStoreDeniesWithTheExactResult() throws {
        let e = try ContractEnforcer.open(kv: BrokenKV(), contract: try signed(ORDER), principal: key.id, now: { self.NOW })
        XCTAssertEqual(e.check(act("review")), storeError)
        XCTAssertEqual(e.peek(act("review")), storeError)
    }

    func testNullLatchMemberIsAStoreErrorForCheckAndPeek() throws {
        let kv = MemoryAtomicKV()
        let sc = try signed(ORDER)
        let id = try XCTUnwrap(sc.get("id")?.asString)
        store(kv, docKey(sc), J(#"{"v":1,"contract_id":"\#(id)","state":\#(stateJSON()),"latched":null}"#))
        let e = try ContractEnforcer.open(kv: kv, contract: sc, principal: key.id, now: { self.NOW })
        XCTAssertEqual(e.check(act("review")), storeError)
        XCTAssertEqual(e.peek(act("review")), storeError)
    }

    func testClockThatIsNotFiniteDeniesWithTheExactResult() throws {
        let clock = Clock(NOW)
        let e = try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: try signed(ORDER), principal: key.id, now: { clock.t })
        XCTAssertTrue(e.check(act("review")).allow)
        clock.t = .nan
        XCTAssertEqual(e.check(act("deploy")), EnforceResult(allow: false, reason: "state-error", violated: [], reasons: ["<state>: clock is not finite"], seq: 1))
    }

    func testStoredDocumentVersionIsOne() throws {
        let kv = MemoryAtomicKV()
        let sc = try signed(ORDER)
        let id = try XCTUnwrap(sc.get("id")?.asString)
        // a version-1 document written by another process is accepted
        store(kv, docKey(sc), J(#"{"v":1,"contract_id":"\#(id)","state":\#(stateJSON())}"#))
        let e = try ContractEnforcer.open(kv: kv, contract: sc, principal: key.id, now: { self.NOW })
        let r = e.check(act("review"))
        XCTAssertTrue(r.allow, "\(r)")
        XCTAssertEqual(r.seq, 1)
        XCTAssertEqual(try kv.get(docKey(sc))?.get("v"), JSONValue.int(1))
        // and a fresh store gets a version-1 document
        let kv2 = MemoryAtomicKV()
        let e2 = try ContractEnforcer.open(kv: kv2, contract: sc, principal: key.id, now: { self.NOW })
        XCTAssertTrue(e2.check(act("review")).allow)
        XCTAssertEqual(try kv2.get(docKey(sc))?.get("v"), JSONValue.int(1))
        // a document of any other version is corrupt
        for v in [0, 2] {
            let kv3 = MemoryAtomicKV()
            store(kv3, docKey(sc), J(#"{"v":\#(v),"contract_id":"\#(id)","state":\#(stateJSON())}"#))
            let e3 = try ContractEnforcer.open(kv: kv3, contract: sc, principal: key.id, now: { self.NOW })
            XCTAssertEqual(e3.check(act("review")).reason, "state-error", "v\(v)")
        }
    }

    func testOpenDefaultsLatchOnViolation() throws {
        let e = try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: try signed("\(NEVER_DELETE),\(ORDER)"), principal: key.id, now: { self.NOW })
        XCTAssertEqual(e.check(act("delete")).reason, "violated")
        XCTAssertEqual(e.check(act("read")).reason, "latched")
    }

    func testOpenDefaultsToTheWallClockInMilliseconds() throws {
        let before = (Date().timeIntervalSince1970 * 1000).rounded(.down)
        let e = try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: try signed(ORDER), principal: key.id)
        XCTAssertTrue(e.check(act("review")).allow)
        let after = (Date().timeIntervalSince1970 * 1000).rounded(.down)
        let now = try XCTUnwrap(IV.num(try e.state()?.state.get("now")))
        XCTAssertGreaterThanOrEqual(now, before)
        XCTAssertLessThanOrEqual(now, after)
    }
}
