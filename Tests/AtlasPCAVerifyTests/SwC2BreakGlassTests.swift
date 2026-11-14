import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Break-glass registry: the shard-count pin, the meta document, fail-closed answers of a store that cannot decide, and the use log kept
/// per grant, against packages/pca-grants/src/breakglass.ts.
final class SwC2BreakGlassTests: XCTestCase {
    private static let authority = V2F.key("swc2-bg-authority"), reviewer = V2F.key("swc2-bg-reviewer")
    private static let HOLDER = "holder-1"
    private static let T: Int64 = 1_000_000

    /// A store that can be switched off and that counts the updates of each key.
    final class SwitchKV: AtomicKV, @unchecked Sendable {
        struct Down: Error {}
        let inner = MemoryAtomicKV()
        private let lock = NSLock()
        private var downFlag = false
        private var counts: [String: Int] = [:]
        var down: Bool {
            get { lock.lock(); defer { lock.unlock() }; return downFlag }
            set { lock.lock(); defer { lock.unlock() }; downFlag = newValue }
        }
        func updates(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; return counts[key] ?? 0 }
        func get(_ key: String) throws -> JSONValue? {
            if down { throw Down() }
            return inner.get(key)
        }
        func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws {
            if down { throw Down() }
            lock.lock()
            counts[key, default: 0] += 1
            lock.unlock()
            inner.update(key, f)
        }
    }

    private func body() -> JObject {
        ["v": .int(1), "id": .string("g1"), "holder": .string(Self.HOLDER), "grant_ref": .string("ref"), "reason_digest": .string("rd"), "max_uses": .int(2),
         "issued_at": .int(Self.T), "expires_at": .int(Self.T + 1000), "review_within": .int(5000), "notify_to": .string("n"), "authority": .string(V2F.pub(Self.authority))]
    }

    private func signedGrant() -> JSONValue {
        var b = body()
        b["sig"] = .string(V2F.sign(Self.authority, IV.message(BreakGlass.DOMAIN, .object(b))!))
        return .object(b)
    }

    private func signedReview(at: Int64) -> JSONValue {
        var r: JObject = ["v": .int(1), "id": .string("g1"), "outcome": .string("justified"), "notes_digest": .string("nd"), "at": .int(at),
                          "reviewer": .string(V2F.pub(Self.reviewer))]
        r["sig"] = .string(V2F.sign(Self.reviewer, IV.message(BreakGlass.REVIEW_DOMAIN, .object(r))!))
        return .object(r)
    }

    private func registry(_ kv: any AtomicKV, shards: Int = 4) -> BreakGlass.Registry {
        try! BreakGlass.Registry(policy: BreakGlass.Policy(authorities: [V2F.pub(Self.authority)], reviewers: [V2F.pub(Self.reviewer)]), kv: kv, shards: shards)
    }

    private func use(_ reg: BreakGlass.Registry, at: Int64, digest: String = "d") -> BreakGlass.Decision {
        reg.use(id: .string("g1"), holder: .string(Self.HOLDER), actionDigest: .string(digest), now: .int(at), notified: .bool(true))
    }

    private func policy() -> BreakGlass.Policy { BreakGlass.Policy(authorities: ["a"], reviewers: ["r"]) }

    func testTheShardCountMustBeFromOneTo4096() {
        for ok in [1, 2, 4095, 4096] { XCTAssertNoThrow(try BreakGlass.Registry(policy: policy(), kv: MemoryAtomicKV(), shards: ok), "\(ok)") }
        for bad in [0, -1, 4097] {
            XCTAssertThrowsError(try BreakGlass.Registry(policy: policy(), kv: MemoryAtomicKV(), shards: bad), "\(bad)") {
                XCTAssertEqual(($0 as? PCAProducerError)?.message, "BreakGlassRegistry: shards must be an integer from 1 to 4096")
            }
        }
        XCTAssertNoThrow(try BreakGlass.Registry(policy: policy(), kv: MemoryAtomicKV()))
    }

    func testTheMetaDocumentIsWrittenOnceAndPinsTheCount() {
        let kv = SwitchKV()
        let reg = registry(kv, shards: 3)
        XCTAssertNil(kv.inner.get("breakglass/meta"), "nothing is written before first use")
        XCTAssertFalse(reg.frozen(holder: .string("h"), now: .int(1)))
        XCTAssertEqual(kv.inner.get("breakglass/meta"), .object(["v": .int(1), "shards": .int(3)]))
        XCTAssertFalse(reg.frozen(holder: .string("h"), now: .int(1)))
        XCTAssertFalse(reg.frozen(holder: .string("h2"), now: .int(1)))
        XCTAssertEqual(kv.updates("breakglass/meta"), 1, "a verified pin is remembered")
    }

    func testADifferentShardCountIsRefusedEverywhere() {
        let kv = MemoryAtomicKV()
        let a = registry(kv, shards: 4), b = registry(kv, shards: 5), same = registry(kv, shards: 4)
        XCTAssertFalse(a.frozen(holder: .string(Self.HOLDER), now: .int(Self.T)))
        let refusal = BreakGlass.Result(ok: false, code: "store_unreachable")
        XCTAssertEqual(b.accept(signedGrant(), now: .int(Self.T)), refusal)
        XCTAssertEqual(b.review(signedReview(at: Self.T), holder: .string(Self.HOLDER), now: .int(Self.T)), refusal)
        XCTAssertEqual(use(b, at: Self.T), BreakGlass.Decision(decision: "deny", code: "store_unreachable", id: "g1"))
        XCTAssertTrue(b.frozen(holder: .string(Self.HOLDER), now: .int(Self.T)), "an undecidable store is frozen")
        XCTAssertEqual(kv.get("breakglass/meta"), .object(["v": .int(1), "shards": .int(4)]), "the pin was not overwritten")
        XCTAssertFalse(same.frozen(holder: .string(Self.HOLDER), now: .int(Self.T)))
        XCTAssertEqual(same.accept(signedGrant(), now: .int(Self.T)), BreakGlass.Result(ok: true, replaced: true))
    }

    func testAStoreThatGoesDownRefusesEveryOperation() {
        let kv = SwitchKV()
        let reg = registry(kv)
        XCTAssertEqual(reg.accept(signedGrant(), now: .int(Self.T)), BreakGlass.Result(ok: true, replaced: true))
        let first = Self.T + 10
        XCTAssertEqual(use(reg, at: first).decision, "allow")
        kv.down = true
        let refusal = BreakGlass.Result(ok: false, code: "store_unreachable")
        XCTAssertEqual(reg.accept(signedGrant(), now: .int(Self.T)), refusal)
        XCTAssertEqual(reg.review(signedReview(at: first), holder: .string(Self.HOLDER), now: .int(first)), refusal)
        XCTAssertEqual(use(reg, at: first + 1), BreakGlass.Decision(decision: "deny", code: "store_unreachable", id: "g1"))
        XCTAssertTrue(reg.frozen(holder: .string(Self.HOLDER), now: .int(first)))
        kv.down = false
        XCTAssertFalse(reg.frozen(holder: .string(Self.HOLDER), now: .int(first)))
    }

    func testAStoreThatIsDownFromTheStartRefusesToo() {
        let kv = SwitchKV()
        kv.down = true
        let reg = registry(kv)
        let refusal = BreakGlass.Result(ok: false, code: "store_unreachable")
        XCTAssertEqual(reg.accept(signedGrant(), now: .int(Self.T)), refusal)
        XCTAssertEqual(reg.review(signedReview(at: Self.T), holder: .string(Self.HOLDER), now: .int(Self.T)), refusal)
        XCTAssertEqual(use(reg, at: Self.T).code, "store_unreachable")
        XCTAssertTrue(reg.frozen(holder: .string(Self.HOLDER), now: .int(Self.T)))
    }

    func testEachUseIsLoggedWithItsNumberDigestAndTime() throws {
        let kv = MemoryAtomicKV()
        let reg = registry(kv)
        XCTAssertEqual(reg.accept(signedGrant(), now: .int(Self.T)), BreakGlass.Result(ok: true, replaced: true))
        XCTAssertEqual(use(reg, at: Self.T + 10, digest: "d1").decision, "allow")
        XCTAssertEqual(use(reg, at: Self.T + 20, digest: "d2").decision, "allow")
        let raw = try XCTUnwrap(try reg.kv.get(reg.key(Self.HOLDER)))
        let uses = raw.asObject?[JKey("grants")]?.asObject?[JKey("g1")]?.asObject?[JKey("uses")]
        XCTAssertEqual(uses, .array([
            .object(["n": .int(1), "action_digest": .string("d1"), "at": .int(Self.T + 10)]),
            .object(["n": .int(2), "action_digest": .string("d2"), "at": .int(Self.T + 20)]),
        ]))
        let shard = BreakGlass.Shard(raw)
        XCTAssertEqual(shard.grants[JKey("g1")]?.digests, ["d1", "d2"])
        XCTAssertEqual(shard.grants[JKey("g1")]?.uses, [Self.T + 10, Self.T + 20])
    }

    func testAUseWithoutALoggedDigestIsStoredWithAnEmptyOne() {
        var s = BreakGlass.Shard()
        s.grants[JKey("g")] = BreakGlass.Entry(rec: [:], uses: [10, 20], review: nil, digests: ["a"])
        let uses = s.json.asObject?[JKey("grants")]?.asObject?[JKey("g")]?.asObject?[JKey("uses")]
        XCTAssertEqual(uses, .array([
            .object(["n": .int(1), "action_digest": .string("a"), "at": .int(10)]),
            .object(["n": .int(2), "action_digest": .string(""), "at": .int(20)]),
        ]))
        XCTAssertEqual(BreakGlass.Shard(s.json).grants[JKey("g")]?.digests, ["a", ""])
    }

    func testNoGrantsIsNotFrozen() {
        XCTAssertFalse(BreakGlass.isFrozen(nil, 5))
        XCTAssertFalse(BreakGlass.isFrozen([:], 5))
    }
}
