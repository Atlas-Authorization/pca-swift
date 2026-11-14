import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Blueprint stores and the registry's fail-closed answers when its store cannot decide, against packages/pca-grants/src/blueprint.ts.
final class SwC2BlueprintTests: XCTestCase {
    private static let op = V2F.key("swc2-bp-operator")

    struct Down: Error {}

    /// A store that cannot answer, or that reads but cannot write.
    final class BrokenStore: Blueprint.Store, @unchecked Sendable {
        let readsWork: Bool
        init(readsWork: Bool) { self.readsWork = readsWork }
        func get(_ key: String) throws -> JObject? { if readsWork { return nil }; throw Down() }
        func put(_ b: JObject) throws { throw Down() }
        func maxEpoch() throws -> Int64 { throw Down() }
    }

    private func text(_ n: Int) -> String { String(repeating: "a", count: n) }

    private func signed() -> JSONValue {
        var b: JObject = ["v": .int(1), "id": .string("bp1"), "key": .string("BP"), "ceiling": .array([]), "epoch": .int(1), "status": .string("active"),
                          "issued_at": .int(1), "operator": .string(V2F.pub(Self.op))]
        b["sig"] = .string(V2F.sign(Self.op, IV.message(Blueprint.DOMAIN, .object(b))!))
        return .object(b)
    }

    func testAnUnreachableStoreRefusesWithExactFields() {
        let refusal = Blueprint.Accept(ok: false, replaced: false, code: "store_unreachable")
        for readsWork in [false, true] {
            let reg = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: BrokenStore(readsWork: readsWork))
            XCTAssertEqual(reg.accept(signed()), refusal, "readsWork \(readsWork)")
        }
    }

    func testTheEpochOfAnUnreadableStoreIsZero() {
        let reg = Blueprint.Registry(operators: [], store: BrokenStore(readsWork: false))
        XCTAssertEqual(reg.epoch, 0)
        XCTAssertThrowsError(try reg.epochOrThrow())
    }

    func testMemoryStoreKeysAreBoundedTo128() throws {
        let s = Blueprint.MemoryStore()
        try s.put(["key": .string(text(128)), "epoch": .int(1)])
        XCTAssertNotNil(try s.get(text(128)))
        XCTAssertNil(try s.get(""))
        try s.put(["key": .string(text(129)), "epoch": .int(1)])
        XCTAssertNil(try s.get(text(129)), "an over-long key is not stored under its own name")
        XCTAssertNotNil(try s.get(""), "it falls to the empty key")
    }

    func testKVStoreKeysAreBoundedTo128() throws {
        let s = Blueprint.KVStore(kv: MemoryAtomicKV())
        try s.put(["key": .string(text(128)), "epoch": .int(1)])
        XCTAssertNotNil(try s.get(text(128)))
        XCTAssertNil(try s.get(""))
        try s.put(["key": .string(text(129)), "epoch": .int(1)])
        XCTAssertNil(try s.get(text(129)))
        XCTAssertNotNil(try s.get(""))
    }

    func testKVStorePutKeepsTheStoredRecordUnlessTheEpochIsHigher() throws {
        let s = Blueprint.KVStore(kv: MemoryAtomicKV())
        try s.put(["key": .string("bp"), "epoch": .int(5), "id": .string("first")])
        try s.put(["key": .string("bp"), "epoch": .int(3), "id": .string("older")])
        XCTAssertEqual(try s.get("bp")?[JKey("id")], .string("first"))
        try s.put(["key": .string("bp"), "epoch": .int(5), "id": .string("same-epoch")])
        XCTAssertEqual(try s.get("bp")?[JKey("id")], .string("first"))
        try s.put(["key": .string("bp"), "epoch": .int(6), "id": .string("newer")])
        XCTAssertEqual(try s.get("bp")?[JKey("id")], .string("newer"))
        try s.put(["key": .string("other"), "epoch": .int(1), "id": .string("x")])
        XCTAssertEqual(try s.get("other")?[JKey("id")], .string("x"))
        XCTAssertEqual(try s.maxEpoch(), 6)
    }

    func testConcurrentAcceptsOverASharedKVNeverLowerARecord() throws {
        let kv = MemoryAtomicKV()
        let pub = V2F.pub(Self.op)
        let regs = (0..<4).map { _ in Blueprint.Registry(operators: [pub], store: Blueprint.KVStore(kv: kv)) }
        let recs: [JSONValue] = (1...64).map { e in
            var b: JObject = ["v": .int(1), "id": .string("bp1"), "key": .string("BP"), "ceiling": .array([]), "epoch": .int(Int64(e)), "status": .string("active"),
                              "issued_at": .int(1), "operator": .string(pub)]
            b["sig"] = .string(V2F.sign(Self.op, IV.message(Blueprint.DOMAIN, .object(b))!))
            return .object(b)
        }
        DispatchQueue.concurrentPerform(iterations: 64) { i in _ = regs[i % 4].accept(recs[63 - i]) }
        XCTAssertEqual(try Blueprint.KVStore(kv: kv).get("BP")?[JKey("epoch")], .int(64))
        XCTAssertEqual(regs[0].epoch, 64)
    }

    func testKVStoreMaxEpochStartsAtZeroAndOnlyRises() throws {
        let kv = MemoryAtomicKV()
        let s = Blueprint.KVStore(kv: kv)
        XCTAssertEqual(try s.maxEpoch(), 0)
        try s.put(["key": .string("a"), "epoch": .int(1)])
        XCTAssertEqual(try s.maxEpoch(), 1)
        try s.put(["key": .string("b"), "epoch": .int(3)])
        XCTAssertEqual(try s.maxEpoch(), 3)
        try s.put(["key": .string("c"), "epoch": .int(2)])
        XCTAssertEqual(try s.maxEpoch(), 3)
        XCTAssertEqual(kv.get("blueprint/max-epoch"), .int(3))
        try s.put(["key": .string("d"), "epoch": .int(3)])
        XCTAssertEqual(kv.get("blueprint/max-epoch"), .int(3))
    }

    func testARecordWithoutAnEpochNeverMovesTheMaximum() throws {
        let kv = MemoryAtomicKV()
        let s = Blueprint.KVStore(kv: kv)
        try s.put(["key": .string("a")])
        XCTAssertEqual(try s.maxEpoch(), 0)
        XCTAssertNil(kv.get("blueprint/max-epoch"), "epoch 0 is not above the empty maximum, nothing is written")
        try s.put(["key": .string("b"), "epoch": .int(0)])
        XCTAssertNil(kv.get("blueprint/max-epoch"))
    }
}
