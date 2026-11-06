import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Every bound of the A2A binding at its edge (the shared vectors stop short of the exact limits) and the receipt chain's
/// signed-record branches.
final class A2aKillTests: XCTestCase {
    static func s(_ n: Int, _ c: String = "a") -> JSONValue { .string(String(repeating: c, count: n)) }
    static func need(_ extra: JObject = [:], kind: String = "scope") -> JSONValue {
        var o: JObject = ["v": .int(1), "kind": .string(kind), "verb": .string("read"), "resource": .string("doc/1")]
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }
    func err(_ extra: JObject, kind: String = "scope") -> String? { A2a.needError(Self.need(extra, kind: kind)) }

    func testVerbAndResourceLengths() {
        XCTAssertNil(err(["verb": Self.s(128)]))
        XCTAssertEqual(err(["verb": Self.s(129)]), "bad_field")
        XCTAssertNil(err(["resource": Self.s(512)]))
        XCTAssertEqual(err(["resource": Self.s(513)]), "bad_field")
    }

    func testScopes() {
        XCTAssertNil(err(["scopes": .array(Array(repeating: .string("s"), count: 16))]))
        XCTAssertEqual(err(["scopes": .array(Array(repeating: .string("s"), count: 17))]), "bad_field")
        XCTAssertNil(err(["scopes": .array([Self.s(128)])]))
        XCTAssertEqual(err(["scopes": .array([Self.s(129)])]), "bad_field")
    }

    func testGrantRefAndPolicyDigest() {
        for k in ["grant_ref", "policy_digest"] {
            XCTAssertNil(err([JKey(k): .string("g")]), k)
            XCTAssertNil(err([JKey(k): Self.s(128)]), k)
            XCTAssertEqual(err([JKey(k): Self.s(129)]), "bad_field", k)
        }
    }

    func testTier() {
        XCTAssertNil(err(["tier": .int(2)], kind: "escalate"))
        XCTAssertNil(err(["tier": .int(3)], kind: "escalate"))
        XCTAssertEqual(err(["tier": .int(1)], kind: "escalate"), "bad_field")
        XCTAssertEqual(err(["tier": .int(4)], kind: "escalate"), "bad_field")
    }

    func testLimits() {
        var sixteen: JObject = [:], seventeen: JObject = [:]
        for i in 0..<16 { sixteen[JKey("k\(i)")] = .int(1) }
        seventeen = sixteen; seventeen["k16"] = .int(1)
        XCTAssertNil(err(["limits": .object(sixteen)]))
        XCTAssertEqual(err(["limits": .object(seventeen)]), "bad_field")
        XCTAssertNil(err(["limits": .object([JKey(String(repeating: "k", count: 64)): .int(1)])]))
        XCTAssertEqual(err(["limits": .object([JKey(String(repeating: "k", count: 65)): .int(1)])]), "bad_field")
        XCTAssertNil(err(["limits": .object(["n": .int(0)])]))
        XCTAssertNil(err(["limits": .object(["n": .double(0.5)])]))
        XCTAssertEqual(err(["limits": .object(["n": .int(-1)])]), "bad_field")
        XCTAssertEqual(err(["limits": .object(["n": .string("1")])]), "bad_field")
    }

    func testDischarges() {
        let d: JSONValue = .object(["issuer": .string("i"), "claim": .string("c")])
        XCTAssertNil(err(["discharges": .array(Array(repeating: d, count: 16))]))
        XCTAssertEqual(err(["discharges": .array(Array(repeating: d, count: 17))]), "bad_field")
        XCTAssertEqual(err(["discharges": .array([.string("not an object")])]), "bad_field")
        XCTAssertNil(err(["discharges": .array([.object(["issuer": Self.s(512), "claim": Self.s(256)])])]))
        XCTAssertEqual(err(["discharges": .array([.object(["issuer": Self.s(513), "claim": .string("c")])])]), "bad_field")
        XCTAssertEqual(err(["discharges": .array([.object(["issuer": .string("i"), "claim": Self.s(257)])])]), "bad_field")
    }

    func testDecodeNeedLengthLimit() {
        // 2048 'A's is within the limit (it decodes to NUL bytes: bad_utf8); one more is too long
        XCTAssertEqual(A2a.decodeNeed(.string(String(repeating: "A", count: 2048))).code, "bad_utf8")
        XCTAssertEqual(A2a.decodeNeed(.string(String(repeating: "A", count: 2049))).code, "too_long")
    }

    func testPushTokenSaltLengthInUTF16Units() {
        let tok = { (salt: String) in A2a.pushToken(taskId: "t", chainIds: ["a"], salt: salt) }
        XCTAssertNotNil(tok(String(repeating: "s", count: 16)))
        XCTAssertNil(tok(String(repeating: "s", count: 15)))
        XCTAssertNotNil(tok(String(repeating: "\u{1F600}", count: 8)))   // 8 astral = 16 units
        XCTAssertNil(tok(String(repeating: "\u{1F600}", count: 6)))      // 12 units
        XCTAssertNil(tok(String(repeating: "\u{1F600}", count: 7) + "s")) // 15 units
        XCTAssertNil(tok(String(repeating: "\u{FFFF}", count: 8)))       // BMP: 8 units
    }

    // ---- signed receipts ----

    static let key = V2F.key("a2a-kill")
    static let signer = V2F.pub(key)
    static let chainIds = ["c1", "c2"]
    static var chain: String { PcaGrant.chainDigest(chainIds) }
    static func receipt(seq: Int64, prev: JSONValue = .null, state: String = "TASK_STATE_WORKING", taskId: String = "task-1") -> JSONValue {
        V2F.signArtifact(A2a.RECEIPT_DOMAIN, ["v": .int(1), "task_id": .string(taskId), "state": .string(state), "seq": .int(seq), "prev": prev,
                                              "chain": .string(chain), "issued_at": .int(1_000), "signer": .string(signer)], key)
    }

    func testReceiptTaskIdLength() {
        XCTAssertTrue(A2a.verifyReceipt(Self.receipt(seq: 0, taskId: String(repeating: "t", count: 4096)), signer: Self.signer))
        XCTAssertFalse(A2a.verifyReceipt(Self.receipt(seq: 0, taskId: String(repeating: "t", count: 4097)), signer: Self.signer))
    }

    func testReceiptPrevRules() {
        let r0 = Self.receipt(seq: 0)
        XCTAssertTrue(A2a.verifyReceipt(r0, signer: Self.signer))
        XCTAssertTrue(A2a.verifyReceipt(Self.receipt(seq: 1, prev: .string(A2a.receiptDigest(r0))), signer: Self.signer))
        XCTAssertFalse(A2a.verifyReceipt(Self.receipt(seq: 1, prev: .string("not-a-digest")), signer: Self.signer))
        XCTAssertFalse(A2a.verifyReceipt(Self.receipt(seq: 1), signer: Self.signer))                                        // seq > 0 needs prev
        XCTAssertFalse(A2a.verifyReceipt(Self.receipt(seq: 0, prev: .string(A2a.receiptDigest(r0))), signer: Self.signer))  // seq 0 has none
    }

    func testReceiptChainResultFields() {
        let empty = A2a.checkReceiptChain([], signer: Self.signer, taskId: "task-1", chainIds: Self.chainIds)
        XCTAssertFalse(empty.ok); XCTAssertEqual(empty.code, "empty"); XCTAssertEqual(empty.at, -1); XCTAssertFalse(empty.terminal); XCTAssertNil(empty.lastState)

        let r0 = Self.receipt(seq: 0)
        let ok = A2a.checkReceiptChain([r0], signer: Self.signer, taskId: "task-1", chainIds: Self.chainIds)
        XCTAssertTrue(ok.ok); XCTAssertNil(ok.code); XCTAssertEqual(ok.at, -1); XCTAssertFalse(ok.terminal); XCTAssertEqual(ok.lastState, "TASK_STATE_WORKING")

        let done = Self.receipt(seq: 1, prev: .string(A2a.receiptDigest(r0)), state: "TASK_STATE_COMPLETED")
        let fin = A2a.checkReceiptChain([r0, done], signer: Self.signer, taskId: "task-1", chainIds: Self.chainIds)
        XCTAssertTrue(fin.ok); XCTAssertTrue(fin.terminal); XCTAssertEqual(fin.lastState, "TASK_STATE_COMPLETED")
    }

    func testReceiptChainLinks() {
        let r0 = Self.receipt(seq: 0)
        let r1 = Self.receipt(seq: 1, prev: .string(A2a.receiptDigest(r0)))
        XCTAssertTrue(A2a.checkReceiptChain([r0, r1], signer: Self.signer, taskId: "task-1", chainIds: Self.chainIds).ok)
        // the right seq with a prev digest of another record: broken (either half alone breaks the link)
        let other = Self.receipt(seq: 0, state: "TASK_STATE_SUBMITTED")
        let wrongPrev = Self.receipt(seq: 1, prev: .string(A2a.receiptDigest(other)))
        let a = A2a.checkReceiptChain([r0, wrongPrev], signer: Self.signer, taskId: "task-1", chainIds: Self.chainIds)
        XCTAssertFalse(a.ok); XCTAssertEqual(a.code, "broken_link"); XCTAssertEqual(a.at, 1); XCTAssertFalse(a.terminal)
        // the right prev digest with a skipped seq
        let skipped = Self.receipt(seq: 2, prev: .string(A2a.receiptDigest(r0)))
        let b = A2a.checkReceiptChain([r0, skipped], signer: Self.signer, taskId: "task-1", chainIds: Self.chainIds)
        XCTAssertFalse(b.ok); XCTAssertEqual(b.code, "broken_link"); XCTAssertEqual(b.at, 1)
    }
}
