import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Undo windows, the pure layer: replays conformance/undo-vectors.json (every section; a missing file FAILS: load throws). Tokens
/// and receipts are re-signed with the vector seed (deterministic Ed25519) and must be the vector's bytes.
final class UndoVectorTests: XCTestCase {
    static func doc() throws -> JSONValue { try ConformanceTests.load("undo-vectors.json") }

    static func key(_ d: JSONValue) throws -> PCAEdKey {
        let label = try XCTUnwrap(d.get("signer")?.get("seed_label")?.asString)
        return try Ed25519Deterministic.key(seed: Canonical.sha256(Array(label.utf8)))
    }

    func testFormatAndSigner() throws {
        let d = try Self.doc()
        XCTAssertEqual(d.get("format")?.asString, "pca-undo-vectors")
        XCTAssertEqual(d.get("ver"), .int(1))
        XCTAssertEqual(try Self.key(d).id, d.get("signer")?.get("public")?.asString)
    }

    func testCompensationDigests() throws {
        let cases = try XCTUnwrap(Self.doc().get("compensation")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 3)
        for c in cases {
            XCTAssertEqual(Undo.compensationDigest(c.get("compensation") ?? .null), c.get("digest")?.asString, c.get("name")?.asString ?? "?")
        }
    }

    func testToken() throws {
        let d = try Self.doc()
        let t = try XCTUnwrap(d.get("token"))
        let record = try XCTUnwrap(t.get("record"))
        let token = try XCTUnwrap(t.get("token"))
        XCTAssertEqual(try Undo.signToken(record: record, key: Self.key(d)), token)
        XCTAssertEqual(Undo.encodeToken(token), t.get("encoded")?.asString)
        XCTAssertEqual(Undo.decodeToken(try XCTUnwrap(t.get("encoded")?.asString)), token)
        XCTAssertEqual(Undo.tokenDigest(token), t.get("digest")?.asString)
        let checks = try XCTUnwrap(t.get("checks")?.asArray)
        XCTAssertGreaterThanOrEqual(checks.count, 12)
        var codes: Set<String> = []
        for c in checks {
            let want = c.get("expect")?.asString ?? "?"
            codes.insert(want)
            let got = Undo.tokenCheck(c.get("token"), expectedSigner: c.get("signer")?.asString ?? "", record: c.get("record") ?? .null,
                                      now: try XCTUnwrap(IV.num(c.get("now"))))
            XCTAssertEqual(got, want, c.get("name")?.asString ?? "?")
        }
        XCTAssertEqual(codes, ["ok", "malformed", "signer", "signature", "record", "binding", "expired"])
    }

    func testReceipts() throws {
        let d = try Self.doc()
        let key = try Self.key(d)
        let signer = try XCTUnwrap(d.get("signer")?.get("public")?.asString)
        let list = try XCTUnwrap(d.get("receipts")?.get("list")?.asArray)
        XCTAssertGreaterThanOrEqual(list.count, 4)
        for x in list {
            let r = try XCTUnwrap(x.get("receipt"))
            XCTAssertEqual(Undo.receiptDigest(r), x.get("digest")?.asString)
            XCTAssertTrue(Undo.verifyReceipt(r, expectedSigner: signer))
            let again = try Undo.signReceipt(record: try XCTUnwrap(r.get("record")?.asString), event: try XCTUnwrap(r.get("event")?.asString),
                                             state: try XCTUnwrap(r.get("state")?.asString), at: try XCTUnwrap(r.get("at")?.safeInt),
                                             compensationDigest: try XCTUnwrap(r.get("compensation_digest")?.asString), prev: try XCTUnwrap(r.get("prev")?.asString),
                                             note: try XCTUnwrap(r.get("note")?.asString), key: key)
            XCTAssertEqual(again, r)
        }
        let chains = try XCTUnwrap(d.get("receipts")?.get("chains")?.asArray)
        XCTAssertGreaterThanOrEqual(chains.count, 12)
        for c in chains {
            var rec = c.get("record")?.asObject ?? [:]
            rec["receipts"] = c.get("receipts")
            let err = Undo.receiptChainError(.object(rec), expectedSigner: c.get("signer")?.asString ?? "")
            XCTAssertEqual(err == nil, c.get("expect")?.get("ok") == .bool(true), "\(c.get("name")?.asString ?? "?"): \(err ?? "nil")")
        }
    }

    func testTransitions() throws {
        let cases = try XCTUnwrap(Self.doc().get("transitions")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 33)
        var bad: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let e = c.get("expect") ?? .null
            let t = Undo.transition(c.get("record") ?? .null, c.get("event") ?? .null, now: try XCTUnwrap(IV.num(c.get("now"))))
            var got: JObject = ["outcome": .string(t.outcome)]
            if let code = t.code { got["code"] = .string(code) }
            if t.outcome == "applied" {
                got["state"] = t.record?.get("state")
                got["ver"] = t.record?.get("ver")
                if e.get("attempt") != nil { got["attempt"] = t.record?.get("attempt") }
            }
            if JSONValue.object(got) != e { bad.append("\(name): got \(Canonical.canonicalize(.object(got))) want \(Canonical.canonicalize(e))") }
            if t.outcome == "refused" && (t.reason ?? "").isEmpty { bad.append("\(name): a refusal without a reason") }
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    func testWindow() throws {
        let cases = try XCTUnwrap(Self.doc().get("window")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 9)
        for c in cases {
            let p = c.get("policy")
            XCTAssertEqual(Undo.resolveWindow(IV.num(c.get("requested")), minMs: IV.num(p?.get("minMs")), maxMs: IV.num(p?.get("maxMs")),
                                              defaultMs: IV.num(p?.get("defaultMs"))),
                           c.get("expect")?.safeInt, c.get("name")?.asString ?? "?")
        }
    }

    func testObligation() throws {
        let cases = try XCTUnwrap(Self.doc().get("obligation")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 6)
        for c in cases {
            XCTAssertEqual(Obligations.obligationError(c.get("obligation")) == nil, c.get("expect")?.get("ok") == .bool(true), c.get("name")?.asString ?? "?")
        }
    }
}

/// Mutation kills: the token check order and the inclusive exp boundary, the receipt member count, the chain links, every
/// transition row's edges, the window clamp and the obligation params.
final class UndoKillTests: XCTestCase {
    static let KEY = try! PCAEdKey(seed: [UInt8](repeating: 21, count: 32))
    static let OTHER = try! PCAEdKey(seed: [UInt8](repeating: 22, count: 32))
    static let CD = Base64URLStrict.encode([UInt8](repeating: 4, count: 32))
    static let END: Int64 = 1_800_000_900_000
    static let RECORD: JSONValue = .object(["id": .string("op_1"), "aud": .string("rs"), "principal": .string("P"), "compensation_digest": .string(CD),
                                            "window_end": .int(END)])

    static func token() -> JObject { try! Undo.signToken(record: RECORD, key: KEY).asObject! }
    static func check(_ t: JObject, _ record: JSONValue = RECORD, signer: String = KEY.id, now: Double = Double(END)) -> String {
        Undo.tokenCheck(.object(t), expectedSigner: signer, record: record, now: now)
    }
    static func rec(_ edit: (inout JObject) -> Void) -> JSONValue {
        var r = RECORD.asObject!
        edit(&r)
        return .object(r)
    }

    func testTokenCheckOrderAndTheInclusiveExpBoundary() {
        let t = Self.token()
        XCTAssertEqual(Self.check(t), "ok", "valid THROUGH window_end")
        XCTAssertEqual(Self.check(t, now: Double(Self.END) + 1), "expired")
        XCTAssertEqual(Self.check(t, now: Double(Self.END) - 0.5), "expired", "a non-integer clock")
        XCTAssertEqual(Self.check(t, now: -0.0), "expired")
        XCTAssertEqual(Self.check(t, now: .nan), "expired")
        XCTAssertEqual(Self.check(t, now: 0), "ok")
        // each earlier failure wins over every later one
        var tampered = t
        tampered["aud"] = .string("other")
        XCTAssertEqual(Self.check(tampered, signer: Self.OTHER.id, now: Double(Self.END) + 1), "signer")
        XCTAssertEqual(Self.check(tampered, Self.rec { $0["id"] = .string("op_2") }, now: Double(Self.END) + 1), "signature")
        XCTAssertEqual(Self.check(t, Self.rec {
            $0["id"] = .string("op_2")
            $0["aud"] = .string("x")
        }, now: Double(Self.END) + 1), "record")
        XCTAssertEqual(Self.check(t, Self.rec { $0["principal"] = .string("Q") }, now: Double(Self.END) + 1), "binding")
        // every binding member
        for (k, v): (String, JSONValue) in [("aud", .string("x")), ("principal", .string("x")), ("compensation_digest", .string("x")),
                                            ("render_digest", .string("x")), ("window_end", .int(Self.END - 1)), ("window_end", .string("x"))] {
            XCTAssertEqual(Self.check(t, Self.rec { $0[JKey(k)] = v }), "binding", k)
        }
        // an absent or null render digest binds the empty one
        XCTAssertEqual(Self.check(t, Self.rec { $0["render_digest"] = .null }), "ok")
        // the members: exactly ten
        var extra = t
        extra["x"] = .int(1)
        XCTAssertEqual(Self.check(extra), "malformed")
        var missing = t
        missing["render_digest"] = nil
        XCTAssertEqual(Self.check(missing), "malformed")
        var badSig = t
        badSig["sig"] = .string("short")
        XCTAssertEqual(Self.check(badSig), "malformed")
        XCTAssertEqual(Undo.tokenCheck(nil, expectedSigner: Self.KEY.id, record: Self.RECORD, now: 0), "malformed")
        XCTAssertThrowsError(try Undo.signToken(record: Self.rec { $0["id"] = .string("") }, key: Self.KEY))
    }

    func testTokenEncoding() {
        let t = JSONValue.object(Self.token())
        let e = Undo.encodeToken(t)!
        XCTAssertEqual(Undo.decodeToken(e), t)
        XCTAssertNil(Undo.decodeToken(""))
        XCTAssertNil(Undo.decodeToken(e + "="))
        XCTAssertNil(Undo.decodeToken(String(repeating: "A", count: 4097)))
        XCTAssertNil(Undo.decodeToken(Base64URLStrict.encode(Array("[1]".utf8))))
        XCTAssertNil(Undo.decodeToken(Base64URLStrict.encode(Array("{".utf8))))
        XCTAssertNotEqual(Undo.tokenDigest(t), Undo.receiptDigest(t), "the two content addresses are domain-separated")
    }

    static func receipt(_ event: String, _ state: String, at: Int64, prev: String, record: String = "op_1", note: String = "", key: PCAEdKey = KEY) -> JSONValue {
        try! Undo.signReceipt(record: record, event: event, state: state, at: at, compensationDigest: CD, prev: prev, note: note, key: key)
    }

    func testReceiptMemberCountAndFields() {
        let r = Self.receipt("opened", "open", at: 1, prev: "").asObject!
        XCTAssertEqual(r.count, 11)
        XCTAssertTrue(Undo.verifyReceipt(.object(r), expectedSigner: Self.KEY.id))
        XCTAssertFalse(Undo.verifyReceipt(.object(r), expectedSigner: Self.OTHER.id))
        var extra = r
        extra["x"] = .int(1)
        XCTAssertFalse(Undo.verifyReceipt(.object(extra), expectedSigner: Self.KEY.id), "a twelfth member")
        var missing = r
        missing["note"] = nil
        XCTAssertFalse(Undo.verifyReceipt(.object(missing), expectedSigner: Self.KEY.id), "ten members")
        var tampered = r
        tampered["at"] = .int(2)
        XCTAssertFalse(Undo.verifyReceipt(.object(tampered), expectedSigner: Self.KEY.id))
        XCTAssertThrowsError(try Undo.signReceipt(record: "op_1", event: "bogus", state: "open", at: 1, compensationDigest: Self.CD, prev: "", note: "", key: Self.KEY))
        XCTAssertThrowsError(try Undo.signReceipt(record: "op_1", event: "opened", state: "bogus", at: 1, compensationDigest: Self.CD, prev: "", note: "", key: Self.KEY))
        XCTAssertFalse(Undo.verifyReceipt(nil, expectedSigner: Self.KEY.id))
    }

    func testChainPrevAtAndLastState() {
        let r0 = Self.receipt("opened", "open", at: 100, prev: "")
        let r1 = Self.receipt("effect", "open", at: 100, prev: Undo.receiptDigest(r0)!)
        let r2 = Self.receipt("vetoed", "vetoed", at: 200, prev: Undo.receiptDigest(r1)!)
        func chain(_ rs: [JSONValue], state: String = "vetoed") -> String? {
            Undo.receiptChainError(.object(["id": .string("op_1"), "compensation_digest": .string(Self.CD), "state": .string(state), "receipts": .array(rs)]),
                                   expectedSigner: Self.KEY.id)
        }
        XCTAssertNil(chain([r0, r1, r2]), "equal times are fine")
        XCTAssertNil(chain([r0, r1], state: "open"))
        XCTAssertEqual(chain([r0, r1, r2], state: "open"), "the last receipt does not state the record state")
        XCTAssertEqual(chain([]), "no receipts")
        XCTAssertEqual(chain([r1, r2]), "receipt 0 does not link to the previous one")
        let firstLinked = Self.receipt("opened", "open", at: 100, prev: Undo.receiptDigest(r0)!)
        XCTAssertEqual(chain([firstLinked], state: "open"), "receipt 0 does not link to the previous one")
        let notOpened = Self.receipt("effect", "open", at: 100, prev: "")
        XCTAssertEqual(chain([notOpened], state: "open"), "the first receipt is not opened")
        XCTAssertEqual(chain([r0, r2]), "receipt 1 does not link to the previous one")
        let back = Self.receipt("vetoed", "vetoed", at: 99, prev: Undo.receiptDigest(r1)!)
        XCTAssertEqual(chain([r0, r1, back]), "receipt 2 goes back in time")
        let otherRecord = Self.receipt("vetoed", "vetoed", at: 200, prev: Undo.receiptDigest(r1)!, record: "op_2")
        XCTAssertEqual(chain([r0, r1, otherRecord]), "receipt 2 is for another record")
        let otherKey = Self.receipt("vetoed", "vetoed", at: 200, prev: Undo.receiptDigest(r1)!, key: Self.OTHER)
        XCTAssertEqual(chain([r0, r1, otherKey]), "receipt 2 does not verify")
    }

    static func open(_ extra: JObject = [:], state: String = "open") -> JSONValue {
        var r: JObject = ["state": .string(state), "window_end": .int(END), "ver": .int(3), "attempt": .int(0)]
        for (k, v) in extra { r[k] = v }
        return .object(r)
    }
    static let VETO: JSONValue = .object(["kind": .string("veto"), "veto": .object(["at": .int(END - 10), "via": .string("operator"), "by": .string("ops")])])
    static func t(_ r: JSONValue, _ e: JSONValue, _ now: Int64 = END) -> UndoTransition { Undo.transition(r, e, now: Double(now)) }

    func testTransitionRowsAndRecords() {
        // veto: the veto is recorded, the via is the receipt note; the window is inclusive
        let v = Self.t(Self.open(), Self.VETO)
        XCTAssertEqual(v.outcome, "applied")
        XCTAssertEqual(v.event, "vetoed")
        XCTAssertEqual(v.note, "operator")
        XCTAssertEqual(v.record?.get("veto")?.get("by")?.asString, "ops")
        XCTAssertEqual(v.record?.get("ver"), .int(4))
        XCTAssertEqual(Self.t(Self.open(), Self.VETO, Self.END + 1).code, "window_closed")
        for via in Undo.VETO_VIAS {
            let e: JSONValue = .object(["kind": .string("veto"), "veto": .object(["at": .int(1), "via": .string(via), "by": .string("b")])])
            XCTAssertEqual(Self.t(Self.open(), e).outcome, "applied", via)
        }
        XCTAssertEqual(Self.t(Self.open(), .object(["kind": .string("veto"), "veto": .object(["at": .double(1.5), "via": .string("token"), "by": .string("b")])])).code, "invalid")
        XCTAssertEqual(Self.t(Self.open(), .object(["kind": .string("veto")])).code, "invalid")
        // finalize: only strictly after the window
        XCTAssertEqual(Self.t(Self.open(), .object(["kind": .string("finalize")]), Self.END).code, "window_open")
        let f = Self.t(Self.open(), .object(["kind": .string("finalize")]), Self.END + 1)
        XCTAssertEqual(f.record?.get("outcome"), .object(["at": .int(Self.END + 1), "status": .string("finalized")]))
        XCTAssertEqual(f.note, "")
        XCTAssertEqual(Self.t(Self.open(state: "compensated"), .object(["kind": .string("finalize")]), Self.END + 1).code, "vetoed")
        // abort: before the effect only; the reason is sliced to 512 / 128 UTF-16 units without splitting a pair
        let why = String(repeating: "a", count: 127) + "😀" + String(repeating: "b", count: 600)
        let a = Self.t(Self.open(), .object(["kind": .string("abort"), "reason": .string(why)]))
        XCTAssertEqual(a.event, "aborted")
        XCTAssertEqual(a.note, String(repeating: "a", count: 127))
        XCTAssertEqual(a.record?.get("outcome")?.get("reason")?.asString?.utf16.count, 512)
        XCTAssertEqual(a.record?.get("outcome")?.get("status")?.asString, "aborted")
        XCTAssertEqual(Self.t(a.record!, .object(["kind": .string("abort")])).outcome, "replayed")
        XCTAssertEqual(Self.t(Self.open(state: "finalized"), .object(["kind": .string("abort")])).code, "finalized")
        XCTAssertEqual(Self.t(Self.open(["effect": .object(["at": .int(1)])]), .object(["kind": .string("abort")])).code, "effect_recorded")
        // effect: the result is kept; a second report is a replay
        let ef = Self.t(Self.open(), .object(["kind": .string("effect"), "result": .object(["id": .string("d1")])]), 5)
        XCTAssertEqual(ef.record?.get("effect"), .object(["at": .int(5), "result": .object(["id": .string("d1")])]))
        XCTAssertEqual(ef.record?.get("state"), .string("open"))
        XCTAssertEqual(Self.t(ef.record!, .object(["kind": .string("effect")])).outcome, "replayed")
        // compensated carries the result; compensation_failed the reason
        let c = Self.t(Self.open(state: "vetoed"), .object(["kind": .string("compensated"), "result": .string("ok")]), 7)
        XCTAssertEqual(c.record?.get("outcome"), .object(["at": .int(7), "status": .string("compensated"), "result": .string("ok")]))
        let cf = Self.t(Self.open(state: "vetoed"), .object(["kind": .string("compensation_failed"), "reason": .string("boom")]))
        XCTAssertEqual(cf.record?.get("state"), .string("compensation_failed"))
        XCTAssertEqual(cf.note, "boom")
        XCTAssertEqual(Self.t(Self.open(state: "compensated"), .object(["kind": .string("compensation_failed")])).code, "not_vetoed")
        // retry bumps the attempt; a malformed attempt is invalid
        let rt = Self.t(Self.open(["attempt": .int(2)], state: "compensation_failed"), .object(["kind": .string("retry")]))
        XCTAssertEqual(rt.record?.get("attempt"), .int(3))
        XCTAssertEqual(rt.record?.get("state"), .string("vetoed"))
        XCTAssertEqual(rt.event, "retried")
        XCTAssertEqual(Self.t(Self.open(["attempt": .string("x")], state: "compensation_failed"), .object(["kind": .string("retry")])).code, "invalid")
        // a malformed record or clock never throws: invalid
        XCTAssertEqual(Self.t(.null, Self.VETO).code, "invalid")
        XCTAssertEqual(Self.t(Self.open(["ver": .double(1.5)]), Self.VETO).code, "invalid")
        XCTAssertEqual(Undo.transition(Self.open(), Self.VETO, now: -0.0).code, "invalid")
        XCTAssertEqual(Undo.transition(Self.open(), Self.VETO, now: .infinity).code, "invalid")
        XCTAssertEqual(Undo.transition(Self.open(), Self.VETO, now: 9_007_199_254_740_992).code, "invalid")
    }

    func testWindowClampEdges() {
        XCTAssertEqual(Undo.resolveWindow(nil), Undo.DEFAULT_WINDOW_MS)
        XCTAssertEqual(Undo.resolveWindow(29_999), 30_000)
        XCTAssertEqual(Undo.resolveWindow(30_000), 30_000)
        XCTAssertEqual(Undo.resolveWindow(30_001), 30_001)
        XCTAssertEqual(Undo.resolveWindow(-5), 30_000)
        XCTAssertEqual(Undo.resolveWindow(86_400_000), 86_400_000)
        XCTAssertEqual(Undo.resolveWindow(86_400_001), 86_400_000)
        XCTAssertEqual(Undo.resolveWindow(60_000.9), 60_000, "floored to whole milliseconds")
        XCTAssertEqual(Undo.resolveWindow(.nan), Undo.DEFAULT_WINDOW_MS)
        XCTAssertEqual(Undo.resolveWindow(.infinity), Undo.DEFAULT_WINDOW_MS)
        XCTAssertEqual(Undo.resolveWindow(nil, defaultMs: 1), 30_000, "a default below the floor is clamped")
        XCTAssertEqual(Undo.resolveWindow(nil, defaultMs: .nan), Undo.DEFAULT_WINDOW_MS)
        XCTAssertEqual(Undo.resolveWindow(100_000_000, maxMs: 100_000_000), 86_400_000, "a host max above the ceiling")
        XCTAssertEqual(Undo.resolveWindow(500_000, maxMs: .nan), 500_000)
        XCTAssertEqual(Undo.resolveWindow(40_000, minMs: 50_000), 50_000)
        XCTAssertEqual(Undo.resolveWindow(40_000, minMs: .infinity), 40_000, "a non-finite policy value counts as absent")
        XCTAssertEqual(Undo.resolveWindow(1, minMs: 120_000, maxMs: 60_000), 120_000)
    }

    func testObligationParams() {
        func ok(_ params: JSONValue?, due: JSONValue? = nil) -> Bool {
            var o: JObject = ["kind": .string("undo_window")]
            if let p = params { o["params"] = p }
            if let d = due { o["due"] = d }
            return Obligations.obligationError(.object(o)) == nil
        }
        XCTAssertTrue(ok(.object(["id": .string("op_1"), "window_end": .int(0)])))
        XCTAssertTrue(ok(.object(["id": .string(String(repeating: "i", count: 128)), "window_end": .int(1)])))
        XCTAssertFalse(ok(.object(["id": .string(String(repeating: "i", count: 129)), "window_end": .int(1)])), "129 characters")
        XCTAssertFalse(ok(.object(["id": .string(""), "window_end": .int(1)])))
        XCTAssertFalse(ok(.object(["id": .string("op_1"), "window_end": .int(-1)])))
        XCTAssertFalse(ok(.object(["id": .string("op_1"), "window_end": .double(1.5)])))
        XCTAssertFalse(ok(.object(["id": .string("op_1"), "window_end": .int(1), "by": .string("x")])), "an extra member")
        XCTAssertFalse(ok(.object(["id": .int(1), "window_end": .int(1)])))
        XCTAssertFalse(ok(nil))
        XCTAssertFalse(ok(.object(["id": .string("op_1"), "window_end": .int(1)]), due: .int(-1)))
        XCTAssertTrue(Obligations.KINDS.contains("undo_window"))
        // the admission's own obligation is well formed, and a 129-character id is not
        XCTAssertNil(Obligations.obligationError(UndoAdmission(id: "op_1", windowEnd: 5, compensationVerb: "v", compensationResource: "r").obligation))
        XCTAssertNotNil(Obligations.obligationError(UndoAdmission(id: String(repeating: "i", count: 129), windowEnd: 5, compensationVerb: "v",
                                                                  compensationResource: "r").obligation))
    }
}

/// The optional undo hook of `PCA.authorize`: asked only for an unanswered, non-provenance escalation; an admission is an allow
/// that runs under a veto window and carries the `undo_window` obligation.
final class UndoAdmissionTests: XCTestCase {
    final class Hook {
        var calls: [UndoAdmitRequest] = []
        var admission: UndoAdmission? = UndoAdmission(id: "op_1", windowEnd: AZ.NOW + 900_000, compensationVerb: "payments.refund",
                                                      compensationResource: "payments/acme")
        var fail = false
        func admit(_ r: UndoAdmitRequest) throws -> UndoAdmission? {
            calls.append(r)
            if fail { throw PCAFailure("coordinator down") }
            return admission
        }
    }

    static func escalate(_ hook: Hook, _ s: AZ.Signed = EscalationTests.signed(), answer: JSONValue? = nil,
                         store: PCAStateStore = MemoryStateStore()) -> PCA.AuthorizeResult {
        AZ.run(s) {
            $0.stateStore = store
            $0.intentV2 = .context(IntentV2Context(.object([:])))
            $0.escalationAnswer = answer
            $0.escalationPrincipals = EscalationTests.pin
            $0.insecureUnboundApproval = true
            $0.undo = hook.admit
        }
    }

    // (a)
    func testAnEscalationAdmittedByTheHookIsAnAllowUnderAVetoWindow() throws {
        let hook = Hook()
        let r = Self.escalate(hook)
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(r.decision, "allow")
        XCTAssertNil(r.escalation)
        XCTAssertEqual(r.undo, hook.admission)
        let end = AZ.NOW + 900_000
        XCTAssertEqual(r.obligations, [.object(["kind": .string("undo_window"), "params": .object(["id": .string("op_1"), "window_end": .int(end)]),
                                                 "due": .int(end)])])
        XCTAssertEqual(r.checks["undo_window"], .pass)
        XCTAssertEqual(r.checks["tighten"], .pass)
        XCTAssertEqual(r.failedChecks, [])
        XCTAssertTrue(r.reasons.contains("undo_window: runs now under a veto window until \(end) (compensation payments.refund)"), "\(r.reasons)")
        XCTAssertEqual(hook.calls.count, 1)
        let req = try XCTUnwrap(hook.calls.first)
        XCTAssertEqual(req.operation.verb, "payments.send")
        XCTAssertEqual(req.grant.get("id"), req.pcactn.get("grant_ref"))
        XCTAssertEqual(req.pcactn.get("action")?.get("verb")?.asString, "payments.send")
        // the admission spent the replay counter like any allow
        let store = MemoryStateStore()
        XCTAssertTrue(Self.escalate(Hook(), store: store).allow)
        XCTAssertFalse(Self.escalate(Hook(), store: store).allow)
        // without the hook the same call escalates
        let none = AZ.run(EscalationTests.signed()) {
            $0.intentV2 = .context(IntentV2Context(.object([:])))
        }
        XCTAssertEqual(none.decision, "escalate")
        XCTAssertNil(none.undo)
        XCTAssertEqual(none.obligations, [])
    }

    // (b)
    func testAProvenanceEscalationNeverReachesTheHook() {
        let hook = Hook()
        let s = AZ.signed()
        let r = ProvenanceFlowTests.raw(s) {
            $0.argProvenance.mediators = [ProvHarness.pin] // pinned, but no bundle: the arguments are unverified
            $0.undo = hook.admit
        }
        XCTAssertEqual(r.decision, "escalate")
        XCTAssertEqual(r.checks["provenance_flow"], .fail)
        XCTAssertNil(r.undo)
        XCTAssertEqual(hook.calls.count, 0)
        // the same with another escalate-class failure next to it
        let both = ProvenanceFlowTests.raw(EscalationTests.signed()) {
            $0.intentV2 = .context(IntentV2Context(.object([:])))
            $0.undo = hook.admit
        }
        XCTAssertEqual(both.decision, "escalate")
        XCTAssertEqual(both.failedChecks, ["provenance_flow", "tighten"])
        XCTAssertEqual(hook.calls.count, 0)
    }

    // (c) Intent v2 rule 17 (`provenance`) is the core verifier's check; the gate that keeps the hook away is asserted on the verdict
    func testARule17ProvenanceFailureBlocksTheHook() {
        XCTAssertTrue(PCA.undoEligible(escalated: true, answerPresented: false, checks: ["tighten": .fail]))
        XCTAssertFalse(PCA.undoEligible(escalated: true, answerPresented: false, checks: ["tighten": .fail, "provenance": .fail]))
        XCTAssertFalse(PCA.undoEligible(escalated: true, answerPresented: false, checks: ["provenance": .fail]))
        XCTAssertTrue(PCA.undoEligible(escalated: true, answerPresented: false, checks: ["tighten": .fail, "provenance": .pass, "provenance_flow": .notEnforced]))
        XCTAssertFalse(PCA.undoEligible(escalated: true, answerPresented: false, checks: ["provenance_flow": .fail]))
        XCTAssertFalse(PCA.undoEligible(escalated: true, answerPresented: true, checks: ["tighten": .fail]))
        XCTAssertFalse(PCA.undoEligible(escalated: false, answerPresented: false, checks: ["tighten": .fail]))
    }

    // (d)
    func testAPresentedAnswerIsNeverOverridden() {
        let hook = Hook()
        let s = EscalationTests.signed()
        let allow = Self.escalate(hook, s, answer: EscalationTests.answer(s))
        XCTAssertTrue(allow.allow, "\(allow.reasons)")
        XCTAssertNil(allow.undo)
        XCTAssertEqual(allow.obligations, [])
        // an answer that does not admit (signed by an unpinned key) keeps the escalation: the hook is still not asked
        let foreign = Self.escalate(hook, s, answer: EscalationTests.answer(s, key: V2F.agent))
        XCTAssertEqual(foreign.decision, "escalate")
        XCTAssertNil(foreign.undo)
        XCTAssertEqual(hook.calls.count, 0)
    }

    // (e)
    func testAHookThatThrowsOrDeclinesLeavesTheEscalation() {
        let throwing = Hook()
        throwing.fail = true
        let r = Self.escalate(throwing)
        XCTAssertEqual(r.decision, "escalate")
        XCTAssertNil(r.undo)
        XCTAssertEqual(throwing.calls.count, 1)
        let declining = Hook()
        declining.admission = nil
        XCTAssertEqual(Self.escalate(declining).decision, "escalate")
        // an admission whose obligation is malformed is ignored (fail closed)
        let malformed = Hook()
        malformed.admission = UndoAdmission(id: String(repeating: "i", count: 129), windowEnd: 1, compensationVerb: "v", compensationResource: "r")
        let m = Self.escalate(malformed)
        XCTAssertEqual(m.decision, "escalate")
        XCTAssertNil(m.undo)
    }

    // (f)
    func testADenyIsNeverTouched() {
        let hook = Hook()
        // the proof is for 50, the handler would run 400: an operation failure is a deny
        let r = AZ.run(EscalationTests.signed()) {
            $0.intentV2 = .context(IntentV2Context(.object([:])))
            $0.operation = PCA.Operation(verb: "payments.send", resource: "payments/acme", params: AuthorizeTests.P400)
            $0.undo = hook.admit
        }
        XCTAssertEqual(r.decision, "deny")
        XCTAssertNil(r.undo)
        XCTAssertEqual(hook.calls.count, 0)
    }
}
