import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mutation-kill tests for IntentAcc.swift: declaration validators, selection, value/combination, receipt and key-set
/// shapes, freshness validation and receipt arithmetic. Every boundary is pinned on both sides.
final class IntentAccKillTests: XCTestCase {
    typealias A = IntentAcc

    func s(_ x: String) -> JSONValue { .string(x) }
    func digest(_ b: UInt8 = 0) -> String { Base64URLStrict.encode([UInt8](repeating: b, count: 32)) }

    func build(_ base: [String: JSONValue], _ patch: [String: JSONValue?]) -> JSONValue {
        var o = JObject()
        for (k, v) in base { o[JKey(k)] = v }
        for (k, v) in patch { o[JKey(k)] = v }   // a nil patch value removes the member (assigning nil removes the key)
        return .object(o)
    }

    // ---- constants / tracked key set ----

    func testSessionLimits() {
        XCTAssertEqual(A.MAX_SESSION_ACCUMULATORS, 16)
        XCTAssertEqual(A.MAX_SESSION_MONITORS, 16)
        XCTAssertEqual(A.MAX_MONITOR_WITHIN, 64)
        XCTAssertEqual(A.MAX_RECEIPT_LIFETIME_MS, 900_000)
    }

    func testTrackedKeySetVersion() {
        let msg = "a tracked key set version must be a safe integer >= 1"
        func t(_ v: Int64) -> String? { A.trackedKeySetError(.object(["version": .int(v), "digest": s(digest())])) }
        XCTAssertNil(t(1))
        XCTAssertNil(t(2))
        XCTAssertEqual(t(0), msg)
        XCTAssertEqual(t(-1), msg)
        XCTAssertEqual(A.trackedKeySet(.object(["version": .int(1), "digest": s(digest())]))?.version, 1)
        XCTAssertNil(A.trackedKeySet(.object(["version": .int(0), "digest": s(digest())])))
    }

    // ---- isKid ----

    func testIsKid() {
        for k in ["a", "Z", "z", "A", "0", "9", "_", ".", ":", "-", "a_b.c:d-e", "09azAZ"] { XCTAssertTrue(A.isKid(k), k) }
        for k in ["", "/", "@", "[", "`", "{", " ", "a b", "a/b", "\u{e9}"] { XCTAssertFalse(A.isKid(k), k) }
        XCTAssertTrue(A.isKid(String(repeating: "a", count: 64)))
        XCTAssertFalse(A.isKid(String(repeating: "a", count: 65)))
    }

    // ---- accumulatorDeclError ----

    let accBase: [String: JSONValue] = [
        "id": .string("a1"), "agg": .string("count"), "sel": .object(["verbs": .array([.string("v")])]),
        "win": .object(["kind": .string("task")]), "key": .null, "holder": .object(["kind": .string("site_local")]),
    ]
    func accErr(_ patch: [String: JSONValue?] = [:]) -> String? { A.accumulatorDeclError(build(accBase, patch)) }
    let at = "accumulator 'a1'"

    func testAccBaseValid() {
        XCTAssertNil(accErr())
    }

    func testAccKnownAndUnknownMembers() {
        XCTAssertEqual(accErr(["extra": .int(1)]), "accumulator: unknown member 'extra'")
        XCTAssertNil(accErr(["agg": s("sum"), "val": s("action.params.x"), "unit": s("u"), "domain_max": .int(5), "cap": .int(5)]))
    }

    func testAccAggNonString() {
        XCTAssertEqual(accErr(["agg": .int(1)]), "\(at): unknown agg")
        XCTAssertEqual(accErr(["agg": s("avg")]), "\(at): unknown agg")
        XCTAssertEqual(accErr(["agg": nil]), "\(at): unknown agg")
    }

    func testAccValMustBePath() {
        XCTAssertEqual(accErr(["agg": s("sum"), "val": .int(1)]), "\(at): val must be action.params.<name>")
        XCTAssertEqual(accErr(["agg": s("sum"), "val": s("x")]), "\(at): val must be action.params.<name>")
        XCTAssertNil(accErr(["agg": s("sum"), "val": s("action.params.x")]))
    }

    func testAccUnit() {
        let msg = "\(at): unit must be a unit id"
        XCTAssertNil(accErr(["unit": s(String(repeating: "a", count: 64))]))
        XCTAssertEqual(accErr(["unit": s(String(repeating: "a", count: 65))]), msg)
        XCTAssertEqual(accErr(["unit": s("A")]), msg)
        XCTAssertEqual(accErr(["unit": s("")]), msg)
        XCTAssertEqual(accErr(["unit": .int(1)]), msg)
        XCTAssertNil(accErr(["unit": s("a.b_c")]))
    }

    func testAccSelVerbs() {
        let msg = "\(at): sel.verbs must be 1..64 verb names"
        func vs(_ n: Int) -> JSONValue { .object(["verbs": .array((0..<n).map { .string("v\($0)") })]) }
        XCTAssertNil(accErr(["sel": vs(1)]))
        XCTAssertNil(accErr(["sel": vs(63)]))
        XCTAssertNil(accErr(["sel": vs(64)]))
        XCTAssertEqual(accErr(["sel": vs(65)]), msg)
        XCTAssertEqual(accErr(["sel": vs(0)]), msg)
        XCTAssertEqual(accErr(["sel": .object(["verbs": .array([.int(1)])])]), msg)
        XCTAssertEqual(accErr(["sel": .object(["verbs": .array([s("")])])]), msg)
        XCTAssertEqual(accErr(["sel": .object(["verbs": s("v")])]), msg)
    }

    func testAccSelAccumulatesInto() {
        XCTAssertNil(accErr(["agg": s("sum"), "sel": .object(["accumulates_into": s("spend.cents")])]))
        XCTAssertEqual(accErr(["agg": s("sum"), "sel": .object(["accumulates_into": .int(1)])]), "\(at): sel.accumulates_into must be a unit id")
        XCTAssertEqual(accErr(["agg": s("sum"), "sel": .object(["accumulates_into": s("A")])]), "\(at): sel.accumulates_into must be a unit id")
    }

    func testAccSelEvent() {
        XCTAssertEqual(accErr(["sel": .object(["event": .int(1)])]), "\(at): unknown sel.event")
        XCTAssertEqual(accErr(["sel": .object(["event": s("nope")])]), "\(at): unknown sel.event")
        XCTAssertNil(accErr(["sel": .object(["event": s("question")]), "holder": .object(["kind": s("wallet")])]))
    }

    func testAccWinSliding() {
        let msg = "\(at): win sliding needs a positive ms"
        func w(_ ms: JSONValue?, extra: Bool = false) -> JSONValue {
            var o: JObject = ["kind": s("sliding")]
            if let ms = ms { o["ms"] = ms }
            if extra { o["extra"] = .int(1) }
            return .object(o)
        }
        XCTAssertNil(accErr(["win": w(.int(1))]))
        XCTAssertNil(accErr(["win": w(.int(1000))]))
        XCTAssertEqual(accErr(["win": w(.int(0))]), msg)
        XCTAssertEqual(accErr(["win": w(.int(-1))]), msg)
        XCTAssertEqual(accErr(["win": w(s("5"))]), msg)
        XCTAssertEqual(accErr(["win": w(nil)]), msg)
        XCTAssertEqual(accErr(["win": w(.int(5), extra: true)]), msg)
    }

    func testAccWinPeriod() {
        let msg = "\(at): win period needs a positive ms and t0 >= 0"
        func w(ms: JSONValue? = .int(5), t0: JSONValue? = .int(0), extra: Bool = false) -> JSONValue {
            var o: JObject = ["kind": s("period")]
            if let ms = ms { o["ms"] = ms }
            if let t0 = t0 { o["t0"] = t0 }
            if extra { o["extra"] = .int(1) }
            return .object(o)
        }
        XCTAssertNil(accErr(["win": w()]))
        XCTAssertNil(accErr(["win": w(ms: .int(1), t0: .int(7))]))
        XCTAssertEqual(accErr(["win": w(ms: .int(0))]), msg)
        XCTAssertEqual(accErr(["win": w(ms: s("5"))]), msg)
        XCTAssertEqual(accErr(["win": w(ms: nil)]), msg)
        XCTAssertEqual(accErr(["win": w(t0: .int(-1))]), msg)
        XCTAssertEqual(accErr(["win": w(t0: s("0"))]), msg)
        XCTAssertEqual(accErr(["win": w(t0: nil)]), msg)
        XCTAssertEqual(accErr(["win": w(extra: true)]), msg)
        XCTAssertEqual(accErr(["win": w(ms: .int(0), t0: .int(-1), extra: true)]), msg)
    }

    func testAccWinTaskAndUnknown() {
        XCTAssertEqual(accErr(["win": .object(["kind": s("task"), "x": .int(1)])]), "\(at): win {kind: task} has no other member")
        XCTAssertEqual(accErr(["win": .object(["kind": s("weird")])]), "\(at): unknown win kind")
    }

    func testAccSequencedHolder() {
        func h(_ extra: [String: JSONValue] = [:]) -> JSONValue {
            var o: JObject = ["kind": s("sequenced"), "uri": s("u"), "root": s(digest())]
            for (k, v) in extra { o[JKey(k)] = v }
            return .object(o)
        }
        XCTAssertNil(accErr(["holder": h()]))
        XCTAssertNil(accErr(["holder": h(["root_pq_pk": s("AAAA"), "keys_uri": s("https://k")])]))
        XCTAssertEqual(accErr(["holder": h(["root_pq_pk": s("AAA=")])]), "\(at): holder.root_pq_pk is not canonical base64url")
        XCTAssertEqual(accErr(["holder": h(["root_pq_pk": s("+AAA")])]), "\(at): holder.root_pq_pk is not canonical base64url")
        XCTAssertEqual(accErr(["holder": h(["root_pq_pk": .int(1)])]), "\(at): holder.root_pq_pk is not canonical base64url")
        XCTAssertEqual(accErr(["holder": h(["keys_uri": s("")])]), "\(at): holder.keys_uri must be a non-empty string")
        XCTAssertEqual(accErr(["holder": h(["keys_uri": .int(1)])]), "\(at): holder.keys_uri must be a non-empty string")
        XCTAssertEqual(accErr(["holder": h(["extra": .int(1)])]), "\(at): holder sequenced has unknown member 'extra'")
    }

    func testAccWalletRulesSkipped() {
        // a wallet-held accumulator is exempt from the val / accumulates_into rules
        let wallet: [String: JSONValue?] = ["agg": s("sum"), "sel": .object(["event": s("question")]), "holder": .object(["kind": s("wallet")])]
        XCTAssertNil(accErr(wallet))
        XCTAssertEqual(accErr(["sel": .object(["event": s("question")])]), "\(at): wallet events are wallet-held and only wallet events are")
    }

    func testAccNonWalletValRules() {
        XCTAssertEqual(accErr(["agg": s("sum")]), "\(at): sum needs val (or sel.accumulates_into for a sum)")
        XCTAssertEqual(accErr(["agg": s("max")]), "\(at): max needs val (or sel.accumulates_into for a sum)")
        XCTAssertEqual(accErr(["agg": s("max"), "sel": .object(["accumulates_into": s("u")])]), "\(at): max needs val")
        XCTAssertEqual(accErr(["agg": s("distinct"), "sel": .object(["accumulates_into": s("u")])]), "\(at): distinct needs val")
        XCTAssertEqual(accErr(["val": s("action.params.x")]), "\(at): count takes no val")
    }

    // ---- monitorDeclError ----

    let monBase: [String: JSONValue] = ["id": .string("m1"), "kind": .string("never"), "p": .object(["verb": .string("v")])]
    func monErr(_ patch: [String: JSONValue?] = [:]) -> String? { A.monitorDeclError(build(monBase, patch)) }
    let mt = "monitor 'm1'"

    func testMonitorBaseAndKinds() {
        XCTAssertNil(monErr())
        XCTAssertNil(monErr(["kind": s("always")]))
        XCTAssertNil(monErr(["kind": s("precedes"), "q": .object(["verb": s("w")])]))
        XCTAssertNil(monErr(["kind": s("requires_prior"), "q": .object(["verb": s("w")])]))
        XCTAssertNil(monErr(["kind": s("responds_within"), "q": .object(["verb": s("w")]), "within": .int(3)]))
        XCTAssertEqual(monErr(["kind": .int(1)]), "\(mt): unknown kind")
        XCTAssertEqual(monErr(["kind": s("sometimes")]), "\(mt): unknown kind")
        XCTAssertEqual(monErr(["extra": .int(1)]), "monitor: unknown member 'extra'")
    }

    func testMonitorPredicateShape() {
        XCTAssertEqual(monErr(["p": nil]), "\(mt): p must be a predicate")
        XCTAssertEqual(monErr(["p": .int(1)]), "\(mt): p must be a predicate")
        XCTAssertEqual(monErr(["p": .object([:])]), "\(mt): p must be a predicate")
        XCTAssertEqual(monErr(["p": .object(["verb": .int(1)])]), "\(mt): p must be a predicate")
        XCTAssertEqual(monErr(["p": .object(["verb": .array([])])]), "\(mt): p must be a predicate")
        XCTAssertEqual(monErr(["p": .object(["verb": .array([.int(1)])])]), "\(mt): p must be a predicate")
        XCTAssertNil(monErr(["p": .object(["verb": .array([s("a"), s("b")])])]))
    }

    func testMonitorQ() {
        XCTAssertEqual(monErr(["q": .object(["verb": s("w")])]), "\(mt): q is required exactly for requires_prior / precedes / responds_within")
        XCTAssertEqual(monErr(["kind": s("precedes")]), "\(mt): q is required exactly for requires_prior / precedes / responds_within")
        XCTAssertEqual(monErr(["kind": s("requires_prior"), "q": .object(["verb": .int(1)])]), "\(mt): q must be a predicate")
        XCTAssertEqual(monErr(["kind": s("precedes"), "q": .int(1)]), "\(mt): q must be a predicate")
    }

    func testMonitorStatus() {
        XCTAssertNil(monErr(["status": s("admitted")]))
        XCTAssertNil(monErr(["status": s("committed")]))
        XCTAssertEqual(monErr(["status": .int(1)]), "\(mt): status must be admitted or committed")
        XCTAssertEqual(monErr(["status": s("other")]), "\(mt): status must be admitted or committed")
    }

    func testMonitorWithin() {
        let msg = "\(mt): within must be an integer in 1..64"
        func w(_ v: JSONValue) -> String? {
            monErr(["kind": s("responds_within"), "q": .object(["verb": s("w")]), "within": v])
        }
        XCTAssertNil(w(.int(1)))
        XCTAssertNil(w(.int(2)))
        XCTAssertNil(w(.int(64)))
        XCTAssertEqual(w(.int(0)), msg)
        XCTAssertEqual(w(.int(65)), msg)
        XCTAssertEqual(w(s("3")), msg)
        XCTAssertEqual(monErr(["within": .int(3)]), "\(mt): within is required exactly for responds_within")
        XCTAssertEqual(monErr(["kind": s("responds_within"), "q": .object(["verb": s("w")])]), "\(mt): within is required exactly for responds_within")
    }

    func testMonitorStates() {
        func st(_ kind: String, _ within: Int64? = nil) -> [String] {
            var o: JObject = ["kind": s(kind)]
            if let w = within { o["within"] = .int(w) }
            return A.monitorStates(.object(o))
        }
        XCTAssertEqual(st("requires_prior"), ["unmet", "met"])
        XCTAssertEqual(st("precedes"), ["unmet", "met"])
        XCTAssertEqual(st("never"), ["clean", "seen"])
        XCTAssertEqual(st("always"), ["ok", "broken"])
        XCTAssertEqual(st("responds_within", 2), ["idle", "pending:1", "pending:2", "missed"])
        XCTAssertEqual(st("responds_within", 1), ["idle", "pending:1", "missed"])
        XCTAssertEqual(st("responds_within", 0), ["idle", "missed"])
        XCTAssertEqual(st("responds_within"), ["idle", "missed"])
        XCTAssertEqual(st("bogus"), [])
    }

    // ---- selection ----

    func schema() -> JSONValue {
        .object(["verbs": .array([.object(["verb": s("v"), "kind": s("write"),
                                           "params": .object(["amount": .object(["type": s("integer"), "accumulates_into": .array([s("u")])])])])])])
    }

    func testSelects() {
        func sel(_ o: JObject) -> JObject { ["sel": .object(o)] }
        XCTAssertFalse(A.selects([:], "v", schema()))
        XCTAssertFalse(A.selects(["sel": .int(1)], "v", schema()))
        XCTAssertFalse(A.selects(sel(["event": s("question"), "verbs": .array([s("v")])]), "v", schema()))
        XCTAssertTrue(A.selects(sel(["verbs": .array([s("v")])]), "v", nil))
        XCTAssertFalse(A.selects(sel(["verbs": .array([s("w")])]), "v", nil))
        XCTAssertFalse(A.selects(sel(["verbs": .array([s("w")])]), "v", schema()))
        XCTAssertTrue(A.selects(sel(["accumulates_into": s("u")]), "v", schema()))
        XCTAssertFalse(A.selects(sel(["accumulates_into": s("u")]), "v", nil))
        XCTAssertFalse(A.selects(sel(["accumulates_into": s("u")]), "other", schema()))
        XCTAssertFalse(A.selects(sel(["accumulates_into": s("zzz")]), "v", schema()))
        XCTAssertFalse(A.selects(sel([:]), "v", schema()))
    }

    // ---- values ----

    func testValueOfCountAndDistinct() {
        let c = A.valueOf(["agg": s("count")], "v", [:], nil)
        XCTAssertEqual(c?.val, 1)
        XCTAssertNil(c?.key)
        let ds = A.valueOf(["agg": s("distinct"), "val": s("action.params.x")], "v", ["x": s("abc")], nil)
        XCTAssertEqual(ds?.val, 1)
        XCTAssertEqual(ds?.key, "\"abc\"")
        let di = A.valueOf(["agg": s("distinct"), "val": s("action.params.x")], "v", ["x": .int(5)], nil)
        XCTAssertEqual(di?.val, 1)
        XCTAssertEqual(di?.key, "5")
        XCTAssertNil(A.valueOf(["agg": s("distinct"), "val": s("action.params.x")], "v", [:], nil))
        XCTAssertNil(A.valueOf(["agg": s("distinct")], "v", ["x": s("a")], nil))
    }

    // ---- combination ----

    func testCombineEmptyPreDefaultsToZero() {
        let empty: JSONValue = .object([:])
        XCTAssertEqual(A.combine("sum", empty, 5, nil), 5)
        XCTAssertEqual(A.combine("count", empty, 1, nil), 1)
        XCTAssertEqual(A.combine("max", empty, 0, nil), 0)
        XCTAssertEqual(A.combine("max", empty, 3, nil), 3)
        XCTAssertEqual(A.combine("distinct", empty, 1, "k"), 1)
        XCTAssertEqual(A.combine("sum", .object(["sum": .int(4)]), 5, nil), 9)
        XCTAssertEqual(A.combine("count", .object(["count": .int(4)]), 1, nil), 5)
        XCTAssertEqual(A.combine("max", .object(["max": .int(7)]), 3, nil), 7)
    }

    func testPreValueDefaultsToZero() {
        let empty: JSONValue = .object([:])
        for agg in ["sum", "count", "max", "distinct"] { XCTAssertEqual(A.preValue(agg, empty), 0, agg) }
        XCTAssertEqual(A.preValue("sum", .object(["sum": .int(4)])), 4)
        XCTAssertEqual(A.preValue("count", .object(["count": .int(5)])), 5)
        XCTAssertEqual(A.preValue("max", .object(["max": .int(6)])), 6)
        XCTAssertEqual(A.preValue("distinct", .object(["values": .array([s("a"), s("b")])])), 2)
    }

    // ---- receipt shape ----

    let rBase: [String: JSONValue] = [
        "v": .int(1), "kind": .string("pca-acc-receipt"), "session": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 32))),
        "acc": .string("a1"), "seq": .int(1), "pre": .int(0), "delta": .int(1), "post": .int(1),
        "pcactn_digest": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 32))), "aud": .string("x"),
        "issued_at": .int(1000), "expires_at": .int(2000), "kid": .string("k1"),
        "ledger": .object(["index": .int(0), "head": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 32)))]),
        "signer": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 32))), "sig": .string("AAAA"),
    ]
    func rErr(_ patch: [String: JSONValue?] = [:]) -> String? { A.receiptShapeError(build(rBase, patch)) }

    func testReceiptBaseValid() { XCTAssertNil(rErr()) }

    func testReceiptVersionAndKind() {
        XCTAssertEqual(rErr(["v": .int(2)]), "not a pca-acc-receipt v1")
        XCTAssertEqual(rErr(["kind": s("other")]), "not a pca-acc-receipt v1")
        XCTAssertEqual(rErr(["v": .int(2), "kind": s("other")]), "not a pca-acc-receipt v1")
    }

    func testReceiptAccSeq() {
        XCTAssertEqual(rErr(["acc": .int(1)]), "receipt.acc is not an accumulator id")
        XCTAssertEqual(rErr(["acc": s("a b")]), "receipt.acc is not an accumulator id")
        XCTAssertEqual(rErr(["acc": nil]), "receipt.acc is not an accumulator id")
        let m = "receipt.seq must be a safe integer >= 1"
        XCTAssertEqual(rErr(["seq": .int(0)]), m)
        XCTAssertEqual(rErr(["seq": s("1")]), m)
        XCTAssertEqual(rErr(["seq": nil]), m)
        XCTAssertNil(rErr(["seq": .int(1)]))
        XCTAssertNil(rErr(["seq": .int(2)]))
    }

    func testReceiptArithmeticFieldsEach() {
        let m = "receipt pre / delta / post must be non-negative safe integers"
        XCTAssertEqual(rErr(["pre": .int(-1)]), m)
        XCTAssertEqual(rErr(["delta": .int(-1)]), m)
        XCTAssertEqual(rErr(["post": .int(-1)]), m)
        XCTAssertEqual(rErr(["pre": s("0")]), m)
        XCTAssertEqual(rErr(["delta": nil]), m)
        XCTAssertEqual(rErr(["post": nil]), m)
    }

    func testReceiptAudKidLifetime() {
        XCTAssertEqual(rErr(["aud": .int(1)]), "receipt.aud must be a non-empty string")
        XCTAssertEqual(rErr(["aud": s("")]), "receipt.aud must be a non-empty string")
        XCTAssertEqual(rErr(["aud": nil]), "receipt.aud must be a non-empty string")
        XCTAssertEqual(rErr(["kid": .int(1)]), "receipt.kid must match [A-Za-z0-9_.:-]{1,64}")
        XCTAssertEqual(rErr(["kid": s("a b")]), "receipt.kid must match [A-Za-z0-9_.:-]{1,64}")
        XCTAssertEqual(rErr(["kid": nil]), "receipt.kid must match [A-Za-z0-9_.:-]{1,64}")
        let life = "receipt.expires_at must be within 900000 ms after issued_at"
        XCTAssertNil(rErr(["issued_at": .int(1000), "expires_at": .int(1000)]))
        XCTAssertEqual(rErr(["issued_at": .int(1000), "expires_at": .int(999)]), life)
        XCTAssertNil(rErr(["issued_at": .int(1000), "expires_at": .int(901_000)]))
        XCTAssertEqual(rErr(["issued_at": .int(1000), "expires_at": .int(901_001)]), life)
    }

    func testReceiptEd25519MustNotCarryPq() {
        let m = "an ed25519 receipt must not carry pq_pk / pq_sig"
        XCTAssertEqual(rErr(["pq_pk": s("AAAA")]), m)
        XCTAssertEqual(rErr(["pq_sig": s("AAAA")]), m)
        XCTAssertEqual(rErr(["pq_pk": s("AAAA"), "pq_sig": s("AAAA")]), m)
    }

    func testReceiptLedgerExactKeys() {
        let m = "receipt.ledger must be {index, head}"
        XCTAssertEqual(rErr(["ledger": .object(["index": .int(0), "head": s(digest()), "x": .int(1)])]), m)
        XCTAssertEqual(rErr(["ledger": .object(["index": .int(0), "x": s(digest())])]), m)
        XCTAssertEqual(rErr(["ledger": .object(["index": .int(0)])]), m)
        XCTAssertEqual(rErr(["ledger": .object(["index": .int(-1), "head": s(digest())])]), m)
        XCTAssertEqual(rErr(["ledger": .object(["index": .int(0), "head": s("AAAA")])]), m)
    }

    // ---- key set shape ----

    let ksBase: [String: JSONValue] = [
        "v": .int(1), "kind": .string("pca-sequencer-keys"), "sequencer": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 32))),
        "version": .int(1), "issued_at": .int(0), "sig": .string("AAAA"),
        "keys": .array([.object(["kid": .string("k0"), "pk": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 32))), "not_before": .int(0)])]),
    ]
    func ksErr(_ patch: [String: JSONValue?] = [:]) -> String? { A.keySetShapeError(build(ksBase, patch)) }
    func keyEntry(_ patch: [String: JSONValue?]) -> JSONValue {
        build(["kid": s("k0"), "pk": s(digest()), "not_before": .int(0)], patch)
    }

    func testKeySetBaseValid() { XCTAssertNil(ksErr()) }

    func testKeySetVersionAndKind() {
        XCTAssertEqual(ksErr(["v": .int(2)]), "not a pca-sequencer-keys v1")
        XCTAssertEqual(ksErr(["kind": s("x")]), "not a pca-sequencer-keys v1")
        XCTAssertEqual(ksErr(["v": .int(2), "kind": s("x")]), "not a pca-sequencer-keys v1")
    }

    func testKeySetKeyCount() {
        func ks(_ n: Int) -> JSONValue {
            .array((0..<n).map { keyEntry(["kid": s("k\($0)")]) })
        }
        XCTAssertNil(ksErr(["keys": ks(1)]))
        XCTAssertNil(ksErr(["keys": ks(255)]))
        XCTAssertNil(ksErr(["keys": ks(256)]))
        XCTAssertEqual(ksErr(["keys": ks(257)]), "keys must be 1..256 entries")
        XCTAssertEqual(ksErr(["keys": ks(0)]), "keys must be 1..256 entries")
    }

    func testKeySetEntryPqPk() {
        let m = "key pq_pk is not canonical base64url"
        XCTAssertNil(ksErr(["keys": .array([keyEntry(["pq_pk": s("AAAA")])])]))
        XCTAssertEqual(ksErr(["keys": .array([keyEntry(["pq_pk": s("AAA=")])])]), m)
        XCTAssertEqual(ksErr(["keys": .array([keyEntry(["pq_pk": .int(1)])])]), m)
    }

    func testKeySetEntryValidity() {
        let m = "key validity must be 0 <= not_before <= not_after"
        XCTAssertNil(ksErr(["keys": .array([keyEntry(["not_before": .int(5), "not_after": .int(5)])])]))
        XCTAssertNil(ksErr(["keys": .array([keyEntry(["not_before": .int(5), "not_after": .int(6)])])]))
        XCTAssertEqual(ksErr(["keys": .array([keyEntry(["not_before": .int(5), "not_after": .int(4)])])]), m)
        XCTAssertEqual(ksErr(["keys": .array([keyEntry(["not_before": .int(5), "not_after": s("9")])])]), m)
        XCTAssertEqual(ksErr(["keys": .array([keyEntry(["not_before": .int(-1)])])]), m)
    }

    func testKeySetEd25519MustNotCarryPq() {
        let m = "an ed25519 key set must not carry pq_pk / pq_sig"
        XCTAssertEqual(ksErr(["pq_pk": s("AAAA")]), m)
        XCTAssertEqual(ksErr(["pq_sig": s("AAAA")]), m)
        XCTAssertEqual(ksErr(["pq_pk": s("AAAA"), "pq_sig": s("AAAA")]), m)
        // a non-ed25519 (here unsupported) suite is not subject to that rule
        XCTAssertEqual(ksErr(["alg": s("no-such-suite"), "pq_pk": s("AAAA")]), "alg: unsupported_suite: 'no-such-suite'")
    }

    // ---- verifyAgainstHolder: freshness validation ----

    /// A receipt of an unsupported suite: shape-valid, so past the freshness gate the verdict is `.unsupported`; a refused
    /// freshness input is `.invalid` instead.
    func probe(now: Double = 1_000_000, receiptAge: Double = A.DEFAULT_MAX_RECEIPT_AGE_MS, keySetAge: Double = A.DEFAULT_MAX_KEYSET_AGE_MS)
        -> IV.SuiteVerdict {
        let r = build(rBase, ["alg": s("no-such-suite")])
        return A.verifyAgainstHolder(r, holder: ["root": s(digest())], keySets: nil, now: now,
                                     fresh: A.Freshness(maxReceiptAgeMs: receiptAge, maxKeySetAgeMs: keySetAge, tracked: nil))
    }

    func testFreshnessGateAccepts() {
        XCTAssertEqual(probe(), .unsupported)
        XCTAssertEqual(probe(receiptAge: 0), .unsupported)
        XCTAssertEqual(probe(keySetAge: 0), .unsupported)
        XCTAssertEqual(probe(receiptAge: 1), .unsupported)
        XCTAssertEqual(probe(keySetAge: 1), .unsupported)
    }

    func testFreshnessGateRefusesNow() {
        XCTAssertEqual(probe(now: 1e300), .invalid)
        XCTAssertEqual(probe(now: .infinity), .invalid)
        XCTAssertEqual(probe(now: .nan), .invalid)
        XCTAssertEqual(probe(now: 0.5), .invalid)
    }

    func testFreshnessGateRefusesReceiptAge() {
        XCTAssertEqual(probe(receiptAge: 1e300), .invalid)   // not a safe integer, but >= 0
        XCTAssertEqual(probe(receiptAge: -1), .invalid)      // safe, but < 0
        XCTAssertEqual(probe(receiptAge: .nan), .invalid)
        XCTAssertEqual(probe(receiptAge: .infinity), .invalid)
    }

    func testFreshnessGateRefusesKeySetAge() {
        XCTAssertEqual(probe(keySetAge: 1e300), .invalid)
        XCTAssertEqual(probe(keySetAge: -1), .invalid)
        XCTAssertEqual(probe(keySetAge: .nan), .invalid)
        XCTAssertEqual(probe(keySetAge: .infinity), .invalid)
    }

    // ---- receipt arithmetic ----

    func rr(_ pre: Int64?, _ delta: Int64?, _ post: Int64?) -> JSONValue {
        var o = JObject()
        if let p = pre { o["pre"] = .int(p) }
        if let d = delta { o["delta"] = .int(d) }
        if let p = post { o["post"] = .int(p) }
        return .object(o)
    }

    func testReceiptArithmetic() {
        XCTAssertFalse(A.receiptArithmeticOk("sum", .object([:]), 1))
        XCTAssertFalse(A.receiptArithmeticOk("sum", rr(nil, 1, 1), 1))
        XCTAssertFalse(A.receiptArithmeticOk("sum", rr(0, nil, 1), 1))
        XCTAssertFalse(A.receiptArithmeticOk("sum", rr(0, 1, nil), 1))
        XCTAssertTrue(A.receiptArithmeticOk("sum", rr(3, 4, 7), 4))
        XCTAssertFalse(A.receiptArithmeticOk("sum", rr(3, 4, 8), 4))
        XCTAssertFalse(A.receiptArithmeticOk("sum", rr(3, 5, 8), 4))
        XCTAssertTrue(A.receiptArithmeticOk("count", rr(3, 1, 4), 1))
        XCTAssertFalse(A.receiptArithmeticOk("count", rr(3, 1, 5), 1))   // delta ok, post wrong
        XCTAssertFalse(A.receiptArithmeticOk("count", rr(3, 0, 4), 1))   // post ok, delta wrong
        XCTAssertFalse(A.receiptArithmeticOk("count", rr(3, 2, 4), 1))
        XCTAssertTrue(A.receiptArithmeticOk("max", rr(3, 5, 5), 5))
        XCTAssertFalse(A.receiptArithmeticOk("max", rr(3, 5, 8), 5))
        XCTAssertTrue(A.receiptArithmeticOk("distinct", rr(3, 1, 4), 1))
        XCTAssertTrue(A.receiptArithmeticOk("distinct", rr(3, 0, 3), 1))
        XCTAssertFalse(A.receiptArithmeticOk("distinct", rr(3, 1, 2), 1))   // post = pre - delta
        XCTAssertFalse(A.receiptArithmeticOk("distinct", rr(3, 2, 5), 1))
        XCTAssertFalse(A.receiptArithmeticOk("distinct", rr(3, 1, 3), 1))
        XCTAssertFalse(A.receiptArithmeticOk("distinct", rr(3, 0, 4), 1))
    }
}
