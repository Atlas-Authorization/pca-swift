import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The prohibition engine (translated from prohibitions.test.ts and prohibitions-one-document.test.ts): veto over permission, stateful
/// invariants, fail-closed matching, canonical state digests, the hash chain, signed constitutions and safety evidence.
final class K05GProhibitionsTests: XCTestCase {
    let key = try! PCAEdKey(seed: [UInt8](repeating: 1, count: 32))
    let signerKey = try! PCAEdKey(seed: [UInt8](repeating: 2, count: 32))
    let otherKey = try! PCAEdKey(seed: [UInt8](repeating: 3, count: 32))
    var PRIN: String { key.id }
    let NOW = 1_700_000_000_000.0
    let DAY = 86_400.0

    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }
    func act(_ verb: String, _ res: String = "/r", _ params: String? = nil, env: String? = nil) -> JSONValue {
        var a: JObject = ["verb": .string(verb), "resource": .string(res)]
        if let p = params { a["params"] = J(p) }
        var o: JObject = ["action": .object(a)]
        if let e = env { o["env"] = J(e) }
        return .object(o)
    }
    func cons(_ invs: String) -> JSONValue { J(#"{"version":1,"principal":"\#(PRIN)","invariants":[\#(invs)]}"#) }
    func state0() -> JSONValue { Prohibitions.emptyState(NOW) }
    func with(_ s: JSONValue, _ k: String, _ v: JSONValue) -> JSONValue {
        guard case var .object(o) = s else { return s }
        o[JKey(k)] = v
        return .object(o)
    }
    func check(_ a: JSONValue, _ c: JSONValue, _ s: JSONValue) -> ProhibitionResult { Prohibitions.checkProhibitions(a, c, s) }

    let SPEND = #"{"id":"spend-day","kind":"cap","when":{"verb":"pay","resource":"*"},"amount":"action.params.usd","max":100,"window_secs":86400}"#
    let NO_PROD_DELETE = #"{"id":"no-prod-delete-without-human","kind":"never_unless","when":{"verb":"delete","resource":"/prod/*"},"unless":[{"field":"env.human_approved","op":"eq","value":true}]}"#
    let NO_EXFIL = #"{"id":"no-pii-exfil","kind":"never","when":{"verb":["export","send"],"resource":"*","where":[{"field":"action.params.contains_pii","op":"eq","value":true}]}}"#

    func testVetoOverPermission() {
        let c = cons("\(NO_PROD_DELETE),\(NO_EXFIL)")
        let d = Prohibitions.composeAuthority(permitted: true, act("delete", "/prod/db1", "{}", env: #"{"human_approved":false}"#), c, state0())
        XCTAssertEqual(d.allow, false)
        XCTAssertEqual(d.decidedBy, "prohibition")
        XCTAssertEqual(d.prohibition.violated, ["no-prod-delete-without-human"])
        XCTAssertTrue(Prohibitions.composeAuthority(permitted: true, act("delete", "/prod/db1", "{}", env: #"{"human_approved":true}"#), c, state0()).allow)
        let leak = act("send", "/mail/x", #"{"contains_pii":true}"#)
        XCTAssertEqual(Prohibitions.composeAuthority(permitted: false, leak, cons(NO_EXFIL), state0()).prohibition.violated, ["no-pii-exfil"])
        XCTAssertFalse(Prohibitions.composeAuthority(permitted: true, leak, cons(NO_EXFIL), state0()).allow)
        XCTAssertEqual(Prohibitions.composeAuthority(permitted: false, act("send", "/mail/x", #"{"contains_pii":false}"#), cons(NO_EXFIL), state0()).decidedBy, "permission")
    }

    func testDailySpendCapAndWindowRoll() throws {
        let c = cons(SPEND)
        var s = state0()
        func pay(_ usd: Int) -> JSONValue { act("pay", "/vendor/acme", "{\"usd\":\(usd)}") }
        for (i, usd) in [40, 40].enumerated() {
            let t = NOW + Double(i) * 1000
            s = with(s, "now", PD.num(t))
            XCTAssertTrue(check(pay(usd), c, s).ok)
            s = Prohibitions.advanceState(pay(usd), c, s, now: t)
        }
        s = with(s, "now", PD.num(NOW + 3000))
        let r = check(pay(30), c, s)
        XCTAssertEqual(r.violated, ["spend-day"])
        XCTAssertEqual(r.reasons, ["spend-day: cap exceeded: 80 + 30 > 100"])
        XCTAssertTrue(check(pay(20), c, s).ok)
        XCTAssertTrue(check(pay(30), c, with(s, "now", PD.num(NOW + (DAY + 10) * 1000))).ok)
    }

    func testCapFailsClosedOnBadAmount() {
        let c = cons(SPEND)
        for p in [nil, "{}", #"{"usd":-5}"#, #"{"usd":"5"}"#, #"{"usd":true}"#] as [String?] {
            let r = check(act("pay", "/v", p), c, state0())
            XCTAssertFalse(r.ok)
            XCTAssertEqual(r.reasons, ["spend-day: amount unresolvable (fail closed)"])
        }
        XCTAssertTrue(check(act("refund", "/v"), c, state0()).ok)
    }

    func testRateAndNeverAfter() {
        let c = cons(#"{"id":"rate","kind":"rate","when":{"verb":"send","resource":"*"},"max":2,"window_secs":60},{"id":"lockdown","kind":"never_after","after":{"verb":"read","resource":"/secrets/*"},"forbid":{"verb":"send","resource":"/net/*"}}"#)
        var s = state0()
        let send = act("send", "/net/out")
        for _ in 0..<2 {
            XCTAssertTrue(check(send, c, s).ok)
            s = Prohibitions.advanceState(send, c, s)
        }
        let r = check(send, c, s)
        XCTAssertEqual(r.violated, ["rate"])
        XCTAssertEqual(r.reasons, ["rate: rate exceeded: 3 > 2 per 60s"])
        let locked = Prohibitions.advanceState(act("read", "/secrets/key"), c, state0())
        XCTAssertEqual(check(send, c, locked).violated, ["lockdown"])
        XCTAssertTrue(check(act("read", "/pub/x"), c, locked).ok)
    }

    func testConservativeMatching() {
        let c = cons(NO_EXFIL), s = state0()
        XCTAssertFalse(check(act("export", "/r", #"{"contains_pii":true}"#), c, s).ok)
        XCTAssertTrue(check(act("export", "/r", #"{"contains_pii":false}"#), c, s).ok)
        XCTAssertTrue(check(act("read", "/r", #"{"contains_pii":true}"#), c, s).ok)
        XCTAssertFalse(check(act("export", "/r"), c, s).ok) // unavailable params: matched
        XCTAssertFalse(check(act("export", "/r", "{}"), c, s).ok) // missing field: matched
        XCTAssertTrue(check(act("export", "/r", #"{"contains_pii":"yes"}"#), c, s).ok) // cleanly different
        XCTAssertFalse(check(act("delete", "/prod/x"), cons(NO_PROD_DELETE), s).ok)
        XCTAssertTrue(check(act("delete", "/staging/x"), cons(NO_PROD_DELETE), s).ok)
        let rx = cons(#"{"id":"r","kind":"never","when":{"verb":"x","resource":"re:/a/[^/]+"}}"#)
        XCTAssertFalse(check(act("x", "/a/" + String(repeating: "b", count: 600)), rx, s).ok) // an oversized subject is matched, not missed
    }

    func testMalformedInvariantsDenyEverything() {
        let bad = [
            #"{"id":"u","kind":"eventually_always","when":{"verb":"x"}}"#, #"{"id":"u","kind":"never","when":{"verb":""}}"#,
            #"{"id":"u","kind":"never","when":{"verb":"x","where":[{"field":"action.verb","op":"regex","value":"."}]}}"#,
            #"{"id":"u","kind":"never","when":{"verb":"x","resource":"re:(a+)+"}}"#,
            #"{"id":"u","kind":"cap","when":{"verb":"x"},"amount":"env.x","max":1}"#, #"{"id":"u","kind":"rate","when":{"verb":"x"},"max":1.5,"window_secs":1}"#,
            #"{"id":"u","kind":"never_unless","when":{"verb":"x"},"unless":[]}"#, #"{"kind":"never","when":{"verb":"x"}}"#, "null",
        ]
        for inv in bad {
            let c = cons(inv)
            XCTAssertFalse(Prohibitions.validateConstitution(c).isEmpty, inv)
            let r = check(act("anything", "/ok"), c, state0())
            XCTAssertFalse(r.ok)
            XCTAssertEqual(r.violated, ["<constitution>"])
            XCTAssertThrowsError(try Prohibitions.signConstitution(c, principal: key), inv)
        }
        let inf = cons(#"{"id":"u","kind":"cap","when":{"verb":"x"},"amount":"action.params.u","max":1}"#)
        var invs = inf.get("invariants")?.asArray ?? []
        if case var .object(o) = invs[0] { o["max"] = .double(.infinity); invs[0] = .object(o) }
        XCTAssertEqual(Prohibitions.validateConstitution(with(inf, "invariants", .array(invs))), ["u: max must be a finite number >= 0"])
    }

    func testExactValidationMessages() {
        let V = Prohibitions.validateConstitution
        XCTAssertEqual(V(nil), ["constitution not an object"])
        XCTAssertEqual(V(J(#"{"version":2,"principal":"","invariants":5}"#)), ["unsupported version 2", "principal missing", "invariants not an array"])
        XCTAssertEqual(V(J(#"{"principal":"p","invariants":[]}"#)), ["unsupported version undefined"])
        XCTAssertEqual(V(J(#"{"version":null,"principal":"p","invariants":[]}"#)), ["unsupported version null"])
        XCTAssertEqual(V(cons("\(NO_EXFIL),\(NO_EXFIL)")), ["no-pii-exfil: duplicate id"])
        XCTAssertEqual(V(cons(#"{"id":"__proto__","kind":"never","when":{"verb":"x"}}"#)), ["__proto__: forbidden id"])
        XCTAssertEqual(V(cons(#"{"id":"\#(String(repeating: "x", count: 129))","kind":"never","when":{"verb":"x"}}"#)), ["\(String(repeating: "x", count: 129)): id too long"])
        XCTAssertEqual(V(cons(#"{"id":"a","kind":"zzz"}"#)), ["a: unknown invariant kind zzz"])
        XCTAssertEqual(V(cons(#"{"id":"a","kind":"rate","when":{"verb":"x"},"max":10001,"window_secs":1}"#)), ["a: max must be an integer in [0,10000]"])
        XCTAssertEqual(V(cons(#"{"id":"a","kind":"rate","when":{"verb":"x"},"max":-0.0,"window_secs":1}"#)), ["a: max must be an integer in [0,10000]"])
        XCTAssertEqual(V(cons(#"{"id":"a","kind":"cap","when":{"verb":"x"},"amount":"action.x","max":1,"window_secs":0}"#)), ["a: bad window_secs"])
        XCTAssertEqual(V(cons(#"{"id":"a","kind":"require_prior","when":{"verb":"x"}}"#)), ["a: prior: not an object"])
        let many = (0..<257).map { #"{"id":"i\#($0)","kind":"never","when":{"verb":"x"}}"# }.joined(separator: ",")
        XCTAssertEqual(V(cons(many)), ["too many invariants"])
    }

    func testMalformedConstitutionActionState() {
        let c = cons(NO_EXFIL)
        XCTAssertFalse(check(act("a", "/b"), with(c, "version", .int(2)), state0()).ok)
        XCTAssertEqual(check(J(#"{"action":{"verb":1}}"#), c, state0()).violated, ["<action>"])
        XCTAssertEqual(check(act("a", "/b"), c, J(#"{"now":"x"}"#)).violated, ["<state>"])
        XCTAssertFalse(check(.null, .null, .null).ok)
    }

    func testSignVerifyTamper() throws {
        let c = cons("\(SPEND),\(NO_EXFIL)")
        let sc = try Prohibitions.signConstitution(c, principal: key)
        XCTAssertEqual(sc.get("id")?.asString, try Prohibitions.constitutionId(c))
        XCTAssertEqual(Prohibitions.verifyConstitution(sc, expectedPrincipal: PRIN), .pass)
        XCTAssertEqual(Prohibitions.verifyConstitution(sc, expectedPrincipal: otherKey.id), .no("principal mismatch"))
        XCTAssertEqual(Prohibitions.verifyConstitution(with(sc, "invariants", J("[\(SPEND)]"))), .no("id does not match content"))
        XCTAssertEqual(Prohibitions.verifyConstitution(with(sc, "sig", .null)), .no("bad signature"))
        XCTAssertFalse(Prohibitions.verifyConstitution(nil).ok)
    }

    func testPerActionEvidence() throws {
        let c = cons("\(SPEND),\(NO_PROD_DELETE),\(NO_EXFIL)")
        let s = Prohibitions.advanceState(act("pay", "/v", #"{"usd":60}"#), c, state0())
        let a = act("pay", "/vendor/acme", #"{"usd":30}"#)
        let e1 = Prohibitions.proveSafety(a, c, s)
        XCTAssertEqual(e1.get("ok"), .bool(true))
        XCTAssertEqual(e1.get("evaluated")?.asArray?.compactMap { $0.get("id")?.asString }, ["spend-day", "no-prod-delete-without-human", "no-pii-exfil"])
        XCTAssertEqual(Prohibitions.verifySafetyEvidence(e1, a, c, s), .pass)
        XCTAssertEqual(Prohibitions.verifySafetyEvidence(with(e1, "state_digest", .string("x")), a, c, s), .no("state digest mismatch"))
        XCTAssertEqual(Prohibitions.verifySafetyEvidence(e1, act("pay", "/vendor/acme", #"{"usd":31}"#), c, s), .no("action digest mismatch"))
        XCTAssertEqual(Prohibitions.verifySafetyEvidence(e1, a, cons(SPEND), s), .no("constitution mismatch"))
        XCTAssertEqual(Prohibitions.verifySafetyEvidence(with(e1, "v", .int(2)), a, c, s), .no("unsupported evidence version"))
        let bad = act("pay", "/vendor/acme", #"{"usd":99}"#)
        let real = Prohibitions.proveSafety(bad, c, s)
        XCTAssertEqual(real.get("ok"), .bool(false))
        XCTAssertEqual(Prohibitions.verifySafetyEvidence(real, bad, c, s), .no("prohibition violated: spend-day"))
    }

    func testSignedBoundEvidence() throws {
        let c = cons("\(SPEND),\(NO_PROD_DELETE),\(NO_EXFIL)")
        let s = Prohibitions.advanceState(act("pay", "/v", #"{"usd":60}"#), c, state0())
        let a = act("pay", "/vendor/acme", #"{"usd":30}"#)
        let se = try Prohibitions.signSafetyEvidence(Prohibitions.proveSafety(a, c, s), signer: signerKey)
        func full(_ over: [String: JSONValue] = [:]) -> JSONValue {
            var d: JObject = ["signer": .string(signerKey.id), "action": a, "constitution": c, "state": s]
            for (k, v) in over { d[JKey(k)] = v }
            return .object(d)
        }
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(se, full()), .pass)
        XCTAssertEqual(se.get("id")?.asString, try Prohibitions.safetyBindingId(se.get("evidence")!, signer: signerKey.id))
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(se, full(["action": act("pay", "/vendor/acme", #"{"usd":31}"#)])).reason, "action digest mismatch (evidence bound to another action)")
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(se, full(["signer": .string(otherKey.id)])).reason, "signer not trusted")
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(se, full(["signer": .array([])])).reason, "no pinned signer")
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(se, full(["actionDigest": .string("mismatch")])).reason, "expected action and digest disagree")
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(nil, full()).reason, "malformed input")
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(se, nil).reason, "malformed input")
        let bad = act("pay", "/vendor/acme", #"{"usd":99}"#)
        let honest = try Prohibitions.signSafetyEvidence(Prohibitions.proveSafety(bad, c, s), signer: signerKey)
        let ex: JSONValue = .object(["signer": .string(signerKey.id), "action": bad, "constitution": c, "state": s])
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(honest, ex).reason, "prohibition violated: spend-day")
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(honest, with(ex, "requireOk", .bool(false))), .pass)
        // an expected constitution that is malformed never verifies
        let broken = with(c, "version", .int(9))
        XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(se, full(["constitution": broken])).reason?.hasPrefix("constitution mismatch") ?? false, true)
    }

    func testUnboundEvidenceIsNotSignable() {
        let c = cons(SPEND)
        let ev = Prohibitions.proveSafety(.object(["action": .object(["verb": .string("pay"), "resource": .string("/v"), "params": .object(["usd": .double(.nan)])])]), c, state0())
        XCTAssertEqual(ev.get("ok"), .bool(false))
        XCTAssertTrue(ev.get("violated")?.asArray?.contains(.string("<action>")) ?? false)
        XCTAssertThrowsError(try Prohibitions.signSafetyEvidence(ev, signer: signerKey))
        XCTAssertThrowsError(try Prohibitions.signSafetyEvidence(with(Prohibitions.proveSafety(act("pay", "/v", #"{"usd":1}"#), c, state0()), "v", .int(9)), signer: signerKey))
    }

    func testRequireApprovalOverAndRequirePrior() {
        let inv = #"{"id":"big-pay","kind":"require_approval_over","when":{"verb":"pay"},"amount":"action.params.usd","threshold":100,"approved":[{"field":"env.cfo_approved","op":"eq","value":true}]}"#
        let c = cons(inv), s = state0()
        XCTAssertTrue(check(act("pay", "/v", #"{"usd":100}"#), c, s).ok)
        let r = check(act("pay", "/v", #"{"usd":101}"#), c, s)
        XCTAssertEqual(r.violated, ["big-pay"])
        XCTAssertEqual(r.reasons, ["big-pay: approval required over 100"])
        XCTAssertTrue(check(act("pay", "/v", #"{"usd":101}"#, env: #"{"cfo_approved":true}"#), c, s).ok)
        XCTAssertFalse(check(act("pay", "/v", #"{"usd":101}"#, env: #"{"cfo_approved":"true"}"#), c, s).ok)
        for p in [nil, "{}", #"{"usd":"5"}"#, #"{"usd":-1}"#] as [String?] { XCTAssertFalse(check(act("pay", "/v", p), c, s).ok) }
        let rp = cons(#"{"id":"review-first","kind":"require_prior","when":{"verb":"deploy"},"prior":{"verb":"review","where":[{"field":"action.params.passed","op":"eq","value":true}]}}"#)
        var st = state0()
        let deploy = act("deploy", "/prod")
        XCTAssertEqual(check(deploy, rp, st).violated, ["review-first"])
        st = Prohibitions.advanceState(act("review", "/pr/1", #"{"passed":false}"#), rp, st)
        XCTAssertEqual(st.get("latched"), .object([:]))
        st = Prohibitions.advanceState(act("review", "/pr/1"), rp, st) // an ambiguous prerequisite is NOT latched
        XCTAssertEqual(st.get("latched"), .object([:]))
        st = Prohibitions.advanceState(act("review", "/pr/1", #"{"passed":true}"#), rp, st)
        XCTAssertEqual(IV.num(st.get("latched")?.get("review-first")), NOW)
        XCTAssertTrue(check(deploy, rp, st).ok)
    }

    func testWhenMatchesCannotEvaluateMeansMatched() {
        let ctx = act("export", "/r", #"{"n":5,"s":"abc","arr":[1,2],"flag":true}"#, env: #"{"tenant":"a"}"#)
        func m(_ cond: String, _ a: JSONValue? = nil) -> Bool { Prohibitions.whenMatches(J(#"{"verb":"export","where":[\#(cond)]}"#), a ?? ctx) }
        let cases = [
            #"{"field":"action.params.missing","op":"eq","value":1}"#, #"{"field":"action.params.n","op":"eq"}"#,
            #"{"field":"action.params.n","op":"eq","ref":"action.params.nope"}"#, #"{"field":"env.nope","op":"ne","value":1}"#,
            #"{"field":"subject.x","op":"eq","value":1}"#, #"{"field":"bogus.root","op":"eq","value":1}"#,
            #"{"field":"action.params.n","op":"in","value":"notarray"}"#, #"{"field":"action.params.n","op":"nin","value":5}"#,
            #"{"field":"action.params.n","op":"lt","value":"str"}"#, #"{"field":"action.params.s","op":"gt","value":3}"#,
            #"{"field":"action.params.n","op":"prefix","value":"a"}"#, #"{"field":"action.params.n","op":"explode","value":1}"#,
            #"{"field":"","op":"eq","value":1}"#, #"{"op":"eq","value":1}"#, "null", #""str""#,
        ]
        for c in cases { XCTAssertTrue(m(c), c) }
        XCTAssertTrue(m(#"{"field":"action.params.n","op":"eq","value":5}"#, act("export", "/r")))
        XCTAssertTrue(Prohibitions.whenMatches(J(#"{"verb":"export"}"#), J(#"{"action":{"verb":1}}"#)))
        XCTAssertTrue(Prohibitions.whenMatches(J(#"{"verb":""}"#), ctx))
        XCTAssertTrue(Prohibitions.whenMatches(nil, ctx))
        XCTAssertTrue(Prohibitions.whenMatches(J(#"{"verb":"export","resource":"re:(a+)+"}"#), ctx))
        XCTAssertTrue(Prohibitions.whenMatches(J(#"{"verb":"export","where":"x"}"#), ctx))
        // cleanly evaluable conditions still evaluate normally
        XCTAssertTrue(m(#"{"field":"action.params.n","op":"eq","value":5}"#))
        XCTAssertFalse(m(#"{"field":"action.params.n","op":"eq","value":6}"#))
        XCTAssertTrue(m(#"{"field":"action.params.n","op":"in","value":[1,5]}"#))
    }

    func testStateDigestIgnoresEntryOrderAndExtraFields() throws {
        let a = J(#"{"now":10,"seq":0,"parent":null,"ledger":{"k":[{"t":2,"amount":1,"junk":1},{"t":1,"amount":5}]},"latched":{}}"#)
        let b = J(#"{"now":10,"seq":0,"parent":null,"ledger":{"k":[{"t":1,"amount":5},{"t":2,"amount":1}],"empty":[]},"latched":{}}"#)
        XCTAssertEqual(try Prohibitions.stateDigest(a), try Prohibitions.stateDigest(b))
        XCTAssertThrowsError(try Prohibitions.stateDigest(J(#"{"now":10}"#)))
        XCTAssertEqual(Prohibitions.stateProblem(J(#"{"now":10,"seq":1,"parent":null,"ledger":{},"latched":{}}"#)), "malformed monitor state: missing chain link")
        XCTAssertEqual(Prohibitions.stateProblem(J(#"{"now":10,"seq":0,"parent":"x","ledger":{},"latched":{}}"#)), "malformed monitor state: genesis has a parent")
        XCTAssertEqual(Prohibitions.stateProblem(J(#"{"now":10,"seq":0,"parent":null,"ledger":{"k":[{"t":11,"amount":1}]},"latched":{}}"#)),
                       "malformed monitor state: ledger entry after now (clock regression)")
    }

    func testChainAndClock() {
        let c = cons(SPEND)
        let s0 = state0()
        let r1 = Prohibitions.checkAndAdvance(permitted: true, act("pay", "/v", #"{"usd":5}"#), c, s0)
        XCTAssertTrue(r1.allow)
        XCTAssertEqual(r1.next.get("seq"), .int(1))
        XCTAssertNotNil(r1.next.get("parent")?.asString)
        let r2 = Prohibitions.checkAndAdvance(permitted: true, act("pay", "/v", #"{"usd":5}"#), c, r1.next)
        XCTAssertNotEqual(r2.next.get("parent"), r1.next.get("parent"))
        XCTAssertEqual(Prohibitions.checkAndAdvance(permitted: true, act("pay", "/v", #"{"usd":5}"#), c, s0, expectedSeq: 7).reason, "stale state head (seq)")
        XCTAssertEqual(Prohibitions.checkAndAdvance(permitted: true, act("pay", "/v", #"{"usd":5}"#), c, s0, expectedStateDigest: "zz").reason, "stale state head (digest)")
        XCTAssertEqual(Prohibitions.checkAndAdvance(permitted: false, act("pay", "/v", #"{"usd":5}"#), c, s0).decidedBy, "permission")
        let back = Prohibitions.advanceStateStrict(act("pay", "/v", #"{"usd":5}"#), c, s0, now: NOW - 1)
        XCTAssertEqual(back.reason, "clock regression")
        XCTAssertEqual(Prohibitions.tickState(s0, now: NOW - 1).reason, "clock regression")
        XCTAssertTrue(Prohibitions.tickState(s0, now: NOW + 1).ok)
    }

    /// prohibitions-one-document: one constitution is one regex document; once the budget is spent a regex evaluation is "could not decide", never "no match".
    func testRegexBudgetRefusalIsAVeto() {
        let invs = (0..<70).map { #"{"id":"n\#($0)","kind":"never","when":{"verb":"x","resource":"re:/a/b"}}"# }.joined(separator: ",")
        let r = check(act("x", "/zzz"), cons(invs), state0())
        XCTAssertEqual(r.violated.count, 6)
        XCTAssertEqual(r.violated.first, "n64")
        // the same trigger alone (fresh budget) is a clean miss
        XCTAssertFalse(Prohibitions.whenMatches(J(#"{"verb":"x","resource":"re:/a/b"}"#), act("x", "/zzz")))
    }
}
