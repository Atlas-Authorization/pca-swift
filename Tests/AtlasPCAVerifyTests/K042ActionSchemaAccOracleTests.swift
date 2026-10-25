import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential kill tests of ActionSchema.swift (rule 14) and IntentAcc.swift (rule 15) against the TS reference.
/// k042-actionschema.json (tools/pca-audit/java-mutate/k042-actionschema-oracle.mts) and k042-intentacc.json
/// (k042-intentacc-oracle.mjs) are shared with every native suite. Swift reports verdicts and codes: the *Error / verify functions
/// compare refused-or-not (and the exact text where Swift words it like the reference), decisions compare exactly.
final class K042ActionSchemaAccOracleTests: XCTestCase {
    // ---------------------------------------------------------------- action schema

    func testShape() throws {
        let cs = K042.arr(try K042.json("k042-actionschema.json").get("shape"))
        var bad: [String] = []
        let td = K042.TextDiffs()
        for c in cs {
            let want = c.get("expect").flatMap { $0.asString }
            let got = ActionSchema.shapeError(K042.parse(K042.str(c.get("doc"))))
            if got?.contains(IV.UNSUPPORTED_SUITE) == true { continue } // a PQ suite this host lacks: by design
            if (want == nil) != (got == nil) { bad.append("\(K042.str(c.get("name"))): want <\(String(describing: want))> got <\(String(describing: got))>") } else { td.add(want, got, K042.str(c.get("name"))) }
        }
        td.finish("action schema shape")
        K042.report(bad, cs.count)
    }

    func testParamValueViolation() throws {
        let cs = K042.arr(try K042.json("k042-actionschema.json").get("pvv"))
        var bad: [String] = []
        let td = K042.TextDiffs()
        for c in cs {
            let want = c.get("expect")?.get("code")?.asString
            let r = ActionSchema.valueViolation(K042.obj(K042.parse(K042.str(c.get("d")))), K042.parse(K042.str(c.get("x"))))
            let got = r?.0
            if want != got { bad.append("\(K042.str(c.get("name"))): want <\(String(describing: want))> got <\(String(describing: got))>") } else if let r = r { td.add(c.get("expect")?.get("reason")?.asString, r.1, K042.str(c.get("name"))) }
        }
        td.finish("action schema value violation")
        K042.report(bad, cs.count)
    }

    func testConform() throws {
        let cs = K042.arr(try K042.json("k042-actionschema.json").get("conform"))
        var bad: [String] = []
        let td = K042.TextDiffs()
        for c in cs {
            let e = c.get("expect")
            let r = ActionSchema.conform(K042.parse(K042.str(c.get("doc"))), verb: K042.str(c.get("verb")), params: K042.parse(K042.str(c.get("params"))))
            if K042.bool(e?.get("ok")) {
                if !r.ok { bad.append("\(K042.str(c.get("name"))): want ok got \(r.code)") }
            } else if r.ok || r.code != K042.str(e?.get("code")) || r.path != e?.get("path")?.asString {
                bad.append("\(K042.str(c.get("name"))): want \(K042.canon(e)) got ok=\(r.ok) \(r.code) \(String(describing: r.path))")
            } else if !r.ok {
                td.add(e?.get("reason")?.asString, r.reason, K042.str(c.get("name")))
            }
        }
        td.finish("action schema conform")
        K042.report(bad, cs.count)
    }

    func testVerify() throws {
        let cs = K042.arr(try K042.json("k042-actionschema.json").get("verify"))
        var bad: [String] = []
        let td = K042.TextDiffs()
        for c in cs {
            let want = c.get("expect")?.asString
            let r = ActionSchema.verify(K042.parse(K042.str(c.get("doc"))), keys: K042.parseOrNil(K042.str(c.get("keys"))))
            if r.reason.contains(IV.UNSUPPORTED_SUITE) { continue } // a PQ suite this host lacks: by design
            if (want == nil) != r.ok { bad.append("\(K042.str(c.get("name"))): want <\(String(describing: want))> got ok=\(r.ok) \(r.reason)") } else if !r.ok { td.add(want, r.reason, K042.str(c.get("name"))) }
        }
        td.finish("action schema verify")
        K042.report(bad, cs.count)
    }

    func testAccumulationParams() throws {
        let cs = K042.arr(try K042.json("k042-actionschema.json").get("acc"))
        var bad: [String] = []
        for c in cs {
            let got = IntentAcc.accumulationParams(K042.obj(K042.parse(K042.str(c.get("v")))), K042.str(c.get("unit")))
            let want = K042.arr(c.get("expect")).map { K042.str($0) }
            if got != want { bad.append("\(K042.str(c.get("name"))): want \(want) got \(got)") }
        }
        K042.report(bad, cs.count)
    }

    func testCanonProjection() throws {
        let cs = K042.arr(try K042.json("k042-actionschema.json").get("canon"))
        var bad: [String] = []
        for c in cs {
            let e = c.get("expect")
            guard K042.bool(e?.get("ok")) else { continue } // the reference throws: Swift's projection never does
            let got = ActionSchema.canonProjection(K042.parse(K042.str(c.get("doc"))), verb: K042.str(c.get("verb")), params: K042.obj(K042.parse(K042.str(c.get("params")))))
            if K042.canon(.object(got)) != K042.canon(e?.get("out")) { bad.append("\(K042.str(c.get("name"))): want \(K042.canon(e?.get("out"))) got \(K042.canon(.object(got)))") }
        }
        K042.report(bad, cs.count)
    }

    // ---------------------------------------------------------------- accumulators (rule 15)

    /// True when any `alg` member in the value names a suite this host lacks (no CryptoKit ML-DSA): such a case is skipped.
    private func needsMissingSuite(_ v: JSONValue) -> Bool {
        switch v {
        case let .object(o): return o.contains { ($0.key.s == "alg" && ($0.value.asString.map { PQ.resolve($0) == nil } ?? false)) || needsMissingSuite($0.value) }
        case let .array(a): return a.contains(where: needsMissingSuite)
        default: return false
        }
    }

    private func cases(_ fn: String) throws -> [JSONValue] {
        let all = K042.arr(try K042.json("k042-intentacc.json"))
        let cs = all.filter { K042.str($0.get("fn")) == fn }
        XCTAssertFalse(cs.isEmpty, "no cases for \(fn)")
        return cs
    }

    /// `f` returns the refusal reason (nil = accepted); a PQ suite this host lacks is skipped (unsupported_suite), by design.
    private func verdictRun(_ fn: String, _ f: ([JSONValue]) -> String?) throws {
        var bad: [String] = []
        let td = K042.TextDiffs()
        let cs = try cases(fn)
        for c in cs {
            let wantOk = K042.isNull(c.get("out"))
            let reason = f(K042.arr(c.get("args")))
            if reason?.contains(IV.UNSUPPORTED_SUITE) == true { continue }
            let gotOk = reason == nil
            if gotOk != wantOk { bad.append("\(K042.str(c.get("name"))): want ok=\(wantOk) got \(gotOk) (\(K042.canon(c.get("out"))))") } else { td.add(c.get("out")?.asString, reason, "\(fn) \(K042.str(c.get("name")))") }
        }
        td.finish(fn)
        K042.report(bad, cs.count)
    }

    /// `f` returns nil to skip a case that needs a PQ suite this host lacks (unsupported_suite).
    private func valueRun(_ fn: String, want norm: (JSONValue?) -> JSONValue? = { $0 }, _ f: ([JSONValue]) -> JSONValue?) throws {
        var bad: [String] = []
        let cs = try cases(fn)
        for c in cs {
            if K042.arr(c.get("args")).contains(where: needsMissingSuite) { continue }
            guard let got = f(K042.arr(c.get("args"))) else { continue }
            if K042.canon(got) != K042.canon(norm(c.get("out"))) { bad.append("\(K042.str(c.get("name")))\n    want \(K042.canon(c.get("out")))\n    got  \(K042.canon(got))") }
        }
        K042.report(bad, cs.count)
    }

    func testDeclarationsAndTrackedKeySet() throws {
        try verdictRun("accumulatorDeclError") { IntentAcc.accumulatorDeclError($0[0]) }
        try verdictRun("monitorDeclError") { IntentAcc.monitorDeclError($0[0]) }
        try verdictRun("trackedKeySetError") { IntentAcc.trackedKeySetError($0[0]) }
        try valueRun("monitorStates") { .array(IntentAcc.monitorStates($0[0]).map { .string($0) }) }
    }

    func testPreStateAndCombine() throws {
        try verdictRun("preStateError") { IntentAcc.preStateError(K042.str($0[0]), $0[1]) }
        try valueRun("preValue") { a in
            let d = IntentAcc.preValue(K042.str(a[0]), a[1])
            return .double(d)
        }
        try valueRun("combineAcc") { a in
            let v = a[2]
            guard let post = IntentAcc.combine(K042.str(a[0]), a[1], IV.num(v.get("val")) ?? 0, v.get("key")?.asString) else { return .null }
            return .double(post)
        }
    }

    func testSelectionAndValues() throws {
        try valueRun("accSelects") { a in .bool(IntentAcc.selects(K042.obj(a[0]), K042.str(a[1]), a[2].isNull ? nil : a[2])) }
        try valueRun("accValueOf") { a in
            let r = IntentAcc.valueOfChecked(K042.obj(a[0]), K042.str(a[1]), K042.obj(a[2]), a[3].isNull ? nil : a[3])
            guard let v = r.value else { return .object(["ok": .bool(false), "reason": .string(r.reason)]) }
            return .object(["ok": .bool(true), "val": .double(v.val), "key": v.key.map { .string($0) } ?? .null])
        }
    }

    func testReceiptsKeySetsAndHolder() throws {
        try valueRun("receiptArithmeticOk") { a in .bool(IntentAcc.receiptArithmeticOk(K042.str(a[0]), a[1], IV.num(a[2]) ?? .nan)) }
        try valueRun("pcactnReservationDigest") { a in IntentAcc.reservationDigest(K042.obj(a[0])).map { .string($0) } ?? .null }
        try verdictRun("receiptShapeError") { IntentAcc.receiptShapeError($0[0]) }
        try verdictRun("keySetShapeError") { IntentAcc.keySetShapeError($0[0]) }
        try valueRun("verifyKeySet") { a in
            guard let root = a[1].asString else { return .bool(false) }
            let present = K042.bool(a[3])
            let r = IntentAcc.verifyKeySet(a[0], root: root, rootPqPk: present ? a[2] : nil)
            if r == .unsupported { return nil }
            return .bool(r == .valid)
        }
        try valueRun("verifyReceiptSignature") { a in
            guard a[0].isObject, let signer = a[1].asString else { return .bool(false) }
            let pin: String? = a[2].asObject?[JKey(signer)]?.asString
            let r = IntentAcc.verifyReceiptSignature(a[0], expectedSigner: signer, pin: pin)
            return r == .unsupported ? nil : .bool(r == .valid)
        }
        try valueRun("verifyReceiptAgainstHolder") { a in
            // a malformed tracked key set is refused by the v2 context validator (acc.keyset_versions) before the holder check;
            // a negative-zero clock / age bound cannot be produced by the verifier (Int64 clock, non-negative integer policy)
            if !a[6].isNull, IntentAcc.trackedKeySetError(a[6]) != nil { return .bool(false) }
            if IV.isNegZero(IV.num(a[3]) ?? 1) || IV.isNegZero(IV.num(a[4]) ?? 1) || IV.isNegZero(IV.num(a[5]) ?? 1) { return .bool(false) }
            var fresh = IntentAcc.Freshness()
            fresh.maxReceiptAgeMs = IV.num(a[4]) ?? .nan
            fresh.maxKeySetAgeMs = IV.num(a[5]) ?? .nan
            fresh.tracked = IntentAcc.trackedKeySet(a[6].isNull ? nil : a[6])
            let r = IntentAcc.verifyAgainstHolder(a[0], holder: K042.obj(a[1]), keySets: a[2].isNull ? nil : a[2], now: IV.num(a[3]) ?? .nan, fresh: fresh)
            return r == .unsupported ? nil : .bool(r == .valid)
        }
    }
}
