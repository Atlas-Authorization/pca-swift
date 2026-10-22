import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential kill tests of Predicates.swift against the TS reference (predicates.ts, hash.ts, JavaScript number
/// semantics): k042-predjs.json (tools/pca-audit/java-mutate/k042-predjs-oracle.mjs: conditions, predicates, lenient canonical
/// equality, numbers, UTF-8 lengths / order, member_of closure caps) and killPred.json.gz
/// (tools/pca-audit/kotlin-mutate/killPred-oracle-gen.mjs: path resolution over many contexts, every leaf operator over fields x
/// operands, `like` globs, `matches`, `member_of` closures, groupings, predicates and predicate lists).
/// A Swift `String` cannot hold a lone surrogate: the goldens' lone-surrogate strings are read as the sentinel scalar.
final class K042PredicatesOracleTests: XCTestCase {
    static func tri(_ s: String) -> Predicates.Tri { s == "true" || s == "T" ? .t : (s == "false" || s == "F" ? .f : .u) }

    func testConditionsAndPredicatesMatchTheReference() throws {
        let g = try K042.json("k042-predjs.json")
        var ctxs: [String: JSONValue] = [:]
        for (k, v) in K042.obj(g.get("ctx")) { ctxs[k.s] = K042.parse(K042.str(v)) }
        var bad: [String] = []
        let tri = K042.arr(g.get("tri"))
        XCTAssertGreaterThan(tri.count, 400)
        for c in tri {
            let cond = K042.parse(K042.str(c.get("cond")))
            let ctx = ctxs[K042.str(c.get("ctx"))] ?? .null
            let want = Self.tri(K042.str(c.get("tri")))
            let got = Predicates.conditionTri(cond, ctx, SafeRegex.Budget())
            if got != want { bad.append("\(K042.str(c.get("name"))): want \(want) got \(got)") }
        }
        for c in K042.arr(g.get("preds")) {
            let preds = K042.parse(K042.str(c.get("preds")))
            let ctx = ctxs[K042.str(c.get("ctx"))] ?? .null
            let want = K042.bool(c.get("allowed"))
            if Predicates.evaluate(preds, ctx) != want { bad.append("\(K042.str(c.get("name"))): allowed want \(want)") }
            if case let .array(ps) = preds {
                let each = K042.arr(c.get("each"))
                XCTAssertEqual(each.count, ps.count)
                for (i, p) in ps.enumerated() where Predicates.predicateMatches(p, ctx, SafeRegex.Budget()) != K042.bool(each[i]) {
                    bad.append("\(K042.str(c.get("name")))[\(i)]: want \(K042.bool(each[i]))")
                }
            }
        }
        K042.report(bad, tri.count)
    }

    func testLenientCanonicalEqualityAndNumbersAndStrings() throws {
        let g = try K042.json("k042-predjs.json")
        var bad: [String] = []
        for c in K042.arr(g.get("eq")) {
            let a = K042.parse(K042.str(c.get("a"))), b = K042.parse(K042.str(c.get("b")))
            // distinct lone surrogates both read as the one sentinel scalar: a Swift String cannot tell them apart (documented skip)
            let sentinel = Character(Canonical.LONE_SURROGATE_SENTINEL)
            if !K042.bool(c.get("eq")) && Canonical.canonicalize(a).contains(sentinel) && Canonical.canonicalize(b).contains(sentinel) { continue }
            if Predicates.deepEq(a, b) != K042.bool(c.get("eq")) { bad.append("\(K042.str(c.get("a"))) == \(K042.str(c.get("b"))): want \(K042.bool(c.get("eq")))") }
        }
        for c in K042.arr(g.get("nums")) {
            let raw = K042.str(c.get("raw"))
            guard let v = K042.parseOrNil(raw) else { bad.append("\(raw): not parsed"); continue }
            let d = IV.num(v) ?? .nan
            if (IV.safe(v) != nil) != K042.bool(c.get("safe")) { bad.append("\(raw): isSafeInteger want \(K042.bool(c.get("safe")))") }
            if d.isFinite != K042.bool(c.get("finite")) { bad.append("\(raw): isFinite want \(K042.bool(c.get("finite")))") }
            // within the plain-decimal range the canonical spelling is exactly JavaScript's String(n) (Swift never prints an exponent)
            if K042.bool(c.get("plain")) && d.isFinite && K042.str(c.get("js")) != "-0" {
                let got = Canonical.numberString(d)
                if got != K042.str(c.get("js")) { bad.append("\(raw): numberString \(got) want \(K042.str(c.get("js")))") }
            }
        }
        let u8 = K042.arr(g.get("u8"))
        XCTAssertGreaterThan(u8.count, 10)
        for c in u8 {
            let s = K042.str(c.get("s"))
            if IV.u8(s) != Int(IV.num(c.get("n")) ?? -1) { bad.append("u8len \(s.unicodeScalars.map { $0.value }): want \(K042.canon(c.get("n"))) got \(IV.u8(s))") }
            if Canonical.hasLoneSurrogate(s) != K042.bool(c.get("lone")) { bad.append("lone \(s.unicodeScalars.map { $0.value }): want \(K042.bool(c.get("lone")))") }
        }
        for c in K042.arr(g.get("cmp")) {
            let a = K042.str(c.get("a")), b = K042.str(c.get("b"))
            let sign = Int(IV.num(c.get("sign")) ?? 0)
            let got = Canonical.compareUtf8(a, b)
            if (got > 0) != (sign > 0) || (got < 0) != (sign < 0) { bad.append("compareUtf8 \(a.unicodeScalars.map { $0.value }) \(b.unicodeScalars.map { $0.value }): want sign \(sign) got \(got)") }
        }
        K042.report(bad, 0)
    }

    private func moCond(_ v: String) -> JSONValue {
        .object(["field": .string("subject.id"), "op": .string("member_of"), "collection": .string("subject.g"), "value": .string(v)])
    }

    func testMemberClosureIsCappedLikeTheReference() throws {
        let g = try K042.json("k042-predjs.json")
        func ctx(id: String, groups: JObject) -> JSONValue {
            .object(["action": .object(["verb": .string("v"), "resource": .string("r")]), "subject": .object(["id": .string(id), "g": .object(groups)])])
        }
        var chain: JObject = [:]
        for i in 0..<10005 { chain[JKey("n\(i)")] = .string("n\(i + 1)") }
        let cc = ctx(id: "n0", groups: chain)
        for (k, want) in K042.obj(g.get("chain")) {
            XCTAssertEqual(Predicates.conditionTri(moCond(k.s), cc, SafeRegex.Budget()), Self.tri(K042.str(want)), "chain \(k.s)")
        }
        var fan: JObject = [:]
        let cs: [JSONValue] = (0..<100).map { .string("c\($0)") }
        fan["s"] = .array((0..<100).map { .string("a\($0)") })
        for i in 0..<100 { fan[JKey("a\(i)")] = .array(cs) }
        fan["c0"] = .string("e")
        fan["e"] = .string("t")
        let fc = ctx(id: "s", groups: fan)
        for (k, want) in K042.obj(g.get("fan")) {
            XCTAssertEqual(Predicates.conditionTri(moCond(k.s), fc, SafeRegex.Budget()), Self.tri(K042.str(want)), "fan \(k.s)")
        }
        XCTAssertEqual(K042.str(g.get("chain")?.get("n10000")), "true")
        XCTAssertEqual(K042.str(g.get("chain")?.get("n10001")), "false")
    }

    func testKillPredResolvePathConditionsAndPredicates() throws {
        try K042.requireCovers(["Predicates", "SafeRegex", "IntentValues", "StrictJSON", "JSONValue"])
        let g = try K042.json("killPred.json.gz")
        let ctxs = K042.arr(g.get("ctxs"))
        func ctx(_ i: JSONValue?) -> JSONValue { ctxs[Int(IV.num(i) ?? 0)] }
        var bad: [String] = []
        for eo in K042.arr(g.get("rp")) {
            let e = K042.arr(eo)
            let r = Predicates.resolve(ctx(e[1]), K042.str(e[0]))
            let wantFound = K042.bool(e[2])
            if (r != nil) != wantFound { bad.append("resolve \(K042.str(e[0])) @ctx\(K042.canon(e[1])): want found=\(wantFound)"); continue }
            if wantFound && K042.canon(r) != K042.canon(e[3]) { bad.append("resolve \(K042.str(e[0])) @ctx\(K042.canon(e[1])): want \(K042.canon(e[3])) got \(K042.canon(r))") }
        }
        let conds = K042.arr(g.get("cond"))
        XCTAssertGreaterThan(conds.count, 100_000)
        for eo in conds {
            let e = K042.arr(eo)
            let got = Predicates.conditionTri(e[0], ctx(e[1]), SafeRegex.Budget())
            if got != Self.tri(K042.str(e[2])) { bad.append("condition \(K042.canon(e[0]).prefix(160)) @ctx\(K042.canon(e[1])): want \(K042.str(e[2])) got \(got)") }
            if bad.count > 60 { break }
        }
        for eo in K042.arr(g.get("pred")) {
            let e = K042.arr(eo)
            if Predicates.predicateMatches(e[0], ctx(e[1]), SafeRegex.Budget()) != K042.bool(e[2]) {
                bad.append("predicate \(K042.canon(e[0]).prefix(160)) @ctx\(K042.canon(e[1])): want \(K042.bool(e[2]))")
            }
        }
        for eo in K042.arr(g.get("preds")) {
            let e = K042.arr(eo)
            if Predicates.evaluate(e[0], ctx(e[1])) != K042.bool(e[2]) {
                bad.append("predicates \(K042.canon(e[0]).prefix(160)) @ctx\(K042.canon(e[1])): want \(K042.bool(e[2]))")
            }
        }
        K042.report(bad, conds.count)
    }
}
