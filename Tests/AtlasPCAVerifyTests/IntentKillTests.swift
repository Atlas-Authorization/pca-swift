import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mutation-kill tests for the Intent Layer M2 code paths (Intent.swift + the hooks in Wire.swift / PCActn.swift): every
/// boundary is pinned on both sides so an off-by-one, negated or deleted branch changes a verdict. Fixture: IntentTests.
final class IntentKillTests: XCTestCase {
    typealias F = IntentTests
    static let PRIOR = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"]

    static func bound() -> JSONValue { F.rootGrant([F.envelope(.string(F.commit()))]) }

    func mustWire(_ name: String, _ v: PCA.Verdict, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(v.checks, ["wire": false], name, file: file, line: line)
        XCTAssertFalse(v.allow, name, file: file, line: line)
        XCTAssertTrue(v.reason.hasPrefix("wire: "), "\(name): \(v.reason)", file: file, line: line)
    }
    func mustPass(_ name: String, _ v: PCA.Verdict, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(v.allow, "\(name): \(v.reason)", file: file, line: line)
        XCTAssertEqual(v.checks["intent"], true, name, file: file, line: line)
        XCTAssertEqual(v.checks.count, 10, name, file: file, line: line)
        XCTAssertEqual(v.reason, "", name, file: file, line: line)
    }
    func mustFail(_ name: String, _ why: String, _ v: PCA.Verdict, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(v.allow, name, file: file, line: line)
        XCTAssertEqual(v.checks["intent"], false, name, file: file, line: line)
        XCTAssertEqual(v.checks.count, 10, name, file: file, line: line)
        XCTAssertTrue(v.reason.hasPrefix("intent: ") && v.reason.contains(why), "\(name): \(v.reason)", file: file, line: line)
        for c in Self.PRIOR { XCTAssertEqual(v.checks[c], true, "\(name): \(c)", file: file, line: line) }
    }

    // ---- wire ----------------------------------------------------------------------------------------------------

    func testWireAcceptedBoundaries() {
        let salt128 = String(repeating: "\u{e9}", count: 64)
        let cases: [(String, [String: JSONValue?], String)] = [
            ("fidelity-0", ["fidelity_ppm": .int(0)], F.SALT),
            ("fidelity-1000000", ["fidelity_ppm": .int(1_000_000)], F.SALT),
            ("residual-0", ["residual_risk_ppm": .int(0)], F.SALT),
            ("residual-max-safe", ["residual_risk_ppm": .int(9_007_199_254_740_991)], F.SALT),
            ("salt-1-byte", ["goal_salt": .string("s")], "s"),
            ("salt-128-bytes", ["goal_salt": .string(salt128)], salt128),
        ]
        for (name, patch, salt) in cases {
            let g = F.rootGrant([F.envelope(.string(F.commit(salt)))])
            mustPass(name, F.verify(F.pcactn(g, F.theIntent(patch)), g))
        }
    }

    func testWireRefusals() {
        let g = Self.bound()
        var cases: [(String, JSONValue)] = [
            ("null", .null), ("array", .array([F.theIntent()])), ("string", .string("x")), ("number", .int(1)),
            ("extra-member", F.theIntent(["extra": .string("x")])),
            ("ref-31", F.theIntent(["ref": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 31)))])),
            ("ref-33", F.theIntent(["ref": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 33)))])),
            ("ref-padded", F.theIntent(["ref": .string(F.REF + "=")])),
            ("ref-number", F.theIntent(["ref": .int(1)])),
            ("map-31", F.theIntent(["map_digest": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 31)))])),
            ("map-std-alphabet", F.theIntent(["map_digest": .string("+" + String(F.MAP.dropFirst()))])),
            ("map-null", F.theIntent(["map_digest": .some(.null)])),
            ("salt-empty", F.theIntent(["goal_salt": .string("")])),
            ("salt-129", F.theIntent(["goal_salt": .string(String(repeating: "\u{e9}", count: 64) + "a")])),
            ("salt-number", F.theIntent(["goal_salt": .int(5)])),
            ("salt-null", F.theIntent(["goal_salt": .some(.null)])),
            ("fidelity-minus-1", F.theIntent(["fidelity_ppm": .int(-1)])),
            ("fidelity-1000001", F.theIntent(["fidelity_ppm": .int(1_000_001)])),
            ("fidelity-fraction", F.theIntent(["fidelity_ppm": .double(1.5)])),
            ("fidelity-string", F.theIntent(["fidelity_ppm": .string("950000")])),
            ("fidelity-bool", F.theIntent(["fidelity_ppm": .bool(true)])),
            ("residual-minus-1", F.theIntent(["residual_risk_ppm": .int(-1)])),
            ("residual-fraction", F.theIntent(["residual_risk_ppm": .double(0.25)])),
            ("residual-bool", F.theIntent(["residual_risk_ppm": .bool(true)])),
            ("residual-string", F.theIntent(["residual_risk_ppm": .string("0")])),
        ]
        for k in Intent.FIELDS { cases.append(("missing-\(k)", F.theIntent([k: nil]))) }
        for (name, i) in cases { mustWire(name, F.verify(F.pcactn(g, i), g)) }
        // the wire reason names the member
        for k in Intent.FIELDS {
            XCTAssertEqual(Intent.validateWire(F.theIntent([k: nil])), "missing field 'intent.\(k)'")
            XCTAssertTrue(Intent.validateWire(F.theIntent([k: .array([])]))?.contains("'intent.\(k)'") ?? false, k)
        }
        XCTAssertEqual(Intent.validateWire(F.theIntent(["zz": .int(1)])), "unknown field 'intent.zz'")
        XCTAssertNil(Intent.validateWire(F.theIntent()))
    }

    // ---- policy --------------------------------------------------------------------------------------------------

    func testPolicyActivation() {
        let g = Self.bound()
        let p = F.pcactn(g, nil)
        for pol in [nil, IntentPolicy(), IntentPolicy(require: false)] {
            let v = F.verify(p, g, pol)
            XCTAssertTrue(v.allow, v.reason); XCTAssertEqual(v.checks.count, 9); XCTAssertNil(v.checks["intent"])
        }
        for (name, pol) in [("require-true", IntentPolicy(require: true)), ("min-alone", IntentPolicy(minFidelityPpm: 0)),
                            ("max-alone", IntentPolicy(maxResidualRiskPpm: 0))] {
            XCTAssertTrue(pol.isActive, name)
            mustFail(name, "requires an intent binding", F.verify(p, g, pol))
        }
        XCTAssertFalse(IntentPolicy().isActive)
    }

    func testPolicyMisconfigured() {
        let g = Self.bound()
        let p = F.pcactn(g, F.theIntent())
        for x in [-1.0, 0.5, Double.nan, Double.infinity, -Double.infinity, -0.0, 9_007_199_254_740_992.0] {
            for pol in [IntentPolicy(minFidelityPpm: x), IntentPolicy(maxResidualRiskPpm: x),
                        IntentPolicy(minFidelityPpm: 0, maxResidualRiskPpm: x), IntentPolicy(minFidelityPpm: x, maxResidualRiskPpm: 0)] {
                mustFail("\(x)", "misconfigured", F.verify(p, g, pol))
            }
            XCTAssertFalse(Intent.okThreshold(x), "\(x)")
        }
        for x in [0.0, 1.0, 9_007_199_254_740_991.0] { XCTAssertTrue(Intent.okThreshold(x), "\(x)") }
        XCTAssertTrue(Intent.okThreshold(nil))
        mustPass("max max-safe", F.verify(p, g, IntentPolicy(minFidelityPpm: 0, maxResidualRiskPpm: 9_007_199_254_740_991)))
        mustFail("before-absent", "misconfigured", F.verify(F.pcactn(g, nil), g, IntentPolicy(require: true, minFidelityPpm: -1)))
    }

    func testThresholdsInclusive() {
        let g = Self.bound()
        let p = F.pcactn(g, F.theIntent()) // fidelity 950000, residual 4310000
        mustPass("min ==", F.verify(p, g, IntentPolicy(minFidelityPpm: 950_000)))
        mustPass("min -1", F.verify(p, g, IntentPolicy(minFidelityPpm: 949_999)))
        mustFail("min +1", "below the policy minimum", F.verify(p, g, IntentPolicy(minFidelityPpm: 950_001)))
        mustPass("max ==", F.verify(p, g, IntentPolicy(maxResidualRiskPpm: 4_310_000)))
        mustPass("max +1", F.verify(p, g, IntentPolicy(maxResidualRiskPpm: 4_310_001)))
        mustFail("max -1", "exceeds the policy maximum", F.verify(p, g, IntentPolicy(maxResidualRiskPpm: 4_309_999)))
        mustFail("floor first", "below the policy minimum", F.verify(p, g, IntentPolicy(minFidelityPpm: 950_001, maxResidualRiskPpm: 0)))
        let q = F.pcactn(g, F.theIntent(["goal_salt": .string("wrong")]))
        mustFail("binding first", "do not open", F.verify(q, g, IntentPolicy(minFidelityPpm: 950_001)))
    }

    // ---- root-grant binding --------------------------------------------------------------------------------------

    func testRootGrantBinding() {
        let bc: JSONValue = .string(F.commit())
        let g = Self.bound()
        let p = F.pcactn(g, F.theIntent())
        // a grant that is not the chain root fails `chain`, but the intent check still reads it (isolates the scan rules)
        let cases: [(String, JSONValue, Bool)] = [
            ("non-object-caveats-skipped", .object(["caveats": .array([.int(5), .string("x"), .null, .array([.int(1)]), F.envelope(bc)])]), true),
            ("non-envelope-skipped", .object(["caveats": .array([.object(["type": .string("max_spend")]), F.envelope(bc)])]), true),
            ("untyped-skipped", .object(["caveats": .array([.object(["goal_commit": .string("x")]), F.envelope(bc)])]), true),
            ("first-envelope-wins", .object(["caveats": .array([F.envelope(.string("decoy")), F.envelope(bc)])]), false),
            ("first-envelope-bad-type-wins", .object(["caveats": .array([F.envelope(.int(7)), F.envelope(bc)])]), false),
            ("goal-commit-number", .object(["caveats": .array([F.envelope(.int(7))])]), false),
            ("goal-commit-missing", .object(["caveats": .array([.object(["type": .string("envelope")])])]), false),
            ("no-envelope", .object(["caveats": .array([.object(["type": .string("max_spend")])])]), false),
            ("empty-caveats", .object(["caveats": .array([])]), false),
            ("caveats-not-array", .object(["caveats": F.envelope(bc)]), false),
            ("no-caveats-key", .object([:]), false),
            ("grant-not-object", .array([F.envelope(bc)]), false),
        ]
        for (name, grant, pass) in cases {
            let v = F.verify(p, grant)
            XCTAssertFalse(v.allow, name); XCTAssertEqual(v.checks["chain"], false, name)
            XCTAssertEqual(v.checks["intent"], pass, "\(name): \(v.reason)")
        }
        for (k, x) in [("ref", JSONValue.string(F.digest("other"))), ("map_digest", .string(F.digest("other"))), ("goal_salt", .string(F.SALT + "x"))] {
            mustFail(k, "do not open", F.verify(F.pcactn(g, F.theIntent([k: x])), g))
        }
        // a ref-only goal ("pca-intent:v1:" + ref) does not open
        let refOnly = Base64URLStrict.encode(Canonical.sha256(try! Canonical.canonicalBytes(.object([
            "d": .string("atlas-pca/goal/v1\u{0}"), "goal": .string("pca-intent:v1:" + F.REF), "salt": .string(F.SALT)]))))
        let h = F.rootGrant([F.envelope(.string(refOnly))])
        mustFail("ref-only-goal", "do not open", F.verify(F.pcactn(h, F.theIntent()), h))
        // the exact preimage
        let want = Base64URLStrict.encode(Canonical.sha256(try! Canonical.canonicalBytes(.object([
            "d": .string("atlas-pca/goal/v1\u{0}"), "goal": .string("pca-intent:v1:" + F.REF + ":" + F.MAP), "salt": .string(F.SALT)]))))
        XCTAssertEqual(PCA.intentGoalCommit(ref: F.REF, mapDigest: F.MAP, goalSalt: F.SALT), want)
        let e = F.rootGrant([])
        mustFail("no-commitment", "no envelope goal commitment", F.verify(F.pcactn(e, F.theIntent()), e))
    }

    // ---- verdict shape -------------------------------------------------------------------------------------------

    func testVerdictShapeAndOrder() throws {
        let g = Self.bound()
        // counter is evaluated before intent: both fail, counter is the reason
        guard var p = F.pcactn(g, F.theIntent(["goal_salt": .string("wrong")])).asObject else { return XCTFail("obj") }
        p["counter"] = .int(-1)
        p.removeValue(forKey: "sig")
        let sig = try F.key("agent").signature(for: Data(try PCA.thresholdMessage(p)))
        p["sig"] = .string(Base64URLStrict.encode(Array(sig)))
        let v = F.verify(.object(p), g)
        XCTAssertFalse(v.allow); XCTAssertEqual(v.checks.count, 10)
        XCTAssertEqual(v.checks["counter"], false); XCTAssertEqual(v.checks["intent"], false)
        XCTAssertTrue(v.reason.hasPrefix("counter: "), v.reason)
        // a wire failure never reports intent, even under an active policy
        mustWire("wire beats policy", F.verify(F.pcactn(g, F.theIntent(["fidelity_ppm": .int(-1)])), g, IntentPolicy(require: true)))
        // every entry point threads the policy
        let text = try Canonical.canonicalizeStrict(F.pcactn(g, nil))
        mustFail("json+id", "requires an intent binding",
                 PCA.verify(json: text, grant: g, now: F.NOW, audience: F.AUD, intentPolicy: IntentPolicy(require: true)))
        mustFail("json+audience", "requires an intent binding",
                 PCA.verify(json: text, grant: g, now: F.NOW, audience: .id(F.AUD), intentPolicy: IntentPolicy(require: true)))
        mustFail("pcactn+audience", "requires an intent binding",
                 PCA.verify(pcactn: F.pcactn(g, nil), grant: g, now: F.NOW, audience: .id(F.AUD), intentPolicy: IntentPolicy(require: true)))
        let plain = PCA.verify(json: text, grant: g, now: F.NOW, audience: F.AUD)
        XCTAssertTrue(plain.allow, plain.reason); XCTAssertNil(plain.checks["intent"])
    }

    func testTamperAfterSigning() {
        let g = Self.bound()
        guard var p = F.pcactn(g, F.theIntent()).asObject else { return XCTFail("obj") }
        mustPass("signed", F.verify(.object(p), g))
        p["intent"] = F.theIntent(["fidelity_ppm": .int(999_999)]) // NOT re-signed
        let v = F.verify(.object(p), g)
        XCTAssertFalse(v.allow); XCTAssertEqual(v.checks["leaf_signature"], false); XCTAssertEqual(v.checks["intent"], true)
        XCTAssertTrue(v.reason.hasPrefix("leaf_signature: "), v.reason)
    }

    func testPolicyFromJSON() {
        for v: JSONValue in [.null, .array([]), .string("x"), .int(1)] { XCTAssertNil(IntentPolicy.fromJSON(v)) }
        XCTAssertEqual(IntentPolicy.fromJSON(.object([:])), IntentPolicy())
        XCTAssertEqual(IntentPolicy.fromJSON(.object(["require": .bool(true)]))?.require, true)
        XCTAssertEqual(IntentPolicy.fromJSON(.object(["require": .string("true")]))?.require, false)
        XCTAssertEqual(IntentPolicy.fromJSON(.object(["min_fidelity_ppm": .int(7), "max_residual_risk_ppm": .double(-2.5)])),
                       IntentPolicy(minFidelityPpm: 7, maxResidualRiskPpm: -2.5))
        for x: JSONValue in [.string("5"), .bool(true), .null, .object([:])] {
            let p = IntentPolicy.fromJSON(.object(["min_fidelity_ppm": x, "max_residual_risk_ppm": x]))
            XCTAssertTrue(p?.isActive ?? false)
            XCTAssertTrue(p?.minFidelityPpm?.isNaN ?? false); XCTAssertTrue(p?.maxResidualRiskPpm?.isNaN ?? false)
        }
    }

    /// A threshold is valid iff its NUMERIC VALUE is a non-negative safe integer, whatever its lexical form.
    func testPolicyLexicalForms() throws {
        let g = Self.bound()
        let p = F.pcactn(g, F.theIntent()) // fidelity 950000, residual 4310000
        for text in [#"{"min_fidelity_ppm":950000.0}"#, #"{"max_residual_risk_ppm":4.31e6}"#, #"{"max_residual_risk_ppm":4.31E+6}"#,
                     #"{"min_fidelity_ppm":0.0}"#, #"{"max_residual_risk_ppm":9007199254740991}"#] {
            mustPass(text, F.verify(p, g, IntentPolicy.fromJSONText(text)))
        }
        let e6 = IntentPolicy.fromJSONText(#"{"min_fidelity_ppm":1e6}"#)
        XCTAssertEqual(e6?.minFidelityPpm, 1_000_000)
        mustFail("1e6 floor", "below the policy minimum", F.verify(p, g, e6))
        for text in [#"{"min_fidelity_ppm":-0.0}"#, #"{"min_fidelity_ppm":-0}"#, #"{"min_fidelity_ppm":950000.5}"#,
                     #"{"max_residual_risk_ppm":-1}"#, #"{"max_residual_risk_ppm":9007199254740992}"#, #"{"max_residual_risk_ppm":1e16}"#,
                     #"{"min_fidelity_ppm":null}"#, #"{"min_fidelity_ppm":true}"#, #"{"min_fidelity_ppm":"950000"}"#] {
            let pol = IntentPolicy.fromJSONText(text)
            XCTAssertNotNil(pol, text)
            mustFail(text, "misconfigured", F.verify(p, g, pol))
        }
        for text in ["[]", "\"x\"", "{", "nul"] { XCTAssertNil(IntentPolicy.fromJSONText(text), text) }
        // the lenient loader keeps the sign of "-0"
        XCTAssertEqual(try StrictJSON.parseLenient("-0"), .double(-0.0))
        if case let .double(d) = try StrictJSON.parseLenient("-0") { XCTAssertEqual(d.sign, .minus) } else { XCTFail("-0") }
        XCTAssertEqual(try StrictJSON.parseLenient("0"), .int(0))
    }
}
