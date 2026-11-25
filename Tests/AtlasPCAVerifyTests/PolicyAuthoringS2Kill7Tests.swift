import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// Forbid-wins certificates and linked policy templates (packages/pca/src/forbid-certificate.ts, policy-link.ts): the name pattern,
/// the template and overlay shape limits, slot filling, references and the registry resolution.
final class S2G7PolicyAuthoringKillTests: XCTestCase {
    typealias J = JSONValue

    func rep(_ c: String, _ n: Int) -> String { String(repeating: c, count: n) }

    // ---- builders ----

    func slotBody(_ names: [String]) -> JSONValue {
        var o: JObject = [:]
        for n in names { o[JKey(n)] = J.object(["$slot": J.string(n)]) }
        return J.object(["predicates": J.array([J.object(o)]), "caveats": J.array([])])
    }

    func def(_ over: JObject = [:], slots: JObject = ["s": J.object(["type": J.string("string")])]) -> JSONValue {
        var d: JObject = ["v": J.int(1), "kind": J.string("pca-policy-template"), "id": J.string("t1"), "version": J.string("1"), "slots": J.object(slots),
                          "body": slotBody(slots.keys.map { $0.s }.sorted())]
        for (k, v) in over { d[k] = v }
        return J.object(d)
    }

    let idMsg = "template id must match ^[a-z][a-z0-9_]{0,63}$"

    // ---- isOne and the kind ----

    func testVersionOneAsADouble() {
        XCTAssertNil(PCA.templateDefError(def(["v": J.double(1)])))
        XCTAssertNil(PCA.templateDefError(def(["v": J.int(1)])))
        for bad in [0.0, 2.0, 1.5, -1.0] { XCTAssertEqual(PCA.templateDefError(def(["v": J.double(bad)])), "template v / kind mismatch", "\(bad)") }
        XCTAssertEqual(PCA.templateDefError(def(["v": J.string("1")])), "template v / kind mismatch")
    }

    func testVersionAndKindAreBothRequired() {
        XCTAssertEqual(PCA.templateDefError(def(["kind": J.string("other")])), "template v / kind mismatch")
        XCTAssertEqual(PCA.templateDefError(def(["v": J.int(2)])), "template v / kind mismatch")
        XCTAssertEqual(PCA.templateDefError(def(["v": J.int(2), "kind": J.string("other")])), "template v / kind mismatch")
    }

    // ---- the name pattern ----

    func testNamePatternAcceptsItsFullRange() {
        for id in ["a", "z", "a0", "a9", "a_", "az", "a_z09", "z" + rep("z", 63)] { XCTAssertNil(PCA.templateDefError(def(["id": J.string(id)])), id) }
    }

    func testNamePatternRefusals() {
        for id in ["", "A", "0a", "_a", "a`", "a{", "a/", "a:", "a-", "aA", "a ", "\u{e9}", rep("a", 65)] {
            XCTAssertEqual(PCA.templateDefError(def(["id": J.string(id)])), idMsg, id)
        }
        XCTAssertNil(PCA.templateDefError(def(["id": J.string(rep("a", 64))])))
    }

    func testTemplateVersionLength() {
        let msg = "template version must be a string of 1..64 characters"
        XCTAssertNil(PCA.templateDefError(def(["version": J.string(rep("v", 64))])))
        XCTAssertEqual(PCA.templateDefError(def(["version": J.string(rep("v", 65))])), msg)
        XCTAssertEqual(PCA.templateDefError(def(["version": J.string("")])), msg)
    }

    // ---- slots ----

    func manySlots(_ n: Int) -> JObject {
        var s: JObject = [:]
        for i in 0..<n { s[JKey("s" + (i < 10 ? "0" : "") + String(i))] = J.object(["type": J.string("string")]) }
        return s
    }

    func testSlotCount() {
        XCTAssertNil(PCA.templateDefError(def(slots: manySlots(32))))
        XCTAssertEqual(PCA.templateDefError(def(slots: manySlots(33))), "more than 32 slots")
    }

    func testSlotValuesList() {
        func withValues(_ v: JSONValue) -> JSONValue { def(slots: ["s": J.object(["type": J.string("string"), "values": v])]) }
        func list(_ n: Int) -> JSONValue { J.array((0..<n).map { J.string("v\($0)") }) }
        let msg = "slot 's'.values must be a list of strings"
        XCTAssertNil(PCA.templateDefError(withValues(list(64))))
        XCTAssertEqual(PCA.templateDefError(withValues(list(65))), msg)
        XCTAssertEqual(PCA.templateDefError(withValues(J.string("x"))), msg, "a closed set that is not a list")
        XCTAssertEqual(PCA.templateDefError(withValues(J.array([J.int(1)]))), msg)
    }

    func testBodyCaveatsMustBeAnArray() {
        let d = def(["body": J.object(["predicates": J.array([J.object(["s": J.object(["$slot": J.string("s")])])]), "caveats": J.string("x")])])
        XCTAssertEqual(PCA.templateDefError(d), "body.caveats must be an array")
    }

    func testPlaceholderPreAndPostAreStrings() {
        let d = def(["body": J.object(["predicates": J.array([J.object(["s": J.object(["$slot": J.string("s"), "pre": J.int(1)])])]), "caveats": J.array([])])])
        XCTAssertEqual(PCA.templateDefError(d), "placeholder pre must be a string")
        let e = def(["body": J.object(["predicates": J.array([J.object(["s": J.object(["$slot": J.string("s"), "post": J.bool(true)])])]), "caveats": J.array([])])])
        XCTAssertEqual(PCA.templateDefError(e), "placeholder post must be a string")
    }

    // ---- overlays ----

    func overlay(_ over: JObject = [:]) -> JSONValue {
        var o: JObject = ["v": J.int(1), "kind": J.string("pca-template-tighten"), "template_id": J.string("t1"), "version_digest": J.string("d")]
        for (k, v) in over { o[k] = v }
        return J.object(o)
    }

    func testOverlayShape() {
        XCTAssertNil(PCA.tightenOverlayError(overlay()))
        XCTAssertEqual(PCA.tightenOverlayError(overlay(["kind": J.string("x")])), "overlay v / kind mismatch")
        XCTAssertEqual(PCA.tightenOverlayError(overlay(["v": J.int(2)])), "overlay v / kind mismatch")
        let w = "overlay add_where must be a list of conditions"
        XCTAssertNil(PCA.tightenOverlayError(overlay(["add_where": J.array([])])))
        XCTAssertNil(PCA.tightenOverlayError(overlay(["add_where": J.array([J.object([:])])])))
        XCTAssertEqual(PCA.tightenOverlayError(overlay(["add_where": J.string("x")])), w)
        XCTAssertEqual(PCA.tightenOverlayError(overlay(["add_where": J.array([J.int(1)])])), w)
        let c = "overlay add_caveats must be a list of caveats"
        XCTAssertNil(PCA.tightenOverlayError(overlay(["add_caveats": J.array([J.object(["type": J.string("c")])])])))
        XCTAssertEqual(PCA.tightenOverlayError(overlay(["add_caveats": J.string("x")])), c)
        XCTAssertEqual(PCA.tightenOverlayError(overlay(["add_caveats": J.array([J.object(["type": J.int(1)])])])), c)
    }

    func testSignedTemplatesAndOverlaysCheckTheirShapeFirst() {
        XCTAssertEqual(PCA.verifyTemplate(J.object(["def": J.object([:]), "signer": J.string("x")]), trusted: ["x"]), "template v / kind mismatch")
        XCTAssertEqual(PCA.verifyTemplate(J.object(["def": def(), "signer": J.string("x")]), trusted: []), "template signer is not trusted")
        XCTAssertEqual(PCA.verifyTighten(J.object(["overlay": J.object([:]), "signer": J.string("x")]), trusted: ["x"]), "overlay v / kind mismatch")
        XCTAssertEqual(PCA.verifyTighten(J.object(["overlay": overlay(), "signer": J.string("x")]), trusted: []), "overlay signer is not trusted")
    }

    // ---- instantiation ----

    func inst(_ d: JSONValue, _ slots: JObject) -> (policy: JSONValue?, reason: String?) { PCA.instantiateTemplate(d, J.object(slots)) }

    func testInstantiateRefusesAnInvalidDefinition() {
        let r = inst(J.object([:]), [:])
        XCTAssertNil(r.policy)
        XCTAssertEqual(r.reason, "template v / kind mismatch")
    }

    func testStringSlotLength() {
        let d = def()
        let msg = "slot 's' must be a string of 1..256 characters"
        XCTAssertNil(inst(d, ["s": J.string(rep("x", 256))]).reason)
        XCTAssertEqual(inst(d, ["s": J.string(rep("x", 257))]).reason, msg)
        XCTAssertEqual(inst(d, ["s": J.string("")]).reason, msg)
        XCTAssertNil(inst(d, ["s": J.string("x")]).reason)
    }

    func testIntegerSlotBoundsAreInclusive() {
        let d = def(slots: ["s": J.object(["type": J.string("integer"), "min": J.int(5), "max": J.int(10)])])
        XCTAssertNil(inst(d, ["s": J.int(5)]).reason)
        XCTAssertNil(inst(d, ["s": J.int(10)]).reason)
        XCTAssertEqual(inst(d, ["s": J.int(4)]).reason, "slot 's' is below its minimum")
        XCTAssertEqual(inst(d, ["s": J.int(11)]).reason, "slot 's' is above its maximum")
        XCTAssertEqual(inst(d, ["s": J.string("5")]).reason, "slot 's' must be a safe integer")
    }

    func list(_ n: Int) -> JSONValue { J.array((0..<n).map { J.string("v\($0)") }) }

    func testSetSlotSize() {
        let d = def(slots: ["s": J.object(["type": J.string("set"), "values": list(64)])])
        let msg = "slot 's' must be a non-empty list of strings"
        XCTAssertNil(inst(d, ["s": list(64)]).reason)
        XCTAssertNil(inst(d, ["s": list(1)]).reason)
        XCTAssertEqual(inst(d, ["s": list(65)]).reason, msg, "65 distinct entries are refused before the closed-set test")
        XCTAssertEqual(inst(d, ["s": J.array([])]).reason, msg)
        XCTAssertEqual(inst(d, ["s": J.string("x")]).reason, msg)
        XCTAssertEqual(inst(d, ["s": J.array([J.string("zz")])]).reason, "slot 's' has a member outside its closed set")
        XCTAssertEqual(inst(d, ["s": J.array([J.string("v0"), J.string("v0")])]).reason, "slot 's' has duplicate members")
    }

    func policyOf(_ d: JSONValue, _ slots: JObject) -> JObject? { inst(d, slots).policy?.asObject }

    func predicate(_ p: JObject?) -> JObject? { p?["predicates"]?.asArray?.first?.asObject }

    func testAWildcardIsRefusedOnlyInAVerbOrResource() {
        func tpl(_ key: String, _ type: String = "string") -> JSONValue {
            def(["body": J.object(["predicates": J.array([J.object([JKey(key): J.object(["$slot": J.string("s")])])]), "caveats": J.array([])])], slots: ["s": J.object(["type": J.string(type)])])
        }
        XCTAssertEqual(predicate(policyOf(tpl("note"), ["s": J.string("a*b")]))?["note"], J.string("a*b"), "not a verb or resource")
        XCTAssertEqual(inst(tpl("verb"), ["s": J.string("a*b")]).reason, "slot 's' would inject a wildcard or regex matcher into a verb or resource")
        XCTAssertEqual(inst(tpl("resource"), ["s": J.string("re:x")]).reason, "slot 's' would inject a wildcard or regex matcher into a verb or resource")
        XCTAssertEqual(predicate(policyOf(tpl("verb"), ["s": J.string("pay")]))?["verb"], J.string("pay"))
        XCTAssertEqual(predicate(policyOf(tpl("verb", "integer"), ["s": J.int(5)]))?["verb"], J.int(5), "a non-string is no matcher")
    }

    func testPreAndPostAreSpliced() {
        func tpl(pre: String?, post: String?) -> JSONValue {
            var ph: JObject = ["$slot": J.string("s")]
            if let p = pre { ph["pre"] = J.string(p) }
            if let p = post { ph["post"] = J.string(p) }
            return def(["body": J.object(["predicates": J.array([J.object(["note": J.object(ph)])]), "caveats": J.array([])])])
        }
        XCTAssertEqual(predicate(policyOf(tpl(pre: nil, post: "-z"), ["s": J.string("a")]))?["note"], J.string("a-z"), "post only")
        XCTAssertEqual(predicate(policyOf(tpl(pre: "p-", post: nil), ["s": J.string("a")]))?["note"], J.string("p-a"), "pre only")
        XCTAssertEqual(predicate(policyOf(tpl(pre: "p-", post: "-z"), ["s": J.string("a")]))?["note"], J.string("p-a-z"))
        XCTAssertEqual(predicate(policyOf(tpl(pre: nil, post: nil), ["s": J.string("a")]))?["note"], J.string("a"))
        XCTAssertEqual(inst(tpl(pre: nil, post: "y"), ["s": J.string("re:x")]).reason, "slot 's' would inject a regex matcher")
        XCTAssertEqual(predicate(policyOf(tpl(pre: "p-", post: nil), ["s": J.string("re:x")]))?["note"], J.string("p-re:x"), "a prefix keeps it from starting with re:")
        XCTAssertEqual(inst(tpl(pre: nil, post: "y"), ["s": J.string("a*")]).reason, "slot 's' cannot be spliced into a string (wildcard or non-string)")
    }

    // ---- references ----

    func ref(_ over: JObject = [:]) -> JSONValue {
        var r: JObject = ["template_id": J.string("t1"), "version_digest": J.string("d"), "slots": J.object([:])]
        for (k, v) in over { r[k] = v }
        return J.object(r)
    }

    func bindRef(_ digest: JSONValue) -> JSONValue {
        J.object(["template_id": J.string("t1"), "version_digest": J.string("d"), "bind_params_digest": digest])
    }

    func testReferenceDigestLengths() {
        XCTAssertNil(PCA.templateRefError(ref(["version_digest": J.string(rep("d", 128))])))
        XCTAssertEqual(PCA.templateRefError(ref(["version_digest": J.string(rep("d", 129))])), "template_ref.version_digest invalid")
        XCTAssertEqual(PCA.templateRefError(ref(["version_digest": J.string("")])), "template_ref.version_digest invalid")
        XCTAssertNil(PCA.templateRefError(bindRef(J.string(rep("b", 128)))))
        XCTAssertEqual(PCA.templateRefError(bindRef(J.string(rep("b", 129)))), "template_ref.bind_params_digest invalid")
        XCTAssertEqual(PCA.templateRefError(bindRef(J.string(""))), "template_ref.bind_params_digest invalid")
        XCTAssertEqual(PCA.templateRefError(bindRef(J.int(1))), "template_ref.bind_params_digest invalid")
    }

    // ---- the registry ----

    func key(_ seed: UInt8) throws -> Curve25519.Signing.PrivateKey { try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32)) }
    func pub(_ k: Curve25519.Signing.PrivateKey) -> String { Base64URLStrict.encode(Array(k.publicKey.rawRepresentation)) }

    func signedTemplate(_ d: JSONValue, _ k: Curve25519.Signing.PrivateKey) throws -> (digest: String, signed: JSONValue) {
        let digest = try XCTUnwrap(PCA.templateDigest(d))
        let msg = Array("atlas-pca/policy-template/v1\u{0}".utf8) + Canonical.sha256(Array(digest.utf8))
        let sig = Base64URLStrict.encode(Array(try k.signature(for: Data(msg))))
        return (digest, J.object(["def": d, "signer": J.string(pub(k)), "sig": J.string(sig)]))
    }

    func testResolveLink() throws {
        let k = try key(1)
        let (digest, st) = try signedTemplate(def(), k)
        let reg: JSONValue = J.object(["templates": J.object([JKey(digest): st]), "trusted": J.array([J.string(pub(k))])])
        let good = ref(["version_digest": J.string(digest), "slots": J.object(["s": J.string("v")])])
        let ok = PCA.resolveLink(good, registry: reg)
        XCTAssertNil(ok.reason)
        XCTAssertEqual(ok.overlays, 0)
        XCTAssertEqual(predicate(ok.policy?.asObject)?["s"], J.string("v"))

        func refused(_ r: JSONValue, _ g: JSONValue, _ why: String, _ line: String) {
            let x = PCA.resolveLink(r, registry: g)
            XCTAssertNil(x.policy, line)
            XCTAssertEqual(x.reason, why, line)
            XCTAssertEqual(x.overlays, 0, line)
        }
        refused(J.object([:]), reg, "template_ref.template_id invalid", "269")
        refused(good, J.object(["templates": J.object([:]), "trusted": J.array([J.string(pub(k))])]), "template version is not in the registry", "272")
        refused(good, J.object(["templates": J.object([JKey(digest): st]), "trusted": J.array([])]), "template signer is not trusted", "273")
        let (_, other) = try signedTemplate(def(["version": J.string("2")]), k)
        refused(good, J.object(["templates": J.object([JKey(digest): other]), "trusted": J.array([J.string(pub(k))])]), "registry entry does not match its digest", "275")
        refused(ref(["version_digest": J.string(digest), "template_id": J.string("other"), "slots": J.object(["s": J.string("v")])]), reg,
                "template id does not match the reference", "276")
        var bindOnly = good.asObject ?? [:]
        bindOnly["slots"] = nil
        bindOnly["bind_params_digest"] = J.string("missing")
        refused(J.object(bindOnly), reg, "parameter object is not available", "279")
        let params = J.object(["s": J.string("v")])
        let regBad = J.object(["templates": J.object([JKey(digest): st]), "trusted": J.array([J.string(pub(k))]), "params": J.object(["wrong": params])])
        var bindWrong = bindOnly
        bindWrong["bind_params_digest"] = J.string("wrong")
        refused(J.object(bindWrong), regBad, "parameter object does not match bind_params_digest", "280")
        let pd = try XCTUnwrap(PCA.templateDigest(params))
        let regBound = J.object(["templates": J.object([JKey(digest): st]), "trusted": J.array([J.string(pub(k))]), "params": J.object([JKey(pd): params])])
        var bindGood = bindOnly
        bindGood["bind_params_digest"] = J.string(pd)
        let bound = PCA.resolveLink(J.object(bindGood), registry: regBound)
        XCTAssertNil(bound.reason)
        XCTAssertEqual(predicate(bound.policy?.asObject)?["s"], J.string("v"))
        refused(ref(["version_digest": J.string(digest), "slots": J.object([:])]), reg, "slot 's' is not filled", "284")
        let ovl = J.object(["overlay": overlay(["version_digest": J.string(digest)]), "signer": J.string(pub(try key(2))), "sig": J.string("x")])
        let regOv = J.object(["templates": J.object([JKey(digest): st]), "trusted": J.array([J.string(pub(k))]), "overlays": J.array([ovl])])
        refused(good, regOv, "overlay signer is not trusted", "291")
    }

    // ---- forbid-wins certificates ----

    func clause(_ id: String, _ kind: String, _ value: String = "true", signer: String? = nil) -> JSONValue {
        var c: JObject = ["id": J.string(id), "kind": J.string(kind), "value": J.string(value)]
        if let s = signer { c["signer"] = J.string(s) }
        return J.object(c)
    }

    func cert(clauses: [JSONValue], winner: JObject, decision: String, shadowed: [String]) -> JSONValue {
        J.object(["v": J.int(1), "kind": J.string("forbid-wins"), "clauses": J.array(clauses), "winner": J.object(winner), "decision": J.string(decision),
                  "shadowed": J.array(shadowed.map { J.string($0) })])
    }

    func testAMalformedWinnerNeedsAnExplicitNullId() {
        XCTAssertTrue(PCA.forbidCertificateConsistent(cert(clauses: [], winner: ["kind": J.string("malformed"), "id": J.null], decision: "deny", shadowed: [])))
        XCTAssertFalse(PCA.forbidCertificateConsistent(cert(clauses: [], winner: ["kind": J.string("malformed")], decision: "deny", shadowed: [])), "no id member")
    }

    func testNoWinnerNeedsAnExplicitNullId() {
        XCTAssertTrue(PCA.forbidCertificateConsistent(cert(clauses: [], winner: ["kind": J.string("none"), "id": J.null], decision: "deny", shadowed: [])))
        XCTAssertFalse(PCA.forbidCertificateConsistent(cert(clauses: [], winner: ["kind": J.string("none")], decision: "deny", shadowed: [])), "no id member")
    }

    func testForbidsAreRankedBySignerThenId() {
        let prec = ["s1", "s2"]
        // the more authoritative signer wins even when its id sorts later and it comes second
        let a = [clause("a", "forbid", signer: "s2"), clause("b", "forbid", signer: "s1")]
        XCTAssertTrue(PCA.forbidCertificateConsistent(cert(clauses: a, winner: ["kind": J.string("forbid"), "id": J.string("b")], decision: "deny", shadowed: ["a"]), precedence: prec))
        XCTAssertFalse(PCA.forbidCertificateConsistent(cert(clauses: a, winner: ["kind": J.string("forbid"), "id": J.string("a")], decision: "deny", shadowed: ["b"]), precedence: prec))
        // the same signer: the smaller id wins even when it comes second
        let b = [clause("b", "forbid", signer: "s1"), clause("a", "forbid", signer: "s1")]
        XCTAssertTrue(PCA.forbidCertificateConsistent(cert(clauses: b, winner: ["kind": J.string("forbid"), "id": J.string("a")], decision: "deny", shadowed: ["b"]), precedence: prec))
        XCTAssertFalse(PCA.forbidCertificateConsistent(cert(clauses: b, winner: ["kind": J.string("forbid"), "id": J.string("b")], decision: "deny", shadowed: ["a"]), precedence: prec))
        // unlisted signers rank after every listed one
        let c = [clause("a", "forbid", signer: "x"), clause("z", "forbid", signer: "s2")]
        XCTAssertTrue(PCA.forbidCertificateConsistent(cert(clauses: c, winner: ["kind": J.string("forbid"), "id": J.string("z")], decision: "deny", shadowed: ["a"]), precedence: prec))
    }
}
