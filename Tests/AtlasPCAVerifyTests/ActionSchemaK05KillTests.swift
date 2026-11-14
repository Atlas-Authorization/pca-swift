import XCTest
import Foundation
@testable import AtlasPCAVerify

/// ActionSchema.swift boundaries pinned to the reference packages/pca/src/action-schema.ts: floors (:300), confirmation shape (:284),
/// v2 verb (:353), v2 document (:389), formats (:509-541), value domains (:560-).
final class ActionSchemaK05KillTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }
    private func rep(_ n: Int, _ c: String = "a") -> String { String(repeating: c, count: n) }
    private lazy var d32 = Base64URLStrict.encode([UInt8](repeating: 3, count: 32))
    private lazy var sigVal = Base64URLStrict.encode([UInt8](repeating: 1, count: 64))

    /// `n` sorted distinct lowercase two-letter words.
    private func words(_ n: Int) -> [String] {
        let al = Array("abcdefghijklmnopqrstuvwxyz")
        return (0..<n).map { "\(al[$0 / 26])\(al[$0 % 26])" }
    }

    // ---- floors ----

    private func floors(_ over: JObject = [:]) -> JSONValue {
        var f: JObject = ["risk": .int(0), "rev": s("reversible"), "blast_ppm": .int(0), "esc": .int(0), "caveats": .array([]), "context": .array([]), "prules": .array([])]
        for (k, v) in over { f[k] = v }
        return .object(f)
    }

    func testFloorsRiskAndEsc() {
        let m = "floors.risk and floors.esc must be integers in 0..3"
        XCTAssertNil(ActionSchema.floorsError(floors()))
        XCTAssertNil(ActionSchema.floorsError(floors(["risk": .int(3), "esc": .int(3)])))
        for k: JKey in ["risk", "esc"] {
            for bad: JSONValue in [.int(4), .int(-1), .string("x")] { XCTAssertEqual(ActionSchema.floorsError(floors([k: bad])), m) }
        }
    }

    func testFloorsBlast() {
        XCTAssertNil(ActionSchema.floorsError(floors(["blast_ppm": .int(1_000_000)])))
        XCTAssertEqual(ActionSchema.floorsError(floors(["blast_ppm": .int(1_000_001)])), "floors.blast_ppm must be an integer in 0..1000000")
    }

    func testFloorsListCount() {
        let ctx = words(65).map { s("session_taint_max:" + $0) }
        XCTAssertNil(ActionSchema.floorsError(floors(["context": .array(Array(ctx.prefix(64)))])))
        XCTAssertEqual(ActionSchema.floorsError(floors(["context": .array(ctx)])), "floors.context must be an array of known entries")
    }

    func testTaintContextClass() {
        XCTAssertTrue(ActionSchema.isTaintContext("session_taint_max:a_z"))
        XCTAssertFalse(ActionSchema.isTaintContext("session_taint_max:`"))
        XCTAssertFalse(ActionSchema.isTaintContext("session_taint_max:{"))
    }

    // ---- confirmation ----

    private func conf(_ over: JObject = [:]) -> JSONValue {
        var c: JObject = ["def_digest": s(d32), "traits_digest": s(d32), "facts_digest": s(d32), "final_traits": .array([]), "dismissed": .array([]),
                          "reviewer_kid": s("rev"), "ts": .int(0), "sig": s(sigVal)]
        for (k, v) in over { c[k] = v }
        return .object(c)
    }

    func testConfirmationListCounts() {
        let ids = words(65).map { s("a.t" + $0) }
        XCTAssertNil(ActionSchema.confirmationShapeError(conf(["final_traits": .array(Array(ids.prefix(64)))])))
        XCTAssertEqual(ActionSchema.confirmationShapeError(conf(["final_traits": .array(ids)])), "confirmation: final_traits must be trait ids")
        let one: JSONValue = .object(["trait": s("pca.pii_access"), "reason": s("r")])
        XCTAssertNil(ActionSchema.confirmationShapeError(conf(["dismissed": .array(Array(repeating: one, count: 64))])))
        XCTAssertEqual(ActionSchema.confirmationShapeError(conf(["dismissed": .array(Array(repeating: one, count: 65))])), "confirmation: dismissed must be an array")
    }

    // ---- v2 verb ----

    private func verb(_ over: JObject = [:]) -> JSONValue {
        var v: JObject = ["verb": s("v"), "kind": s("read"), "params": .object([:]), "effects": .array([s("read")]), "traits": .array([]), "def": s(d32), "floors": floors()]
        for (k, x) in over { v[k] = x }
        return .object(v)
    }
    private func vErr(_ over: JObject = [:]) -> String? { ActionSchema.verbDeclError(verb(over), nil, v2: true) }

    func testValueAndParentOnV2() {
        let d: JSONValue = .object(["type": s("string"), "semantic": s("x"), "sensitivity": s("free")])
        XCTAssertEqual(vErr(["params": .object(["action.params.a": d, "action.params.a.b": d])]),
                       "verb 'v': parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'")
        XCTAssertNil(vErr(["params": .object(["action.params.a": d, "action.params.b.c": d])]))
    }

    func testEffectsListLimitAndOrder() {
        func effs(_ e: [String]) -> JObject { ["kind": s("write"), "effects": .array(e.map { s($0) })] }
        XCTAssertNil(vErr(effs(["create", "delete", "exec", "export", "pay", "privilege", "provision", "publish", "read", "send", "sign", "update"])))
        XCTAssertNil(vErr(effs(["create", "delete"])))
        XCTAssertNil(vErr(effs(["create", "delete", "update"])))
        let m = "verb 'v': effects must be sorted and distinct"
        XCTAssertEqual(vErr(effs(["delete", "create"])), m)
        XCTAssertEqual(vErr(effs(["create", "create"])), m)
        XCTAssertEqual(vErr(effs(["create", "update", "delete"])), m)
    }

    func testTraitCount() {
        let ids = words(65).map { s("a.t" + $0) }
        XCTAssertNil(vErr(["traits": .array(Array(ids.prefix(64)))]))
        XCTAssertEqual(vErr(["traits": .array(ids)]), "verb 'v': traits must be trait ids")
    }

    func testDefMustBeADigest() {
        XCTAssertEqual(vErr(["def": .int(1)]), "verb 'v': def must be a canonical base64url SHA-256 digest")
    }

    // ---- v2 document ----

    private func doc(_ over: JObject = [:]) -> JSONValue {
        var d: JObject = ["v": .int(2), "kind": s("pca-action-schema"), "site": s("site"), "aud": s("aud"), "version": s("1"), "verbs": .array([verb()]),
                          "sig": .object(["alg": s("ed25519"), "kid": s("k"), "value": s(sigVal)])]
        for (k, v) in over { d[k] = v }
        return .object(d)
    }
    private func shape(_ over: JObject = [:]) -> String? { ActionSchema.shapeError(doc(over)) }

    func testTraitsDigest() {
        let m = "traits_digest must be a canonical base64url SHA-256 digest"
        XCTAssertNil(shape())
        XCTAssertNil(shape(["traits_digest": s(d32)]))
        XCTAssertEqual(shape(["traits_digest": s("x")]), m)
        XCTAssertEqual(shape(["traits_digest": .int(1)]), m)
    }

    func testTraitDefs() {
        let m = "trait_defs must be an array of up to 64 objects"
        let o: JSONValue = .object([:])
        XCTAssertNil(shape(["trait_defs": .array([])]))
        XCTAssertNil(shape(["trait_defs": .array(Array(repeating: o, count: 64))]))
        XCTAssertEqual(shape(["trait_defs": .array(Array(repeating: o, count: 65))]), m)
        XCTAssertEqual(shape(["trait_defs": .array([.int(1)])]), m)
        XCTAssertEqual(shape(["trait_defs": .int(1)]), m)
    }

    func testPack() {
        let m = "pack must be {ns, version, root}"
        func pack(ns: String = "n", version: String = "1", root: JSONValue? = nil) -> String? {
            shape(["pack": .object(["ns": s(ns), "version": s(version), "root": root ?? s(d32)])])
        }
        XCTAssertNil(pack())
        XCTAssertNil(pack(ns: rep(64)))
        XCTAssertEqual(pack(ns: rep(65)), m)
        XCTAssertNil(pack(version: rep(128)))
        XCTAssertEqual(pack(version: rep(129)), m)
        XCTAssertEqual(pack(root: .int(1)), m)
    }

    // ---- verify, past the shape check ----

    func testVerifyShapedFailsClosedOnItsOwn() {
        XCTAssertFalse(ActionSchema.verifyShaped(.int(1), keys: .array([])).ok)
        XCTAssertFalse(ActionSchema.verifyShaped(.object([:]), keys: .array([])).ok)
        XCTAssertFalse(ActionSchema.verifyShaped(.object(["sig": .object(["kid": .int(1)])]), keys: .array([])).ok)
        // the body is outside the strict profile: no message to verify
        let keys: JSONValue = .array([.object(["kid": s("k"), "pk": s(d32)])])
        let r = ActionSchema.verifyShaped(.object(["sig": .object(["kid": s("k")]), "x": .double(-0.0)]), keys: keys)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "malformed schema")
    }

    // ---- formats ----

    private func check(_ f: String, _ x: String) -> Bool { ActionSchema.formatCheck(f)!(x) }

    /// :513-514. The test IBAN carries `A`, the first letter (value 10): a two-digit value multiplies by 100.
    func testIbanLetterValue() {
        XCTAssertTrue(check("iban", "NL91ABNA0417164300"))
        XCTAssertTrue(check("iban", "GB82WEST12345698765432"))
    }

    /// :520
    func testCidr4() {
        for ok in ["255.255.255.255/32", "1.2.3.4/0"] { XCTAssertTrue(check("cidr", ok), ok) }
        for bad in ["1.2.3.256/8", "256.2.3.4/8", "1.2.3.4/33", "1.2.3.04/8", "1.2.3.4/08"] { XCTAssertFalse(check("cidr", bad), bad) }
    }

    /// :522
    func testCidr6() {
        for ok in ["::/0", "::/128", "a:b:c/64"] { XCTAssertTrue(check("cidr", ok), ok) }
        for bad in ["abcd/64", "a:b/64", "::/129", "a:::b/64", "::/01"] { XCTAssertFalse(check("cidr", bad), bad) }
    }

    /// :525 `s.length <= 254`
    func testEmailLength() {
        func email(_ last: Int) -> String { rep(64) + "@" + rep(63, "b") + "." + rep(63, "c") + "." + rep(last, "d") }
        XCTAssertEqual(email(61).utf16.count, 254)
        XCTAssertTrue(check("email", email(61)))
        XCTAssertFalse(check("email", email(62)))
    }

    // ---- value domains ----

    private func viol(_ d: JObject, _ x: JSONValue) -> String? { ActionSchema.valueViolation(d, x)?.0 }

    func testObjectRefLengthIsInclusive() {
        let d: JObject = ["type": s("object_ref"), "max_len": .int(3)]
        XCTAssertNil(viol(d, s("abc")))
        XCTAssertEqual(viol(d, s("abcd")), "out_of_domain")
    }

    func testDurationBoundsAreInclusive() {
        let plain: JObject = ["type": s("duration")]
        XCTAssertNil(viol(plain, .int(0)))
        XCTAssertEqual(viol(plain, .int(-1)), "out_of_domain")
        let d: JObject = ["type": s("duration"), "min": .int(5), "max": .int(7)]
        XCTAssertNil(viol(d, .int(5)))
        XCTAssertNil(viol(d, .int(7)))
        XCTAssertEqual(viol(d, .int(4)), "out_of_domain")
        XCTAssertEqual(viol(d, .int(8)), "out_of_domain")
    }
}
