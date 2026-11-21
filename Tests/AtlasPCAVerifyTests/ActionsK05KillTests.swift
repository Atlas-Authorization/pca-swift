import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import AtlasPCAVerify

/// Actions.swift boundaries pinned to the reference: packages/pca-actions/src/def.ts (patterns, ranks), validate.ts, traits.ts,
/// confirmation.ts, import/review.ts, derive.ts.
final class ActionsK05KillTests: XCTestCase {
    private let key = Curve25519.Signing.PrivateKey()
    private func s(_ x: String) -> JSONValue { .string(x) }
    private func rep(_ n: Int, _ c: String = "a") -> String { String(repeating: c, count: n) }
    private var d32: String { Base64URLStrict.encode([UInt8](repeating: 3, count: 32)) }

    /// A dotted name of exactly `n` bytes (99 <= n <= 131) with four segments, each within 32 bytes.
    private func name(_ n: Int) -> String { rep(32) + "." + rep(32, "b") + "." + rep(32, "c") + "." + rep(n - 99, "d") }

    private func def(_ over: JObject = [:]) -> JObject {
        var d: JObject = ["v": .int(1), "kind": s("pca-action-def"), "verb": s("a.b"), "title": s("t"), "effects": .array([s("read")]),
                          "resource": .object(["type": s("t"), "id": s("*"), "scope": s("one")]), "params": .object([:]), "review": .object(["state": s("authored")])]
        for (k, v) in over { d[k] = v }
        return d
    }

    // ---- ranks (def.ts:34, def.ts:52) ----

    func testRankTables() {
        XCTAssertEqual(Actions.REV_RANK["irreversible"], 2)
        XCTAssertEqual(Actions.SENSITIVITY_RANK["critical"], 2)
    }

    // ---- patterns (def.ts:101-107) ----

    func testAsciiClassesExcludeTheNeighbours() {
        XCTAssertTrue(Actions.isVerb("a.z0_9"))
        for bad in ["`a.b", "{a.b", "a.`", "a.{", "a./", "a./b"] { XCTAssertFalse(Actions.isVerb(bad), bad) }
    }

    func testSegmentLengths() {
        XCTAssertTrue(Actions.isVerb(rep(32) + ".b"))
        XCTAssertFalse(Actions.isVerb(rep(33) + ".b"))
        XCTAssertTrue(Actions.isVerb("a." + rep(32)))
        XCTAssertFalse(Actions.isVerb("a." + rep(33)))
        XCTAssertTrue(Actions.isAlias("a." + rep(32)))
        XCTAssertFalse(Actions.isAlias("a." + rep(33)))
        XCTAssertTrue(Actions.isResourceType(rep(32)))
        XCTAssertFalse(Actions.isResourceType(rep(33)))
    }

    func testParamNameUppercaseRange() {
        for ok in ["A", "Y", "Z", "A.Z"] { XCTAssertTrue(Actions.isParamName(ok), ok) }
        for bad in ["@", "["] { XCTAssertFalse(Actions.isParamName(bad), bad) }
    }

    /// validate.ts:101 `/^[A-Z]{3}$/`
    func testUnitCurrencyRange() {
        func err(_ c: String) -> String? {
            Actions.paramError("x", .object(["type": s("integer"), "unit": .object(["kind": s("money"), "ccy": s(c), "exp": .int(2)])]), [])
        }
        for ok in ["AAA", "ZZZ", "AYZ"] { XCTAssertNil(err(ok), ok) }
        for bad in ["@AA", "[AA", "AA@", "AA["] { XCTAssertEqual(err(bad), "x: unit.ccy must be an ISO 4217 style code", bad) }
    }

    // ---- validateDef length limits (validate.ts:177, 178, 185; MAX_VERB_BYTES = 128) ----

    func testVerbBytes() {
        XCTAssertNil(Actions.validateDef(.object(def())))
        XCTAssertNil(Actions.validateDef(.object(def(["verb": s(name(128))]))))
        XCTAssertEqual(Actions.validateDef(.object(def(["verb": s(name(129))]))), "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)")
    }

    func testAliasBytes() {
        XCTAssertNil(Actions.validateDef(.object(def(["aliases": .array([s(name(128))])]))))
        XCTAssertEqual(Actions.validateDef(.object(def(["aliases": .array([s(name(129))])]))), "aliases must be distinct verb-shaped names other than the verb")
    }

    func testResourceTypeLength() {
        func res(_ t: String) -> JObject { def(["resource": .object(["type": s(t), "id": s("*"), "scope": s("one")])]) }
        XCTAssertNil(Actions.validateDef(.object(res(name(128)))))
        XCTAssertEqual(Actions.validateDef(.object(res(name(129)))), "resource.type is malformed")
    }

    // ---- profile lattice and registry (traits.ts) ----

    /// An unknown class joins as the worst one, whichever side it is on.
    func testJoinOfAnUnknownClass() {
        for known in ["reversible", "rate_limited", "irreversible"] {
            XCTAssertEqual(Actions.join(Profile(rev: known), Profile(rev: "zzz")).rev, "irreversible", known)
            XCTAssertEqual(Actions.join(Profile(rev: "zzz"), Profile(rev: known)).rev, "irreversible", known)
        }
    }

    /// traits.ts:98: an undefined rank compares false.
    func testLeqOfAnUnknownClassIsFalse() {
        XCTAssertFalse(Actions.leq(Profile(rev: "zzz"), Profile()))
        XCTAssertFalse(Actions.leq(Profile(), Profile(rev: "zzz")))
        XCTAssertTrue(Actions.leq(Profile(), Profile()))
    }

    /// traits.ts:70: `pca.` is reserved unless core is asked for.
    func testCoreDefaultsToFalse() {
        let t: JSONValue = .object(["id": s("pca.x"), "implies": .array([]), "floor": Profile.bottom.json, "card_phrase": s("c")])
        XCTAssertEqual(Actions.registryError([t]), "trait 'pca.x': the pca. namespace is reserved for core traits")
        XCTAssertNil(Actions.registryError([t], core: true))
        XCTAssertThrowsError(try Actions.buildRegistry([t])) { XCTAssertEqual(($0 as? ActionKitError)?.code, "bad_registry") }
        XCTAssertNoThrow(try Actions.buildRegistry([t], core: true))
    }

    // ---- confirmation (confirmation.ts) ----

    private func pins(_ extra: JObject = [:]) -> JSONValue {
        var p: JObject = ["keys": .array([.object(["kid": s("rev"), "pk": s(Base64URLStrict.encode(Array(key.publicKey.rawRepresentation))), "roles": .array([s("reviewer")])])])]
        for (k, v) in extra { p[k] = v }
        return .object(p)
    }

    private func signedVerb(extra: JObject = [:], dismissed: [JSONValue] = []) throws -> JObject {
        var base: JObject = ["verb": s("v"), "def": s(d32), "traits": .array([s("pca.bulk")])]
        for (k, v) in extra { base[k] = v }
        var att: JObject = ["def_digest": s(d32), "traits_digest": s(Actions.traitsDigest(Actions.coreRegistry)), "facts_digest": s(Actions.factsDigest(base)),
                            "final_traits": .array([s("pca.bulk")]), "dismissed": .array(dismissed), "reviewer_kid": s("rev"), "ts": .int(5)]
        let msg = try XCTUnwrap(Actions.reviewMessage(att))
        att["sig"] = s(Base64URLStrict.encode(Array(try key.signature(for: Data(msg)))))
        base["confirmation"] = .object(att)
        return base
    }

    /// confirmation.ts:14 blankReason: `\s` holds VT, FF and CR.
    func testABlankDismissalReasonDoesNotConfirm() throws {
        func dismissed(_ r: String) throws -> JObject { try signedVerb(dismissed: [.object(["trait": s("pca.pii_access"), "reason": s(r)])]) }
        XCTAssertTrue(Actions.verbConfirmed(try dismissed("x"), Actions.coreRegistry, pins()))
        for r in ["\u{0B}", "\u{0C}", "\u{0D}", "\u{09}", " "] {
            XCTAssertFalse(Actions.verbConfirmed(try dismissed(r), Actions.coreRegistry, pins()), "U+\(String(r.unicodeScalars.first!.value, radix: 16))")
        }
    }

    /// Not a list of digests: refused here. TS spreads a string instead (reported as looser).
    func testExtraTraitsDigestsMustBeStrings() throws {
        let v = try signedVerb()
        XCTAssertTrue(Actions.verbConfirmed(v, Actions.coreRegistry, pins(["traits_digests": .array([s("x")])])))
        XCTAssertFalse(Actions.verbConfirmed(v, Actions.coreRegistry, pins(["traits_digests": s("x")])))
        XCTAssertFalse(Actions.verbConfirmed(v, Actions.coreRegistry, pins(["traits_digests": .array([.int(1)])])))
    }

    /// A verb outside the strict profile has no facts digest: unconfirmed.
    func testAnUnhashableVerbIsNotConfirmed() throws {
        let v = try signedVerb(extra: ["x": .double(-0.0)])
        XCTAssertEqual(Actions.factsDigest(v), "")
        XCTAssertFalse(Actions.verbConfirmed(v, Actions.coreRegistry, pins()))
    }

    /// import/review.ts:51: the final traits are exactly the def's declared traits, not merely as many.
    func testDefLevelFinalTraitsMustEqualTheDeclaredTraits() throws {
        func confirmed(final: String) throws -> JObject {
            var d = def(["traits": .array([s("pca.bulk")])])
            var att: JObject = ["def_digest": s(Actions.defDigest(d)), "traits_digest": s(Actions.traitsDigest(Actions.coreRegistry)), "facts_digest": s(d32),
                                "final_traits": .array([s(final)]), "dismissed": .array([]), "reviewer_kid": s("rev"), "ts": .int(5)]
            let msg = try XCTUnwrap(Actions.reviewMessage(att))
            att["sig"] = s(Base64URLStrict.encode(Array(try key.signature(for: Data(msg)))))
            d["review"] = .object(["state": s("confirmed"), "attestation": .object(att)])
            return d
        }
        XCTAssertTrue(Actions.isConfirmed(try confirmed(final: "pca.bulk"), Actions.coreRegistry, pins()))
        XCTAssertFalse(Actions.isConfirmed(try confirmed(final: "pca.pii_access"), Actions.coreRegistry, pins()))
    }

    // ---- rule 22 (derive.ts:178) ----

    /// A consistent unconfirmed read verb: it carries every trait (minus `missing`) and the floor of all of them.
    private func honest(_ over: JObject = [:], missing: String? = nil) throws -> JObject {
        let reg = Actions.coreRegistry
        let top = Actions.topTraits(reg)
        let floor = try Actions.floorOf(reg, top).json
        let carried: [JSONValue] = top.filter { $0 != missing }.map { .string($0) }
        var v: JObject = ["verb": s("v"), "kind": s("read"), "effects": .array([s("read")]), "params": .object([:]), "traits": .array(carried), "floors": floor]
        for (k, x) in over { v[k] = x }
        return v
    }
    private func floorErr(_ v: JObject) -> String? { Actions.schemaVerbFloorError(v, Actions.coreRegistry) }

    func testMalformedParamsAreRefusedLast() throws {
        XCTAssertNil(floorErr(try honest()))
        XCTAssertEqual(floorErr(try honest(["params": .object(["action.params.x": .int(1)])])), "schema_floor_forged: malformed parameter")
        XCTAssertEqual(floorErr(try honest(["params": .array([])])), "schema_floor_forged: params")
    }

    /// An array `param` slices like a string: the 15th element names the parameter, so the boolean domain is covered and nothing is irreversible.
    func testReversibilityByAnArrayParamDropsFourteenElements() throws {
        let param: JSONValue = .array(Array(repeating: s("x"), count: 14) + [s("p")])
        let by: JSONValue = .object(["param": param, "map": .object(["true": s("reversible"), "false": s("reversible")])])
        let v = try honest(["params": .object(["action.params.p": .object(["type": s("boolean")])]), "reversibility_by": by], missing: "pca.irreversible")
        XCTAssertEqual(floorErr(v), "schema_traits_forged: unconfirmed action must carry every trait (missing pca.irreversible)")
    }

    /// derive.ts:201 `indexOf` of a one-element array is -1 while `leq` reads the same array by its string form.
    func testFloorsRevThatIsNotAStringRanksBelowEveryClass() throws {
        var floors = try XCTUnwrap(try honest()["floors"]?.asObject)
        floors["rev"] = .array([s("irreversible")])
        XCTAssertEqual(floorErr(try honest(["floors": .object(floors)])), "schema_floor_forged: floors.rev is below the declared reversibility")
        // an unknown declared class ranks -1 as well: -1 is not below -1
        XCTAssertNil(floorErr(try honest(["floors": .object(floors), "reversibility": s("zzz")])))
    }

    /// normalize.ts:46 `r.default ?? 'irreversible'`
    func testUncoveredDefaultOfTheJSReading() throws {
        func worst(_ extra: JObject) throws -> String {
            var o: JObject = ["by": s("none"), "map": .object(["a": s("reversible")])]
            for (k, v) in extra { o[k] = v }
            return try Actions.worstReversibilityJS(.object(o), [:])
        }
        XCTAssertEqual(try worst(["default": s("reversible")]), "reversible")
        XCTAssertEqual(try worst(["default": .null]), "irreversible")
        XCTAssertEqual(try worst([:]), "irreversible")
    }

    func testJsHasOwn() {
        let obj: JSONValue = .object(["a": .int(1)])
        XCTAssertTrue(Actions.jsHasOwn(obj, "a"))
        XCTAssertFalse(Actions.jsHasOwn(obj, "b"))
        XCTAssertFalse(Actions.jsHasOwn(.int(1), "a"))
        XCTAssertFalse(Actions.jsHasOwn(nil, "a"))
        let arr: JSONValue = .array([.int(1), .int(2)])
        XCTAssertTrue(Actions.jsHasOwn(arr, "length"))
        XCTAssertTrue(Actions.jsHasOwn(arr, "0"))
        XCTAssertTrue(Actions.jsHasOwn(arr, "1"))
        for bad in ["2", "-1", "x", "01", "+1"] { XCTAssertFalse(Actions.jsHasOwn(arr, bad), bad) }
        let str: JSONValue = .string("ab")
        XCTAssertTrue(Actions.jsHasOwn(str, "length"))
        XCTAssertTrue(Actions.jsHasOwn(str, "1"))
        XCTAssertFalse(Actions.jsHasOwn(str, "2"))
    }

    /// derive.ts:215: anything but the registry's digest is a mismatch, a non-string too.
    func testANonStringTraitsDigestIsAMismatch() {
        XCTAssertThrowsError(try Actions.registryOfSchema(["traits_digest": .int(1)])) { XCTAssertEqual(($0 as? ActionKitError)?.code, "traits_digest_mismatch") }
        XCTAssertEqual(Actions.schemaFloorError(["traits_digest": .int(1)])?.hasPrefix("traits_digest_mismatch"), true)
        XCTAssertNoThrow(try Actions.registryOfSchema(["traits_digest": s(Actions.traitsDigest(Actions.coreRegistry))]))
    }
}
