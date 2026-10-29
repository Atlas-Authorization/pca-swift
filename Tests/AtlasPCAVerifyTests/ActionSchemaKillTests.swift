import XCTest
import Foundation
@testable import AtlasPCAVerify

/// `ActionSchema` boundaries pinned one by one: every size limit (accepted at the limit, refused one past it), every member
/// guard with its exact refusal text, the calendar-date rules, and the value-domain checks of `conformAction`.
final class ActionSchemaKillTests: XCTestCase {
    private func a(_ n: Int) -> String { String(repeating: "a", count: n) }
    private func s(_ x: String) -> JSONValue { .string(x) }

    // ---- builders ------------------------------------------------------------------------------------------------------

    private func decl(_ over: JObject = [:], drop: [String] = []) -> JObject {
        var d: JObject = ["type": s("string"), "semantic": s("x"), "sensitivity": s("free")]
        for (k, v) in over { d[k] = v }
        for k in drop { d[JKey(k)] = nil }
        return d
    }
    private func pErr(_ over: JObject = [:], drop: [String] = [], units: JObject? = nil) -> String? {
        ActionSchema.paramDeclError("action.params.x", .object(decl(over, drop: drop)), units)
    }
    private func verbV(_ over: JObject = [:], params: JObject = [:]) -> JSONValue {
        var v: JObject = ["verb": s("v"), "kind": s("read"), "params": .object(params)]
        for (k, x) in over { v[k] = x }
        return .object(v)
    }
    private func vErr(_ over: JObject = [:], params: JObject = [:]) -> String? { ActionSchema.verbDeclError(verbV(over, params: params), nil) }
    private static let SIGVAL = Base64URLStrict.encode([UInt8](repeating: 1, count: 64))
    private func sig(_ over: JObject = [:]) -> JSONValue {
        var g: JObject = ["alg": s("ed25519"), "kid": s("k"), "value": s(ActionSchemaKillTests.SIGVAL)]
        for (k, v) in over { g[k] = v }
        return .object(g)
    }
    private func doc(_ over: JObject = [:]) -> JSONValue {
        var d: JObject = ["v": .int(1), "kind": s("pca-action-schema"), "site": s("site"), "aud": s("aud"), "version": s("1"),
                          "verbs": .array([verbV()]), "sig": sig()]
        for (k, v) in over { d[k] = v }
        return .object(d)
    }
    private func shape(_ over: JObject = [:]) -> String? { ActionSchema.shapeError(doc(over)) }
    private func ids(_ n: Int, _ p: String = "u") -> [JSONValue] { (0..<n).map { s("\(p)\($0)") } }

    // ---- shapeError: members and sizes ---------------------------------------------------------------------------------

    func testAWellFormedDocumentPassesAndUnknownMembersAreNamed() {
        XCTAssertNil(shape())
        XCTAssertEqual(shape(["zzz": .int(1)]), "unknown member 'zzz'")
        XCTAssertEqual(shape(["sig": sig(["zzz": .int(1)])]), "sig: unknown member 'zzz'")
        XCTAssertEqual(ActionSchema.verbDeclError(verbV(["zzz": .int(1)]), nil), "verb entry: unknown member 'zzz'")
        XCTAssertEqual(pErr(["zzz": .int(1)]), "action.params.x: unknown member 'zzz'")
        XCTAssertEqual(shape(["v": .int(3)]), "unsupported schema version")
        XCTAssertEqual(shape(["kind": s("other")]), "kind must be 'pca-action-schema'")
    }

    func testSiteAudVersionLimits() {
        let msg = "site, aud and version must be non-empty strings"
        XCTAssertNil(shape(["site": s(a(2048))]))
        XCTAssertEqual(shape(["site": s(a(2049))]), msg)
        XCTAssertNil(shape(["aud": s(a(256))]))
        XCTAssertEqual(shape(["aud": s(a(257))]), msg)
        XCTAssertNil(shape(["version": s(a(128))]))
        XCTAssertEqual(shape(["version": s(a(129))]), msg)
        XCTAssertEqual(shape(["site": s("")]), msg)
        XCTAssertEqual(shape(["aud": s("")]), msg)
        XCTAssertEqual(shape(["version": s("")]), msg)
        XCTAssertEqual(shape(["site": .int(1)]), msg)
    }

    func testUnitsAndState() {
        func units(_ id: String, _ u: JSONValue) -> String? { shape(["units": .object([JKey(id): u])]) }
        let k: JObject = ["kind": s("money")]
        XCTAssertNil(units("u", .object(k)))
        XCTAssertNil(units(a(64), .object(k)))
        XCTAssertEqual(units(a(65), .object(k)), "unit id '\(a(65))' is malformed")
        XCTAssertEqual(units("A", .object(k)), "unit id 'A' is malformed")
        XCTAssertNil(units("a.b_1", .object(k)))
        // the unit's kind: at most 64 bytes
        XCTAssertNil(units("u", .object(["kind": s(a(64))])))
        XCTAssertEqual(units("u", .object(["kind": s(a(65))])), "unit 'u' must be an object with a kind")
        XCTAssertEqual(units("u", .object([:])), "unit 'u' must be an object with a kind")
        XCTAssertEqual(units("u", .int(1)), "unit 'u' must be an object with a kind")
        XCTAssertEqual(units("u", .object(["kind": s("k"), "zzz": .int(1)])), "unit 'u': unknown member")
        // currency: at most 16 bytes
        XCTAssertNil(units("u", .object(["kind": s("k"), "currency": s(a(16))])))
        XCTAssertEqual(units("u", .object(["kind": s("k"), "currency": s(a(17))])), "unit 'u': currency must be a string")
        // exponent in [0, 18]
        let em = "unit 'u': exponent must be an integer in [0, 18]"
        XCTAssertNil(units("u", .object(["kind": s("k"), "exponent": .int(0)])))
        XCTAssertNil(units("u", .object(["kind": s("k"), "exponent": .int(18)])))
        XCTAssertEqual(units("u", .object(["kind": s("k"), "exponent": .int(19)])), em)
        XCTAssertEqual(units("u", .object(["kind": s("k"), "exponent": .int(-1)])), em)
        XCTAssertEqual(units("u", .object(["kind": s("k"), "exponent": s("x")])), em)
        XCTAssertEqual(units("u", .object(["kind": s("k"), "exponent": .double(1.5)])), em)
        XCTAssertEqual(shape(["units": .array([])]), "units must be an object")
        // state
        XCTAssertNil(shape(["state": .array([])]))
        XCTAssertEqual(shape(["state": .object([:])]), "state must be an array")
    }

    func testVerbCountLimit() {
        func verbs(_ n: Int) -> JSONValue { .array((0..<n).map { verbV(["verb": s("v\($0)")]) }) }
        XCTAssertNil(shape(["verbs": verbs(256)]))
        XCTAssertEqual(shape(["verbs": verbs(257)]), "verbs must be 1..256 entries")
        XCTAssertEqual(shape(["verbs": verbs(0)]), "verbs must be 1..256 entries")
        XCTAssertNil(shape(["verbs": verbs(1)]))
        XCTAssertEqual(shape(["verbs": .array([verbV(), verbV()])]), "verb 'v' is declared twice")
    }

    func testSignatureShape() {
        XCTAssertNil(shape(["sig": sig(["kid": s(a(128))])]))
        XCTAssertEqual(shape(["sig": sig(["kid": s(a(129))])]), "sig.kid must be a non-empty string")
        XCTAssertEqual(shape(["sig": sig(["kid": s("")])]), "sig.kid must be a non-empty string")
        XCTAssertEqual(shape(["sig": sig(["value": .int(1)])]), "sig.value is not canonical base64url")
        XCTAssertEqual(shape(["sig": sig(["value": s("a")])]), "sig.value is not canonical base64url")
        XCTAssertNil(shape(["sig": sig(["pq_value": s(ActionSchemaKillTests.SIGVAL)])]))
        XCTAssertEqual(shape(["sig": sig(["pq_value": .int(1)])]), "sig.pq_value is not canonical base64url")
        XCTAssertEqual(shape(["sig": sig(["pq_value": s("a")])]), "sig.pq_value is not canonical base64url")
        XCTAssertEqual(shape(["sig": sig(["alg": .int(1)])]), "sig.alg: alg must be a string")
        XCTAssertEqual(shape(["sig": .int(1)]), "sig must be an object")
    }

    func testVerifyRefusesAKeyWhoseAlgIsNotAString() {
        let pk = Base64URLStrict.encode([UInt8](repeating: 7, count: 32))
        let keys: JSONValue = .array([.object(["kid": s("k"), "alg": .int(5), "pk": s(pk)])])
        let r = ActionSchema.verify(doc(), keys: keys)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "schema key: alg must be a string")
        let none = ActionSchema.verify(doc(), keys: .array([]))
        XCTAssertFalse(none.ok)
        XCTAssertEqual(none.reason, "no schema key with kid 'k'")
    }

    // ---- paramDeclError ------------------------------------------------------------------------------------------------

    func testParamTypeSemanticSensitivityRequired() {
        XCTAssertNil(pErr())
        XCTAssertEqual(pErr(["type": s("bogus")]), "action.params.x: unknown type")
        XCTAssertEqual(pErr(drop: ["semantic"]), "action.params.x: semantic must be a non-empty string")
        XCTAssertEqual(pErr(["semantic": .int(1)]), "action.params.x: semantic must be a non-empty string")
        XCTAssertEqual(pErr(["semantic": s("")]), "action.params.x: semantic must be a non-empty string")
        XCTAssertNil(pErr(["semantic": s(a(128))]))
        XCTAssertEqual(pErr(["semantic": s(a(129))]), "action.params.x: semantic must be a non-empty string")
        XCTAssertEqual(pErr(drop: ["sensitivity"]), "action.params.x: unknown sensitivity")
        XCTAssertEqual(pErr(["sensitivity": .int(1)]), "action.params.x: unknown sensitivity")
        XCTAssertEqual(pErr(["sensitivity": s("bogus")]), "action.params.x: unknown sensitivity")
        XCTAssertNil(pErr(["required": .bool(false)]))
        XCTAssertEqual(pErr(["required": s("yes")]), "action.params.x: required must be a boolean")
    }

    func testParamValuesLimits() {
        let vals: (Int) -> JSONValue = { n in .array((0..<n).map { self.s("v\($0)") }) }
        XCTAssertNil(pErr(["values": vals(256)]))
        XCTAssertEqual(pErr(["values": vals(257)]), "action.params.x: values must be 1..256 strings")
        XCTAssertEqual(pErr(["values": vals(0)]), "action.params.x: values must be 1..256 strings")
        XCTAssertEqual(pErr(["values": .array([.int(1)])]), "action.params.x: values must be 1..256 strings")
        // each value: a non-empty string of at most 256 UTF-8 bytes
        XCTAssertNil(pErr(["values": .array([s(a(256))])]))
        XCTAssertEqual(pErr(["values": .array([s(a(257))])]), "action.params.x: values must be 1..256 strings")
        XCTAssertEqual(pErr(["values": .array([s("")])]), "action.params.x: values must be 1..256 strings")
        XCTAssertEqual(pErr(["values": .array([s("a"), s("a")])]), "action.params.x: values must be distinct")
        XCTAssertEqual(pErr(["type": s("integer"), "values": .array([s("a")])]), "action.params.x: values apply to string and set only")
        XCTAssertNil(pErr(["type": s("set"), "values": .array([s("a")])]))
        XCTAssertEqual(pErr(["type": s("set")]), "action.params.x: a set needs values")
    }

    func testParamMinMax() {
        let m = "must be a safe integer on an integer parameter"
        XCTAssertNil(pErr(["type": s("integer"), "min": .int(0), "max": .int(5)]))
        XCTAssertNil(pErr(["type": s("integer"), "min": .int(5), "max": .int(5)]))
        XCTAssertEqual(pErr(["type": s("integer"), "min": .int(6), "max": .int(5)]), "action.params.x: min > max")
        XCTAssertEqual(pErr(["min": .int(1)]), "action.params.x: min \(m)")
        XCTAssertEqual(pErr(["max": .int(1)]), "action.params.x: max \(m)")
        XCTAssertEqual(pErr(["type": s("integer"), "min": s("a")]), "action.params.x: min \(m)")
        XCTAssertEqual(pErr(["type": s("integer"), "max": .double(1.5)]), "action.params.x: max \(m)")
        // arrays: min / max only when the items are integers
        XCTAssertEqual(pErr(["type": s("array"), "min": .int(1)]), "action.params.x: min \(m)")
        XCTAssertEqual(pErr(["type": s("array"), "items": s("string"), "max": .int(1)]), "action.params.x: max \(m)")
        XCTAssertNil(pErr(["type": s("array"), "items": s("integer"), "min": .int(1), "max": .int(5)]))
    }

    func testParamMaxLen() {
        let m = "action.params.x: max_len must be a positive safe integer"
        XCTAssertNil(pErr(["max_len": .int(1)]))
        XCTAssertNil(pErr(["max_len": .int(2)]))
        XCTAssertEqual(pErr(["max_len": .int(0)]), m)
        XCTAssertEqual(pErr(["max_len": .int(-1)]), m)
        XCTAssertEqual(pErr(["max_len": s("x")]), m)
    }

    func testParamItems() {
        let m = "action.params.x: items applies to array only"
        XCTAssertNil(pErr(["type": s("array"), "items": s("integer")]))
        XCTAssertNil(pErr(["type": s("array"), "items": s(a(64))]))
        XCTAssertEqual(pErr(["type": s("array"), "items": s(a(65))]), m)
        XCTAssertEqual(pErr(["type": s("array"), "items": s("")]), m)
        XCTAssertEqual(pErr(["type": s("array"), "items": .int(1)]), m)
        XCTAssertEqual(pErr(["type": s("string"), "items": s("integer")]), m)
    }

    func testParamItemCounts() {
        let m = "must be a non-negative safe integer on a set or array"
        XCTAssertNil(pErr(["type": s("array"), "min_items": .int(1), "max_items": .int(2)]))
        XCTAssertNil(pErr(["type": s("set"), "values": .array([s("a")]), "min_items": .int(1), "max_items": .int(2)]))
        XCTAssertEqual(pErr(["min_items": .int(1)]), "action.params.x: min_items \(m)")
        XCTAssertEqual(pErr(["max_items": .int(1)]), "action.params.x: max_items \(m)")
        XCTAssertEqual(pErr(["type": s("array"), "min_items": .int(-1)]), "action.params.x: min_items \(m)")
        XCTAssertEqual(pErr(["type": s("array"), "max_items": s("a")]), "action.params.x: max_items \(m)")
        XCTAssertNil(pErr(["type": s("array"), "min_items": .int(2), "max_items": .int(2)]))
        XCTAssertNil(pErr(["type": s("array"), "min_items": .int(0)]))
        XCTAssertEqual(pErr(["type": s("array"), "min_items": .int(3), "max_items": .int(2)]), "action.params.x: min_items > max_items")
    }

    func testParamDefaultAndNeutralDefault() {
        XCTAssertEqual(pErr(["default": .null]), "action.params.x: default must not be null (absent = no default)")
        XCTAssertEqual(pErr(["principal_neutral_default": s("x")]), "action.params.x: principal_neutral_default must be a boolean")
        XCTAssertEqual(pErr(["principal_neutral_default": .bool(true)]), "action.params.x: principal_neutral_default needs a default")
        XCTAssertNil(pErr(["principal_neutral_default": .bool(false)]))
        XCTAssertNil(pErr(["principal_neutral_default": .bool(true), "default": s("d")]))
    }

    func testParamAccumulatesInto() {
        let cnt = "action.params.x: accumulates_into must be 1..8 unit ids"
        let ent = "action.params.x: accumulates_into entries must be unit ids"
        let int: JObject = ["type": s("integer")]
        func acc(_ v: [JSONValue]) -> String? { pErr(int.merging(["accumulates_into": .array(v)]) { $1 }) }
        XCTAssertNil(acc(ids(8)))
        XCTAssertEqual(acc(ids(9)), cnt)
        XCTAssertEqual(acc([]), cnt)
        XCTAssertNil(acc(ids(1)))
        XCTAssertEqual(pErr(int.merging(["accumulates_into": s("u")]) { $1 }), cnt)
        XCTAssertEqual(pErr(["accumulates_into": .array([s("u")])]), "action.params.x: accumulates_into applies to integer parameters only")
        XCTAssertNil(acc([s(a(64))]))
        XCTAssertEqual(acc([s(a(65))]), ent)
        XCTAssertEqual(acc([s("A")]), ent)
        XCTAssertEqual(acc([s("u"), .int(1)]), ent)
        XCTAssertEqual(acc([s("u"), s("u")]), "action.params.x: accumulates_into must be distinct")
    }

    func testParamIssuedBySiteAndDescription() {
        XCTAssertNil(pErr(["issued_by_site": .bool(true)]))
        XCTAssertEqual(pErr(["issued_by_site": s("x")]), "action.params.x: issued_by_site must be a boolean")
        XCTAssertNil(pErr(["description": s(a(1024))]))
        XCTAssertEqual(pErr(["description": s(a(1025))]), "action.params.x: description must be a string")
        XCTAssertEqual(pErr(["description": s("")]), "action.params.x: description must be a string")
        XCTAssertNil(pErr(["description": s("fine")]))
    }

    // ---- verbDeclError -------------------------------------------------------------------------------------------------

    func testVerbNameAndKind() {
        XCTAssertNil(vErr())
        XCTAssertNil(vErr(["verb": s(a(128))]))
        XCTAssertEqual(vErr(["verb": s(a(129))]), "verb entry: verb must be a non-empty string")
        XCTAssertEqual(vErr(["verb": s("")]), "verb entry: verb must be a non-empty string")
        XCTAssertEqual(vErr(["kind": s("x")]), "verb 'v': kind must be read or write")
        XCTAssertEqual(vErr(["reversibility": s("x")]), "verb 'v': unknown reversibility")
        XCTAssertNil(vErr(["reversibility": s("irreversible")]))
    }

    func testVerbParamCount() {
        func ps(_ n: Int) -> JObject {
            var o: JObject = [:]
            for i in 0..<n { o[JKey("action.params.p\(i)")] = .object(decl()) }
            return o
        }
        XCTAssertNil(vErr(params: ps(64)))
        XCTAssertEqual(vErr(params: ps(65)), "verb 'v': more than 64 parameters")
        // the first refused parameter in sorted order is reported
        XCTAssertEqual(vErr(params: ["action.params.b": .object(decl(["type": s("zz")])), "action.params.a": .object(decl(["type": s("yy")]))]),
                       "verb 'v': action.params.a: unknown type")
    }

    func testVerbReversibilityBy() {
        let p: JObject = ["action.params.x": .object(decl())]
        func rb(_ r: JObject) -> String? { vErr(["reversibility_by": .object(r)], params: p) }
        let good: JObject = ["param": s("action.params.x"), "map": .object(["a": s("reversible")])]
        XCTAssertNil(rb(good))
        XCTAssertNil(rb(good.merging(["default": s("irreversible")]) { $1 }))
        XCTAssertEqual(rb(good.merging(["default": s("bogus")]) { $1 }), "verb 'v': reversibility_by.default is not a reversibility class")
        XCTAssertEqual(rb(good.merging(["default": .int(1)]) { $1 }), "verb 'v': reversibility_by.default is not a reversibility class")
        XCTAssertEqual(rb(good.merging(["zzz": .int(1)]) { $1 }), "verb 'v': reversibility_by must be {param, map, default?}")
        XCTAssertEqual(rb(["param": s("action.params.nope"), "map": good["map"]!]), "verb 'v': reversibility_by.param must be a declared parameter")
        XCTAssertEqual(rb(["param": good["param"]!, "map": .object([:])]), "verb 'v': reversibility_by.map must map values to reversibility classes")
        XCTAssertEqual(rb(["param": good["param"]!, "map": .object(["a": s("bogus")])]), "verb 'v': reversibility_by.map must map values to reversibility classes")
    }

    func testVerbMcpAndOpenapi() {
        XCTAssertNil(vErr(["mcp": .object(["tool": s("t")])]))
        XCTAssertNil(vErr(["mcp": .object(["tool": s(a(128))])]))
        XCTAssertEqual(vErr(["mcp": .object(["tool": s(a(129))])]), "verb 'v': mcp must be {tool}")
        XCTAssertEqual(vErr(["mcp": .object([:])]), "verb 'v': mcp must be {tool}")
        XCTAssertEqual(vErr(["mcp": .object(["tool": s("t"), "x": s("y")])]), "verb 'v': mcp must be {tool}")
        XCTAssertEqual(vErr(["mcp": .object(["other": s("t")])]), "verb 'v': mcp must be {tool}")
        XCTAssertEqual(vErr(["mcp": s("t")]), "verb 'v': mcp must be {tool}")
        XCTAssertNil(vErr(["openapi": .object(["operationId": s("t")])]))
        XCTAssertNil(vErr(["openapi": .object(["operationId": s(a(128))])]))
        XCTAssertEqual(vErr(["openapi": .object(["operationId": s(a(129))])]), "verb 'v': openapi must be {operationId}")
        XCTAssertEqual(vErr(["openapi": .object([:])]), "verb 'v': openapi must be {operationId}")
        XCTAssertEqual(vErr(["openapi": .object(["operationId": s("t"), "x": s("y")])]), "verb 'v': openapi must be {operationId}")
        XCTAssertEqual(vErr(["openapi": .object(["other": s("t")])]), "verb 'v': openapi must be {operationId}")
    }

    func testVerbHarmEffectsReturnsWorldDescription() {
        for k in ["harm", "effects", "returns"] {
            XCTAssertNil(vErr([JKey(k): .object([:])]), k)
            XCTAssertEqual(vErr([JKey(k): s("x")]), "verb 'v': \(k) must be an object", k)
            XCTAssertEqual(vErr([JKey(k): .array([])]), "verb 'v': \(k) must be an object", k)
        }
        XCTAssertNil(vErr(["world": .array([])]))
        XCTAssertEqual(vErr(["world": .object([:])]), "verb 'v': world must be an array")
        XCTAssertNil(vErr(["description": s(a(1024))]))
        XCTAssertEqual(vErr(["description": s(a(1025))]), "verb 'v': description must be a string")
        XCTAssertEqual(vErr(["description": s("")]), "verb 'v': description must be a string")
        XCTAssertNil(vErr(["description": s("ok")]))
    }

    // ---- isCalendarDate ------------------------------------------------------------------------------------------------

    func testCalendarDateMonthLengths() {
        let dim = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        func ds(_ y: Int, _ m: Int, _ d: Int) -> String {
            let p = { (n: Int, w: Int) -> String in String(repeating: "0", count: w - String(n).count) + String(n) }
            return "\(p(y, 4))-\(p(m, 2))-\(p(d, 2))"
        }
        for m in 1...12 {
            XCTAssertTrue(ActionSchema.isCalendarDate(ds(2023, m, 1)), ds(2023, m, 1))
            XCTAssertTrue(ActionSchema.isCalendarDate(ds(2023, m, dim[m - 1])), ds(2023, m, dim[m - 1]))
            XCTAssertFalse(ActionSchema.isCalendarDate(ds(2023, m, dim[m - 1] + 1)), ds(2023, m, dim[m - 1] + 1))
            XCTAssertFalse(ActionSchema.isCalendarDate(ds(2023, m, 0)), ds(2023, m, 0))
        }
        XCTAssertTrue(ActionSchema.isCalendarDate("2024-02-29"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2024-02-30"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2023-02-29"))
        XCTAssertTrue(ActionSchema.isCalendarDate("2000-02-29"))
        XCTAssertFalse(ActionSchema.isCalendarDate("1900-02-29"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2019-02-29"))
        XCTAssertTrue(ActionSchema.isCalendarDate("2028-02-29"))
        XCTAssertTrue(ActionSchema.isCalendarDate("0001-01-01"))
        XCTAssertTrue(ActionSchema.isCalendarDate("9999-12-31"))
    }

    func testCalendarDateShapeAndRanges() {
        XCTAssertFalse(ActionSchema.isCalendarDate("0000-01-01"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026-00-10"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026-13-01"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026-01-00"))
        // a non-digit never counts as a digit (here 'x' would otherwise make the year 2092)
        XCTAssertFalse(ActionSchema.isCalendarDate("202x-01-01"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026-0x-01"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026-01-0x"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026/01/01"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026-01-011"))
        XCTAssertFalse(ActionSchema.isCalendarDate("2026-1-01"))
        XCTAssertFalse(ActionSchema.isCalendarDate(""))
    }

    // ---- valueViolation / conform --------------------------------------------------------------------------------------

    private func viol(_ d: JObject, _ x: JSONValue) -> String? { ActionSchema.valueViolation(d, x)?.0 }
    private func violMsg(_ d: JObject, _ x: JSONValue) -> String? { ActionSchema.valueViolation(d, x)?.1 }

    func testStringDefaultMaxLen() {
        let d: JObject = ["type": s("string")]
        XCTAssertNil(viol(d, s(a(1024))))
        XCTAssertEqual(viol(d, s(a(1025))), "out_of_domain")
        XCTAssertEqual(violMsg(d, s(a(1025))), "longer than 1024 UTF-8 bytes")
        XCTAssertNil(viol(["type": s("string"), "max_len": .int(3)], s("abc")))
        XCTAssertEqual(viol(["type": s("string"), "max_len": .int(3)], s("abcd")), "out_of_domain")
        XCTAssertEqual(viol(d, .int(1)), "bad_type")
    }

    func testArrayDefaultMaxItemsAndBounds() {
        let strs: (Int) -> JSONValue = { n in .array(Array(repeating: self.s("a"), count: n)) }
        let d: JObject = ["type": s("array")]
        XCTAssertNil(viol(d, strs(0)))
        XCTAssertNil(viol(d, strs(64)))
        XCTAssertEqual(viol(d, strs(65)), "out_of_domain")
        XCTAssertEqual(violMsg(d, strs(65)), "array length outside the declared bounds")
        let mn: JObject = ["type": s("array"), "min_items": .int(2)]
        XCTAssertEqual(viol(mn, strs(1)), "out_of_domain")
        XCTAssertNil(viol(mn, strs(2)))
        XCTAssertNil(viol(mn, strs(3)))
        let mx: JObject = ["type": s("array"), "max_items": .int(2)]
        XCTAssertNil(viol(mx, strs(2)))
        XCTAssertEqual(viol(mx, strs(3)), "out_of_domain")
        XCTAssertNil(viol(mx, strs(0)))
        XCTAssertEqual(viol(d, s("a")), "bad_type")
    }

    func testArrayItemTypes() {
        // no declared items: strings only
        XCTAssertEqual(viol(["type": s("array")], .array([.int(1)])), "bad_type")
        XCTAssertEqual(violMsg(["type": s("array")], .array([.int(1)])), "array items must be strings of at most 1024 UTF-8 bytes")
        XCTAssertNil(viol(["type": s("array")], .array([s("a")])))
        XCTAssertEqual(viol(["type": s("array"), "max_len": .int(1)], .array([s("ab")])), "bad_type")
        XCTAssertNil(viol(["type": s("array"), "max_len": .int(2)], .array([s("ab")])))
        // integer items
        let d: JObject = ["type": s("array"), "items": s("integer"), "min": .int(1), "max": .int(5)]
        XCTAssertNil(viol(d, .array([.int(3)])))
        XCTAssertNil(viol(d, .array([.int(1), .int(5)])))
        XCTAssertEqual(viol(d, .array([.int(0)])), "out_of_domain")
        XCTAssertEqual(viol(d, .array([.int(6)])), "out_of_domain")
        XCTAssertEqual(violMsg(d, .array([.int(6)])), "array item outside min/max")
        XCTAssertEqual(viol(d, .array([s("a")])), "bad_type")
        XCTAssertEqual(violMsg(d, .array([s("a")])), "array items must be safe integers")
        XCTAssertEqual(viol(d, .array([.double(1.5)])), "bad_type")
    }

    func testSetBounds() {
        let vals: JSONValue = .array([s("a"), s("b"), s("c")])
        let strs: ([String]) -> JSONValue = { .array($0.map { self.s($0) }) }
        let d: JObject = ["type": s("set"), "values": vals]
        XCTAssertNil(viol(d, strs([])))
        XCTAssertNil(viol(d, strs(["a", "b", "c"])))
        XCTAssertEqual(viol(d, strs(["a", "a"])), "out_of_domain")
        XCTAssertEqual(viol(d, strs(["z"])), "out_of_domain")
        XCTAssertEqual(viol(d, .array([.int(1)])), "bad_type")
        XCTAssertEqual(viol(d, s("a")), "bad_type")
        let mn: JObject = ["type": s("set"), "values": vals, "min_items": .int(2)]
        XCTAssertEqual(viol(mn, strs(["a"])), "out_of_domain")
        XCTAssertEqual(violMsg(mn, strs(["a"])), "set size outside the declared bounds")
        XCTAssertNil(viol(mn, strs(["a", "b"])))
        let mx: JObject = ["type": s("set"), "values": vals, "max_items": .int(1)]
        XCTAssertNil(viol(mx, strs(["a"])))
        XCTAssertEqual(viol(mx, strs(["a", "b"])), "out_of_domain")
        XCTAssertNil(viol(mx, strs([])))
    }

    func testConformReportsANonObjectDeclarationAsBadType() {
        let schema: JSONValue = .object(["verbs": .array([.object(["verb": s("v"), "params": .object(["action.params.x": s("nope")])])])])
        let r = ActionSchema.conform(schema, verb: "v", params: .object([:]))
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.code, "bad_type")
        XCTAssertEqual(r.path, "action.params.x")
        let ok = ActionSchema.conform(.object(["verbs": .array([.object(["verb": s("v"), "params": .object([:])])])]), verb: "v", params: .object([:]))
        XCTAssertTrue(ok.ok)
    }

    // ---- v2 verb `confirmation` and the unsigned document ------------------------------------------------------------------

    private static let D32 = Base64URLStrict.encode([UInt8](repeating: 2, count: 32))
    private func conf(_ over: JObject = [:]) -> JObject {
        var c: JObject = ["def_digest": s(Self.D32), "traits_digest": s(Self.D32), "facts_digest": s(Self.D32), "final_traits": .array([s("pca.bulk"), s("pca.scheduled")]),
                          "dismissed": .array([.object(["trait": s("pca.pii_access"), "reason": s("not personal data")])]), "reviewer_kid": s("rev"), "ts": .int(0), "sig": s(Self.SIGVAL)]
        for (k, v) in over { c[k] = v }
        return c
    }
    private func v2Verb(_ c: JSONValue?) -> JSONValue {
        var v: JObject = ["verb": s("v"), "kind": s("read"), "params": .object([:]), "effects": .array([s("read")]), "traits": .array([]), "def": s(Self.D32),
                          "floors": .object(["risk": .int(0), "rev": s("reversible"), "blast_ppm": .int(0), "esc": .int(0), "caveats": .array([]), "context": .array([]), "prules": .array([])])]
        if let c = c { v["confirmation"] = c }
        return .object(v)
    }
    private func cErr(_ over: JObject = [:], drop: String? = nil) -> String? {
        var c = conf(over)
        if let d = drop { c[JKey(d)] = nil }
        return ActionSchema.verbDeclError(v2Verb(.object(c)), nil, v2: true)
    }

    func testConfirmationShape() {
        XCTAssertNil(ActionSchema.verbDeclError(v2Verb(nil), nil, v2: true))
        XCTAssertNil(cErr())
        XCTAssertNotNil(ActionSchema.verbDeclError(v2Verb(.null), nil, v2: true))
        XCTAssertNotNil(ActionSchema.verbDeclError(v2Verb(.array([])), nil, v2: true))
        XCTAssertNotNil(ActionSchema.verbDeclError(v2Verb(.object(conf())), nil, v2: false)) // v1 has no v2 members
        XCTAssertNotNil(cErr(["zzz": .int(1)]))
        XCTAssertNotNil(cErr(drop: "reviewer_kid"))
        XCTAssertNotNil(cErr(["def_digest": s("AA")]))
        XCTAssertNotNil(cErr(["sig": s(Base64URLStrict.encode([UInt8](repeating: 1, count: 63)))]))
        XCTAssertNotNil(cErr(["final_traits": .array([s("pca.scheduled"), s("pca.bulk")])]))
        XCTAssertNotNil(cErr(["final_traits": .array([s("pca.bulk"), s("pca.bulk")])]))
        XCTAssertNotNil(cErr(["final_traits": .array([s("bulk")])]))
        XCTAssertNotNil(cErr(["dismissed": .array([.object(["trait": s("pca.pii_access")])])]))
        XCTAssertNotNil(cErr(["dismissed": .array([.object(["trait": s("pca.pii_access"), "reason": s("")])])]))
        XCTAssertNotNil(cErr(["dismissed": .array([.object(["trait": s("pca.pii_access"), "reason": s(a(257))])])]))
        XCTAssertNil(cErr(["dismissed": .array([.object(["trait": s("pca.pii_access"), "reason": s(a(256))])])]))
        XCTAssertNotNil(cErr(["reviewer_kid": s(a(129))]))
        XCTAssertNil(cErr(["reviewer_kid": s(a(128))]))
        XCTAssertNotNil(cErr(["ts": .int(-1)]))
        XCTAssertNotNil(cErr(["ts": .double(1.5)]))
        XCTAssertNotNil(cErr(["ts": s("1")]))
    }

    func testUnsignedDocument() {
        var d = doc().asObject!
        d["sig"] = nil
        XCTAssertNil(ActionSchema.shapeError(.object(d), signed: false))
        XCTAssertNotNil(ActionSchema.shapeError(.object(d)))
        d["sig"] = sig()
        XCTAssertEqual(ActionSchema.shapeError(.object(d), signed: false), "an unsigned schema must not carry sig")
    }
}
