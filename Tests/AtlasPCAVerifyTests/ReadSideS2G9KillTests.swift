import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the ReadSide.swift survivors of group 9: every size bound (both sides), the mode grammar and ranks, the grant window, the
/// redaction modes at their edges, and the receipt chain (issued_at, link and signature). Pinned to packages/pca/src/readside.ts.
final class S2G9ReadSideKillTests: XCTestCase {
    typealias F = V2F
    private static let key = F.key("s2g9-read")
    private static var pub: String { F.pub(key) }
    private func s(_ x: String) -> JSONValue { .string(x) }
    private func b32(_ n: UInt8) -> String { Base64URLStrict.encode([UInt8](repeating: n, count: 32)) }
    private func rep(_ n: Int, _ c: String = "a") -> String { String(repeating: c, count: n) }
    /// n ascending lowercase names `<p>00`, `<p>01`, ...
    private func names(_ p: String, _ n: Int) -> [String] { (0..<n).map { "\(p)\($0 < 10 ? "0" : "")\($0)" } }

    // ---- mode grammar and ranks (lines 69, 71, 75, 76) ----

    func testModeGrammar() {
        for ok in ["show", "last4", "hash", "token", "drop", "bucket:1", "bucket:9", "bucket:19", "bucket:90", "bucket:123456789"] {
            XCTAssertTrue(ReadSide.isMode(ok), ok)
        }
        for bad in ["bucket:", "bucket:0", "bucket:05", "bucket:1234567890", "bucket:1x", "bucket:a", "bucket", "Show", "", "bucket:-1", "bucket:1 "] {
            XCTAssertFalse(ReadSide.isMode(bad), bad)
        }
    }

    func testModeRanks() {
        XCTAssertEqual(ReadSide.rank("bucket:5"), 2)
        XCTAssertEqual(ReadSide.rank("show"), 0)
        XCTAssertEqual(ReadSide.rank("last4"), 1)
        XCTAssertEqual(ReadSide.rank("token"), 3)
        XCTAssertEqual(ReadSide.rank("hash"), 4)
        XCTAssertEqual(ReadSide.rank("drop"), 5)
        XCTAssertEqual(ReadSide.rank("zzz"), 5)
    }

    // ---- grant bounds (lines 82-84, 98-100, 108) ----

    private func entry(verb: String = "v", prefix: String = "/", purposes: [String] = ["p"], modes: JObject = [:], dm: String = "show") -> JObject {
        ["verb": s(verb), "resource_prefix": s(prefix), "purposes": .array(purposes.map { s($0) }), "modes": .object(modes), "default_mode": s(dm)]
    }

    func testEntryBounds() {
        func ok(_ e: JObject) -> Bool { ReadSide.parseEntry(.object(e)) != nil }
        XCTAssertTrue(ok(entry()))
        XCTAssertTrue(ok(entry(verb: rep(128))), "line 82")
        XCTAssertFalse(ok(entry(verb: rep(129))), "line 82")
        XCTAssertTrue(ok(entry(prefix: rep(512))), "line 82")
        XCTAssertFalse(ok(entry(prefix: rep(513))), "line 82")
        XCTAssertTrue(ok(entry(purposes: names("p", 16))), "line 83")
        XCTAssertFalse(ok(entry(purposes: names("p", 17))), "line 83")
        XCTAssertFalse(ok(entry(purposes: [])), "at least one purpose")
        func modes(_ n: Int) -> JObject { Dictionary(uniqueKeysWithValues: names("c", n).map { (JKey($0), s("show")) }) }
        XCTAssertTrue(ok(entry(modes: modes(32))), "line 84")
        XCTAssertFalse(ok(entry(modes: modes(33))), "line 84")
    }

    private func grantBody(reads: [JSONValue]? = nil, caps: JObject = [:], sinks: JObject = [:], iat: Int64 = 0, exp: Int64 = 10_000) -> JObject {
        ["v": .int(1), "id": s("g1"), "principal": s(Self.pub), "issued_at": .int(iat), "expires_at": .int(exp),
         "reads": .array(reads ?? [.object(entry())]), "caps": .object(caps), "sinks": .object(sinks)]
    }

    func testGrantBounds() {
        func ok(_ b: JObject) -> Bool { ReadSide.parseGrant(.object(b)) != nil }
        XCTAssertTrue(ok(grantBody()))
        XCTAssertTrue(ok(grantBody(reads: Array(repeating: JSONValue.object(entry()), count: 32))), "line 98")
        XCTAssertFalse(ok(grantBody(reads: Array(repeating: JSONValue.object(entry()), count: 33))), "line 98")
        XCTAssertFalse(ok(grantBody(reads: [])), "line 98: at least one read")
        func caps(_ n: Int) -> JObject { Dictionary(uniqueKeysWithValues: names("k", n).map { (JKey($0), JSONValue.int(1)) }) }
        XCTAssertTrue(ok(grantBody(caps: caps(32))), "line 99")
        XCTAssertFalse(ok(grantBody(caps: caps(33))), "line 99")
        func sinks(_ n: Int) -> JObject { Dictionary(uniqueKeysWithValues: names("s", n).map { (JKey($0), JSONValue.object(["allow": .array([]), "escalate": .array([])])) }) }
        XCTAssertTrue(ok(grantBody(sinks: sinks(16))), "line 100")
        XCTAssertFalse(ok(grantBody(sinks: sinks(17))), "line 100")
        func sink(allow: Int, escalate: Int) -> JObject {
            ["x": .object(["allow": .array(names("a", allow).map { s($0) }), "escalate": .array(names("b", escalate).map { s($0) })])]
        }
        XCTAssertTrue(ok(grantBody(sinks: sink(allow: 16, escalate: 16))), "line 108")
        XCTAssertFalse(ok(grantBody(sinks: sink(allow: 17, escalate: 0))), "line 108: allow")
        XCTAssertFalse(ok(grantBody(sinks: sink(allow: 0, escalate: 17))), "line 108: escalate")
    }

    // ---- the grant window and the failure tuple (lines 120, 123) ----

    private func signed(_ body: JObject) -> JSONValue {
        .object(["body": .object(body), "sig": s(F.sign(Self.key, IV.message(ReadSide.READ_GRANT_DOMAIN, .object(body))!))])
    }

    func testGradeGrantWindowAndFailureTuple() {
        let g = signed(grantBody(iat: 100, exp: 200))
        let atStart = ReadSide.gradeGrant(g, s(Self.pub), .int(100))
        XCTAssertNotNil(atStart.grant, "line 123: valid from issued_at")
        XCTAssertNil(atStart.code)
        XCTAssertEqual(ReadSide.gradeGrant(g, s(Self.pub), .int(99)).code, "not_yet")
        XCTAssertEqual(ReadSide.gradeGrant(g, s(Self.pub), .int(200)).code, "expired")
        XCTAssertNotNil(ReadSide.gradeGrant(g, s(Self.pub), .int(199)).grant)
        let bad = ReadSide.gradeGrant(g, .int(1), .int(100))
        XCTAssertEqual(bad.code, "bad_request")
        XCTAssertEqual(bad.now, 0, "line 120")
        XCTAssertEqual(bad.principal, "")
        XCTAssertEqual(ReadSide.gradeGrant(g, s(Self.pub), .string("x")).now, 0)
    }

    // ---- redaction ----

    private func redact(reads: [JObject]? = nil, verb: String = "v", resource: String = "/r", salt: String = "0123456789abcdef", classes: [String: String] = [:],
                        record: JObject = [:], tighten: JObject = [:], required: [String] = [], defaultMode: String = "show", modes: JObject = [:]) -> ReadResult {
        let e = reads ?? [entry(verb: verb.count > 128 ? "v" : verb, modes: modes, dm: defaultMode)]
        let g = signed(grantBody(reads: e.map { .object($0) }))
        var fields: JObject = [:]
        for (k, v) in classes { fields[JKey(k)] = s(v) }
        let input: JSONValue = .object(["principal": s(Self.pub), "now": .int(1000), "verb": s(verb), "resource": s(resource), "purpose": s("p"),
                                        "schema": .object(["fields": .object(fields), "required": .array(required.map { s($0) })]), "record": .object(record),
                                        "tighten": .object(tighten), "salt": s(salt), "counts": .object([:])])
        return ReadSide.redactRead(grant: g, input: input)
    }

    func testRequestSizeBounds() {
        XCTAssertEqual(redact(verb: rep(128)).decision, "allow", "line 142")
        XCTAssertEqual(redact(verb: rep(129)).code, "bad_request", "line 142")
        XCTAssertEqual(redact(resource: "/" + rep(511)).decision, "allow", "line 142")
        XCTAssertEqual(redact(resource: "/" + rep(512)).code, "bad_request", "line 142")
        XCTAssertEqual(redact(salt: rep(16)).decision, "allow", "lines 62, 143: a salt of SALT_MIN units is enough")
        XCTAssertEqual(redact(salt: rep(15)).code, "bad_request", "lines 62, 143")
        XCTAssertEqual(ReadSide.SALT_MIN, 16)
    }

    func testTightenTieKeepsTheGrantsMode() {
        let r = redact(classes: ["amt": "money"], record: ["amt": .int(47)], tighten: ["money": s("bucket:100")], modes: ["money": s("bucket:10")])
        XCTAssertEqual(r.view["amt"], .int(40), "line 169: an equal rank does not replace the granted mode")
        let t = redact(classes: ["amt": "money"], record: ["amt": .int(47)], tighten: ["money": s("hash")], modes: ["money": s("bucket:10")])
        XCTAssertNotNil(t.view["amt"]?.asString, "a stricter tighten does")
    }

    func testLast4Edges() {
        func view(_ v: String) -> JSONValue? { redact(classes: ["card": "pan"], record: ["card": s(v)], defaultMode: "last4").view["card"] }
        XCTAssertEqual(view("abcde"), s("****bcde"), "line 178: five characters")
        XCTAssertNil(view("abcd"), "four characters are not enough")
        XCTAssertNil(view("ab\u{10000}cd"), "line 178: U+10000 is not a BMP code point, the value is dropped")
        XCTAssertEqual(view("ab\u{FFEE}cd"), s("****b\u{FFEE}cd"), "the last BMP code point is still shown")
    }

    func testBucketEdges() {
        func view(_ mode: String, _ n: Int64) -> JSONValue? { redact(classes: ["n": "num"], record: ["n": .int(n)], defaultMode: mode).view["n"] }
        XCTAssertEqual(view("bucket:10", 47), .int(40))
        XCTAssertEqual(view("bucket:10", 0), .int(0), "line 181: zero is a valid amount")
        XCTAssertNil(view("bucket:10", -5), "line 181: a negative amount is dropped")
        XCTAssertEqual(view("bucket:1", 7), .int(7), "line 181: a bucket of 1 is a valid width")
    }

    // ---- receipts (lines 209, 213, 214, 218, 228, 232, 238) ----

    private func body(seq: Int64 = 0, prev: JSONValue = .null, issued: Int64 = 100, verb: String = "v", resource: String = "/", fields: JObject = [:],
                       labels: [String] = []) -> JObject {
        ["v": .int(1), "grant": s(b32(9)), "verb": s(verb), "resource": s(resource), "purpose": s("p"), "seq": .int(seq), "prev": prev,
         "fields": .object(fields), "labels": .array(labels.map { s($0) }), "issued_at": .int(issued), "signer": s(Self.pub)]
    }
    private func sign(_ b: JObject, bad: Bool = false) -> JObject {
        var r = b
        let msg = bad ? [UInt8]([1, 2, 3]) : IV.message(ReadSide.READ_RECEIPT_DOMAIN, .object(b))!
        r["sig"] = s(F.sign(Self.key, msg))
        return r
    }

    func testReceiptShapeBounds() {
        func ok(_ b: JObject) -> Bool { ReadSide.parseReceipt(.object(sign(b))) != nil }
        XCTAssertTrue(ok(body()))
        XCTAssertTrue(ok(body(verb: rep(128))), "line 209")
        XCTAssertFalse(ok(body(verb: rep(129))), "line 209")
        XCTAssertTrue(ok(body(resource: rep(512))), "line 209")
        XCTAssertFalse(ok(body(resource: rep(513))), "line 209")
        XCTAssertTrue(ok(body(labels: names("l", 32))), "line 213")
        XCTAssertFalse(ok(body(labels: names("l", 33))), "line 213")
        func fields(_ n: Int, cls: String = "c") -> JObject {
            Dictionary(uniqueKeysWithValues: names("f", n).map { (JKey($0), JSONValue.object(["class": s(cls), "action": s("shown"), "kind": .null, "vd": s(b32(1))])) })
        }
        XCTAssertTrue(ok(body(fields: fields(64))), "line 214")
        XCTAssertFalse(ok(body(fields: fields(65))), "line 214")
        XCTAssertTrue(ok(body(fields: fields(1, cls: "unclassified"))), "line 218")
        XCTAssertFalse(ok(body(fields: fields(1, cls: "Bad Class"))), "line 218: a class is a label or 'unclassified'")
    }

    func testChainLabelsEdges() {
        let gd = b32(9)
        func chain(_ rs: [JObject], now: Int64 = 1000) -> ChainLabels {
            ReadSide.readChainLabels(receipts: .array(rs.map { .object($0) }), rsSigner: Self.pub, grantDigest: gd, now: now)
        }
        XCTAssertEqual(ReadSide.readChainLabels(receipts: nil, rsSigner: Self.pub, grantDigest: gd, now: 1), .failed(code: "bad_receipt", at: 0), "line 228")
        let r0 = sign(body())
        XCTAssertEqual(chain([r0], now: 100), .labels([]), "line 232: a receipt issued at now is fine")
        XCTAssertEqual(chain([r0], now: 99), .failed(code: "bad_receipt", at: 0))
        // linked and signed
        let ref0 = ReadSide.readReceiptRef(.object(r0))!
        let r1 = sign(body(seq: 1, prev: s(ref0)))
        XCTAssertEqual(chain([r0, r1]), .labels([]))
        // signed but not linked (line 238)
        let unlinked = sign(body(seq: 1, prev: s(b32(5))))
        XCTAssertEqual(chain([r0, unlinked]), .failed(code: "bad_receipt", at: 1), "line 238: a broken link is refused even when the signature is good")
        // linked but badly signed (line 238)
        let forged = sign(body(seq: 1, prev: s(ref0)), bad: true)
        XCTAssertEqual(chain([r0, forged]), .failed(code: "bad_receipt", at: 1), "line 238: a bad signature is refused even when the link is good")
    }
}
