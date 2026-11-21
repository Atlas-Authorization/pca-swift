import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kill tests (mutation sheet swift-k05 group 8) for Obligations.swift, RuntimeClaim.swift, SafeRegex.complement and
/// MemoryStateStore.consumeOnce.
final class S2G8ObligationsKillTests: XCTestCase {
    // ---------------------------------------------------------------- redact field paths (lines 17-26)

    func testFieldPathSegments() {
        for s in ["a", "A", "_", "a0", "a_9", "a.b", "a.b.c.d.e.f.g.h", String(repeating: "a", count: 64), "a." + String(repeating: "b", count: 64)] {
            XCTAssertTrue(Obligations.fieldOk(s), s)
        }
        XCTAssertFalse(Obligations.fieldOk(""), "an empty path")
        for s in ["a..b", ".a", "a."] { XCTAssertFalse(Obligations.fieldOk(s), "line 17/20 an empty segment: \(s)") }
        XCTAssertFalse(Obligations.fieldOk("a.b.c.d.e.f.g.h.i"), "line 18 nine segments")
        XCTAssertFalse(Obligations.fieldOk(String(repeating: "a", count: 65)), "line 20 a 65-character segment")
        XCTAssertFalse(Obligations.fieldOk("a." + String(repeating: "b", count: 65)))
    }

    func testFieldPathCharacters() {
        for c in ["A", "Z", "a", "z", "_"] { XCTAssertTrue(Obligations.fieldOk(c), "line 23 '\(c)' starts a segment") }
        for c in ["@", "[", "`", "{", "^", "0", "9", "-", "/", ":"] { XCTAssertFalse(Obligations.fieldOk(c), "line 23/25 '\(c)' may not start a segment") }
        for c in ["0", "9", "A", "Z", "a", "z", "_"] { XCTAssertTrue(Obligations.fieldOk("a" + c), "line 24 '\(c)' continues a segment") }
        for c in ["/", ":", "@", "[", "`", "{", "^", "-", " "] { XCTAssertFalse(Obligations.fieldOk("a" + c), "line 24 '\(c)' may not continue a segment") }
        XCTAssertTrue(Obligations.fieldOk("a1"), "line 26 a digit after the first character")
        XCTAssertFalse(Obligations.fieldOk("1a"), "line 21 a digit may not be first")
        XCTAssertTrue(Obligations.fieldOk("a.b1"), "the first flag resets for every segment")
        XCTAssertFalse(Obligations.fieldOk("a.1b"))
    }

    // ---------------------------------------------------------------- parameter bounds (lines 11, 35-43)

    private func ob(_ kind: String, _ params: JObject) -> JSONValue { .object(["kind": .string(kind), "params": .object(params)]) }
    private func text(_ n: Int) -> JSONValue { .string(String(repeating: "x", count: n)) }

    func testRedactFieldCount() {
        func fields(_ n: Int) -> JSONValue { .array((0..<n).map { JSONValue.string("f\($0)") }) }
        XCTAssertNil(Obligations.obligationError(ob("redact", ["fields": fields(32)])), "lines 11, 42 thirty-two fields")
        XCTAssertEqual(Obligations.obligationError(ob("redact", ["fields": fields(33)])), "redact.fields must be 1..32 dotted field paths")
        XCTAssertEqual(Obligations.obligationError(ob("redact", ["fields": fields(0)])), "redact.fields must be 1..32 dotted field paths")
        XCTAssertNil(Obligations.obligationError(ob("redact", ["fields": fields(1)])))
        XCTAssertEqual(Obligations.obligationError(ob("redact", ["fields": .array([.int(5)])])), "redact.fields must be 1..32 dotted field paths", "line 43")
        XCTAssertEqual(Obligations.obligationError(ob("redact", ["fields": .array([.string("a"), .string("a")])])), "redact.fields has a duplicate")
    }

    func testStringParameterBounds() {
        XCTAssertNil(Obligations.obligationError(ob("log", ["sink": text(128)])), "line 35")
        XCTAssertEqual(Obligations.obligationError(ob("log", ["sink": text(129)])), "log.sink must be a non-empty string of at most 128 characters")
        XCTAssertEqual(Obligations.obligationError(ob("log", ["sink": .string("")])), "log.sink must be a non-empty string of at most 128 characters")
        XCTAssertNil(Obligations.obligationError(ob("log", [:])), "a log obligation may omit its sink")
        XCTAssertNil(Obligations.obligationError(ob("notify", ["to": text(256)])), "line 36")
        XCTAssertEqual(Obligations.obligationError(ob("notify", ["to": text(257)])), "notify.to is required (a non-empty string of at most 256 characters)")
        XCTAssertNil(Obligations.obligationError(ob("watermark", ["id": text(128)])), "line 37")
        XCTAssertEqual(Obligations.obligationError(ob("watermark", ["id": text(129)])), "watermark.id is required (a non-empty string of at most 128 characters)")
    }

    // ---------------------------------------------------------------- merge (line 101)

    func testMergeLimit() {
        func list(_ prefix: String, _ n: Int) -> JSONValue { .array((0..<n).map { ob("watermark", ["id": .string("\(prefix)\($0)")]) }) }
        let sixteen = Obligations.mergeObligations([list("a", 8), list("b", 8)])
        XCTAssertTrue(sixteen.ok, "line 101 sixteen merged obligations")
        XCTAssertEqual(sixteen.obligations.count, 16)
        let seventeen = Obligations.mergeObligations([list("a", 9), list("b", 8)])
        XCTAssertFalse(seventeen.ok)
        XCTAssertEqual(seventeen.reason, "more than 16 obligations after merging")
        // duplicates across lists collapse
        XCTAssertEqual(Obligations.mergeObligations([list("a", 16), list("a", 16)]).obligations.count, 16)
    }

    // ---------------------------------------------------------------- RuntimeClaim (lines 16, 17, 21)

    private static let rkey = V2F.key("s2g8-runtime-claim")

    private func claim(passport: String, evidence: String, iat: Int64 = 100, exp: Int64 = 200) -> JSONValue {
        var body: JObject = ["v": .int(1), "class": .string("os_confined"), "passport_digest": .string(passport), "evidence_digest": .string(evidence),
                             "iat": .int(iat), "exp": .int(exp), "attestor": .string(V2F.pub(Self.rkey))]
        body["sig"] = .string(V2F.sign(Self.rkey, IV.message(RuntimeClaim.DOMAIN, .object(body))!))
        return .object(body)
    }
    private func verified(_ c: JSONValue, passport: String, evidence: String, now: Int64) -> String {
        RuntimeClaim.verifiedClass(c, pinnedAttestors: [V2F.pub(Self.rkey)], passportDigest: passport, verifiedEvidence: [evidence], now: .int(now))
    }

    func testRuntimeClaimDigestBounds() {
        let p128 = String(repeating: "p", count: 128), e128 = String(repeating: "e", count: 128)
        XCTAssertEqual(verified(claim(passport: p128, evidence: e128), passport: p128, evidence: e128, now: 150), "os_confined", "lines 16, 17 128 characters")
        let p129 = String(repeating: "p", count: 129), e129 = String(repeating: "e", count: 129)
        XCTAssertEqual(verified(claim(passport: p129, evidence: e128), passport: p129, evidence: e128, now: 150), "none", "line 16 a 129-character passport digest")
        XCTAssertEqual(verified(claim(passport: p128, evidence: e129), passport: p128, evidence: e129, now: 150), "none", "line 17 a 129-character evidence digest")
    }

    func testRuntimeClaimWindow() {
        let c = claim(passport: "p", evidence: "e")
        XCTAssertEqual(verified(c, passport: "p", evidence: "e", now: 100), "os_confined", "line 21 iat <= now")
        XCTAssertEqual(verified(c, passport: "p", evidence: "e", now: 99), "none")
        XCTAssertEqual(verified(c, passport: "p", evidence: "e", now: 199), "os_confined")
        XCTAssertEqual(verified(c, passport: "p", evidence: "e", now: 200), "none")
    }

    // ---------------------------------------------------------------- SafeRegex.complement (line 61)

    func testComplementKeepsTheLastCodeUnit() {
        let c = SafeRegex.complement([(0, 0xfffe)])
        XCTAssertEqual(c.count, 1, "line 61")
        XCTAssertEqual(c.first?.0, 0xffff)
        XCTAssertEqual(c.first?.1, 0xffff)
        XCTAssertEqual(SafeRegex.complement([(0, 0xffff)]).count, 0)
        let mid = SafeRegex.complement([(5, 9)])
        XCTAssertEqual(mid.count, 2)
        XCTAssertEqual(mid.first?.0, 0)
        XCTAssertEqual(mid.first?.1, 4)
        XCTAssertEqual(mid.last?.0, 10)
        XCTAssertEqual(mid.last?.1, 0xffff)
    }

    // ---------------------------------------------------------------- MemoryStateStore.consumeOnce (line 93)

    func testRepeatedConsumeExtendsTheRetention() throws {
        let s = MemoryStateStore()
        XCTAssertTrue(try s.consumeOnce(key: "k", retainUntil: 100, now: 0))
        XCTAssertFalse(try s.consumeOnce(key: "k", retainUntil: 200, now: 0), "a repeat is refused and keeps the later expiry")
        XCTAssertFalse(try s.consumeOnce(key: "k", retainUntil: 300, now: 150), "line 93 the entry is still retained at 150")
        XCTAssertTrue(try s.consumeOnce(key: "k", retainUntil: 400, now: 350), "after every retention has passed the key is free again")
    }
}
