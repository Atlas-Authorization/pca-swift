import XCTest
import Foundation
import AtlasPCAVerify

/// The reference's flat helper names, through the public surface only.
final class ReferenceNamesTests: XCTestCase {
    static func hex(_ s: String) -> [UInt8] {
        let t = Array(s.utf8)
        return stride(from: 0, to: t.count, by: 2).map { UInt8(String(decoding: t[$0..<$0 + 2], as: UTF8.self), radix: 16)! }
    }
    static func m(_ v: JSONValue?, _ k: String) -> JSONValue? { if case let .object(o)? = v { return o[JKey(k)] }; return nil }

    func testSha384AndKeys() {
        XCTAssertEqual(PCA.sha384(Array("abc".utf8)), Self.hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"))
        XCTAssertEqual(PCA.sha384([]).count, 48)
        XCTAssertEqual(PCA.encodeKey([0xfb, 0xff]), "-_8")
    }

    /// RFC 8032 section 7.1, test 1 (empty message).
    func testVerifyB64u() {
        let pk = PCA.encodeKey(Self.hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
        let sig = PCA.encodeKey(Self.hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"))
        XCTAssertTrue(PCA.verifyB64u(pk, [], sig))
        XCTAssertFalse(PCA.verifyB64u(pk, [0], sig))
        XCTAssertFalse(PCA.verifyB64u(pk, [], String(sig.dropLast())), "a wrong length is refused")
        XCTAssertFalse(PCA.verifyB64u(pk + "=", [], sig), "padding is refused")
        XCTAssertFalse(PCA.verifyB64u("not base64url!", [], sig))
    }

    func testTightenAndPredicates() {
        XCTAssertEqual(PCA.tighten("allow", .string("ok")), "allow")
        XCTAssertEqual(PCA.tighten("allow", .string("escalate")), "escalate")
        XCTAssertEqual(PCA.tighten("escalate", .string("ok")), "escalate")
        XCTAssertEqual(PCA.tighten("allow", .string("whatever")), "deny")
        XCTAssertEqual(PCA.tighten("allow", nil), "deny")
        let preds: JSONValue = .array([.object(["verb": .string("read"), "resource": .string("doc/*")])])
        let ctx: (String, String) -> JSONValue = { v, r in .object(["action": .object(["verb": .string(v), "resource": .string(r)])]) }
        let ok = PCA.evaluatePredicates(preds, ctx("read", "doc/1"))
        XCTAssertEqual(Self.m(ok, "allowed"), .bool(true))
        XCTAssertNotNil(Self.m(ok, "matched"))
        let no = PCA.evaluatePredicates(preds, ctx("write", "doc/1"))
        XCTAssertEqual(Self.m(no, "allowed"), .bool(false))
        XCTAssertEqual(Self.m(no, "reason"), .string("no predicate permits write on doc/1"))
        XCTAssertEqual(Self.m(PCA.evaluatePredicates(.array([]), ctx("read", "x")), "reason"), .string("envelope grants no predicates"))
        XCTAssertEqual(Self.m(PCA.evaluatePredicates(nil, ctx("read", "x")), "allowed"), .bool(false))
    }

    func testParseDerTime() {
        XCTAssertEqual(PCA.parseDerTime(0x17, "170101000000Z"), 1_483_228_800_000)
        XCTAssertEqual(PCA.parseDerTime(0x17, "500101000000Z"), -631_152_000_000, "YY >= 50 is 19YY")
        XCTAssertEqual(PCA.parseDerTime(0x18, "20300101000000Z"), 1_893_456_000_000)
        XCTAssertTrue(PCA.parseDerTime(0x17, "171301000000Z").isNaN, "month 13")
        XCTAssertTrue(PCA.parseDerTime(0x18, "20300230000000Z").isNaN, "Feb 30")
        XCTAssertTrue(PCA.parseDerTime(0x18, "20300101000060Z").isNaN, "second 60 does not roll over")
        XCTAssertFalse(PCA.parseDerTime(0x18, "20240229000000Z").isNaN, "a leap day")
        XCTAssertTrue(PCA.parseDerTime(0x18, "20230229000000Z").isNaN)
        XCTAssertTrue(PCA.parseDerTime(0x17, "170101000000+0100").isNaN)
        XCTAssertTrue(PCA.parseDerTime(0x04, "170101000000Z").isNaN)
    }

    func testRsaKeyOkAndFrostOrder() {
        let n512 = [UInt8(0x80)] + [UInt8](repeating: 0xff, count: 63) // 512 bits
        XCTAssertTrue(PCA.rsaKeyOk(modulus: n512, exponent: [1, 0, 1]))
        XCTAssertTrue(PCA.rsaKeyOk(modulus: n512, exponent: [3]))
        XCTAssertFalse(PCA.rsaKeyOk(modulus: n512, exponent: [1]), "e = 1 makes the signature the message")
        XCTAssertFalse(PCA.rsaKeyOk(modulus: n512, exponent: [4]), "an even exponent")
        XCTAssertFalse(PCA.rsaKeyOk(modulus: n512, exponent: [1, 0, 0, 0, 1]), "an exponent wider than 32 bits")
        XCTAssertFalse(PCA.rsaKeyOk(modulus: [UInt8](repeating: 0xff, count: 63), exponent: [3]), "a modulus below 512 bits")
        XCTAssertFalse(PCA.rsaKeyOk(modulus: [UInt8](repeating: 0xff, count: 2049), exponent: [3]), "a modulus above 16384 bits")
        XCTAssertEqual(PCAFrost.L.count, 32)
        XCTAssertEqual(PCAFrost.L[0], 0xed)
        XCTAssertEqual(PCAFrost.L[31], 0x10)
    }

    func testWfOutput() throws {
        let o = Workflow.wfOutput(.int(5), labels: ["b", "a"], unit: "usd", num: true)
        XCTAssertEqual(Self.m(o, "num"), .int(5))
        XCTAssertEqual(Self.m(o, "unit"), .string("usd"))
        XCTAssertEqual(Self.m(o, "labels"), .array([.string("a"), .string("b")]))
        XCTAssertEqual(Self.m(o, "digest"), Workflow.valueDigest(.int(5)).map { .string($0) })
        XCTAssertEqual(Self.m(Workflow.wfOutput(.int(5)), "num"), .null, "num is carried only when asked")
        XCTAssertEqual(Self.m(Workflow.wfOutput(.string("x"), num: true), "num"), .null, "and only for an integer")
        XCTAssertEqual(Self.m(Workflow.wfOutput(.bool(true)), "unit"), .null)
        XCTAssertNil(Workflow.wfOutput(.double(1.5)))
        XCTAssertNil(Workflow.wfOutput(.object([:])))
        XCTAssertNil(Workflow.wfOutput(.int(9_007_199_254_740_992)))
    }
}
