import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Attest review findings (review-swift-attest.md): every call that touches attacker-shaped input runs under a deadline.

final class A0DeadlineAttestJWSDepthTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// S1: a header of N '[' used to recurse once per level in the V8 error-text rebuild and crash the process.
    func testDeeplyNestedHeaderGivesAMessageNotACrash() {
        let deep = Base64URLStrict.encode([UInt8](repeating: 0x5b, count: 200_000))
        let msg: String? = S2Deadline.within(20, "JWS.segmentError deep") { JWS.segmentError(deep, "e30") }
        XCTAssertEqual(msg, "Maximum call stack size exceeded")
        let obj = Base64URLStrict.encode(Array(String(repeating: "{\"a\":", count: 5_000).utf8))
        let msg2: String? = S2Deadline.within(20, "JWS.segmentError deep objects") { JWS.segmentError("e30", obj) }
        XCTAssertEqual(msg2, "Maximum call stack size exceeded")
    }

    func testShallowBrokenJsonStillGetsItsV8Message() {
        let broken = Base64URLStrict.encode(Array("[1,".utf8))
        let msg: String? = S2Deadline.within(10, "JWS.segmentError shallow") { JWS.segmentError(broken, "e30") }
        XCTAssertNotNil(msg)
        XCTAssertNotEqual(msg, "Maximum call stack size exceeded")
        XCTAssertFalse((msg ?? "").isEmpty)
    }

    func testTheLenientParserRefusesAnOversizedDocument() {
        let big = [UInt8](repeating: 0x20, count: Attest.MAX_LENIENT_BYTES + 1) + Array("1".utf8)
        let r: Bool? = S2Deadline.within(20, "jsonLenient oversized") { Attest.jsonLenient(big) == nil }
        XCTAssertEqual(r, true)
        let ok: Bool? = S2Deadline.within(10, "jsonLenient small") { Attest.jsonLenient(Array("{\"a\":1}".utf8)) != nil }
        XCTAssertEqual(ok, true)
    }
}

final class A0DeadlineAttestXMLDepthTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func parse(_ levels: Int) -> String? {
        let src = String(repeating: "<a>", count: levels) + String(repeating: "</a>", count: levels)
        return S2Deadline.within(20, "XML.parse \(levels) levels") { () -> String in
            do { _ = try XML.parse(src); return "ok" } catch { return (error as? AttestError)?.message ?? "other" }
        }
    }

    /// S2: the namespace walk and the recursive readers are bounded by refusing deep documents.
    func testNestingPastTheLimitIsRefusedAndTheLimitItselfParses() {
        XCTAssertEqual(parse(XML.MAX_DEPTH), "ok")
        XCTAssertEqual(parse(XML.MAX_DEPTH + 1), "XML nesting is too deep")
        XCTAssertEqual(parse(5_000), "XML nesting is too deep")
        XCTAssertEqual(parse(200_000), "XML nesting is too deep")
    }
}

final class A0DeadlineAttestNvidiaConfigTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func message(_ f: () throws -> Void) -> String { do { try f(); return "no throw" } catch { return (error as? AttestError)?.message ?? "other" } }

    /// S4: a malformed collateral / leafSubjectIncludes / firmware member throws; it never silently disables the check.
    func testMalformedCollateralPolicyAndFirmwareThrow() {
        let pins: JSONValue = .array([.string("ab")])
        let pol: JSONValue = .object(["measurements": .object(["1": .string("aa")])])
        XCTAssertEqual(message { _ = try NvidiaVerifier(["rootSpkiSha256": pins, "policy": pol, "collateral": .string("required")]) },
                       "createNvidiaSpdmVerifier: collateral must be an object")
        XCTAssertEqual(message { _ = try NvidiaVerifier(["rootSpkiSha256": pins, "policy": .object(["measurements": .object(["1": .string("aa")]), "leafSubjectIncludes": .int(5)])]) },
                       "createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string")
        XCTAssertEqual(message { _ = try NvidiaHook(["rimRootSpkiSha256": pins, "firmware": .string("x")]) }, "nvidiaCollateralHook: firmware must be an object")
        // control: a string leafSubjectIncludes with a null collateral is fine
        XCTAssertEqual(message { _ = try NvidiaVerifier(["rootSpkiSha256": pins, "policy": .object(["measurements": .object(["1": .string("aa")]), "leafSubjectIncludes": .string("NVIDIA")]), "collateral": .null]) }, "no throw")
    }
}

final class A0DeadlineAttestIntelCollateralShapeTests: XCTestCase {
    /// S5: a present, truthy, non-object collateral is garbage (refused), never "missing".
    func testNonObjectCollateralIsGarbageButAbsentFalsyAndObjectAreNot() {
        func garbage(_ v: JSONValue?) -> Bool {
            var o: JObject = ["quote": .string("x")]
            if let v = v { o["collateral"] = v }
            return DcapVerifier.collateralIsGarbage(o)
        }
        XCTAssertTrue(garbage(.string("x")))
        XCTAssertTrue(garbage(.int(5)))
        XCTAssertTrue(garbage(.array([])))
        XCTAssertTrue(garbage(.bool(true)))
        XCTAssertFalse(garbage(nil))
        XCTAssertFalse(garbage(.null))
        XCTAssertFalse(garbage(.string("")))
        XCTAssertFalse(garbage(.int(0)))
        XCTAssertFalse(garbage(.bool(false)))
        XCTAssertFalse(garbage(.object([:])))
        XCTAssertFalse(DcapVerifier.collateralIsGarbage(nil))
    }
}

final class A0DeadlineSigstoreCertExtensionsTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func e(_ tag: UInt8, _ c: [UInt8]) -> [UInt8] {
        let l = c.count
        let h: [UInt8] = l < 128 ? [UInt8(l)] : l < 256 ? [0x81, UInt8(l)] : l < 65_536 ? [0x82, UInt8(l >> 8), UInt8(l & 0xff)] : [0x83, UInt8(l >> 16), UInt8((l >> 8) & 0xff), UInt8(l & 0xff)]
        return [tag] + h + c
    }

    private func cert(oids: [[UInt8]]) -> [UInt8] {
        var exts: [UInt8] = []
        for o in oids { exts += e(0x30, e(0x06, o) + e(0x04, [0])) }
        return e(0x30, e(0x30, e(0xa3, e(0x30, exts))))
    }

    /// S7: the duplicate-extension check is linear now: thousands of distinct extensions parse quickly, a duplicate is still refused.
    func testManyDistinctExtensionsParseQuicklyAndADuplicateIsRefused() {
        var oids: [[UInt8]] = []
        for n in 0..<4_000 {
            let hi: UInt8 = UInt8(n >> 8)
            let lo: UInt8 = UInt8(n & 0x7f)
            let mid: UInt8 = UInt8((n >> 7) & 0x7f)
            oids.append([0x2b, 0x06, 0x01, hi, lo, mid])
        }
        XCTAssertEqual(Set(oids).count, 4_000, "distinct OIDs in the fixture")
        let der = cert(oids: oids)
        let n: Int?? = S2Deadline.within(20, "parseCert 4000 extensions") { try? Sigstore.parseCert(der).exts.count }
        XCTAssertEqual(n ?? nil, 4_000)
        let dup = cert(oids: [[0x2b, 0x06, 0x01, 0x01], [0x2b, 0x06, 0x01, 0x02], [0x2b, 0x06, 0x01, 0x01]])
        let refused: Bool? = S2Deadline.within(10, "parseCert duplicate") { (try? Sigstore.parseCert(dup)) == nil }
        XCTAssertEqual(refused, true)
    }
}
