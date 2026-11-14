import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Review findings (0.5 crypto review): the quadratic OID arc decode, the unbounded OCSP nesting recursion and weak RSA public keys.
/// Every call that touches attacker-shaped input runs under a deadline. Class name carries the AttestDER / AttestNvidiaOcsp / AttestCrypto
/// stems so the mutation tool runs these first.
final class A0DeadlineAttestDERLimitsTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func oidResult(_ content: [UInt8]) -> String? {
        S2Deadline.within(10, "oidToDotted \(content.count) bytes") { () -> String in
            let b: [UInt8] = [0x06] + content
            do { return try DER.oidToDotted(b, DerTlv(tag: 0x06, start: 1, end: b.count)) } catch { return "ERR:\((error as? AttestError)?.message ?? "?")" }
        }
    }

    func testAHugeOidArcIsRefusedQuicklyAndRealOidsStillDecode() {
        // one arc of 100,000 groups (0xFF ... 0x7F): the quadratic decimal conversion would take tens of seconds
        let huge = [UInt8](repeating: 0xff, count: 99_999) + [0x7f]
        XCTAssertEqual(oidResult(huge), "ERR:extension OID is too long")
        // under the content cap but one arc past the group cap
        let longArc = [0x2a] + [UInt8](repeating: 0xff, count: MAX_OID_ARC_GROUPS) + [0x7f]
        XCTAssertEqual(oidResult(longArc), "ERR:extension OID has an oversized arc")
        // exactly MAX_OID_ARC_GROUPS groups is accepted
        let okArc = [0x2a] + [UInt8](repeating: 0x81, count: MAX_OID_ARC_GROUPS - 1) + [0x01]
        XCTAssertFalse(oidResult(okArc)?.hasPrefix("ERR") ?? true, "an arc of MAX_OID_ARC_GROUPS groups decodes")
        // one byte over the content cap, in short arcs
        XCTAssertEqual(oidResult([UInt8](repeating: 0x01, count: MAX_OID_CONTENT + 1)), "ERR:extension OID is too long")
        XCTAssertFalse(oidResult([UInt8](repeating: 0x01, count: MAX_OID_CONTENT))?.hasPrefix("ERR") ?? true, "exactly the content cap decodes")
        // real OIDs: 2.5.4.3 and a 2.25.<128-bit UUID> arc (19 groups)
        XCTAssertEqual(oidResult([0x55, 0x04, 0x03]), "2.5.4.3")
        let uuid: [UInt8] = [0x69] + [UInt8](repeating: 0xff, count: 18) + [0x7f]
        XCTAssertTrue(oidResult(uuid)?.hasPrefix("2.25.") ?? false, "a UUID arc decodes: \(oidResult(uuid) ?? "nil")")
    }
}

final class A0DeadlineAttestNvidiaOcspDepthTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// `levels` nested SEQUENCEs around one NULL.
    private func nested(_ levels: Int) -> [UInt8] {
        var c: [UInt8] = [0x05, 0x00]
        for _ in 0..<levels {
            let l = c.count
            let len: [UInt8] = l < 128 ? [UInt8(l)] : l < 256 ? [0x81, UInt8(l)] : l < 65_536 ? [0x82, UInt8(l >> 8), UInt8(l & 0xff)] : [0x83, UInt8(l >> 16), UInt8((l >> 8) & 0xff), UInt8(l & 0xff)]
            c = [0x30] + len + c
        }
        return c
    }

    private func wellFormed(_ levels: Int) -> Bool? {
        let der = nested(levels)
        return S2Deadline.within(10, "timesWellFormed \(levels) levels") { () -> Bool in
            guard let n = try? OCSP.readNode(der, 0, der.count) else { return false }
            return OCSP.timesWellFormed(der, n)
        }
    }

    func testNestingPastTheDepthLimitIsRefusedAndDepthAtTheLimitIsFine() {
        XCTAssertEqual(wellFormed(OCSP.MAX_OCSP_DEPTH), true, "the outermost sequence is level 1, so MAX levels of SEQUENCE around a NULL are accepted")
        XCTAssertEqual(wellFormed(OCSP.MAX_OCSP_DEPTH + 1), false, "one level too many is refused")
        XCTAssertEqual(wellFormed(4_000), false, "a deeply nested response is refused without recursing to the bottom")
    }
}

final class A0DeadlineAttestCryptoRsaKeyTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private static func modulus(bits: Int) -> [UInt8] {
        var n = [UInt8](repeating: 0xab, count: (bits + 7) / 8)
        n[0] = UInt8(truncatingIfNeeded: 0xff >> UInt8((8 - bits % 8) % 8)) | UInt8(1 << ((bits - 1) % 8))
        n[n.count - 1] |= 1
        return n
    }
    private static func one(_ k: Int) -> [UInt8] { [UInt8](repeating: 0, count: k - 1) + [1] }

    func testWeakExponentsAreRefusedAndOrdinaryOnesAccepted() {
        let n = Self.modulus(bits: 1024)
        let results: [Bool]? = S2Deadline.within(10, "rsaKeyOK exponents") {
            [[0x01], [0x02], [0x04], [0x00, 0x01], [0x01, 0x00, 0x00], [], [0x00], [0x03], [0x01, 0x00, 0x01], [0x7f, 0xff, 0xff, 0xff], [0x80, 0, 0, 0x01], [0x01, 0, 0, 0, 0x01]].map { ACrypto.rsaKeyOK(n: n, e: $0) }
        }
        XCTAssertEqual(results, [false, false, false, false, false, false, false, true, true, true, true, false],
                       "e = 1, even e (2, 4, 65536), empty, zero and a 33-bit e are refused; 3, 65537, 2^31-1 and a 32-bit odd e pass")
    }

    func testModulusBounds() {
        let r: [Bool]? = S2Deadline.within(10, "rsaKeyOK modulus bounds") {
            [16384, 16385, 512, 511].map { ACrypto.rsaKeyOK(n: Self.modulus(bits: $0), e: [0x03]) }
                + [ACrypto.rsaKeyOK(n: { var m = Self.modulus(bits: 1024); m[m.count - 1] &= 0xfe; return m }(), e: [0x03])]
        }
        XCTAssertEqual(r, [true, false, true, false, true], "16384 bits is the ceiling and 512 the floor (OpenSSL's bounds); parity of n is rsaPublic's job")
    }

    func testTheBarePrimitiveStillTakesAnyExponentItsCallersGate() {
        // rsaPublic is the primitive the e = 1 fixtures of the RSA tests use; the key rules live in rsaKeyOK at every call site
        let got: [UInt8]?? = S2Deadline.within(10, "rsaPublic e=1") { ACrypto.rsaPublic(n: Self.modulus(bits: 1024), e: [0x01], sig: Self.one(128)) }
        XCTAssertEqual(got ?? nil, Self.one(128))
    }
}
