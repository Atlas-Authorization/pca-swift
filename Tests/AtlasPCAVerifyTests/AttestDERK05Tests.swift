import XCTest
@testable import AtlasPCAVerify

/// Boundaries of the strict DER readers, pinned to packages/pca/src/x509-strict.ts and x509-validity.ts.
final class AttestDERK05Tests: XCTestCase {
    typealias F = StrictChainForge

    func got(_ f: () throws -> DerTlv) -> String {
        do {
            let t = try f()
            return "ok \(t.tag) \(t.start) \(t.end)"
        } catch { return (error as? AttestError)?.message ?? "?" }
    }

    func message(_ f: () throws -> Void) -> String {
        do {
            try f()
            return "no error"
        } catch { return (error as? AttestError)?.message ?? "?" }
    }

    // ---- readTlv of x509-strict.ts ----

    func testReadTlvStrictBoundaries() {
        let long = [0x30, 0x81, 0x80] + [UInt8](repeating: 0, count: 128)
        let rows: [(String, [UInt8], Int, String)] = [
            ("one byte inside the limit", [0x30, 0x00], 1, "DER: truncated header"),
            ("0x80", [0x30, 0x80, 0x00, 0x00], 4, "DER: unsupported length form"),
            ("four length octets", [0x30, 0x84, 0x01, 0x00, 0x00, 0x00], 6, "DER: unsupported length form"),
            ("length octets end at the limit", [0x30, 0x81, 0x80], 3, "DER: element overruns its parent"),
            ("length octets past the limit", [0x30, 0x82, 0x01, 0x00], 3, "DER: truncated length"),
            ("one length octet of zero", [0x30, 0x81, 0x00, 0x00], 4, "DER: non-minimal length (long form below 128)"),
            ("two length octets, leading zero", [0x30, 0x82, 0x00, 0x80], 4, "DER: non-minimal length (leading zero)"),
            ("exactly 128 in long form", long, long.count, "ok 48 3 131"),
            ("127 in long form", [0x30, 0x81, 0x7f], 3, "DER: non-minimal length (long form below 128)"),
        ]
        for (name, b, limit, want) in rows { XCTAssertEqual(got { try DER.readTlvStrict(b, 0, limit) }, want, name) }
    }

    // ---- tlvAt of x509-validity.ts ----

    func testTlvAtBoundaries() {
        let rows: [(String, [UInt8], String)] = [
            ("four length octets", [0x30, 0x84, 0, 0, 0, 1, 0xaa], "ok 48 6 7"),
            ("five length octets", [0x30, 0x85, 0, 0, 0, 0, 1, 0xaa], "bad length"),
            ("0x80", [0x30, 0x80], "bad length"),
            ("length octet is the last byte", [0x30, 0x81, 0x00], "ok 48 3 3"),
            ("non-minimal is accepted here", [0x30, 0x82, 0x00, 0x01, 0xaa], "ok 48 4 5"),
            ("end at the buffer", [0x30, 0x00], "ok 48 2 2"),
            ("overrun", [0x30, 0x01], "truncated"),
            ("one byte", [0x30], "truncated"),
        ]
        for (name, b, want) in rows { XCTAssertEqual(got { try DER.tlvAt(b, 0) }, want, name) }
        XCTAssertEqual(got { try DER.tlvAt([0x30, 0x00], -1) }, "truncated")
    }

    func testTlvAtInsideALimit() {
        let rows: [(String, [UInt8], Int, String)] = [
            ("length octets past the limit", [0x30, 0x82, 0x01, 0x00], 3, "bad length"),
            ("element past the limit", [0x30, 0x01, 0xaa], 2, "truncated"),
            ("header past the limit", [0x30, 0x00], 1, "truncated"),
            ("long-form header past the limit", [0x30, 0x81, 0x00], 1, "truncated"),
            ("zero limit", [0x30, 0x00], 0, "truncated"),
            ("negative limit", [0x30, 0x00], -1, "truncated"),
            ("empty and negative", [], -1, "truncated"),
            ("limit at the buffer", [0x30, 0x01, 0xaa], 3, "ok 48 2 3"),
            ("limit beyond the buffer is the buffer", [0x30, 0x05, 0xaa], 100, "truncated"),
            ("limit beyond the buffer, element fits", [0x30, 0x01, 0xaa], 100, "ok 48 2 3"),
        ]
        for (name, b, limit, want) in rows { XCTAssertEqual(got { try DER.tlvAt(b, 0, limit: limit) }, want, name) }
    }

    // ---- oidEquals ----

    func testOidEqualsNeedsTheTagAndTheLength() {
        let want = DER.OID_BASIC_CONSTRAINTS
        XCTAssertTrue(DER.oidEquals(want, DerTlv(tag: 0x06, start: 0, end: 3), want))
        XCTAssertFalse(DER.oidEquals(want, DerTlv(tag: 0x04, start: 0, end: 3), want), "wrong tag, same bytes")
        XCTAssertFalse(DER.oidEquals(want + [0x01], DerTlv(tag: 0x06, start: 0, end: 4), want), "longer, same prefix")
        XCTAssertFalse(DER.oidEquals([0x55, 0x1d, 0x14], DerTlv(tag: 0x06, start: 0, end: 3), want))
    }

    // ---- readCertRoleInfo ----

    static func cert(_ exts: [UInt8]...) -> [UInt8] { F.seq(F.seq(DERB.tlv(0xa3, F.seq(exts.flatMap { $0 })))) }
    static func bc(_ body: [UInt8]) -> [UInt8] { F.ext(F.OID_BC, critical: true, F.seq(body)) }

    func testCaFlagIsAnyNonZeroByte() throws {
        let rows: [(UInt8, Bool)] = [(0x00, false), (0x01, true), (0x02, true), (0xff, true)]
        for (byte, want) in rows {
            XCTAssertEqual(try DER.readCertRoleInfo(Self.cert(Self.bc([0x01, 0x01, byte]))).ca, want, "\(byte)")
        }
    }

    func testPathLenIsBigEndianOverTwoBytes() throws {
        let rows: [([UInt8], Int)] = [([0x00], 0), ([0x7f], 127), ([0x01, 0x02], 258), ([0x7f, 0xff], 32767)]
        for (mag, want) in rows {
            XCTAssertEqual(try DER.readCertRoleInfo(Self.cert(Self.bc(DERB.tlv(0x02, mag)))).pathLen, want)
        }
    }

    func testMalformedPathLen() {
        let want = "BasicConstraints pathLenConstraint malformed"
        let rows: [(String, [UInt8])] = [
            ("not an INTEGER", [0x0a, 0x01, 0x01]),
            ("empty INTEGER", [0x02, 0x00]),
            ("three bytes", [0x02, 0x03, 0x01, 0x00, 0x00]),
            ("negative", [0x02, 0x01, 0x80]),
        ]
        // a following extension keeps every read inside the buffer
        for (name, body) in rows {
            XCTAssertEqual(message { _ = try DER.readCertRoleInfo(Self.cert(Self.bc(body), F.KU_CERT_SIGN)) }, want, name)
        }
    }

    // ---- decimal arcs ----

    func testDecimalOfBase128HasNoLeadingZero() {
        let rows: [([UInt8], [UInt8])] = [
            ([], [0]), ([0], [0]), ([0, 0], [0]), ([5], [5]), ([10], [1, 0]), ([100], [1, 0, 0]),
            ([0, 10], [1, 0]), ([1, 0], [1, 2, 8]), ([0x7f, 0x7f], [1, 6, 3, 8, 3]),
        ]
        for (groups, want) in rows { XCTAssertEqual(DER.decimalOfBase128(groups), want, "\(groups)") }
    }

    func testDecSub() {
        // the first row has no borrow, so no mutant reaches a negative digit before this asserts
        let rows: [([UInt8], Int, [UInt8])] = [
            ([9, 9], 11, [8, 8]),
            ([1, 0, 0, 5], 80, [9, 2, 5]),
            ([8, 5], 80, [5]),
            ([8, 0], 80, [0]),
            ([1, 0, 0, 0], 80, [9, 2, 0]),
            ([1, 0, 7, 9], 80, [9, 9, 9]),
            ([1, 0, 0, 0], 999, [1]),
            ([2, 0, 0], 100, [1, 0, 0]),
            ([1, 2, 3, 4, 5, 6], 0, [1, 2, 3, 4, 5, 6]),
        ]
        for (d, n, want) in rows { XCTAssertEqual(DER.decSub(d, n), want, "\(d) - \(n)") }
    }

    func testOidToDottedFirstArc() throws {
        let big: [UInt8] = [0x81] + [UInt8](repeating: 0x80, count: 9) + [0x00] // 2^70
        let rows: [([UInt8], String)] = [
            ([0x00], "0.0"), ([0x05], "0.5"), ([0x09], "0.9"), ([0x0a], "0.10"), ([0x27], "0.39"),
            ([0x28], "1.0"), ([0x29], "1.1"), ([0x2d], "1.5"), ([0x4f], "1.39"),
            ([0x50], "2.0"), ([0x51], "2.1"), ([0x63], "2.19"), ([0x64], "2.20"),
            ([0x81, 0x00], "2.48"), ([0x87, 0x67], "2.919"), ([0x87, 0x68], "2.920"), ([0x88, 0x37], "2.999"),
            (big, "2.1180591620717411303344"),
            ([0x2a, 0x03, 0x04], "1.2.3.4"), ([0x55, 0x1d, 0x13], "2.5.29.19"), ([0x00] + big, "0.0.1180591620717411303424"),
        ]
        for (c, want) in rows {
            XCTAssertEqual(try DER.oidToDotted(c, DerTlv(tag: 0x06, start: 0, end: c.count)), want, "\(c)")
        }
    }

    func testOidToDottedRefusals() {
        let rows: [([UInt8], UInt8, String)] = [
            ([0x80, 0x01], 0x06, "extension OID has a non-minimal arc"),
            ([0x01, 0x80, 0x01], 0x06, "extension OID has a non-minimal arc"),
            ([0x81], 0x06, "extension OID is truncated"),
            ([0x01], 0x04, "extension OID is malformed"),
            ([], 0x06, "extension OID is malformed"),
        ]
        for (c, tag, want) in rows {
            XCTAssertEqual(message { _ = try DER.oidToDotted(c, DerTlv(tag: tag, start: 0, end: c.count)) }, want, "\(c)")
        }
    }

    // ---- the [3] block ----

    func testExtensionBlockPlacement() throws {
        let block = DERB.tlv(0xa3, F.seq(F.KU_CA))
        let serial = DERB.tlv(0x02, [0x01])
        XCTAssertEqual(try DER.parseTbsExtensions(F.seq(serial + block)).oids, ["2.5.29.15"])
        XCTAssertEqual(try DER.parseTbsExtensions(F.seq(serial)).oids, [], "no block is not an error")
        XCTAssertEqual(message { _ = try DER.parseTbsExtensions(F.seq(block + serial)) }, "extensions block is not the last TBS element")
        XCTAssertEqual(message { _ = try DER.parseTbsExtensions(F.seq(block + block)) }, "duplicate [3] extensions block")
    }

    // ---- civil time, against Date in x509-validity.ts ----

    func testLeapYears() {
        for y in [0, 4, 400, 1600, 2000, 2024, 2400] { XCTAssertTrue(DER.isLeap(y), "\(y)") }
        for y in [1, 99, 100, 101, 399, 401, 1900, 2023, 2100] { XCTAssertFalse(DER.isLeap(y), "\(y)") }
    }

    func testDaysInMonth() {
        let want = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        for (i, days) in want.enumerated() { XCTAssertEqual(DER.daysInMonth(2023, i + 1), days, "month \(i + 1)") }
        XCTAssertEqual(DER.daysInMonth(2024, 2), 29)
        XCTAssertEqual(DER.daysInMonth(1900, 2), 28)
        XCTAssertEqual(DER.daysInMonth(2000, 2), 29)
    }

    /// Expected values are Date.UTC of the same fields.
    func testEpochMsAcrossEras() {
        XCTAssertEqual(DER.epochMs(1970, 1, 1, 0, 0, 0), 0)
        XCTAssertEqual(DER.epochMs(2000, 3, 1, 0, 0, 0), 951_868_800_000)
        XCTAssertEqual(DER.epochMs(2000, 2, 29, 0, 0, 0), 951_782_400_000)
        XCTAssertEqual(DER.epochMs(2100, 3, 1, 0, 0, 0), 4_107_542_400_000)
        XCTAssertEqual(DER.epochMs(0, 1, 1, 0, 0, 0), -62_167_219_200_000)
        XCTAssertEqual(DER.epochMs(0, 2, 29, 0, 0, 0), -62_162_121_600_000)
        XCTAssertEqual(DER.epochMs(-400, 3, 1, 0, 0, 0), -74_784_816_000_000)
        XCTAssertNil(DER.epochMs(1900, 2, 29, 0, 0, 0))
    }

    func testDerTimeFields() {
        let t = { (tag: Int, s: String) in DER.parseDerTime(tag, Array(s.utf8)) }
        XCTAssertEqual(t(0x18, "00000101000000Z"), -62_167_219_200_000)
        XCTAssertEqual(t(0x18, "20000229000000Z"), 951_782_400_000)
        XCTAssertNil(t(0x18, "19000229000000Z"))
        XCTAssertEqual(t(0x17, "000229000000Z"), 951_782_400_000)
        XCTAssertEqual(t(0x18, "19700101000001Z"), 1000)
        XCTAssertEqual(t(0x17, "700101000001Z"), 1000)
        // the last digit position is checked, and so is the Z, each on its own
        XCTAssertNil(t(0x18, "2025010100000AZ"))
        XCTAssertNil(t(0x18, "20250101000000X"))
        XCTAssertNil(t(0x17, "25010100000AZ"))
        XCTAssertNil(t(0x17, "250101000000X"))
    }

    // ---- validity ----

    static let NB = 1_735_689_600_000 as Int64, NA = 2_051_222_400_000 as Int64

    static func withValidity(_ notBefore: String = "250101000000Z", _ notAfter: String = "350101000000Z") -> [UInt8] {
        let validity = F.seq(DERB.tlv(0x17, Array(notBefore.utf8)) + DERB.tlv(0x17, Array(notAfter.utf8)))
        return F.seq(F.seq(DERB.tlv(0x02, [0x01]) + F.seq([]) + F.seq([]) + validity))
    }

    func testValidityMayEndExactlyAtTheTbsEnd() {
        let (from, to) = DER.derValidity(Self.withValidity())
        XCTAssertEqual(from, Self.NB)
        XCTAssertEqual(to, Self.NA)
        // past the TBS it is not the validity
        let validity = F.seq(DERB.tlv(0x17, Array("250101000000Z".utf8)) + DERB.tlv(0x17, Array("350101000000Z".utf8)))
        let (f2, t2) = DER.derValidity(F.seq(F.seq(DERB.tlv(0x02, [0x01]) + F.seq([]) + F.seq([])) + validity))
        XCTAssertNil(f2)
        XCTAssertNil(t2)
    }

    func testUnparseableBoundsAreNeverValid() {
        let certs: [[UInt8]] = [[1, 2, 3], [], Self.withValidity("bad"), Self.withValidity("250101000000Z", "bad")]
        for c in certs {
            XCTAssertFalse(DER.derValidAt(c, Self.NB, 0))
            XCTAssertFalse(DER.derValidAtF(c, Self.NB, 0))
        }
    }

    func testFractionalSkewEdges() {
        let c = Self.withValidity()
        let rows: [(String, Int64, Double, Bool)] = [
            ("at notBefore", Self.NB, 0, true),
            ("at notAfter", Self.NA, 0, true),
            ("at notAfter, skew must not push it out", Self.NA, 1, true),
            ("at notBefore, skew must not push it out", Self.NB, 1, true),
            ("before", Self.NB - 1, 0, false),
            ("before, inside skew", Self.NB - 1, 1, true),
            ("before, outside a fractional skew", Self.NB - 1, 0.5, false),
            ("after", Self.NA + 1, 0, false),
            ("after, inside skew", Self.NA + 1, 1.5, true),
            ("after, outside a fractional skew", Self.NA + 1, 0.5, false),
        ]
        for (name, now, skew, want) in rows { XCTAssertEqual(DER.derValidAtF(c, now, skew), want, name) }
    }

    /// x509ValidAt refuses a non-finite skew.
    func testNonFiniteSkewIsRefused() {
        let c = Self.withValidity()
        for skew in [Double.infinity, -Double.infinity, Double.nan] {
            XCTAssertFalse(DER.derValidAtF(c, Self.NB + 1, skew), "\(skew)")
        }
    }
}
