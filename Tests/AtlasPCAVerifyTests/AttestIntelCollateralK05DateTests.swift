import XCTest
@testable import AtlasPCAVerify

/// `dateUTC` is JS Date.UTC with a 1-based month, `crlTime` is derTime (attest-intel-collateral.ts:96-111), `jsDateParse` is Date.parse for the
/// ISO forms, `checkFresh` is attest-intel-collateral.ts:261-268. Expected values are independent of the code under test (Python datetime).
final class AttestIntelCollateralK05DateTests: XCTestCase {
    private typealias C = IntelCollateral

    func testDaysFromCivilEveryMonth() {
        let want: [Int64] = [11323, 11354, 11382, 11413, 11443, 11474, 11504, 11535, 11566, 11596, 11627, 11657] // the first of each month of 2001
        for (i, d) in want.enumerated() { XCTAssertEqual(C.daysFromCivil(2001, i + 1, 1), d, "month \(i + 1)") }
    }

    func testDaysFromCivilCenturyWithinAnEra() {
        XCTAssertEqual(C.daysFromCivil(1970, 1, 1), 0)
        XCTAssertEqual(C.daysFromCivil(2000, 3, 1), 11017)
        XCTAssertEqual(C.daysFromCivil(2099, 3, 1), 47176)
        XCTAssertEqual(C.daysFromCivil(2100, 3, 1), 47541)
    }

    /// Proleptic Gregorian, as Date.UTC. Year 0 is leap, so 1 March -1 is 366 days before 1 March 0 (-719468), and 400 years are 146097 days.
    func testDaysFromCivilNegativeYears() {
        XCTAssertEqual(C.daysFromCivil(0, 3, 1), -719_468)
        XCTAssertEqual(C.daysFromCivil(-1, 3, 1), -719_834)
        XCTAssertEqual(C.daysFromCivil(-400, 3, 1), -865_565)
    }

    func testDateUTCTwoDigitYears() {
        XCTAssertEqual(C.dateUTC(0, 1, 1, 0, 0, 0), -2_208_988_800_000) // 1900
        XCTAssertEqual(C.dateUTC(50, 1, 1, 0, 0, 0), -631_152_000_000) // 1950
        XCTAssertEqual(C.dateUTC(99, 1, 1, 0, 0, 0), 915_148_800_000) // 1999
        XCTAssertEqual(C.dateUTC(100, 1, 1, 0, 0, 0), -59_011_459_200_000) // year 100 stays year 100
    }

    func testDateUTCMonthsRollOver() {
        XCTAssertEqual(C.dateUTC(2000, 1, 1, 0, 0, 0), 946_684_800_000)
        XCTAssertEqual(C.dateUTC(2000, 12, 1, 0, 0, 0), 975_628_800_000)
        XCTAssertEqual(C.dateUTC(2000, 13, 1, 0, 0, 0), 978_307_200_000) // 2001-01
        XCTAssertEqual(C.dateUTC(2000, 14, 1, 0, 0, 0), 980_985_600_000) // 2001-02
        XCTAssertEqual(C.dateUTC(2000, 25, 1, 0, 0, 0), 1_009_843_200_000) // 2002-01
        XCTAssertEqual(C.dateUTC(2000, 0, 1, 0, 0, 0), 944_006_400_000) // 1999-12
        XCTAssertEqual(C.dateUTC(2000, -10, 1, 0, 0, 0), 917_827_200_000) // 1999-02
        XCTAssertEqual(C.dateUTC(2000, -11, 1, 0, 0, 0), 915_148_800_000) // 1999-01
    }

    func testDateUTCTimeFieldsAndDayRollOver() {
        XCTAssertEqual(C.dateUTC(2000, 1, 1, 1, 2, 3), 946_688_523_000)
        XCTAssertEqual(C.dateUTC(2000, 1, 32, 0, 0, 0), 949_363_200_000) // 2000-02-01
    }

    func testDigitsIsTheAsciiRange() {
        XCTAssertTrue(C.digits(ArraySlice<UInt8>([0x30, 0x39])))
        XCTAssertFalse(C.digits(ArraySlice<UInt8>([0x2f])))
        XCTAssertFalse(C.digits(ArraySlice<UInt8>([0x3a])))
    }

    private func time(_ tag: UInt8, _ s: String) -> Int64? {
        let b = Array(s.utf8)
        return try? C.crlTime(b, DerTlv(tag: tag, start: 0, end: b.count))
    }

    private func timeError(_ tag: UInt8, _ s: String) -> String? {
        let b = Array(s.utf8)
        return IntelForge.refusal { try C.crlTime(b, DerTlv(tag: tag, start: 0, end: b.count)) }
    }

    func testUTCTime() {
        XCTAssertEqual(time(0x17, "250615123456Z"), 1_749_990_896_000)
        XCTAssertEqual(time(0x17, "500101000000Z"), -631_152_000_000) // 1950
        XCTAssertEqual(time(0x17, "490101000000Z"), 2_493_072_000_000) // 2049
        XCTAssertEqual(timeError(0x17, "25010100000XZ"), "bad UTCTime")
    }

    func testGeneralizedTime() {
        XCTAssertEqual(time(0x18, "20251115123456Z"), 1_763_210_096_000)
        XCTAssertEqual(time(0x18, "00500101000000Z"), -631_152_000_000) // Date.UTC(50, ...) is 1950
        XCTAssertEqual(timeError(0x18, "2025111512345XZ"), "bad GeneralizedTime")
        XCTAssertEqual(timeError(0x18, "20251115123456X"), "bad GeneralizedTime")
        XCTAssertEqual(timeError(0x18, "2025111512345Z"), "bad GeneralizedTime")
        XCTAssertEqual(timeError(0x02, "20251115123456Z"), "not a DER time")
    }

    private let t: Int64 = 1_767_225_600_000 // 2026-01-01T00:00:00Z

    func testDateParseOptionalParts() {
        XCTAssertEqual(C.jsDateParse("2026-01-01T00:00Z"), t) // no seconds: 0
        XCTAssertEqual(C.jsDateParse("2026-01-01T00:00:00.9Z"), t + 900)
        XCTAssertEqual(C.jsDateParse("2026-01-01T00:00:00.05Z"), t + 50)
    }

    func testDateParseRefusesMalformedFields() {
        for bad in ["2026-01-0:", "2026-01-01T12:3xZ", "2026-01-01T00:00:5xZ", "2026-01-01T00:00:00x", "2026-01-01T00:00:00Zx",
                    "2026-01-01T00:00:00+01:00x", "2026-01-01T00:00:00x01:00", "2026-01-01T00:00:00+01x00"] {
            XCTAssertNil(C.jsDateParse(bad), bad)
        }
    }

    /// Every one of these ends where a field or a separator was expected. "T12" trapped on u[13] before the fix.
    /// Date.parse reads the zone-less forms as local time; a verifier must not depend on the host zone, so these stay refused (attest-intel-collateral.ts:262).
    func testDateParseRefusesTextEndingEarly() {
        for bad in ["2026-01-0", "2026-01-01T", "2026-01-01T0", "2026-01-01T12", "2026-01-01T12:", "2026-01-01T00:00", "2026-01-01T00:00:00", "2026-01-01T00:00:00.5"] {
            XCTAssertNil(C.jsDateParse(bad), bad)
        }
    }

    func testCheckFreshBoundaries() {
        let body: JObject = ["issueDate": .string("2026-01-01T00:00:00Z"), "nextUpdate": .string("2026-01-02T00:00:00Z")]
        XCTAssertEqual(C.checkFresh(body, "X", t - 1), "X: issueDate is in the future")
        XCTAssertEqual(C.checkFresh(body, "X", t), "")
        XCTAssertEqual(C.checkFresh(body, "X", t + 86_400_000), "")
        XCTAssertEqual(C.checkFresh(body, "X", t + 86_400_001), "X: stale (nextUpdate passed)")
    }
}
