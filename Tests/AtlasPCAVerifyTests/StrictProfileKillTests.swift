import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The reference reads a step-up event and a JWS header / payload with the strict canonical JSON profile: a repeated member, a number with an exponent or a
/// trailing-zero fraction and a lone surrogate are refused, and a refused JWS segment is reported as "invalid JSON". Each case below fails if the native reads
/// the text with the lenient parser (which gets as far as the field checks, or as far as the engine's own message).
final class StrictProfileKillTests: XCTestCase {
    private func eventRefusal(_ text: String) -> String? {
        do { _ = try PCAEvents.parseEvent(.string(text)); return nil } catch { return (error as? JSError)?.message ?? "\(error)" }
    }

    func testEventParserRefusesWhatTheStrictProfileRefuses() {
        for text in [#"{"id":"a","id":"b"}"#, #"{"id":"a","at":1e3}"#, #"{"id":"a","at":1.0}"#, #"{"id":"a","type":"\ud800"}"#] {
            let m = eventRefusal(text)
            XCTAssertNotNil(m, text)
            XCTAssertTrue(m?.hasPrefix("json: ") ?? false, "\(text): \(m ?? "accepted")")
        }
        // a plain object reaches the field checks (not a JSON refusal)
        XCTAssertEqual(eventRefusal(#"{"at":1}"#), "parseEvent: bad id")
        // a text carrying the library's lone-surrogate scalar is a lone surrogate
        XCTAssertTrue(eventRefusal("{\"id\":\"a\",\"type\":\"\(String(Unicode.Scalar(0xFD800)!))\"}")?.hasPrefix("json: ") ?? false)
    }

    private func token(_ header: String, _ payload: String) -> String {
        Base64URLStrict.encode(Array(header.utf8)) + "." + Base64URLStrict.encode(Array(payload.utf8)) + ".c2ln"
    }

    /// MAA and Confidential Space header / payload segments: a repeated member and non-JSON are refused with one engine-independent reason; numbers are read as
    /// written (real vendor tokens carry exponents, `-0` and `8.0`).
    func testJwsSegmentsRefuseADuplicateReadNumbersAsWrittenAndReportInvalidJson() {
        let good = #"{"alg":"ES256"}"#
        for (h, p) in [(good, #"{"a":1,"a":2}"#), (#"{"alg":"ES256","alg":"x"}"#, "{}"), ("x", "{}"), (good, #"{"a":"#), (good, #"{"a":{"b":1,"b":1}}"#)] {
            do {
                _ = try JWS.parse(token(h, p), "parseMaaJwt")
                XCTFail("accepted \(h) \(p)")
            } catch {
                XCTAssertTrue("\(error)".contains("parseMaaJwt: malformed JSON segment: invalid JSON"), "\(h) \(p): \(error)")
            }
        }
        for p in [#"{"a":1.5}"#, #"{"a":8.0,"b":1e3}"#, #"{"svn":-0}"#, #"{"a":1.50}"#] {
            XCTAssertNoThrow(try JWS.parse(token(good, p), "parseMaaJwt"), p)
        }
    }

    func testVendorDocumentsAreReadAsJsonParseReadsThemWithADuplicateRefused() {
        XCTAssertNil(Attest.jsonLenient(Array(#"{"tcbInfo":{"a":1},"tcbInfo":{"a":2}}"#.utf8)))
        XCTAssertNotNil(Attest.jsonLenient(Array(#"{"tcbInfo":{"a":8.0,"b":1e3}}"#.utf8)))
    }
}
