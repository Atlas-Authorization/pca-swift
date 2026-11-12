import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Arg-provenance boundaries pinned to the reference arg-provenance.ts: the leaf cap (`out.length > MAX_PROV_LEAVES` on entry),
/// content keys `^(0|[1-9][0-9]{0,8})$`, the 256-byte observation source and mediator bounds, and the recorder (`clip`, the
/// epoch-millisecond clock, `issued_at = max(prev?.issued_at ?? 0, trunc(now()))`).
final class ArgProvenanceKill2Tests: XCTestCase {
    private func a(_ n: Int) -> String { String(repeating: "a", count: n) }

    func testLeavesExactlyAtTheCapThenAnEmptyContainer() {
        let full = (0..<PCA.MAX_PROV_LEAVES).map { _ in JSONValue.string("x") }
        XCTAssertEqual(PCA.provLeaves(.array(full + [.array([])]))?.count, PCA.MAX_PROV_LEAVES)
        XCTAssertEqual(PCA.provLeaves(.array(full + [.object([:])]))?.count, PCA.MAX_PROV_LEAVES)
        XCTAssertNil(PCA.provLeaves(.array(full + [.string("y")])))
    }

    func testContentIndex() {
        XCTAssertEqual(PCA.contentIndex("0"), 0)
        XCTAssertEqual(PCA.contentIndex("9"), 9)
        XCTAssertEqual(PCA.contentIndex("10"), 10)
        XCTAssertEqual(PCA.contentIndex("90"), 90)
        XCTAssertEqual(PCA.contentIndex("123456789"), 123456789)
        XCTAssertEqual(PCA.contentIndex("999999999"), 999999999)
        for bad in ["", "00", "01", "09", "1234567890", "9999999999", "+1", "-1", " 1", "1 ", "a", "/", ":", "1/", "1:", "١"] {
            XCTAssertNil(PCA.contentIndex(bad), bad)
        }
    }

    private func decide(observed source: String) -> ArgProvenanceDecision {
        PCA.decideArgProvenance(ArgProvenanceInput(bundle: nil,
                                                   operation: .object(["verb": .string("v"), "resource": .string("r"), "params": .object([:])]),
                                                   mediators: .array([]),
                                                   observed: .array([.object(["origin": .string("tool"), "source": .string(source)])])))
    }

    func testObservationSourceIsAtMost256Bytes() {
        XCTAssertNotEqual(decide(observed: a(256)).code, "malformed_config")
        XCTAssertNotEqual(decide(observed: String(repeating: "é", count: 128)).code, "malformed_config")
        XCTAssertEqual(decide(observed: a(257)).code, "malformed_config")
        XCTAssertEqual(decide(observed: String(repeating: "é", count: 128) + "a").code, "malformed_config")
        XCTAssertEqual(decide(observed: "").code, "malformed_config")
    }

    func testRecorderMediatorAndKidBounds() {
        let seed = [UInt8](repeating: 7, count: 32)
        XCTAssertNoThrow(try ProvenanceRecorder(mediator: a(256), kid: a(64), secretKey: seed))
        XCTAssertThrowsError(try ProvenanceRecorder(mediator: a(257), kid: "k", secretKey: seed))
        XCTAssertThrowsError(try ProvenanceRecorder(mediator: "m", kid: a(65), secretKey: seed))
        XCTAssertThrowsError(try ProvenanceRecorder(mediator: "", kid: "k", secretKey: seed))
    }

    func testDefaultClockIsEpochMilliseconds() throws {
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32))
        let lo = Int64(Date().timeIntervalSince1970 * 1000) - 1
        let issued = try XCTUnwrap(r.principal("hi").get("issued_at")?.safeInt)
        let hi = Int64(Date().timeIntervalSince1970 * 1000) + 1
        XCTAssertGreaterThanOrEqual(issued, lo)
        XCTAssertLessThanOrEqual(issued, hi)
    }

    func testIssuedAtIsMaxOfPreviousOrZeroAndNow() throws {
        var clock: [Int64] = [0, -5, 7, 3]
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32), now: { clock.removeFirst() })
        XCTAssertEqual(try r.principal("a").get("issued_at")?.safeInt, 0)  // first receipt: max(0, now)
        XCTAssertEqual(try r.tool("t", "b").get("issued_at")?.safeInt, 0)  // a clock below zero never goes negative
        XCTAssertEqual(try r.tool("t", "c").get("issued_at")?.safeInt, 7)
        XCTAssertEqual(try r.tool("t", "d").get("issued_at")?.safeInt, 7)  // a clock going back never orders a receipt before its predecessor
        let neg = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32), now: { -9 })
        XCTAssertEqual(try neg.principal("a").get("issued_at")?.safeInt, 0)
    }

    func testClipHalvesByUTF16UnitsAndNeverSplitsAPair() throws {
        XCTAssertEqual(try ProvenanceRecorder.clip(""), "-")
        XCTAssertEqual(try ProvenanceRecorder.clip("a"), "a")
        XCTAssertEqual(try ProvenanceRecorder.clip(a(256)), a(256))
        XCTAssertEqual(try ProvenanceRecorder.clip(a(257)), a(128))
        XCTAssertEqual(try ProvenanceRecorder.clip(a(1000)), a(250))
        // 2-byte units: U+0080 (the first) and U+07FF (the last)
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{80}", count: 128)), String(repeating: "\u{80}", count: 128))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{80}", count: 129)), String(repeating: "\u{80}", count: 64))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{7FF}", count: 129)), String(repeating: "\u{7FF}", count: 64))
        // 3-byte units: U+0800 (the first) and U+FFFF
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{800}", count: 85)), String(repeating: "\u{800}", count: 85))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{800}", count: 86)), String(repeating: "\u{800}", count: 43))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{FFFF}", count: 86)), String(repeating: "\u{FFFF}", count: 43))
        // 4-byte pairs (2 units each): 64 fit; 65 halve to unit 65 = a low surrogate, so the cut moves back one unit
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "😀", count: 64)), String(repeating: "😀", count: 64))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "😀", count: 65)), String(repeating: "😀", count: 32))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{10000}", count: 65)), String(repeating: "\u{10000}", count: 32)) // low DC00
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "\u{103FF}", count: 65)), String(repeating: "\u{103FF}", count: 32)) // low DFFF
        // "a" + 64 pairs = 257 bytes, 129 units: the cut at 64 is a low surrogate, so 63 units = "a" + 31 pairs
        XCTAssertEqual(try ProvenanceRecorder.clip("a" + String(repeating: "😀", count: 64)), "a" + String(repeating: "😀", count: 31))
        // a cut on a pair boundary is kept: "abc" + 64 pairs = 259 bytes, 131 units, unit 65 is a high surrogate -> 65 units
        XCTAssertEqual(try ProvenanceRecorder.clip("abc" + String(repeating: "😀", count: 64)), "abc" + String(repeating: "😀", count: 31))
    }
}
