import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Small survivors of mutation round 2, sheet 3: RevokedSet, protect()'s revocation hook, the Sigstore +HH:MM offset and compareVersion.
final class S2R3MiscKillTests: XCTestCase {
    func testRevokedSetNilIdIsNeverRevoked() {
        let s = RevokedSet()
        XCTAssertFalse(s.contains(nil), "Protect.swift line 8: no id, not revoked")
        s.insert("a")
        XCTAssertFalse(s.contains(nil))
        XCTAssertTrue(s.contains("a"))
        XCTAssertFalse(s.contains("b"))
    }

    func testProtectRevocationHookConsultsTheCallersHook() throws {
        let g = try XCTUnwrap(JSONValue.parse("{\"id\":\"g1\"}"))
        let yes = protect(audience: "a", operation: { _ in nil }, isRevoked: { _, _ in true })
        let hookYes = try XCTUnwrap(yes.config.authorize?.isRevoked)
        XCTAssertEqual(try hookYes(g, g), true, "Protect.swift line 45: the caller's isRevoked decides")
        let no = protect(audience: "a", operation: { _ in nil }, isRevoked: { _, _ in false })
        let hookNo = try XCTUnwrap(no.config.authorize?.isRevoked)
        XCTAssertEqual(try hookNo(g, g), false)
        no.revoke("g1")
        XCTAssertEqual(try hookNo(g, g), true, "a revoked id wins over the caller's hook")
        let none = protect(audience: "a", operation: { _ in nil })
        let hookNone = try XCTUnwrap(none.config.authorize?.isRevoked)
        XCTAssertEqual(try hookNone(g, g), false)
    }

    func testSigstoreOffsetChecksBothHourDigits() {
        // t = "+0::00": the first hour digit is a digit, the second is ':' (so the hour would read 10 if it were not checked)
        XCTAssertNil(Sigstore.isoMs("1970-01-01T00:00:00+0::00"), "Sigstore.swift line 70: t[1..<3] are both digits")
        XCTAssertEqual(Sigstore.isoMs("1970-01-01T00:00:00+00:00"), Int64(0))
    }

    func testCompareVersionTreatsFractionalDifferenceAsPositive() {
        // Number("1e-1") is 0.1: d = 0.1 is greater than 0 (a threshold of 1 instead of 0 would call it smaller)
        XCTAssertEqual(K3.compareVersion("1e-1", "0"), 1, "K3.swift line 47")
        XCTAssertEqual(K3.compareVersion("0", "1e-1"), -1)
        XCTAssertEqual(K3.compareVersion("0.5", "0.4"), 1)
    }

    func testBlueprintRegistryTakesItsLockOncePerCall() {
        let st = Blueprint.MemoryStore()
        let reg = Blueprint.Registry(operators: ["o"], store: st)
        S2LK.check(reg.lock, "accept") { _ = reg.accept(nil) }
        S2LK.check(st.lock, "epoch") { _ = reg.epoch }
        S2LK.check(st.lock, "get") { _ = try? reg.get("k") }
    }
}
