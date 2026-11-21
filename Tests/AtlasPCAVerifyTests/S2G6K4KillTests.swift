import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kill tests (mutation sheet swift-k05 group 6) for K4.swift: the PAN heuristic, token reference characters, the pricing config,
/// the risk decision, answer nonces and the ERC-7715 granted-permission check.
final class S2G6K4KillTests: XCTestCase {
    // ---------------------------------------------------------------- looksLikePan (lines 30, 41, 42)

    func testLooksLikePanDigitsAndLuhn() {
        let p = "4291417776317063" // Luhn-valid; contains 0 and 9
        XCTAssertTrue(K4.looksLikePan(p), "line 42 digits 0 and 9 are digits")
        XCTAssertTrue(K4.looksLikePan("5555555555554444"), "line 30 a doubled 5 is 10 and loses 9")
        XCTAssertFalse(K4.looksLikePan("5555555555554445"), "a failing check digit")
        XCTAssertTrue(K4.looksLikePan(p + "x"), "line 42 a non-digit ends a run that is a PAN")
        XCTAssertTrue(K4.looksLikePan(p + ":"), "line 42 ':' is not a digit")
        XCTAssertTrue(K4.looksLikePan(p + "/"), "line 42 '/' is not a digit")
        XCTAssertFalse(K4.looksLikePan("42055526/67869819"), "line 42 '/' is not a digit (it would make a 17-element Luhn-valid run)")
    }

    func testLooksLikePanSeparators() {
        let p = "4291417776317063"
        let a = String(p.prefix(8)), b = String(p.dropFirst(8))
        for sep in ["-", " ", "\t", "\n", "\u{0b}", "\u{0c}", "\r"] {
            XCTAssertTrue(K4.looksLikePan(a + sep + b), "line 41 separator U+\(sep.unicodeScalars.first!.value) is skipped")
        }
        for sep in ["!", "\u{1f}", "\u{08}", "\u{0e}", "."] {
            XCTAssertFalse(K4.looksLikePan(a + sep + b), "line 41 U+\(sep.unicodeScalars.first!.value) is not a separator")
        }
    }

    // ---------------------------------------------------------------- tokenRefError (line 49)

    func testTokenRefAlphabet() {
        for c in ["0", "9", "A", "Z", "a", "z", "_", ".", ":", "-"] {
            XCTAssertNil(K4.tokenRefError(.string("AAAAAAA" + c)), "line 49 '\(c)' is allowed")
        }
        for c in ["/", ";", "@", "[", "`", "{", "!", " ", "+", "~"] {
            XCTAssertEqual(K4.tokenRefError(.string("AAAAAAA" + c)), "token_ref_malformed", "line 49 '\(c)' is not allowed")
        }
        XCTAssertEqual(K4.tokenRefError(.string("AAAAAAA")), "token_ref_malformed")
    }

    // ---------------------------------------------------------------- pricing config and decision (lines 73-94)

    private static let key = V2F.key("s2g6-k4-principal")

    private static func config(cost: Int64 = 100, max: Int64 = 1000, ceiling: Int64 = 100_000, step: Int64 = 500_000, tamper: Bool = false) -> JSONValue {
        var body: JObject = ["v": .int(1), "principal": .string(V2F.pub(key)), "currency": .string("USD"), "interruptionCost": .int(cost),
                             "maxInterruptionCost": .int(max), "hardCeilingLoss": .int(ceiling), "epoch": .int(1), "tightenStepPpm": .int(step)]
        let digest = IV.strictHash(.object(["kind": .string("pca.escalation_pricing"), "body": .object(body)]))!
        body["sig"] = .string(V2F.sign(key, Array((tamper ? digest + "x" : digest).utf8)))
        return .object(body)
    }

    func testPricingConfigBoundaries() {
        XCTAssertNil(K4.pricingConfigError(Self.config()), "control")
        XCTAssertNil(K4.pricingConfigError(Self.config(cost: 1000, max: 1000)), "line 73 a cost equal to the maximum is allowed")
        XCTAssertEqual(K4.pricingConfigError(Self.config(cost: 1001, max: 1000)), "config_cost_above_max")
        XCTAssertNil(K4.pricingConfigError(Self.config(step: 0)), "line 74 a zero tighten step is allowed")
        XCTAssertNil(K4.pricingConfigError(Self.config(step: K4.MAX_MULTIPLIER_PPM)))
        XCTAssertEqual(K4.pricingConfigError(Self.config(step: K4.MAX_MULTIPLIER_PPM + 1)), "config_step_invalid")
        XCTAssertEqual(K4.pricingConfigError(Self.config(tamper: true)), "config_signature_invalid")
    }

    private static let risk: JSONValue = .object(["currency": .string("USD"), "loss": .int(1), "pBadUpperPpm": .int(K4.PPM)])
    private static let cal: JSONValue = .object(["multiplierPpm": .int(K4.PPM)])

    func testDecideRefusesAnInvalidConfig() {
        let v = K4.decide(config: Self.config(tamper: true), calibration: Self.cal, risk: Self.risk)
        XCTAssertEqual(v, K4.Verdict(ask: true, reason: "config_signature_invalid"), "line 84")
        XCTAssertEqual(K4.decide(config: nil, calibration: Self.cal, risk: Self.risk).reason, "config_malformed")
    }

    func testDecideTieDoesNotAsk() {
        // capped = 1e12 and loss == interruptionCost: both products are equal, so the expected loss does not exceed the cost
        let risk: JSONValue = .object(["currency": .string("USD"), "loss": .int(100), "pBadUpperPpm": .int(K4.PPM)])
        let v = K4.decide(config: Self.config(cost: 100), calibration: Self.cal, risk: risk)
        XCTAssertEqual(v, K4.Verdict(ask: false, reason: "expected_loss_within_interruption_cost"), "line 94 equal low words")
        let more: JSONValue = .object(["currency": .string("USD"), "loss": .int(101), "pBadUpperPpm": .int(K4.PPM)])
        XCTAssertEqual(K4.decide(config: Self.config(cost: 100), calibration: Self.cal, risk: more).reason, "expected_loss_exceeds_interruption_cost")
    }

    // ---------------------------------------------------------------- answer nonce length (line 100)

    private static func answer(_ nonce: String) -> JSONValue {
        var body: JObject = ["v": .int(1), "principal": .string(V2F.pub(key)), "nonce": .string(nonce), "action_digest": .string("d"), "answer": .string("approve")]
        let digest = IV.strictHash(.object(["kind": .string("pca.escalation_answer"), "body": .object(body)]))!
        body["sig"] = .string(V2F.sign(key, Array(digest.utf8)))
        return .object(body)
    }

    func testAnswerNonceMustBeEightCharacters() {
        func seen(_ nonce: String) -> [String] {
            K4.updateCalibration(config: Self.config(), mult: K4.PPM, seen: [], answers: [Self.answer(nonce)], risks: [:]).seen
        }
        XCTAssertEqual(seen("abcdefgh"), ["abcdefgh"], "line 100 eight characters are enough")
        XCTAssertEqual(seen("abcdefghi"), ["abcdefghi"])
        XCTAssertEqual(seen("abcdefg"), [], "line 100 seven characters are not")
    }

    // ---------------------------------------------------------------- verifyGranted (lines 135-160)

    private static let mgr = "0x" + String(repeating: "a", count: 40)

    private static func perm(_ allowance: String) -> JSONValue {
        .object(["type": .string("native-token-allowance"), "data": .object(["tokenAddress": .string("0xt"), "allowance": .string(allowance)]),
                 "isAdjustmentAllowed": .bool(false)])
    }

    private func granted(ctx: String = "0x1234", mgr: String = S2G6K4KillTests.mgr, allowance: String = "0x10", gotFrom: JSONValue = .string("0xdef"),
                         sentFrom: JSONValue = .string("0xdef"), expiry: Int64 = 900, grant: JSONValue? = nil) -> String? {
        let sent: JSONValue = .object(["chainId": .string("0x1"), "to": .string("0xabc"), "from": sentFrom, "permission": Self.perm("0x10")])
        let got: JSONValue = .object(["context": .string(ctx), "delegationManager": .string(mgr), "chainId": .string("0x1"), "to": .string("0xabc"),
                                      "from": gotFrom, "permission": Self.perm(allowance),
                                      "rules": .array([.object(["type": .string("expiry"), "data": .object(["timestamp": .int(expiry)])])])])
        let g: JSONValue = grant ?? .object(["grantDigest": .string("gd"), "expiresAtSec": .int(1000)])
        return K4.verifyGranted(g: g, sent: sent, got: got, allowedManagers: [mgr], contextOwner: nil)
    }

    func testGrantedBaseline() {
        XCTAssertNil(granted(), "control: an equal allowance, before the expiry")
    }

    func testContextHexAlphabet() {
        for c in ["0", "9", "A", "F", "a", "f"] { XCTAssertNil(granted(ctx: "0x" + c), "line 14 '\(c)' is hex") }
        for c in ["/", ":", "@", "G", "`", "g", "-", " "] { XCTAssertEqual(granted(ctx: "0x" + c), "context_malformed", "line 14 '\(c)' is not hex") }
        XCTAssertEqual(granted(ctx: "0x"), "context_malformed", "line 14 an empty hex string")
        XCTAssertEqual(granted(ctx: "0xG1"), "context_malformed", "line 135 the third character is checked")
        XCTAssertNil(granted(ctx: "0x1"), "line 135 a one-digit context")
        XCTAssertEqual(granted(ctx: "1234"), "context_malformed")
    }

    func testManagerHexAlphabet() {
        let tail = String(repeating: "a", count: 39)
        for c in ["0", "9", "A", "F", "a", "f"] { XCTAssertNil(granted(mgr: "0x" + c + tail), "line 137 '\(c)'") }
        XCTAssertEqual(granted(mgr: "0xG" + tail), "delegation_manager_not_allowed", "line 137 the third character is checked")
        XCTAssertEqual(granted(mgr: "0x/" + tail), "delegation_manager_not_allowed")
        XCTAssertEqual(granted(mgr: "0xg" + tail), "delegation_manager_not_allowed")
        XCTAssertEqual(granted(mgr: "0xa" + String(repeating: "a", count: 38)), "delegation_manager_not_allowed", "a short manager")
    }

    func testFromIsCheckedOnlyWhenSentNamesOne() {
        XCTAssertEqual(granted(gotFrom: .string("0xother")), "from_mismatch", "line 141")
        XCTAssertNil(granted(gotFrom: .string("0xother"), sentFrom: .null), "line 141 a null from is not compared")
    }

    func testAllowanceDigits() {
        XCTAssertNil(granted(allowance: "0x0"), "line 148 the allowance zero")
        XCTAssertEqual(granted(allowance: "0x01"), "amount_malformed", "line 148 a leading zero")
        XCTAssertEqual(granted(allowance: "0x00"), "amount_malformed")
        XCTAssertEqual(granted(allowance: "0x11"), "amount_widened")
        XCTAssertEqual(granted(allowance: "0x100"), "amount_widened")
        XCTAssertNil(granted(allowance: "0xf"), "a shorter hex quantity is smaller")
    }

    func testExpiryAgainstAGrantWithoutOne() {
        XCTAssertEqual(granted(expiry: 1, grant: .object(["grantDigest": .string("gd")])), "expiry_extended", "line 160 a missing grant expiry is 0")
        XCTAssertNil(granted(expiry: 0, grant: .object(["grantDigest": .string("gd")])))
        XCTAssertEqual(granted(expiry: 1001), "expiry_extended")
        XCTAssertNil(granted(expiry: 1000))
    }
}
