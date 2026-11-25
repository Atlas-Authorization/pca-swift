import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kill tests for the platform-deterministic decay, the number-type check in the no-widen guard, the unrepresentable-time refusals and the
/// bond power curve (exactly rounded operations only).
final class ClockContractKillTests: XCTestCase {
    func testDecayExactFactorBits() {
        let h = 3_600_000.0, step = 0.9993233275026507
        func prod(_ k: Int, _ m: Int) -> Double { var f = 1.0; for _ in 0..<k { f *= 0.5 }; for _ in 0..<m { f *= step }; return f }
        XCTAssertEqual(PCAImmune.decay(1, h, h).bitPattern, 0.5.bitPattern)
        XCTAssertEqual(PCAImmune.decay(1, h / 1024, h).bitPattern, step.bitPattern)
        XCTAssertEqual(PCAImmune.decay(1, 2.5 * h, h).bitPattern, prod(2, 512).bitPattern)
        XCTAssertEqual(PCAImmune.decay(1, 0.3 * h, h).bitPattern, prod(0, 307).bitPattern)
        XCTAssertEqual(PCAImmune.decay(8, 0, h), 8)
    }

    func testNoWidenRefusesNonNumberKappaTheta() {
        let base: JObject = ["kappa": .int(1), "theta1": .int(2), "theta2": .int(2), "lambda": .int(1), "rho": .int(1), "bMax": .int(1), "weights": .object([:])]
        XCTAssertNil(PCAImmune.noWidenViolation(base, base))
        for field in ["kappa", "theta1", "theta2"] {
            for bad in [JSONValue.null, .bool(true), .bool(false), .string("5")] {
                var a = base; a[JKey(field)] = bad
                XCTAssertNotNil(PCAImmune.noWidenViolation(base, a), "\(field) \(bad)")
            }
        }
    }

    func testSdJwtRefusesUnrepresentableNow() {
        for n in [1e300, -1e300, Double.nan, Double.infinity, -Double.infinity] {
            var o = PCASdJwt.VerifyOptions(issuerKey: .ed25519([UInt8](repeating: 1, count: 32)))
            o.nowMs = n
            let r = PCASdJwt.verifyPcaSdJwt("a.b.c~", o)
            XCTAssertEqual(r.get("ok"), .bool(false))
            XCTAssertTrue((r.get("reason")?.asString ?? "").contains("now is not a representable time"), "\(n)")
        }
    }

    func testReceiveSetRefusesUnrepresentableNow() throws {
        let set = try PCASignals.buildSET(.object(["events": .object([JKey(PCASignals.EV_GRANT_REVOKED): .object(["grant_ref": .string("g1"), "event_timestamp": .int(1)])]),
                                                  "issuer": .string("https://tx.example"), "audience": .string("rx")]), key: RefSignalsTests.k1)
        for n in [1e300, -1e300, Double.nan, Double.infinity] {
            let opts: JSONValue = .object(["issuer": .string("https://tx.example"), "audience": .string("rx"), "maxAgeSec": .int(300), "nowSec": .double(n)])
            let st = PCASignals.createRevocationState()
            let r = PCASignals.receiveSET(.string(set), key: RefSignalsTests.k1Pub, opts: opts, store: try PCASignals.createInMemorySetReplayStore(), state: st)
            XCTAssertEqual(r.get("ok"), .bool(false), "\(n)")
            XCTAssertEqual(r.get("reason"), .string("now is not a representable time"), "\(n)")
            XCTAssertFalse(PCASignals.isRevoked(st, "g1"))
        }
    }

    func testBondPowerCurveEighths() throws {
        func bond(_ g: Double, _ e: Double) throws -> Double {
            var p = PCAIntentBond.BondPolicy(); p.floor = 0; p.k = 1; p.curveKind = "power"; p.gamma = g
            return try PCAIntentBond.bondAmount(p, e)
        }
        XCTAssertEqual(try bond(2, 3), 9)
        XCTAssertEqual(try bond(1.5, 4), 8)
        XCTAssertEqual(try bond(1.125, 16), PCAIntentBond.quantizeUp(16 * 16.0.squareRoot().squareRoot().squareRoot()))
        for g in [1.1, 64.125, 65, Double.infinity] { XCTAssertThrowsError(try bond(g, 2), "\(g)") }
        XCTAssertEqual(try bond(64, 1), 1)
    }

    /// A KB-JWT whose payload text is written by hand and signed with the holder key.
    private func kbPresentation(iatLiteral: String) throws -> (sd: String, opts: PCASdJwt.VerifyOptions) {
        let issuerSeed = [UInt8](repeating: 1, count: 32), holderSeed = [UInt8](repeating: 2, count: 32)
        var io = PCASdJwt.IssueOptions(issuerSeed: issuerSeed)
        io.keyBinding = true
        io.holderPublicKey = .raw(try Ed25519Deterministic.key(seed: holderSeed).pub)
        let pc: JSONValue = .object(["cap_chain": .array([.object(["issuer": .string("did:ex:i"), "holder": .string("did:ex:h")])]),
                                     "aud": .string("rx"), "iat": .int(1_700_000_000_000), "exp": .int(1_700_003_600_000)])
        let head = try PCASdJwt.present(try PCASdJwt.issuePcaSdJwt(pc, io), [])
        let b64 = { (t: String) in Base64URLStrict.encode(Array(t.utf8)) }
        let input = b64("{\"alg\":\"EdDSA\",\"typ\":\"kb+jwt\"}") + "." + b64("{\"iat\":\(iatLiteral),\"aud\":\"rx\",\"sd_hash\":\"\(PCASdJwt.sha(head))\"}")
        let kb = input + "." + Base64URLStrict.encode(try Ed25519Deterministic.sign(seed: holderSeed, Array(input.utf8)))
        var o = PCASdJwt.VerifyOptions(issuerKey: .ed25519(try Ed25519Deterministic.key(seed: issuerSeed).pub))
        o.nowMs = 1_700_000_100_000
        o.kbMaxAgeSec = 300
        return (head + kb, o)
    }

    func testKbJwtIatOverflowLiteralIsRefused() throws {
        // control: the same construction with a finite iat verifies, so the refusals below are caused by the iat alone
        let ok = try kbPresentation(iatLiteral: "1700000100")
        XCTAssertEqual(PCASdJwt.verifyPcaSdJwt(ok.sd, ok.opts).get("ok"), .bool(true))
        // the lenient parser turns 1e999 into +Infinity (it does not throw); the strict parser used for JWS segments refuses an exponent literal (the whole presentation is refused as a non-canonical JWS)
        XCTAssertEqual(try StrictJSON.parseLenient("1e999"), .double(.infinity))
        XCTAssertEqual(try StrictJSON.parseLenient("-1e999"), .double(-.infinity))
        for lit in ["1e999", "-1e999"] {
            let t = try kbPresentation(iatLiteral: lit)
            let r = PCASdJwt.verifyPcaSdJwt(t.sd, t.opts)
            XCTAssertEqual(r.get("ok"), .bool(false), lit)
            XCTAssertTrue((r.get("reason")?.asString ?? "").contains("exponent form is not allowed"), "\(lit): \(String(describing: r.get("reason")))")
        }
    }
}
