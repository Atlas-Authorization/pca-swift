import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the Passport.swift survivors of group 2. Pinned to packages/pca/src/passport.ts (:298 times, skew clamp, evidence age).
final class S2G2PassportKillTests: XCTestCase {
    private typealias P = PassportConformanceTests
    private static let NOW = PassportConformanceTests.NOW
    private static let MAX: Int64 = 9_007_199_254_740_991
    private static let DAY: Int64 = 86_400_000

    private func sign(_ passport: JObject, iat iatOpt: Int64? = nil, nbf nbfOpt: Int64? = nil, exp expOpt: Int64? = nil, evidence: JSONValue? = nil) -> JSONValue {
        let iat: Int64 = iatOpt ?? (Self.NOW - 1_000)
        let nbf: Int64 = nbfOpt ?? (Self.NOW - 1_000)
        let exp: Int64 = expOpt ?? (Self.NOW + 60_000)
        let key = P.issuer
        var body: JObject = ["typ": .string("atlas-pca/passport"), "ver": .int(1), "passport": .object(passport), "iss": .string(V2F.pub(key)),
                             "sub": .string(V2F.pub(P.agent)), "iat": .int(iat), "nbf": .int(nbf), "exp": .int(exp)]
        if let e = evidence { body["evidence"] = e }
        body["sig"] = .string(V2F.sign(key, IV.message(PCA.PASSPORT_SIG_DOMAIN, .object(body))!))
        return .object(body)
    }

    private func opts(now nowOpt: Int64? = nil, skew: Int64? = nil, maxAge: Int64? = nil, trusted: Bool = true) -> PassportOptions {
        var o = PassportOptions(trustedIssuers: trusted ? [V2F.pub(P.issuer)] : [], nowMs: nowOpt ?? Self.NOW, revoked: { _, _, _ in false })
        o.clockSkewMs = skew
        o.maxEvidenceAgeMs = maxAge
        return o
    }

    func testFailureVerdictCarriesNothing() {
        let v = PCA.verifyPassport(nil, opts())
        XCTAssertFalse(v.ok)
        XCTAssertEqual(v.reason, "malformed")
        XCTAssertFalse(v.hardwareVerified, "line 84: a refusal is never hardware verified")
        XCTAssertEqual(v.exp, 0, "line 84: a refusal carries exp 0")
        XCTAssertEqual(v.iss, "")
        XCTAssertEqual(v.sub, "")
        XCTAssertNil(v.passport)
        XCTAssertNil(v.detail)
    }

    func testTimeFieldBoundaries() {
        let p = P.passport()
        // untrusted issuer: reaching "unknown_issuer" means the times check passed
        func reason(_ sp: JSONValue, now: Int64? = nil) -> String { PCA.verifyPassport(sp, opts(now: now, trusted: false)).reason }
        XCTAssertEqual(reason(sign(p, iat: -Self.MAX)), "unknown_issuer", "line 125: iat == -MAX_SAFE is a safe integer")
        XCTAssertEqual(reason(sign(p), now: Self.MAX), "unknown_issuer", "line 126: now == MAX_SAFE is a safe integer")
        XCTAssertEqual(reason(sign(p), now: -Self.MAX), "unknown_issuer", "line 126: now == -MAX_SAFE is a safe integer")
        let same = PCA.verifyPassport(sign(p, nbf: Self.NOW, exp: Self.NOW), opts(trusted: false))
        XCTAssertEqual(same.reason, "malformed", "line 126: exp == nbf is refused")
        XCTAssertEqual(same.detail, "times")
        let before = PCA.verifyPassport(sign(p, nbf: Self.NOW, exp: Self.NOW - 1), opts(trusted: false))
        XCTAssertEqual(before.detail, "times")
        XCTAssertEqual(reason(sign(p, nbf: Self.NOW, exp: Self.NOW + 1)), "unknown_issuer")
    }

    func testSkewIsClampedToSixtySeconds() {
        let p = P.passport()
        // a huge declared skew counts as exactly 60000 ms (line 91)
        let atEdge = sign(p, nbf: Self.NOW + 60_000, exp: Self.NOW + 200_000)
        XCTAssertEqual(PCA.verifyPassport(atEdge, opts(skew: 10_000_000)).reason, "", "nbf exactly 60000 ahead is within the clamped skew")
        let past = sign(p, nbf: Self.NOW + 60_001, exp: Self.NOW + 200_000)
        XCTAssertEqual(PCA.verifyPassport(past, opts(skew: 10_000_000)).reason, "not_yet_valid", "nbf 60001 ahead is beyond the clamped skew")
        // a negative skew counts as 0
        let ahead = sign(p, nbf: Self.NOW + 1, exp: Self.NOW + 200_000)
        XCTAssertEqual(PCA.verifyPassport(ahead, opts(skew: -5)).reason, "not_yet_valid")
    }

    func testExpiryUsesTheSkewAsTolerance() {
        let sp = sign(P.passport())
        let exp = Self.NOW + 60_000
        // with a 100 ms skew, 50 ms before exp is alive and 100 ms after exp is expired (exp - skew... now - skew >= exp)
        XCTAssertEqual(PCA.verifyPassport(sp, opts(now: exp - 50, skew: 100)).reason, "", "line 133: now - skew, not now + skew")
        XCTAssertEqual(PCA.verifyPassport(sp, opts(now: exp + 99, skew: 100)).reason, "")
        XCTAssertEqual(PCA.verifyPassport(sp, opts(now: exp + 100, skew: 100)).reason, "expired")
    }

    // ---- hardware evidence age ----

    private func evidence(at: Int64) -> JSONValue { .object(["document": .object(["nonce": .string("n-1")]), "at": .int(at)]) }

    private func run(at: Int64, skew: Int64? = nil, maxAge: Int64? = nil) -> String {
        let hwp = P.passport(hardware: true)
        var o = opts(skew: skew, maxAge: maxAge)
        o.attest = { _, _ in PassportAttestation(ok: true, bound: true, measured: ["model_id": .string("m1"), "operator": .string("acme")]) }
        return PCA.verifyPassport(sign(hwp, evidence: evidence(at: at)), o).reason
    }

    func testEvidenceAgeBoundaries() {
        let n = Self.NOW
        XCTAssertEqual(run(at: n, maxAge: 0), "", "line 147: a zero max age admits evidence taken now (maxAge < 0, not <= 0 / < 1)")
        XCTAssertEqual(run(at: n - 1, maxAge: 0), "hardware_evidence_stale")
        XCTAssertEqual(run(at: n - 1_000, maxAge: 1_000), "", "line 147: age == maxAge is fresh (> not >=)")
        XCTAssertEqual(run(at: n - 1_001, maxAge: 1_000), "hardware_evidence_stale")
        XCTAssertEqual(run(at: n + 100, skew: 100), "", "line 147: evidence exactly skew in the future is fine (> not >=)")
        XCTAssertEqual(run(at: n + 101, skew: 100), "hardware_evidence_stale")
        XCTAssertEqual(run(at: n, maxAge: -1), "hardware_evidence_stale", "a negative max age refuses everything")
    }

    func testDefaultEvidenceAgeIsTwentyFourHours() {
        let n = Self.NOW
        XCTAssertEqual(PCA.DEFAULT_PASSPORT_EVIDENCE_AGE_MS, 86_400_000, "line 93")
        XCTAssertEqual(run(at: n - Self.DAY), "", "line 93: exactly 24 h old is fresh")
        XCTAssertEqual(run(at: n - Self.DAY - 1), "hardware_evidence_stale", "line 93: one ms older is stale")
        XCTAssertEqual(run(at: n - Self.DAY + 1), "")
    }
}
