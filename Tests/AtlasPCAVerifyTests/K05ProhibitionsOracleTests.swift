import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of Prohibitions.swift against the TS reference (prohibitions.ts): test-data/k05-prohibitions.json.gz (constitution and
/// state validation, the monitor grids around every boundary, advance, evidence, signed evidence, check-and-advance). Verdicts are
/// compared as {ok, reason?}; a reference throw requires a native refusal.
final class K05ProhibitionsOracleTests: XCTestCase {
    static let file = "k05-prohibitions.json.gz"
    static let covers = ["Prohibitions"]

    static func key(_ v: JSONValue?) throws -> PCAEdKey {
        guard let s = v?.asString, let b = Base64URLStrict.decode(s) else { throw PDFail(what: "bad seed") }
        return try PCAEdKey(seed: b)
    }

    static func verdict(_ v: ProhibitionVerdict) -> JSONValue { v.json }
    static func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
    static func opt(_ s: String?) -> JSONValue { s.map { .string($0) } ?? .null }

    /// The optional 4th argument of the reference: absent = nil; present but not a number (null: a clock regression / stale head) = NaN.
    static func optNum(_ v: JSONValue?) -> Double? {
        guard let v = v else { return nil }
        if case .null = v { return .nan }
        return IV.num(v) ?? .nan
    }

    static func transition(_ ok: Bool, _ state: JSONValue?, _ reason: String?) -> JSONValue {
        ok ? .object(["ok": .bool(true), "state": state ?? .null]) : .object(["ok": .bool(false), "reason": .string(reason ?? "")])
    }

    static func call(_ c: K05Case) -> K05Got {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
        switch c.fn {
        case "validateInvariant": return .value(strs(Prohibitions.validateInvariant(a0)))
        case "validateConstitution": return .value(strs(Prohibitions.validateConstitution(a0)))
        case "stateProblem": return .value(opt(Prohibitions.stateProblem(a0)))
        case "canonicalState": return K05.run({ _ in nil }) { try Prohibitions.canonicalState(a0) }
        case "stateDigest": return K05.run({ _ in nil }) { .string(try Prohibitions.stateDigest(a0)) }
        case "tickState":
            let t = Prohibitions.tickState(a0, now: IV.num(a1) ?? .nan)
            return .value(transition(t.ok, t.state, t.reason))
        case "emptyState":
            // the reference keeps any `now` it is given: a number goes through the Double API, anything else is stored as is
            if let n = IV.num(a0) { return .value(Prohibitions.emptyState(n)) }
            return .value(Prohibitions.emptyState(rawNow: a0 ?? .null))
        case "checkProhibitions": return .value(Prohibitions.checkProhibitions(a0, a1, a2).json)
        case "advanceStateStrict":
            let r = Prohibitions.advanceStateStrict(a0, a1, a2, now: optNum(a3))
            return .value(transition(r.ok, r.state, r.reason))
        case "proveSafety": return .value(Prohibitions.proveSafety(a0, a1, a2))
        case "verifySafetyEvidence": return .value(verdict(Prohibitions.verifySafetyEvidence(a0, a1, a2, a3)))
        case "safetyBindingId": return K05.run({ _ in nil }) { .string(try Prohibitions.safetyBindingId(a0 ?? .null, signer: a1?.asString ?? "")) }
        case "signSafetyEvidence": return signCase(c, a0, a1, c.arg(2))
        case "verifySignedSafetyEvidence": return .value(verdict(Prohibitions.verifySignedSafetyEvidence(a0, a1)))
        case "checkAndAdvance":
            let o = c.arg(4)
            let r = Prohibitions.checkAndAdvance(permitted: a0 == .bool(true), a1, a2, a3, expectedSeq: optNum(o?.get("expectedSeq")),
                                                 expectedStateDigest: o?.get("expectedStateDigest")?.asString)
            var out: JObject = ["allow": .bool(r.allow), "decidedBy": .string(r.decidedBy), "evidence": r.evidence, "prohibition": r.prohibition.json, "next": r.next]
            if let why = r.reason, !why.isEmpty { out["reason"] = .string(why) }
            return .value(.object(out))
        case "verifyConstitution": return .value(verdict(Prohibitions.verifyConstitution(a0, expectedPrincipal: a1?.asString)))
        case "constitutionId": return K05.run({ _ in nil }) { .string(try Prohibitions.constitutionId(a0 ?? .null)) }
        case "whenAffirmative": return .value(.bool(Prohibitions.whenAffirmative(a0, a1)))
        default: return .threw("unknown fn \(c.fn)")
        }
    }

    /// The reference takes (evidence, secret, public) and a signer that is not a non-empty string is refused. Apple's CryptoKit signs Ed25519
    /// with a random nonce, so there everything but `sig` is compared exactly and the sig is verified over the exact signed bytes.
    static func signCase(_ c: K05Case, _ ev: JSONValue?, _ secret: JSONValue?, _ pub: JSONValue?) -> K05Got {
        let got = K05.run({ _ in nil }) {
            try Prohibitions.signSafetyEvidence(ev ?? .null, signer: try key(secret), signerPublic: pub?.asString ?? "")
        }
        #if os(Linux)
        return got
        #else
        guard case let .value(g) = got, !c.threw, case let .object(want) = c.out, let wantSig = want[JKey("sig")]?.asString, case let .object(go) = g,
              let gotSig = go[JKey("sig")]?.asString, let id = go[JKey("id")]?.asString, let signer = go[JKey("signer")]?.asString else { return got }
        var a = want, b = go
        a[JKey("sig")] = nil
        b[JKey("sig")] = nil
        guard K05.canon(.object(a)) == K05.canon(.object(b)) else { return got }
        // verify under the key that actually signed (in the mismatched-pair case the claimed signer is deliberately another key)
        guard let signingKey = try? key(secret), !signer.isEmpty,
              Ed25519Strict.verifyB64u(Base64URLStrict.encode(signingKey.pub), PD.domainMessage(Prohibitions.SAFETY_EVIDENCE_SIG_DOMAIN, id), gotSig), !wantSig.isEmpty else { return .threw("bad signature") }
        return .value(c.out)
        #endif
    }

    func replay(_ fns: Set<String>, min: Int) throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, fns) { c in d.add(c, K05.diff(c, Self.call(c))) }
        d.finish(min)
    }

    func testValidation() throws { try replay(["validateInvariant", "validateConstitution", "stateProblem"], min: 2500) }
    func testStateCanonicalForms() throws { try replay(["canonicalState", "stateDigest", "tickState", "emptyState"], min: 450) }
    func testMonitor() throws { try replay(["checkProhibitions", "whenAffirmative"], min: 4000) }
    func testAdvance() throws { try replay(["advanceStateStrict"], min: 2800) }
    func testEvidence() throws { try replay(["proveSafety", "verifySafetyEvidence", "safetyBindingId", "signSafetyEvidence"], min: 1500) }
    func testSignedEvidenceAndConstitution() throws { try replay(["verifySignedSafetyEvidence", "verifyConstitution", "constitutionId"], min: 2500) }
    func testCheckAndAdvance() throws { try replay(["checkAndAdvance"], min: 900) }
}
