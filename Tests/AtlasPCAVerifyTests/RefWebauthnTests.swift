import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAWebauthn against the reference (@atlasauth/pca-webauthn). Bytes cross as {"$bytes"}; a JS-typed hostile
/// expectation maps to the value the reference ends up comparing (a non-string rpId is empty, a null storedSignCount is NaN, a
/// non-string origin matches no origin) or, where a typed parameter cannot hold it, a skip. The reasons the reference ends with the JS
/// engine's message are cut at the colon, as the reference runner cuts them.
final class RefWebauthnTests: XCTestCase {
    static let file = "ref-webauthn.json.gz"
    struct Skip: Error { let why: String }
    static let NEVER = "\u{0}non-string" // never equal to a string the reference compares against

    /// A step-up input as the reference reads it: bytes, a string, an object; an array destructures to its indices, another primitive to
    /// nothing; null throws.
    static func stepIn(_ v: JSONValue?) throws -> PCAWebauthn.StepUpInput {
        if let b = Base.bytes(v) { return .digest(b) }
        switch v {
        case nil, .null?: throw JSError("Cannot destructure property 'sig' of 'p' as it is null.")
        case let .string(s)?: return .b64u(s)
        case let .object(o)?: return .actn(o)
        case let .array(a)?:
            var m: JObject = [:]
            for (i, x) in a.enumerated() { m[JKey(String(i))] = x }
            return .actn(m)
        default: return .actn([:])
        }
    }

    static func payExp(_ v: JSONValue?) throws -> PCAWebauthn.PaymentExpectation {
        guard let m = v?.asObject else { throw JSError("payment expectation is not an object") }
        guard let t = m["total"]?.asObject else { throw JSError("Cannot read properties of undefined (reading 'currency')") }
        guard let top = m["topOrigin"]?.asString else {
            throw Skip(why: "an expectation without topOrigin: the typed native requires it, the reference compares against undefined")
        }
        var e = PCAWebauthn.PaymentExpectation(topOrigin: top, currency: t["currency"]?.asString ?? NEVER, value: t["value"]?.asString ?? NEVER)
        if let x = m["payeeName"] { e.payeeName = x.asString ?? NEVER }
        if let x = m["payeeOrigin"] { e.payeeOrigin = x.asString ?? NEVER }
        return e
    }

    static func verify(_ a: JSONValue?, _ ev: JSONValue?) throws -> JSONValue {
        let am = Ref.obj(a), em = Ref.obj(ev)
        let pk: PCAWebauthn.PublicKey? = Base.bytes(am["publicKey"]).map { .cose($0) } ?? am["publicKey"].map { .jwk($0) }
        let assertion = PCAWebauthn.Assertion(authenticatorData: Base.bytes(am["authenticatorData"]), clientDataJSON: Base.bytes(am["clientDataJSON"]),
                                              signature: Base.bytes(am["signature"]), publicKey: pk)
        let ch: PCAWebauthn.Challenge? = Base.bytes(em["expectedChallenge"]).map { .bytes($0) } ?? em["expectedChallenge"]?.asString.map { .b64u($0) }
        var stored: Double? = nil
        if let x = em["storedSignCount"] { stored = x.isNumber ? IV.num(x) : .nan }
        var e = PCAWebauthn.Expectations(expectedChallenge: ch, rpId: em["rpId"]?.asString ?? "",
                                         origins: (em["origins"]?.asArray ?? []).map { $0.asString ?? NEVER }, storedSignCount: stored)
        e.requireUV = JS.truthy(em["requireUV"])
        e.requireLowS = em["requireLowS"] == .bool(true)
        e.rejectCrossOrigin = em["rejectCrossOrigin"] != .bool(false)
        if let x = em["payment"] {
            if x == .null { throw Skip(why: "a null payment expectation is not expressible (the reference fails closed reading it)") }
            do { e.payment = try payExp(x) } catch let s as Skip { throw s } catch {
                throw Skip(why: "a malformed payment expectation is not expressible (the reference fails closed reading it)")
            }
        }
        var calls: [JSONValue] = []
        if em["hook"] == .bool(true) {
            e.onSignCountRegression = { st, rep in calls.append(.object(["storedSignCount": PCASdJwt.jnum(st), "reportedSignCount": PCASdJwt.jnum(rep)])) }
        }
        var r = PCAWebauthn.verifyAssertion(assertion, e).json
        if case var .object(o) = r, let reason = o["reason"]?.asString {
            for p in ["public key could not be resolved", "verification error (fail closed)"] where reason.hasPrefix(p + ":") { o["reason"] = .string(p) }
            r = .object(o)
        }
        return .object(["result": r, "hook": .array(calls)])
    }

    func testWebauthn() throws {
        try K042.requireCovers(["Webauthn"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            var got: BaseGot
            do {
                switch c.fn {
                case "constants":
                    got = .value(.object(["MAX_AUTHENTICATOR_DATA_BYTES": .int(Int64(PCAWebauthn.MAX_AUTHENTICATOR_DATA_BYTES)),
                                          "MAX_CLIENT_DATA_BYTES": .int(Int64(PCAWebauthn.MAX_CLIENT_DATA_BYTES)), "MAX_SIGNATURE_BYTES": .int(Int64(PCAWebauthn.MAX_SIGNATURE_BYTES))]))
                case "coseKeyToJwk":
                    got = Ref.v {
                        guard let b = Base.bytes(a0) else { throw JSError("coseKeyToJwk: expected a Uint8Array") }
                        return .object(try PCAWebauthn.coseKeyToJwk(b))
                    }
                case "parseAuthenticatorData":
                    let p = Base.bytes(a0).flatMap { PCAWebauthn.parseAuthenticatorData($0) }
                    got = .value(p.map { .object(["rpIdHash": Base.bytesValue($0.rpIdHash), "flags": $0.flags.json, "signCount": .int(Int64($0.signCount))]) } ?? .null)
                case "buildStepUpChallenge":
                    got = Ref.v { Base.bytesValue(try PCAWebauthn.buildStepUpChallenge(try Self.stepIn(a0))) }
                case "stepUpChallengeB64u":
                    got = Ref.s { try PCAWebauthn.stepUpChallengeB64u(try Self.stepIn(a0)) }
                case "buildApprovalChallenge", "approvalChallengeForActn":
                    got = Ref.v {
                        guard let rd = a1?.asString else { throw JSError("renderDigest must be a string") }
                        let x = try Self.stepIn(a0)
                        return c.fn == "buildApprovalChallenge" ? Base.bytesValue(try PCAWebauthn.buildApprovalChallenge(x, rd)) : .string(try PCAWebauthn.approvalChallengeForActn(x, rd))
                    }
                case "spcPaymentError":
                    let e: PCAWebauthn.PaymentExpectation
                    do { e = try Self.payExp(a1) } catch let s as Skip { throw s } catch { got = .threw(nil); break }
                    got = .value(Base.opt(PCAWebauthn.spcPaymentError(a0, e, a2?.asString ?? "")))
                case "verifyAssertion":
                    let r = try Self.verify(a0, a1)
                    got = .value(r)
                default:
                    d.skip("\(c.fn): not mapped"); return
                }
            } catch let s as Skip {
                d.skip(s.why); return
            } catch {
                got = .threw(Ref.code(error))
            }
            // a client-data document with a lone UTF-16 unit parses in the reference (the unit survives into the challenge check); a Swift string cannot hold it, so the
            // native refuses the document earlier, with the document-level reason
            if c.name.hasSuffix("lone surrogate"), case let .value(v) = got, v.get("result")?.get("ok") == .bool(false) { d.skip("lone surrogate in client data: refused earlier"); return }
            d.add(c, Base.diff(c, got))
        }
        d.finish(900)
    }

    func testWebauthnFailClosed() throws {
        // nothing verifies without a stored counter, and a missing challenge is never decodable
        let a = PCAWebauthn.Assertion(authenticatorData: [UInt8](repeating: 0, count: 37), clientDataJSON: Array("{}".utf8), signature: [], publicKey: nil)
        XCTAssertEqual(PCAWebauthn.verifyAssertion(a, .init(expectedChallenge: nil, rpId: "x", origins: ["o"], storedSignCount: nil)).reason,
                       "storedSignCount is required (use 0 for a credential never used)")
        XCTAssertFalse(PCAWebauthn.verifyAssertion(a, .init(expectedChallenge: nil, rpId: "x", origins: ["o"], storedSignCount: 0)).ok)
        XCTAssertThrowsError(try PCAWebauthn.coseKeyToJwk([0xa1, 0x01, 0x1b])) // 8-byte argument
        XCTAssertNil(PCAWebauthn.derToRaw([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01])) // negative r
    }
}
