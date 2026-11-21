import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of Undo.swift against the TS reference (undo.ts): test-data/k05-undo.json.gz (5985 cases: compensation digest,
/// token sign/check/encode/decode/digest, receipts and chains, the state machine over every state x event x clock, the window clamp).
/// Typed-API mappings: a `now` that is not a JSON number is NaN (both sides treat any non-safe-integer clock alike); a secret that is
/// not 32 bytes cannot become a `PCAEdKey` (the reference's `signer_missing`); a non-string token / pin cannot reach the String API
/// (the reference returns null / false for those).
final class K05UndoOracleTests: XCTestCase {
    static let file = "k05-undo.json.gz"
    static let covers = ["Undo", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "Ed25519Strict", "Issue", "Keys", "PcaGuard", "JSONValue", "StrictParser"]

    static func now(_ v: JSONValue?) -> Double { IV.num(v) ?? .nan }

    static func key(_ v: JSONValue?) -> PCAEdKey? {
        guard let s = v?.asString, let seed = Base64URLStrict.decode(s), seed.count == 32 else { return nil }
        return try? Ed25519Deterministic.key(seed: seed)
    }

    static func opt(_ s: String?) -> K05Got { .value(s.map { .string($0) } ?? .null) }

    func testDigestsTokensAndReceipts() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["compensationDigest", "signUndoToken", "undoTokenCheck", "encodeUndoToken", "undoTokenDigest", "decodeUndoToken",
                                 "signUndoReceipt", "undoReceiptDigest", "verifyUndoReceipt", "undoReceiptChainError"]) { c in
            let a0 = c.arg(0) ?? .null
            switch c.fn {
            case "compensationDigest":
                // nil = the reference throws (a non-object or a missing member)
                let got = Undo.compensationDigest(a0)
                d.add(c, K05.diff(c, got.map { .value(.string($0)) } ?? .threw(nil)))
            case "signUndoToken":
                guard let k = Self.key(c.arg(1)) else { d.add(c, K05.diff(c, .threw("signer_missing"))); return }
                let got = K05.run { try Undo.signToken(record: a0, key: k) }
                // the reference signs any record; the Swift producer refuses exactly the records whose token the verifier would refuse as
                // malformed (it never issues an unusable token): such a refusal agrees when tokenCheck reads the reference's token as malformed
                if case .threw = got, !c.threw, Undo.tokenCheck(c.out, expectedSigner: c.out.get("signer")?.asString ?? "", record: a0, now: 0) == "malformed" {
                    d.add(c, nil); return
                }
                d.add(c, K05.diff(c, got))
            case "undoTokenCheck":
                let got = Undo.tokenCheck(c.arg(0), expectedSigner: c.arg(1)?.asString ?? "", record: c.arg(2) ?? .null, now: Self.now(c.arg(3)))
                d.add(c, K05.diff(c, .value(.string(got))))
            case "encodeUndoToken":
                let got = Undo.encodeToken(a0)
                d.add(c, K05.diff(c, got.map { .value(.string($0)) } ?? .threw(nil)))
            case "undoTokenDigest":
                let got = Undo.tokenDigest(a0)
                d.add(c, K05.diff(c, got.map { .value(.string($0)) } ?? .threw(nil)))
            case "decodeUndoToken":
                let got: JSONValue = a0.asString.flatMap { Undo.decodeToken($0) } ?? .null
                d.add(c, K05.diff(c, .value(got)))
            case "signUndoReceipt":
                guard let k = Self.key(c.arg(1)), let b = a0.asObject, let at = IV.int(b["at"]) else { d.add(c, K05.diff(c, .threw(nil))); return }
                d.add(c, K05.diff(c, K05.run {
                    try Undo.signReceipt(record: b["record"]?.asString ?? "", event: b["event"]?.asString ?? "", state: b["state"]?.asString ?? "", at: at,
                                         compensationDigest: b["compensation_digest"]?.asString ?? "", prev: b["prev"]?.asString ?? "",
                                         note: b["note"]?.asString ?? "", key: k)
                }))
            case "undoReceiptDigest":
                let got = Undo.receiptDigest(a0)
                d.add(c, K05.diff(c, got.map { .value(.string($0)) } ?? .threw(nil)))
            case "verifyUndoReceipt":
                let got = c.arg(1)?.asString.map { Undo.verifyReceipt(c.arg(0), expectedSigner: $0) } ?? false
                d.add(c, K05.diff(c, .value(.bool(got))))
            case "undoReceiptChainError":
                d.add(c, K05.diff(c, Self.opt(Undo.receiptChainError(a0, expectedSigner: c.arg(1)?.asString ?? ""))))
            default:
                d.skip("\(c.fn): not mapped")
            }
        }
        d.finish(1300)   // 1429 cases, 91 carry a lone surrogate (skipped)
    }

    func testStateMachine() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["undoTransition"]) { c in
            let t = Undo.transition(c.arg(0) ?? .null, c.arg(1) ?? .null, now: Self.now(c.arg(2)))
            var o: JObject = ["outcome": .string(t.outcome)]
            if let code = t.code { o["code"] = .string(code) }
            if let r = t.reason { o["reason"] = .string(r) }
            if let r = t.record { o["record"] = r }
            if t.outcome == "applied" { o["receipt"] = .object(["event": K05.opt(t.event), "note": K05.opt(t.note)]) }
            d.add(c, K05.diff(c, .value(.object(o))))
        }
        d.finish(4000)
    }

    func testWindowClamp() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["resolveUndoWindow"]) { c in
            let p = c.arg(1)
            let got = Undo.resolveWindow(IV.num(c.arg(0)), minMs: IV.num(p?.get("minMs")), maxMs: IV.num(p?.get("maxMs")), defaultMs: IV.num(p?.get("defaultMs")))
            d.add(c, K05.diff(c, .value(.int(got))))
        }
        d.finish(150)
    }
}
