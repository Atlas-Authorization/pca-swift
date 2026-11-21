import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of CaveatLang.swift against the TS reference (caveat-lang.ts, server/require-pca.ts presentedK1):
/// test-data/k05-caveatlang.json.gz (16104 cases: every shape check under structural mutation, every limit at -1/0/+1, seeded derive
/// expressions, re-signed discharges / narrow blocks, whole K1 evaluations over random chains, the K1 request headers).
/// Typed-API mappings: a clock that is not a safe integer is Int64.max (refused by the same safe-integer check); a k1 input that is
/// not an object is "not configured" (nil), as in the reference; derive claims that are not objects hold no claims.
final class K05CaveatLangOracleTests: XCTestCase {
    static let file = "k05-caveatlang.json.gz"
    static let covers = ["CaveatLang", "Caveats", "Capability", "IntentWB", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "Ed25519Strict",
                         "PQ", "Issue", "JSONValue", "Keys", "Agent"]

    static func clock(_ v: JSONValue?) -> Int64 { IV.int(v) ?? Int64.max }

    static func bound(_ b: [BoundCaveat]) -> JSONValue {
        .array(b.map { .object(["caveat": $0.caveat, "hop": .int(Int64($0.hop)), "cap_hash": .string($0.capHash)]) })
    }

    func testShapes() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["spiffeIdError", "needsDischargeError", "dischargeShapeError", "narrowShapeError", "maxUsesError", "maxUsesSlotKey",
                                 "spiffeBoundError", "deriveError"]) { c in
            let a = c.arg(0)
            let got: String?
            switch c.fn {
            case "spiffeIdError": got = PCA.spiffeIdError(a)
            case "needsDischargeError": got = PCA.needsDischargeError(a)
            case "dischargeShapeError": got = PCA.dischargeShapeError(a)
            case "narrowShapeError": got = PCA.narrowShapeError(a)
            case "maxUsesError": got = PCA.maxUsesError(a)
            case "spiffeBoundError": got = PCA.spiffeBoundError(a)
            case "deriveError": got = PCA.deriveError(a)
            default:
                guard let cap = a?.asString, let id = c.arg(1)?.asString, let i = IV.int(c.arg(2)) else { d.skip("maxUsesSlotKey: untyped args"); return }
                got = PCA.maxUsesSlotKey(capHash: cap, id: id, i: Int(i))
            }
            d.add(c, K05.diff(c, .value(K05.opt(got))))
        }
        d.finish(7300)   // 7768 cases, ~220 carry a lone surrogate (skipped)
    }

    func testEvaluateDerive() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["evaluateDerive"]) { c in
            guard let cav = c.arg(0)?.asObject, let inp = c.arg(1)?.asObject else { d.skip("evaluateDerive: non-object args"); return }
            var claims: [JKey: JObject] = [:]
            for (k, v) in inp["claims"]?.asObject ?? [:] { if let o = v.asObject { claims[k] = o } }
            let r = PCA.evaluateDerive(cav, now: Self.clock(inp["now"]), action: inp["action"], history: inp["history"]?.asArray, claims: claims)
            d.add(c, K05.diff(c, .value(r.map { .bool($0) } ?? .null)))
        }
        d.finish(4700)
    }

    func testDischargesAndNarrowBlocks() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["verifyDischarge", "verifyNarrow", "boundCaveats", "dischargeRequests"]) { c in
            switch c.fn {
            case "verifyDischarge":
                let b = c.arg(2)
                // the typed pins are always a list of well-typed pins: a non-list, or a pin for this issuer that cannot be a DischargePin
                // (a missing / non-string pk), is not expressible (both sides refuse it: no pin / a signature that cannot verify)
                guard case let .array(rawPins)? = b?.get("pins") else { d.skip("verifyDischarge: pins is not a list (typed API)"); return }
                let issuer = c.arg(1)?.get("issuer")
                if rawPins.contains(where: { $0.isObject && $0.get("label") == issuer && DischargePin.fromJSON($0) == nil }) {
                    d.skip("verifyDischarge: a pin for the issuer that is not a well-typed DischargePin (typed API)"); return
                }
                let bind = DischargeBinding(capHash: b?.get("cap_hash")?.asString ?? "", actionDigest: b?.get("action_digest")?.asString,
                                            pins: (b?.get("pins")?.asArray ?? []).compactMap { DischargePin.fromJSON($0) },
                                            now: Self.clock(b?.get("now")), revoked: b?.get("revoked")?.asArray?.compactMap { $0.asString })
                let r = PCA.verifyDischarge(c.arg(0), c.arg(1), bind)
                let got: JSONValue = r.ok ? .object(["ok": .bool(true), "digest": .string(r.digest), "claims": .object(r.claims)])
                    : .object(["ok": .bool(false), "reason": .string(r.reason)])
                d.add(c, K05.diff(c, .value(got)))
            case "verifyNarrow":
                let b = c.arg(3)
                let r = PCA.verifyNarrow(c.arg(0), grant: c.arg(1) ?? .null, chain: c.arg(2), now: Self.clock(b?.get("now")),
                                         actionDigest: b?.get("action_digest")?.asString)
                let got: JSONValue = r.ok ? .object(["ok": .bool(true), "caveats": .array(r.caveats)]) : .object(["ok": .bool(false), "reason": .string(r.reason)])
                d.add(c, K05.diff(c, .value(got)))
            case "boundCaveats":
                let r = PCA.boundCaveats(grant: c.arg(0) ?? .null, chain: c.arg(1))
                d.add(c, K05.diff(c, .value(r.map(Self.bound) ?? .null)))
            default:
                d.skip("dischargeRequests: the agent-side request builder is not part of the Swift SDK")
            }
        }
        d.finish(1880)   // 1994 cases, 82 carry a lone surrogate (skipped)
    }

    func testK1Evaluation() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["evaluateK1", "evaluateCaveatsK1"]) { c in
            let k1: K1Input? = c.arg(2)?.isObject == true ? CaveatLangTests.k1Input(c.arg(2)) : nil
            if c.fn == "evaluateK1" {
                let ctx = c.arg(3)
                let r = PCA.evaluateK1(grant: c.arg(0) ?? .null, chain: c.arg(1), k1: k1, now: Self.clock(ctx?.get("now")), action: ctx?.get("action"))
                let got: JSONValue = .object(["ok": .bool(r.ok), "failed": .array(r.failed.map { .string($0) }), "reasons": .array(r.reasons.map { .string($0) }),
                                              "plain": .array(r.plain), "bound": Self.bound(r.bound)])
                d.add(c, K05.diff(c, .value(got)))
            } else {
                let r = PCA.evaluateCaveatsK1(grant: c.arg(0) ?? .null, chain: c.arg(1), k1: k1, context: c.arg(3) ?? .null)
                d.add(c, K05.diff(c, .value(.object(["allow": .bool(r.allow), "failed": .array(r.failed.map { .string($0) })]))))
            }
        }
        d.finish(1500)
    }

    func testPresentedHeaders() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["presentedK1"]) { c in
            var h: [String: String] = [:]
            for (k, v) in c.arg(0)?.asObject ?? [:] { h[k.s] = v.asString ?? "" }
            let got: JSONValue
            do {
                let r = try PCA.presentedK1(headers: h)
                var v: JObject = [:]
                if let ds = r.discharges { v["discharges"] = .array(ds) }
                if let n = r.narrow { v["narrow"] = n }
                got = .object(["ok": .bool(true), "value": .object(v)])
            } catch {
                got = .object(["ok": .bool(false)])
            }
            d.add(c, K05.diff(c, .value(got)))
        }
        d.finish(54)
    }
}
