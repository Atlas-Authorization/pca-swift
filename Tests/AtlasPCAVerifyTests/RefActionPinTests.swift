import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// Action pins: the constants, the registry-signed evolution records and documents (signing under Ed25519 / ML-DSA / the hybrid, key entries, verification with
/// reasons) and the principal's re-approval of a widening step, against the reference corpus: every case, every fn. A verification reason that carries the
/// reference's exception text is compared by prefix. Signing under ML-DSA is compared byte for byte when the opt-in OpenSSL product is linked.
final class RefActionPinTests: XCTestCase {
    typealias A = RefAnalyzer

    private static func mlDsa(_ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(.mlDsa65, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(.mlDsa65, seed: seed)
    }
    private static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    private static func key(_ secret: JSONValue?, _ suite: JSONValue?) throws -> PCASuiteKey {
        guard let s = Base.bytes(secret) else { throw PCAProducerError("secret") }
        let ed = try Ed25519Deterministic.key(seed: s)
        var key = PCASuiteKey.ed25519(ed)
        if let su = JS.present(suite) {
            guard let alg = IV.sigAlg(su.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(su.get("pqSeed")).map { try mlDsa($0) })
        }
        return key
    }

    private static func verdict(_ reason: String?) -> JSONValue { reason.map { .object(["ok": .bool(false), "reason": .string($0)]) } ?? .object(["ok": .bool(true)]) }
    private static func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3), a4 = A.arg(c, 4)
        switch c.fn {
        case "constants":
            return .value(.object(["ACTION_PIN_ON_NEW": strs(Actions.ACTION_PIN_ON_NEW), "EVOLUTION_CLASSES": strs(Actions.EVOLUTION_CLASSES), "EVOLUTION_DIFF_DOMAIN": .string(Actions.EVOLUTION_DIFF_DOMAIN),
                                   "EVOLUTION_DOMAIN": .string(Actions.EVOLUTION_DOMAIN), "EVOLUTION_RECORD_KIND": .string(Actions.EVOLUTION_RECORD_KIND), "MAX_ESC_TIER": .int(Actions.MAX_ESC_TIER),
                                   "MAX_EVOLUTION_STEPS": .int(Int64(Actions.MAX_EVOLUTION_STEPS)), "REAPPROVAL_DOMAIN": .string(Actions.REAPPROVAL_DOMAIN), "REAPPROVAL_KIND": .string(Actions.REAPPROVAL_KIND)]))
        case "signEvolutionRecord": return A.run { try Actions.signEvolutionRecord(a0 ?? .null, kid: a1?.asString ?? "", key: try key(a2, a3)) }
        case "registryKeyOf": return A.run { try Actions.registryKeyOf(kid: a0?.asString ?? "", key: try key(a1, a2)) }
        case "signRegistryDoc": return A.run { try ActionPacks.signRegistryDoc(a0?.asString ?? "", a1 ?? .null, kid: a2?.asString ?? "", key: try key(a3, a4)) }
        case "verifyEvolutionRecord": return .value(verdict(Actions.evolutionRecordSigError(a0, a1)))
        case "verifyRegistrySig": return .value(verdict(Actions.registrySigError(a0?.asString ?? "", a1 ?? .null, a2 ?? .null, a3)))
        case "signReapproval":
            return A.run {
                guard let secret = Base.bytes(a0?.get("principalSecret")), let grant = a0?.get("grantId")?.asString else { throw JSError("bad arguments") }
                return try Actions.signReapproval(grantId: grant, record: a0?.get("record") ?? .null, principal: try Ed25519Deterministic.key(seed: secret))
            }
        case "reapprovalValid":
            return .value(.bool(Actions.reapprovalValid(a0, grantId: a1?.asString ?? "\u{0}", issuer: a2?.asString ?? "", verb: a3?.asString ?? "\u{0}", diff: a4?.asString ?? "\u{0}")))
        default: return nil
        }
    }

    private static func cut(_ v: JSONValue) -> JSONValue {
        guard case var .object(o) = v, let r = o["reason"]?.asString, r.hasPrefix("verification error:") else { return v }
        o["reason"] = .string("verification error:")
        return .object(o)
    }

    private static func signed(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard ["signRegistryDoc", "signEvolutionRecord"].contains(c.fn), !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out else { return got }
        var m = mine, w = want
        var holder: JKey? = nil
        if c.fn == "signEvolutionRecord" { holder = "sig"; guard case let .object(ms)? = mine["sig"], case let .object(ws)? = want["sig"] else { return got }; m = ms; w = ws }
        guard let alg = w["alg"]?.asString, alg != "ed25519" else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_value" : "value")
        m[field] = nil
        w[field] = nil
        if let h = holder { mine[h] = .object(m); want[h] = .object(w) } else { mine = m; want = w }
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-action-pin.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            var g = Self.signed(c, got)
            if case let .value(v) = g, !c.threw, ["verifyEvolutionRecord", "verifyRegistrySig"].contains(c.fn) {
                let (x, y) = (Self.cut(v), Self.cut(c.out))
                let same = Base.canon(x) == Base.canon(y)
                if !same, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
                d.add(c, same ? nil : Base.diff(c, .value(x)))
                return
            }
            if !MLDSA.available, Base.diff(c, g) != nil, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            if case .threw = got { g = got }
            d.add(c, Base.diff(c, g))
        }
        XCTAssertEqual(n, 111)
        XCTAssertEqual(seen, ["signEvolutionRecord": 33, "verifyEvolutionRecord": 21, "signRegistryDoc": 20, "reapprovalValid": 17, "signReapproval": 8, "verifyRegistrySig": 6, "registryKeyOf": 5, "constants": 1])
        d.finish(111 - d.skipped.values.reduce(0, +))
    }
}
