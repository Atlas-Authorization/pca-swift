import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The semantic judge threshold (statement, signed message, verdict signing under Ed25519 / ML-DSA / the hybrid, verdict verification with pins, the judge
/// attestation gate, k-of-n with the conformal cutoff, the verifier hook, the risk contribution) against the reference corpus: every case, every fn. The
/// legacy opt-out `allowUnboundPq` is not supported: the cases the reference accepts only through it are asserted REFUSED. Signing under ML-DSA is compared
/// byte for byte when the opt-in OpenSSL product is linked; otherwise the platform signs (hedged) and the ML-DSA signature is the one member not compared.
final class RefSemanticThresholdTests: XCTestCase {
    typealias S = PCAIntentSemantic
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

    private static func attestation(_ a: JSONValue?) -> S.Attestation? {
        guard let a = a, a.isObject else { return nil }
        let by = a.get("byJudge")?.asObject ?? [:]
        return S.Attestation(resolve: { v in v.get("judge")?.asString.flatMap { by[JKey($0)] } }, approved: JS.present(a.get("approved")), require: a.get("require") == .bool(true))
    }

    private static func sign(_ a0: JSONValue?, _ a1: JSONValue?, _ a2: JSONValue?) throws -> JSONValue {
        guard let secret = Base.bytes(a0) else { throw PCAProducerError("secret") }
        let ed = try Ed25519Deterministic.key(seed: secret)
        var key = PCASuiteKey.ed25519(ed)
        if let suite = JS.present(a2) {
            guard let alg = IV.sigAlg(suite.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(suite.get("pqSeed")).map { try mlDsa($0) })
        }
        return try S.signJudgeVerdict(key, a1 ?? .null)
    }

    private static func hook(_ o: JSONValue?, _ ctxs: [JSONValue]) throws -> JSONValue {
        let mode = o?.get("actionDigestMode")?.asString ?? "default"
        var opts = S.VerifierOptions(judgeKeys: o?.get("judgeKeys") ?? .null, k: o?.get("k") ?? .null, verdicts: { $0.get("verdicts") }, goalCommitment: { $0.get("goal") },
                                     calibration: JS.present(o?.get("calibration")), optionalWhenAbsent: o?.get("optionalWhenAbsent") == .bool(true),
                                     attestation: { attestation($0.get("attestation")) })
        if mode.hasPrefix("fixed:") { let d = String(mode.dropFirst(6)); opts.actionDigest = { _ in d } }
        let v = S.createSemanticVerifier(opts)
        return .array(try ctxs.map { try v($0) })
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2)
        switch c.fn {
        case "constants": return .value(.object(["SEMANTIC_JUDGE_DOMAIN": .string(S.SEMANTIC_JUDGE_DOMAIN), "SCORE_SCALE": .int(Int64(S.SCORE_SCALE))]))
        case "quantizeScore": return A.run { .int(S.quantizeScore(IV.num(a0) ?? .nan)) }
        case "statementOf": return A.run { try S.statementOf(a0 ?? .null) }
        case "semanticJudgeMessage": return A.run { Base.bytesValue(try S.semanticJudgeMessage(a0 ?? .null)) }
        case "verdictDigest": return A.run { .string(try S.verdictDigest(a0 ?? .null)) }
        case "signJudgeVerdict": return A.run { try sign(a0, a1, a2) }
        case "verifyJudgeVerdict":
            return .value(.bool(S.verifyJudgeVerdict(a0, a1?.get("actionDigest")?.asString, a1?.get("goalCommitment")?.asString, a2?.get("pqPins"))))
        case "verifyJudgeAttestation": return .value(S.verifyJudgeAttestation(JS.present(a0), JS.present(a1), JS.present(a2)))
        case "verifySemanticThreshold":
            return A.run { S.verifySemanticThreshold(a0, a1 ?? .null, attestation(a1?.get("attestation"))?.gate) }
        case "semanticVerifier": return A.run { try hook(a0, a1?.asArray ?? []) }
        case "semanticRiskContribution": return A.run { .double(S.semanticRiskContribution(IV.num(a0) ?? .nan)) }
        default: return nil
        }
    }

    /// A verdict signed with the platform's hedged ML-DSA differs from the reference in its ML-DSA signature only.
    private static func signed(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "signJudgeVerdict", !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out, let alg = want["alg"]?.asString else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_sig" : "sig")
        mine[field] = nil
        want[field] = nil
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        var unbound = 0
        let n = try Base.each("ref-semantic-threshold.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            // the legacy opt-out is not ported: a verdict the reference accepts only through it is refused here
            let usesOptOut = Base.canon(.array(c.args)).contains("\"allowUnboundPq\":true")
            if usesOptOut, let ok = c.out.get("ok") == .bool(true) ? true : (c.out == .bool(true) ? true : nil), ok {
                guard let got = Self.call(c), case let .value(v) = got else { XCTFail("unhandled \(c.fn)"); return }
                XCTAssertTrue(v == .bool(false) || v.get("ok") == .bool(false), c.name)
                unbound += 1
                return
            }
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            let diff = Base.diff(c, Self.signed(c, got))
            if diff != nil, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            d.add(c, diff)
        }
        XCTAssertEqual(n, 186)
        XCTAssertEqual(unbound, 2, "the two cases accepted by the reference only through allowUnboundPq are asserted refused")
        XCTAssertEqual(seen, ["verifySemanticThreshold": 39, "verifyJudgeVerdict": 27, "quantizeScore": 26, "statementOf": 21, "verifyJudgeAttestation": 18, "semanticRiskContribution": 14,
                              "signJudgeVerdict": 13, "semanticVerifier": 12, "semanticJudgeMessage": 11, "verdictDigest": 4, "constants": 1])
        d.finish(186 - 2 - d.skipped.values.reduce(0, +))
    }
}
