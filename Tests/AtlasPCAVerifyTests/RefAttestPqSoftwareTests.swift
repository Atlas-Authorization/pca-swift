import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The post-quantum software attestation root (statement minting under ML-DSA, SLH-DSA and the hybrids; the verifier with trusted PQ keys, suite
/// policy, binding and measurement allowlists) against the reference corpus: every case, every fn. Minting under ML-DSA is compared byte for byte when
/// the opt-in OpenSSL product is linked (deterministic ML-DSA); otherwise the platform signs (hedged ML-DSA) and the ML-DSA signature is the one member
/// not compared. SLH-DSA statements are verify-only inputs: they are compared only where the SLH-DSA backend is registered.
final class RefAttestPqSoftwareTests: XCTestCase {
    typealias P = PCAAttestPq
    typealias A = RefAnalyzer

    static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    static var slhDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.registerSlhDsa()
        #else
        return PCASlhDsaHook.isRegistered
        #endif
    }

    private static func mlDsa(_ level: PCAMLDSALevel, _ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(level, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(level, seed: seed)
    }

    /// The key of a spec `{alg, edSecret?, seed?}` (seeds are base64url secrets after the label resolution).
    private static func key(_ k: JSONValue?) throws -> PCASuiteKey {
        guard let alg = k?.get("alg")?.asString else { throw PCAProducerError("alg") }
        let ed = try k?.get("edSecret")?.asString.flatMap { Base64URLStrict.decode($0) }.map { try Ed25519Deterministic.key(seed: $0) }
        // the reference's key objects carry their ML-DSA level: a seed minted for the other family is not "the matching PQ key material"
        // (the generator's seed labels name the family, and the harness resolves them to the sha256 seed)
        func seedOf(_ family: String) -> [UInt8] { Canonical.sha256(Array("atlas-pca-conformance/pq-software/\(family)/pq".utf8)) }
        let want87 = alg.contains("87")
        let pq = try k?.get("seed")?.asString.flatMap { Base64URLStrict.decode($0) }.flatMap { seed -> PCAPQKey? in
            if seed == seedOf(want87 ? "ml-dsa-65" : "ml-dsa-87") { return nil }
            return try mlDsa(want87 ? .mlDsa87 : .mlDsa65, seed)
        }
        return try PCASuiteKey(alg: alg, ed: ed, pq: pq)
    }

    private static func keysOut(_ a: P.Attestor) -> JObject {
        var o: JObject = ["pqPublicKey": .string(a.pqPublicKey)]
        if let e = a.ed25519PublicKey { o["ed25519PublicKey"] = .string(e) }
        return o
    }

    private static func strings(_ v: JSONValue?) -> [String]? {
        guard case let .array(a)? = v else { return nil }
        return a.compactMap { $0.asString }
    }

    private static func options(_ cfg: JSONValue?, _ evidence: JSONValue?) -> P.VerifierOptions {
        let pol = cfg?.get("policy")
        var o = P.VerifierOptions(trustedPqPublicKeys: strings(cfg?.get("trustedPqPublicKeys")) ?? [],
                                  policy: P.Policy(measurements: strings(pol?.get("measurements")) ?? [], weightsMeasurements: strings(pol?.get("weightsMeasurements"))),
                                  trustedEd25519PublicKeys: strings(cfg?.get("trustedEd25519PublicKeys")), requirePq: cfg?.get("requirePq") != .bool(false),
                                  requireHybrid: cfg?.get("requireHybrid") == .bool(true))
        // an allowedSuites that is not an array allows nothing (an empty set)
        if let a = cfg?.get("allowedSuites") { o.allowedSuites = strings(a) ?? [] }
        if cfg?.get("noEvidenceSeam") != .bool(true) {
            let st = JS.present(evidence)
            o.resolveEvidence = { _, _ in st }
        }
        return o
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1)
        switch c.fn {
        case "constants": return .value(.object(["PQ_ATTEST_DOMAIN": .string(P.PQ_ATTEST_DOMAIN)]))
        case "attest":
            return A.run {
                let at = try P.createPqSoftwareAttestor(try key(a0))
                var o = keysOut(at)
                o["statement"] = try at.attest(a1 ?? .null)
                return .object(o)
            }
        case "buildAttestor": return A.run { .object(keysOut(try P.createPqSoftwareAttestor(try key(a0)))) }
        case "buildVerifier":
            return A.run {
                _ = try P.createPqSoftwareVerifier(options(a0, nil))
                return .object(["built": .bool(true)])
            }
        case "verifyPq":
            return A.run {
                let v = try P.createPqSoftwareVerifier(options(a0?.get("config"), a0?.get("evidence")))
                let i = a0?.get("input")
                return try v.verify(document: .null, ctx: .null, nowMs: IV.num(i?.get("nowMs")) ?? .nan, expected: JS.present(i?.get("expected")) ?? .null).json
            }
        default: return nil
        }
    }

    /// Minting with the platform's hedged ML-DSA differs from the reference in the ML-DSA signature only.
    private static func minted(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "attest", !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out,
              case var .object(ms)? = mine["statement"], case var .object(ws)? = want["statement"], let alg = ws["alg"]?.asString else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_sig" : "sig")
        ms[field] = nil
        ws[field] = nil
        mine["statement"] = .object(ms)
        want["statement"] = .object(ws)
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let slh = Self.slhDsa
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-attest-pq-software.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            let diff = Base.diff(c, Self.minted(c, got))
            if diff != nil, !slh, Base.canon(.array(c.args)).contains("slh-dsa") { d.skip("SLH-DSA backend is not registered in this build"); return }
            if diff != nil, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            d.add(c, diff)
        }
        XCTAssertEqual(n, 137)
        XCTAssertEqual(seen, ["verifyPq": 90, "attest": 29, "buildAttestor": 9, "buildVerifier": 8, "constants": 1])
        d.finish(137 - d.skipped.values.reduce(0, +))
    }
}
