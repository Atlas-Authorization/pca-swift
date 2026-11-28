import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The safety certificate (risk-budget bound, checks with evidence links, guardian signature) against the reference corpus: every case, every fn.
/// ISSUING under ml-dsa-65 or the hybrid is compared byte for byte when the opt-in OpenSSL product is linked (deterministic ML-DSA on libcrypto 3.5+);
/// otherwise the platform signs (hedged ML-DSA), so every other member is compared and the certificate must verify under the guardian's pinned key.
final class RefSafetyCertificateTests: XCTestCase {
    typealias S = SafetyCertificate
    typealias A = RefAnalyzer

    static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    private static func mlDsa(_ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(.mlDsa65, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(.mlDsa65, seed: seed)
    }

    /// The verifier options of a case (null = none).
    private static func opts(_ v: JSONValue?) -> S.VerifyOptions {
        var o = S.VerifyOptions()
        guard let v = v, v.isObject else { return o }
        o.guardian = v.get("guardian")?.asString
        o.requireChecks = (v.get("requireChecks")?.asArray ?? []).compactMap { $0.asString }
        o.maxAgeMs = IV.num(v.get("maxAgeMs"))
        o.now = IV.num(v.get("now"))
        if let pins = v.get("pqPins")?.asObject {
            var m: [String: String] = [:]
            for (k, p) in pins { if let t = p.asString { m[k.s] = t } }
            o.pqPins = m
        }
        o.allowUnboundPq = v.get("allowUnboundPq") == .bool(true)
        return o
    }

    private static func issue(_ a: JSONValue?) throws -> JSONValue {
        guard let a = a, let secret = Base.bytes(a.get("guardianSecret")) else { throw PCAProducerError("guardianSecret") }
        let ed = try Ed25519Deterministic.key(seed: secret)
        var key = PCASuiteKey.ed25519(ed)
        if let suite = JS.present(a.get("suite")) {
            // an alg that is not a string, or not a registered suite, is refused when the key is built
            guard let alg = IV.sigAlg(suite.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(suite.get("pqSeed")).map { try mlDsa($0) })
        }
        return try S.issueSafetyCertificate(policy: a.get("policy"), guardian: key, grantRef: a.get("grantRef")?.asString, instance: a.get("instance")?.asString,
                                            checks: JS.present(a.get("checks")), issuedAt: IV.num(a.get("issuedAt")))
    }

    /// A certificate the platform signed with hedged ML-DSA: everything but the ML-DSA signature equals the reference and it verifies under the pin.
    private static func issued(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard !exactMlDsa, !c.threw, case let .value(cert) = got, let alg = c.out.get("alg")?.asString, alg != "ed25519",
              case var .object(mine) = cert, case var .object(want) = c.out, let guardian = mine["guardian"]?.asString, let pk = mine["pq_pk"]?.asString,
              S.verifySafetyCertificate(cert, S.VerifyOptions(pqPins: [guardian: pk])).ok else { return got }
        let field = JKey(alg == "ml-dsa-65" ? "sig" : "pq_sig")
        mine[field] = nil
        want[field] = nil
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1)
        switch c.fn {
        case "constants":
            return .value(.object(["MAX_SAFETY_CHECKS": .int(Int64(S.MAX_SAFETY_CHECKS)), "SAFETY_CERT_DOMAIN": .string(S.SAFETY_CERT_DOMAIN),
                                   "SAFETY_CERT_SCOPE": .string(S.SAFETY_CERT_SCOPE), "SAFETY_CERT_VERSION": .int(Int64(S.SAFETY_CERT_VERSION))]))
        case "safetyCertificateBound": return A.run { PD.num(S.safetyCertificateBound(a0)) }
        case "safetyCertificateStatement":
            guard let bound = IV.num(a0) else { return .threw(nil) }
            return .value(.string(S.safetyCertificateStatement(bound)))
        case "validateSafetyChecks": return .value(Base.opt(S.validateSafetyChecks(a0)))
        case "safetyCertificateMessage": return A.run { Base.bytesValue(try S.safetyCertificateMessage(a0 ?? .null)) }
        case "issueSafetyCertificate": return issued(c, A.run { try issue(a0) })
        case "verifySafetyCertificate": return A.run { S.verifySafetyCertificate(a0, opts(a1)).json }
        case "encodeSafetyCertificate": return A.run { .string(try S.encodeSafetyCertificate(a0 ?? .null)) }
        case "decodeSafetyCertificate":
            // the typed API takes text; anything else is not a certificate
            guard let text = a0?.asString else { return .value(.null) }
            return .value(S.decodeSafetyCertificate(text) ?? .null)
        case "safetyCertificateForCompliance": return .value(S.safetyCertificateForCompliance(a0, opts(a1)) ?? .null)
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        #if canImport(AtlasPCAOpenSSL)
        // with the product linked in CI a missing backend fails: the byte-for-byte ML-DSA certificates are what that run is for
        if ProcessInfo.processInfo.environment["CI"] != nil { XCTAssertTrue(PCAOpenSSL.mlDsaAvailable(), "libcrypto without ML-DSA (needs 3.5+)") }
        #endif
        let d = Base.Diffs()
        var notComparable = 0
        let n = try Base.each("ref-safety-certificate.json.gz", seeds: true) { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            // an OS without ML-DSA refuses those suites (fail closed): a case that signs or verifies one is not comparable there
            if !MLDSA.available, Base.diff(c, got) != nil, Base.canon(.array(c.args)).contains("ml-dsa") {
                d.skip("ML-DSA is not available on this OS"); notComparable += 1; return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 262)
        d.finish(262 - notComparable)
    }

    func testACertificateRoundTrip() throws {
        let policy = K042.parse(#"{"weights":{"alpha":0.25,"beta":0.2,"gamma":0.2,"delta":0.2,"epsilon":0.1,"zeta":0.05},"theta1":0.3,"theta2":0.7,"kappa":2,"lambda":0.01,"rho":0.5,"bMax":3}"#)
        let checks = K042.parse(#"[{"id":"tests","status":"passed","evidence":{"kind":"url","ref":"https://ci.example/run/1"},"at":1}]"#)
        let ed = try PCAEdKey(seed: [UInt8](repeating: 7, count: 32))
        let cert = try S.issueSafetyCertificate(policy: policy, guardian: .ed25519(ed), checks: checks, issuedAt: 1000)
        XCTAssertEqual(S.verifySafetyCertificate(cert, S.VerifyOptions(requireChecks: ["tests"], maxAgeMs: 10, now: 1005)), S.Verdict(ok: true, reason: nil, recomputedBound: 1.5))
        XCTAssertEqual(S.decodeSafetyCertificate(try S.encodeSafetyCertificate(cert)).map { Base.canon($0) }, Base.canon(cert))
        // a changed parameter no longer matches the stated bound, and a changed statement breaks the signature
        guard case var .object(o) = cert, case var .object(p)? = o["params"] else { return XCTFail("shape") }
        var forged = o
        forged["statement"] = .string("safe")
        XCTAssertEqual(S.verifySafetyCertificate(.object(forged)).reason, "guardian signature does not verify")
        p["bMax"] = .int(300)
        o["params"] = .object(p)
        XCTAssertEqual(S.verifySafetyCertificate(.object(o)).reason, "stated bound does not equal B_max/κ recomputed from the parameters")
        XCTAssertNil(S.safetyCertificateForCompliance(.object(o)))
        XCTAssertEqual(S.validateSafetyChecks(K042.parse(#"[{"id":"a","status":"passed","evidence":{"kind":"url","ref":"https://u:p@ci.example/"},"at":1}]"#)),
                       "check 'a' evidence URL must be a plain https URL")
    }
}
