import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The PUF attestation root (repetition-code fuzzy extractor, simulated PUF, TPM-EK provider over an injected runner, enrollment, device attestor,
/// enrollment registry, verifier) against the reference corpus: every case, every fn. Signing under ML-DSA is compared byte for byte when the opt-in OpenSSL
/// product is linked (deterministic ML-DSA); otherwise the platform signs (hedged) and the ML-DSA signature is the one member not compared.
final class RefAttestPufTests: XCTestCase {
    typealias P = PCAAttestPuf
    typealias A = RefAnalyzer

    private static let pqKey: P.PqKeyFromSeed? = {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return { level, seed in try PCAOpenSSL.mlDsaKey(level, seed: seed) } }
        #endif
        return nil
    }()
    private static var exactMlDsa: Bool { pqKey != nil }

    private static func bytes(_ v: JSONValue?) throws -> [UInt8] {
        guard let b = Base.bytes(v) else { throw JSError("expected bytes") }
        return b
    }

    private static func wrap(_ v: JSONValue) -> JSONValue { .object(["ok": .bool(true), "value": v]) }
    private static func sha(_ b: [UInt8]) -> JSONValue { .string(ACrypto.hex(Canonical.sha256(b))) }

    /// A simulated PUF of a spec `{id, seed, length, flip?}` (the seed is a base64url string after the label resolution).
    private static func puf(_ s: JSONValue?) throws -> P.SimulatedPuf {
        guard let id = s?.get("id")?.asString, let seed = s?.get("seed")?.asString.flatMap({ Base64URLStrict.decode($0) }), let len = s?.get("length")?.safeInt else { throw JSError("bad spec") }
        let flips = (s?.get("flip")?.asArray ?? []).compactMap { $0.safeInt.map { Int($0) } }
        return P.createSimulatedPuf(id: id, seed: seed, length: Int(len), flip: flips)
    }

    /// The `randomBytes` callback of a case: its first call returns r1 and its second r2, each cut to the length asked.
    private static func rand(_ v: JSONValue?) throws -> (Int) -> [UInt8] {
        let r = try (v?.asArray ?? []).map { try bytes($0) }
        var i = 0
        return { n in defer { i += 1 }; return i < r.count ? Array(r[i].prefix(n)) : [] }
    }

    private static func int(_ v: JSONValue?) -> Double { IV.num(v) ?? .nan }

    private static func tpm(_ a: JSONValue?) -> JSONValue {
        var calls: [JSONValue] = []
        func out(_ r: Result<JSONValue, Error>) -> JSONValue {
            var o: JObject = [:]
            switch r {
            case let .success(v): o["ok"] = .bool(true); o["value"] = v
            case let .failure(e): o["ok"] = .bool(false); o["error"] = .string((e as? JSError)?.message ?? "\(e)")
            }
            o["calls"] = .array(calls)
            return .object(o)
        }
        let opts = a?.get("opts")
        let run = a?.get("run")
        let runner: P.TpmCommandRunner = { cmd, args in
            calls.append(.array([.string(cmd), .array(args.map { .string($0) })]))
            if let t = run?.get("$throws")?.asString { throw JSError(t) }
            guard let r = run, r.isObject else { return nil }
            return P.TpmCommandResult(status: r.get("status")?.safeInt.map { Int($0) }, stdout: Base.bytes(r.get("stdout")) ?? [], stderr: r.get("stderr")?.asString, error: r.get("error")?.asString)
        }
        do {
            let intOr0: (JSONValue?) -> Int? = { v in v == nil ? nil : (IV.num(v).flatMap { $0.isFinite && $0.rounded() == $0 ? Int($0) : nil } ?? 0) }
            let p = try P.TpmEkProvider(id: opts?.get("id")?.asString ?? "", length: intOr0(opts?.get("length")) ?? 0, run: runner, tool: opts?.get("tool")?.asString,
                                        ekHandle: opts?.get("ekHandle")?.asString, args: strings(opts?.get("args")), minEkBytes: intOr0(opts?.get("minEkBytes")))
            switch a?.get("op")?.asString {
            case "readEkPublic"?: return out(.success(Base.bytesValue(try p.readEkPublic())))
            default:
                // the reference reads the EK before it uses the challenge, and an absent challenge is the oracle's default one (sha256 of its randomness label)
                guard let ch = a?.get("challenge") else { return out(.success(Base.bytesValue(try p.response(Canonical.sha256(Array("attest-puf-oracle-randomness/challenge".utf8)))))) }
                guard let cb = Base.bytes(ch) else { _ = try p.readEkPublic(); throw JSError("expected bytes") }
                return out(.success(Base.bytesValue(try p.response(cb))))
            }
        } catch { return out(.failure(error)) }
    }

    private static func strings(_ v: JSONValue?) -> [String]? {
        guard case let .array(a)? = v else { return nil }
        return a.compactMap { $0.asString }
    }

    private static func registry(_ a: JSONValue?) -> JSONValue {
        let r = P.EnrollmentRegistry(a?.get("enrollments"))
        return wrap(.array((a?.get("ops")?.asArray ?? []).map { op in
            if let e = op.get("register") { r.register(e); return .null }
            if op.get("register") != nil || op.asObject?.keys.contains(JKey("register")) == true { r.register(nil); return .null }
            if let id = op.get("lookup")?.asString { return r.lookup(id) ?? .null }
            if let id = op.get("revoke")?.asString { r.revoke(id); return .null }
            if let id = op.get("isRevoked")?.asString { return .bool(r.isRevoked(id)) }
            return .null
        }))
    }

    private static func verifierOptions(_ cfg: JSONValue?, enrollments: [JSONValue], revoked: [String]?, evidence: JSONValue?) -> P.VerifierOptions {
        let pol = cfg?.get("policy")
        var p = P.Policy(measurements: strings(pol?.get("measurements")) ?? [], weightsMeasurements: strings(pol?.get("weightsMeasurements")))
        if pol?.get("identity")?.asString == "custom" {
            p.deriveIdentity = { st, enr in
                .object(["model_id": .string("m-custom"), "weights_digest": .string(st.get("weights_digest")?.asString ?? ""), "weights_measured": .bool(true),
                         "runtime_measurement": st.get("measurement") ?? .null, "operator": enr.get("providerId") ?? .null])
            }
        }
        var o = P.VerifierOptions(policy: p, requirePq: cfg?.get("requirePq") == .bool(true))
        if cfg?.get("noResolveEnrollment") != .bool(true) {
            o.resolveEnrollment = { id, _, _ in enrollments.last { $0.get("providerId")?.asString == id } }
        }
        if let r = revoked { o.isRevoked = { r.contains($0) } }
        if cfg?.get("noEvidenceSeam") != .bool(true) {
            let st = JS.present(evidence)
            o.resolveEvidence = { _, _ in st }
        }
        return o
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "constants":
            return .value(.object(["PUF_EXTRACT_INFO": .string(P.PUF_EXTRACT_INFO), "PUF_ATTEST_DOMAIN": .string(P.PUF_ATTEST_DOMAIN), "PUF_KEY_BYTES": .int(Int64(P.PUF_KEY_BYTES)),
                                   "TPM_EK_PUF_DOMAIN": .string(P.TPM_EK_PUF_DOMAIN)]))
        case "repetitionCorrectionBound":
            return A.run {
                let r = P.repetitionCorrectionBound(number: JS.toNumber(a0))
                return r.isFinite && abs(r) < 9e15 ? .int(Int64(r)) : .double(r)
            }
        case "simulatedPufResponse": return A.run { Base.bytesValue(try puf(a0).response(try bytes(a1))) }
        case "fuzzyEnroll":
            return A.run {
                let r = try P.fuzzyEnroll(try bytes(a0), rep: int(a1?.get("rep")), messageBits: int(a1?.get("messageBits")), randomBytes: try rand(a2))
                let v: JSONValue = .object(["keySha256": sha(r.key), "helper": r.helper])
                return c.out.get("ok") != nil && c.out.get("value") != nil ? wrap(v) : v
            }
        case "fuzzyReproduce": return A.run { wrap(.object(["keySha256": sha(try P.fuzzyReproduce(try bytes(a0), a1))])) }
        case "tpmEk": return .value(tpm(a0))
        case "enrollPuf":
            return A.run {
                wrap(try P.enrollPuf(provider: try puf(a0), challenge: try bytes(a1), rep: int(a2?.get("rep")), messageBits: int(a2?.get("messageBits")), alg: a2?.get("alg"),
                                     randomBytes: try rand(a3), pqKey: pqKey))
            }
        case "pufAttest":
            return A.run {
                guard let enr = a1 else { throw JSError("enrollment") }
                return wrap(try P.createPufAttestor(provider: try puf(a0), enrollment: enr, pqKey: pqKey).attest(a2 ?? .null))
            }
        case "registry": return .value(registry(a0))
        case "verifyPuf":
            return A.run {
                let i = a0?.get("input")
                let o = verifierOptions(a0?.get("config"), enrollments: a0?.get("enrollments")?.asArray ?? [], revoked: strings(a0?.get("revoked")), evidence: a0?.get("evidence"))
                return try P.createPufVerifier(o).verify(document: .object([:]), ctx: .object([:]), nowMs: IV.num(i?.get("nowMs")) ?? .nan,
                                                         expected: JS.present(i?.get("expected")) ?? .null).json
            }
        case "buildVerifier":
            return A.run {
                _ = try P.createPufVerifier(verifierOptions(a0, enrollments: [], revoked: nil, evidence: nil))
                return wrap(.object(["built": .bool(true)]))
            }
        default: return nil
        }
    }

    /// An ML-DSA statement signed by the platform's hedged ML-DSA differs from the reference in its signature only.
    private static func minted(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "pufAttest", !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out,
              case var .object(ms)? = mine["value"], case var .object(ws)? = want["value"], ws["alg"]?.asString?.hasPrefix("ml-dsa") == true else { return got }
        ms["sig"] = nil
        ws["sig"] = nil
        mine["value"] = .object(ms)
        want["value"] = .object(ws)
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-attest-puf.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            let diff = Base.diff(c, Self.minted(c, got))
            if diff != nil, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            d.add(c, diff)
        }
        XCTAssertEqual(n, 278)
        XCTAssertEqual(seen, ["fuzzyReproduce": 80, "verifyPuf": 52, "simulatedPufResponse": 30, "tpmEk": 30, "fuzzyEnroll": 23, "pufAttest": 22, "enrollPuf": 13,
                              "repetitionCorrectionBound": 12, "registry": 10, "buildVerifier": 5, "constants": 1])
        d.finish(278 - d.skipped.values.reduce(0, +))
    }
}
