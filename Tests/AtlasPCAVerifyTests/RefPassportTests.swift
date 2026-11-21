import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The agent passport (fingerprint, issue, binding match, registry, trust score, evidence binding, signing, verification with revocation and hardware
/// evidence, assurance label) against the reference corpus: every case, every fn. The legacy opt-out `allowUnboundPq` is not supported: the case the
/// reference accepts only through it is asserted REFUSED. Signing under ML-DSA is compared byte for byte when the opt-in OpenSSL product is linked.
final class RefPassportTests: XCTestCase {
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

    private static func int(_ v: JSONValue?) -> Int64? { v?.safeInt }

    private static func key(_ secret: JSONValue?, _ suite: JSONValue?) throws -> PCASuiteKey {
        guard let s = Base.bytes(secret) else { throw PCAProducerError("issuerSecret") }
        let ed = try Ed25519Deterministic.key(seed: s)
        var key = PCASuiteKey.ed25519(ed)
        if let su = JS.present(suite) {
            guard let alg = IV.sigAlg(su.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(su.get("pqSeed")).map { try mlDsa($0) })
        }
        return key
    }

    private static func attestation(_ r: JSONValue?) -> PassportAttestation {
        PassportAttestation(ok: r?.get("ok") == .bool(true), bound: r?.get("bound") == .bool(true), measured: r?.get("measured")?.asObject)
    }

    private static func verdictJSON(_ v: PassportVerdict) -> JSONValue {
        if v.ok { return .object(["ok": .bool(true), "passport": v.passport ?? .null, "iss": .string(v.iss), "sub": .string(v.sub), "exp": .int(v.exp), "hardware_verified": .bool(v.hardwareVerified)]) }
        var o: JObject = ["ok": .bool(false), "reason": .string(v.reason)]
        if let d = v.detail { o["detail"] = .string(d) }
        return .object(o)
    }

    private static func verify(_ sp: JSONValue?, _ o: JSONValue?) -> JSONValue {
        var pins: [String: String] = [:]
        for (k, v) in o?.get("pqPins")?.asObject ?? [:] { if let t = v.asString { pins[k.s] = t } }
        var opts = PassportOptions(trustedIssuers: (o?.get("trustedIssuers")?.asArray ?? []).compactMap { $0.asString }, nowMs: int(o?.get("now")) ?? 0, clockSkewMs: int(o?.get("clockSkewMs")),
                                   maxEvidenceAgeMs: int(o?.get("maxEvidenceAgeMs")), subject: o?.get("subject")?.asString, pqPins: pins)
        switch o?.get("revocation") {
        case .string("none")?, nil: break
        case .string("throws")?: opts.revoked = { _, _, _ in throw JSError("revocation source down") }
        case let r?:
            if let ids = r.get("revokedIds")?.asArray?.compactMap({ $0.asString }) { opts.revoked = { id, _, _ in ids.contains(id) } }
            else { let b = r.get("revoked") == .bool(true); opts.revoked = { _, _, _ in b } }
        }
        if let h = o?.get("hardware") {
            opts.attest = { _, _ in
                if let t = h.get("throws")?.asString { throw JSError(t) }
                return attestation(h.get("result"))
            }
        }
        return verdictJSON(PCA.verifyPassport(sp, opts))
    }

    private struct LabeledStub: HardwareAttestationVerifier, AssuranceLabeled {
        let assuranceLabel: AssuranceLabel
        func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult { HardwareResult() }
    }

    private static func assurance(_ v: JSONValue?, _ label: JSONValue?) -> JSONValue {
        let verdict = PassportVerdict(ok: v?.get("ok") == .bool(true), reason: "", detail: nil, passport: v?.get("passport"), iss: v?.get("iss")?.asString ?? "", sub: v?.get("sub")?.asString ?? "",
                                      exp: int(v?.get("exp")) ?? 0, hardwareVerified: v?.get("hardware_verified") == .bool(true))
        var rp = PCA.RequirePassport(trustedIssuers: [])
        if let l = JS.present(label), l.isObject, l.get("level")?.asString != nil {
            rp.defaultHardware = DefaultHardware(verifier: LabeledStub(assuranceLabel: AssuranceLabel(level: l.get("level")!.asString!, vendor: l.get("vendor")?.asString)))
        } else if label?.asString != "no-verifier" {
            rp.defaultHardware = DefaultHardware(verifier: VendorVerifierLessStub())
        }
        let a = PCA.passportAssurance(verdict, rp)
        var o: JObject = ["level": .string(a.level ?? "unknown")]
        if let vendor = a.vendor { o["vendor"] = .string(vendor) }
        return .object(o)
    }

    /// A verifier that carries no label.
    private struct VendorVerifierLessStub: HardwareAttestationVerifier {
        func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult { HardwareResult() }
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2)
        switch c.fn {
        case "constants":
            return .value(.object(["PASSPORT_SIG_DOMAIN": .string(PCA.PASSPORT_SIG_DOMAIN), "PASSPORT_VERSION": .int(PCA.PASSPORT_VERSION), "DEFAULT_PASSPORT_EVIDENCE_AGE_MS": .int(PCA.DEFAULT_PASSPORT_EVIDENCE_AGE_MS)]))
        case "passportFingerprint": return A.run { .string(try PCAIssue.passportFingerprint(a0?.asObject ?? [:])) }
        case "issuePassport": return A.run { .object(try PCAIssue.issuePassport(a0?.asObject ?? [:])) }
        case "matchesBinding":
            return A.run {
                let r = try PCA.matchesBinding(a0, a1)
                return .object(["ok": .bool(r.ok), "reasons": .array(r.reasons.map { .string($0) })])
            }
        case "registry":
            let r = PCA.buildPassportRegistry(a0?.asArray ?? [])
            return .value(.array((a1?.asArray ?? []).map { op in
                let o = op.asArray ?? []
                switch o.first?.asString {
                case "get"?: return o.count > 1 ? (o[1].asString.flatMap { r.get($0) } ?? .null) : .null
                case "has"?: return .bool(o.count > 1 ? (o[1].asString.map { r.has($0) } ?? false) : false)
                default: return .array(r.all())
                }
            }))
        case "trustScore": return A.run { .double(PCA.trustScore(a0 ?? .null, knownOperators: (a1?.get("knownOperators")?.asArray).map { $0.compactMap { $0.asString } })) }
        case "passportEvidenceBinding":
            return A.run {
                guard let id = a0?.asString, let sub = a1?.asString, let n = a2?.asString else { throw JSError("bad args") }
                let b = PCA.passportEvidenceBinding(passportId: id, subject: sub, nonce: n)
                return .object(["holderPub": .string(b.holderPub), "grantRef": .string(b.grantRef), "epoch": .int(b.epoch), "nonce": .string(b.nonce)])
            }
        case "signPassport":
            return A.run {
                guard let p = a0?.asObject, let o = a1, let iat = int(o.get("iat")), let exp = int(o.get("exp")) else { throw JSError("bad args") }
                return try PCAIssue.signPassport(p, issuer: try key(o.get("issuerSecret"), o.get("suite")), subject: o.get("subject")?.asString ?? "", iat: iat, nbf: int(o.get("nbf")), exp: exp,
                                                 evidence: o.get("evidence")?.asObject)
            }
        case "verifyPassport": return .value(verify(a0, a1))
        case "passportAssurance": return .value(assurance(a0, a1))
        default: return nil
        }
    }

    private static func signed(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "signPassport", !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out, let alg = want["alg"]?.asString else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_sig" : "sig")
        mine[field] = nil
        want[field] = nil
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        var unbound = 0
        let n = try Base.each("ref-passport.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            if c.fn == "verifyPassport", c.arg(1)?.get("allowUnboundPq") == .bool(true), c.out.get("ok") == .bool(true) {
                guard case let .value(v)? = Self.call(c) else { XCTFail("unhandled"); return }
                XCTAssertEqual(v.get("ok"), .bool(false), c.name)
                unbound += 1
                return
            }
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            let diff = Base.diff(c, Self.signed(c, got))
            if diff != nil, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            d.add(c, diff)
        }
        XCTAssertEqual(n, 516)
        XCTAssertEqual(unbound, 1, "the case accepted by the reference only through allowUnboundPq is asserted refused")
        XCTAssertEqual(seen, ["matchesBinding": 267, "verifyPassport": 109, "trustScore": 67, "signPassport": 30, "passportFingerprint": 13, "issuePassport": 12, "passportAssurance": 8,
                              "passportEvidenceBinding": 5, "registry": 4, "constants": 1])
        d.finish(516 - 1 - d.skipped.values.reduce(0, +))
    }
}
