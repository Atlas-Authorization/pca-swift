import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the dispute-evidence replay `PCAEvidence.verifyEvidenceBundle` against the reference (@atlasauth/pca-evidence): the
/// whole findings report, `report_digest` included, over the section 4 chargeback walkthrough (real keys, derived from fixed seeds by the
/// generators) and its tampered / re-trusted variants. The trust spec is the reference's `EvidenceTrust` as JSON except `verifiers.<name>`:
/// a constant `{ok, reason?}` (python corpus) or the string 'ok' | 'fail' | 'throws' (java corpus). Also the COSE signed statement over the
/// bundle reference (the corpus carries the signing key as `{"$seed": label}`).
final class RefEvidenceBundleTests: XCTestCase {
    static func port(_ spec: JSONValue) -> EvidencePort {
        switch spec {
        case let .string(s):
            return { _, _ in
                if s == "throws" { throw JSError("boom") }
                return s == "ok" ? EvidenceVerdict(ok: true) : EvidenceVerdict(ok: false, reason: "port refused")
            }
        default:
            let ok = spec.get("ok") == .bool(true)
            let reason = spec.get("reason")?.asString ?? ""
            return { _, _ in EvidenceVerdict(ok: ok, reason: reason) }
        }
    }

    static func ports(_ trust: JSONValue?) -> EvidencePorts {
        var p = EvidencePorts()
        guard let v = trust?.get("verifiers")?.asObject else { return p }
        for (k, spec) in v {
            switch k.s {
            case "sessionRoot": p.sessionRoot = port(spec)
            case "schema": p.schema = port(spec)
            case "receipt": p.receipt = port(spec)
            case "fact": p.fact = port(spec)
            case "classifier": p.classifier = port(spec)
            case "offerSet": p.offerSet = port(spec)
            case "labels": p.labels = port(spec)
            case "effect": p.effect = port(spec)
            case "verdict": p.verdict = port(spec)
            case "settlement": p.settlement = port(spec)
            default: break
            }
        }
        return p
    }

    static func replay(_ file: String, min: Int) throws {
        try K042.requireCovers(["EvidenceBundle", "EvidenceWire", "IntentStatement", "Evidence"])
        let d = Base.Diffs()
        try Base.each(file, ["verifyEvidenceBundle"]) { c in
            var trust = c.arg(1)
            if trust == .null { trust = nil }
            if case var .object(o)? = trust { o[JKey("verifiers")] = nil; trust = .object(o) }
            let got = Ref.v { try PCAEvidence.verifyEvidenceBundle(c.arg(0), trust: trust, ports: ports(c.arg(1))) }
            d.add(c, Base.diff(c, got))
        }
        d.finish(min)
    }

    func testBundlePython() throws { try Self.replay("ref-evidence-bundle-py.json.gz", min: 150) }

    func testBundleJavaExtra2() throws { try Self.replay("ref-evidence-java-extra2.json.gz", min: 150) }

    func testSignedStatement() throws {
        let d = Base.Diffs()
        try Base.each("ref-evidence-java-extra.json.gz", ["evidenceSignedStatement"]) { c in
            let spec = c.arg(1)
            guard let signer = try? RefScittTests.signer(spec) else { d.skip("no key"); return }
            let got = Ref.v {
                Base.bytesValue(try PCAEvidence.evidenceSignedStatement(c.arg(0), signer: signer, issuer: spec?.get("issuer")?.asString ?? "",
                                                                      subject: spec?.get("subject")?.asString))
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(16)
    }

    func testEvidenceBundleFailClosed() throws {
        // not a bundle: a failed shape finding, never a pass
        let r = try PCAEvidence.verifyEvidenceBundle(.object([:]))
        XCTAssertEqual(r.get("ok"), .bool(false))
        XCTAssertEqual(r.get("consistent"), .bool(false))
        // a malformed trust input fails the whole replay closed
        let t = try PCAEvidence.verifyEvidenceBundle(.object([:]), trust: .object(["acc": .object(["x": .int(1)])]))
        XCTAssertEqual(t.get("findings")?.asArray?.first?.get("code"), .string("trust.acc"))
        XCTAssertThrowsError(try PCAEvidence.verifyEvidenceBundle(.object([:]), trust: .string("x")))
        // the statement signer refuses a malformed bundle
        XCTAssertThrowsError(try PCAEvidence.evidenceSignedStatement(nil, signer: .eddsa(try Ed25519Deterministic.key(seed: [UInt8](repeating: 7, count: 32))), issuer: "i"))
    }
}
