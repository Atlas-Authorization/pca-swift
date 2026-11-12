import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of ProvenanceGate.swift against the TS reference (provenance-gate.ts): test-data/k05-provgate.json.gz (4616
/// cases: facts / policy shape, the gate over every refusal code and a seeded random walk, RFC 9162 inclusion proofs real and
/// tampered, the leaf hash and the caveat builder). Inclusion args are the wire form (leaf b64u, index, size, [proof b64u], root b64u);
/// an index or size that is not a JSON integer cannot reach the Int64 API (the reference returns false for those).
final class K05ProvGateOracleTests: XCTestCase {
    static let file = "k05-provgate.json.gz"
    static let covers = ["ProvenanceGate", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "JSONValue"]

    static func b64(_ v: JSONValue?) -> [UInt8]? {
        guard let s = v?.asString else { return nil }
        return s.isEmpty ? [] : Base64URLStrict.decode(s)
    }

    static func integer(_ v: JSONValue?) -> Int64? {
        guard let d = IV.num(v), d.isFinite, d.rounded(.towardZero) == d, abs(d) < 9.2e18 else { return nil }
        return Int64(d)
    }

    func testShapesAndGate() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["provenanceFactsError", "provenancePolicyError", "provenanceGate"]) { c in
            switch c.fn {
            case "provenanceFactsError": d.add(c, K05.diff(c, .value(K05.opt(PCA.provenanceFactsError(c.arg(0))))))
            case "provenancePolicyError": d.add(c, K05.diff(c, .value(K05.opt(PCA.provenancePolicyError(c.arg(0))))))
            default:
                let r = PCA.provenanceGate(c.arg(0))
                let got: JSONValue = r.ok ? .object(["ok": .bool(true), "level": .int(r.level), "claims": .object(r.claims)])
                    : .object(["ok": .bool(false), "code": .string(r.code)])
                d.add(c, K05.diff(c, .value(got)))
            }
        }
        d.finish(3400)   // 3538 cases, 98 carry a lone surrogate (skipped)
    }

    func testInclusionLeafHashAndCaveat() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["verifyRfc9162Inclusion", "rfc9162LeafHash", "provenanceCaveat"]) { c in
            switch c.fn {
            case "verifyRfc9162Inclusion":
                guard let leaf = Self.b64(c.arg(0)), let root = Self.b64(c.arg(4)), let ps = c.arg(3)?.asArray else { d.skip("inclusion: undecodable wire args"); return }
                let proof = ps.compactMap { Self.b64($0) }
                guard proof.count == ps.count else { d.skip("inclusion: undecodable proof element"); return }
                guard let i = Self.integer(c.arg(1)), let n = Self.integer(c.arg(2)) else { d.add(c, K05.diff(c, .value(.bool(false)))); return }
                d.add(c, K05.diff(c, .value(.bool(PCA.verifyRfc9162Inclusion(leafHash: leaf, index: i, size: n, proof: proof, root: root)))))
            case "rfc9162LeafHash":
                guard let data = Self.b64(c.arg(0)) else { d.skip("leaf hash: undecodable data"); return }
                d.add(c, K05.diff(c, .value(K05.bytesValue(PCA.rfc9162LeafHash(data)))))
            default:
                guard let o = c.arg(0)?.asObject, let issuer = o["issuer"]?.asString, let lvl = IV.int(o["min_level"]) else { d.skip("caveat: options outside the typed struct"); return }
                var opt = ProvenanceCaveatOptions(issuer: issuer, minLevel: lvl)
                opt.id = o["id"]?.asString
                opt.sourceRepo = o["source_repo"]?.asString
                opt.builderIds = o["builder_ids"]?.asArray?.compactMap { $0.asString }
                opt.oidcIssuer = o["oidc_issuer"]?.asString
                if case let .bool(b)? = o["require_runtime"] { opt.requireRuntime = b }
                opt.bind = o["bind"]?.asString
                opt.ttlMs = IV.int(o["ttl_ms"])
                d.add(c, K05.diff(c, .value(PCA.provenanceCaveat(opt))))
            }
        }
        d.finish(1070)
    }
}
