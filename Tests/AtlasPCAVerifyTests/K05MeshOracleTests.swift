import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of Mesh.swift (and the Merkle primitives it rests on: Ledger.verifyConsistency, PCA.verifyNonMembership) against the
/// TS reference (mesh.ts, ledger.ts, revocation.ts): test-data/k05-mesh.json.gz (16363 cases). The mesh verdict is compared on ok,
/// reason and hop (the reference's trace / root_principal / leaf are TS-only extras); Swift's hop -1 / empty reason are "absent".
final class K05MeshOracleTests: XCTestCase {
    static let file = "k05-mesh.json.gz"
    static let covers = ["Mesh", "Ledger", "Merkle", "RevocationStaleness", "IntentWB", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict",
                         "Ed25519Strict", "PQ", "JSONValue", "Keys"]

    /// A JS number as the reference serialises it (an integral value is an integer lexeme).
    static func num(_ d: Double) -> JSONValue {
        if d == 0 && d.sign == .minus { return .double(d) }
        return d.rounded() == d && abs(d) <= 9_007_199_254_740_991 ? .int(Int64(d)) : .double(d)
    }

    func testMeshProofs() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["verifyMeshProof"]) { c in
            let v = Mesh.verifyMeshProof(c.arg(0), trust: c.arg(1))
            var o: JObject = ["ok": .bool(v.ok)]
            if !v.reason.isEmpty { o["reason"] = .string(v.reason) }
            if v.hop >= 0 { o["hop"] = .int(Int64(v.hop)) }
            d.add(c, K05.diff(c, .value(.object(o))))
        }
        d.finish(5300)   // 5559 cases, 189 carry a lone surrogate (skipped)
    }

    func testHeadsConsistencyNonMembership() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["checkHeadAdvance", "verifyLedgerConsistency", "verifyNonMembership"]) { c in
            switch c.fn {
            case "checkHeadAdvance":
                let r = Mesh.checkHeadAdvance(c.arg(0), c.arg(1), c.arg(2))
                d.add(c, K05.diff(c, .value(r.isEmpty ? .null : .string(r))))
            case "verifyLedgerConsistency":
                d.add(c, K05.diff(c, .value(.bool(Ledger.verifyConsistency(c.arg(0), c.arg(1), c.arg(2))))))
            default:
                guard let root = c.arg(0)?.asString, let id = c.arg(2)?.asString else { d.add(c, K05.diff(c, .value(.bool(false)))); return }
                d.add(c, K05.diff(c, .value(.bool(PCA.verifyNonMembership(root: root, proof: c.arg(1) ?? .null, id: id)))))
            }
        }
        d.finish(10_200)   // 10501 cases, 188 carry a lone surrogate (skipped)
    }

    func testEffectiveAuthority() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["effectiveAuthority"]) { c in
            let (e, err) = Mesh.effective(c.arg(0))
            if !err.isEmpty { d.add(c, K05.diff(c, .value(.object(["error": .string(err)])))); return }
            var o: JObject = ["prefixes": .array(e.prefixes.map { .string($0) })]
            if e.hasAct { o["actions"] = .array(e.actions.map { .string($0) }) }
            if e.hasAud { o["audience"] = .array(e.audience.map { .string($0) }) }
            if e.hasAmount { o["maxAmount"] = Self.num(e.maxAmount) }
            if e.hasExp { o["expiresAt"] = Self.num(e.expiresAt) }
            if e.hasHops { o["maxHops"] = Self.num(e.maxHops) }
            d.add(c, K05.diff(c, .value(.object(o))))
        }
        d.finish(370)
    }

    /// a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused.
    func testEmptyHeadAdvances() {
        let j = K042.parse("{\"e\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":0,\"root\":\"\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"n\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":3,\"root\":\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"ok\":{\"oldSize\":0,\"newSize\":3,\"path\":[]},\"path\":{\"oldSize\":0,\"newSize\":3,\"path\":[\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\"]},\"old1\":{\"oldSize\":1,\"newSize\":3,\"path\":[]}}")
        let adv = { (pf: JSONValue?) in Mesh.checkHeadAdvance(j.get("e"), j.get("n"), pf) }
        XCTAssertEqual(adv(j.get("ok")), "")
        XCTAssertEqual(adv(nil), "consistency proof required for a larger head")
        XCTAssertEqual(adv(j.get("path")), "head is not consistent with the previous head (fork or rewrite)")
        XCTAssertEqual(adv(j.get("old1")), "consistency proof required for a larger head")
    }
}
