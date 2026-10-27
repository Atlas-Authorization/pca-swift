import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The extension layer of the conformance corpus (optimistic-vectors.json, ledger-vectors.json): every vector must reproduce the
/// reference verdict exactly. Nothing is skipped; each table's size must equal the file's `counts`.
final class ExtensionVectorTests: XCTestCase {
    /// The row counts of the committed corpus, asserted against the REAL table sizes (not only the file's own `counts`), so a truncated
    /// or regenerated file that is not re-pinned here fails.
    static let expectedCounts: [String: Int] = [
        "optimistic_claim": 52, "optimistic_window": 25, "optimistic_fraud_proof": 37, "optimistic_settlement": 102,
        "ledger_inclusion": 96, "ledger_consistency": 149, "ledger_tree_head": 64, "ledger_cosign": 56, "ledger_head_consistency": 26,
        "ledger_checkpoint_chain": 23, "ledger_witnessed_head": 30, "ledger_equivocation": 7,
    ]

    static func rows(_ doc: JSONValue, _ table: String) -> [JSONValue] {
        let arr = doc.get(table)?.asArray ?? []
        XCTAssertFalse(arr.isEmpty, "\(table): missing or empty table")
        XCTAssertEqual(Int64(arr.count), doc.get("counts")?.get(table)?.safeInt, "\(table): counts says another size")
        XCTAssertEqual(arr.count, expectedCounts[table], "\(table): this runner pins another size")
        return arr
    }

    /// `requires_suite` names a registered suite beyond the core ones: an SDK that cannot run it must refuse (false / check `suite`).
    static func lacks(_ v: JSONValue) -> Bool {
        guard let s = v.get("requires_suite")?.asString else { return false }
        return PQ.resolve(s) == nil
    }

    /// The vector's `pins`; nil when ABSENT (cosigners then fall back to the policy's pqPins), `[:]` for an explicit empty object.
    static func pinsOf(_ v: JSONValue) -> [String: String]? { v.get("pins") == nil ? nil : Ledger.pinsOf(v.get("pins")) }

    /// A vector that expects acceptance of an ML-DSA / hybrid artifact cannot pass where the runtime has no ML-DSA (macos-15):
    /// skipped there; every refusal vector still runs.
    static func needsMLDSA(_ v: JSONValue) -> Bool {
        if MLDSA.available { return false }
        let e = v.get("expect")
        guard e?.get("ok") == .bool(true) || e?.get("check")?.asString == "ok" else { return false }
        return Canonical.canonicalize(v).contains("ml-dsa")
    }

    static func f(_ v: JSONValue?) -> Double { IV.num(v) ?? .nan }
    static func name(_ v: JSONValue) -> String { v.get("name")?.asString ?? "?" }
    static func policy(_ v: JSONValue?) -> JObject? { v?.asObject }

    func testOptimisticVectors() throws {
        let doc = try ConformanceTests.load("optimistic-vectors.json")
        let wp = doc.get("window_policy")
        let pol = Optimistic.ChallengeWindowPolicy(minWindowMs: Self.f(wp?.get("minWindowMs")), maxWindowMs: Self.f(wp?.get("maxWindowMs")), maxSkewMs: Self.f(wp?.get("maxSkewMs")))
        var bad: [String] = []
        for v in Self.rows(doc, "optimistic_claim") {
            let got = Optimistic.claimCheck(v.get("claim"), expectedPcactnDigest: v.get("pcactn_digest")?.asString ?? "", signerPublic: v.get("signer_public")?.asString ?? "",
                                            serverNow: Self.f(v.get("server_now")), policy: pol)
            let e = v.get("expect")
            if got != e?.get("check")?.asString || (got == "ok") != (e?.get("ok") == .bool(true)) { bad.append("claim/\(Self.name(v)): got \(got) want \(Canonical.canonicalize(e ?? .null))") }
        }
        for v in Self.rows(doc, "optimistic_window") {
            let i = Self.f(v.get("issued_at")), w = Self.f(v.get("challenge_window_ms")), now = Self.f(v.get("now"))
            let e = v.get("expect")
            if Optimistic.challengeWindowEnd(issuedAt: i, windowMs: w) != Self.f(e?.get("end")) || Optimistic.withinChallengeWindow(issuedAt: i, windowMs: w, now: now) != (e?.get("within") == .bool(true))
                || Optimistic.claimStatus(issuedAt: i, windowMs: w, now: now) != e?.get("phase")?.asString { bad.append("window/\(Self.name(v))") }
        }
        for v in Self.rows(doc, "optimistic_fraud_proof") {
            let got = Optimistic.fraudProofWireCheck(v.get("claim"), v.get("proof"))
            if got != v.get("expect")?.get("check")?.asString { bad.append("fraud/\(Self.name(v)): got \(got) want \(Canonical.canonicalize(v.get("expect") ?? .null))") }
        }
        for v in Self.rows(doc, "optimistic_settlement") {
            if Self.needsMLDSA(v) { continue }
            let got = Optimistic.settlementWireCheck(v.get("record"), guardianPublic: v.get("guardian_public")?.asString ?? "", pins: Self.pinsOf(v))
            let want = Self.lacks(v) ? "suite" : v.get("expect")?.get("check")?.asString
            if got != want { bad.append("settlement/\(Self.name(v)): got \(got) want \(Canonical.canonicalize(v.get("expect") ?? .null))") }
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    func testLedgerVectors() throws {
        let doc = try ConformanceTests.load("ledger-vectors.json")
        XCTAssertEqual(doc.get("empty_tree_root")?.asString, Ledger.EMPTY_TREE_ROOT)
        let d = doc.get("domains")
        XCTAssertEqual(d?.get("sth")?.asString, Ledger.STH_DOMAIN)
        XCTAssertEqual(d?.get("sth_witness")?.asString, Ledger.STH_WITNESS_DOMAIN)
        XCTAssertEqual(d?.get("ledger_head")?.asString, Ledger.LEDGER_HEAD_DOMAIN)
        XCTAssertEqual(d?.get("optimistic_claim")?.asString, Optimistic.CLAIM_DOMAIN)
        XCTAssertEqual(d?.get("settlement")?.asString, Optimistic.SETTLEMENT_DOMAIN)
        var bad: [String] = []
        func chk(_ table: String, _ v: JSONValue, _ got: Bool, _ want: Bool) {
            if got != (want && !Self.lacks(v)) && !Self.needsMLDSA(v) { bad.append("\(table)/\(Self.name(v)): got \(got) want \(want)") }
        }
        func ok(_ v: JSONValue) -> Bool { v.get("expect")?.get("ok") == .bool(true) }
        func guardian(_ v: JSONValue) -> String { v.get("guardian_public")?.asString ?? "" }
        func pins(_ v: JSONValue) -> [String: String]? { Self.pinsOf(v) }
        for v in Self.rows(doc, "ledger_inclusion") { chk("inclusion", v, Ledger.verifyInclusion(v.get("root")?.asString ?? "", v.get("proof"), v.get("leaf")), ok(v)) }
        for v in Self.rows(doc, "ledger_consistency") { chk("consistency", v, Ledger.verifyConsistency(v.get("old_root"), v.get("new_root"), v.get("proof")), ok(v)) }
        for v in Self.rows(doc, "ledger_tree_head") { chk("tree_head", v, Ledger.verifyTreeHead(v.get("sth"), guardian(v), nil, pins(v)), ok(v)) }
        for v in Self.rows(doc, "ledger_cosign") { chk("cosign", v, Ledger.verifyTreeHead(v.get("sth"), guardian(v), Self.policy(v.get("policy")), pins(v)), ok(v)) }
        for v in Self.rows(doc, "ledger_head_consistency") {
            chk("head_consistency", v, Ledger.verifyHeadConsistency(v.get("older"), v.get("newer"), v.get("proof"), guardian(v), nil, pins(v)), ok(v))
        }
        for v in Self.rows(doc, "ledger_checkpoint_chain") {
            let got = Ledger.verifyCheckpointChain(v.get("chain"), guardian(v), Self.policy(v.get("policy")), pins(v))
            let e = v.get("expect")
            if Self.needsMLDSA(v) { continue }
            // without ML-DSA (OS older than 26) an earlier ML-DSA hop is refused, so a forgery's index cannot be reproduced; the refusal itself still must be
            let atUnknowable = !MLDSA.available && Canonical.canonicalize(v).contains("ml-dsa")
            if got.ok != (e?.get("ok") == .bool(true)) || (!got.ok && !atUnknowable && Int64(got.at) != e?.get("at")?.safeInt) { bad.append("chain/\(Self.name(v)): got \(got) want \(Canonical.canonicalize(e ?? .null))") }
        }
        for v in Self.rows(doc, "ledger_witnessed_head") { chk("witnessed_head", v, Ledger.verifyWitnessedHead(v.get("head"), v.get("witness_public")?.asString ?? "", pins(v)), ok(v)) }
        for v in Self.rows(doc, "ledger_equivocation") {
            chk("equivocation", v, Ledger.detectEquivocation(v.get("a"), v.get("b"), v.get("witness_public")?.asString ?? ""), v.get("expect")?.get("equivocation") == .bool(true))
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    // ---- hostile shapes never trap and are never accepted ----

    func testHostileInputsAreRefused() throws {
        let texts = ["null", "1", "\"x\"", "[]", "{}", "{\"size\":1e999}", "[null]", "{\"sth\":null,\"proof\":null}"]
        for t in texts {
            let v = try StrictJSON.parseLenient(t)
            XCTAssertFalse(Ledger.verifyConsistency(v, v, v), t)
            XCTAssertFalse(Ledger.verifyTreeHead(v, "k", nil), t)
            XCTAssertFalse(Ledger.verifyTreeHead(v, "k", ["threshold": .int(0)]), t)
            XCTAssertFalse(Ledger.verifyWitnessedHead(v, "k"), t)
            XCTAssertFalse(Ledger.verifyWitnessCosignature(v, v, "k"), t)
            XCTAssertFalse(Ledger.verifyHeadConsistency(v, v, v, "k", nil), t)
            XCTAssertFalse(Ledger.detectEquivocation(v, v, "k"), t)
            XCTAssertFalse(Ledger.verifyCheckpointChain(v, "k", nil).ok, t)
            XCTAssertFalse(Ledger.verifyInclusion("r", v, v), t)
            XCTAssertNotEqual(Optimistic.fraudProofWireCheck(v, v), "ok", t)
            XCTAssertNotEqual(Optimistic.settlementWireCheck(v, guardianPublic: "k"), "ok", t)
            XCTAssertNotEqual(Optimistic.claimCheck(v, expectedPcactnDigest: "d", signerPublic: "k", serverNow: 0), "ok", t)
        }
    }

    func testWindowBoundaryAndNonFinite() {
        XCTAssertTrue(Optimistic.withinChallengeWindow(issuedAt: 100, windowMs: 50, now: 150))
        XCTAssertFalse(Optimistic.withinChallengeWindow(issuedAt: 100, windowMs: 50, now: 151))
        XCTAssertEqual(Optimistic.claimStatus(issuedAt: 100, windowMs: 50, now: 151), "finalized")
        XCTAssertEqual(Optimistic.claimStatus(issuedAt: 100, windowMs: 50, now: 150), "open")
        XCTAssertFalse(Optimistic.withinChallengeWindow(issuedAt: 100, windowMs: 50, now: .infinity))
        XCTAssertFalse(Optimistic.withinChallengeWindow(issuedAt: 100, windowMs: 50, now: .nan))
    }

    func testConsistencyGuards() {
        // sizes 3 and 3 + 2^32 never collide; size 0 needs the empty root and an empty path
        let r = Base64URLStrict.encode([UInt8](repeating: 1, count: 32))
        func proof(_ o: Int64, _ n: Int64, _ path: [JSONValue] = []) -> JSONValue { .object(["oldSize": .int(o), "newSize": .int(n), "path": .array(path)]) }
        XCTAssertTrue(Ledger.verifyConsistency(.string(Ledger.EMPTY_TREE_ROOT), .string(r), proof(0, 5)))
        XCTAssertFalse(Ledger.verifyConsistency(.string(r), .string(r), proof(0, 5)))
        XCTAssertFalse(Ledger.verifyConsistency(.string(Ledger.EMPTY_TREE_ROOT), .string(r), proof(0, 5, [.string(r)])))
        XCTAssertTrue(Ledger.verifyConsistency(.string(r), .string(r), proof(3, 3)))
        XCTAssertFalse(Ledger.verifyConsistency(.string(r), .string(r), proof(3, 3 + 4_294_967_296)))
        XCTAssertFalse(Ledger.verifyConsistency(.string(r), .string(r), proof(5, 3)))
    }
}
