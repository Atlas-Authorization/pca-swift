import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the Lease.swift survivors of group 2 (path grammar, record bounds, defaults, locks, history).
/// Pinned to packages/pca-grants/src/lease.ts (path regex `^[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}$`, caps 128/256, 16 approvers).
final class S2G2LeaseKillTests: XCTestCase {
    private static let key = V2F.key("s2g2-lease-authority")
    private static var authority: String { V2F.pub(key) }
    private static let other = V2F.key("s2g2-lease-other")
    private static var otherAuthority: String { V2F.pub(other) }

    private func rep(_ n: Int) -> String { String(repeating: "a", count: n) }

    // ---- pathOk ----

    func testPathOk() {
        // grammar boundaries (lines 16, 17, 19, 21, 22)
        XCTAssertTrue(Lease.pathOk("a"), "one segment is valid (line 17: count < 1)")
        XCTAssertFalse(Lease.pathOk(""), "empty path")
        XCTAssertFalse(Lease.pathOk("a//b"), "an empty middle segment is refused (line 16/19)")
        XCTAssertFalse(Lease.pathOk("/a"), "leading slash (empty first segment)")
        XCTAssertFalse(Lease.pathOk("a/"), "trailing slash (empty last segment)")
        XCTAssertTrue(Lease.pathOk(Array(repeating: "a", count: 8).joined(separator: "/")), "8 segments are valid (line 17: > 8, 8->7)")
        XCTAssertFalse(Lease.pathOk(Array(repeating: "a", count: 9).joined(separator: "/")), "9 segments are refused (line 17)")
        XCTAssertTrue(Lease.pathOk(rep(64)), "a 64-byte segment is valid (line 19: > 64)")
        XCTAssertFalse(Lease.pathOk(rep(65)), "a 65-byte segment is refused (line 19)")
        XCTAssertTrue(Lease.pathOk("a/" + rep(64)), "a 64-byte second segment is valid")
        XCTAssertFalse(Lease.pathOk("a/" + rep(65)), "a 65-byte second segment is refused")
        // character class (line 21): each boundary byte on both sides
        let good = ["a", "z", "0", "9", "_", ".", "-", "a.b", "a-b", "a_b", "5"]
        for g in good { XCTAssertTrue(Lease.pathOk(g), "\(g) is in the class") }
        let bad = ["`", "{", "/", ":", "^", ",", "!", "A", "Z", "@", " ", "~", "a b", "é", "a!b"]
        for b in bad { XCTAssertFalse(Lease.pathOk(b), "\(b) is outside the class") }
        XCTAssertFalse(Lease.pathOk("a/`"), "backtick (96) in a later segment")
        XCTAssertFalse(Lease.pathOk("/"), "just a slash")
    }

    // ---- wellFormed ----

    private func base() -> JObject {
        ["v": .int(1), "lease_id": .string("L"), "path": .string("a/b"), "grant_ref": .string("g"), "holder": .string("h"), "requester": .string("r"),
         "approvers": .array([.string("a")]), "justification_digest": .string("j"), "seq": .int(1), "issued_at": .int(10), "renewed_at": .int(10),
         "expires_at": .int(20), "max_ttl": .int(100), "authority": .string("A")]
    }

    private func wf(_ over: JObject) -> Bool {
        var o = base()
        for (k, v) in over { o[k] = v }
        return Lease.wellFormed(.object(o)) != nil
    }

    func testWellFormedBase() {
        XCTAssertTrue(wf([:]), "the base record is well formed")
        XCTAssertFalse(wf(["v": .int(2)]))
    }

    func testWellFormedStringCaps() {
        XCTAssertTrue(wf(["lease_id": .string(rep(128))]), "lease_id 128 (line 33)")
        XCTAssertFalse(wf(["lease_id": .string(rep(129))]), "lease_id 129 (line 33)")
        XCTAssertTrue(wf(["grant_ref": .string(rep(256))]), "grant_ref 256 (line 33)")
        XCTAssertFalse(wf(["grant_ref": .string(rep(257))]), "grant_ref 257 (line 33)")
        XCTAssertTrue(wf(["holder": .string(rep(128))]), "holder 128 (line 34)")
        XCTAssertFalse(wf(["holder": .string(rep(129))]), "holder 129 (line 34)")
        XCTAssertTrue(wf(["requester": .string(rep(128))]), "requester 128 (line 34)")
        XCTAssertFalse(wf(["requester": .string(rep(129))]), "requester 129 (line 34)")
        XCTAssertTrue(wf(["authority": .string(rep(128))]), "authority 128 (line 35)")
        XCTAssertFalse(wf(["authority": .string(rep(129))]), "authority 129 (line 35)")
        XCTAssertTrue(wf(["justification_digest": .string(rep(128))]), "digest 128 (line 35)")
        XCTAssertFalse(wf(["justification_digest": .string(rep(129))]), "digest 129 (line 35)")
    }

    func testWellFormedNumbers() {
        XCTAssertFalse(wf(["seq": .int(0)]), "seq 0 refused (line 39: seq >= 1)")
        XCTAssertTrue(wf(["max_ttl": .int(1)]), "max_ttl 1 accepted (line 39: ttl >= 1)")
        XCTAssertFalse(wf(["max_ttl": .int(0)]), "max_ttl 0 refused (line 39)")
        // line 40
        XCTAssertFalse(wf(["seq": .int(2), "issued_at": .int(10), "renewed_at": .int(9), "expires_at": .int(20)]), "renewed < issued")
        XCTAssertFalse(wf(["seq": .int(2), "renewed_at": .int(10), "expires_at": .int(10)]), "expires == renewed (expires <= renewed)")
        XCTAssertFalse(wf(["seq": .int(1), "renewed_at": .int(11), "expires_at": .int(20)]), "seq 1 with renewed != issued")
        XCTAssertTrue(wf(["seq": .int(2), "renewed_at": .int(10), "expires_at": .int(11)]), "renewed == issued is fine at seq 2")
        XCTAssertTrue(wf(["seq": .int(2), "renewed_at": .int(11), "expires_at": .int(20)]), "renewed > issued is fine at seq 2")
    }

    func testWellFormedApprovers() {
        let sixteen = JSONValue.array(Array(repeating: JSONValue.string("a"), count: 16))
        let seventeen = JSONValue.array(Array(repeating: JSONValue.string("a"), count: 17))
        XCTAssertTrue(wf(["approvers": sixteen]), "16 approvers (line 9 / 41)")
        XCTAssertFalse(wf(["approvers": seventeen]), "17 approvers (line 9 / 41)")
        XCTAssertTrue(wf(["approvers": .array([.string(rep(128))])]), "approver of 128 (line 41)")
        XCTAssertFalse(wf(["approvers": .array([.string(rep(129))])]), "approver of 129 (line 41)")
        XCTAssertTrue(wf(["approvers": .array([])]), "no approvers")
    }

    func testNumDefaultsToZero() {
        XCTAssertEqual(Lease.num([:], "x"), 0, "line 28: an absent number is 0")
        XCTAssertEqual(Lease.num(["x": .string("s")], "x"), 0)
        XCTAssertEqual(Lease.num(["x": .int(7)], "x"), 7)
    }

    // ---- revocation records ----

    private func revBase() -> JObject {
        ["v": .int(1), "target": .string("lease"), "value": .string("L"), "revoked_at": .int(5), "authority": .string("A")]
    }

    private func rwf(_ over: JObject) -> Bool {
        var o = revBase()
        for (k, v) in over { o[k] = v }
        return Lease.revWellFormed(.object(o)) != nil
    }

    func testRevWellFormedCaps() {
        XCTAssertTrue(rwf([:]))
        XCTAssertTrue(rwf(["value": .string(rep(256))]), "value 256 (line 55)")
        XCTAssertFalse(rwf(["value": .string(rep(257))]), "value 257 (line 55)")
        XCTAssertTrue(rwf(["authority": .string(rep(128))]), "authority 128 (line 56)")
        XCTAssertFalse(rwf(["authority": .string(rep(129))]), "authority 129 (line 56)")
    }

    func testVerifiersRefuseNothing() {
        XCTAssertFalse(Lease.verifyLease(nil), "line 50")
        XCTAssertFalse(Lease.verifyLease(.object([:])), "line 50")
        XCTAssertFalse(Lease.verifyLeaseRevocation(nil), "line 63")
        XCTAssertFalse(Lease.verifyLeaseRevocation(.object([:])), "line 63")
    }

    func testCoversIsInclusiveOfTheRevocationInstant() {
        var l = base()
        l["issued_at"] = .int(10)
        var r = revBase()
        r["revoked_at"] = .int(10)
        XCTAssertTrue(Lease.covers(r, l), "issued_at == revoked_at is covered (line 73: >)")
        r["revoked_at"] = .int(9)
        XCTAssertFalse(Lease.covers(r, l), "issued after the revocation is not covered")
    }

    func testSodMinApprovalsZero() {
        XCTAssertEqual(Lease.sodError(requester: "r", holder: "h", approvers: [], minApprovals: 0), "minApprovals must be a positive integer", "line 85")
        XCTAssertNil(Lease.sodError(requester: "r", holder: "h", approvers: ["a"], minApprovals: 1))
    }

    func testPolicyDefaults() {
        let p = Lease.Policy(authorities: ["x"])
        XCTAssertEqual(p.minApprovals, 1, "line 104: default minApprovals")
        XCTAssertTrue(p.freshJustification, "line 104: default freshJustification")
        XCTAssertNil(p.eligibleApprovers)
        XCTAssertNil(p.maxTtlCeiling)
        XCTAssertEqual(p.authorities, ["x"])
    }

    // ---- registry ----

    private func lease(_ id: String, seq: Int64 = 1, issued: Int64 = 1000, renewed: Int64 = 1000, expires: Int64 = 1500, maxTtl: Int64 = 2000,
                       digest: String = "j") -> JSONValue {
        var l: JObject = ["v": .int(1), "lease_id": .string(id), "path": .string("svc/a"), "grant_ref": .string("g"), "holder": .string("h"), "requester": .string("r"),
                          "approvers": .array([.string("a")]), "justification_digest": .string(digest), "seq": .int(seq), "issued_at": .int(issued),
                          "renewed_at": .int(renewed), "expires_at": .int(expires), "max_ttl": .int(maxTtl), "authority": .string(Self.authority)]
        l["sig"] = .string(V2F.sign(Self.key, IV.message(Lease.DOMAIN, .object(l))!))
        return .object(l)
    }

    private func revocation(target: String, value: String, at: Int64 = 5000, signer: V2F.K? = nil, authority: String? = nil) -> JSONValue {
        let k = signer ?? Self.key
        var r: JObject = ["v": .int(1), "target": .string(target), "value": .string(value), "revoked_at": .int(at),
                          "authority": .string(authority ?? V2F.pub(k))]
        r["sig"] = .string(V2F.sign(k, IV.message(Lease.REVOKE_DOMAIN, .object(r))!))
        return .object(r)
    }

    private func reg(_ ceiling: Int64? = nil) throws -> Lease.Registry {
        try Lease.Registry(policy: Lease.Policy(authorities: [Self.authority], minApprovals: 1, maxTtlCeiling: ceiling), kv: MemoryAtomicKV())
    }

    func testFailureValuesHaveZeroDefaults() throws {
        let r = try reg()
        let a = r.accept(nil)
        XCTAssertFalse(a.ok)
        XCTAssertEqual(a.code, "bad_record")
        XCTAssertFalse(a.replaced, "line 117: replaced defaults to false")
        XCTAssertEqual(a.seq, 0, "line 118: seq defaults to 0")
        XCTAssertNil(a.reason)
        let v = r.revoke(nil)
        XCTAssertFalse(v.ok)
        XCTAssertEqual(v.code, "bad_record")
        XCTAssertEqual(v.revoked, 0, "line 125: revoked defaults to 0")
    }

    func testTtlCeilingRefusalIsNotOk() throws {
        let a = try reg(1000).accept(lease("c", maxTtl: 1001))
        XCTAssertFalse(a.ok, "line 164: ttl_ceiling is a refusal")
        XCTAssertEqual(a.code, "ttl_ceiling")
    }

    func testRenewalAtTheSameRenewedAtIsAccepted() throws {
        let r = try reg()
        XCTAssertTrue(r.accept(lease("n")).ok)
        let a = r.accept(lease("n", seq: 2, renewed: 1000, expires: 1600, digest: "j2"))
        XCTAssertTrue(a.ok, "line 181: renewed_at == current renewed_at with a later expiry extends; got \(a)")
        XCTAssertNil(a.code)
        XCTAssertEqual(a.seq, 2)
        // equal expiry is not extending
        XCTAssertEqual(r.accept(lease("n", seq: 3, renewed: 1100, expires: 1600, digest: "j3")).code, "not_extending")
        XCTAssertTrue(r.accept(lease("n", seq: 3, renewed: 1100, expires: 1700, digest: "j3")).ok)
        // earlier renewed_at than current is not extending
        XCTAssertEqual(r.accept(lease("n", seq: 4, renewed: 1050, expires: 1800, digest: "j4")).code, "not_extending")
    }

    func testHistoryRecordsEveryAcceptedRecord() throws {
        let r = try reg()
        XCTAssertEqual(r.history("h"), [])
        XCTAssertTrue(r.accept(lease("h")).ok)
        XCTAssertEqual(r.history("h"), [Lease.HistoryEntry(seq: 1, renewedAt: 1000, expiresAt: 1500, justificationDigest: "j")], "line 191")
        XCTAssertTrue(r.accept(lease("h", seq: 2, renewed: 1100, expires: 1600, digest: "j2")).ok)
        XCTAssertEqual(r.history("h"), [Lease.HistoryEntry(seq: 1, renewedAt: 1000, expiresAt: 1500, justificationDigest: "j"),
                                        Lease.HistoryEntry(seq: 2, renewedAt: 1100, expiresAt: 1600, justificationDigest: "j2")])
        XCTAssertNotNil(r.get("h"))
    }

    /// Revocations held across every shard (a lease-target revocation lives in one).
    private func total(_ r: Lease.Registry) throws -> Int { try (0..<r.shardCount).reduce(0) { $0 + (try r.shardRevocations($1)).count } }

    func testRevocationByAnUnknownAuthorityIsARefusal() throws {
        let r = try reg()
        let v = r.revoke(revocation(target: "lease", value: "x", signer: Self.other))
        XCTAssertFalse(v.ok, "line 202")
        XCTAssertEqual(v.code, "unknown_authority")
        XCTAssertEqual((try! total(r)), 0)
    }

    func testRevocationsAreDeduplicatedBySignature() throws {
        let r = try reg()
        let one = revocation(target: "lease", value: "x")
        XCTAssertTrue(r.revoke(one).ok)
        XCTAssertTrue(r.revoke(one).ok)
        XCTAssertEqual((try! total(r)), 1, "line 203: the same revocation twice is stored once")
        XCTAssertTrue(r.revoke(revocation(target: "lease", value: "y")).ok)
        XCTAssertEqual((try! total(r)), 2, "line 203: a different revocation is stored")
    }
}
