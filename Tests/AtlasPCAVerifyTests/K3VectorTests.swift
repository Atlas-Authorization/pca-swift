import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED K3 operational-plane vectors (packages/pca/conformance/k3-vectors.json): consistency tokens, policy
/// bundles, the decision log, list receipts and cursors, and the grant-management signatures. Every expected value
/// (codes, reasons, digests) is compared exactly; a kind the runner does not know fails the test.
final class K3VectorTests: XCTestCase {
    static let kinds = [
        "fresh_at_verify", "fresh_at_digest", "fresh_at_check", "bundle_digest", "bundle_verify", "log_commit", "log_head_verify",
        "log_inclusion", "log_batch_verify", "list_objects_digest", "list_receipt_verify", "list_bind", "list_cursor_verify",
        "authority_digest", "authority_compare", "amend_verify", "revoke_verify", "need_approve_verify",
    ]

    private func o(_ kv: KeyValuePairs<String, JSONValue>) -> JSONValue {
        var m: JObject = [:]
        for (k, v) in kv { m[JKey(k)] = v }
        return .object(m)
    }
    private func s(_ v: String?) -> JSONValue { v.map { JSONValue.string($0) } ?? .null }
    private func b(_ v: Bool) -> JSONValue { .bool(v) }
    private func n(_ v: Int64) -> JSONValue { .int(v) }

    /// The result of one primitive, in the shape of the vector's `expect`.
    private func run(_ kind: String, _ i: JSONValue) -> JSONValue? {
        let signer = i.get("signer")?.asString ?? ""
        switch kind {
        case "fresh_at_verify":
            return o(["valid": b(FreshAt.verify(i.get("token"), signer: signer))])
        case "fresh_at_digest":
            return o(["digest": s(i.get("token").flatMap { FreshAt.digest($0) })])
        case "fresh_at_check":
            let opt = i.get("options")
            guard let now = IV.safe(opt?.get("now")) else { return nil }
            var maxAge: Int64?
            if let m = opt?.get("maxTokenAgeMs") { guard let d = IV.safe(m) else { return nil }; maxAge = Int64(d) }
            let v = FreshAt.check(i.get("token"), local: FreshAt.State(json: i.get("local")), signer: opt?.get("signer")?.asString ?? "",
                                  scope: opt?.get("scope")?.asString ?? "", now: Int64(now), maxTokenAgeMs: maxAge)
            switch v {
            case .ok: return o(["decision": s("ok")])
            case let .escalate(behind): return o(["decision": s("escalate"), "code": s("stale_state"), "behind": .array(behind.map { JSONValue.string($0) })])
            case let .deny(code): return o(["decision": s("deny"), "code": s(code)])
            }
        case "bundle_digest":
            return o(["digest": s(K3.bundleDigest(i.get("bundle")))])
        case "bundle_verify":
            let opt = i.get("options")
            var last: (revision: Int64, digest: String)?
            if let l = opt?.get("last") {
                guard let r = K3Sig.safeInt(l.get("revision")), let d = l.get("digest")?.asString else { return nil }
                last = (r, d)
            }
            let ov = K3.BundleOptions(signers: (opt?.get("signers")?.asArray ?? []).compactMap { $0.asString },
                                      threshold: IV.safe(opt?.get("threshold")).map { Int64($0) },
                                      verifierVersion: opt?.get("verifierVersion")?.asString ?? "", last: last)
            let r = K3.verifyBundle(i.get("bundle"), ov)
            return r.ok ? o(["ok": b(true), "revision": n(r.revision), "digest": s(r.digest), "signers": .array(r.signers.map { JSONValue.string($0) })])
                        : o(["ok": b(false), "code": s(r.code), "reason": s(r.reason)])
        case "log_commit":
            return o(["commit": s(K3.recordCommit(i.get("record")))])
        case "log_head_verify":
            return o(["valid": b(K3.verifyLogHead(i.get("head"), signer: signer))])
        case "log_inclusion":
            return o(["valid": b(K3.verifyRecordInclusion(i.get("record"), proof: i.get("proof"), head: i.get("head"), signer: signer))])
        case "log_batch_verify":
            let r = K3.verifyBatch(i.get("batch"), state: i.get("state"), signer: signer)
            return r.ok ? o(["ok": b(true), "next": n(r.next), "lastCommit": s(r.lastCommit)]) : o(["ok": b(false), "reason": s(r.reason)])
        case "list_objects_digest":
            return o(["digest": s(K3.objectsDigest(i.get("objects")?.asArray ?? []))])
        case "list_receipt_verify":
            return o(["valid": b(K3.verifyListReceipt(i.get("receipt"), signer: signer, objects: i.get("objects")?.asArray))])
        case "list_bind":
            return o(["digest": s(K3.listBind(i.get("bind")))])
        case "list_cursor_verify":
            let r = K3.verifyListCursor(i.get("cursor"), signer: signer, bind: i.get("bind"))
            if !r.ok { return o(["ok": b(false), "reason": s(r.reason)]) }
            return r.inner.map { o(["ok": b(true), "inner": s($0), "skip": n(r.skip)]) } ?? o(["ok": b(true), "skip": n(r.skip)])
        case "authority_digest":
            return o(["digest": s(K3.authorityDigest(i.get("authority")))])
        case "authority_compare":
            return o(["order": s(K3.compareAuthority(i.get("old"), i.get("new")))])
        case "amend_verify":
            let r = K3.verifyAmendment(i.get("grant"), i.get("request"), stepUpOk: i.get("step_up_ok") == .bool(true))
            return r.ok ? o(["ok": b(true), "widens": b(r.widens), "next_digest": s(r.digest)]) : o(["ok": b(false), "code": s(r.code)])
        case "revoke_verify":
            let r = K3.verifyRevokeSignature(i.get("root"), scope: i.get("scope"), sig: i.get("sig"))
            return r.ok ? o(["ok": b(true), "scope": s(r.scope)]) : o(["ok": b(false), "code": s(r.code)])
        case "need_approve_verify":
            let r = K3.verifyNeedApproval(i.get("need_request"), grant: i.get("grant"), approved: i.get("approved"), sig: i.get("sig"), stepUpOk: i.get("step_up_ok") == .bool(true))
            return r.ok ? o(["ok": b(true), "authority_digest": s(r.digest)]) : o(["ok": b(false), "code": s(r.code)])
        default:
            return nil
        }
    }

    func testK3Vectors() throws {
        let doc = try ConformanceTests.load("k3-vectors.json")
        let prim = doc.get("primitives")?.asObject ?? [:]
        XCTAssertEqual(Set(prim.keys.map { $0.s }), Set(Self.kinds), "k3-vectors.json carries kinds this runner does not replay (or lacks some)")
        var ran = 0
        var failures: [String] = []
        for kind in Self.kinds {
            let cases = prim[JKey(kind)]?.asArray ?? []
            XCTAssertFalse(cases.isEmpty, "\(kind): no vectors")
            for c in cases {
                ran += 1
                let name = "\(kind)/\(c.get("name")?.asString ?? "?")"
                guard let input = c.get("input"), let want = c.get("expect") else { failures.append("\(name): malformed vector"); continue }
                guard let got = run(kind, input) else { failures.append("\(name): runner could not read the input"); continue }
                if !Predicates.deepEq(got, want) {
                    failures.append("\(name): got \((try? Canonical.canonicalizeStrict(got)) ?? "?") want \((try? Canonical.canonicalizeStrict(want)) ?? "?")")
                }
            }
        }
        XCTAssertGreaterThan(ran, 100)
        XCTAssertTrue(failures.isEmpty, "\(failures.count) of \(ran) K3 vectors failed:\n" + failures.joined(separator: "\n"))
    }

    /// Every function is total: hostile or absent input returns the failure value (never a trap).
    func testMalformedInputIsRefused() {
        let junk: [JSONValue?] = [nil, .null, .bool(true), .int(7), .string("x"), .array([]), .object([:]), .object(["v": .int(1)])]
        for j in junk {
            XCTAssertFalse(FreshAt.verify(j, signer: "k"))
            XCTAssertEqual(FreshAt.check(j, local: FreshAt.State(json: nil), signer: "k", scope: "s", now: 0), .deny(code: "bad_token"))
            XCTAssertFalse(K3.verifyLogHead(j, signer: "k"))
            XCTAssertFalse(K3.verifyRecordInclusion(j, proof: j, head: j, signer: "k"))
            XCTAssertFalse(K3.verifyBatch(j, state: j, signer: "k").ok)
            XCTAssertFalse(K3.verifyListReceipt(j, signer: "k"))
            XCTAssertFalse(K3.verifyListCursor(j, signer: "k").ok)
            XCTAssertFalse(K3.verifyBundle(j, K3.BundleOptions(signers: ["k"], threshold: 1, verifierVersion: "1.0.0")).ok)
            XCTAssertFalse(K3.verifyAmendment(j, j, stepUpOk: true).ok)
            XCTAssertFalse(K3.verifyRevokeSignature(j, scope: j, sig: j).ok)
            XCTAssertFalse(K3.verifyNeedApproval(j, grant: j, approved: j, sig: j, stepUpOk: true).ok)
            XCTAssertEqual(K3.compareAuthority(j, j), "incomparable")
        }
        XCTAssertEqual(K3.compareVersion("0.5.0", "0.5"), 0)
        XCTAssertEqual(K3.compareVersion("0.10.0", "0.9.9"), 1)
        XCTAssertEqual(K3.compareVersion("1", "1.0.1"), -1)
        XCTAssertTrue(K3.validVersion("1.2.3.4"))
        XCTAssertFalse(K3.validVersion("1.2.3.4.5"))
        XCTAssertFalse(K3.validVersion("1."))
        XCTAssertFalse(K3.validVersion("1234567"))
    }
}
