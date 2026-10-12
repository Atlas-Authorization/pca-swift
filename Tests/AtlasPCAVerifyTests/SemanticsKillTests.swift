import XCTest
@testable import AtlasPCAVerify

/// Semantics the shared corpus does not decide on its own: the Verdict reason, the typed Ed25519 threshold path, every
/// registered pq_pk length, the unsigned `threshold` slot staying outside the strict-canonical body, field folding of
/// non-canonical sums.
final class SemanticsKillTests: XCTestCase {
    static let ORDER = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"]

    /// allow => reason ""; deny => the reason names the FIRST failing check (normative order).
    func testVerdictReasonIsTheFirstFailingCheck() throws {
        let doc = try ConformanceTests.load("vectors.json")
        var ran = 0, denies = 0
        for v in doc.get("vectors")?.asArray ?? [] {
            guard let pc = v.get("pcactn"), let grant = v.get("grant"), let now = v.get("context")?.get("now")?.safeInt,
                  let aud = v.get("context")?.get("aud")?.asString, !ConformanceTests.hasSentinel(v),
                  ConformanceTests.unsupportedSuite(v) == nil else { continue }
            let r = PCA.verify(pcactn: pc, grant: grant, now: now, audience: aud)
            ran += 1
            let name = v.get("name")?.asString ?? "?"
            if r.allow { XCTAssertEqual(r.reason, "", name); continue }
            denies += 1
            let first = Self.ORDER.first { r.checks[$0] == false }
            XCTAssertNotNil(first, name)
            XCTAssertTrue(r.reason.hasPrefix("\(first ?? "?"):"), "\(name): \(r.reason)")
        }
        XCTAssertGreaterThan(ran, 100); XCTAssertGreaterThan(denies, 50)
    }

    /// `threshold` (like `sig` / `pq_sig`) is unsigned: an out-of-profile value inside it never fails the strict body check.
    func testThresholdSlotIsOutsideTheStrictBody() throws {
        let doc = try ConformanceTests.load("vectors.json")
        guard let v = (doc.get("vectors")?.asArray ?? []).first(where: { $0.get("name")?.asString == "valid-in-plan-action" }),
              var pc = v.get("pcactn")?.asObject, let grant = v.get("grant"),
              let now = v.get("context")?.get("now")?.safeInt, let aud = v.get("context")?.get("aud")?.asString else { return XCTFail("vector") }
        XCTAssertTrue(PCA.verify(pcactn: .object(pc), grant: grant, now: now, audience: aud).allow)
        pc["threshold"] = .object([JKey("shares"): .array([]), JKey("x"): .double(-0.0), JKey("y"): .int(Int64.max)])
        let r = PCA.verify(pcactn: .object(pc), grant: grant, now: now, audience: aud)
        XCTAssertEqual(r.checks["wire"], true, r.reason)
        XCTAssertTrue(r.allow, r.reason)
        // ... but the same value in a SIGNED slot is a wire failure
        var pc2 = pc; pc2.removeValue(forKey: "threshold")
        pc2["risk_claim"] = .object([JKey("r"): .int(0), JKey("inputs"): .object([JKey("x"): .double(-0.0)])])
        XCTAssertEqual(PCA.verify(pcactn: .object(pc2), grant: grant, now: now, audience: aud).checks, ["wire": false])
    }

    /// The typed Ed25519 path (`Threshold.verify`) counts a correctly signed share and refuses it over another message.
    func testTypedThresholdVerify() throws {
        let doc = try ConformanceTests.load("vectors.json")
        var ran = 0, ranPqElsewhere = 0
        for v in doc.get("primitives")?.get("threshold_set")?.asArray ?? [] {
            guard case .bool(true)? = v.get("valid"), let roleS = v.get("role")?.asString, let role = Threshold.Role(rawValue: roleS),
                  let t = v.get("t")?.safeInt, let set = v.get("signer_set")?.asArray, let share = v.get("share"),
                  share.get("alg") == nil, let pk = share.get("publicKey")?.asString, let sig = share.get("sig")?.asString,
                  let tm = v.get("threshold_message")?.asString.flatMap({ Base64URLStrict.decode($0) }) else { continue }
            var typed: [Threshold.Signer] = []
            var ok = true
            for m in set {
                guard let r = m.get("role")?.asString.flatMap(Threshold.Role.init(rawValue:)), let k = m.get("publicKey")?.asString else { ok = false; break }
                typed.append(Threshold.Signer(role: r, publicKey: k, pqPk: m.get("pq_pk")?.asString))
            }
            if !ok || typed.contains(where: { $0.role == role && $0.pqPk != nil }) { continue }
            ran += 1
            if typed.contains(where: { $0.pqPk != nil }) { ranPqElsewhere += 1 }
            let good = Threshold.verify([Threshold.Share(role: role, publicKey: pk, sig: sig)], tm, typed, Int(t))
            XCTAssertEqual(good.roles, [role], v.get("name")?.asString ?? "")
            XCTAssertEqual(good.count, 1)
            XCTAssertEqual(good.ok, t == 1)
            let bad = Threshold.verify([Threshold.Share(role: role, publicKey: pk, sig: sig)], tm + [0], typed, Int(t))
            XCTAssertEqual(bad.roles, []); XCTAssertFalse(bad.ok); XCTAssertEqual(bad.count, 0)
        }
        XCTAssertGreaterThanOrEqual(ran, 4)
        XCTAssertGreaterThanOrEqual(ranPqElsewhere, 1) // an Ed25519 role in a set where ANOTHER role registers pq_pk still counts
    }

    func testTypedThresholdSignerSetRules() {
        let k1 = String(repeating: "A", count: 43), k2 = "B" + String(repeating: "A", count: 42)
        let a = Threshold.Signer(role: .agent, publicKey: k1), g = Threshold.Signer(role: .guardian, publicKey: k1)
        let bad = Threshold.verify([], [1], [a, g], 1)
        XCTAssertEqual(bad.reason, "signer set registers one key under two roles")
        XCTAssertEqual(bad.count, 0); XCTAssertFalse(bad.ok)
        XCTAssertEqual(Threshold.verify([], [1], [a, a], 1).reason, "only 0 distinct valid key(s), need 1")
        XCTAssertEqual(Threshold.verify([], [1], [a, Threshold.Signer(role: .agent, publicKey: k2)], 1).reason, "signer set registers more than one key for role agent")
        let t0 = Threshold.verify([], [1], [a], 0)
        XCTAssertEqual(t0.reason, "invalid threshold t=0 (must be 1, 2 or 3)"); XCTAssertEqual(t0.count, 0)
        XCTAssertEqual(Threshold.verify([], [1], [a], 4).count, 0)
    }

    /// Every registered PQ public-key length is accepted in a signer set; one byte more or less is refused.
    func testRegisteredPqKeyLengths() {
        let k = String(repeating: "A", count: 43)
        func set(_ n: Int) -> [JSONValue] {
            [.object([JKey("role"): .string("agent"), JKey("publicKey"): .string(k), JKey("pq_pk"): .string(Base64URLStrict.encode([UInt8](repeating: 7, count: n)))])]
        }
        XCTAssertEqual(Threshold.PQ_PK_LENGTHS, [1952, 2592, 32, 64, 897, 1793, 97484])
        for n in Threshold.PQ_PK_LENGTHS.sorted() {
            XCTAssertNotNil(Threshold.validatedRegistry(set(n)), "\(n)")
            XCTAssertNil(Threshold.validatedRegistry(set(n + 1)), "\(n + 1)")
            XCTAssertNil(Threshold.validatedRegistry(set(n - 1)), "\(n - 1)")
        }
    }

    /// fadd folds a carry out of 2^256 (2^256 = 38 mod p) for any 256-bit operands, not only canonical ones.
    func testFieldAddFoldsCarry() {
        let m = UInt64.max
        XCTAssertEqual(Ed25519Torsion.fadd(Ed25519Torsion.Fe(m, m, m, m), Ed25519Torsion.Fe(1)), Ed25519Torsion.Fe(38))
        XCTAssertEqual(Ed25519Torsion.fadd(Ed25519Torsion.Fe(m, m, m, m), Ed25519Torsion.Fe(m, m, m, m)), Ed25519Torsion.Fe(74)) // 2^257 - 2 = 2*38 - 2
    }

    /// Gates that the public path reaches only after an earlier check: tested directly.
    func testDirectGates() {
        XCTAssertFalse(MLDSA.verify(publicKey: [1], message: [], signature: [2]))
        XCTAssertFalse(MLDSA.verify(publicKey: [UInt8](repeating: 0, count: 1952), message: [], signature: [UInt8](repeating: 0, count: 3308)))
        XCTAssertFalse(MLDSA.verify(publicKey: [UInt8](repeating: 0, count: 1951), message: [], signature: [UInt8](repeating: 0, count: 3309)))
        // Merkle: a sibling hash that is not canonical 32-byte base64url is a refusal, never a pass
        let leaf = JSONValue.object([JKey("a"): .int(1)])
        let lh = Merkle.leafHash(leaf)
        let sib = [UInt8](repeating: 9, count: 32)
        let root = Base64URLStrict.encode(Merkle.nodeHash(lh, sib))
        func proof(_ h: String) -> JObject {
            [JKey("index"): .int(0), JKey("size"): .int(2), JKey("path"): .array([.object([JKey("side"): .string("R"), JKey("hash"): .string(h)])])]
        }
        XCTAssertTrue(Merkle.verifyInclusion(root, proof(Base64URLStrict.encode(sib)), leaf))
        XCTAssertFalse(Merkle.verifyInclusion(root, proof("AAA"), leaf))
        XCTAssertFalse(Merkle.verifyInclusion(root, proof(Base64URLStrict.encode(sib) + "A"), leaf))
    }

    /// `.unset` fails closed when the PCActn carries a signed aud; `.any` opts out.
    func testAudienceModes() throws {
        let doc = try ConformanceTests.load("vectors.json")
        guard let v = (doc.get("vectors")?.asArray ?? []).first(where: { $0.get("name")?.asString == "valid-in-plan-action" }),
              let pc = v.get("pcactn"), let grant = v.get("grant"), let now = v.get("context")?.get("now")?.safeInt else { return XCTFail("vector") }
        let unset = PCA.verify(pcactn: pc, grant: grant, now: now, audience: .unset)
        XCTAssertEqual(unset.checks["audience"], false); XCTAssertFalse(unset.allow)
        XCTAssertTrue(unset.reason.hasPrefix("audience:"), unset.reason)
        let any = PCA.verify(pcactn: pc, grant: grant, now: now, audience: .any)
        XCTAssertEqual(any.checks["audience"], true); XCTAssertTrue(any.allow, any.reason)
        XCTAssertFalse(PCA.verify(pcactn: pc, grant: grant, now: now, audience: .id("someone-else")).allow)
    }

    /// Typed path: a duplicate (role, key) entry must carry the same pq_pk (or none on both).
    func testTypedDuplicateMemberPqPk() {
        let k = String(repeating: "A", count: 43)
        let q1 = Base64URLStrict.encode([UInt8](repeating: 1, count: 32)), q2 = Base64URLStrict.encode([UInt8](repeating: 2, count: 32))
        let a1 = Threshold.Signer(role: .agent, publicKey: k, pqPk: q1), a2 = Threshold.Signer(role: .agent, publicKey: k, pqPk: q2)
        XCTAssertEqual(Threshold.verify([], [1], [a1, a2], 1).reason, "malformed signer set (pq_pk)")
        XCTAssertEqual(Threshold.verify([], [1], [a1, Threshold.Signer(role: .agent, publicKey: k)], 1).reason, "malformed signer set (pq_pk)")
        XCTAssertEqual(Threshold.verify([], [1], [a1, a1], 1).reason, "only 0 distinct valid key(s), need 1")
        let g = Threshold.Signer(role: .guardian, publicKey: "B" + String(repeating: "A", count: 42))
        XCTAssertEqual(Threshold.verify([], [1], [a1, g, a1], 1).reason, "only 0 distinct valid key(s), need 1") // compares with the SAME role's first entry
        XCTAssertEqual(Threshold.verify([], [1], [Threshold.Signer(role: .agent, publicKey: k, pqPk: "AAA")], 1).reason, "malformed signer set (pq_pk)")
    }

    /// The typed path reports the FIRST share problem; caution accepts the closed interval [0, 1] in either number form.
    func testFirstShareReasonAndCautionBounds() throws {
        let k = String(repeating: "A", count: 43), k2 = "B" + String(repeating: "A", count: 42)
        let set = [Threshold.Signer(role: .agent, publicKey: k)]
        let sig = String(repeating: "A", count: 86)
        let r = Threshold.verify([Threshold.Share(role: .guardian, publicKey: k2, sig: sig), Threshold.Share(role: .agent, publicKey: k2, sig: sig)], [1], set, 1)
        XCTAssertEqual(r.reason, "role guardian is not in the signer set")
        let r2 = Threshold.verify([Threshold.Share(role: .agent, publicKey: k2, sig: sig), Threshold.Share(role: .guardian, publicKey: k2, sig: sig)], [1], set, 1)
        XCTAssertEqual(r2.reason, "share for role agent uses a key not registered for that role")

        let doc = try ConformanceTests.load("vectors.json")
        guard let v = (doc.get("vectors")?.asArray ?? []).first(where: { $0.get("name")?.asString == "valid-in-plan-action" }),
              var pc = v.get("pcactn")?.asObject, let grant = v.get("grant"), let now = v.get("context")?.get("now")?.safeInt else { return XCTFail("vector") }
        for (c, ok) in [(JSONValue.double(1.0), true), (.double(0.0), true), (.double(0.5), true), (.int(1), true), (.int(0), true),
                        (.double(1.0000001), false), (.double(-0.5), false), (.int(2), false), (.int(-1), false), (.string("1"), false)] {
            pc["caution"] = c
            XCTAssertEqual(PCA.verify(pcactn: .object(pc), grant: grant, now: now, audience: .any).checks["wire"] ?? false, ok, "\(c)")
        }
        // Merkle: a path step that is not an object is a refusal
        XCTAssertFalse(Merkle.verifyInclusion("x", [JKey("index"): .int(0), JKey("size"): .int(2), JKey("path"): .array([.int(1)])], .null))
        XCTAssertEqual((BigUInt(1) << 40).bit(64), 0)   // limb index == limb count
        XCTAssertEqual((BigUInt(1) << 40).bit(63), 0)
    }

    /// Fail-closed guards behind earlier checks, tested directly; a non-string threshold share sig is a wire failure.
    func testMoreDirectGates() throws {
        XCTAssertFalse(PQ.verifySuite(alg: "ml-dsa-65", holder: String(repeating: "A", count: 43), pq: nil, message: [], sig: "AAAA", pqSig: nil))
        XCTAssertFalse(PQ.verifySuite(alg: "hybrid-ed25519-ml-dsa-65", holder: String(repeating: "A", count: 43), pq: nil, message: [], sig: "AAAA", pqSig: "AAAA"))
        XCTAssertFalse(Merkle.verifyInclusion("x", [JKey("index"): .int(0), JKey("path"): .array([])], .null))
        XCTAssertFalse(Merkle.verifyInclusion("x", [JKey("size"): .int(1), JKey("path"): .array([])], .null))
        let doc = try ConformanceTests.load("vectors.json")
        guard let v = (doc.get("vectors")?.asArray ?? []).first(where: { $0.get("name")?.asString == "valid-in-plan-action" }),
              var pc = v.get("pcactn")?.asObject, let grant = v.get("grant"), let now = v.get("context")?.get("now")?.safeInt else { return XCTFail("vector") }
        let share: (JSONValue) -> JSONValue = { sig in .object([JKey("shares"): .array([.object([JKey("role"): .string("agent"), JKey("publicKey"): .string(String(repeating: "A", count: 43)), JKey("sig"): sig])])]) }
        pc["threshold"] = share(.string(String(repeating: "A", count: 86)))
        XCTAssertEqual(PCA.verify(pcactn: .object(pc), grant: grant, now: now, audience: .any).checks["wire"], true)
        for bad in [JSONValue.int(5), .null, .string("AAAA")] {
            pc["threshold"] = share(bad)
            XCTAssertEqual(PCA.verify(pcactn: .object(pc), grant: grant, now: now, audience: .any).checks, ["wire": false], "\(bad)")
        }
    }
}
