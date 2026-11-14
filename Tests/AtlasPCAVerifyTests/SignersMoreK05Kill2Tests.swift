import XCTest
@testable import AtlasPCAVerify

// Producers pinned to the TypeScript reference: agent-native.ts (caution claims), pq.ts (signPqBinding), threshold.ts
// (signPreparedShare), mesh.ts (assembleMeshProof), intent-session.ts / intent-session-caveat.ts, action-schema.ts,
// intent-required.ts, policy-link.ts, revocation.ts (signRevocationEpoch), pcactn.ts (signPCActnSuite), capability.ts (attenuate)
// and adapters.ts (PROV_HEADER_MAX). Keys come from fixed seeds; the PQ half of a suite key is a stand-in signer, so no ML-DSA runs.

private func k2ed(_ b: UInt8) throws -> PCAEdKey { try PCAEdKey(seed: [UInt8](repeating: b, count: 32)) }

/// A suite key whose PQ half signs every message as the bytes 09 09 09 (base64url "CQkJ"); PCASuiteKey needs ML-DSA signing available.
private func k2Suite(_ alg: String) throws -> PCASuiteKey {
    try XCTSkipUnless(PCAPQKey.signingAvailable, "a PQ suite key needs ML-DSA signing on this platform")
    let pq = PCAPQKey(level: .mlDsa65, pk: [UInt8](repeating: 7, count: 1952), signFn: { _ in [9, 9, 9] })
    return try PCASuiteKey(alg: alg, ed: try k2ed(5), pq: pq)
}

private let k2PqSig = "CQkJ"

private func k2Err(_ f: () throws -> Any) -> String? {
    do { _ = try f(); return nil } catch let e as PCAProducerError { return e.message } catch { return "other: \(error)" }
}

private func k2Vector(_ op: String) throws -> JObject {
    let doc = try ConformanceTests.load("producer-vectors.json")
    for c in doc.get("cases")?.asArray ?? [] where c.get("op")?.asString == op && c.get("expect")?.get("error") == nil {
        if let a = c.get("args")?.asObject { return a }
    }
    throw PCAProducerError("no vector for \(op)")
}

/// One hop of mesh evidence against `head` signed `sig`.
private func k2Hop(_ domain: String, sig: String, head: JSONValue, cosigs: [JSONValue], cap: JObject, issuer: JObject, binding: JSONValue? = nil) -> JSONValue {
    var ev: JObject = ["domain": .string(domain), "head": .object(["head": head, "sig": .string(sig), "cosigs": .array(cosigs)]),
                       "inclusion": .object(["index": .int(0)]), "revocation": .object(["cap": .object(cap), "issuer_key": .object(issuer)])]
    if let b = binding { ev["binding"] = b }
    return .object(ev)
}

private func k2Proof(_ hops: [JSONValue], pinProofs: [JSONValue] = []) throws -> JSONValue {
    let leaf = try k2ed(11)
    let root = try PCAIssue.mintRoot(principal: .ed25519(try k2ed(10)), holder: leaf.id, caveats: [])
    return try PCASigners.assembleMeshProof(chain: [root], hops: hops, action: .object(["verb": .string("read")]), leaf: leaf, pinProofs: pinProofs)
}

final class SignersMoreK05Kill2Tests: XCTestCase {
    // ---- mesh proof, one hop per head (a merge is in MeshProofMergeKill2Tests) ----

    func testA1MeshProofTablesForOneHop() throws {
        let l1: JSONValue = .object(["id": .string("a")]), l2: JSONValue = .object(["id": .string("b")])
        let head: JSONValue = .object(["size": .int(4), "root": .string("r")])
        let cos: JSONValue = .object(["witness": .string("w1"), "sig": .string("c1")])
        let hop = k2Hop("d1", sig: "s1", head: head, cosigs: [cos], cap: ["size": .int(4), "lo": l1, "hi": l2], issuer: ["size": .int(4), "lo": l1])
        let p = try k2Proof([hop])
        XCTAssertEqual(p.get("heads"), .array([.object(["head": head, "sig": .string("s1"), "cosigs": .array([cos])])]))
        XCTAssertEqual(p.get("rev_leaves"), .array([l1, l2]), "an identical leaf is carried once")
        let want: JSONValue = .object(["domain": .string("d1"), "head": .int(0), "inclusion": .object(["index": .int(0)]),
                                       "revocation": .object(["cap": .object(["size": .int(4), "lo": .int(0), "hi": .int(1)]),
                                                              "issuer_key": .object(["size": .int(4), "lo": .int(0)])])])
        XCTAssertEqual(p.get("hops"), .array([want]))
        XCTAssertNil(p.get("pin_proofs"), "no pin proofs: no member")
        let pin: JSONValue = .object(["domain": .string("d1")])
        XCTAssertEqual(try k2Proof([hop], pinProofs: [pin]).get("pin_proofs"), .array([pin]))
    }

    func testA2MeshProofLeavesOutFalsySidesAndBindingAndAnAbsentSize() throws {
        let head: JSONValue = .object(["size": .int(1)])
        let falsy = k2Hop("d1", sig: "s1", head: head, cosigs: [], cap: ["size": .int(4), "lo": .null, "hi": .int(0)],
                          issuer: ["lo": .bool(false), "hi": .string("")], binding: JSONValue.null)
        let p = try k2Proof([falsy])
        XCTAssertEqual(p.get("rev_leaves"), .array([]))
        let hop = try XCTUnwrap(p.get("hops")?.asArray?.first)
        XCTAssertEqual(hop.get("revocation"), .object(["cap": .object(["size": .int(4)]), "issuer_key": .object([:])]))
        XCTAssertNil(hop.get("binding"), "a null binding is left out")
        for b: JSONValue in [.bool(false), .string(""), .int(0)] {
            let q = try k2Proof([k2Hop("d1", sig: "s1", head: head, cosigs: [], cap: [:], issuer: [:], binding: b)])
            XCTAssertNil(q.get("hops")?.asArray?.first?.get("binding"), "\(b)")
        }
        let bound: JSONValue = .object(["domain": .string("d1")])
        let q = try k2Proof([k2Hop("d1", sig: "s1", head: head, cosigs: [], cap: [:], issuer: [:], binding: bound)])
        XCTAssertEqual(q.get("hops")?.asArray?.first?.get("binding"), bound)
    }

    func testMeshProofRefusesHopsWithoutHeadOrRevocation() throws {
        let head: JSONValue = .object(["size": .int(1)])
        var noHead = try XCTUnwrap(k2Hop("d1", sig: "s1", head: head, cosigs: [], cap: [:], issuer: [:]).asObject)
        noHead["head"] = nil
        XCTAssertEqual(k2Err { try k2Proof([.object(noHead)]) }, "assembleMeshProof: hop evidence needs a cosigned head")
        var noRev = try XCTUnwrap(k2Hop("d1", sig: "s1", head: head, cosigs: [], cap: [:], issuer: [:]).asObject)
        noRev["revocation"] = nil
        XCTAssertEqual(k2Err { try k2Proof([.object(noRev)]) }, "assembleMeshProof: hop evidence needs its revocation bracketing")
        noRev["revocation"] = .object(["cap": .object([:])])
        XCTAssertEqual(k2Err { try k2Proof([.object(noRev)]) }, "assembleMeshProof: malformed revocation evidence")
    }

    // ---- caution claims (agent-native.ts cautionBodyError / signCaution) ----

    func testCautionReasonAndRangeBounds() throws {
        XCTAssertEqual(PCASigners.MAX_CAUTION_REASON_LENGTH, 64, "MAX_CAUTION_REASON_LEN")
        func err(_ reason: JSONValue?, caution: JSONValue = .double(0.5)) -> String? {
            var b: JObject = ["action_digest": .string("ad"), "holder": .string("h"), "caution": caution]
            if let r = reason { b["reason"] = r }
            return PCASigners.cautionBodyError(b)
        }
        XCTAssertNil(err(nil))
        XCTAssertNil(err(.string(String(repeating: "a", count: 64))))
        XCTAssertNil(err(.string("ok_.:-A9")))
        let bad: [JSONValue] = [.string(String(repeating: "a", count: 65)), .string(""), .string("a b"), .string("\u{e9}"), .int(5), .null]
        for r in bad { XCTAssertEqual(err(r), "invalid reason", "\(r)") }
        XCTAssertNil(err(nil, caution: .int(0)), "0 is in [0,1]")
        XCTAssertNil(err(nil, caution: .int(1)))
        XCTAssertEqual(err(nil, caution: .double(-0.5)), "caution must be a finite number in [0,1]")
        XCTAssertEqual(err(nil, caution: .double(1.5)), "caution must be a finite number in [0,1]")
    }

    func testSignCautionReturnsTheCleanNormalizedBody() throws {
        let k = try k2ed(1)
        let b: JObject = ["action_digest": .string("ad"), "holder": .string(k.id), "caution": .double(1.0), "extra": .int(1)]
        let out = try PCASigners.signCaution(.object(b), holder: k)
        XCTAssertEqual(out.get("caution"), .int(1), "the claim is the strict JSON reading of what was signed")
        XCTAssertNil(out.get("extra"))
        XCTAssertEqual(out, try PCAIssue.norm(out))
    }

    // ---- PQ key binding, prepared shares ----

    func testPqBindingEpochIsAnyPositiveSafeInteger() throws {
        let k = try k2ed(2)
        XCTAssertEqual(try PCASigners.signPqBinding(ed: k, pqPk: "cHE", epoch: Canonical.MAX_SAFE, aud: "a").get("epoch"), .int(Canonical.MAX_SAFE))
        for e: Int64 in [0, Canonical.MAX_SAFE + 1] {
            XCTAssertEqual(k2Err { try PCASigners.signPqBinding(ed: k, pqPk: "cHE", epoch: e, aud: "a") }, "signPqBinding: epoch must be a positive safe integer")
        }
    }

    func testEd25519ProducersCarryNoSuiteFields() throws {
        let ed = try k2ed(5)
        let share = try PCASigners.signPreparedShare(role: "principal", key: .ed25519(ed), prepared: [1, 2, 3])
        XCTAssertNil(share.get("alg"))
        XCTAssertNil(share.get("pq_sig"))
        XCTAssertEqual(try PCASigners.actionSchemaKeyOf(kid: "k1", site: .ed25519(ed)), .object(["kid": .string("k1"), "alg": .string("ed25519"), "pk": .string(ed.id)]))
        let epoch = RevocationEpochBody(instanceId: "i", grantRef: "g", epoch: 1, setSize: 0, root: "r", issuedAt: 1, notAfter: 2)
        XCTAssertNil(try PCASigners.signRevocationEpoch(epoch, guardian: .ed25519(ed)).get("pq_sig"))
        let doc = try XCTUnwrap(try k2Vector("sign_action_schema")["doc"])
        let schema = try PCASigners.signActionSchema(doc, kid: "site-k1", site: .ed25519(ed))
        XCTAssertEqual(schema.get("sig")?.get("alg"), .string("ed25519"))
        XCTAssertNil(schema.get("sig")?.get("pq_value"))
    }

    func testPqSuiteProducersCarryTheirSuiteFields() throws {
        let hy = try k2Suite("hybrid-ed25519-ml-dsa-65")
        let pure = try k2Suite("ml-dsa-65")
        let share = try PCASigners.signPreparedShare(role: "principal", key: hy, prepared: [1, 2, 3])
        XCTAssertEqual(share.get("alg"), .string("hybrid-ed25519-ml-dsa-65"))
        XCTAssertEqual(share.get("pq_sig"), .string(k2PqSig))
        let pureShare = try PCASigners.signPreparedShare(role: "principal", key: pure, prepared: [1, 2, 3])
        XCTAssertEqual(pureShare.get("alg"), .string("ml-dsa-65"))
        XCTAssertEqual(pureShare.get("sig"), .string(k2PqSig))
        XCTAssertNil(pureShare.get("pq_sig"), "a pure PQ suite has no second half")

        let pk = try XCTUnwrap(hy.pq?.pkB64u)
        XCTAssertEqual(try PCASigners.actionSchemaKeyOf(kid: "k1", site: hy).get("pq_pk"), .string(pk))
        let doc = try XCTUnwrap(try k2Vector("sign_action_schema")["doc"])
        let schema = try PCASigners.signActionSchema(doc, kid: "site-k1", site: hy)
        XCTAssertEqual(schema.get("sig")?.get("alg"), .string("hybrid-ed25519-ml-dsa-65"))
        XCTAssertEqual(schema.get("sig")?.get("pq_value"), .string(k2PqSig))
        let epoch = RevocationEpochBody(instanceId: "i", grantRef: "g", epoch: 1, setSize: 0, root: "r", issuedAt: 1, notAfter: 2)
        XCTAssertEqual(try PCASigners.signRevocationEpoch(epoch, guardian: hy).get("pq_sig"), .string(k2PqSig))
    }

    // ---- session root and session grants ----

    func testSessionRootRefusalsAreTheReferenceMessages() throws {
        let k = try k2ed(20), other = try k2ed(21)
        var b = try XCTUnwrap(try k2Vector("sign_session_root")["body"]?.asObject)
        b["principals"] = .array([.object(["key": .string(k.id)])])
        XCTAssertEqual(try PCASigners.signSessionRoot(.object(b), principal: .ed25519(k)).get("signer"), .string(k.id))
        var notMine = b
        notMine["principals"] = .array([.object(["key": .string(other.id)])])
        XCTAssertEqual(k2Err { try PCASigners.signSessionRoot(.object(notMine), principal: .ed25519(k)) },
                       "signSessionRoot: the signer is not one of the session principals")
        var noQuestion = b
        noQuestion["question_uri"] = nil
        XCTAssertEqual(k2Err { try PCASigners.signSessionRoot(.object(noQuestion), principal: .ed25519(k)) },
                       "signSessionRoot: question_uri must be a non-empty string")
    }

    func testSessionGrantSaltAndCaveatCheck() throws {
        let a = try k2Vector("mint_session_grant")
        let session = try XCTUnwrap(a["session"]?.asString), root = try XCTUnwrap(a["root"]?.asString)
        let md = try XCTUnwrap(a["map_digest"]?.asString), preds = try XCTUnwrap(a["predicates"]?.asArray)
        let principal = PCASuiteKey.ed25519(try k2ed(22)), holder = try k2ed(23).id
        let g = try PCASigners.mintSessionGrant(principal: principal, holder: holder, session: session, seq: 0, root: root, mapDigest: md, predicates: preds)
        XCTAssertEqual(g.goalSalt.count, 22, "16 random bytes")
        XCTAssertNotNil(Base64URLStrict.decode(g.goalSalt, length: 16))
        XCTAssertEqual(k2Err { try PCASigners.mintSessionGrant(principal: principal, holder: holder, session: session, seq: 1, root: root, mapDigest: md, predicates: preds) },
                       "mintSessionGrant: intent_session caveat: prev is present exactly when seq > 0")
    }

    // ---- action schema, intent-required ----

    func testActionSchemaShapeIsCheckedBeforeSigning() throws {
        var bad = try XCTUnwrap(try k2Vector("sign_action_schema")["doc"]?.asObject)
        bad["kind"] = .string("x")
        XCTAssertEqual(k2Err { try PCASigners.signActionSchema(.object(bad), kid: "site-k1", site: .ed25519(try k2ed(24))) },
                       "signActionSchema: kind must be 'pca-action-schema'")
    }

    func testCellCoordsBounds() {
        func dims(_ n: Int) -> JSONValue {
            var m: JObject = [:]
            for i in 0..<n { m[JKey("d\(i)")] = .array([.int(0), .int(1)]) }
            return .object(m)
        }
        XCTAssertNil(PCASigners.cellCoordsError(dims(64)))
        XCTAssertEqual(PCASigners.cellCoordsError(dims(65)), "coords must be an object of 1..64 dimensions")
        XCTAssertEqual(PCASigners.cellCoordsError(dims(0)), "coords must be an object of 1..64 dimensions")
        let r: JSONValue = .array([.int(0), .int(1)])
        XCTAssertNil(PCASigners.cellCoordsError(.object([JKey(String(repeating: "p", count: 256)): r])))
        XCTAssertEqual(PCASigners.cellCoordsError(.object([JKey(String(repeating: "p", count: 257)): r])), "a coordinate path must be 1..256 characters")
        XCTAssertEqual(PCASigners.cellCoordsError(.object([JKey(""): r])), "a coordinate path must be 1..256 characters")
        func range(_ lo: Int64, _ hi: Int64) -> String? { PCASigners.cellCoordsError(.object(["p": .array([.int(lo), .int(hi)])])) }
        XCTAssertNil(range(2, 2), "lo == hi is a range")
        XCTAssertNil(range(0, 5))
        XCTAssertEqual(range(3, 1), "coords 'p': need 0 <= lo <= hi")
        XCTAssertEqual(range(-1, 5), "coords 'p': need 0 <= lo <= hi")
    }

    func testIntentRequiredShape() throws {
        let a = try k2Vector("sign_intent_required")
        let body = try XCTUnwrap(a["body"]?.asObject)
        XCTAssertNil(PCASigners.intentRequiredShapeError(.object(body)))
        var v2 = body
        v2["v"] = .int(2)
        XCTAssertEqual(PCASigners.intentRequiredShapeError(.object(v2)), "not a pca-intent-required v1")
        XCTAssertEqual(k2Err { try PCASigners.signIntentRequired(.object(v2), kid: "site-k1", site: .ed25519(try k2ed(26))) },
                       "signIntentRequired: not a pca-intent-required v1")
        var noDims = body
        noDims["cell"] = .object(["verb": .string("refund"), "coords": .object([:])])
        XCTAssertEqual(PCASigners.intentRequiredShapeError(.object(noDims)), "coords must be an object of 1..64 dimensions")
        let ids: [(String, Bool)] = [("q_1", true), ("q-1", true), ("Q9", true), (String(repeating: "a", count: 64), true),
                                     ("q.1", false), ("", false), (String(repeating: "a", count: 65), false), ("q\u{e9}", false)]
        for (q, ok) in ids {
            var b = body
            b["question_id"] = .string(q)
            XCTAssertEqual(PCASigners.intentRequiredShapeError(.object(b)), ok ? nil : "question_id must match [A-Za-z0-9_-]{1,64}", q)
        }
    }

    // ---- policy templates and tighten overlays ----

    func testTemplateAndOverlayAreCheckedBeforeSigning() throws {
        let p = try k2ed(27)
        let def = try XCTUnwrap(try k2Vector("sign_template")["def"])
        XCTAssertEqual(try PCASigners.signTemplate(def, principal: p).get("signer"), .string(p.id))
        var badDef = try XCTUnwrap(def.asObject)
        badDef["kind"] = .string("x")
        XCTAssertEqual(k2Err { try PCASigners.signTemplate(.object(badDef), principal: p) }, "signTemplate: template v / kind mismatch")
        let overlay = try XCTUnwrap(try k2Vector("sign_tighten")["overlay"])
        XCTAssertEqual(try PCASigners.signTighten(overlay, principal: p).get("signer"), .string(p.id))
        var badOverlay = try XCTUnwrap(overlay.asObject)
        badOverlay["kind"] = .string("x")
        XCTAssertEqual(k2Err { try PCASigners.signTighten(.object(badOverlay), principal: p) }, "signTighten: overlay v / kind mismatch")
    }
}

/// Hops against one head share its table entry; kept out of the SignersMore classes because a mutant that drops the table append
/// traps on the merge, and those classes decide such a mutant first.
final class MeshProofMergeKill2Tests: XCTestCase {
    private let head: JSONValue = .object(["size": .int(4), "root": .string("r")])

    private func hop(_ domain: String, _ sig: String, _ cosigs: [JSONValue]) -> JSONValue {
        k2Hop(domain, sig: sig, head: head, cosigs: cosigs, cap: ["size": .int(4)], issuer: ["size": .int(4)])
    }

    private func cos(_ w: String, _ sig: String) -> JSONValue { .object(["witness": .string(w), "sig": .string(sig)]) }

    func testCosignaturesMergeByWitnessAsTheReference() throws {
        let p = try k2Proof([hop("d1", "s1", [cos("w1", "c1")]),
                             hop("d2", "s1", [cos("w1", "c1b"), cos("w2", "c2"), .string("x"), .string("y")]),
                             hop("d3", "s2", [cos("w3", "c3")])])
        // a non-object cosignature reads as no witness; the witness set is taken once, before the hop's cosignatures are added
        XCTAssertEqual(p.get("heads"), .array([
            .object(["head": head, "sig": .string("s1"), "cosigs": .array([cos("w1", "c1"), cos("w2", "c2"), .string("x"), .string("y")])]),
            .object(["head": head, "sig": .string("s2"), "cosigs": .array([cos("w3", "c3")])]),
        ]))
        let hopHeads: [JSONValue] = try XCTUnwrap(p.get("hops")?.asArray).map { $0.get("head") ?? .null }
        XCTAssertEqual(hopHeads, [.int(0), .int(0), .int(1)])
    }

    func testNoWitnessAndANullWitnessAreDifferentKeys() throws {
        let unnamed: JSONValue = .object(["sig": .string("a")])
        let p = try k2Proof([hop("d1", "s1", [unnamed]),
                             hop("d2", "s1", [.object(["sig": .string("b")]), .object(["witness": .null, "sig": .string("c")])])])
        XCTAssertEqual(p.get("heads")?.asArray?.first?.get("cosigs"), .array([unnamed, .object(["witness": .null, "sig": .string("c")])]))
    }

    func testANullCosignatureIsRefusedWhenHeadsMerge() throws {
        XCTAssertEqual(k2Err { try k2Proof([hop("d1", "s1", [cos("w1", "c1")]), hop("d2", "s1", [.null])]) },
                       "assembleMeshProof: a cosignature is null")
        XCTAssertEqual(k2Err { try k2Proof([hop("d1", "s1", [.null]), hop("d2", "s1", [])]) }, "assembleMeshProof: a cosignature is null")
        XCTAssertNil(k2Err { try k2Proof([hop("d1", "s1", [.null])]) }, "an unmerged head is copied as given")
    }
}

/// capability.ts attenuate, pcactn.ts signPCActnSuite, adapters.ts PROV_HEADER_MAX and the request headers.
final class IssueHeadersKill2Tests: XCTestCase {
    func testAttenuateKeepsTheHolder() throws {
        let p = try k2ed(30), h = try k2ed(31)
        let root = try PCAIssue.mintRoot(principal: .ed25519(p), holder: h.id, caveats: [])
        let added: JSONValue = .object(["type": .string("expires"), "at": .int(5)])
        let att = try PCAIssue.attenuate(parent: root, added: [added], signer: .ed25519(h))
        XCTAssertEqual(att.get("holder"), .string(h.id))
        XCTAssertEqual(att.get("issuer"), .string(h.id))
        XCTAssertEqual(att.get("parent"), .string(Capability.capHash(root)))
        XCTAssertEqual(att.get("caveats"), .array([added]))
        XCTAssertEqual(k2Err { try PCAIssue.attenuate(parent: .object([:]), added: [], signer: .ed25519(h)) }, "attenuate: malformed parent")
    }

    func testSignPCActnReplacesSigAndKeepsAPqSigTheSuiteDoesNotSign() throws {
        let body: JSONValue = .object(["ver": .int(2), "aud": .string("a"), "counter": .int(1), "sig": .string("old"), "pq_sig": .string("stale")])
        let out = try PCAIssue.signPCActn(body, signer: .ed25519(try k2ed(32)))
        XCTAssertEqual(out.get("pq_sig"), .string("stale"))
        let sig = try XCTUnwrap(out.get("sig")?.asString)
        XCTAssertEqual(Base64URLStrict.decode(sig, length: 64)?.count, 64)
        let hybrid = try PCAIssue.signPCActn(body, signer: try k2Suite("hybrid-ed25519-ml-dsa-65"))
        XCTAssertEqual(hybrid.get("pq_sig"), .string(k2PqSig))
    }

    func testHeadersCarryOnlyWhatIsGiven() throws {
        let act: JSONValue = .object(["x": .int(1)])
        XCTAssertEqual(Set(PCAIssue.headers(act).keys), ["PCA-Action"])
        XCTAssertEqual(Set(PCAIssue.headers(act, discharges: []).keys), ["PCA-Action"])
        let h = PCAIssue.headers(act, discharges: [.object(["id": .string("d")])], narrow: .object(["n": .int(1)]), escalationAnswer: .object(["e": .int(1)]))
        XCTAssertEqual(h["PCA-Discharges"], Base64URLStrict.encode(Canonical.utf8("[{\"id\":\"d\"}]")))
        XCTAssertEqual(h["PCA-Narrow"], Base64URLStrict.encode(Canonical.utf8("{\"n\":1}")))
        XCTAssertEqual(h["PCA-Escalation-Answer"], Base64URLStrict.encode(Canonical.utf8("{\"e\":1}")))
    }

    func testProvenanceHeaderLimitIsInclusive() throws {
        XCTAssertEqual(PCAIssue.PROVENANCE_HEADER_MAX, 8192, "PROV_HEADER_MAX")
        let act: JSONValue = .object(["x": .int(1)])
        // {"a":"<n>"} is n + 8 bytes: 6144 bytes encode to exactly 8192 base64url characters, 6145 to 8194
        func prov(_ n: Int) -> JSONValue { .object(["a": .string(String(repeating: "y", count: n))]) }
        XCTAssertEqual(PCAIssue.headers(act, provenance: prov(6136))["PCA-Provenance"]?.count, 8192)
        XCTAssertNil(PCAIssue.headers(act, provenance: prov(6137))["PCA-Provenance"])
    }
}
