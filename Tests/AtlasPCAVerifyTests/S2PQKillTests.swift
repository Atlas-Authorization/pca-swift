import XCTest
import Foundation
@testable import AtlasPCAVerify

/// ML-DSA tests that RUN wherever the SDK can sign (macOS 26, and Linux through liboqs): real keys from PCAPQKey.generate / fromSeed, real
/// signatures, and tampered pq_pk / holder_pq / pq_sig with the exact refusals. Kills Keys.swift 81, 108-112, 127; Issue.swift 35, 169, 187, 302;
/// ArgProvenance.swift 499; Capability.swift 65, 173. None of these skips: signing is required to be available.
final class S2PQKillTests: XCTestCase {
    private func ed(_ b: UInt8) throws -> PCAEdKey { try PCAEdKey(seed: [UInt8](repeating: b, count: 32)) }
    private func pqKey(_ level: PCAMLDSALevel = .mlDsa65, _ b: UInt8 = 4) throws -> PCAPQKey { try PCAPQKey.fromSeed(level, seed: [UInt8](repeating: b, count: 32)) }
    private func hybrid(edSeed: UInt8 = 2, pqSeed: UInt8 = 4) throws -> PCASuiteKey {
        try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed(edSeed), pq: pqKey(.mlDsa65, pqSeed))
    }
    private func bump(_ v: JSONValue?) -> JSONValue {
        let s = v?.asString ?? ""
        return .string((s.first == "A" ? "B" : "A") + s.dropFirst())
    }

    override func setUpWithError() throws {
        #if !os(Linux)
        // an Apple OS below 26 cannot sign ML-DSA (the mutation shards run on Linux, where signing is required below)
        try XCTSkipUnless(PCAPQKey.signingAvailable, "ML-DSA signing needs OS 26")
        #endif
    }

    func testSigningIsAvailableHere() {
        XCTAssertTrue(PCAPQKey.signingAvailable, "this platform must be able to sign ML-DSA")
    }

    // ---- Keys.swift 81 ----

    func testRealKeysHaveTheirLevelsSizes() throws {
        let a = try PCAPQKey.generate(.mlDsa65), b = try PCAPQKey.generate(.mlDsa87)
        XCTAssertEqual(a.pk.count, 1952, "line 81: the guard lets a signing platform through")
        XCTAssertEqual(b.pk.count, 2592)
        XCTAssertNotEqual(a.pk, try PCAPQKey.generate(.mlDsa65).pk, "a generated key is random")
        XCTAssertEqual(try pqKey(.mlDsa65, 7).pk, try pqKey(.mlDsa65, 7).pk, "fromSeed is reproducible")
        XCTAssertNotEqual(try pqKey(.mlDsa65, 7).pk, try pqKey(.mlDsa65, 8).pk)
        XCTAssertEqual(try a.signFn([1, 2, 3]).count, 3309)
        XCTAssertEqual(try b.signFn([1, 2, 3]).count, 4627)
        XCTAssertThrowsError(try PCAPQKey.fromSeed(.mlDsa65, seed: [1, 2, 3]))
    }

    // ---- Keys.swift 108-112 with real keys ----

    func testSuiteKeyChecksWithRealKeys() throws {
        XCTAssertNoThrow(try PCASuiteKey(alg: "ml-dsa-65", ed: nil, pq: pqKey(.mlDsa65)), "lines 108, 109: a pure PQ suite needs no Ed25519 key")
        XCTAssertNoThrow(try PCASuiteKey(alg: "ml-dsa-87", ed: nil, pq: pqKey(.mlDsa87)))
        XCTAssertNoThrow(try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-87", ed: ed(2), pq: pqKey(.mlDsa87)))
        func msg(_ f: () throws -> Void) -> String? {
            do {
                try f()
                return nil
            } catch { return (error as? PCAProducerError)?.message }
        }
        XCTAssertEqual(msg { _ = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: nil, pq: self.pqKey()) }, "'hybrid-ed25519-ml-dsa-65' requires an Ed25519 key", "line 109")
        XCTAssertEqual(msg { _ = try PCASuiteKey(alg: "ml-dsa-65", ed: try self.ed(2), pq: nil) }, "'ml-dsa-65' requires an ML-DSA key", "lines 110, 111")
        XCTAssertEqual(msg { _ = try PCASuiteKey(alg: "ml-dsa-65", ed: nil, pq: try self.pqKey(.mlDsa87)) }, "'ml-dsa-65' needs a different ML-DSA level", "line 112")
        XCTAssertEqual(msg { _ = try PCASuiteKey(alg: "ml-dsa-87", ed: nil, pq: try self.pqKey(.mlDsa65)) }, "'ml-dsa-87' needs a different ML-DSA level", "line 112")
        XCTAssertEqual(msg { _ = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-87", ed: try self.ed(2), pq: try self.pqKey(.mlDsa65)) },
                       "'hybrid-ed25519-ml-dsa-87' needs a different ML-DSA level")
    }

    // ---- Keys.swift 127: real signature routing ----

    func testSignRoutingWithRealSignatures() throws {
        let msg: [UInt8] = [10, 20, 30]
        let pure = try PCASuiteKey(alg: "ml-dsa-65", ed: nil, pq: pqKey())
        let p = try pure.sign(msg)
        XCTAssertEqual(Base64URLStrict.decode(p.sig)?.count, 3309, "line 127: a pure PQ suite's primary signature is the ML-DSA one")
        XCTAssertNil(p.pqSig)
        let h = try hybrid().sign(msg)
        XCTAssertEqual(Base64URLStrict.decode(h.sig)?.count, 64, "line 127: a hybrid's primary signature is the Ed25519 one")
        XCTAssertEqual(Base64URLStrict.decode(h.pqSig ?? "")?.count, 3309)
    }

    // ---- Capability.swift 65, 173 and the hybrid hop ----

    private func chain(bound: Bool = true) throws -> (root: JSONValue, child: JSONValue, holder: PCASuiteKey, principal: PCAEdKey) {
        let principal = try ed(1)
        let h = try hybrid()
        let root = try PCAIssue.mintRoot(principal: .ed25519(principal), holder: h.id!, holderPqPk: bound ? h.pq!.pkB64u : nil, caveats: [])
        let child = try PCAIssue.delegate(parent: root, toHolder: try ed(9).id, added: [], signer: h)
        return (root, child, h, principal)
    }

    func testAHybridHopBoundToItsHoldersCommitmentVerifies() throws {
        let c = try chain()
        XCTAssertNotNil(c.child.get("pq_sig")?.asString, "Issue.swift 35")
        XCTAssertEqual(c.child.get("alg")?.asString, "hybrid-ed25519-ml-dsa-65")
        XCTAssertEqual(c.child.get("pq_pk")?.asString, c.holder.pq!.pkB64u)
        XCTAssertNil(Capability.verifyChain([c.root, c.child], expectedRootIssuer: c.principal.id))
    }

    func testPqBindingErrorDirect() throws {
        let h = try hybrid()
        let pk = h.pq!.pkB64u
        XCTAssertNil(Capability.pqBindingError(["alg": .string("ed25519")], committed: nil, label: "x"))
        XCTAssertNil(Capability.pqBindingError(["alg": .string("hybrid-ed25519-ml-dsa-65"), "pq_pk": .string(pk)], committed: Capability.holderPqCommitment(pk), label: "x"))
        XCTAssertTrue(Capability.pqBindingError(["alg": .string("hybrid-ed25519-ml-dsa-65"), "pq_pk": .string(pk)], committed: nil, label: "leaf")?
            .hasPrefix("leaf: suite 'hybrid-ed25519-ml-dsa-65' needs a PQ key bound to the signer") ?? false, "line 65")
        XCTAssertEqual(Capability.pqBindingError(["alg": .string("hybrid-ed25519-ml-dsa-65"), "pq_pk": .string(pk)], committed: "other", label: "leaf"),
                       "leaf: pq_pk does not match the signer's committed holder_pq (F-2)", "line 65")
        XCTAssertEqual(Capability.pqBindingError(["alg": .string("hybrid-ed25519-ml-dsa-65")], committed: Capability.holderPqCommitment(pk), label: "leaf"),
                       "leaf: pq_pk does not match the signer's committed holder_pq (F-2)", "a hybrid hop without pq_pk")
    }

    func testAnUnboundPqHopIsRefused() throws {
        let c = try chain(bound: false)
        let why = try XCTUnwrap(Capability.verifyChain([c.root, c.child], expectedRootIssuer: c.principal.id))
        XCTAssertTrue(why.hasPrefix("hop 1: suite 'hybrid-ed25519-ml-dsa-65' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment"),
                      "line 173: \(why)")
        XCTAssertTrue(why.hasSuffix("(unbound PQ keys are rejected; F-2)"))
    }

    func testASwappedPqPkIsRefusedAsNotCommitted() throws {
        let c = try chain()
        let other = try pqKey(.mlDsa65, 77)
        let forged = c.child.setting("pq_pk", .string(other.pkB64u))
        XCTAssertEqual(Capability.verifyChain([c.root, forged], expectedRootIssuer: c.principal.id),
                       "hop 1: pq_pk does not match the signer's committed holder_pq (F-2)", "line 173")
    }

    func testATamperedPqSigOrEdSigOrHolderPqIsRefused() throws {
        let c = try chain()
        let badPq = c.child.setting("pq_sig", bump(c.child.get("pq_sig")))
        XCTAssertEqual(Capability.verifyChain([c.root, badPq], expectedRootIssuer: c.principal.id), "hop 1: bad signature (not signed by expected key)")
        let badEd = c.child.setting("sig", bump(c.child.get("sig")))
        XCTAssertEqual(Capability.verifyChain([c.root, badEd], expectedRootIssuer: c.principal.id), "hop 1: bad signature (not signed by expected key)")
        let noPq = JSONValue.object({ () -> JObject in var o = c.child.asObject!; o["pq_sig"] = nil; return o }())
        XCTAssertEqual(Capability.verifyChain([c.root, noPq], expectedRootIssuer: c.principal.id), "hop 1: bad signature (not signed by expected key)", "a hybrid needs both halves")
        // the parent's holder_pq is part of its signed body: changing it breaks the root
        let badRoot = c.root.setting("holder_pq", bump(c.root.get("holder_pq")))
        XCTAssertEqual(Capability.verifyChain([badRoot, c.child], expectedRootIssuer: c.principal.id), "hop 0: body digest mismatch")
    }

    // ---- Issue.swift 35, 169, 187, 302 ----

    func testEveryHybridArtifactCarriesAVerifiablePqSig() throws {
        let k = try hybrid()
        let pin = k.pq!.pkB64u
        // 187: signArtifact
        let art = try PCAIssue.signArtifact(domain: "d\u{0}", body: .object(["x": .int(1)]), signer: k)
        XCTAssertEqual(Base64URLStrict.decode(art["pq_sig"]?.asString ?? "")?.count, 3309, "line 187")
        XCTAssertTrue(IntentWB.verifyArtifactSig("d\u{0}", art, k.ed!.id, pqPin: pin))
        var tampered = art
        tampered["pq_sig"] = bump(art["pq_sig"])
        XCTAssertFalse(IntentWB.verifyArtifactSig("d\u{0}", tampered, k.ed!.id, pqPin: pin), "a tampered pq_sig is refused")
        var swapped = art
        swapped["pq_pk"] = .string(try pqKey(.mlDsa65, 55).pkB64u)
        XCTAssertFalse(IntentWB.verifyArtifactSig("d\u{0}", swapped, k.ed!.id, pqPin: pin), "a swapped pq_pk is refused")
        XCTAssertFalse(IntentWB.verifyArtifactSig("d\u{0}", art, k.ed!.id, pqPin: try pqKey(.mlDsa65, 55).pkB64u), "a wrong pin is refused")
        // an Ed25519-only artifact has none
        let plain = try PCAIssue.signArtifact(domain: "d\u{0}", body: .object(["x": .int(1)]), signer: .ed25519(try ed(2)))
        XCTAssertNil(plain["pq_sig"])
    }

    func testPCActnAndPassportCarryAPqSig() throws {
        let k = try hybrid()
        // 169: PCActn
        let root = try PCAIssue.mintRoot(principal: k, holder: k.id!, caveats: [])
        let plan = try PCAIssue.commitPlan([["id": .string("n1"), "verb": .string("v"), "resource": .string("r")]])
        let act = try PCAIssue.buildPCActn(PCAIssue.ActSpec(grant: root, chain: [root], plan: plan, nodeId: "n1", counter: 1, signer: k, aud: "a", iat: 1))
        XCTAssertEqual(Base64URLStrict.decode(act.get("pq_sig")?.asString ?? "")?.count, 3309, "line 169")
        XCTAssertEqual(act.get("alg")?.asString, "hybrid-ed25519-ml-dsa-65")
        XCTAssertEqual(act.get("pq_pk")?.asString, k.pq!.pkB64u)
        // 302: passport
        let p: JObject = ["model_id": .string("m"), "operator": .string("o"), "hardware_rooted": .bool(false), "issued_at": .int(1)]
        var pp = p
        pp["id"] = .string(PCA.passportFingerprint(p)!)
        let sp = try PCAIssue.signPassport(pp, issuer: k, subject: "s", iat: 100, exp: 200)
        XCTAssertEqual(Base64URLStrict.decode(sp.get("pq_sig")?.asString ?? "")?.count, 3309, "line 302")
        // 35 is covered by testAHybridHopBoundToItsHoldersCommitmentVerifies
    }

    // ---- ArgProvenance.swift 499 ----

    func testTheRecorderPinCarriesThePqKeyOfAHybridSigner() throws {
        let k = try hybrid()
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", signer: k)
        XCTAssertEqual(r.pin.get("pq_pk")?.asString, k.pq!.pkB64u, "line 499")
        XCTAssertEqual(r.pin.get("pk")?.asString, k.ed!.id)
        let plain = try ProvenanceRecorder(mediator: "m", kid: "k", signer: .ed25519(try ed(2)))
        XCTAssertNil(plain.pin.get("pq_pk"))
        let receipt = try r.web("https://x.test/", "page")
        XCTAssertEqual(receipt.get("alg")?.asString, "hybrid-ed25519-ml-dsa-65")
        XCTAssertNotNil(receipt.get("pq_sig")?.asString)
    }
}
