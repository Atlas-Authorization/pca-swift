import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// Differential replay of the PQ threshold step-up against the reference (@atlasauth/pca-pq-threshold): the signed group descriptor, the ML-DSA-65 pqT-of-m
/// quorum, the standalone hybrid verifier, and the signer / fold / PCActn threshold hook. The corpora carry seed labels ({"$bytes": {"$seed": label}}) where the
/// generator used a private seed; `each(seeds: true)` resolves them to {"$bytes"} members.
final class RefPqThresholdTests: XCTestCase {
    static let file = "ref-pq-threshold.json.gz"
    static let extra = "ref-pq-threshold-java-extra.json.gz"

    static func seedBytes(_ v: JSONValue?) -> [UInt8]? {
        Base.bytes(v)
    }

    static func key(_ v: JSONValue?) -> PQTKey {
        if let s = v?.asString { return .b64u(s) }
        if let b = Base.bytes(v) { return .bytes(b) }
        return .other
    }

    static func keys(_ v: JSONValue?) -> [PQTKey]? { v?.asArray?.map(key) }

    static func participants(_ v: JSONValue?) -> [PQTParticipant?]? {
        v?.asArray?.map { e in
            guard let o = e.asObject else { return e == .null ? nil : PQTParticipant(identifier: nil, publicKey: .other) }
            return PQTParticipant(identifier: o["identifier"], publicKey: key(o["publicKey"]))
        }
    }

    static func edKey(_ seed: [UInt8]?) -> PCAEdKey? {
        guard let s = seed, s.count == 32 else { return nil }
        return try? Ed25519Deterministic.key(seed: s)
    }

    static func opts(_ o: JSONValue?) -> PCAPqThreshold.HybridOpts {
        PCAPqThreshold.HybridOpts(groupKey: key(o?.get("groupKey")), pqPublicKeys: keys(o?.get("pqPublicKeys")), t: o?.get("t"), pqT: o?.get("pqT"),
                                  groupDescriptor: o?.get("groupDescriptor"), trustedAuthorities: keys(o?.get("trustedAuthorities")), signerSetCommitment: o?.get("signerSetCommitment"))
    }

    func testPqThreshold() throws {
        try K042.requireCovers(["PqThreshold", "Ed25519Strict", "MLDSA"])
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            if Base.negZero(.array(c.args)) { d.skip("negative zero argument"); return }
            let got: BaseGot
            switch c.fn {
            case "signerSetCommitment":
                got = Ref.s { try PCAGroupDescriptor.signerSetCommitment(Self.participants(a0)) }
            case "issueGroupDescriptor":
                got = Ref.v {
                    try PCAGroupDescriptor.issueGroupDescriptor(authority: Self.edKey(Self.seedBytes(a0?.get("authoritySeed"))), groupPublicKey: Self.key(a0?.get("groupPublicKey")),
                                                                t: a0?.get("t"), participants: Self.participants(a0?.get("participants")))
                }
            case "verifyGroupDescriptor":
                let e = a1
                got = .value(PCAGroupDescriptor.verifyGroupDescriptor(a0, trustedAuthorities: Self.keys(e?.get("trustedAuthorities")), groupKey: Self.key(e?.get("groupKey")),
                                                                      t: e?.get("t"), signerSetCommitment: e?.get("signerSetCommitment")))
            case "normalizePqQuorumPool":
                got = .value(.array(PCAPqThreshold.normalizePqQuorumPool(Self.keys(a0) ?? []).sorted().map { .string($0) }))
            case "pqQuorumRepresentative":
                got = Ref.v { guard let m = Base.bytes(a0) else { throw JSError("expected bytes") }; return Base.bytesValue(PCAPqThreshold.pqQuorumRepresentative(m)) }
            case "verifyPqQuorum":
                guard MLDSA.available else { d.skip("ML-DSA is not available on this OS"); return }
                got = Ref.v {
                    guard let m = Base.bytes(c.arg(1)) else { throw JSError("expected bytes") }
                    return PCAPqThreshold.verifyPqQuorum(a0, message: m, pool: PCAPqThreshold.normalizePqQuorumPool(Self.keys(c.arg(2)) ?? []), pqT: c.arg(3))
                }
            case "verifyHybridThreshold":
                guard MLDSA.available else { d.skip("ML-DSA is not available on this OS"); return }
                got = .value(PCAPqThreshold.verifyHybridThreshold(action: a0, artifact: a1, opts: Self.opts(c.arg(2))))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(MLDSA.available ? 200 : 60)
    }

    /// The signing side: a real FROST quorum plus ML-DSA co-signers (FROST nonces are random, so the aggregate is compared by its verdict), the fold into a
    /// PCActn threshold container and the core threshold hook. The step-up verification through the core verifier (`stepUp` cases) is not carried: the native core
    /// has no tri-state per-check report to hook into.
    func testHybridSignFoldHook() throws {
        try K042.requireCovers(["PqThreshold"])
        guard MLDSA.available, PCAPQKey.signingAvailable else { throw XCTSkip("ML-DSA signing is not available on this OS") }
        let d = Base.Diffs()
        try Base.each(Self.extra, seeds: true) { c in
            let a0 = c.arg(0)
            let got: BaseGot
            switch c.fn {
            case "fold":
                got = Ref.v {
                    guard let action = a0?.asObject, let art = c.arg(1), art != .null else { throw JSError("not objects") }
                    let r = try PCAPqThreshold.foldHybridStepUp(action: action, artifact: art)
                    var m: JObject = ["pcactn": r.pcactn]
                    if let pq = r.pq { m["pq"] = pq }
                    return .object(m)
                }
            case "hook":
                got = Ref.v {
                    let hook = try PCAPqThreshold.thresholdHook(Self.opts(a0), pqBlock: a0?.get("pqBlock"))
                    let r = hook(c.arg(1) ?? .null)
                    var m: JObject = ["enforced": .bool(r.enforced), "ok": .bool(r.ok)]
                    if let w = r.reason { m["reason"] = .string(w) }
                    return .object(m)
                }
            case "hybridSign":
                got = Ref.v {
                    var r = try Self.hybridSign(a0)
                    // ML-DSA signing here is hedged (fresh randomness per call), so the signature bytes cannot match the reference's; the verdict in the same result
                    // proves each one verifies, and its length is compared before the reference bytes stand in for it
                    if case var .object(top) = r, case var .object(art)? = top["artifact"], case var .object(pq)? = art["pq"], case var .array(sg)? = pq["signers"],
                       case let .array(want)? = c.out.get("artifact")?.get("pq")?.get("signers"), want.count == sg.count {
                        for i in sg.indices {
                            guard case var .object(s) = sg[i], let a = s["sig"]?.asString, let b = want[i].get("sig")?.asString, a.utf16.count == b.utf16.count else { continue }
                            s["sig"] = .string(b); sg[i] = .object(s)
                        }
                        pq["signers"] = .array(sg); art["pq"] = .object(pq); top["artifact"] = .object(art); r = .object(top)
                    }
                    return r
                }
            case "stepUp": d.skip("stepUp: needs the core verifier's per-check report with the threshold hook"); return
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(60)
    }

    static func hybridSign(_ x: JSONValue?) throws -> JSONValue {
        guard let x = x, let t = x.get("t")?.safeInt, let n = x.get("n")?.safeInt, let secret = seedBytes(x.get("secret")), let action = x.get("action")?.asObject,
              let authSeed = seedBytes(x.get("authSeed")), let auth = edKey(authSeed) else { throw JSError("bad case") }
        let coeffs = try (x.get("coefficients")?.asArray ?? []).map { c -> [UInt8] in guard let b = seedBytes(c) else { throw JSError("bad coefficient") }; return b }
        let kg = try PCAFrost.trustedDealerKeygen(t: t, n: n, secret: secret, coefficients: coeffs)
        let quorum = try (x.get("quorum")?.asArray ?? []).map { id -> PCAFrost.ParticipantShare in
            guard let s = kg.participantShares.first(where: { $0.identifier == id.safeInt }) else { throw JSError("unknown quorum member") }
            return s
        }
        let keys = try (x.get("pqSeeds")?.asArray ?? []).map { s -> PCAPQKey in
            guard let b = seedBytes(s) else { throw JSError("bad pq seed") }
            return try PCAPQKey.fromSeed(.mlDsa65, seed: b)
        }
        let signers = try (x.get("pq")?.asArray ?? []).map { i -> PCAPQKey in
            guard let k = i.safeInt, Int(k) < keys.count, k >= 0 else { throw JSError("bad pq index") }
            return keys[Int(k)]
        }
        let pqT = x.get("pqT")?.safeInt.map { Int($0) }
        let signT = x.get("signT")?.safeInt ?? t
        let artifact = try PCAPqThreshold.hybridThresholdSign(action: action, groupPublicKey: kg.groupPublicKey, quorum: quorum, t: Int(signT), pqSigners: signers, pqT: pqT)
        let parts = kg.participantShares.map { PQTParticipant(identifier: .int($0.identifier), publicKey: .bytes($0.publicKey)) }
        let desc = try PCAGroupDescriptor.issueGroupDescriptor(authority: auth, groupPublicKey: .bytes(kg.groupPublicKey), t: .int(t), participants: parts)
        let opts = PCAPqThreshold.HybridOpts(groupKey: .bytes(kg.groupPublicKey), pqPublicKeys: keys.map { .bytes($0.pk) }, t: .int(t), pqT: .int(Int64(pqT ?? signers.count)),
                                             groupDescriptor: desc, trustedAuthorities: [.bytes(auth.pub)])
        let verdict = PCAPqThreshold.verifyHybridThreshold(action: .object(action), artifact: artifact, opts: opts)
        var frost = artifact.get("frost")?.asObject ?? [:]
        let sig = frost["sig"]?.asString ?? ""
        frost["sig"] = nil
        frost["sigLen"] = .int(Int64(sig.utf16.count))
        var shown = artifact.asObject ?? [:]
        shown["frost"] = .object(frost)
        return .object(["artifact": .object(shown), "verdict": verdict])
    }
}
