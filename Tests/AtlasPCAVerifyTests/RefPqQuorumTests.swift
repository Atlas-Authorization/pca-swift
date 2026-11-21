import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The in-core post-quantum quorum sets, quorum proofs and rotation chains against the reference corpus (every case, every fn).
/// Two things depend on what the build links:
///  - SIGNING (`signQuorumShare`, `signRotationShare`) is compared byte for byte when the opt-in OpenSSL product is linked (deterministic ML-DSA on
///    libcrypto 3.5+); otherwise a share signed by the platform (hedged ML-DSA) is checked by verifying it, and the refusals are compared as usual.
///  - VERIFYING a share of an SLH-DSA signer needs the SLH-DSA backend of the same product; without it those shares are refused (fail closed), so the
///    cases whose reference verdict depends on one are counted as skipped there. The SLH-DSA workflow runs this class with the backend and skips none.
final class RefPqQuorumTests: XCTestCase {
    typealias Q = PqQuorum
    private static func s(_ x: String) -> JSONValue { .string(x) }
    /// The reference's `[...shares]`: an array's elements, a string's characters; any other value has none (or throws, which the replay compares).
    private static func spread(_ v: JSONValue?) -> [JSONValue] {
        if let a = v?.asArray { return a }
        if let str = v?.asString { return str.map { .string(String($0)) } }
        return []
    }

    private static func seed(_ v: JSONValue?) -> [UInt8]? {
        guard let t = v?.asString, let b = Base64URLStrict.decode(t), b.count == 32 else { return nil }
        return b
    }

    static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    private static func mlDsa(_ level: PCAMLDSALevel, _ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(level, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(level, seed: seed)
    }

    /// The suite key of the entry at `index` from `{edSecret?, mlDsa?, mlDsa87?}` (resolved seeds). A missing or mismatched member is a refusal, as in the
    /// reference (`signWithSuite` requires exactly the key material of the entry's suite).
    private static func suiteKey(_ set: JSONValue?, _ index: JSONValue?, _ keys: JSONValue?) throws -> PCASuiteKey {
        guard let k = keys, k.isObject else { throw PCAProducerError("keys") }
        guard case let .array(signers)? = set?.get("signers"), let i = index, let n = JS.indexKey(JS.toString(i)), Int(n) < signers.count,
              let alg = signers[Int(n)].get("alg")?.asString, let suite = PQ.suites[alg] else { throw PCAProducerError("signQuorumShare: no such signer index") }
        let ed = try seed(k.get("edSecret")).map { try Ed25519Deterministic.key(seed: $0) }
        var pq: PCAPQKey?
        if suite.pq == .mlDsa65, let sd = seed(k.get("mlDsa")) { pq = try mlDsa(.mlDsa65, sd) }
        if suite.pq == .mlDsa87, let sd = seed(k.get("mlDsa87")) { pq = try mlDsa(.mlDsa87, sd) }
        return try PCASuiteKey(alg: alg, ed: ed, pq: pq)
    }

    /// A share the platform signed (hedged ML-DSA): the index is the reference's and the signature verifies as a one-signer quorum of that entry.
    private static func shareVerifies(_ share: JSONValue, _ want: JSONValue, _ set: JSONValue?, _ msg: [UInt8]) -> Bool {
        guard Base.canon(share.get("i")) == Base.canon(want.get("i")), (share.get("pq_sig") == nil) == (want.get("pq_sig") == nil),
              case let .array(signers)? = set?.get("signers"), let n = JS.indexKey(JS.toString(share.get("i"))), Int(n) < signers.count,
              let alg = signers[Int(n)].get("alg")?.asString, let pq = signers[Int(n)].get("pq")?.asString else { return false }
        return PQ.verifySuite(alg: alg, holder: signers[Int(n)].get("ed")?.asString ?? "", pq: PQ.resolvePqKey(identity: nil, artifactPk: nil, trustedPk: pq), message: msg,
                              sig: share.get("sig")?.asString, pqSig: share.get("pq_sig")?.asString)
    }

    private static func signed(_ c: BaseCase, _ set: JSONValue?, _ msg: () throws -> [UInt8], _ sign: () throws -> JSONValue) -> BaseGot {
        let got = Base.run({ _ in nil }, sign)
        guard !exactMlDsa, !c.threw, case let .value(share) = got, let m = try? msg() else { return got }
        return shareVerifies(share, c.out, set, m) ? .value(c.out) : got
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3), a4 = c.arg(4)
        func run(_ f: () throws -> JSONValue) -> BaseGot { Base.run({ _ in nil }, f) }
        func need(_ v: JSONValue?) throws -> JSONValue {
            guard let x = v else { throw PCAProducerError("missing argument") }
            return x
        }
        switch c.fn {
        case "constants": return .value(.object(["PQ_QUORUM_MAX_SIGNERS": .int(Int64(Q.PQ_QUORUM_MAX_SIGNERS)), "PQ_QUORUM_MAX_CHAIN": .int(Int64(Q.PQ_QUORUM_MAX_CHAIN))]))
        case "buildQuorumSet": return .value(Q.buildQuorumSet(a0, t: a1, minHashBased: a2))
        case "loadQuorumSet": return .value(Q.loadQuorumSet(a0))
        case "quorumMessage": return run { Base.bytesValue(try Q.quorumMessage(setId: try need(a0), epoch: try need(a1), actionDigest: try need(a2))) }
        case "quorumActionDigest":
            // the reference hashes text as its UTF-8 bytes; the typed API takes bytes
            guard let message = Base.bytes(a0) ?? a0?.asString.map({ Array($0.utf8) }) else { return .threw(nil) }
            return .value(s(Q.quorumActionDigest(message)))
        case "signQuorumShare":
            return signed(c, a0, { try Q.quorumMessage(setId: a0?.get("id") ?? .null, epoch: a2 ?? .null, actionDigest: a3 ?? .null) }) {
                // the reference binds the message first: a value the canonical form refuses is a refusal whatever the keys are
                _ = try Q.quorumMessage(setId: try need(a0?.get("id")), epoch: try need(a2), actionDigest: try need(a3))
                return try Q.signQuorumShare(set: try need(a0), index: try need(a1), epoch: try need(a2), actionDigest: try need(a3), key: try suiteKey(a0, a1, a4))
            }
        case "assembleQuorumProof": return run { try Q.assembleQuorumProof(set: try need(a0), shares: Self.spread(a1)) }
        case "verifyQuorum": return .value(Q.verifyQuorum(a0))
        case "verifyQuorumApproval":
            // a message that is not bytes is refused (the typed API takes bytes); null options are no options
            guard let msg = Base.bytes(a2) else { return .value(.bool(false)) }
            return .value(.bool(Q.verifyQuorumApproval(set: a0, proof: a1, message: msg, epoch: a3, expectedSetId: a4?.get("expectedSetId"), requireHashBased: a4?.get("requireHashBased"))))
        case "rotationActionDigest": return run { s(try Q.rotationActionDigest(toSetId: try need(a0), toEpoch: try need(a1))) }
        case "buildRotationCert": return run { try Q.buildRotationCert(from: try need(a0), fromEpoch: try need(a1), to: try need(a2), shares: Self.spread(a3)) }
        case "signRotationShare":
            let next: JSONValue = (IV.num(a2)).map { PD.num($0 + 1) } ?? .null
            return signed(c, a0, { try Q.quorumMessage(setId: a0?.get("id") ?? .null, epoch: a2 ?? .null,
                                                       actionDigest: s(try Q.rotationActionDigest(toSetId: a3?.get("id") ?? .null, toEpoch: next))) }) {
                _ = try Q.rotationActionDigest(toSetId: try need(a3?.get("id")), toEpoch: next)
                return try Q.signRotationShare(from: try need(a0), index: try need(a1), fromEpoch: try need(a2), to: try need(a3), key: try suiteKey(a0, a1, a4))
            }
        case "verifyRotationChain": return .value(Q.verifyRotationChain(genesisSet: a0, genesisEpoch: a1, chain: a2))
        case "isRotationFork": return .value(.bool(Q.isRotationFork(a0, a1)))
        case "quorumProofSize": return run { try Q.quorumProofSize(set: try need(a0), indices: a1) }
        default: return nil
        }
    }

    /// True when a value names an SLH-DSA suite anywhere (a set entry `alg`).
    private static func namesSlh(_ v: JSONValue) -> Bool {
        switch v {
        case let .string(t): return t.contains("slh-dsa")
        case let .array(a): return a.contains(where: namesSlh)
        case let .object(o): return o.values.contains(where: namesSlh)
        default: return false
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        #if canImport(AtlasPCAOpenSSL)
        PCAOpenSSL.registerSlhDsa()
        defer { PCASlhDsaHook.unregister() }
        // with the product linked in CI a missing backend fails: the byte-for-byte signing and the SLH-DSA verdicts are what this run is for
        if ProcessInfo.processInfo.environment["CI"] != nil {
            XCTAssertTrue(PCAOpenSSL.mlDsaAvailable(), "libcrypto without ML-DSA (needs 3.5+)")
            XCTAssertTrue(PCASlhDsaHook.isRegistered, "libcrypto without SLH-DSA (needs 3.5+)")
        }
        #endif
        let d = Base.Diffs()
        var notComparable = 0
        let verifying: Set<String> = ["verifyQuorum", "verifyQuorumApproval", "verifyRotationChain"]
        let n = try Base.each("ref-pq-threshold-quorum.json.gz", seeds: true) { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            // without the SLH-DSA backend a share of an SLH-DSA signer is refused, so a verdict that depends on one cannot be compared
            if !PCASlhDsaHook.isRegistered, verifying.contains(c.fn), Self.namesSlh(.array(c.args)), Base.diff(c, got) != nil {
                d.skip("needs the SLH-DSA backend (the opt-in OpenSSL product)"); notComparable += 1; return
            }
            // an OS without ML-DSA refuses those suites (fail closed): nothing that signs or verifies one is comparable there
            if !MLDSA.available, Base.diff(c, got) != nil, verifying.contains(c.fn) || c.fn.hasPrefix("sign") {
                d.skip("ML-DSA is not available on this OS"); notComparable += 1; return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 389)
        d.finish(388 - notComparable) // one case carries a lone surrogate, which a Swift String cannot hold
    }

    func testAQuorumRoundTrip() throws {
        guard PCAPQKey.signingAvailable else { throw XCTSkip("ML-DSA signing is not available on this platform") }
        let keys = try (0..<3).map { _ in try PCASuiteKey(alg: "ml-dsa-65", ed: nil, pq: try PCAPQKey.generate(.mlDsa65)) }
        let signers: JSONValue = .array(keys.map { .object(["alg": .string("ml-dsa-65"), "keys": .object(["mlDsaPub": .string($0.pqPk ?? "")])]) })
        let built = Q.buildQuorumSet(signers, t: .int(2))
        let set = try XCTUnwrap(built.get("set"))
        XCTAssertEqual(Q.loadQuorumSet(set).get("ok"), .bool(true))
        let order = (set.get("signers")?.asArray ?? []).map { e in keys.first { $0.pqPk == e.get("pq")?.asString }! }
        let digest: JSONValue = .string(Q.quorumActionDigest(Array("approve".utf8)))
        let shares = try [0, 2].map { try Q.signQuorumShare(set: set, index: .int(Int64($0)), epoch: .int(1), actionDigest: digest, key: order[$0]) }
        let proof = try Q.assembleQuorumProof(set: set, shares: shares)
        let ok = Q.verifyQuorum(.object(["set": set, "proof": proof, "epoch": .int(1), "actionDigest": digest]))
        XCTAssertEqual(ok.get("count"), .int(2), JS.stringify(ok))
        XCTAssertTrue(Q.verifyQuorumApproval(set: set, proof: proof, message: Array("approve".utf8), epoch: .int(1)))
        XCTAssertEqual(Q.verifyQuorum(.object(["set": set, "proof": proof, "epoch": .int(2), "actionDigest": digest])).get("reason"), .string("bad-signature"))
        let one = try Q.assembleQuorumProof(set: set, shares: [shares[0]])
        XCTAssertEqual(Q.verifyQuorum(.object(["set": set, "proof": one, "epoch": .int(1), "actionDigest": digest])).get("reason"), .string("below-threshold"))
        let twice = try Q.assembleQuorumProof(set: set, shares: [shares[0], shares[0]])
        XCTAssertEqual(Q.verifyQuorum(.object(["set": set, "proof": twice, "epoch": .int(1), "actionDigest": digest])).get("reason"), .string("duplicate-signer"))
        XCTAssertThrowsError(try Q.signQuorumShare(set: set, index: .int(3), epoch: .int(1), actionDigest: digest, key: order[0]))
    }
}
