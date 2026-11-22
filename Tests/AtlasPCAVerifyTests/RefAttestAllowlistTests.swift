import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The signed measurement-allowlist manifests (verify, durable verify, create, sign, revoke, project, vendor policy fields) and their transparency anchor
/// (commit, operator log, evidence, verifyAllowlistAnchored) against the reference corpus: every case, every fn. A refusal is compared by its code, not
/// its text. Signing under ML-DSA is compared byte for byte when the opt-in OpenSSL product is linked; otherwise the platform signs (hedged).
final class RefAttestAllowlistTests: XCTestCase {
    typealias L = PCAAttestAllowlist
    typealias N = PCAAllowlistAnchor
    typealias A = RefAnalyzer

    private static func mlDsa(_ level: PCAMLDSALevel, _ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(level, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(level, seed: seed)
    }
    private static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    private static func key(_ alg: String?, _ spec: JSONValue?) throws -> PCASuiteKey {
        guard let alg = alg else { throw PCAProducerError("alg") }
        let ed = try spec?.get("edSecret")?.asString.flatMap { Base64URLStrict.decode($0) }.map { try Ed25519Deterministic.key(seed: $0) }
        let pq = try spec?.get("seed")?.asString.flatMap { Base64URLStrict.decode($0) }.map { try mlDsa(alg.contains("87") ? .mlDsa87 : .mlDsa65, $0) }
        return try PCASuiteKey(alg: alg, ed: ed, pq: pq)
    }

    private static func options(_ o: JSONValue?) -> L.VerifyOptions {
        L.VerifyOptions(issuerKeys: o?.get("issuerKeys") ?? .null, nowMs: IV.num(o?.get("nowMs")) ?? .nan, minVersion: o?.get("minVersion"), lastSeenVersion: o?.get("lastSeenVersion"),
                        lastSeenDigest: o?.get("lastSeenDigest"), clockSkewMs: o?.get("clockSkewMs"), maxLifetimeMs: o?.get("maxLifetimeMs"))
    }

    /// A refusal carries a code; its text is not compared.
    private static func normRefusal(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(normRefusal))
        case let .object(o):
            if o["$throws"] != nil { return .object(["$throws": .bool(true)]) }
            if o["ok"] == .bool(false), o["code"] != nil { return .object(["ok": .bool(false), "code": o["code"]!]) }
            return .object(o.mapValues(normRefusal))
        default: return v
        }
    }

    private static func spec(_ v: JSONValue?) -> JSONValue { v ?? .null }

    private static func durable(_ a: JSONValue?) -> JSONValue {
        let kv = MemoryAtomicKV()
        for (k, v) in a?.get("initial")?.asObject ?? [:] { kv.update(k.s) { _ in v } }
        let o = options(a?.get("opts"))
        let results = (a?.get("steps")?.asArray ?? []).map { L.verifyAllowlistDurable($0, o, kv) }
        var state = JObject()
        for k in kv.keys() { state[JKey(k)] = kv.get(k) ?? .null }
        return .object(["results": .array(results), "kv": .object(state)])
    }

    private static func anchorOps(_ a: JSONValue?) throws -> JSONValue {
        guard let secret = a?.get("secret")?.asString.flatMap({ Base64URLStrict.decode($0) }) else { throw PCAProducerError("secret") }
        let guardian = PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: secret))
        let log = N.createAllowlistAnchorLog(instanceId: a?.get("instanceId")?.asString ?? "", principal: a?.get("principal")?.asString ?? "")
        func opt(_ v: JSONValue?) -> N.SignOptions { N.SignOptions(guardian: guardian, nowMs: IV.num(v) ?? .nan) }
        return .array((a?.get("ops")?.asArray ?? []).map { op in
            do {
                if let what = op.get("anchor") { return try N.anchorAllowlistHead(log, what, opt(op.get("nowMs"))) }
                if let t = op.get("refresh") { return try N.refreshAnchorHead(log, opt(t)) }
                if let i = op.get("evidenceFor") { return try N.evidenceFor(log, IV.num(i) ?? .nan, cachedSize: IV.num(op.get("cached")?.get("size"))) }
                if op.get("latest") != nil { return log.latest() ?? .null }
                if op.get("entries") != nil { return .array(log.entries()) }
                throw JSError("bad op")
            } catch { return .object(["$throws": .string((error as? JSError)?.message ?? "\(error)")]) }
        })
    }

    private static func anchored(_ a: JSONValue?) -> JSONValue {
        let o = a?.get("opts")
        let opts = N.VerifyOptions(trust: o?.get("trust") ?? .null, nowMs: IV.num(o?.get("nowMs")) ?? .nan, maxHeadAgeMs: o?.get("maxHeadAgeMs"), clockSkewMs: o?.get("clockSkewMs"),
                                   cachedHead: o?.get("cachedHead"))
        return N.verifyAllowlistAnchored(a?.get("verified") ?? .null, JS.present(a?.get("evidence")), opts)
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2)
        switch c.fn {
        case "constants": return .value(.object(["ALLOWLIST_KINDS": .array(L.ALLOWLIST_KINDS.map { .string($0) }), "DOMAIN": .string(L.DOMAIN)]))
        case "verifyAllowlistManifest": return .value(L.verifyAllowlistManifest(a0, options(a1)))
        case "verifyAllowlistDurable": return .value(durable(a0))
        case "createAllowlistManifest": return A.run { try L.createAllowlistManifest(a0) }
        case "signAllowlistManifest":
            return A.run { try L.signAllowlistManifest(a0, issuer: a1?.get("issuer")?.asString ?? "", key: try key(a1?.get("alg")?.asString, a1?.get("keySpec"))) }
        case "revokeAllowlistEntry": return A.run { try L.revokeAllowlistEntry(a0, a1, a2) }
        case "driverVersionSlotHex": return A.run { .string(try L.driverVersionSlotHex(a0)) }
        case "projectAllowlist": return A.run { try L.projectAllowlist(a0 ?? .null, nowMs: IV.num(a1?.get("nowMs")) ?? .nan) }
        case "policyFields":
            return A.run {
                guard let p = a1 else { throw JSError("projection") }
                switch a0?.asString {
                case "azureMaaPolicyFields"?: return L.azureMaaPolicyFields(p)
                case "intelDcapPolicyFields"?: return L.intelDcapPolicyFields(p)
                case "sevSnpPolicyFields"?: return L.sevSnpPolicyFields(p)
                case "gcpCsPolicyFields"?: return L.gcpCsPolicyFields(p)
                case "nvidiaCcPolicyFields"?: return L.nvidiaCcPolicyFields(p)
                default: throw JSError("unknown policy fn")
                }
            }
        case "anchorCommit": return A.run { .string(try N.allowlistAnchorCommit(a0)) }
        case "anchorEntryOf": return .value(N.anchorEntryOf(a0 ?? .null))
        case "anchorOps": return A.run { try anchorOps(a0) }
        case "verifyAnchored": return .value(anchored(a0))
        default: return nil
        }
    }

    private static func compare(_ c: BaseCase, _ got: BaseGot) -> String? {
        if c.threw { return Base.diff(c, got) }
        guard case let .value(v) = got else { return Base.diff(c, got) }
        return Base.canon(normRefusal(v)) == Base.canon(normRefusal(c.out)) ? nil : Base.diff(c, .value(normRefusal(v)))
    }

    /// A manifest signed by the platform's hedged ML-DSA differs from the reference in its ML-DSA signature only.
    private static func signedBy(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "signAllowlistManifest", !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out,
              let alg = want["alg"]?.asString, alg != "ed25519" else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_sig" : "sig")
        mine[field] = nil
        want[field] = nil
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        #if canImport(AtlasPCAOpenSSL)
        _ = PCAOpenSSL.registerSlhDsa()
        #endif
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-attest-allowlist.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            let diff = Self.compare(c, Self.signedBy(c, got))
            // an OS without ML-DSA, or a build without the SLH-DSA / FN-DSA backends, refuses those suites: such a case is not comparable there
            if diff != nil, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            if diff != nil, !PCASlhDsaHook.isRegistered, Base.canon(.array(c.args)).contains("slh-dsa") { d.skip("SLH-DSA backend is not registered in this build"); return }
            d.add(c, diff)
        }
        XCTAssertEqual(n, 959)
        XCTAssertEqual(seen, ["verifyAllowlistManifest": 744, "verifyAnchored": 72, "policyFields": 45, "verifyAllowlistDurable": 23, "anchorOps": 20, "driverVersionSlotHex": 13,
                              "revokeAllowlistEntry": 11, "signAllowlistManifest": 10, "projectAllowlist": 9, "createAllowlistManifest": 6, "anchorCommit": 4, "constants": 1, "anchorEntryOf": 1])
        d.finish(959 - d.skipped.values.reduce(0, +))
    }
}
