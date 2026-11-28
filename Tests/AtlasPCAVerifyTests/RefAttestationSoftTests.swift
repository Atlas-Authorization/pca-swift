import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The software attestation layer (binding, dev attestor, registry, nonce store and entropy gate, agent-binding match, verifier and hook, multi-root,
/// evidence anchor) against the reference corpus: every case, every fn. A constant hardware verifier is `{result}` or `{throws}`. The legacy opt-out
/// `allowUnboundPq` is not supported: the two cases the reference accepts only through it must be REFUSED here (a pure post-quantum or hybrid document
/// verifies only under a pinned key). Minting a pure ML-DSA or hybrid document is compared byte for byte when the opt-in OpenSSL product is linked
/// (deterministic ML-DSA on libcrypto 3.5+); otherwise the platform signs (hedged ML-DSA), so every other member is compared.
final class RefAttestationSoftTests: XCTestCase {
    typealias P = PCAAttestation
    typealias A = RefAnalyzer

    private static let closed = "attestation verification error (fail closed):"
    static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    private static func mlDsa(_ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(.mlDsa65, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(.mlDsa65, seed: seed)
    }

    private static func suiteKey(_ secret: [UInt8], _ suite: JSONValue?) throws -> PCASuiteKey {
        let ed = try Ed25519Deterministic.key(seed: secret)
        var key = PCASuiteKey.ed25519(ed)
        if let s = JS.present(suite) {
            guard let alg = IV.sigAlg(s.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(s.get("pqSeed")).map { try mlDsa($0) })
        }
        return key
    }

    /// A reason that carries the reference's own exception text after the colon is compared by its prefix only.
    private static func trim(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(trim))
        case let .object(o):
            var out = JObject()
            for (k, x) in o {
                if k.s == "reason", let r = x.asString, r.hasPrefix(closed) { out[k] = .string(closed) } else { out[k] = trim(x) }
            }
            return .object(out)
        default: return v
        }
    }

    /// The constant hardware verifier of a case. A result that is not an object is "not a result": a failed root in a multi-root policy, a plain
    /// rejection alone; a null result is a TypeError alone (the reference reads `.ok` of it).
    private static func hw(_ h: JSONValue?, alone: Bool) -> PCAAttestationHardwareVerifier? {
        guard let h = JS.present(h) else { return nil }
        return P.HardwareFunc { _, _, _, _ in
            if let t = h.get("throws") { throw JSError(t.asString ?? "") }
            guard let r = JS.present(h.get("result")) else {
                if alone { throw JSError("Cannot read properties of null (reading 'ok')") }
                return .notAResult
            }
            guard r.isObject || r.isArray else { return .notAResult }
            var host: [String: String]? = nil
            if let ho = r.get("hostAsserted")?.asObject { host = [:]; for (k, v) in ho { host?[k.s] = v.asString ?? "" } }
            return P.HardwareResult(ok: JS.truthy(r.get("ok")), reason: JS.present(r.get("reason")).map { JS.toString($0) }, measured: r.get("measured"),
                                    bound: r.get("bound") == .bool(true), hostAsserted: host)
        }
    }

    private static func strings(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    private static func pins(_ v: JSONValue?) -> [String: String]? {
        guard let o = v?.asObject else { return nil }
        var m: [String: String] = [:]
        for (k, p) in o { if let t = p.asString { m[k.s] = t } }
        return m
    }

    private static func num(_ v: JSONValue?) -> Double? { IV.num(v) }

    /// A store constructed from the untyped corpus arguments (`max`, `{retentionMs}`): anything that is not a number is not an integer and is refused.
    private static func store(_ max: JSONValue?, _ opts: JSONValue?, now: @escaping () -> Double) throws -> P.MemoryNonceStore {
        var m: Double = 100_000
        if let x = JS.present(max) { guard let n = IV.num(x) else { throw JSError("memoryNonceStore: max must be a positive integer") }; m = n }
        var r: Double? = nil
        if let x = JS.present(opts?.get("retentionMs")) { guard let n = IV.num(x) else { throw JSError("memoryNonceStore: retentionMs must be a positive integer (ms)") }; r = n }
        return try P.MemoryNonceStore(max: m, retentionMs: r, now: now)
    }

    private final class ConstStore: PCAAttestationNonceStore {
        let answer: Bool
        init(_ a: Bool) { answer = a }
        func consume(_ nonce: String) -> Bool { answer }
    }

    private static func verifyInput(_ i: JSONValue?) -> P.VerifyInput {
        P.VerifyInput(document: JS.present(i?.get("document")), ctx: i?.get("ctx") ?? .null, expected: i?.get("expected") ?? .null,
                      nowMs: num(i?.get("nowMs")) ?? .nan, trustedAttestorKeys: strings(i?.get("trustedAttestorKeys")), pqPins: pins(i?.get("pqPins")),
                      hardwareVerifier: hw(i?.get("hardware"), alone: true), maxNonceAgeMs: num(i?.get("maxNonceAgeMs")), clockSkewMs: num(i?.get("clockSkewMs")))
    }

    private static func hook(_ op: JSONValue, _ ctxs: [JSONValue]) throws -> JSONValue {
        let now = num(op.get("now")) ?? .nan
        var o = P.VerifierOptions(trustedAttestorKeys: strings(op.get("trustedAttestorKeys")))
        o.minNonceBytes = op.get("minNonceBytes")
        o.insecureSelfDeclaredNonce = op.get("insecure_selfDeclaredNonce") == .bool(true)
        o.maxNonceAgeMs = num(op.get("maxNonceAgeMs"))
        o.clockSkewMs = num(op.get("clockSkewMs"))
        o.pqPins = pins(op.get("pqPins"))
        o.now = { now }
        o.hardwareVerifier = hw(op.get("hardware"), alone: true)
        o.resolveDocument = P.attestationRegistry(op.get("docs")?.asArray ?? [])
        if let s = JS.present(op.get("store")) { o.nonceStore = try store(s.get("max"), s, now: { now }) }
        if case let .bool(b)? = op.get("storeConsume") { o.nonceStore = ConstStore(b) }
        switch op.get("binding") {
        case .string("throws")?: o.expectedBinding = { _ in throw JSError("boom") }
        case let .object(b)?:
            let by = b["byNonce"]?.asObject ?? [:]
            // a JavaScript object key: String(quote_digest), "undefined" when absent
            o.expectedBinding = { ctx in by[JKey(JS.toString(ctx.get("pcactn")?.get("attestation")?.get("quote_digest")))] }
        default: break
        }
        let v = P.createAttestationVerifier(o)
        return .array(ctxs.map { v.verify($0).json })
    }

    private static func multi(_ pol: JSONValue?, _ inp: JSONValue?) throws -> JSONValue {
        var roots: [P.Root] = []
        for r in pol?.get("roots")?.asArray ?? [] {
            guard let id = r.get("id")?.asString else { throw JSError("createMultiRootVerifier: each root needs a non-empty id") }
            let v: PCAAttestationHardwareVerifier = hw(r.get("hw"), alone: false) ?? P.HardwareFunc { _, _, _, _ in throw JSError("verifier is not defined") }
            roots.append(P.Root(id: id, verifier: v, required: r.get("required") == .bool(true), suite: r.get("suite")?.asString))
        }
        let verifier = try P.createMultiRootVerifier(roots: roots, threshold: num(pol?.get("threshold")) ?? .nan)
        guard let i = JS.present(inp) else { return .object(["built": .bool(true)]) }
        return try verifier.verify(document: i.get("document") ?? .null, ctx: i.get("ctx") ?? .null, nowMs: num(i.get("nowMs")) ?? .nan, expected: i.get("expected") ?? .null).json
    }

    private static func anchor(_ ev: JSONValue?, _ op: JSONValue?) throws -> JSONValue {
        var ledger: PCATransparencyLedger? = nil
        if op?.get("ledger")?.asString == "ok" {
            let l = PCATransparencyLedger(principal: op?.get("principal")?.asString ?? "")
            for i in 0..<Int(op?.get("preload")?.safeInt ?? 0) { try l.appendCommitment("c\(i)") }
            ledger = l
        }
        var guardian: PCASuiteKey? = nil
        if let secret = Base.bytes(op?.get("guardianSeed")) { guardian = .ed25519(try Ed25519Deterministic.key(seed: secret)) }
        let nowV = op?.get("now").flatMap { IV.num($0) }.map { v in { () -> Double in v } }
        return try P.anchorAttestationEvidence(ev ?? .null, P.AnchorOptions(ledger: ledger, guardian: guardian, instanceId: op?.get("instanceId")?.asString,
                                                                              now: nowV, required: op?.get("required") == .bool(true)))
    }

    private static func attest(_ a0: JSONValue?, _ a1: JSONValue?, _ a2: JSONValue?) throws -> P.DevAttestor {
        guard let secret = Base.bytes(a0) else { throw PCAProducerError("secret") }
        return try P.createDevAttestor(try suiteKey(secret, a1))
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2)
        switch c.fn {
        case "attestationBinding": return A.run { Base.bytesValue(try P.attestationBinding(a0)) }
        case "attestationBindingB64u": return A.run { .string(try P.attestationBindingB64u(a0)) }
        case "attest": return A.run { try attest(a0, a1, a2).attest(a2 ?? .null) }
        case "attestorPublicKey": return A.run { .string(try attest(a0, a1, nil).publicKey) }
        case "attestationDigest": return A.run { .string(try P.attestationDigest(a0 ?? .null)) }
        case "registry":
            let resolve = P.attestationRegistry(a0?.asArray ?? [])
            return .value(.array((a1?.asArray ?? []).map { q in
                resolve(.object(["pcactn": .object(["attestation": .object(["quote_digest": q])])])) ?? .null
            }))
        case "nonceStore":
            return A.run {
                var t: Double = 0
                let st = try store(a0, a1, now: { t })
                return .array(try (a2?.asArray ?? []).map { x in
                    let op = x.asArray ?? []
                    if op.first?.asString == "clock" { t = IV.num(op.count > 1 ? op[1] : nil) ?? .nan; return .null }
                    if case let .string(n)? = (op.count > 1 ? op[1] : nil) { return .bool(st.consume(n)) }
                    return .bool(false) // a nonce that is not a string is never consumed
                })
            }
        case "nonceEntropyOk": return .value(.bool(P.nonceEntropyOk(a0, JS.present(a1))))
        case "requiresAttestation": return .value(.bool(P.requiresAttestation(JS.present(a0))))
        case "nonceBinds": return .value(.bool(P.nonceBinds(a0, a1)))
        case "matchAgentBinding": return A.run { try P.matchAgentBinding(a0, JS.present(a1)).map { .string($0) } ?? .null }
        case "verifyAttestation": return .value(A.out(P.verifyAttestation(verifyInput(a0)).json))
        case "attestationHook": return A.run { try hook(a0 ?? .null, a1?.asArray ?? []) }
        case "multiRoot": return A.run { try multi(a0, a1) }
        case "attestationEvidenceDigest": return A.run { .string(try P.attestationEvidenceDigest(a0 ?? .null)) }
        case "anchorEvidence": return A.run { try anchor(a0, a1) }
        case "constants":
            return .value(.object(["ATTEST_BIND_DOMAIN": .string(P.ATTEST_BIND_DOMAIN), "MAX_ATTESTATION_AGE_MS": .int(Int64(P.MAX_ATTESTATION_AGE_MS)),
                                   "DEFAULT_NONCE_RETENTION_MS": .int(Int64(P.DEFAULT_NONCE_RETENTION_MS)),
                                   "MIN_ATTESTATION_NONCE_BYTES": .int(Int64(P.MIN_ATTESTATION_NONCE_BYTES)), "ATTEST_ANCHOR_DOMAIN": .string(P.ATTEST_ANCHOR_DOMAIN)]))
        default: return nil
        }
    }

    /// The generic comparison, with a reason that carries the reference's own exception text compared by its prefix.
    private static func compare(_ c: BaseCase, _ got: BaseGot) -> String? {
        if c.threw { return Base.diff(c, got) }
        guard case let .value(v) = got else { return Base.diff(c, got) }
        return Base.canon(trim(v)) == Base.canon(trim(c.out)) ? nil : Base.diff(c, .value(trim(v))) ?? "\(c.name): differs after the reason prefix cut"
    }

    /// A pure post-quantum or hybrid document minted with the platform's hedged ML-DSA differs from the reference in its ML-DSA signature only.
    private static func minted(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "attest", !exactMlDsa, !c.threw, case let .value(doc) = got, let alg = c.out.get("alg")?.asString, alg != "ed25519",
              case var .object(mine) = doc, case var .object(want) = c.out else { return got }
        let field = JKey(alg == "ml-dsa-65" ? "sig" : "pq_sig")
        mine[field] = nil
        want[field] = nil
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        #if canImport(AtlasPCAOpenSSL)
        if ProcessInfo.processInfo.environment["CI"] != nil { XCTAssertTrue(PCAOpenSSL.mlDsaAvailable(), "libcrypto without ML-DSA (needs 3.5+)") }
        #endif
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        var unbound = 0
        let n = try Base.each("ref-attestation-soft.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            // the legacy opt-out is not ported: the cases the reference accepts only through it must be refused
            if c.fn == "verifyAttestation", c.arg(0)?.get("allowUnboundPq") == .bool(true), c.out.get("ok") == .bool(true) {
                unbound += 1
                XCTAssertFalse(P.verifyAttestation(Self.verifyInput(A.arg(c, 0))).ok, c.name)
                return
            }
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            if !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") || Base.canon(.array(c.args)).contains("hybrid") {
                if Self.compare(c, got) != nil { d.skip("ML-DSA is not available on this OS"); return }
            }
            d.add(c, Self.compare(c, Self.minted(c, got)))
        }
        XCTAssertEqual(n, 512)
        XCTAssertEqual(unbound, 2, "the two cases accepted by the reference only through allowUnboundPq are asserted refused")
        XCTAssertEqual(seen, ["attestationBinding": 27, "attestationBindingB64u": 27, "attest": 18, "attestorPublicKey": 3, "attestationDigest": 6, "registry": 6,
                              "nonceStore": 23, "nonceEntropyOk": 32, "requiresAttestation": 29, "matchAgentBinding": 170, "nonceBinds": 8, "verifyAttestation": 91,
                              "attestationHook": 23, "multiRoot": 27, "attestationEvidenceDigest": 11, "anchorEvidence": 10, "constants": 1])
        d.finish(512 - 2 - d.skipped.values.reduce(0, +))
    }

    private static func claims(_ nonce: String) -> JSONValue {
        K042.parse(#"{"model_id":"m","weights_digest":"w","runtime_measurement":"7","operator":"op","nonce":"\#(nonce)","issued_at":1000,"expires_at":2000,"holder_pub":"holder","grant_ref":"g1","epoch":2}"#)
    }

    private static func ctx(_ nonce: String) -> JSONValue {
        K042.parse(#"{"pcactn":{"grant_ref":"g1","attestation":{"epoch":2,"quote_digest":"\#(nonce)"}},"grant":null}"#)
    }

    func testAMintedDocumentVerifiesAndAReplayIsRefused() throws {
        let ed = try Ed25519Deterministic.key(seed: [UInt8](repeating: 9, count: 32))
        let key = PCASuiteKey.ed25519(ed)
        let attestor = try P.createDevAttestor(key)
        let exp = P.ExpectedBinding(holderPub: "holder", grantRef: "g1", epoch: 2, nonce: "abcdefghijklmnopqrstuvwxyz012345")
        let doc = try attestor.attest(Self.claims(exp.nonce))
        let ctx = Self.ctx(exp.nonce)
        let store = try P.MemoryNonceStore(now: { 1500 })
        var o = P.VerifierOptions(trustedAttestorKeys: [attestor.publicKey], nonceStore: store, resolveDocument: P.attestationRegistry([doc]),
                                  expectedBinding: { _ in exp.json }, now: { 1500 })
        o.minNonceBytes = nil
        let hook = P.createAttestationVerifier(o)
        XCTAssertEqual(hook.verify(ctx), P.HookResult(enforced: true, ok: true, reason: nil, present: true, bound: true))
        XCTAssertEqual(hook.verify(ctx).reason, "attestation nonce already consumed (replay)")
        XCTAssertEqual(hook.assuranceLabel, AssuranceLabel(level: "software"))
    }

    #if canImport(AtlasPCAOpenSSL)
    func testAHybridDocumentVerifiesOnlyUnderItsPin() throws {
        guard PCAOpenSSL.mlDsaAvailable() else { return }
        let ed = try Ed25519Deterministic.key(seed: [UInt8](repeating: 3, count: 32))
        let pq = try PCAOpenSSL.mlDsaKey(.mlDsa65, seed: [UInt8](repeating: 4, count: 32))
        let key = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed, pq: pq)
        let attestor = try P.createDevAttestor(key)
        let exp = P.ExpectedBinding(holderPub: "holder", grantRef: "g1", epoch: 2, nonce: "abcdefghijklmnopqrstuvwxyz012345")
        let doc = try attestor.attest(Self.claims(exp.nonce))
        let ctx = Self.ctx(exp.nonce)
        var input = P.VerifyInput(document: doc, ctx: ctx, expected: exp.json, nowMs: 1500, trustedAttestorKeys: [attestor.publicKey])
        XCTAssertFalse(P.verifyAttestation(input).ok)
        input.pqPins = [attestor.publicKey: doc.get("pq_pk")?.asString ?? ""]
        XCTAssertTrue(P.verifyAttestation(input).ok)
    }
    #endif
}
