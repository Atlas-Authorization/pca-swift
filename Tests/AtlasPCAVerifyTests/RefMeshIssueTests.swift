import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The issuing side of the mesh and the federation primitives against the reference corpus: constants, the effective authority, the size and latency
/// models, the worked example, scripted domain / witness lifecycles (rollback, forks, revocation supersets, clocks, durable stores, export / import),
/// capability translation, the federated budget tree and cross-reference commitments. Every key is derived from its label and signs deterministically
/// (RFC 8032), so signed results are compared byte for byte on every platform. A scripted op that refuses is `{"$err": message}`.
final class RefMeshIssueTests: XCTestCase {
    private static func s(_ x: String) -> JSONValue { .string(x) }
    private static func key(_ label: String) throws -> PCAEdKey { try RefAnalyzer.key(label) }
    /// A resolved seed argument (base64url of 32 bytes) as a key; anything else is not a key.
    private static func seedKey(_ v: JSONValue?) throws -> PCAEdKey {
        guard let t = v?.asString, let b = Base64URLStrict.decode(t), b.count == 32 else { throw PCAProducerError("not a key") }
        return try Ed25519Deterministic.key(seed: b)
    }
    private static func cap(_ label: String) -> JSONValue {
        .object(["id": s(label), "issuer": s("iss-" + label), "holder": s("h"), "caveats": .array([.object(["type": s("scope"), "actions": .array([s(label)])])])])
    }

    /// A store whose save throws once `failAfter` saves happened.
    private final class FailingStore: MeshWitnessStore {
        let inner = MemoryMeshWitnessStore()
        let failAfter: Int
        var saves = 0
        init(_ n: Int) { failAfter = n }
        func load() throws -> JSONValue? { try inner.load() }
        func save(_ state: JSONValue) throws {
            saves += 1
            if saves > failAfter { throw PCAProducerError("disk") }
            try inner.save(state)
        }
    }

    static func script(_ ops: [JSONValue]) -> JSONValue {
        var doms: [String: MeshDomain] = [:], ws: [String: MeshWitness] = [:], heads: [String: JSONValue] = [:], binds: [String: JSONValue] = [:]
        var stores: [String: MeshWitnessStore] = [:]
        var created: [MeshDomain] = [] // in creation order: two names can share one key, and the reference finds the first
        func get<T>(_ m: [String: T], _ k: JSONValue) throws -> T {
            guard let name = k.asString, let v = m[name] else { throw PCAProducerError("unknown name \(JS.toString(k))") }
            return v
        }
        func size(_ v: JSONValue?) throws -> Int {
            guard let d = IV.safe(v) else { throw PCAProducerError("consistencyProof: invalid sizes") }
            return Int(d)
        }
        func with(_ v: JSONValue, _ k: String, _ x: JSONValue) -> JSONValue {
            var o = v.asObject ?? [:]
            o[JKey(k)] = x
            return .object(o)
        }
        return .array(ops.map { raw in
            let op = raw.asArray ?? []
            func a(_ i: Int) -> JSONValue { i < op.count ? op[i] : .null }
            func str(_ i: Int) -> String { a(i).asString ?? "" }
            do {
                switch str(0) {
                case "domain":
                    let d = MeshDomain(name: str(1), secret: try key("mesh-issue/d/" + str(2)))
                    doms[str(1)] = d
                    created.append(d)
                    return s(d.id)
                case "witness":
                    let w = try MeshWitness(secret: try key("mesh-issue/w/" + str(2)))
                    ws[str(1)] = w
                    return s(w.id)
                case "witnessOpts":
                    let x = a(3)
                    let store: MeshWitnessStore? = JS.truthy(x.get("store")) ? try get(stores, x.get("store") ?? .null) : nil
                    let clock: (() -> Double)? = JS.present(x.get("clock")).map { v in { IV.num(v) ?? .nan } }
                    let w = try MeshWitness(secret: try key("mesh-issue/w/" + str(2)), store: store, clock: clock, maxClockSkewMs: JS.present(x.get("skew")).flatMap { IV.num($0) })
                    ws[str(1)] = w
                    return s(w.id)
                case "store": stores[str(1)] = MemoryMeshWitnessStore(); return .bool(true)
                case "failStore": stores[str(1)] = FailingStore(Int(IV.num(a(2)) ?? 0)); return .bool(true)
                case "storeLoad": return try get(stores, a(1)).load() ?? .null
                case "record": return .int(Int64(try get(doms, a(1)).record(cap(str(2)))))
                case "revoke": try get(doms, a(1)).revoke(str(2)); return .null
                case "publish":
                    let d = try get(doms, a(1))
                    let witnesses = try (a(4).asArray ?? []).map { try get(ws, $0) }
                    let h = try d.publishHead(witnesses: witnesses, timestamp: a(3), threshold: a(5).isNull ? nil : Int(IV.num(a(5)) ?? 0))
                    heads[str(2)] = h
                    return h
                case "fork": heads[str(1)] = with(try get(heads, a(2)), str(3), a(4)); return .null
                case "forkHead":
                    let h = try get(heads, a(2))
                    heads[str(1)] = with(h, "head", with(h.get("head") ?? .null, str(3), a(4)))
                    return .null
                case "cosign":
                    let w = try get(ws, a(1)), h = try get(heads, a(2))
                    guard let domainId = h.get("head")?.get("domain")?.asString, let d = created.first(where: { IV.same($0.id, domainId) }) else { throw PCAProducerError("no such domain") }
                    var req: JObject = ["head": h]
                    if a(3).asString == "domain" {
                        if let prev = w.lastSeen(domainId) { req["consistency"] = try d.consistencyProof(oldSize: try size(prev.get("size")), newSize: try size(h.get("head")?.get("size"))) }
                    } else if JS.truthy(a(3)) { req["consistency"] = a(3) }
                    req["rev_ids"] = a(4).asString == "domain" ? .array(d.revocationSetCopy().list().map { s($0) }) : a(4)
                    return try w.cosign(.object(req))
                case "lastSeen":
                    let w = try get(ws, a(1))
                    return w.lastSeen(doms[str(2)]?.id ?? str(2)) ?? .null
                case "export": return try get(ws, a(1)).exportState()
                case "import":
                    let w = try get(ws, a(1))
                    if let other = a(2).get("$export") { try w.importState(try get(ws, other).exportState()) } else { try w.importState(a(2)) }
                    return .null
                case "restart":
                    let w = try MeshWitness(secret: try key("mesh-issue/w/" + str(3)), store: try get(stores, a(2)))
                    ws[str(1)] = w
                    return w.exportState()
                case "consistency": return try get(doms, a(1)).consistencyProof(oldSize: try size(a(2)), newSize: a(3).isNull ? nil : try size(a(3)))
                case "enroll":
                    let b = try get(doms, a(1)).enroll(agent: str(3), role: str(4))
                    binds[str(2)] = b
                    return b
                case "evidence":
                    let d = try get(doms, a(1)), h = try get(heads, a(3))
                    return try d.evidence(cap: cap(str(2)), head: h, binding: a(4).isNull ? nil : try get(binds, a(4)))
                default: throw PCAProducerError("op")
                }
            } catch {
                return .object(["$err": s((error as? PCAProducerError)?.message ?? "\(error)")])
            }
        })
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0) ?? .null, a1 = c.arg(1), a2 = c.arg(2)
        func run(_ f: () throws -> JSONValue) -> BaseGot { Base.run({ _ in nil }, f) }
        switch c.fn {
        case "constants":
            return .value(.object(["DEFAULT_MAX_HEAD_AGE_MS": PD.num(Mesh.DEFAULT_MAX_HEAD_AGE_MS), "DEFAULT_MAX_CLOCK_SKEW_MS": PD.num(Mesh.DEFAULT_MAX_CLOCK_SKEW_MS),
                                   "DEFAULT_MAX_CHAIN_LENGTH": .int(Int64(Mesh.DEFAULT_MAX_CHAIN_LENGTH))]))
        // the id is a text template: a value that is not a string reads as its JavaScript text
        case "keyRevocationId": return .value(s(keyRevocationId(JS.toString(a0))))
        case "effectiveAuthority": return run { try Mesh.effectiveAuthority(a0) }
        case "meshProofSize": return run { try Mesh.meshProofSize(a0) }
        case "revocationLatencyBound": return .value(Mesh.revocationLatencyBound(a0))
        case "buildMeshExample":
            return run {
                let ex = try Mesh.buildMeshExample(now: IV.num(a0) ?? 1_800_000_000_000) { try Ed25519Deterministic.key(seed: $0) }
                func ids(_ m: [String: MeshDomain]) -> JSONValue { .object(JObject(uniqueKeysWithValues: m.map { (JKey($0.key), s($0.value.id)) })) }
                func obj(_ m: [String: JSONValue]) -> JSONValue { .object(JObject(uniqueKeysWithValues: m.map { (JKey($0.key), $0.value) })) }
                return .object(["trust": ex.trust, "proof": ex.proof, "evidence": .array(ex.evidence), "chain": .array(ex.chain), "heads": obj(ex.heads), "bindings": obj(ex.bindings),
                                "domains": ids(ex.domains), "witnesses": .array(ex.witnesses.map { s($0.id) })])
            }
        case "demonstrateForkRejection": return run { try Mesh.demonstrateForkRejection() }
        case "meshIssue": return .value(script(a0.asArray ?? []))
        case "translateCapability":
            return run {
                // the reference reads the bridge key last: a refusal for any other reason is the same refusal here
                var args = a1?.asObject ?? [:]
                let secret = args.removeValue(forKey: "bridgeSecret")
                return try Mesh.translateCapability(a0, a1?.isObject == true ? .object(args) : (a1 ?? .null), bridge: try seedKey(secret))
            }
        case "translatedEffectiveAuthority": return .value(Mesh.translatedEffectiveAuthority(a0))
        case "verifyTranslatedCapability": return .value(Mesh.verifyTranslatedCapability(a0, a1))
        case "createFederatedBudget": return .value(Mesh.createFederatedBudget(a0))
        case "allocateSub": return .value(Mesh.allocateSub(a0, a1))
        case "spendFederated": return .value(Mesh.spendFederated(a0, a1, a2))
        case "federatedSafetyBound": return .value(PD.num(Mesh.federatedSafetyBound(a0)))
        case "meshActionDigest": return run { s(try Mesh.meshActionDigest(a0)) }
        case "crossReferenceCommit": return run { s(try Mesh.crossReferenceCommit(a0)) }
        case "anchorCrossReference": return run { try Mesh.anchorCrossReference(domain: try seedKey(a0), commit: a1 ?? .null, seq: a2 ?? .null) }
        case "verifyCrossReference": return .value(Mesh.verifyCrossReference(a0, a1))
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var perFn: [String: Int] = [:]
        var noMlDsa = 0
        let n = try Base.each("ref-mesh-issue.json.gz", seeds: true) { c in
            perFn[c.fn, default: 0] += 1
            // the hybrid-root translations need ML-DSA-65 verification, which an OS before macOS / iOS 26 does not have (refused there, fail closed)
            if !MLDSA.available, c.name.contains("hybrid") { d.skip("ML-DSA is not available on this OS"); noMlDsa += 1; return }
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            // a non-finite number is {"$num": ...} in the corpus
            if case let .value(v) = got { d.add(c, Base.diff(c, .value(RefAnalyzer.out(v)))) } else { d.add(c, Base.diff(c, got)) }
        }
        XCTAssertEqual(n, 787)
        XCTAssertEqual(perFn["meshIssue"], 23)
        XCTAssertEqual(perFn.count, 19)
        d.finish(785 - noMlDsa) // two cases carry a lone surrogate, which a Swift String cannot hold
    }

    func testTheWorkedExampleVerifies() throws {
        let ex = try Mesh.buildMeshExample()
        XCTAssertTrue(Mesh.verifyMeshProof(ex.proof, trust: ex.trust).ok)
        XCTAssertEqual(try Mesh.meshProofSize(ex.proof).get("chain_bytes"), .int(Int64(Canonical.utf8(try Canonical.canonicalizeStrict(.array(ex.chain))).count)))
        XCTAssertEqual(try Mesh.demonstrateForkRejection().get("fork_rejected"), .bool(true))
    }

    func testTranslationAndCrossReferenceRoundTrip() throws {
        let ex = try Mesh.buildMeshExample()
        let bridge = try PCAEdKey.generate(), ga = try PCAEdKey.generate(), gb = try PCAEdKey.generate()
        let args: JSONValue = .object(["fromGuardian": .string(ga.id), "toGuardian": .string(gb.id), "issued_at": .int(1),
                                       "additionalCaveats": .array([.object(["type": .string("max_amount"), "max": .int(10)])])])
        let tc = try Mesh.translateCapability(.array(ex.chain), args, bridge: bridge)
        let v = Mesh.verifyTranslatedCapability(tc, .object(["bridge": .string(bridge.id)]))
        XCTAssertEqual(v.get("ok"), .bool(true), JS.stringify(v))
        XCTAssertEqual(v.get("effective")?.get("maxAmount"), .int(10))
        XCTAssertEqual(Mesh.verifyTranslatedCapability(tc, .null).get("reason"), .string("malformed translated capability"))
        var widened = tc.asObject ?? [:]
        widened["caveats"] = .array(Array((tc.get("caveats")?.asArray ?? []).dropFirst()))
        XCTAssertEqual(Mesh.verifyTranslatedCapability(.object(widened)).get("ok"), .bool(false))

        let x: JSONValue = .object(["action_digest": .string(try Mesh.meshActionDigest(.object(["type": .string("t")]))), "fromGuardian": .string(ga.id), "toGuardian": .string(gb.id),
                                    "nonce": .string("n"), "at": .int(5)])
        let commit: JSONValue = .string(try Mesh.crossReferenceCommit(x))
        let anchors: JSONValue = .object(["from": try Mesh.anchorCrossReference(domain: ga, commit: commit, seq: .int(0)), "to": try Mesh.anchorCrossReference(domain: gb, commit: commit, seq: .int(3))])
        XCTAssertEqual(Mesh.verifyCrossReference(x, anchors).get("ok"), .bool(true))
        let swapped: JSONValue = .object(["from": anchors.get("to") ?? .null, "to": anchors.get("from") ?? .null])
        XCTAssertEqual(Mesh.verifyCrossReference(x, swapped).get("ok"), .bool(false))
    }
}
