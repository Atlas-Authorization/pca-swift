import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the issuing side of the mesh against the TypeScript reference: the domain's evidence, enroll and pin proofs (ref-core-mesh-domain-java), proof assembly
/// and action signing over scripted multi-domain sequences (ref-core-mesh-proof-java) and the witness with its durable store (the `meshWitness` cases of
/// ref-core-stores-java). Each case is a script of operations whose results are compared as one array; a thrown error is `{"$err": ...}` (the message for the
/// witness, a bare "Error" for the domain and proof scripts).
final class RefCoreStoresMeshTests: XCTestCase {
    private static func key(_ label: String) throws -> PCAEdKey { try RefCoreStoresTests.edKey(label) }
    private static func s(_ x: String) -> JSONValue { .string(x) }
    private static func cap(_ label: String) -> JSONValue {
        .object(["id": s(label), "issuer": s("iss-" + label), "holder": s("h"), "caveats": .array([.object(["type": s("scope"), "actions": .array([s(label)])])])])
    }
    private static func arg(_ op: [JSONValue], _ i: Int) -> JSONValue { i < op.count ? op[i] : .null }
    private static func str(_ op: [JSONValue], _ i: Int) throws -> String {
        guard let v = arg(op, i).asString else { throw PCAProducerError("not a string") }
        return v
    }
    private static func need<T>(_ v: T?) throws -> T {
        guard let x = v else { throw PCAProducerError("missing") }
        return x
    }
    private static func threshold(_ v: JSONValue) -> Int? { v.isNull ? nil : v.safeInt.map { Int($0) } }
    private static func with(_ v: JSONValue, _ k: String, _ x: JSONValue) -> JSONValue {
        var o = v.asObject ?? [:]
        o[JKey(k)] = x
        return .object(o)
    }

    private static func script(_ ops: [JSONValue], byMessage: Bool, _ f: ([JSONValue]) throws -> JSONValue) -> JSONValue {
        .array(ops.map { o in
            do { return try f(o.asArray ?? []) } catch {
                return .object(["$err": s(byMessage ? ((error as? PCAProducerError)?.message ?? "\(error)") : "Error")])
            }
        })
    }

    static func domainScript(_ ops: [JSONValue], _ prefix: String) -> JSONValue {
        var doms: [String: MeshDomain] = [:], ws: [String: MeshWitness] = [:], heads: [String: JSONValue] = [:], binds: [String: JSONValue] = [:]
        return script(ops, byMessage: false) { op in
            switch try str(op, 0) {
            case "domain":
                let d = MeshDomain(name: try str(op, 1), secret: try key(prefix + (try str(op, 2))))
                doms[try str(op, 1)] = d
                return s(d.id)
            case "witness":
                let w = try MeshWitness(secret: try key(prefix + (try str(op, 2))))
                ws[try str(op, 1)] = w
                return s(w.id)
            case "record": return .int(Int64(try need(doms[try str(op, 1)]).record(cap(try str(op, 2)))))
            case "revoke": try need(doms[try str(op, 1)]).revoke(try str(op, 2)); return .null
            case "publish":
                let names = try need(arg(op, 4).asArray).map { try str([$0], 0) }
                let h = try need(doms[try str(op, 1)]).publishHead(witnesses: try names.map { try need(ws[$0]) }, timestamp: arg(op, 3), threshold: threshold(arg(op, 5)))
                heads[try str(op, 2)] = h
                return h
            case "fork": heads[try str(op, 1)] = with(try need(heads[try str(op, 2)]), try str(op, 3), arg(op, 4)); return .null
            case "enroll":
                let b = try need(doms[try str(op, 1)]).enroll(agent: try str(op, 3), role: try str(op, 4))
                binds[try str(op, 2)] = b
                return b
            case "evidence":
                // `binds.get(name)`: an unknown name is an absent binding, not a refusal
                var binding: JSONValue? = nil
                if !arg(op, 4).isNull { binding = binds[try str(op, 4)] }
                return try need(doms[try str(op, 1)]).evidence(cap: cap(try str(op, 2)), head: try need(heads[try str(op, 3)]), binding: binding)
            case "pinProof":
                let pin: JSONValue = arg(op, 2).asString != nil ? try need(try need(heads[try str(op, 2)]).get("head")) : arg(op, 2)
                return try need(doms[try str(op, 1)]).pinProof(pin: pin, head: try need(heads[try str(op, 3)]))
            case "nonMembership": return try need(doms[try str(op, 1)]).revocationSetCopy().nonMembershipProof(try str(op, 2))
            default: throw PCAProducerError("op")
            }
        }
    }

    static func proofScript(_ ops: [JSONValue]) -> JSONValue {
        var doms: [String: MeshDomain] = [:], ws: [String: MeshWitness] = [:], store: [String: JSONValue] = [:]
        let prefix = "mesh-proof/"
        return script(ops, byMessage: false) { op in
            switch try str(op, 0) {
            case "domain":
                let d = MeshDomain(name: try str(op, 1), secret: try key(prefix + (try str(op, 2))))
                doms[try str(op, 1)] = d
                return s(d.id)
            case "witness":
                let w = try MeshWitness(secret: try key(prefix + (try str(op, 2))))
                ws[try str(op, 1)] = w
                return s(w.id)
            case "record": return .int(Int64(try need(doms[try str(op, 1)]).record(cap(try str(op, 2)))))
            case "revoke": try need(doms[try str(op, 1)]).revoke(try str(op, 2)); return .null
            case "publish":
                let names = try need(arg(op, 4).asArray).map { try str([$0], 0) }
                let h = try need(doms[try str(op, 1)]).publishHead(witnesses: try names.map { try need(ws[$0]) }, timestamp: arg(op, 3), threshold: threshold(arg(op, 5)))
                store[try str(op, 2)] = h
                return h
            case "subcos":
                let h = try need(store[try str(op, 2)])
                let cos = try need(h.get("cosigs")?.asArray)
                let picked: [JSONValue] = try need(arg(op, 3).asArray).map { v in
                    let i = Int(try need(v.safeInt))
                    guard i >= 0, i < cos.count else { throw PCAProducerError("range") }
                    return cos[i]
                }
                store[try str(op, 1)] = with(h, "cosigs", .array(picked))
                return .null
            case "fork": store[try str(op, 1)] = with(try need(store[try str(op, 2)]), try str(op, 3), arg(op, 4)); return .null
            case "forkHead":
                let h = try need(store[try str(op, 2)])
                store[try str(op, 1)] = with(h, "head", with(try need(h.get("head")), try str(op, 3), arg(op, 4)))
                return .null
            case "enroll":
                let b = try need(doms[try str(op, 1)]).enroll(agent: try str(op, 3), role: try str(op, 4))
                store[try str(op, 2)] = b
                return b
            case "ev":
                let binding: JSONValue? = arg(op, 5).isNull ? nil : try need(store[try str(op, 5)])
                let e = try need(doms[try str(op, 1)]).evidence(cap: cap(try str(op, 3)), head: try need(store[try str(op, 4)]), binding: binding)
                store[try str(op, 2)] = e
                return e
            case "setEv":
                var e = try need(try need(store[try str(op, 2)]).asObject)
                let val = arg(op, 4), name = try str(op, 3)
                if case let .object(vo) = val, vo["$del"] != nil { e[JKey(name)] = nil }
                else if name == "head", let k = val.asString, let h = store[k] { e["head"] = h }
                else { e[JKey(name)] = val }
                store[try str(op, 1)] = .object(e)
                return .null
            case "pinProofAs":
                let pinV = arg(op, 3)
                let pin: JSONValue = pinV.asString != nil ? try need(try need(store[pinV.asString!]).get("head")) : pinV
                let p = try need(doms[try str(op, 1)]).pinProof(pin: pin, head: try need(store[try str(op, 4)]))
                store[try str(op, 2)] = p
                return p
            case "assemble":
                let pins: [JSONValue] = try arg(op, 5).isNull ? [] : try need(arg(op, 5).asArray).map { try need(store[try str([$0], 0)]) }
                let chain = try need(arg(op, 1).asArray).map { cap(try str([$0], 0)) }
                let hops = try need(arg(op, 2).asArray).map { try need(store[try str([$0], 0)]) }
                return try PCASigners.assembleMeshProof(chain: chain, hops: hops, action: arg(op, 3), leaf: try key(prefix + (try str(op, 4))), pinProofs: pins)
            case "sign":
                let chain = try need(arg(op, 1).asArray).map { cap(try str([$0], 0)) }
                return s(try PCASigners.signMeshAction(chain: chain, action: arg(op, 2), leaf: try key(prefix + (try str(op, 3)))))
            default: throw PCAProducerError("op")
            }
        }
    }

    static func witnessScript(_ ops: [JSONValue]) -> JSONValue {
        var stores: [String: MemoryMeshWitnessStore] = [:], ws: [String: MeshWitness] = [:], doms: [String: MeshDomain] = [:]
        return script(ops, byMessage: true) { op in
            switch try str(op, 0) {
            case "store": stores[try str(op, 1)] = MemoryMeshWitnessStore(); return .bool(true)
            case "witness":
                let st: MeshWitnessStore? = arg(op, 2).isNull ? nil : try need(stores[try str(op, 2)])
                let w = try MeshWitness(secret: try key(try str(op, 3)), store: st)
                ws[try str(op, 1)] = w
                return s(w.id)
            case "witnessClock":
                let now = try need(IV.num(arg(op, 3)))
                let skew: Double? = arg(op, 4).isNull ? nil : IV.num(arg(op, 4))
                ws[try str(op, 1)] = try MeshWitness(secret: try key(try str(op, 2)), clock: { now }, maxClockSkewMs: skew)
                return .bool(true)
            case "restart":
                let w = try MeshWitness(secret: try key(try str(op, 3)), store: try need(stores[try str(op, 2)]))
                ws[try str(op, 1)] = w
                return w.exportState()
            case "domain":
                let d = MeshDomain(name: try str(op, 1), secret: try key(try str(op, 2)))
                doms[try str(op, 1)] = d
                return s(d.id)
            case "record":
                let id = try str(op, 2)
                return .int(Int64(try need(doms[try str(op, 1)]).record(.object(["id": s(id), "caveats": .array([.object(["type": s("scope"), "actions": .array([s(id)])])])]))))
            case "revoke": try need(doms[try str(op, 1)]).revoke(try str(op, 2)); return .null
            case "publish":
                let names = try need(arg(op, 3).asArray).map { try str([$0], 0) }
                return try need(doms[try str(op, 1)]).publishHead(witnesses: try names.map { try need(ws[$0]) }, timestamp: arg(op, 2), threshold: threshold(arg(op, 4)))
            case "lastSeen": return try need(ws[try str(op, 1)]).lastSeen(try str(op, 2)) ?? .null
            case "export": return try need(ws[try str(op, 1)]).exportState()
            case "import": try need(ws[try str(op, 1)]).importState(arg(op, 2)); return .null
            case "load": return try need(stores[try str(op, 1)]).load() ?? .null
            case "save": try need(stores[try str(op, 1)]).save(arg(op, 2)); return .null
            case "domainId": return s(try need(doms[try str(op, 1)]).id)
            default: throw PCAProducerError("op")
            }
        }
    }

    private func replay(_ file: String, _ fn: String, minimum: Int, _ run: ([JSONValue]) -> JSONValue) throws {
        let d = Base.Diffs()
        let n = try Base.each(file, [fn]) { c in d.add(c, Base.diff(c, .value(run(c.arg(0)?.asArray ?? [])))) }
        XCTAssertGreaterThanOrEqual(n, minimum, fn)
        d.finish(minimum)
    }

    func testMeshDomainAgainstTheReference() throws {
        try replay("ref-core-mesh-domain-java.json.gz", "meshDomain", minimum: 18) { Self.domainScript($0, "mesh-domain/") }
    }

    func testMeshProofAssemblyAgainstTheReference() throws {
        try replay("ref-core-mesh-proof-java.json.gz", "meshProof", minimum: 8) { Self.proofScript($0) }
    }

    func testMeshWitnessAgainstTheReference() throws {
        try replay(RefCoreStoresTests.file, "meshWitness", minimum: 9) { Self.witnessScript($0) }
    }

    func testNonMembershipProofsVerify() throws {
        let set = RevocationSet(["b", "d", "f", "h", "j"])
        for rid in ["a", "c", "e", "g", "i", "k", "", "key:x"] {
            guard case let .object(p) = try set.nonMembershipProof(rid) else { return XCTFail("proof") }
            XCTAssertTrue(Mesh.nonMembership(set.root, p, rid), rid)
        }
        for rid in ["b", "d", "j"] { XCTAssertThrowsError(try set.nonMembershipProof(rid), rid) }
        XCTAssertEqual(try RevocationSet().nonMembershipProof("a").get("size"), .int(0))
    }
}
