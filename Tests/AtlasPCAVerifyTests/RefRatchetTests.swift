import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the capability ratchet and the risk accumulator against the reference (@atlasauth/pca-ratchet): leaf
/// nullifiers, the counter and risk adapters, the carry-forward quantizer, the ratchet scenarios (derive / sign / verify / once), the
/// Pedersen commitments and the range / budget / attested-budget verdicts. The reference provers draw fresh randomness, so the recorded
/// prover cases are refusals (they must refuse with the reference's code); the roundtrips live in RefRatchetKatTests.
final class RefRatchetTests: XCTestCase {
    static let file = "ref-ratchet.json.gz"
    typealias R = PCARatchet
    typealias A = PCARatchetAccumulator

    /// Leaf signatures are compared byte for byte, so the deterministic RFC 8032 signer stands in for the hedged platform one.
    static let signer: PCARatchet.LeafSigner = { Ed25519Deterministic.sign(seed: $0, $1) }

    static func code(_ e: Error) -> String? { (e as? PCARatchetError)?.code }
    static func bi(_ n: PCABigInt) -> JSONValue { .object(["$bigint": .string(n.description)]) }

    /// {"$bigint": "<decimal>"}: the reference's BigInt argument.
    static func bigArg(_ v: JSONValue?) -> PCABigInt? {
        guard let o = v?.asObject, o.count == 1, let s = o["$bigint"]?.asString else { return nil }
        return PCABigInt(s)
    }

    static func units(_ v: JSONValue?) throws -> PCABigInt {
        if let b = bigArg(v) {
            if b.isNegative { throw PCARatchetError("invalid_value", "risk/budget must be >= 0") }
            return b
        }
        return try PCABigInt.units(v)
    }

    /// The reference refuses a plain number where a bigint is required.
    static func needBig(_ v: JSONValue?) throws -> PCABigInt {
        guard let b = bigArg(v) else { throw PCARatchetError(nil, "a bigint is required") }
        return b
    }

    /// A {"$bytes": <non-string>} argument: the shared decoder cannot represent it (the reference refuses it while decoding).
    static func badBytes(_ v: JSONValue) -> Bool {
        switch v {
        case let .object(o):
            if o.count == 1, let b = o["$bytes"] { return b.asString == nil }
            return o.values.contains(where: badBytes)
        case let .array(a): return a.contains(where: badBytes)
        default: return false
        }
    }

    static func keyString(_ k: JSONValue) -> String {
        switch k {
        case let .string(s): return s
        case let .int(i): return String(i)
        default: return Base.canon(k)
        }
    }

    /// The corpus clonePath: a deep copy with `path` set to `value` ("__DEL__" deletes); an empty path names the member "undefined".
    static func setPath(_ v: JSONValue, _ path: [JSONValue], _ value: JSONValue) -> JSONValue {
        let del = value == .string("__DEL__")
        let key: JSONValue = path.last ?? .string("undefined")
        func go(_ t: JSONValue, _ i: Int) -> JSONValue {
            if i >= path.count - 1 {
                switch t {
                case var .object(o):
                    o[JKey(keyString(key))] = del ? nil : value
                    return .object(o)
                case var .array(a):
                    if !del, case let .int(n) = key, n >= 0, Int(n) < a.count { a[Int(n)] = value }
                    return .array(a)
                default: return t
                }
            }
            let k = path[i]
            switch t {
            case var .object(o):
                if let ks = k.asString, let child = o[JKey(ks)] { o[JKey(ks)] = go(child, i + 1); return .object(o) }
                return t
            case var .array(a):
                if case let .int(n) = k, n >= 0, Int(n) < a.count { a[Int(n)] = go(a[Int(n)], i + 1); return .array(a) }
                return t
            default: return t
            }
        }
        return go(v, 0)
    }

    struct ThrowingStore: PCASpentLeafStore {
        func claim(_ nullifier: String, _ record: String) throws -> (first: Bool, record: String?) { throw JSError("boom") }
    }

    static func scenario(_ spec: JSONValue?) -> JSONValue {
        let store: PCASpentLeafStore = spec?.get("store")?.asString == "throws" ? ThrowingStore() : PCAMemorySpentLeafStore()
        var state: PCARatchetState?
        var root: String?
        var sigs: [JSONValue] = []
        var out: [JSONValue] = []
        for s in spec?.get("ops")?.asArray ?? [] {
            do {
                switch s.get("op")?.asString {
                case "derive"?:
                    guard let depth = s.get("depth") else { throw JSError("depth missing") }
                    let d = try R.deriveRatchetRoot(seed: Base.bytes(s.get("seed")) ?? [], depth: depth)
                    state = d.state
                    root = d.rootCommitment
                    out.append(.object(["root": .string(d.rootCommitment), "leafPubKeys": .array(d.state.leafPubKeys.map { .string($0) }),
                                        "available": .array(R.availableLeaves(d.state).map { .int(Int64($0)) })]))
                case "sign"?:
                    guard let st = state, let msg = Base.bytes(s.get("msg")) else { throw JSError("no state") }
                    let r = try R.signAtLeaf(st, leafIndex: s.get("leaf"), message: msg, signer: signer)
                    state = r.newState
                    sigs.append(r.signature)
                    out.append(.object(["signature": r.signature]))
                case "avail"?:
                    guard let st = state else { throw JSError("no state") }
                    out.append(.array(R.availableLeaves(st).map { .int(Int64($0)) }))
                case "isAvail"?:
                    guard let st = state else { throw JSError("no state") }
                    out.append(.bool(R.isLeafAvailable(st, leafIndex: s.get("leaf"))))
                case let op? where op == "verify" || op == "once":
                    guard case let .int(ref)? = s.get("sigRef"), ref >= 0, Int(ref) < sigs.count, let msg = Base.bytes(s.get("msg")) else {
                        throw JSError("no signature")
                    }
                    var sig = sigs[Int(ref)]
                    for p in s.get("set")?.asArray ?? [] {
                        guard let pair = p.asArray, pair.count == 2 else { throw JSError("bad set") }
                        sig = setPath(sig, pair[0].asArray ?? [], pair[1])
                    }
                    let rc: JSONValue = s.get("root")?.asString == "other" ? .string("other-root") : (root.map { .string($0) } ?? .null)
                    if op == "verify" {
                        out.append(.bool(R.verifyLeafSignature(rootCommitment: rc, leafIndex: s.get("leaf"), message: msg, signature: sig)))
                    } else {
                        out.append(R.verifyLeafSignatureOnce(rootCommitment: rc, leafIndex: s.get("leaf"), message: msg, signature: sig, store: store))
                    }
                default: throw JSError("bad op")
                }
            } catch {
                let e: JSONValue = code(error).map { JSONValue.string($0) } ?? .bool(true)
                out.append(.object(["$err": e]))
            }
        }
        return .array(out)
    }

    func testRatchetAgainstTheReference() throws {
        try K042.requireCovers(["Ratchet", "RatchetGroup", "RatchetAccumulator", "JSInterop", "Merkle"])
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            if Self.badBytes(.array(c.args)) { d.skip("malformed $bytes argument"); return }
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3), a4 = c.arg(4)
            let got: BaseGot
            switch c.fn {
            case "leafNullifier":
                guard let root = a0?.asString else { d.skip("leafNullifier: non-string root"); return }
                got = Base.run(Self.code) { .string(try R.leafNullifier(rootCommitment: root, leafIndex: a1)) }
            case "counterToLeafIndex": got = Base.run(Self.code) { .int(Int64(try R.counterToLeafIndex(a0, depth: a1))) }
            case "leafIndexToCounter": got = Base.run(Self.code) { .int(Int64(try R.leafIndexToCounter(a0))) }
            case "leafIndexForAction": got = Base.run(Self.code) { .int(Int64(try R.leafIndexForAction(a0, depth: a1))) }
            case "riskToUnits": got = Base.run(Self.code) { Self.bi(try R.riskToUnits(a0)) }
            case "budgetCeilingUnits": got = Base.run(Self.code) { Self.bi(try R.budgetCeilingUnits(a0)) }
            case "quantizer":
                var q = PCARiskQuantizer()
                var out: [JSONValue] = []
                for r in a0?.asArray ?? [] {
                    if let u = try? q.next(r) { out.append(Self.bi(u)) } else { out.append(.object(["$err": .bool(true)])) }
                }
                out.append(Self.bi(q.totalUnits))
                got = .value(.array(out))
            case "ratchet": got = .value(Self.scenario(a0))
            case "commitRisk":
                got = Base.run(Self.code) {
                    let risk = try Self.units(a0)
                    let r = try A.commitRisk(risk, blinding: try Self.needBig(a1))
                    return .object(["commitment": .string(r.commitment), "blinding": Self.bi(r.blinding)])
                }
            case "addCommitments":
                got = Base.run(Self.code) {
                    switch a0 {
                    case let .array(a)?:
                        return .string(try A.addCommitments(try a.map { guard let s = $0.asString else { throw JSError("not a string") }; return s }))
                    case let .string(s)?:
                        // for-of over a string yields its characters: none decodes, the empty string sums to the identity
                        if !s.isEmpty { throw JSError("not a canonical 32-byte base64url string") }
                        return .string(try A.addCommitments([]))
                    default: throw JSError("not iterable")
                    }
                }
            case "openCommitment":
                guard let risk = try? Self.units(a1), let blinding = Self.bigArg(a2) else { got = .value(.bool(false)); break }
                got = .value(.bool(A.openCommitment(a0, risk: risk, blinding: blinding)))
            case "verifyRiskRange": got = .value(.bool(A.verifyRiskRange(a0, proof: a1)))
            case "verifyBudget":
                guard let bMax = try? Self.units(a1) else { got = .value(.bool(false)); break }
                got = .value(.bool(A.verifyBudget(a0, bMax: bMax, proof: a2)))
            case "verifyBoundedBudget":
                guard let bMax = try? Self.units(a2) else { got = .value(.bool(false)); break }
                got = .value(.bool(A.verifyBoundedBudget(a0, rangeProofs: a1, bMax: bMax, budgetProof: a3)))
            case "proveBudget":
                got = Base.run(Self.code) {
                    guard let rs = a0?.asArray, let bs = a1?.asArray else { throw JSError("not a list") }
                    if rs.count != bs.count { throw PCARatchetError("length_mismatch", "risks and blindings must have equal length") }
                    let ceiling = try Self.units(a2)
                    var risks: [PCABigInt] = [], blindings: [PCABigInt] = []
                    for i in rs.indices { risks.append(try Self.units(rs[i])); blindings.append(try Self.needBig(bs[i])) }
                    return try A.proveBudget(risks: risks, blindings: blindings, bMax: ceiling)
                }
            case "proveRiskRange":
                got = Base.run(Self.code) { try A.proveRiskRange(try Self.units(a0), blinding: try Self.needBig(a1)) }
            case "issueRiskCommitment":
                got = Base.run(Self.code) {
                    let risk = try Self.units(a0)
                    guard let digest = a1?.asString else { throw JSError("not a string") }
                    let key = a2?.asString == "short" ? [UInt8](repeating: 0, count: 3) : RefKeys.seed("ratchet-authority")
                    let r = try R.issueRiskCommitment(risk: risk, actionDigest: digest, authoritySecretKey: key, signer: Self.signer)
                    return .object(["commitment": .string(r.commitment), "blinding": Self.bi(r.blinding), "rangeProof": r.rangeProof, "attestation": r.attestation])
                }
            case "verifyRiskAttestation": got = .value(.bool(R.verifyRiskAttestation(commitment: a0, attestation: a1, authorityPublicKey: a2)))
            case "verifyAttestedBudget":
                guard let bMax = try? Self.units(a3) else { got = .value(.bool(false)); break }
                got = .value(.bool(R.verifyAttestedBudget(items: a0, expectedActionDigests: a1, authorityPublicKey: a2, bMax: bMax, budgetProof: a4)))
            default:
                XCTFail("unknown fn \(c.fn)")
                return
            }
            // a prover's recorded value is one random draw: those proofs are checked by the verifier in the roundtrip tests
            if !c.threw, ["proveBudget", "proveRiskRange", "issueRiskCommitment"].contains(c.fn) {
                d.skip("\(c.fn): random proof, covered by the roundtrip tests"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1000)
    }
}
