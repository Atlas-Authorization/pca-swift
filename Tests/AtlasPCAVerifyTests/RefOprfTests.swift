import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// Differential replay of PCAOprf / PCAOprfPca (RFC 9497 ristretto255-SHA512 OPRF / VOPRF / POPRF and the private revocation / rate-limit
/// layer) against the reference (@atlasauth/pca-oprf). Keys derive from fixed public seeds and every pinned blind / proof nonce is in the
/// corpus, so outputs compare byte for byte. A non-bytes argument where the reference needs a Uint8Array is a refusal.
///
/// The corpus carries no key material: a seed is {"$seed": label} (sha256("atlas-pca-conformance/" + label)), a derived server key is
/// {"$sk": {seed, info, mode}} (re-derived here), and in an expected result every such value is {"$sha256": b64u(sha256(bytes))} (the native result
/// is hashed the same way before comparing). Literal bytes that remain are public constants (all-zero / all-ones / group-order scalars) and junk seeds.
final class RefOprfTests: XCTestCase {
    typealias O = PCAOprf
    typealias P = PCAOprfPca
    static let file = "ref-oprf.json.gz"

    struct Bad: Error {}

    /// Resolves the {"$seed"} / {"$sk"} descriptors of a value tree to {"$bytes"} members.
    static func restore(_ v: JSONValue) throws -> JSONValue {
        switch v {
        case let .array(a): return .array(try a.map(restore))
        case let .object(o):
            if o.count == 1, let (k, x) = o.first {
                if k.s == "$seed", let l = x.asString { return Base.bytesValue(seed(l)) }
                if k.s == "$sk" {
                    let sd = try bytes(try restore(x.get("seed") ?? .null)), info = try bytes(try restore(x.get("info") ?? .null))
                    return Base.bytesValue(try O.deriveKeyPair(seed: sd, info: info, mode: try mode(x.get("mode"))).secretKey)
                }
            }
            return .object(try o.mapValues(restore))
        default: return v
        }
    }

    static func bytes(_ v: JSONValue?) throws -> [UInt8] { guard let b = Base.bytes(v) else { throw Bad() }; return b }
    /// An optional Uint8Array: absent is nil, present but not bytes is a refusal (null reaches the reference as null, not undefined).
    static func opt(_ c: BaseCase, _ i: Int) throws -> [UInt8]? { try i < c.args.count ? bytes(c.args[i]) : nil }
    static func mode(_ v: JSONValue?) throws -> O.Mode { guard let m = v?.asString.flatMap({ O.Mode(rawValue: $0) }) else { throw Bad() }; return m }
    static func bv(_ b: [UInt8]) -> JSONValue { Base.bytesValue(b) }
    static func str(_ v: JSONValue?) throws -> String { guard let s = v?.asString else { throw Bad() }; return s }

    static func evalJSON(_ r: O.EvaluateResult) -> JSONValue {
        var o: JObject = ["evaluatedElement": bv(r.evaluatedElement)]
        if let p = r.proof { o["proof"] = bv(p) }
        return .object(o)
    }

    static var poprfKey: [UInt8] { get throws { try O.deriveKeyPair(seed: seed("ref-oprf/key-poprf"), info: [UInt8]("k".utf8), mode: .poprf).secretKey } }

    /// seed('ref-oprf/key-<mode>') of the generator: sha256 of "atlas-pca-conformance/" + label (base lib seed()).
    static func seed(_ label: String) -> [UInt8] { Array(SHA256.hash(data: Data(("atlas-pca-conformance/" + label).utf8))) }

    static func keyFor(_ m: O.Mode) throws -> [UInt8] {
        try O.deriveKeyPair(seed: seed("ref-oprf/key-\(m.rawValue)"), info: [UInt8]("k".utf8), mode: m).secretKey
    }

    static func revocation(_ capId: JSONValue?, _ op: JSONValue?) throws -> Bool {
        let sk = try bytes(op?.get("sk")), m = try mode(op?.get("mode"))
        let revoked = try (op?.get("revoked")?.asArray ?? []).map { try str($0) }
        let set = try P.buildRevocationSet(secretKey: sk, revokedCapIds: revoked, mode: m)
        let lie = op?.get("lie")?.asString
        let evalKey: [UInt8]
        if lie == "wrong-key" { evalKey = try poprfKey } else { evalKey = sk }
        let real = try P.makeRevocationEvaluator(secretKey: evalKey, mode: m)
        let ev: P.BlindEvaluator = { b in
            let r = try real(b)
            return lie == "no-proof" ? O.EvaluateResult(evaluatedElement: r.evaluatedElement) : r
        }
        return try P.isRevokedPrivate(try str(capId), blindEval: ev, revokedSet: set)
    }

    static func counter(_ limit: JSONValue?, _ steps: JSONValue?) throws -> JSONValue {
        let n: Int
        switch limit {
        case let .int(i)?: n = Int(i)
        case let .double(d)? where d.isFinite && d.rounded() == d: n = Int(d)
        default: throw Bad()
        }
        let c = try P.RateWindowCounter(limit: n)
        var out: [JSONValue] = []
        for s in steps?.asArray ?? [] {
            guard let a = s.asArray, let op = a.first?.asString else { throw Bad() }
            switch op {
            case "hit":
                let r = c.hit(try bytes(a.count > 1 ? a[1] : nil))
                out.append(.object(["count": .int(Int64(r.count)), "allowed": .bool(r.allowed)]))
            case "count": out.append(.int(Int64(c.count(try bytes(a.count > 1 ? a[1] : nil)))))
            default: c.reset(); out.append(.null)
            }
        }
        return .array(out)
    }

    func testOprfAgainstTheReference() throws {
        try K042.requireCovers(["Oprf", "RatchetGroup"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c0 in
            let c = BaseCase(fn: c0.fn, name: c0.name, args: try c0.args.map(Self.restore), out: c0.out, suspect: c0.suspect, raw: c0.raw)
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "deriveKeyPair":
                    let k = try O.deriveKeyPair(seed: try Self.bytes(a[0]), info: try Self.bytes(a[1]), mode: try Self.mode(a[2]))
                    return .object(["secretKey": Self.bv(k.secretKey), "publicKey": Self.bv(k.publicKey)])
                case "publicKeyFor": return Self.bv(try O.publicKeyFor(try Self.bytes(a[0])))
                case "deserializeScalar": return .string(BigUInt(bytesLE: try O.deserializeScalar(try Self.bytes(a[0]))).ratchetDecimal)
                case "serializeScalar":
                    guard let n = PCABigInt(try Self.str(a[0])) else { throw Bad() }
                    return Self.bv(O.serializeScalar(n))
                case "hashToGroup": return Self.bv(try O.hashToGroup(try Self.bytes(a[0]), try Self.mode(a[1])))
                case "deserializeElement": return Self.bv(try O.deserializeElement(try Self.bytes(a[0])))
                case "blind":
                    let r = try O.blind(input: try Self.bytes(a[0]), mode: try Self.mode(a[1]), fixedBlind: try Self.opt(c, 2))
                    return .object(["blind": Self.bv(r.blind), "blindedElement": Self.bv(r.blindedElement)])
                case "blindEvaluate":
                    return Self.evalJSON(try O.blindEvaluate(secretKey: try Self.bytes(a[0]), blindedElement: try Self.bytes(a[1]), mode: try Self.mode(a[2]),
                                                            publicKey: try Self.opt(c, 3), fixedProofRandomness: try Self.opt(c, 4)))
                case "evaluate": return Self.bv(try O.evaluate(secretKey: try Self.bytes(a[0]), input: try Self.bytes(a[1]), mode: try Self.mode(a[2])))
                case "finalize":
                    let o = a.count > 4 ? a[4] : nil
                    return Self.bv(try O.finalize(input: try Self.bytes(a[0]), blind: try Self.bytes(a[1]), evaluatedElement: try Self.bytes(a[2]),
                                                  mode: try Self.mode(a[3]), proof: o?.get("proof").flatMap { Base.bytes($0) },
                                                  publicKey: o?.get("publicKey").flatMap { Base.bytes($0) },
                                                  blindedElement: o?.get("blindedElement").flatMap { Base.bytes($0) }))
                case "blindPoprf":
                    let r = try O.blindPoprf(input: try Self.bytes(a[0]), info: try Self.bytes(a[1]), publicKey: try Self.bytes(a[2]), fixedBlind: try Self.opt(c, 3))
                    return .object(["blind": Self.bv(r.blind), "blindedElement": Self.bv(r.blindedElement), "tweakedKey": Self.bv(r.tweakedKey)])
                case "blindEvaluatePoprf":
                    return Self.evalJSON(try O.blindEvaluatePoprf(secretKey: try Self.bytes(a[0]), blindedElement: try Self.bytes(a[1]), info: try Self.bytes(a[2]),
                                                                 fixedProofRandomness: try Self.opt(c, 3)))
                case "finalizePoprf":
                    guard let o = a.count > 4 ? a[4] : nil, let proof = Base.bytes(o.get("proof")) else { throw Bad() }
                    return Self.bv(try O.finalizePoprf(input: try Self.bytes(a[0]), blind: try Self.bytes(a[1]), evaluatedElement: try Self.bytes(a[2]),
                                                       info: try Self.bytes(a[3]), proof: proof, blindedElement: try Self.bytes(o.get("blindedElement")),
                                                       tweakedKey: try Self.bytes(o.get("tweakedKey"))))
                case "evaluatePoprf": return Self.bv(try O.evaluatePoprf(secretKey: try Self.bytes(a[0]), input: try Self.bytes(a[1]), info: try Self.bytes(a[2])))
                case "toHex": return .string(O.toHex(try Self.bytes(a[0])))
                case "bytesEqual": return .bool(O.bytesEqual(try Self.bytes(a[0]), try Self.bytes(a[1])))
                case "buildRevocationSet":
                    let m = try Self.mode(a[2])
                    let ids = try (a[1].asArray ?? []).map { try Self.str($0) }
                    if c.name.hasSuffix("-surrogate") { _ = try P.buildRevocationSet(secretKey: try Self.bytes(a[0]), revokedCapIds: ids, mode: m); return .string(m.rawValue) }
                    let s = try P.buildRevocationSet(secretKey: try Self.bytes(a[0]), revokedCapIds: ids, mode: m)
                    var o: JObject = ["outputs": .array(s.outputs.sorted().map { .string($0) }), "mode": .string(m.rawValue)]
                    // the generator drops the public key from the duplicate-ids case only
                    if let pk = s.publicKey, !c.name.hasSuffix("-dups") { o["publicKey"] = Self.bv(pk) }
                    return .object(o)
                case "isRevokedPrivate": return .bool(try Self.revocation(a[0], a[1]))
                case "rateToken":
                    return Self.bv(try P.rateToken(secretKey: try Self.bytes(a[0]), identifier: try Self.str(a[1]), window: try Self.str(a[2])))
                case "rateTokenHex":
                    return .string(try P.rateTokenHex(secretKey: try Self.bytes(a[0]), identifier: try Self.str(a[1]), window: try Self.str(a[2])))
                case "privateRateToken":
                    let op = a[2]
                    let sk = try Self.bytes(op.get("sk"))
                    let pk = try Base.bytes(op.get("pk")) ?? O.publicKeyFor(sk)
                    return Self.bv(try P.privateRateToken(try Self.str(a[0]), try Self.str(a[1]), blindEval: P.makeRateEvaluator(secretKey: sk), publicKey: pk))
                case "rateCounter": return try Self.counter(a[0], a[1])
                default: throw Bad()
                }
            }
            d.add(c, Base.diff(c, RefFrostTests.masked(got, c.out)))
        }
        d.finish(508)
    }
}
