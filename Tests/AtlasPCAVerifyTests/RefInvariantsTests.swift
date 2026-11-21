import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAInvariants against the reference (@atlasauth/pca-invariants): key pairs from seeds, the legal-chain
/// builder (the chains compare byte for byte: Ed25519 signing is deterministic, so the key constructor is swapped for the RFC 8032
/// one), the risk "worsen" helper and the registry constants. The corpus carries seed labels, never key bytes ({"$seed": label}).
final class RefInvariantsTests: XCTestCase {
    static let file = "ref-invariants.json.gz"

    /// {"$seed": label} -> {"$bytes": sha256("atlas-pca-conformance/" + label)}.
    static func restore(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(restore))
        case let .object(o):
            // {"$bytes": {"$seed": label}}: the seed object already stands for the bytes
            if o.count == 1, let inner = o["$bytes"]?.asObject, inner["$seed"] != nil { return restore(.object(inner)) }
            if o.count == 1, let l = o["$seed"]?.asString { return Base.bytesValue(Canonical.sha256(Array("atlas-pca-conformance/\(l)".utf8))) }
            return .object(o.mapValues(restore))
        default: return v
        }
    }

    static func det(_ seed: [UInt8]) throws -> PCAEdKey { try Ed25519Deterministic.key(seed: seed) }

    func testInvariants() throws {
        try K042.requireCovers(["Invariants", "Issue", "Keys"])
        let d = Base.Diffs()
        try Base.each(Self.file) { raw in
            let c = BaseCase(fn: raw.fn, name: raw.name, args: raw.args.map(Self.restore), out: Self.restore(raw.out), suspect: raw.suspect, raw: raw.raw)
            let got: BaseGot
            switch c.fn {
            case "keyPairFromSeed":
                got = Ref.v {
                    guard let seed = Base.bytes(c.arg(0)) else { throw JSError("seed") }
                    let p = try PCAInvariants.keyPairFromSeed(seed, keyFor: Self.det)
                    return .object(["secretKey": Base.bytesValue(p.secretKey), "publicKey": Base.bytesValue(p.publicKey), "pub": .string(p.pub)])
                }
            case "buildChain":
                got = Ref.v {
                    let m = Ref.obj(c.arg(0))
                    func seed(_ v: JSONValue?) throws -> [UInt8] { guard let b = Base.bytes(v) else { throw JSError("seed") }; return b }
                    let hops = try (m["hops"]?.asArray ?? []).map { (h: JSONValue) throws -> PCAInvariants.Hop in
                        PCAInvariants.Hop(holderSeed: try seed(h.get("holderSeed")), addedSpecs: h.get("addedSpecs")?.asArray ?? [])
                    }
                    let model = PCAInvariants.ChainModel(principalSeed: try seed(m["principalSeed"]), holder0Seed: try seed(m["holder0Seed"]),
                                                         rootSpecs: m["rootSpecs"]?.asArray ?? [], hops: hops, predicates: m["predicates"] ?? .null)
                    let ch = try PCAInvariants.buildChain(model, keyFor: Self.det)
                    return .object(["caps": .array(ch.caps), "predicates": ch.predicates, "rootIssuer": .string(ch.rootIssuer), "holders": PCADataflow.strs(ch.holders)])
                }
            case "worsen": got = Ref.v { try PCAInvariants.worsen(c.arg(0) ?? .null, c.arg(1) ?? .null) }
            case "consts":
                got = .value(.object(["DEFAULT_SEED": .int(Int64(PCAInvariants.DEFAULT_SEED)), "DEFAULT_NUM_RUNS": .int(Int64(PCAInvariants.DEFAULT_NUM_RUNS)),
                                      "INVARIANT_NAMES": PCADataflow.strs(PCAInvariants.INVARIANT_NAMES)]))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(300)
    }
}
