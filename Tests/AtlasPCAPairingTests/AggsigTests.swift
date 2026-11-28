import XCTest
@testable import AtlasPCAVerify
@testable import AtlasPCAPairing

/// Replays the reference corpus (BLS12-381 PoP aggregation, registry, capability chain, witness cosignatures). Secret keys are
/// never stored in the corpus: a `{"$seed": label}` argument is derived here from the generator's documented scheme,
/// sk = sha256(sha256("atlas-pca-conformance/" + label)) mod (r - 1) + 1.
final class AggsigTests: XCTestCase {
    static let twoR: [UInt8] = [
        0xe7, 0xdb, 0x4e, 0xa6, 0x53, 0x3a, 0xfa, 0x90, 0x66, 0x73, 0xb0, 0x10, 0x13, 0x43, 0xb0, 0x0a,
        0xa7, 0x7b, 0x48, 0x05, 0xff, 0xfc, 0xb7, 0xfd, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x02]

    static func ge(_ a: [UInt8], _ b: [UInt8]) -> Bool { a.lexicographicallyPrecedes(b) == false }

    /// d mod (r - 1) + 1, with d = k*r + v (k in 0...2, v = d mod r by blst): d mod (r-1) = (v + k) mod (r-1).
    static func seedKey(_ label: String) -> [UInt8] {
        let d = Ref.sha256(Ref.sha256(Array("atlas-pca-conformance/\(label)".utf8)))
        let k: UInt64 = ge(d, twoR) ? 2 : (ge(d, blsOrderBE) ? 1 : 0)
        return (Fr(reducing: d) + Fr(k) + Fr(1)).bytes
    }

    static func bytes(_ v: JSONValue?) -> [UInt8]? { Ref.bytes(v) }

    static func secret(_ v: JSONValue?) -> [UInt8]? {
        if let l = v?.get("$seed")?.asString { return seedKey(l) }
        return Ref.bytes(v)
    }

    static func byteList(_ v: JSONValue?) -> [[UInt8]]? {
        guard let a = v?.asArray else { return nil }
        var out: [[UInt8]] = []
        for x in a { guard let b = Ref.bytes(x) else { return nil }; out.append(b) }
        return out
    }

    /// Registers every {pk, pop}; nil on the first refusal.
    static func registerAll(_ v: JSONValue?) -> [Aggsig.RegisteredKey]? {
        var out: [Aggsig.RegisteredKey] = []
        for k in v?.asArray ?? [] {
            guard let pk = bytes(k.get("pk")), let pop = bytes(k.get("pop")), let r = Aggsig.registerKey(pk, pop).key else { return nil }
            out.append(r)
        }
        return out
    }

    /// The reference's registry helper: stops at the first refused key and keeps the ones admitted so far.
    static func registry(_ v: JSONValue?) -> Aggsig.KeyRegistry {
        let r = Aggsig.KeyRegistry()
        for k in v?.asArray ?? [] {
            guard let pk = bytes(k.get("pk")), let pop = bytes(k.get("pop")), r.register(pk, pop).isOk else { break }
        }
        return r
    }

    static func bv(_ b: [UInt8]?) -> JSONValue? { b.map { Ref.bytesValue($0) } }
    static let registerFailed: JSONValue = .object(["registerFailed": .bool(true)])

    static func run(_ c: RefCase) -> JSONValue? {
        let a = c.args
        func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
        switch c.fn {
        case "publicKeyOf": return secret(arg(0)).flatMap { try? Aggsig.publicKeyOf($0) }.flatMap(bv)
        case "popProve": return secret(arg(0)).flatMap { try? Aggsig.popProve($0) }.flatMap(bv)
        case "sign":
            guard let sk = secret(arg(0)), let m = bytes(arg(1)) else { return nil }
            return bv(try? Aggsig.sign(sk, m))
        case "verify":
            guard let pk = bytes(arg(0)), let m = bytes(arg(1)), let s = bytes(arg(2)) else { return nil }
            return .bool(Aggsig.verify(pk, m, s))
        case "keyValidate": return bytes(arg(0)).map { .bool(Aggsig.keyValidate($0)) }
        case "registerKey":
            guard let pk = bytes(arg(0)), let pop = bytes(arg(1)) else { return nil }
            let r = Aggsig.registerKey(pk, pop)
            return r.isOk ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
        case "aggregate": return byteList(arg(0)).flatMap { try? Aggsig.aggregate($0) }.flatMap(bv)
        case "aggregateVerify":
            guard let msgs = byteList(arg(1)), let agg = bytes(arg(2)) else { return nil }
            guard let ks = registerAll(arg(0)) else { return registerFailed }
            return .bool(Aggsig.aggregateVerify(ks, msgs, agg))
        case "fastAggregateVerify":
            guard let m = bytes(arg(1)), let agg = bytes(arg(2)) else { return nil }
            guard let ks = registerAll(arg(0)) else { return registerFailed }
            return .bool(Aggsig.fastAggregateVerify(ks, m, agg))
        case "mintBlsRoot":
            guard let sk = secret(arg(0)), let pub = arg(1)?.asString, let h = arg(2)?.asString, let cav = arg(3) else { return nil }
            return try? AggsigChain.mintBlsRoot(principalSecret: sk, principalPublic: pub, holder: h, caveats: cav)
        case "chainDelegate":
            guard let p = arg(0), let h = arg(1)?.asString, let added = arg(2), let sk = secret(arg(3)) else { return nil }
            return try? AggsigChain.blsDelegate(parent: p, toHolder: h, added: added, signerSecret: sk)
        case "chainAttenuate":
            guard let p = arg(0), let added = arg(1), let sk = secret(arg(2)) else { return nil }
            return try? AggsigChain.blsAttenuate(parent: p, added: added, signerSecret: sk)
        case "capHash": return arg(0).flatMap { try? AggsigChain.capHash($0) }.map { .string($0) }
        case "aggregateChainSignatures": return arg(0).flatMap { try? AggsigChain.aggregateChainSignatures($0) }.flatMap(bv)
        case "verifyAggregatedChain":
            guard let chain = arg(0), let agg = bytes(arg(1)) else { return nil }
            let r = AggsigChain.verifyAggregatedChain(chain, aggSig: agg, registry: registry(arg(2)), expectedRoot: arg(3)?.asString)
            return r.ok ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
        case "cosignTreeHead":
            guard let sth = arg(0), let sk = secret(arg(1)) else { return nil }
            return try? AggsigWitness.cosignTreeHead(sth, witnessSecret: sk)
        case "verifyWitnessCosignature":
            guard let sth = arg(0), let c = arg(1) else { return nil }
            return .bool(AggsigWitness.verifyWitnessCosignature(sth, c))
        case "aggregateWitnessCosignatures": return arg(0).flatMap { try? AggsigWitness.aggregateWitnessCosignatures($0) }.flatMap(bv)
        case "verifyAggregatedWitnessCosignatures":
            guard let sth = arg(0), let agg = bytes(arg(2)) else { return nil }
            guard let ks = registerAll(arg(1)) else { return registerFailed }
            return .bool(AggsigWitness.verifyAggregatedWitnessCosignatures(sth, witnessKeys: ks, aggSig: agg))
        default: return nil
        }
    }

    func testReplayCorpus() throws {
        let d = Ref.Diffs()
        let n = try Ref.each("ref-aggsig.json.gz") { c in
            let known: Set<String> = ["publicKeyOf", "popProve", "sign", "verify", "keyValidate", "registerKey", "aggregate", "aggregateVerify",
                "fastAggregateVerify", "mintBlsRoot", "chainDelegate", "chainAttenuate", "capHash", "aggregateChainSignatures",
                "verifyAggregatedChain", "cosignTreeHead", "verifyWitnessCosignature", "aggregateWitnessCosignatures",
                "verifyAggregatedWitnessCosignatures"]
            if !known.contains(c.fn) { d.skip("unknown fn \(c.fn)"); return }
            d.add(Ref.diff(c, AggsigTests.run(c)))
        }
        XCTAssertEqual(n, 552)
        d.finish(552)
    }

    func testSeedKeyMatchesCorpusPublicKey() throws {
        // aggsig-0's public key is the first corpus case (publicKeyOf/k0)
        var seen = false
        try Ref.each("ref-aggsig.json.gz", ["publicKeyOf"]) { c in
            if c.name == "publicKeyOf/k0" { seen = true; XCTAssertEqual(AggsigTests.run(c), c.out) }
        }
        XCTAssertTrue(seen)
    }

    func testRegisteredKeyOnlyThroughProof() throws {
        let kp = try Aggsig.keyGen()
        XCTAssertFalse(Aggsig.registerKey(kp.publicKey, try Aggsig.sign(kp.secretKey, kp.publicKey)).isOk, "a signature under the signature DST is not a proof of possession")
        XCTAssertTrue(Aggsig.registerKey(kp.publicKey, try Aggsig.popProve(kp.secretKey)).isOk)
    }
}
