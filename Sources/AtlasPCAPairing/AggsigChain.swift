import Foundation
import AtlasPCAVerify

/// A BLS-suite attenuable capability chain: the structure of the core chain (hash-linked, holder-to-issuer continuity,
/// append-only caveats) with every hop signed under the BLS12-381 PoP scheme, so an M-hop chain's signatures collapse into
/// one 96-byte aggregate checked by one pairing-product AggregateVerify. Capabilities are JSON objects
/// (id, issuer, holder, caveats, parent?, body_digest, sig, suite).
public enum AggsigChain {
    public static let blsSuite = "bls12-381-pop"
    public static let maxChainDepth = 16
    static let capBlsDomain = Array("atlas-pca/cap-bls/v1\0".utf8)

    public struct Result: Equatable {
        public let ok: Bool
        public let reason: String?
        static let pass = Result(ok: true, reason: nil)
        static func fail(_ r: String) -> Result { Result(ok: false, reason: r) }
    }

    static func get(_ v: JSONValue, _ k: String) -> JSONValue? { v.objectValue?[JKey(k)] }
    static func str(_ v: JSONValue, _ k: String) -> String? { get(v, k)?.stringValue }

    /// The message a hop signs: the domain separator followed by the raw body digest.
    static func sigMessage(_ bodyDigest: String) throws -> [UInt8] {
        guard let d = PCAWire.b64uDecode(bodyDigest) else { throw PairingError("bad body digest") }
        return capBlsDomain + d
    }

    static func body(issuer: JSONValue, holder: JSONValue, caveats: JSONValue, parent: JSONValue) -> JSONValue {
        .object(["issuer": issuer, "holder": holder, "caveats": caveats, "parent": parent])
    }

    /// Identity of a capability: the hash of everything EXCEPT sig, so a free sig string cannot mint distinct identities.
    public static func capHash(_ c: JSONValue) throws -> String {
        guard var o = c.objectValue else { throw PairingError("capability is not an object") }
        o[JKey("sig")] = nil
        return try PCAWire.hashCanonicalStrict(.object(o))
    }

    /// Validates a caveat list against the strict profile and returns it (the reference round-trips it through canonical JSON).
    static func caveatList(_ v: JSONValue?) throws -> [JSONValue] {
        guard let v = v, let a = v.arrayValue else { throw PairingError("caveats must be an array") }
        _ = try PCAWire.canonicalStrict(v)
        return a
    }

    static func seal(issuer: String, holder: String, caveats: [JSONValue], parent: String?, signer: [UInt8]) throws -> JSONValue {
        let digest = try PCAWire.hashCanonicalStrict(body(issuer: .string(issuer), holder: .string(holder), caveats: .array(caveats), parent: parent.map { .string($0) } ?? .null))
        let sig = try Aggsig.sign(signer, try sigMessage(digest))
        var cap: JObject = ["id": .string(digest), "issuer": .string(issuer), "holder": .string(holder), "caveats": .array(caveats),
                            "body_digest": .string(digest), "sig": .string(PCAWire.b64uEncode(sig)), "suite": .string(blsSuite)]
        if let p = parent { cap[JKey("parent")] = .string(p) }
        return .object(cap)
    }

    public static func blsPublicKey(_ sk: [UInt8]) throws -> String { PCAWire.b64uEncode(try Aggsig.publicKeyOf(sk)) }

    /// A root capability, signed by the principal (the root issuer).
    public static func mintBlsRoot(principalSecret: [UInt8], principalPublic: String, holder: String, caveats: JSONValue) throws -> JSONValue {
        try seal(issuer: principalPublic, holder: holder, caveats: try caveatList(caveats), parent: nil, signer: principalSecret)
    }

    /// A child with the same holder; caveats = parent.caveats ++ added; signed by the parent's holder.
    public static func blsAttenuate(parent: JSONValue, added: JSONValue, signerSecret: [UInt8]) throws -> JSONValue {
        guard let h = str(parent, "holder") else { throw PairingError("parent has no holder") }
        return try blsDelegate(parent: parent, toHolder: h, added: added, signerSecret: signerSecret)
    }

    /// Like `blsAttenuate`, but rebinds the holder to a new key.
    public static func blsDelegate(parent: JSONValue, toHolder: String, added: JSONValue, signerSecret: [UInt8]) throws -> JSONValue {
        guard let issuer = str(parent, "holder") else { throw PairingError("parent has no holder") }
        let pc = try caveatList(get(parent, "caveats")), ac = try caveatList(added)
        return try seal(issuer: issuer, holder: toHolder, caveats: pc + ac, parent: try capHash(parent), signer: signerSecret)
    }

    static func wellTyped(_ c: JSONValue) -> Bool {
        guard c.objectValue != nil else { return false }
        for k in ["id", "issuer", "holder", "body_digest", "sig"] where str(c, k) == nil { return false }
        guard str(c, "suite") == blsSuite else { return false }
        if let p = get(c, "parent"), p.stringValue == nil { return false }
        guard let cavs = get(c, "caveats")?.arrayValue else { return false }
        for cv in cavs {
            guard cv.objectValue != nil, str(cv, "type") != nil else { return false }
        }
        return true
    }

    /// Collapses every per-hop signature of `chain` into one 96-byte aggregate.
    public static func aggregateChainSignatures(_ chain: JSONValue) throws -> [UInt8] {
        guard let hops = chain.arrayValue, !hops.isEmpty else { throw PairingError("aggregateChainSignatures: empty chain") }
        return try Aggsig.aggregate(try hops.map { h in
            guard let s = str(h, "sig"), let b = PCAWire.b64uDecode(s) else { throw PairingError("aggregateChainSignatures: hop sig is not valid base64url") }
            return b
        })
    }

    /// Verifies an entire BLS capability chain against one aggregate signature: structure (depth, well-typedness, links,
    /// holder-to-issuer continuity, append-only caveats), then one AggregateVerify over every hop. Every hop issuer must be in
    /// `registry`; `expectedRoot` pins the root issuer when given. Never traps.
    public static func verifyAggregatedChain(_ chain: JSONValue, aggSig: [UInt8], registry: Aggsig.KeyRegistry, expectedRoot: String? = nil) -> Result {
        guard let hops = chain.arrayValue, !hops.isEmpty else { return .fail("empty chain") }
        if hops.count > maxChainDepth { return .fail("chain too long (max \(maxChainDepth) hops)") }
        for (i, h) in hops.enumerated() where !wellTyped(h) { return .fail("hop \(i): malformed capability") }
        if get(hops[0], "parent") != nil { return .fail("hop 0: root must not have a parent") }
        if let e = expectedRoot, str(hops[0], "issuer") != e { return .fail("hop 0: root issuer is not the expected principal") }

        var pks: [Aggsig.RegisteredKey] = []
        var msgs: [[UInt8]] = []
        for (i, c) in hops.enumerated() {
            let issuer = str(c, "issuer")!, holder = str(c, "holder")!, digestField = str(c, "body_digest")!
            let digest: String
            do { digest = try PCAWire.hashCanonicalStrict(body(issuer: .string(issuer), holder: .string(holder), caveats: get(c, "caveats")!, parent: get(c, "parent") ?? .null)) }
            catch { return .fail("hop \(i): malformed body") }
            if digest != digestField || str(c, "id") != digestField { return .fail("hop \(i): body digest mismatch") }

            guard let ib = PCAWire.b64uDecode(issuer) else { return .fail("hop \(i): malformed issuer key") }
            guard let pk = registry.get(ib) else { return .fail("hop \(i): issuer key has no verified proof of possession (not in the registry)") }

            if i > 0 {
                let parent = hops[i - 1]
                guard let ph = try? capHash(parent), str(c, "parent") == ph else { return .fail("hop \(i): broken parent link") }
                if issuer != str(parent, "holder") { return .fail("hop \(i): issuer is not the parent's bound holder") }
                let cc = get(c, "caveats")!.arrayValue!, pc = get(parent, "caveats")!.arrayValue!
                if cc.count < pc.count { return .fail("hop \(i): drops parent caveat(s)") }
                for j in pc.indices {
                    let a = try? PCAWire.hashCanonicalStrict(cc[j]), b = try? PCAWire.hashCanonicalStrict(pc[j])
                    if a == nil || b == nil || a != b { return .fail("hop \(i): caveat \(j) altered or reordered") }
                }
            }
            guard let m = try? sigMessage(digestField) else { return .fail("hop \(i): body digest mismatch") }
            pks.append(pk)
            msgs.append(m)
        }

        // the per-hop sig fields must be canonical and sum to the aggregate that is verified
        var sigs: [[UInt8]] = []
        for h in hops {
            guard let b = PCAWire.b64uDecode(str(h, "sig")!) else { return .fail("malformed hop sig") }
            sigs.append(b)
        }
        guard let sum = try? Aggsig.aggregate(sigs) else { return .fail("malformed hop sig") }
        if sum != aggSig { return .fail("hop sig fields do not sum to the aggregate signature") }
        if !Aggsig.aggregateVerify(pks, msgs, aggSig) { return .fail("aggregate signature does not verify over all hops") }
        return .pass
    }
}
