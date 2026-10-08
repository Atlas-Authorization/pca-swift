import Foundation

/// Capability-chain attenuation verification, mirroring `capability.ts` / the Rust `verify_chain`:
/// per-hop caveat narrowing (append-only), holder-binding continuity (issuer == parent.holder),
/// hash-linked parents, root issuer pinning, strict Ed25519 hop signatures, and the 16-hop cap
/// (enforced before any signature work).
enum Capability {
    static let CAP_DOMAIN: [UInt8] = Canonical.utf8("atlas-pca/cap/v1") + [0x00]
    static let MAX_CHAIN_DEPTH = 16

    /// Hash of the full capability, including its signature.
    static func capHash(_ c: JSONValue) -> String { Canonical.hashCanonical(c) }

    /// The hop body whose hash is `id` / `body_digest` / the signed message: `{issuer, holder, caveats,
    /// parent}` PLUS the suite fields (`alg`, `pq_pk`) bound in for a NON-default suite, so a downgrade or
    /// ML-DSA key-swap breaks the hop digest. Byte-identical to the classical body for `ed25519`. Mirrors
    /// `signableBody` in capability.ts / the Rust `signable_hop_body`. Returns nil for an unknown `alg`
    /// (fail-closed, before any hashing).
    private static func signableHopBody(_ c: [String: JSONValue]) -> JSONValue? {
        guard let suite = PQ.resolve(c["alg"]?.asString) else { return nil }
        var body: [String: JSONValue] = [
            "issuer": c["issuer"] ?? .null,
            "holder": c["holder"] ?? .null,
            "caveats": c["caveats"] ?? .null,
            "parent": c["parent"] ?? .null,
        ]
        if suite.alg != .ed25519 {
            body["alg"] = .string(suite.alg.rawValue)
            if suite.needsPqPk, let pk = c["pq_pk"], pk.asString != nil { body["pq_pk"] = pk }
        }
        return .object(body)
    }

    private static func str(_ c: [String: JSONValue], _ k: String) -> String { c[k]?.asString ?? "" }

    /// Returns a failure reason, or nil when the hop signature is valid. The hop signature is suite-agile
    /// (B4 crypto-agility), routed through the SAME `PQ.verifyLeaf` seam as the PCActn leaf: `ed25519` is a
    /// strict Ed25519 `sig` under the expected holder; `ml-dsa-65` an ML-DSA-65 `sig` under `pq_pk`; the
    /// hybrid requires BOTH. An unknown suite fails closed before any hashing.
    private static func checkSig(_ c: [String: JSONValue], signer: String, label: String) -> String? {
        guard let body = signableHopBody(c) else {
            return "\(label): unknown signature alg '\(c["alg"]?.asString ?? "")'"
        }
        let digest = Canonical.hashCanonical(body)
        let bd = str(c, "body_digest")
        let id = str(c, "id")
        if digest != bd || id != bd { return "\(label): body digest mismatch" }
        guard let d = Base64URLStrict.decode(bd, length: 32) else {
            return "\(label): bad signature (not signed by expected key)"
        }
        let msg = CAP_DOMAIN + d
        if PQ.verifyLeaf(alg: c["alg"]?.asString, holder: signer, pqPublicKey: c["pq_pk"]?.asString,
                         message: msg, sig: c["sig"]?.asString, pqSig: c["pq_sig"]?.asString) { return nil }
        return "\(label): bad signature (not signed by expected key)"
    }

    /// `nil` when valid, else a reason. The 16-hop cap is enforced before any signature work.
    static func verifyChain(_ chain: [JSONValue], expectedRootIssuer: String?) -> String? {
        if chain.isEmpty { return "empty chain" }
        if chain.count > MAX_CHAIN_DEPTH { return "chain too long (max \(MAX_CHAIN_DEPTH) hops)" }
        for (i, c) in chain.enumerated() where !c.isObject { return "hop \(i): malformed capability" }

        guard let root = chain[0].asObject else { return "hop 0: malformed" }
        if root["parent"] != nil { return "hop 0: root must not have a parent" }
        if let exp = expectedRootIssuer, root["issuer"]?.asString != exp {
            return "hop 0: root issuer is not the expected principal"
        }
        if let e = checkSig(root, signer: str(root, "issuer"), label: "hop 0") { return e }

        for i in 1..<chain.count {
            let label = "hop \(i)"
            guard let parent = chain[i - 1].asObject, let c = chain[i].asObject else { return "\(label): malformed" }
            let ph = capHash(chain[i - 1])
            if c["parent"]?.asString != ph { return "\(label): broken parent link" }
            if c["issuer"] != parent["holder"] { return "\(label): issuer is not the parent's bound holder" }
            if let e = checkSig(c, signer: str(parent, "holder"), label: label) { return e }
            let pc = parent["caveats"]?.asArray ?? []
            let cc = c["caveats"]?.asArray ?? []
            if cc.count < pc.count { return "\(label): drops parent caveat(s)" }
            for j in 0..<pc.count {
                if Canonical.hashCanonical(cc[j]) != Canonical.hashCanonical(pc[j]) {
                    return "\(label): caveat \(j) altered or reordered"
                }
            }
        }
        return nil
    }
}
