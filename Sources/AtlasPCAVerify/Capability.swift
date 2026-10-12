import Foundation

/// Capability-chain attenuation verification, mirroring `capability.ts` / the Rust `verify_chain`:
/// per-hop caveat narrowing (append-only), holder-binding continuity (issuer == parent.holder),
/// hash-linked parents, root issuer pinning, strict Ed25519 hop signatures, and the 16-hop cap
/// (enforced before any signature work).
enum Capability {
    static let CAP_DOMAIN: [UInt8] = Canonical.utf8("atlas-pca/cap/v1") + [0x00]
    static let MAX_CHAIN_DEPTH = 16
    /// Shared hard caveat caps (all PCA verifiers): per-hop cumulative list, and the sum over every hop of a chain.
    static let MAX_CAVEATS_PER_HOP = 256
    static let MAX_CAVEATS_PER_CHAIN = 1024
    static let CAVEAT_LIMIT_REASON = "chain exceeds caveat limit (max \(MAX_CAVEATS_PER_HOP) per hop, \(MAX_CAVEATS_PER_CHAIN) per chain)"

    /// True when the chain breaks the caveat caps; reads raw list sizes only, so it runs before any hashing/signature work.
    static func caveatLimitExceeded(_ chain: [JSONValue]) -> Bool {
        var total = 0
        for c in chain {
            let n = c.asObject?["caveats"]?.asArray?.count ?? 0
            if n > MAX_CAVEATS_PER_HOP { return true }
            total += n
            if total > MAX_CAVEATS_PER_CHAIN { return true }
        }
        return false
    }

    /// Hash of the full capability, including its signature.
    static func capHash(_ c: JSONValue) -> String { Canonical.hashCanonical(c) }

    /// The hop body whose hash is `id` / `body_digest` / the signed message: `{issuer, holder, caveats,
    /// parent}` PLUS the suite fields (`alg`, `pq_pk`) bound in for a NON-default suite, so a downgrade or
    /// ML-DSA key-swap breaks the hop digest. Byte-identical to the classical body for `ed25519`. Mirrors
    /// `signableBody` in capability.ts / the Rust `signable_hop_body`. Returns nil for an unknown `alg`
    /// (fail-closed, before any hashing).
    private static func signableHopBody(_ c: JObject) -> JSONValue? {
        guard let suite = PQ.resolve(c["alg"]?.asString) else { return nil }
        var body: JObject = [
            "issuer": c["issuer"] ?? .null,
            "holder": c["holder"] ?? .null,
            "caveats": c["caveats"] ?? .null,
            "parent": c["parent"] ?? .null,
        ]
        if let hp = c["holder_pq"], hp.asString != nil { body["holder_pq"] = hp } // TS bodyOf: iff defined
        if suite.alg != .ed25519 {
            body["alg"] = .string(suite.alg.rawValue)
            if suite.needsPqPk, let pk = c["pq_pk"], pk.asString != nil { body["pq_pk"] = pk }
        }
        return .object(body)
    }

    /// F-2 commitment to a holder's PQ key: b64u(sha256("atlas-pca/holder-pq/v1\0" || utf8(pq_pk))).
    static func holderPqCommitment(_ pqPk: String) -> String {
        Base64URLStrict.encode(Canonical.sha256(Canonical.utf8("atlas-pca/holder-pq/v1") + [0x00] + Canonical.utf8(pqPk)))
    }

    /// `allowedSuites` policy for one hop / leaf (absent `alg` == ed25519). nil policy == unrestricted.
    static func suitePolicyError(_ alg: String?, _ label: String, _ allowed: [String]?) -> String? {
        guard let allowed = allowed else { return nil }
        let a = alg ?? "ed25519"
        return allowed.contains(a) ? nil : "\(label): signature suite '\(a)' is not allowed by this verifier's suite policy"
    }

    /// F-2/F-4: a suite carrying a PQ key is accepted only if `pq_pk` hashes to the signer's committed `holder_pq`.
    static func pqBindingError(_ signed: JObject, committed: String?, label: String) -> String? {
        guard let suite = PQ.resolve(signed["alg"]?.asString), suite.needsPqPk else { return nil }
        guard let cm = committed else {
            return "\(label): suite '\(suite.alg.rawValue)' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)"
        }
        guard let pk = signed["pq_pk"]?.asString, holderPqCommitment(pk) == cm else {
            return "\(label): pq_pk does not match the signer's committed holder_pq (F-2)"
        }
        return nil
    }

    private static func str(_ c: JObject, _ k: String) -> String { c[JKey(k)]?.asString ?? "" }

    /// Returns a failure reason, or nil when the hop signature is valid. The hop signature is suite-agile
    /// (B4 crypto-agility), routed through the SAME `PQ.verifyLeaf` seam as the PCActn leaf: `ed25519` is a
    /// strict Ed25519 `sig` under the expected holder; `ml-dsa-65` an ML-DSA-65 `sig` under `pq_pk`; the
    /// hybrid requires BOTH. An unknown suite fails closed before any hashing.
    private static func checkSig(_ c: JObject, signer: String, label: String, pq: PinnedPQ?) -> String? {
        guard let body = signableHopBody(c) else {
            return "\(label): unknown signature alg '\(c["alg"]?.asString ?? "")'"
        }
        // STRICT canonical form, like the reference (hashCanonical in hash.ts is strict): a hop body out of the strict
        // profile (nesting deeper than MAX_JSON_DEPTH, unsafe integer, ...) is refused, never hashed leniently.
        guard let canon = try? Canonical.canonicalizeStrict(body) else { return "\(label): malformed body" }
        let digest = Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(canon)))
        let bd = str(c, "body_digest")
        let id = str(c, "id")
        if digest != bd || id != bd { return "\(label): body digest mismatch" }
        guard let d = Base64URLStrict.decode(bd, length: 32) else {
            return "\(label): bad signature (not signed by expected key)"
        }
        let msg = CAP_DOMAIN + d
        // The PQ half verifies under the RESOLVED `pq` key, never under the hop's own pq_pk.
        if PQ.verifySuite(alg: c["alg"]?.asString, holder: signer, pq: pq,
                          message: msg, sig: c["sig"]?.asString, pqSig: c["pq_sig"]?.asString) { return nil }
        return "\(label): bad signature (not signed by expected key)"
    }

    static func rootPqPinReason(_ alg: String) -> String {
        "hop 0: root suite '\(alg)' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant "
            + "(policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)"
    }

    /// The root hop has no parent holding a `holder_pq` commitment, so a non-ed25519 root's PQ key must come from a
    /// verifier-side authority: the verifier's stored copy of this very grant (`trustedRoot`, same content hash) or a pin
    /// for `root.issuer`. Mirrors `rootPq` in capability.ts. Returns (key or nil for an Ed25519 root, refusal reason or nil).
    private static func resolveRootPq(_ root: JObject, pqPins: [String: String]?, trustedRoot: JSONValue?) -> (PinnedPQ?, String?) {
        guard let suite = PQ.resolve(root["alg"]?.asString), suite.needsPqPk else { return (nil, nil) }
        let pk = root["pq_pk"]?.asString
        var trusted: String? = nil
        if let tr = trustedRoot, let pk = pk, capHash(tr) == capHash(.object(root)) { trusted = pk }
        let key = PQ.resolvePqKey(identity: root["issuer"]?.asString, artifactPk: pk, pqPins: pqPins, trustedPk: trusted)
        guard let k = key else { return (nil, rootPqPinReason(suite.alg.rawValue)) }
        return (k, nil)
    }

    /// `nil` when valid, else a reason. The 16-hop cap is enforced before any signature work. A non-ed25519 (pure-PQ or
    /// hybrid) ROOT is accepted only if `pqPins[root.issuer]` equals the root's `pq_pk`, or `trustedRoot` is the root
    /// itself (the verifier's own stored grant); otherwise it is refused (R4-01).
    /// Mirrors `wellTyped` in capability.ts (R6-05): id/issuer/holder/body_digest/sig are strings; alg/pq_pk/pq_sig/
    /// holder_pq/parent are absent or strings (JSON null is NOT absent); caveats is an array of objects each with a string
    /// `type`. A correctly SIGNED but ill-typed hop is refused like in the reference.
    static func wellTyped(_ v: JSONValue) -> Bool {
        guard let c = v.asObject else { return false }
        for k in ["id", "issuer", "holder", "body_digest", "sig"] {
            if c[JKey(k)]?.asString == nil { return false }
        }
        for k in ["alg", "pq_pk", "pq_sig", "holder_pq", "parent"] {
            if let x = c[JKey(k)], x.asString == nil { return false }
        }
        guard let cv = c["caveats"]?.asArray else { return false }
        for x in cv {
            guard let o = x.asObject, o["type"]?.asString != nil else { return false }
        }
        return true
    }

    static func verifyChain(_ chain: [JSONValue], expectedRootIssuer: String?, allowedSuites: [String]? = nil,
                            pqPins: [String: String]? = nil, trustedRoot: JSONValue? = nil) -> String? {
        if chain.isEmpty { return "empty chain" }
        if chain.count > MAX_CHAIN_DEPTH { return "chain too long (max \(MAX_CHAIN_DEPTH) hops)" }
        if caveatLimitExceeded(chain) { return CAVEAT_LIMIT_REASON }
        for (i, c) in chain.enumerated() where !wellTyped(c) { return "hop \(i): malformed capability" }

        guard let root = chain[0].asObject else { return "hop 0: malformed" }
        if root["parent"] != nil { return "hop 0: root must not have a parent" }
        if let exp = expectedRootIssuer, root["issuer"]?.asString != exp {
            return "hop 0: root issuer is not the expected principal"
        }
        if let e = suitePolicyError(root["alg"]?.asString, "hop 0", allowedSuites) { return e }
        let (rootPq, rootErr) = resolveRootPq(root, pqPins: pqPins, trustedRoot: trustedRoot)
        if let e = rootErr { return e }
        if let e = checkSig(root, signer: str(root, "issuer"), label: "hop 0", pq: rootPq) { return e }

        for i in 1..<chain.count {
            let label = "hop \(i)"
            guard let parent = chain[i - 1].asObject, let c = chain[i].asObject else { return "\(label): malformed" }
            let ph = capHash(chain[i - 1])
            if c["parent"]?.asString != ph { return "\(label): broken parent link" }
            if c["issuer"] != parent["holder"] { return "\(label): issuer is not the parent's bound holder" }
            if let e = suitePolicyError(c["alg"]?.asString, label, allowedSuites) { return e }
            if let e = pqBindingError(c, committed: parent["holder_pq"]?.asString, label: label) { return e }
            let hopPq = PQ.resolvePqKey(identity: parent["holder"]?.asString, artifactPk: c["pq_pk"]?.asString,
                                        holderPq: parent["holder_pq"]?.asString)
            if let e = checkSig(c, signer: str(parent, "holder"), label: label, pq: hopPq) { return e }
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
