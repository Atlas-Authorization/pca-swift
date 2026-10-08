import Foundation

/// The CORE PCActn verifier (wire format v2). Byte-matches `@atlasauth/pca` and the Rust / Go / .NET
/// verifiers. Checks, in the normative order: wire (terminal), version, audience, validity, chain,
/// plan_inclusion, leaf_signature, counter. Later-milestone checks (attestation, threshold, revocation, …)
/// are out of scope for the core verdict.
public enum PCA {
    public static let WIRE_VERSION: Int64 = 2
    static let SIG_DOMAIN: [UInt8] = Canonical.utf8("atlas-pca/actn/v2") + [0x00]
    static let MAX_LIFETIME_MS: Int64 = 3_600_000
    static let MAX_SKEW_MS: Int64 = 60_000

    /// Verdict for the core checks. `checks[name]` is true when it passed. A wire failure is terminal and is
    /// the ONLY entry (`["wire": false]`); otherwise all eight checks are present. `allow` == every check true.
    public struct Verdict {
        public let allow: Bool
        public let checks: [String: Bool]
        public let reason: String
    }

    /// This verifier's own audience, compared to the PCActn's signed `aud` (mirrors `pcactn.ts`):
    ///  - `.id(x)` must equal `aud`;
    ///  - `.any` is a deliberate opt-out (accept any audience);
    ///  - `.unset` FAILS CLOSED when the PCActn carries a signed `aud`.
    public enum Audience {
        case id(String)
        case any
        case unset
    }

    static func wireFail(_ why: String) -> Verdict {
        Verdict(allow: false, checks: ["wire": false], reason: "wire: \(why)")
    }

    /// SIG_DOMAIN ‖ sha256(strictCanonical(pcactn without `sig`, `threshold` and `pq_sig`)).
    static func thresholdMessage(_ p: [String: JSONValue]) throws -> [UInt8] {
        var body: [String: JSONValue] = [:]
        for (k, v) in p where k != "sig" && k != "threshold" && k != "pq_sig" { body[k] = v }
        let canon = try Canonical.canonicalizeStrict(.object(body))
        return SIG_DOMAIN + Canonical.sha256(Canonical.utf8(canon))
    }

    /// Verify RAW PCActn text: strict-parse first (a parse failure is a `wire` failure), then the core checks.
    public static func verify(json text: String, grant: JSONValue, now: Int64, audience: Audience) -> Verdict {
        do {
            let v = try StrictJSON.parse(text)
            return verify(pcactn: v, grant: grant, now: now, audience: audience)
        } catch {
            return wireFail("\(error)")
        }
    }

    /// Convenience: concrete audience id (as the conformance harness and the other verifiers use).
    public static func verify(json text: String, grant: JSONValue, now: Int64, audience: String) -> Verdict {
        verify(json: text, grant: grant, now: now, audience: .id(audience))
    }

    public static func verify(pcactn: JSONValue, grant: JSONValue, now: Int64, audience: String) -> Verdict {
        verify(pcactn: pcactn, grant: grant, now: now, audience: .id(audience))
    }

    public static func verify(pcactn: JSONValue, grant: JSONValue, now: Int64, audience: Audience) -> Verdict {
        if let why = Wire.validate(pcactn) { return wireFail(why) }
        guard let p = pcactn.asObject else { return wireFail("PCActn is not an object") }

        var checks: [String: Bool] = [:]
        var reason = ""
        func record(_ name: String, _ ok: Bool, _ why: @autoclosure () -> String) {
            checks[name] = ok
            if !ok && reason.isEmpty { reason = "\(name): \(why())" }
        }

        checks["wire"] = true

        // version
        record("version", p["ver"]?.safeInt == WIRE_VERSION, "unsupported ver")

        // audience (freshness binding P0-5)
        let aud = p["aud"]?.asString
        let hasAud = !(aud?.isEmpty ?? true)
        switch audience {
        case .any:
            checks["audience"] = true
        case .unset:
            record("audience", !hasAud, "PCActn carries a signed aud but this verifier supplied no audience")
        case let .id(expected):
            record("audience", aud == expected, "aud does not match this resource server / instance")
        }

        // validity
        let iat = p["iat"]?.safeInt ?? 0
        let exp = p["exp"]?.safeInt ?? 0
        if exp <= iat { record("validity", false, "exp must be greater than iat") }
        else if exp - iat > MAX_LIFETIME_MS { record("validity", false, "lifetime exceeds \(MAX_LIFETIME_MS) ms") }
        else if iat > now &+ MAX_SKEW_MS { record("validity", false, "iat is in the future (clock skew)") }
        else if now > exp { record("validity", false, "the PCActn has expired") }
        else { checks["validity"] = true }

        // capability chain, root == grant
        let chain = p["cap_chain"]?.asArray ?? []
        if chain.isEmpty {
            record("chain", false, "empty chain")
        } else if chain.count > Capability.MAX_CHAIN_DEPTH {
            record("chain", false, "chain too long (max \(Capability.MAX_CHAIN_DEPTH) hops)")
        } else if Capability.capHash(chain[0]) != Capability.capHash(grant) {
            record("chain", false, "chain root is not the grant")
        } else if let e = Capability.verifyChain(chain, expectedRootIssuer: grant.get("issuer")?.asString) {
            record("chain", false, e)
        } else {
            checks["chain"] = true
        }

        // plan inclusion (leaf recomputed from the action itself)
        let plan = p["plan"]?.asObject ?? [:]
        let action = p["action"]?.asObject
        let cond = plan["conditions_digest"]?.asString ?? Merkle.conditionsDigestDefault()
        let root = plan["root"]?.asString ?? ""
        let proof = plan["inclusion_proof"]?.asObject
        let planOk = Merkle.planLeaf(plan["node_id"], action, cond).map { Merkle.verifyInclusion(root, proof, $0) } ?? false
        record("plan_inclusion", planOk, "action is not a node of the committed plan")

        // leaf signature over the v2 signed message, under the PCActn's signature suite (B4 crypto-agility):
        // ed25519 (strict Ed25519 under the leaf holder), ml-dsa-65 (under pq_pk), or hybrid (BOTH).
        var sigOk = false
        if let leafCap = chain.last?.asObject, let holder = leafCap["holder"]?.asString,
           let msg = try? thresholdMessage(p) {
            sigOk = PQ.verifyLeaf(alg: p["alg"]?.asString, holder: holder, pqPublicKey: p["pq_pk"]?.asString,
                                  message: msg, sig: p["sig"]?.asString, pqSig: p["pq_sig"]?.asString)
        }
        record("leaf_signature", sigOk, "signature does not verify under the leaf holder key")

        // counter: safe integer >= 0
        let counterOk = (p["counter"]?.safeInt).map { $0 >= 0 } ?? false
        record("counter", counterOk, "missing or not a non-negative safe integer")

        let allow = checks.values.allSatisfy { $0 }
        return Verdict(allow: allow, checks: checks, reason: reason)
    }
}
