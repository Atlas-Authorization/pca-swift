import Foundation

/// The CORE PCActn verifier (wire format v2). Byte-matches `@atlasauth/pca` and the Rust / Go / .NET
/// verifiers. Checks, in the normative order: wire (terminal), version, audience, validity, chain,
/// plan_inclusion, leaf_signature, counter (then `intent` when the PCActn carries it). Later-milestone checks (attestation, threshold, revocation, …)
/// are out of scope for the core verdict.
public enum PCA {
    public static let WIRE_VERSION: Int64 = 2
    static let SIG_DOMAIN: [UInt8] = Canonical.utf8("atlas-pca/actn/v2") + [0x00]
    static let MAX_LIFETIME_MS: Int64 = 3_600_000
    static let MAX_SKEW_MS: Int64 = 60_000
    /// Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing.
    public static let MAX_ARTIFACT_BYTES = 524_288
    public static let ARTIFACT_SIZE_REASON = "artifact exceeds size limit (max \(MAX_ARTIFACT_BYTES) bytes)"

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
    static func thresholdMessage(_ p: JObject) throws -> [UInt8] {
        var body: JObject = [:]
        for (k, v) in p where k != "sig" && k != "threshold" && k != "pq_sig" { body[k] = v }
        let canon = try Canonical.canonicalizeStrict(.object(body))
        return SIG_DOMAIN + Canonical.sha256(Canonical.utf8(canon))
    }

    /// Verify RAW PCActn text: strict-parse first (a parse failure is a `wire` failure), then the core checks.
    public static func verify(json text: String, grant: JSONValue, now: Int64, audience: Audience, allowedSuites: [String]? = nil, intentPolicy: IntentPolicy? = nil, intentV2: IntentV2Context? = nil) -> Verdict {
        if text.utf8.count > MAX_ARTIFACT_BYTES { return wireFail(ARTIFACT_SIZE_REASON) } // FIRST: before any parsing
        do {
            let v = try StrictJSON.parse(text)
            return verify(pcactn: v, grant: grant, now: now, audience: audience, allowedSuites: allowedSuites, intentPolicy: intentPolicy, intentV2: intentV2)
        } catch {
            return wireFail("\(error)")
        }
    }

    /// Convenience: concrete audience id (as the conformance harness and the other verifiers use).
    public static func verify(json text: String, grant: JSONValue, now: Int64, audience: String, allowedSuites: [String]? = nil, intentPolicy: IntentPolicy? = nil, intentV2: IntentV2Context? = nil) -> Verdict {
        verify(json: text, grant: grant, now: now, audience: .id(audience), allowedSuites: allowedSuites, intentPolicy: intentPolicy, intentV2: intentV2)
    }

    public static func verify(pcactn: JSONValue, grant: JSONValue, now: Int64, audience: String, allowedSuites: [String]? = nil, intentPolicy: IntentPolicy? = nil, intentV2: IntentV2Context? = nil) -> Verdict {
        verify(pcactn: pcactn, grant: grant, now: now, audience: .id(audience), allowedSuites: allowedSuites, intentPolicy: intentPolicy, intentV2: intentV2)
    }

    /// `allowedSuites`: optional verifier suite policy (nil = none; an empty list refuses everything). Absent `alg` == "ed25519".
    /// `intentPolicy`: optional Intent Layer M2 policy (nil = none). The `intent` check runs after `counter` and is
    /// reported iff the PCActn carries `intent` or the policy is active; otherwise the verdict is the pre-M2 one.
    public static func verify(pcactn: JSONValue, grant: JSONValue, now: Int64, audience: Audience, allowedSuites: [String]? = nil, intentPolicy: IntentPolicy? = nil, intentV2: IntentV2Context? = nil) -> Verdict {
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
            // scalar-exact: Swift String == is canonical-equivalence (NFC "\u{e9}" == NFD "e\u{301}"), JSON strings compare code point by code point
            record("audience", aud.map { $0.unicodeScalars.elementsEqual(expected.unicodeScalars) } ?? false, "aud does not match this resource server / instance")
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
        } else if Capability.caveatLimitExceeded(chain) {
            record("chain", false, Capability.CAVEAT_LIMIT_REASON) // before any hashing or signature work
        } else if Capability.capHash(chain[0]) != Capability.capHash(grant) {
            record("chain", false, "chain root is not the grant")
        } else if let e = Capability.verifyChain(chain, expectedRootIssuer: grant.get("issuer")?.asString, allowedSuites: allowedSuites, trustedRoot: grant) /* chain[0] == grant was checked above */ {
            record("chain", false, e)
        } else {
            checks["chain"] = true
        }

        // grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
        // ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed
        // on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
        let grantRef = p["grant_ref"]?.asString
        let rootId = chain.first?.asObject?["id"]?.asString
        record("grant_ref_bound", grantRef != nil && !(grantRef ?? "").isEmpty && grantRef == rootId,
               "grant_ref is not the id of the root capability in cap_chain")

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
        var leafWhy = "signature does not verify under the leaf holder key"
        if let leafCap = chain.last?.asObject,
           let e = Capability.suitePolicyError(p["alg"]?.asString, "leaf", allowedSuites)
                ?? Capability.pqBindingError(p, committed: leafCap["holder_pq"]?.asString, label: "leaf") {
            leafWhy = e
        } else if let leafCap = chain.last?.asObject, let holder = leafCap["holder"]?.asString,
           let msg = try? thresholdMessage(p) {
            sigOk = PQ.verifySuite(alg: p["alg"]?.asString, holder: holder,
                                   pq: PQ.resolvePqKey(identity: holder, artifactPk: p["pq_pk"]?.asString,
                                                       holderPq: leafCap["holder_pq"]?.asString),
                                   message: msg, sig: p["sig"]?.asString, pqSig: p["pq_sig"]?.asString)
        }
        record("leaf_signature", sigOk, leafWhy)

        // counter: safe integer >= 0
        let counterOk = (p["counter"]?.safeInt).map { $0 >= 0 } ?? false
        record("counter", counterOk, "missing or not a non-negative safe integer")

        // Intent Layer M2: `intent` (reported iff the PCActn carries `intent` or the policy is active)
        let session = p["intent_session"]?.get("session")?.asString
        let mapForm = p["intent_session"]?.get("map_form")?.asString
        if let d = Intent.decide(p["intent"], grant: grant, policy: intentPolicy, session: session, mapForm: mapForm) {
            record("intent", d.ok, d.why)
        }

        // Intent Layer v2, in order: schema (rule 14), intent_session (13), layers (V5), accumulators (15), facts (16),
        // provenance (17), classes (18); each reported only when the PCActn carries `intent_session` or a v2 policy is
        // active (IntentV2.swift). Absent both, the verdict is the pre-v2 one.
        for c in IntentV2.decide(p, grant: grant, ctx: intentV2, now: now).checks {
            record(c.name, c.ok, c.reason)
        }

        let allow = checks.values.allSatisfy { $0 }
        return Verdict(allow: allow, checks: checks, reason: reason)
    }
}
