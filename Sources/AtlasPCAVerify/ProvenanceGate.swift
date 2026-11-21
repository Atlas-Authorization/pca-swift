import Foundation

// Build provenance as a K1 discharge (track K9): a port of the TypeScript reference (packages/pca/src/provenance-gate.ts). The
// RFC 9162 inclusion check, the policy gates over the facts the cryptographic Sigstore check established (refusal codes, check
// order and reasons are the reference's, shared through conformance/provenance-vectors.json), and the `needs_discharge` caveat
// a grant uses to ask an `artifact` verifier for the claims. Provenance can only remove authority.
//
// Total: malformed input is `false` or a refusal code, never a trap.

/// `{ok: true, level, claims}` or `{ok: false, code}`.
public struct ProvenanceGateResult: Equatable, Sendable {
    public let ok: Bool
    public let level: Int64
    /// The claims an `artifact` discharge carries (empty on refusal).
    public let claims: JObject
    /// The refusal code (empty on success).
    public let code: String
    static func no(_ c: String) -> ProvenanceGateResult { ProvenanceGateResult(ok: false, level: 0, claims: [:], code: c) }
}

/// Options of `PCA.provenanceCaveat`; nil members take the reference default.
public struct ProvenanceCaveatOptions: Sendable {
    /// Caveat id (K1 id syntax). Default `provenance`.
    public var id: String?
    /// Label of the verifier's `artifact` pin.
    public var issuer: String
    /// 1, 2 or 3.
    public var minLevel: Int64
    public var sourceRepo: String?
    /// Allowed builder ids (1..16), when given.
    public var builderIds: [String]?
    public var oidcIssuer: String?
    /// Require `runtime_bound: true`. Default true.
    public var requireRuntime: Bool?
    /// `chain_hop` or `action`. Default `action`.
    public var bind: String?
    /// Default 300 000 (5 minutes).
    public var ttlMs: Int64?
    public init(issuer: String, minLevel: Int64, id: String? = nil, sourceRepo: String? = nil, builderIds: [String]? = nil, oidcIssuer: String? = nil,
                requireRuntime: Bool? = nil, bind: String? = nil, ttlMs: Int64? = nil) {
        self.issuer = issuer
        self.minLevel = minLevel
        self.id = id
        self.sourceRepo = sourceRepo
        self.builderIds = builderIds
        self.oidcIssuer = oidcIssuer
        self.requireRuntime = requireRuntime
        self.bind = bind
        self.ttlMs = ttlMs
    }
}

extension PCA {
    public static let SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
    public static let INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"

    // ---- RFC 9162 inclusion ----

    /// RFC 9162 section 2.1.1: the hash of a leaf, SHA-256(0x00 || data).
    public static func rfc9162LeafHash(_ data: [UInt8]) -> [UInt8] { Canonical.sha256([0] + data) }

    private static func provNodeHash(_ l: [UInt8], _ r: [UInt8]) -> [UInt8] { Canonical.sha256([1] + l + r) }

    /// RFC 9162 section 2.1.3.2: verify an inclusion proof of `leafHash` at `index` in a tree of `size` leaves with root `root`.
    /// `proof` runs from the leaf level up, without the leaf and the root. Index and size are non-negative safe integers (64-bit
    /// arithmetic). False on any malformed input.
    public static func verifyRfc9162Inclusion(leafHash: [UInt8], index: Int64, size: Int64, proof: [[UInt8]], root: [UInt8]) -> Bool {
        guard index >= 0, size >= 1, size <= Canonical.MAX_SAFE, index < size else { return false }
        guard leafHash.count == 32, root.count == 32, proof.count <= 64, proof.allSatisfy({ $0.count == 32 }) else { return false }
        var fn = index, sn = size - 1
        var r = leafHash
        for p in proof {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                r = provNodeHash(p, r)
                if fn & 1 == 0 {
                    while fn & 1 == 0 && fn != 0 {
                        fn >>= 1
                        sn >>= 1
                    }
                }
            } else {
                r = provNodeHash(r, p)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 && r == root
    }

    // ---- facts and policy ----

    /// A non-empty string of at most 2048 UTF-8 bytes.
    private static func provStr(_ v: JSONValue?) -> Bool { IV.bounded(v, 2048) != nil }

    private static func provLevel(_ v: JSONValue?) -> Int64? { IV.int(v).flatMap { (1...3).contains($0) ? $0 : nil } }

    private static func provSubjectError(_ s: JSONValue?) -> Bool {
        guard case let .object(o)? = s, closedMembers(o, ["alg", "digest"], [], "object") == nil, let alg = o["alg"]?.asString else { return true }
        let n = IV.same(alg, "sha256") ? 64 : IV.same(alg, "sha512") ? 128 : -1
        guard n > 0, let d = o["digest"]?.asString else { return true }
        let u = Array(d.unicodeScalars)
        return !(u.count == n && u.allSatisfy { ($0.value >= 0x30 && $0.value <= 0x39) || ($0.value >= 0x61 && $0.value <= 0x66) })
    }

    /// nil when well-formed (closed members, bounded strings), else the reference's reason.
    public static func provenanceFactsError(_ fv: JSONValue?) -> String? {
        guard case let .object(f)? = fv else { return "facts must be an object" }
        if let e = closedMembers(f, ["v", "predicate_type", "build_type", "builder_id", "subjects", "identity", "oidc_issuer", "integrated_time", "rekor_log_index"],
                                 ["source_repo", "source_ref", "source_digest", "provenance_source"], "facts") { return e }
        if IV.int(f["v"]) != 1 { return "facts.v must be 1" }
        for k in ["predicate_type", "build_type", "builder_id", "identity", "oidc_issuer"] where !provStr(f[JKey(k)]) { return "facts.\(k) must be a non-empty string" }
        for k in ["source_repo", "source_ref", "source_digest"] where f[JKey(k)] != nil && !provStr(f[JKey(k)]) { return "facts.\(k) must be a non-empty string" }
        guard case let .array(subs)? = f["subjects"], (1...64).contains(subs.count), !subs.contains(where: { provSubjectError($0) }) else { return "facts.subjects must be 1..64 {alg, digest}" }
        if IV.nonNeg(f["integrated_time"]) == nil { return "facts.integrated_time must be a non-negative integer" }
        if IV.nonNeg(f["rekor_log_index"]) == nil { return "facts.rekor_log_index must be a non-negative integer" }
        if let pv = f["provenance_source"] {
            guard case let .object(p) = pv, closedMembers(p, ["uri"], ["git_commit"], "object") == nil, provStr(p["uri"]), p["git_commit"] == nil || provStr(p["git_commit"]) else {
                return "facts.provenance_source is malformed"
            }
        }
        return nil
    }

    /// nil when well-formed, else the reference's reason.
    public static func provenancePolicyError(_ pv: JSONValue?) -> String? {
        guard case let .object(p)? = pv else { return "policy must be an object" }
        if let e = closedMembers(p, ["roots", "min_level"], ["source_repo", "source_ref", "source_ref_prefix", "build_types", "max_age_s", "require_runtime"], "policy") { return e }
        guard case let .array(roots)? = p["roots"], (1...32).contains(roots.count) else { return "policy.roots must hold 1..32 pairs" }
        for rv in roots {
            guard case let .object(r) = rv, closedMembers(r, ["oidc_issuer", "builder_id", "level"], ["identity", "identity_prefix"], "object") == nil else { return "policy root is malformed" }
            if !provStr(r["oidc_issuer"]) || !provStr(r["builder_id"]) { return "policy root needs oidc_issuer and builder_id" }
            if (r["identity"] == nil) == (r["identity_prefix"] == nil) { return "policy root needs exactly one of identity and identity_prefix" }
            if r["identity"] != nil && !provStr(r["identity"]) { return "policy root identity is malformed" }
            // a prefix must at least name a scheme and a host (length in UTF-16 code units, as the reference counts it)
            if let pre = r["identity_prefix"], !(provStr(pre) && IV.u16(pre.asString ?? "") >= 10) { return "policy root identity_prefix must be at least 10 characters" }
            if provLevel(r["level"]) == nil { return "policy root level must be 1, 2 or 3" }
        }
        if provLevel(p["min_level"]) == nil { return "policy.min_level must be 1, 2 or 3" }
        if p["source_repo"] != nil && !provStr(p["source_repo"]) { return "policy.source_repo is malformed" }
        if p["source_ref"] != nil && p["source_ref_prefix"] != nil { return "policy takes source_ref or source_ref_prefix, not both" }
        if p["source_ref"] != nil && !provStr(p["source_ref"]) { return "policy.source_ref is malformed" }
        if p["source_ref_prefix"] != nil && !provStr(p["source_ref_prefix"]) { return "policy.source_ref_prefix is malformed" }
        if let b = p["build_types"] {
            guard case let .array(xs) = b, (1...16).contains(xs.count), xs.allSatisfy({ provStr($0) }) else { return "policy.build_types must hold 1..16 strings" }
        }
        if p["max_age_s"] != nil && !(IV.int(p["max_age_s"]).map { $0 >= 1 } ?? false) { return "policy.max_age_s must be a positive integer" }
        if let rr = p["require_runtime"] { if case .bool = rr {} else { return "policy.require_runtime must be a boolean" } }
        return nil
    }

    // ---- the gate ----

    /// The provenance gates in the reference order over `{facts, policy, runtime?, now}`: policy, facts, clock, runtime digest,
    /// predicate type, time, a pinned signer-builder pair (the highest matching level), the level floor, the provenance's own
    /// source against the certificate's, the source repository and ref pins, the build type, then the subject. An absent member
    /// is absent; a JSON null is present (and malformed). Total.
    public static func provenanceGate(_ input: JSONValue?) -> ProvenanceGateResult {
        typealias R = ProvenanceGateResult
        guard case let .object(inp)? = input else { return .no("malformed_facts") }
        if provenancePolicyError(inp["policy"]) != nil { return .no("malformed_policy") }
        if provenanceFactsError(inp["facts"]) != nil { return .no("malformed_facts") }
        guard let now = IV.nonNeg(inp["now"]) else { return .no("malformed_facts") }
        guard case let .object(f)? = inp["facts"], case let .object(p)? = inp["policy"] else { return .no("malformed_facts") }
        let rt = inp["runtime"]
        if rt != nil && provSubjectError(rt) { return .no("malformed_runtime") }
        func fs(_ k: String) -> String? { f[JKey(k)]?.asString }
        func ps(_ k: String) -> String? { p[JKey(k)]?.asString }
        if !IV.same(fs("predicate_type"), SLSA_PROVENANCE_V1) { return .no("predicate_type") }
        let it = IV.nonNeg(f["integrated_time"]) ?? 0
        if it > now { return .no("future") }
        if let max = IV.int(p["max_age_s"]), now - it > max { return .no("stale") }
        let identity = fs("identity") ?? ""
        var level: Int64 = 0
        for rv in p["roots"]?.asArray ?? [] {
            guard case let .object(r) = rv else { continue }
            if !IV.same(r["oidc_issuer"]?.asString, fs("oidc_issuer")) || !IV.same(r["builder_id"]?.asString, fs("builder_id")) { continue }
            let hit: Bool
            if let id = r["identity"]?.asString { hit = IV.same(id, identity) } else { hit = IV.startsWith(identity, r["identity_prefix"]?.asString ?? "") }
            if !hit { continue }
            level = Swift.max(level, IV.int(r["level"]) ?? 0)
        }
        if level == 0 { return .no("no_root") }
        if level < (IV.int(p["min_level"]) ?? 4) { return .no("level") }
        if case let .object(src)? = f["provenance_source"] {
            if let gc = src["git_commit"]?.asString, let sd = fs("source_digest"), !IV.same(gc, sd) { return .no("source_mismatch") }
            if let repo = fs("source_repo") {
                let uri = src["uri"]?.asString ?? "", base = "git+" + repo
                if !(IV.same(uri, base) || IV.startsWith(uri, base + "@")) { return .no("source_mismatch") }
            }
        }
        if let want = ps("source_repo"), !IV.same(fs("source_repo"), want) { return .no("source_repo") }
        if let want = ps("source_ref"), !IV.same(fs("source_ref"), want) { return .no("source_ref") }
        if let pre = ps("source_ref_prefix"), !(fs("source_ref").map { IV.startsWith($0, pre) } ?? false) { return .no("source_ref") }
        if let bts = p["build_types"]?.asArray, !bts.contains(where: { IV.same($0.asString, fs("build_type")) }) { return .no("build_type") }
        let subjects = f["subjects"]?.asArray ?? []
        let subject: JSONValue
        var bound = false
        if let r = rt {
            guard let hit = subjects.first(where: { IV.same($0.get("alg")?.asString, r.get("alg")?.asString) && IV.same($0.get("digest")?.asString, r.get("digest")?.asString) }) else {
                return .no("runtime_mismatch")
            }
            subject = hit
            bound = true
        } else {
            if p["require_runtime"] == .bool(true) { return .no("runtime_required") }
            if subjects.count != 1 { return .no("subject_ambiguous") }
            subject = subjects[0]
        }
        var claims: JObject = [
            "subject_alg": subject.get("alg") ?? .null,
            "subject_digest": subject.get("digest") ?? .null,
            "slsa_level": .int(level),
        ]
        for k in ["builder_id", "build_type", "oidc_issuer", "identity", "source_repo", "source_ref", "source_digest"] {
            if let v = f[JKey(k)] { claims[JKey(k)] = v }
        }
        claims["rekor_log_index"] = .int(IV.nonNeg(f["rekor_log_index"]) ?? 0)
        claims["runtime_bound"] = .bool(bound)
        if claims.values.contains(where: { $0.asString.map { IV.u8($0) > 256 } ?? false }) { return .no("claim_too_long") }
        return R(ok: true, level: level, claims: claims, code: "")
    }

    // ---- caveat ----

    private static func provReq(_ claim: String, _ op: String, _ value: JSONValue) -> JSONValue {
        .object(["claim": .string(claim), "op": .string(op), "value": value])
    }

    /// A `needs_discharge` caveat that asks the pinned `artifact` verifier for provenance claims.
    public static func provenanceCaveat(_ o: ProvenanceCaveatOptions) -> JSONValue {
        var require: [JSONValue] = [provReq("slsa_level", "gte", .int(o.minLevel))]
        if let r = o.sourceRepo { require.append(provReq("source_repo", "eq", .string(r))) }
        if let b = o.builderIds { require.append(provReq("builder_id", "in", .array(b.map { .string($0) }))) }
        if let i = o.oidcIssuer { require.append(provReq("oidc_issuer", "eq", .string(i))) }
        if o.requireRuntime != false { require.append(provReq("runtime_bound", "eq", .bool(true))) }
        return .object([
            "type": .string(CAVEAT_NEEDS_DISCHARGE),
            "id": .string(o.id ?? "provenance"),
            "issuer": .string(o.issuer),
            "issuer_class": .string("artifact"),
            "bind": .string(o.bind ?? "action"),
            "ttl_ms": .int(o.ttlMs ?? 300_000),
            "require": .array(require),
        ])
    }
}
