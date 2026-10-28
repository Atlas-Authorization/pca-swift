import Foundation

// Caveat language v2 (track K1): a port of the TypeScript reference (packages/pca/src/caveat-lang.ts; reasons are the
// reference's, character for character). Six verifier-side features, ALL of them restrictions (a caveat only removes
// authority; a verifier that does not know a type refuses the chain):
//
//  - `needs_discharge`  a third-party caveat: valid only with a signed discharge from a key THIS verifier pinned.
//  - `sealed`           no hop may be appended below the hop that carries it.
//  - narrow block       a holder-signed self-attenuation that rides beside the PCActn (no new hop).
//  - `max_uses`         a lifetime use count spent through the verifier's replay store (n first-use slots).
//  - `derive`           a bounded, stratified, non-recursive derived-fact check in Kleene three-valued logic.
//  - `spiffe_bound`     the presenting workload's verified SPIFFE ID must match.
//
// Everything is total: a malformed caveat, discharge, narrow block or context is a refusal, never a trap and never an allow.

/// A caveat of the leaf hop with the hop that introduced it.
public struct BoundCaveat: Equatable, Sendable {
    public let caveat: JSONValue
    /// Index of the hop that introduced the caveat (0 = the root grant).
    public let hop: Int
    /// `capHash` of that hop.
    public let capHash: String
    public init(caveat: JSONValue, hop: Int, capHash: String) {
        self.caveat = caveat
        self.hop = hop
        self.capHash = capHash
    }
}

/// A verifier-side pin for a discharge issuer. `label` is what caveats name; the keys never appear in a token.
public struct DischargePin: Equatable, Sendable {
    public let label: String
    /// `human`, `org`, `workload` or `model`.
    public let issuerClass: String
    public let pk: String
    public let pqPk: String?
    public let spiffeId: String?
    public init(label: String, issuerClass: String, pk: String, pqPk: String? = nil, spiffeId: String? = nil) {
        self.label = label
        self.issuerClass = issuerClass
        self.pk = pk
        self.pqPk = pqPk
        self.spiffeId = spiffeId
    }

    /// `{label, class, pk, pq_pk?, spiffe_id?}`; nil when `label`, `class` or `pk` is not a string.
    public static func fromJSON(_ v: JSONValue?) -> DischargePin? {
        guard case let .object(o)? = v, let l = o["label"]?.asString, let c = o["class"]?.asString, let pk = o["pk"]?.asString else { return nil }
        return DischargePin(label: l, issuerClass: c, pk: pk, pqPk: o["pq_pk"]?.asString, spiffeId: o["spiffe_id"]?.asString)
    }
}

/// What a discharge is judged against.
public struct DischargeBinding: Sendable {
    /// `capHash` of the hop that carries the caveat.
    public var capHash: String
    /// `PCA.dischargeActionDigest` of the PCActn being decided (needed for bind `action`).
    public var actionDigest: String?
    public var pins: [DischargePin]
    public var now: Int64
    /// `PCA.dischargeDigest` values the verifier has revoked.
    public var revoked: [String]?
    public init(capHash: String, actionDigest: String? = nil, pins: [DischargePin], now: Int64, revoked: [String]? = nil) {
        self.capHash = capHash
        self.actionDigest = actionDigest
        self.pins = pins
        self.now = now
        self.revoked = revoked
    }
}

/// `ok` with the discharge's digest and claims, or a refusal `reason`.
public struct DischargeVerdict: Equatable, Sendable {
    public let ok: Bool
    public let digest: String
    public let claims: JObject
    public let reason: String
    static func no(_ r: String) -> DischargeVerdict { DischargeVerdict(ok: false, digest: "", claims: [:], reason: r) }
}

/// `ok` with the caveats the narrow block adds, or a refusal `reason`.
public struct NarrowVerdict: Equatable, Sendable {
    public let ok: Bool
    public let caveats: [JSONValue]
    public let reason: String
    static func no(_ r: String) -> NarrowVerdict { NarrowVerdict(ok: false, caveats: [], reason: r) }
}

/// The outcome of `PCA.reserveMaxUses`: `spent` caveats were charged one use each.
public struct UsesVerdict: Equatable, Sendable {
    public let ok: Bool
    public let spent: Int
    public let reason: String
    static func no(_ r: String) -> UsesVerdict { UsesVerdict(ok: false, spent: 0, reason: r) }
}

/// The verifier's own K1 inputs (never taken from the request, except `discharges` and `narrow`, which are verified).
public struct K1Input: Sendable {
    /// The verifier's pins for discharge issuers.
    public var pins: [DischargePin]
    /// Discharges presented with the action.
    public var discharges: [JSONValue]
    /// A narrow block presented with the action.
    public var narrow: JSONValue?
    /// `PCA.dischargeActionDigest` of the PCActn being decided.
    public var actionDigest: String?
    /// `PCA.dischargeDigest` values the verifier has revoked.
    public var revokedDischarges: [String]?
    /// The SPIFFE ID of the presenting workload, from an SVID the verifier verified.
    public var spiffeId: String?
    /// The verifier's own record of this holder's admitted actions: `{t, verb, resource}` events.
    public var history: [JSONValue]?
    public init(pins: [DischargePin] = [], discharges: [JSONValue] = [], narrow: JSONValue? = nil, actionDigest: String? = nil,
                revokedDischarges: [String]? = nil, spiffeId: String? = nil, history: [JSONValue]? = nil) {
        self.pins = pins
        self.discharges = discharges
        self.narrow = narrow
        self.actionDigest = actionDigest
        self.revokedDischarges = revokedDischarges
        self.spiffeId = spiffeId
        self.history = history
    }
}

/// The outcome of `PCA.evaluateK1`.
public struct K1Result: Sendable {
    public let ok: Bool
    /// Types of the unsatisfied caveats, in order (`<malformed>` for one without a string type).
    public let failed: [String]
    /// One reason per failure (same order).
    public let reasons: [String]
    /// Verified narrow-block caveats that are NOT K1 types: the caller evaluates them with its stock evaluator.
    public let plain: [JSONValue]
    /// The K1 caveats evaluated, with their hops: hand them to `reserveMaxUses` once everything allowed.
    public let bound: [BoundCaveat]
}

extension PCA {
    public static let CAVEAT_NEEDS_DISCHARGE = "needs_discharge"
    public static let CAVEAT_SEALED = "sealed"
    public static let CAVEAT_MAX_USES = "max_uses"
    public static let CAVEAT_DERIVE = "derive"
    public static let CAVEAT_SPIFFE_BOUND = "spiffe_bound"
    /// Caveat types this module evaluates (the stock evaluators refuse them).
    public static let K1_CAVEAT_TYPES = [CAVEAT_NEEDS_DISCHARGE, CAVEAT_SEALED, CAVEAT_MAX_USES, CAVEAT_DERIVE, CAVEAT_SPIFFE_BOUND]

    public static let DISCHARGE_DOMAIN = "atlas-pca/discharge/v1\u{0}"
    static let DISCHARGE_REF_DOMAIN = "atlas-pca/discharge-ref/v1"
    static let DISCHARGE_ACTION_DOMAIN = "atlas-pca/discharge-action/v1"
    public static let NARROW_DOMAIN = "atlas-pca/narrow/v1\u{0}"
    static let MAX_USES_DOMAIN = "atlas-pca/max-uses/v1\u{0}"
    /// A discharge or narrow block lives at most 24 hours.
    public static let K1_MAX_LIFETIME_MS: Int64 = 86_400_000
    public static let MAX_USES_LIMIT: Int64 = 256
    static let NARROW_MAX_CAVEATS = 16
    static let DERIVE_MAX_DEFS = 8
    static let DERIVE_MAX_NODES = 32
    static let DERIVE_MAX_DEPTH = 4
    static let DERIVE_MAX_WINDOW_MS: Int64 = 30 * 86_400_000
    static let DERIVE_MAX_HISTORY = 10_000
    static let SPIFFE_MAX_ID_BYTES = 2048
    static let ISSUER_CLASSES = ["human", "org", "workload", "model", "artifact"]
    static let REQUIRE_OPS = ["eq", "neq", "gte", "lte", "in"]
    static let NARROW_FORBIDDEN = ["envelope", CAVEAT_SEALED, "budget_alloc", "intent_session"]

    // ---- small shared rules ----

    /// `isSafeInt(now)`: the clock is a safe integer (the range check of an `Int64`, never `abs`, which traps on `Int64.min`).
    static func k1ClockOk(_ now: Int64) -> Bool { now >= -Canonical.MAX_SAFE && now <= Canonical.MAX_SAFE }

    /// Exact code-point equality of a JSON string value with an ASCII literal.
    private static func k1Is(_ v: JSONValue?, _ s: String) -> Bool { IV.same(v?.asString, s) }

    /// `^[a-z0-9][a-z0-9_.-]{0,63}$`
    static func k1IdOk(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        guard (1...64).contains(u.count) else { return false }
        func lead(_ c: Unicode.Scalar) -> Bool { (c.value >= 0x61 && c.value <= 0x7A) || (c.value >= 0x30 && c.value <= 0x39) }
        guard lead(u[0]) else { return false }
        return u.dropFirst().allSatisfy { lead($0) || $0 == "_" || $0 == "." || $0 == "-" }
    }

    private static func k1Id(_ v: JSONValue?) -> Bool { v?.asString.map(k1IdOk) ?? false }
    private static func k1Name(_ v: JSONValue?) -> Bool { v?.asString.map { IV.isName($0) } ?? false }
    private static func k1Str256(_ v: JSONValue?) -> Bool { IV.bounded(v, 256) != nil }

    /// A wire scalar a claim or constant may be: a string of 1..256 UTF-8 bytes, a boolean or a safe integer.
    static func k1Scalar(_ v: JSONValue?) -> Bool {
        guard IV.isScalar(v) else { return false }
        if case .string? = v { return k1Str256(v) }
        return true
    }

    private static func k1Digest(_ v: JSONValue?) -> Bool { IV.digest(v) != nil }

    /// A JSON object's members sorted by UTF-8 key order (deterministic first-failure reporting).
    private static func k1Sorted(_ o: JObject) -> [(key: JKey, value: JSONValue)] { o.sorted { $0.key < $1.key } }

    // ======================================================================================
    // SPIFFE ID syntax (SPIFFE-ID.md)
    // ======================================================================================

    /// nil when `s` is a valid SPIFFE ID: `spiffe://` + a trust domain of lowercase letters, digits, `.`, `-`, `_` (1..255) +
    /// an optional path of non-empty segments over `[A-Za-z0-9._-]` that are not `.` or `..`, no trailing slash, at most 2048
    /// bytes, no query or fragment.
    public static func spiffeIdError(_ s: JSONValue?) -> String? {
        guard let str = s?.asString, !str.isEmpty else { return "SPIFFE ID must be a non-empty string" }
        return spiffeIdError(str)
    }

    public static func spiffeIdError(_ s: String) -> String? {
        if s.isEmpty { return "SPIFFE ID must be a non-empty string" }
        if s.utf8.count > SPIFFE_MAX_ID_BYTES { return "SPIFFE ID is too long" }
        if !IV.startsWith(s, "spiffe://") { return "SPIFFE ID must begin with spiffe://" }
        let rest = Array(s.unicodeScalars.dropFirst(9))
        let slash = rest.firstIndex(of: "/")
        let td = slash.map { Array(rest[..<$0]) } ?? rest
        let path = slash.map { Array(rest[$0...]) } ?? []
        func tdChar(_ c: Unicode.Scalar) -> Bool {
            (c.value >= 0x61 && c.value <= 0x7A) || (c.value >= 0x30 && c.value <= 0x39) || c == "." || c == "-" || c == "_"
        }
        if td.isEmpty || td.count > 255 || !td.allSatisfy(tdChar) { return "invalid trust domain" }
        if path.isEmpty { return nil }
        if path.last == "/" { return "path must not end with a slash" }
        func segChar(_ c: Unicode.Scalar) -> Bool {
            (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A) || (c.value >= 0x30 && c.value <= 0x39) || c == "." || c == "-" || c == "_"
        }
        for seg in path.split(separator: "/", omittingEmptySubsequences: false).dropFirst() {
            if seg.isEmpty || (seg.count == 1 && seg[seg.startIndex] == ".") || (seg.count == 2 && seg.allSatisfy { $0 == "." }) || !seg.allSatisfy(segChar) {
                return "invalid path segment"
            }
        }
        return nil
    }

    // ======================================================================================
    // Hop analysis: which hop introduced a caveat
    // ======================================================================================

    /// The hops the policy layer sees: the chain (root first), else the grant alone.
    static func k1Hops(_ grant: JSONValue, _ chain: JSONValue?) -> [JSONValue] {
        if let a = chain?.asArray, !a.isEmpty { return a }
        return [grant]
    }

    /// Every caveat of the leaf hop with the hop that introduced it. Caveat lists are cumulative and append-only, so the
    /// caveat at position `p` was introduced by the first hop whose list is longer than `p`. nil for a malformed chain.
    public static func boundCaveats(grant: JSONValue, chain: JSONValue? = nil) -> [BoundCaveat]? {
        let hops = k1Hops(grant, chain)
        guard let leaf = hops.last, let cs = leaf.get("caveats")?.asArray else { return nil }
        var hashes: [Int: String] = [:]
        var out: [BoundCaveat] = []
        for (p, caveat) in cs.enumerated() {
            let h = hops.firstIndex(where: { ($0.get("caveats")?.asArray?.count ?? 0) > p }) ?? (hops.count - 1)
            let hash: String
            if let x = hashes[h] {
                hash = x
            } else {
                hash = Capability.capHash(hops[h])
                hashes[h] = hash
            }
            out.append(BoundCaveat(caveat: caveat, hop: h, capHash: hash))
        }
        return out
    }

    static func k1IsMaxUses(_ c: JSONValue) -> Bool { k1Is(c.get("type"), CAVEAT_MAX_USES) }

    /// True for a caveat object whose `type` is one this module evaluates.
    public static func isK1Caveat(_ c: JSONValue?) -> Bool {
        guard let t = c?.asObject?["type"]?.asString else { return false }
        return K1_CAVEAT_TYPES.contains { IV.same($0, t) }
    }

    // ======================================================================================
    // needs_discharge: the third-party caveat and its discharge
    // ======================================================================================

    private static func requireError(_ r: JSONValue) -> String? {
        guard case let .object(o) = r else { return "requirement must be an object" }
        if let e = closedMembers(o, ["claim", "op", "value"], [], "require") { return e }
        if !k1Name(o["claim"]) { return "claim name is malformed" }
        guard let op = o["op"]?.asString, REQUIRE_OPS.contains(where: { IV.same($0, op) }) else { return "op must be eq, neq, gte, lte or in" }
        let value = o["value"]
        if IV.same(op, "in") {
            guard case let .array(xs)? = value, !xs.isEmpty, xs.count <= 16, xs.allSatisfy({ k1Scalar($0) }) else { return "'in' needs 1..16 scalar values" }
        } else if IV.same(op, "gte") || IV.same(op, "lte") {
            if IV.int(value) == nil { return "'\(op)' needs a safe integer" }
        } else if !k1Scalar(value) {
            return "value must be a scalar"
        }
        return nil
    }

    /// nil when the caveat is well-formed: closed members, canonical names, bounded sizes.
    public static func needsDischargeError(_ c: JSONValue?) -> String? {
        guard case let .object(o)? = c else { return "caveat must be an object" }
        if let e = closedMembers(o, ["type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require"], ["issuer_spiffe"], "needs_discharge") { return e }
        if !k1Is(o["type"], CAVEAT_NEEDS_DISCHARGE) { return "not a needs_discharge caveat" }
        if !k1Id(o["id"]) { return "id is malformed" }
        if !k1Id(o["issuer"]) { return "issuer label is malformed" }
        guard let cls = o["issuer_class"]?.asString, ISSUER_CLASSES.contains(where: { IV.same($0, cls) }) else { return "issuer_class must be human, org, workload, model or artifact" }
        if !k1Is(o["bind"], "chain_hop") && !k1Is(o["bind"], "action") { return "bind must be 'chain_hop' or 'action'" }
        guard let ttl = IV.int(o["ttl_ms"]), ttl >= 1, ttl <= K1_MAX_LIFETIME_MS else { return "ttl_ms must be 1..86400000" }
        guard case let .array(reqs)? = o["require"], reqs.count <= 16 else { return "require must be an array of at most 16 requirements" }
        for r in reqs { if let e = requireError(r) { return e } }
        if let sp = o["issuer_spiffe"], let e = spiffeIdError(sp) { return "issuer_spiffe: \(e)" }
        return nil
    }

    /// The digest of the exact PCActn (counter and signature included): a bind-`action` discharge authorises that one action.
    public static func dischargeActionDigest(pcactn: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(DISCHARGE_ACTION_DOMAIN), "pcactn": pcactn]))
    }

    /// Content address of a discharge (signature included); what a revocation list names. nil outside the strict JSON profile.
    public static func dischargeDigest(_ d: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(DISCHARGE_REF_DOMAIN), "discharge": d]))
    }

    static let D_REQUIRED = ["v", "kind", "caveat_id", "issuer", "cap_hash", "bind", "claims", "iat", "not_after", "nonce", "sig"]
    static let D_OPTIONAL = ["action_digest", "alg", "pq_pk", "pq_sig"]

    /// nil = a well-formed discharge.
    public static func dischargeShapeError(_ a: JSONValue?) -> String? {
        guard case let .object(o)? = a else { return "not an object" }
        if let e = closedMembers(o, D_REQUIRED, D_OPTIONAL, "discharge") { return e }
        if IV.num(o["v"]) != 1 || !k1Is(o["kind"], "pca-discharge") { return "not a pca-discharge v1" }
        if !k1Id(o["caveat_id"]) { return "caveat_id is malformed" }
        if !k1Id(o["issuer"]) { return "issuer label is malformed" }
        if !k1Digest(o["cap_hash"]) { return "cap_hash must be canonical base64url (32 bytes)" }
        let isAction = k1Is(o["bind"], "action")
        if !isAction && !k1Is(o["bind"], "chain_hop") { return "bind must be 'chain_hop' or 'action'" }
        if isAction ? !k1Digest(o["action_digest"]) : (o["action_digest"] != nil) { return "action_digest is required for bind action and forbidden for chain_hop" }
        guard case let .object(claims)? = o["claims"], claims.count <= 16 else { return "claims must be an object of at most 16 members" }
        for (k, v) in k1Sorted(claims) where !IV.isName(k.s) || !k1Scalar(v) { return "claim '\(k.s)' is malformed" }
        guard let iat = IV.nonNeg(o["iat"]), let na = IV.nonNeg(o["not_after"]) else { return "iat and not_after must be non-negative safe integers" }
        if !(na > iat) { return "not_after must be greater than iat" }
        if na - iat > K1_MAX_LIFETIME_MS { return "a discharge lives at most \(K1_MAX_LIFETIME_MS) ms" }
        guard let n = o["nonce"]?.asString, let nb = Base64URLStrict.decode(n), nb.count >= 16 else { return "nonce must be canonical base64url of at least 16 bytes" }
        if o["sig"]?.asString == nil { return "sig must be a string" }
        return IntentWB.artifactSuiteError(o)
    }

    private static func claimHolds(_ r: JSONValue, _ claims: JObject) -> Bool {
        guard let name = r.get("claim")?.asString, let v = claims[JKey(name)], let op = r.get("op")?.asString else { return false }
        let want = r.get("value")
        switch op {
        case "eq": return IV.scalarEq(v, want)
        case "neq": return !IV.scalarEq(v, want)
        case "gte":
            guard let x = IV.int(v), let y = IV.int(want) else { return false }
            return x >= y
        case "lte":
            guard let x = IV.int(v), let y = IV.int(want) else { return false }
            return x <= y
        case "in": return (want?.asArray ?? []).contains { IV.scalarEq(v, $0) }
        default: return false
        }
    }

    /// Verify one discharge against one caveat. The verifier's own pins decide the key; the discharge is bound to the hop
    /// carrying the caveat (and for `action` to the PCActn); it must be inside its window and within the caveat's `ttl_ms`; and
    /// its claims must satisfy every requirement. Total.
    public static func verifyDischarge(_ discharge: JSONValue?, _ caveat: JSONValue?, _ bind: DischargeBinding) -> DischargeVerdict {
        if !k1ClockOk(bind.now) { return .no("the verifier clock is not a safe integer (fail closed)") }
        if let ce = needsDischargeError(caveat) { return .no("malformed needs_discharge caveat: \(ce)") }
        if let de = dischargeShapeError(discharge) { return .no("malformed discharge: \(de)") }
        guard case let .object(c)? = caveat, case let .object(d)? = discharge,
              let cid = c["id"]?.asString, let cIssuer = c["issuer"]?.asString, let cClass = c["issuer_class"]?.asString,
              let cBind = c["bind"]?.asString, let ttl = IV.int(c["ttl_ms"]), case let .array(reqs)? = c["require"],
              let dCaveat = d["caveat_id"]?.asString, let dIssuer = d["issuer"]?.asString, let dBind = d["bind"]?.asString,
              let dCap = d["cap_hash"]?.asString, let iat = IV.nonNeg(d["iat"]), let notAfter = IV.nonNeg(d["not_after"]),
              case let .object(claims)? = d["claims"] else { return .no("discharge error (fail closed): malformed input") }
        if !IV.same(dCaveat, cid) { return .no("the discharge is for another caveat") }
        if !IV.same(dIssuer, cIssuer) { return .no("the discharge names another issuer") }
        let pins = bind.pins.filter { IV.same($0.label, cIssuer) }
        if pins.isEmpty { return .no("the issuer is not pinned by this verifier") }
        if pins.count > 1 { return .no("the issuer label is pinned more than once (ambiguous)") }
        let pin = pins[0]
        if !IV.same(pin.issuerClass, cClass) { return .no("the pinned issuer is not of the class the caveat requires") }
        if let want = c["issuer_spiffe"]?.asString, !IV.same(pin.spiffeId, want) {
            return .no("the pinned issuer does not carry the SPIFFE ID the caveat requires")
        }
        if !IntentWB.verifyArtifactSig(DISCHARGE_DOMAIN, d, pin.pk, pqPin: pin.pqPk) { return .no("discharge signature invalid") }
        if !IV.same(dBind, cBind) { return .no("the discharge binds differently than the caveat requires") }
        if !IV.same(dCap, bind.capHash) { return .no("the discharge is bound to another hop") }
        if IV.same(cBind, "action") && !IV.same(d["action_digest"]?.asString, bind.actionDigest) { return .no("the discharge is bound to another action") }
        if bind.now < iat { return .no("the discharge is from the future") }
        if bind.now > notAfter { return .no("the discharge has expired") }
        if notAfter - iat > ttl { return .no("the discharge lives longer than the caveat allows") }
        guard let digest = dischargeDigest(discharge ?? .null) else { return .no("discharge error (fail closed): the discharge is outside the strict JSON profile") }
        if let rv = bind.revoked, rv.contains(where: { IV.same($0, digest) }) { return .no("the discharge is revoked") }
        for r in reqs where !claimHolds(r, claims) { return .no("claim '\(r.get("claim")?.asString ?? "")' does not satisfy the caveat") }
        return DischargeVerdict(ok: true, digest: digest, claims: claims, reason: "")
    }

    // ======================================================================================
    // narrow: holder-signed per-action self-attenuation (no new hop)
    // ======================================================================================

    static let N_REQUIRED = ["v", "kind", "cap_hash", "holder", "caveats", "iat", "not_after", "nonce", "sig"]
    static let N_OPTIONAL = ["action_digest", "alg", "pq_pk", "pq_sig"]

    /// nil = a well-formed narrow block.
    public static func narrowShapeError(_ a: JSONValue?) -> String? {
        guard case let .object(o)? = a else { return "not an object" }
        if let e = closedMembers(o, N_REQUIRED, N_OPTIONAL, "narrow") { return e }
        if IV.num(o["v"]) != 1 || !k1Is(o["kind"], "pca-narrow") { return "not a pca-narrow v1" }
        if !k1Digest(o["cap_hash"]) { return "cap_hash must be canonical base64url (32 bytes)" }
        guard let holder = IV.bounded(o["holder"], 64), Base64URLStrict.decode(holder, length: 32) != nil else { return "holder must be canonical base64url (32 bytes)" }
        guard case let .array(cs)? = o["caveats"], cs.count >= 1, cs.count <= NARROW_MAX_CAVEATS else { return "caveats must be 1..\(NARROW_MAX_CAVEATS) caveats" }
        for c in cs {
            guard let t = c.asObject?["type"]?.asString else { return "every caveat must be an object with a string type" }
            if NARROW_FORBIDDEN.contains(where: { IV.same($0, t) }) { return "a narrow block cannot carry a '\(t)' caveat" }
        }
        if let ad = o["action_digest"], !k1Digest(ad) { return "action_digest must be canonical base64url (32 bytes)" }
        guard let iat = IV.nonNeg(o["iat"]), let na = IV.nonNeg(o["not_after"]) else { return "iat and not_after must be non-negative safe integers" }
        if !(na > iat) { return "not_after must be greater than iat" }
        if na - iat > K1_MAX_LIFETIME_MS { return "a narrow block lives at most \(K1_MAX_LIFETIME_MS) ms" }
        guard let n = o["nonce"]?.asString, let nb = Base64URLStrict.decode(n), nb.count >= 16 else { return "nonce must be canonical base64url of at least 16 bytes" }
        if o["sig"]?.asString == nil { return "sig must be a string" }
        return IntentWB.artifactSuiteError(o)
    }

    /// Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key
    /// the leaf's `holder_pq` commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its window.
    /// The caveats it carries then join the chain's. It can only ADD restrictions. Total.
    public static func verifyNarrow(_ narrow: JSONValue?, grant: JSONValue, chain: JSONValue?, now: Int64, actionDigest: String? = nil) -> NarrowVerdict {
        if !k1ClockOk(now) { return .no("the verifier clock is not a safe integer (fail closed)") }
        if let e = narrowShapeError(narrow) { return .no("malformed narrow block: \(e)") }
        guard case let .object(n)? = narrow, let holder = n["holder"]?.asString, let capH = n["cap_hash"]?.asString,
              let iat = IV.nonNeg(n["iat"]), let notAfter = IV.nonNeg(n["not_after"]), case let .array(cs)? = n["caveats"],
              let leaf = k1Hops(grant, chain).last else { return .no("narrow error (fail closed): malformed input") }
        if !IV.same(holder, leaf.get("holder")?.asString) { return .no("the narrow block is not signed by the leaf holder") }
        if !IV.same(capH, Capability.capHash(leaf)) { return .no("the narrow block is bound to another hop") }
        var pq: String?
        if let apk = n["pq_pk"]?.asString, let committed = leaf.get("holder_pq")?.asString, Capability.holderPqCommitment(apk) == committed { pq = apk }
        if !IntentWB.verifyArtifactSig(NARROW_DOMAIN, n, holder, pqPin: pq) { return .no("narrow signature invalid") }
        if let ad = n["action_digest"]?.asString, !IV.same(ad, actionDigest) { return .no("the narrow block is bound to another action") }
        if now < iat { return .no("the narrow block is from the future") }
        if now > notAfter { return .no("the narrow block has expired") }
        return NarrowVerdict(ok: true, caveats: cs, reason: "")
    }

    // ======================================================================================
    // max_uses: n atomic first-use slots in the verifier's replay store
    // ======================================================================================

    /// nil when the caveat is well-formed.
    public static func maxUsesError(_ c: JSONValue?) -> String? {
        guard case let .object(o)? = c else { return "caveat must be an object" }
        if let e = closedMembers(o, ["type", "id", "n", "until"], [], "max_uses") { return e }
        if !k1Is(o["type"], CAVEAT_MAX_USES) { return "not a max_uses caveat" }
        if !k1Id(o["id"]) { return "id is malformed" }
        guard let n = IV.int(o["n"]), n >= 1, n <= MAX_USES_LIMIT else { return "n must be 1..\(MAX_USES_LIMIT)" }
        guard IV.nonNeg(o["until"]) != nil else { return "until must be a non-negative safe integer" }
        return nil
    }

    /// The store key of use slot `i` of caveat `id` carried by the hop `capHash`: b64u(sha256(domain NUL cap NUL id NUL i)).
    public static func maxUsesSlotKey(capHash: String, id: String, i: Int) -> String {
        Base64URLStrict.encode(Canonical.sha256(Canonical.utf8("\(MAX_USES_DOMAIN)\(capHash)\u{0}\(id)\u{0}\(i)")))
    }

    /// Spend one use of every `max_uses` caveat in `bound`, in order, after the rest of the decision allows. Each caveat takes
    /// the first free slot of its `n`: slot `i` is `store.consumeOnce(key: maxUsesSlotKey(...), retainUntil: until, now:)`, which
    /// succeeds exactly once per key while the slot is retained, so concurrent actions never share a slot, across
    /// processes when the store is durable and shared. The first exhausted, expired or malformed caveat refuses; slots already
    /// taken stay spent (a use is spent when the action is admitted; a refusal after that cannot give it back: fail closed).
    /// A slot is retained at least until `until`; after that the caveat is expired anyway, so the store may forget it.
    public static func reserveMaxUses(store: any PCAStateStore, bound: [BoundCaveat], now: Int64) -> UsesVerdict {
        if !k1ClockOk(now) { return .no("the verifier clock is not a safe integer (fail closed)") }
        var spent = 0
        var ids = Set<String>()
        for b in bound {
            guard k1Is(b.caveat.get("type"), CAVEAT_MAX_USES) else { continue }
            if let err = maxUsesError(b.caveat) { return .no("malformed max_uses caveat: \(err)") }
            guard let id = b.caveat.get("id")?.asString, let n = IV.int(b.caveat.get("n")), let until = IV.nonNeg(b.caveat.get("until")) else {
                return .no("malformed max_uses caveat: malformed input")
            }
            let dup = b.capHash + "\u{0}" + id
            if ids.contains(where: { IV.same($0, dup) }) { return .no("duplicate max_uses id '\(id)'") }
            ids.insert(dup)
            if now >= until { return .no("max_uses '\(id)' has expired") }
            var took = false
            var i: Int64 = 0
            while i < n && !took {
                do {
                    took = try store.consumeOnce(key: maxUsesSlotKey(capHash: b.capHash, id: id, i: Int(i)), retainUntil: until, now: now)
                } catch {
                    return .no("max_uses error (fail closed): the replay store failed")
                }
                i += 1
            }
            if !took { return .no("max_uses '\(id)' is exhausted") }
            spent += 1
        }
        return UsesVerdict(ok: true, spent: spent, reason: "")
    }

    // ======================================================================================
    // derive: bounded derived facts in Kleene three-valued logic
    // ======================================================================================

    private static func exprError(_ x: JSONValue?, _ names: Set<JKey>, _ depth: Int, _ count: inout Int) -> String? {
        if depth > DERIVE_MAX_DEPTH { return "expression nests deeper than \(DERIVE_MAX_DEPTH)" }
        count += 1
        if count > DERIVE_MAX_NODES { return "more than \(DERIVE_MAX_NODES) expression nodes" }
        guard case let .object(o)? = x else { return "expression must be an object" }
        if o["ref"] != nil {
            if let e = closedMembers(o, ["ref"], [], "ref") { return e }
            if let r = o["ref"]?.asString, names.contains(JKey(r)) { return nil }
            return "ref names no earlier def"
        }
        if o["const"] != nil {
            if let e = closedMembers(o, ["const"], [], "const") { return e }
            return k1Scalar(o["const"]) ? nil : "const must be a scalar"
        }
        let op = o["op"]?.asString ?? ""
        if IV.same(op, "and") || IV.same(op, "or") {
            if let e = closedMembers(o, ["op", "args"], [], op) { return e }
            guard case let .array(args)? = o["args"], args.count >= 1, args.count <= 8 else { return "\(op) needs 1..8 arguments" }
            for a in args { if let r = exprError(a, names, depth + 1, &count) { return r } }
            return nil
        }
        if IV.same(op, "not") {
            if let e = closedMembers(o, ["op", "arg"], [], "not") { return e }
            return exprError(o["arg"], names, depth + 1, &count)
        }
        if ["eq", "neq", "lt", "lte", "gt", "gte"].contains(where: { IV.same($0, op) }) {
            if let e = closedMembers(o, ["op", "a", "b"], [], op) { return e }
            if let r = exprError(o["a"], names, depth + 1, &count) { return r }
            return exprError(o["b"], names, depth + 1, &count)
        }
        return "unknown expression"
    }

    /// nil when the caveat is well-formed: bounded, closed, and non-recursive (a def refers only to defs before it).
    public static func deriveError(_ c: JSONValue?) -> String? {
        guard case let .object(o)? = c else { return "caveat must be an object" }
        if let e = closedMembers(o, ["type", "id", "defs", "check"], [], "derive") { return e }
        if !k1Is(o["type"], CAVEAT_DERIVE) { return "not a derive caveat" }
        if !k1Id(o["id"]) { return "id is malformed" }
        guard case let .array(defs)? = o["defs"], defs.count <= DERIVE_MAX_DEFS else { return "defs must be an array of at most \(DERIVE_MAX_DEFS)" }
        var names = Set<JKey>()
        var count = 0
        for dv in defs {
            guard case let .object(d) = dv, let name = d["name"]?.asString, IV.isName(name) else { return "def name is malformed" }
            if names.contains(JKey(name)) { return "def '\(name)' is defined twice" }
            var de: String?
            switch d["kind"]?.asString ?? "" {
            case "count":
                de = closedMembers(d, ["name", "kind", "window_ms"], ["verb", "resource_prefix"], "count")
                if de == nil {
                    if let w = IV.int(d["window_ms"]), w >= 1, w <= DERIVE_MAX_WINDOW_MS {} else { de = "window_ms out of range" }
                }
                if de == nil, let v = d["verb"], !k1Str256(v) { de = "verb must be a non-empty string" }
                if de == nil, let v = d["resource_prefix"], !k1Str256(v) { de = "resource_prefix must be a non-empty string" }
            case "param":
                de = closedMembers(d, ["name", "kind", "path"], [], "param")
                if de == nil {
                    if let p = d["path"]?.asString, IV.split(p, ".").count <= 4, IV.split(p, ".").allSatisfy(IV.isPathSegment) {} else { de = "param path is malformed" }
                }
            case "action":
                de = closedMembers(d, ["name", "kind", "field"], [], "action")
                if de == nil, !k1Is(d["field"], "verb") && !k1Is(d["field"], "resource") { de = "field must be 'verb' or 'resource'" }
            case "claim":
                de = closedMembers(d, ["name", "kind", "caveat_id", "claim"], [], "claim")
                if de == nil, !(k1Id(d["caveat_id"]) && k1Name(d["claim"])) { de = "claim reference is malformed" }
            case "expr":
                de = closedMembers(d, ["name", "kind", "expr"], [], "expr")
                if de == nil { de = exprError(d["expr"], names, 1, &count) }
            default:
                de = "unknown def kind"
            }
            if let e = de { return "def '\(name)': \(e)" }
            names.insert(JKey(name))
        }
        return exprError(o["check"], names, 1, &count)
    }

    /// Kleene evaluation: nil = unknown. Only booleans combine; ordering needs safe integers (else unknown); equality never coerces.
    private static func deriveEval(_ x: JSONValue?, _ env: [JKey: JSONValue]) -> JSONValue? {
        guard case let .object(o)? = x else { return nil }
        if let r = o["ref"] { return r.asString.flatMap { env[JKey($0)] } }
        if let c = o["const"] { return c }
        let op = o["op"]?.asString ?? ""
        if IV.same(op, "not") {
            guard case let .bool(b)? = deriveEval(o["arg"], env) else { return nil }
            return .bool(!b)
        }
        if IV.same(op, "and") || IV.same(op, "or") {
            let stop = IV.same(op, "or")
            var unknown = false
            for a in o["args"]?.asArray ?? [] {
                guard case let .bool(b)? = deriveEval(a, env) else {
                    unknown = true
                    continue
                }
                if b == stop { return .bool(stop) }
            }
            return unknown ? nil : .bool(!stop)
        }
        guard let a = deriveEval(o["a"], env), let b = deriveEval(o["b"], env) else { return nil }
        if IV.same(op, "eq") { return .bool(IV.scalarEq(a, b)) }
        if IV.same(op, "neq") { return .bool(!IV.scalarEq(a, b)) }
        guard let ai = IV.int(a), let bi = IV.int(b) else { return nil }
        switch op {
        case "lt": return .bool(ai < bi)
        case "lte": return .bool(ai <= bi)
        case "gt": return .bool(ai > bi)
        case "gte": return .bool(ai >= bi)
        default: return nil
        }
    }

    /// The number of the verifier's own history events inside `(now - window, now]` matching the optional verb / prefix; nil
    /// (unknown) when the history is absent, too long or carries a malformed event.
    private static func deriveCount(_ d: JObject, _ w: Int64, _ now: Int64, _ history: [JSONValue]?) -> JSONValue? {
        guard let h = history, h.count <= DERIVE_MAX_HISTORY else { return nil }
        let verb = d["verb"]?.asString
        let prefix = d["resource_prefix"]?.asString
        var n: Int64 = 0
        for e in h {
            guard case let .object(eo) = e, let t = IV.int(eo["t"]), let ev = eo["verb"]?.asString, let er = eo["resource"]?.asString else { return nil }
            if t > now - w && t <= now && (verb.map { IV.same(ev, $0) } ?? true) && (prefix.map { IV.startsWith(er, $0) } ?? true) { n += 1 }
        }
        return .int(n)
    }

    /// Evaluate a well-formed derive caveat: true only when `check` is exactly true (false and unknown both refuse).
    /// `claims` maps a caveat id to the claims of the discharge that VERIFIED in this evaluation: the only claim source.
    static func evaluateDerive(_ c: JObject, now: Int64, action: JSONValue?, history: [JSONValue]?, claims: [JKey: JObject]) -> Bool? {
        var env: [JKey: JSONValue] = [:]
        for dv in c["defs"]?.asArray ?? [] {
            guard case let .object(d) = dv, let name = d["name"]?.asString else { continue }
            var v: JSONValue?
            switch d["kind"]?.asString ?? "" {
            case "count":
                if let w = IV.int(d["window_ms"]) { v = deriveCount(d, w, now, history) }
            case "param":
                if let p = d["path"]?.asString, let r = IntentWB.resolveParamPath(action?.get("params"), "action.params." + p), k1Scalar(r) { v = r }
            case "action":
                if let f = d["field"]?.asString, let x = action?.get(f), k1Str256(x) { v = x }
            case "claim":
                if let cid = d["caveat_id"]?.asString, let cl = d["claim"]?.asString { v = claims[JKey(cid)]?[JKey(cl)] }
            case "expr":
                v = deriveEval(d["expr"], env)
            default:
                break
            }
            if let x = v { env[JKey(name)] = x }
        }
        if case let .bool(b)? = deriveEval(c["check"], env) { return b }
        return nil
    }

    // ======================================================================================
    // spiffe_bound
    // ======================================================================================

    /// nil when the caveat is well-formed: exactly one of `spiffe_id` / `spiffe_prefix`, a valid SPIFFE ID.
    public static func spiffeBoundError(_ c: JSONValue?) -> String? {
        guard case let .object(o)? = c else { return "caveat must be an object" }
        if let e = closedMembers(o, ["type"], ["spiffe_id", "spiffe_prefix"], "spiffe_bound") { return e }
        if !k1Is(o["type"], CAVEAT_SPIFFE_BOUND) { return "not a spiffe_bound caveat" }
        if (o["spiffe_id"] == nil) == (o["spiffe_prefix"] == nil) { return "exactly one of spiffe_id and spiffe_prefix" }
        return spiffeIdError(o["spiffe_id"] ?? o["spiffe_prefix"])
    }

    /// `spiffe_id`: the peer must equal it. `spiffe_prefix`: the peer must equal it or lie below it (`prefix + "/"`).
    private static func spiffeSatisfied(_ c: JSONValue, _ peer: String?) -> Bool {
        guard spiffeBoundError(c) == nil, let p = peer, spiffeIdError(p) == nil, case let .object(o) = c else { return false }
        if let id = o["spiffe_id"]?.asString { return IV.same(p, id) }
        guard let pre = o["spiffe_prefix"]?.asString else { return false }
        return IV.same(p, pre) || IV.startsWith(p, pre + "/")
    }

    // ======================================================================================
    // The K1 evaluator
    // ======================================================================================

    /// Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Non-K1 caveats are left to the stock
    /// evaluators. `needs_discharge`, `sealed`, `max_uses`, `derive` ids must be unique per type over the chain and narrow block:
    /// a duplicate fails every caveat that shares it. `max_uses` is only checked for well-formedness and expiry here;
    /// `reserveMaxUses` spends it. Total.
    public static func evaluateK1(grant: JSONValue, chain: JSONValue?, k1 k1opt: K1Input?, now: Int64, action: JSONValue?) -> K1Result {
        var failed: [String] = []
        var reasons: [String] = []
        func fail(_ c: JSONValue?, _ why: String) {
            failed.append(c?.asObject?["type"]?.asString ?? "<malformed>")
            reasons.append(why)
        }
        func result(_ plain: [JSONValue], _ bound: [BoundCaveat]) -> K1Result {
            K1Result(ok: failed.isEmpty, failed: failed, reasons: reasons, plain: plain, bound: bound)
        }
        let baseOpt = boundCaveats(grant: grant, chain: chain)
        guard let base = baseOpt, k1ClockOk(now) else {
            fail(.object(["type": .string("<malformed>")]), baseOpt == nil ? "malformed capability chain" : "the verifier clock is not a safe integer (fail closed)")
            return result([], [])
        }
        // No K1 input at all (not even an empty one): every K1 caveat is refused, whatever its type.
        guard let k1 = k1opt else {
            let mine = base.filter { isK1Caveat($0.caveat) }
            for b in mine { fail(b.caveat, "the caveat language is not configured (no k1 input)") }
            return result([], mine)
        }
        let hops = k1Hops(grant, chain)
        let leafIndex = hops.count - 1
        var bound = base
        var plain: [JSONValue] = []
        if let narrow = k1.narrow {
            let nv = verifyNarrow(narrow, grant: grant, chain: chain, now: now, actionDigest: k1.actionDigest)
            if !nv.ok {
                fail(.object(["type": .string("narrow")]), nv.reason)
                return result([], bound.filter { isK1Caveat($0.caveat) })
            }
            let leafHash = Capability.capHash(hops[leafIndex])
            bound += nv.caveats.map { BoundCaveat(caveat: $0, hop: leafIndex, capHash: leafHash) }
            plain = nv.caveats.filter { !isK1Caveat($0) }
        }
        let k1Bound = bound.filter { isK1Caveat($0.caveat) }
        // ids are unique per type across the chain and narrow block
        var seen: [JKey: Int] = [:]
        func seenKey(_ c: JSONValue) -> JKey? {
            guard let t = c.get("type")?.asString, let id = c.get("id")?.asString else { return nil }
            return JKey(t + "\u{0}" + id)
        }
        for b in k1Bound { if let k = seenKey(b.caveat) { seen[k, default: 0] += 1 } }
        var claims: [JKey: JObject] = [:]
        // pass 1: discharges (derive reads their claims)
        for b in k1Bound where k1Is(b.caveat.get("type"), CAVEAT_NEEDS_DISCHARGE) {
            if let bad = needsDischargeError(b.caveat) {
                fail(b.caveat, bad)
                continue
            }
            let id = b.caveat.get("id")?.asString ?? ""
            if (seenKey(b.caveat).flatMap { seen[$0] } ?? 0) > 1 {
                fail(b.caveat, "duplicate needs_discharge id '\(id)'")
                continue
            }
            var why = "no discharge presented"
            var okd: DischargeVerdict?
            for d in k1.discharges {
                guard case let .object(dobj) = d, IV.same(dobj["caveat_id"]?.asString, id) else { continue }
                let v = verifyDischarge(d, b.caveat, DischargeBinding(capHash: b.capHash, actionDigest: k1.actionDigest, pins: k1.pins, now: now,
                                                                      revoked: k1.revokedDischarges))
                if v.ok {
                    okd = v
                    break
                }
                why = v.reason
            }
            if let ok = okd {
                claims[JKey(id)] = ok.claims
            } else {
                fail(b.caveat, why)
            }
        }
        // pass 2: everything else, in order
        for b in k1Bound {
            let c = b.caveat
            guard let ty = c.get("type")?.asString else { continue }
            let id = c.get("id")?.asString ?? ""
            let dup = (seenKey(c).flatMap { seen[$0] } ?? 0) > 1
            switch ty {
            case CAVEAT_SEALED:
                if let e = closedMembers(c.asObject ?? [:], ["type"], [], "sealed") {
                    fail(c, e)
                } else if b.hop != leafIndex {
                    fail(c, "a hop was appended below a sealed hop")
                }
            case CAVEAT_MAX_USES:
                if let e = maxUsesError(c) {
                    fail(c, e)
                } else if dup {
                    fail(c, "duplicate max_uses id '\(id)'")
                } else if let until = IV.nonNeg(c.get("until")), now >= until {
                    fail(c, "max_uses '\(id)' has expired")
                }
            case CAVEAT_DERIVE:
                if let e = deriveError(c) {
                    fail(c, e)
                } else if dup {
                    fail(c, "duplicate derive id '\(id)'")
                } else if case let .object(co) = c {
                    let r = evaluateDerive(co, now: now, action: action, history: k1.history, claims: claims)
                    if r != true { fail(c, r == nil ? "derive check is unknown (a fact is missing)" : "derive check is false") }
                }
            case CAVEAT_SPIFFE_BOUND:
                if !spiffeSatisfied(c, k1.spiffeId) { fail(c, "the presenting workload does not carry the required SPIFFE ID") }
            default:
                break
            }
        }
        return result(plain, k1Bound)
    }

    /// The whole caveat decision of a leaf: K1 types by `evaluateK1`, every other caveat of `policyCaveats(grant, chain)` PLUS the
    /// verified narrow block's plain caveats by the agent-native evaluator. `context` is the stock context (`now`,
    /// `delegation_depth`, `action` {verb, resource, params}, ...). Returns `(allow, failed sorted)`; `failed` = stock failures +
    /// K1 failures. Total.
    public static func evaluateCaveatsK1(grant: JSONValue, chain: JSONValue?, k1: K1Input?, context: JSONValue) -> (allow: Bool, failed: [String]) {
        let now = IV.int(context.get("now")) ?? Int64.max
        let k = evaluateK1(grant: grant, chain: chain, k1: k1, now: now, action: context.get("action"))
        let pc = policyCaveats(grant: grant, chain: chain)
        let stockList: JSONValue?
        if case let .array(list)? = pc {
            stockList = .array(list.filter { !isK1Caveat($0) } + k.plain)
        } else {
            stockList = pc
        }
        let actionContext: JSONValue = .object(["action": context.get("action") ?? .null])
        let s = evaluateAgentCaveats(stockList, context: context, actionContext: actionContext)
        let failed = (s.failed + k.failed).sorted(by: IV.utf8Less)
        return (failed.isEmpty, failed)
    }
}

// ======================================================================================
// Presented discharges / narrow block (the request headers)
// ======================================================================================

/// What `PCA.presentedK1` read: `discharges` (a JSON array) and `narrow` (any JSON value), each nil when its header is absent.
public struct PresentedK1: Equatable, Sendable {
    public let discharges: [JSONValue]?
    public let narrow: JSONValue?
}

/// A header that could not be read (not strict base64url of UTF-8, not strict JSON, or `PCA-Discharges` not an array).
public struct PresentedK1Error: Error, Equatable, Sendable {
    public let message: String
}

extension PCA {
    /// The value of header `name` (lowercase), names matched case-insensitively. Case-variants carrying DIFFERENT values are
    /// ambiguous and read as absent (never silently pick one). An empty value is absent.
    private static func k1Header(_ headers: [String: String], _ name: String) -> String? {
        let vals = Set(headers.filter { $0.key.lowercased() == name }.map { $0.value })
        guard vals.count == 1, let v = vals.first, !v.isEmpty else { return nil }
        return v
    }

    private static func k1HeaderJSON(_ v: String) throws -> JSONValue {
        guard let bytes = Base64URLStrict.decode(v), let text = String(bytes: bytes, encoding: .utf8) else {
            throw PresentedK1Error(message: "not strict base64url of UTF-8")
        }
        do { return try StrictJSON.parse(text) } catch { throw PresentedK1Error(message: "not strict JSON") }
    }

    /// Discharges and a narrow block as presented with a request: header `PCA-Discharges` (strict base64url of a UTF-8 JSON
    /// array) and `PCA-Narrow` (strict base64url JSON, any value; the verifier refuses a non-object). Throws
    /// `PresentedK1Error` for an unreadable header: treat it as NO discharges (the K1 caveat stays unsatisfied). Merge the result
    /// into the verifier's own `K1Input` with the verifier's values winning, and only when a K1Input is configured at all.
    public static func presentedK1(headers: [String: String]) throws -> PresentedK1 {
        var discharges: [JSONValue]?
        if let d = k1Header(headers, "pca-discharges") {
            guard case let .array(a) = try k1HeaderJSON(d) else { throw PresentedK1Error(message: "PCA-Discharges must be a JSON array") }
            discharges = a
        }
        var narrow: JSONValue?
        if let n = k1Header(headers, "pca-narrow") { narrow = try k1HeaderJSON(n) }
        return PresentedK1(discharges: discharges, narrow: narrow)
    }
}
