import Foundation

/// One minted token: the data class, the value, the digest of the grant it was minted under, and that grant's expiry.
public struct VaultEntry: Equatable {
    public let cls: String
    public let value: JSONValue
    public let grant: String
    public let exp: Int64
    public init(cls: String, value: JSONValue, grant: String, exp: Int64) {
        self.cls = cls
        self.value = value
        self.grant = grant
        self.exp = exp
    }
}

public protocol VaultStore: AnyObject {
    func put(_ token: String, _ entry: VaultEntry)
    func get(_ token: String) -> VaultEntry?
}

/// In-process vault (one lock). Keys compare by Unicode scalars like every JSON key here.
public final class MemoryVault: VaultStore, @unchecked Sendable {
    private var m: [JKey: VaultEntry] = [:]
    private let lock = NSLock()
    public init() {}
    public func put(_ token: String, _ entry: VaultEntry) {
        lock.lock()
        defer { lock.unlock() }
        m[JKey(token)] = entry
    }
    public func get(_ token: String) -> VaultEntry? {
        lock.lock()
        defer { lock.unlock() }
        return m[JKey(token)]
    }
}

public struct DetokenizeResult: Equatable {
    public let decision: String
    public let code: String?
    /// the scalar value on allow, else null
    public let value: JSONValue
    public var json: JSONValue {
        .object(["decision": .string(decision), "code": code.map { JSONValue.string($0) } ?? .null, "value": value])
    }
}

/// The epsilon accounting state of one principal: explicit and immutable (a step returns the next one).
public struct AggregateState: Equatable {
    public var spentMicro: Int64
    public var queries: Int64
    public var answered: [JKey: Int64]
    public init(spentMicro: Int64 = 0, queries: Int64 = 0, answered: [JKey: Int64] = [:]) {
        self.spentMicro = spentMicro
        self.queries = queries
        self.answered = answered
    }
    public static let empty = AggregateState()

    /// nil when `v` is not a well-formed state: {spent_micro, queries} unsigned safe integers, `answered` an object of safe integers.
    public static func parse(_ v: JSONValue?) -> AggregateState? {
        guard let o = v?.asObject, let s = K5.uint(o["spent_micro"]), let q = K5.uint(o["queries"]), let a = o["answered"]?.asObject else { return nil }
        var out: [JKey: Int64] = [:]
        for (k, x) in a {
            guard let n = ReadVault.safeInt(x) else { return nil }
            out[k] = n
        }
        return AggregateState(spentMicro: s, queries: q, answered: out)
    }
    var valid: Bool {
        spentMicro >= 0 && spentMicro <= Canonical.MAX_SAFE && queries >= 0 && queries <= Canonical.MAX_SAFE
            && answered.values.allSatisfy { $0 >= -Canonical.MAX_SAFE && $0 <= Canonical.MAX_SAFE }
    }
    public var json: JSONValue {
        var a: JObject = [:]
        for (k, v) in answered { a[k] = .int(v) }
        return .object(["spent_micro": .int(spentMicro), "queries": .int(queries), "answered": .object(a)])
    }
}

public struct AggregateResult: Equatable {
    public let decision: String
    public let code: String?
    public let value: Int64?
    public let state: AggregateState
    public let chargedMicro: Int64
    /// The shape the shared vectors expect: {decision, code, value, state, charged_micro}.
    public var json: JSONValue {
        .object(["decision": .string(decision), "code": code.map { JSONValue.string($0) } ?? .null, "value": value.map { JSONValue.int($0) } ?? .null,
                 "state": state.json, "charged_micro": .int(chargedMicro)])
    }
}

/// A stream of 48-bit draws. Not thread safe: one stream per query.
public final class Draws {
    let seed: String
    var block: Int64 = 0
    var buf: [Int64] = [] // reversed: removeLast() yields the next draw in order

    init(seed: String) { self.seed = seed }

    /// Block i is the decoded SHA-256 of the canonical {d, seed, i}; five 48-bit big-endian values (bytes 0-5, 6-11, ...) per block.
    func next48() throws -> Int64 {
        if buf.isEmpty {
            guard let h = IV.strictHash(.object(["d": .string(ReadVault.DP_STREAM), "seed": .string(seed), "i": .int(block)])),
                  let bytes = Base64URLStrict.decode(h, length: 32) else { throw ReadVault.RangeError() }
            block += 1
            var vals: [Int64] = []
            for k in 0..<5 {
                var v: Int64 = 0
                for j in 0..<6 { v = v * 256 + Int64(bytes[k * 6 + j]) }
                vals.append(v)
            }
            buf = Array(vals.reversed())
        }
        return buf.removeLast()
    }

    /// Uniform on 0..<n, 1 <= n <= 2^47, by rejection sampling (at most 100000 draws).
    public func uniform(_ n: Int64) throws -> Int64 {
        guard n >= 1, n <= (Int64(1) << 47) else { throw ReadVault.RangeError() }
        let two48 = Int64(1) << 48
        let limit = two48 - (two48 % n)
        for _ in 0..<ReadVault.MAX_STEPS {
            let r = try next48()
            if r < limit { return r % n }
        }
        throw ReadVault.RangeError()
    }
}

struct AggRule {
    let verb: String, prefix: String
    let purposes: [String], fns: [String]
    let minGroup: Int64, clamp: Int64, epsilon: Int64
    let dp: Bool
}

struct AggGrant {
    let raw: JSONValue
    let principal: String
    let issuedAt: Int64, expiresAt: Int64
    let rules: [AggRule]
    let budget: Int64, maxQueries: Int64
}

/// K5 tokenisation vault and aggregate read limits (C-315..C-319). Total; replays packages/pca/conformance/vault-aggregate-vectors.json.
/// Port of packages/pca/src/read-vault.ts. Every number is a signed 64-bit integer (all intermediate values stay below 2^53 in the reference).
public enum ReadVault {
    struct RangeError: Error {}
    public static let AGGREGATE_DOMAIN = "atlas-pca/aggregate-grant/v1\u{0}"
    static let AG_REF = "atlas-pca/aggregate-grant-ref/v1"
    static let AG_Q = "atlas-pca/aggregate-query/v1"
    static let AG_N = "atlas-pca/aggregate-noise/v1"
    static let DP_STREAM = "atlas-pca/dp-stream/v1"
    static let MAX_STEPS = 100_000

    static func safeInt(_ v: JSONValue?) -> Int64? {
        if case let .int(i)? = v, i >= -Canonical.MAX_SAFE, i <= Canonical.MAX_SAFE { return i }
        return nil
    }

    // ---- vault ----

    /// `ReadSide.redactRead` that also records every token it minted in `store`.
    public static func redactReadWithVault(grant: JSONValue?, input: JSONValue?, store: VaultStore) -> ReadResult {
        let r = ReadSide.redactRead(grant: grant, input: input)
        guard r.decision == "allow", let g = ReadSide.parseGrant(grant?.get("body")), let digest = ReadSide.readGrantDigest(g.raw) else { return r }
        for (path, f) in r.fields where f.get("action")?.asString == "masked" && f.get("kind")?.asString == "token" {
            guard let tok = r.view[path]?.asString, let cls = f.get("class")?.asString, let val = input?.get("record")?.get(path.s) else { continue }
            store.put(tok, VaultEntry(cls: cls, value: val, grant: digest, exp: g.expiresAt))
        }
        return r
    }

    /// Turn a token back into its value, only for a sink the grant allows that token's class to reach.
    public static func detokenize(grant: JSONValue?, principal: JSONValue?, now: JSONValue?, sink: JSONValue?, token: JSONValue?, store: VaultStore) -> DetokenizeResult {
        func no(_ code: String) -> DetokenizeResult { DetokenizeResult(decision: "deny", code: code, value: .null) }
        guard K5.b32(principal) != nil, K5.uint(now) != nil, let tok = token?.asString, let sinkName = sink?.asString else { return no("bad_request") }
        let gr = ReadSide.gradeGrant(grant, principal, now)
        guard let g = gr.grant else { return no(gr.code ?? "bad_request") }
        guard let e = store.get(tok) else { return no("unknown_token") }
        guard let gd = ReadSide.readGrantDigest(g.raw) else { return no("bad_request") }
        if e.grant != gd { return no("unknown_token") }
        if gr.now >= e.exp { return no("expired") }
        guard let rule = g.sinks[sinkName] else { return no("unknown_sink") }
        if rule.allow.contains(e.cls) { return DetokenizeResult(decision: "allow", code: nil, value: e.value) }
        if rule.escalate.contains(e.cls) { return DetokenizeResult(decision: "escalate", code: "label_escalate", value: .null) }
        return no("label_flow")
    }

    // ---- aggregates ----

    static func parseRule(_ x: JSONValue) -> AggRule? {
        guard let r = x.asObject, K5.onlyKeys(r, ["verb", "resource_prefix", "purposes", "fns", "min_group", "clamp", "epsilon_micro", "dp"]),
              let verb = K3Sig.str(r["verb"], 128), let prefix = K3Sig.str(r["resource_prefix"], 512),
              let purposes = K5.sortedUnique(r["purposes"], 16, K5.isId), !purposes.isEmpty,
              let fns = K5.sortedUnique(r["fns"], 2, { $0 == "count" || $0 == "sum" }), !fns.isEmpty,
              let mg = K5.uint(r["min_group"]), mg >= 1, let clamp = K5.uint(r["clamp"]), clamp <= 1_000_000,
              let eps = K5.uint(r["epsilon_micro"]), eps <= 1_073_741_824, case let .bool(dp)? = r["dp"], dp ? eps >= 1 : true else { return nil }
        return AggRule(verb: verb, prefix: prefix, purposes: purposes, fns: fns, minGroup: mg, clamp: clamp, epsilon: eps, dp: dp)
    }

    /// `validAggregateGrantBody`: nil when malformed.
    static func parseAggGrant(_ v: JSONValue?) -> AggGrant? {
        guard let raw = v, let b = raw.asObject,
              K5.onlyKeys(b, ["v", "id", "principal", "issued_at", "expires_at", "rules", "epsilon_budget_micro", "max_queries"]),
              K5.uint(b["v"]) == 1, K5.idV(b["id"]) != nil, let principal = K5.b32(b["principal"]),
              let iat = K5.uint(b["issued_at"]), let exp = K5.uint(b["expires_at"]),
              let ra = b["rules"]?.asArray, !ra.isEmpty, ra.count <= 16,
              let budget = K5.uint(b["epsilon_budget_micro"]), let mq = K5.uint(b["max_queries"]) else { return nil }
        var rules: [AggRule] = []
        for x in ra { guard let r = parseRule(x) else { return nil }; rules.append(r) }
        return AggGrant(raw: raw, principal: principal, issuedAt: iat, expiresAt: exp, rules: rules, budget: budget, maxQueries: mq)
    }

    public static func aggregateGrantDigest(_ body: JSONValue) -> String? { K3Sig.digest(AG_REF, "g", body) }

    /// Answer one aggregate under the signed grant, or refuse. `state` is never mutated; a refusal returns it unchanged (a malformed state
    /// or an internal error returns the empty state). `noise` is "seeded" (deterministic from the salt and the query) or "secure" (PRODUCTION).
    public static func aggregateRead(grant: JSONValue?, principal: JSONValue?, now: JSONValue?, verb: JSONValue?, resource: JSONValue?, purpose: JSONValue?,
                                     fn: JSONValue?, values: JSONValue?, salt: JSONValue?, noise: JSONValue?, state: AggregateState) -> AggregateResult {
        guard state.valid else { return refusal("bad_request", .empty) }
        do {
            return try aggregate(grant, principal, now, verb, resource, purpose, fn, values, salt, noise, state)
        } catch {
            return refusal("bad_request", .empty)
        }
    }

    static func refusal(_ code: String, _ s: AggregateState) -> AggregateResult {
        AggregateResult(decision: "deny", code: code, value: nil, state: s, chargedMicro: 0)
    }

    static func clampSum(_ vs: [Int64], _ c: Int64) -> Int64 { vs.reduce(0) { $0 + max(-c, min(c, $1)) } }

    static func aggregate(_ grant: JSONValue?, _ principal: JSONValue?, _ now: JSONValue?, _ verbV: JSONValue?, _ resourceV: JSONValue?, _ purposeV: JSONValue?,
                          _ fnV: JSONValue?, _ valuesV: JSONValue?, _ saltV: JSONValue?, _ noiseV: JSONValue?, _ st: AggregateState) throws -> AggregateResult {
        func keep(_ code: String) -> AggregateResult { refusal(code, st) }
        guard let p = K5.b32(principal), let n = K5.uint(now) else { return keep("bad_request") }
        guard let sg = grant?.asObject, K5.onlyKeys(sg, ["body", "sig"]), let g = parseAggGrant(sg["body"]) else { return keep("bad_grant") }
        if g.principal != p || !K3Sig.verifyBody(AGGREGATE_DOMAIN, g.raw, signer: p, sig: sg["sig"]) { return keep("bad_signature") }
        if n < g.issuedAt { return keep("not_yet") }
        if n >= g.expiresAt { return keep("expired") }
        guard let verb = K3Sig.str(verbV, 128), let resource = K3Sig.str(resourceV, 512), let purpose = purposeV?.asString, K5.isId(purpose),
              let fn = fnV?.asString, fn == "count" || fn == "sum", let noise = noiseV?.asString, noise == "seeded" || noise == "secure",
              let salt = saltV?.asString, IV.u16(salt) >= ReadSide.SALT_MIN,
              let va = valuesV?.asArray, va.count <= 1_000_000 else { return keep("bad_request") }
        var values: [Int64] = []
        values.reserveCapacity(va.count)
        for x in va { guard let i = safeInt(x) else { return keep("bad_request") }; values.append(i) }
        let rb = Array(resource.utf8)
        guard let rule = g.rules.first(where: { IV.same($0.verb, verb) && rb.starts(with: $0.prefix.utf8) && $0.purposes.contains(purpose) }),
              rule.fns.contains(fn) else { return keep("no_read_scope") }
        if Int64(values.count) < rule.minGroup { return keep("group_too_small") }
        let clamped = clampSum(values, rule.clamp)
        guard let gd = aggregateGrantDigest(g.raw),
              let qd = IV.strictHash(.object(["d": .string(AG_Q), "g": .string(gd), "verb": .string(verb), "resource": .string(resource), "purpose": .string(purpose),
                                              "fn": .string(fn), "n": .int(Int64(values.count)), "s": .int(clamped)])) else { throw RangeError() }
        if let prior = st.answered[JKey(qd)] {
            return AggregateResult(decision: "allow", code: nil, value: prior, state: st, chargedMicro: 0)
        }
        if st.queries + 1 > g.maxQueries { return keep("query_cap") }
        let cost = rule.dp ? rule.epsilon : 0
        if st.spentMicro + cost > g.budget { return keep("epsilon_exhausted") }
        var exact = fn == "count" ? Int64(values.count) : clamped
        if rule.dp {
            let sens = fn == "count" ? 1 : rule.clamp
            let draws: Draws
            if noise == "secure" {
                draws = secureDraws()
            } else {
                guard let seed = IV.strictHash(.object(["d": .string(AG_N), "salt": .string(salt), "q": .string(qd)])) else { throw RangeError() }
                draws = seededDraws(seed)
            }
            exact += try discreteLaplace(draws, rule.epsilon, sens * 1_000_000)
        }
        var answered = st.answered
        answered[JKey(qd)] = exact
        return AggregateResult(decision: "allow", code: nil, value: exact, state: AggregateState(spentMicro: st.spentMicro + cost, queries: st.queries + 1, answered: answered),
                               chargedMicro: cost)
    }

    // ---- integer-exact discrete Laplace sampler (Canonne, Kamath, Steinke 2020, Alg. 1-2) ----

    public static func seededDraws(_ seed: String) -> Draws { Draws(seed: seed) }

    /// The PRODUCTION mode: a 32-byte seed from the operating system's CSPRNG (base64url, unpadded) feeding the same sampler. Answers differ per
    /// call; a repeated identical query is still answered from the state's cache.
    public static func secureDraws() -> Draws {
        var g = SystemRandomNumberGenerator()
        let bytes = (0..<32).map { _ in UInt8.random(in: 0...255, using: &g) }
        return Draws(seed: Base64URLStrict.encode(bytes))
    }

    static func mul(_ a: Int64, _ b: Int64) throws -> Int64 {
        let (m, o) = a.multipliedReportingOverflow(by: b)
        if o { throw RangeError() }
        return m
    }

    /// Bernoulli(num/den).
    static func bern(_ d: Draws, _ num: Int64, _ den: Int64) throws -> Bool { try d.uniform(den) < num }

    /// Bernoulli(exp(-num/den)) for 0 <= num/den <= 1.
    static func bernExpSmall(_ d: Draws, _ num: Int64, _ den: Int64) throws -> Bool {
        var k: Int64 = 1
        while k <= Int64(MAX_STEPS) {
            let dk = try mul(den, k)
            let hit = try bern(d, num, dk)
            if !hit { return k % 2 == 1 }
            k += 1
        }
        throw RangeError()
    }

    /// Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2). Throws where the reference throws a RangeError.
    public static func discreteLaplace(_ d: Draws, _ s: Int64, _ t: Int64) throws -> Int64 {
        guard s >= 1 else { throw RangeError() } // the reference divides by s: 0 / negative never yields a sample
        for _ in 0..<MAX_STEPS {
            let u = try d.uniform(t)
            let first = try bernExpSmall(d, u, t)
            if !first { continue }
            var v: Int64 = 0
            while true {
                let more = try bernExpSmall(d, 1, 1)
                if !more { break }
                v += 1
                if v > Int64(MAX_STEPS) { throw RangeError() }
            }
            let tv = try mul(t, v)
            let y = (u + tv) / s // non-negative operands: integer division is the reference's floor
            let negative = try d.uniform(2) == 1
            if negative && y == 0 { continue }
            return negative ? -y : y
        }
        throw RangeError()
    }
}
