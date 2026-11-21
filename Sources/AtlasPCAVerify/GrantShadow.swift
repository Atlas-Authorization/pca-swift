import Foundation

/// Shadow policy rollout of `pca-grants` (shadow.ts). An enforced bundle revision may list candidate bundles in `shadow`; `runShadow` computes the
/// enforced decision first and returns it untouched, recording what each candidate would have said. Every divergence becomes a verifier-signed diff;
/// `promotionGate` must pass before `promoteShadow` builds the next revision's body. Nothing here decides an action: it is analysis and rollout
/// tooling that runs beside the verifier.
public enum Shadow {
    public static let SHADOW_DIFF_DOMAIN = "atlas-pca/shadow-diff/v1\u{0}"
    public static let WIDENING_EXPLANATION_DOMAIN = "atlas-pca/shadow-widening-explanation/v1\u{0}"
    public static let PROMOTION_APPROVAL_DOMAIN = "atlas-pca/shadow-promotion-approval/v1\u{0}"

    static func rank(_ k: String?) -> Int {
        switch k { case "deny": return 0; case "escalate": return 1; case "allow": return 2; default: return -1 }
    }
    static func isKind(_ k: JSONValue?) -> Bool { rank(k?.asString) >= 0 }

    /// A candidate bundle: its digest and its pure decision function (a throw is an `error` outcome).
    public struct Candidate {
        public let digest: String
        public let decide: (JSONValue) throws -> String?
        public init(digest: String, decide: @escaping (JSONValue) throws -> String?) { self.digest = digest; self.decide = decide }
    }

    /// What one candidate said. `decision` is a decision kind or `error`; `widening`: the candidate would have been MORE permissive.
    public struct Outcome: Equatable {
        public let digest: String
        public let decision: String
        public let diverged: Bool
        public let widening: Bool
        public var json: JSONValue {
            .object(["digest": .string(digest), "decision": .string(decision), "diverged": .bool(diverged), "widening": .bool(widening)])
        }
    }

    /// The enforced decision and what each candidate would have said.
    public struct Run {
        public let decision: String?
        public let shadow: [Outcome]
    }

    public static func runShadow(_ input: JSONValue, enforced: (JSONValue) throws -> String?, candidates: [Candidate]) rethrows -> Run {
        let decision = try enforced(input)
        var out: [Outcome] = []
        for c in candidates {
            // a value type: the candidate gets its own copy and cannot mutate the enforced input
            if let d = try? c.decide(input), rank(d) >= 0 {
                out.append(Outcome(digest: c.digest, decision: d, diverged: d != decision, widening: rank(d) > rank(decision)))
            } else {
                out.append(Outcome(digest: c.digest, decision: "error", diverged: false, widening: false))
            }
        }
        return Run(decision: decision, shadow: out)
    }

    /// The `shadow` member of a decision record, from the outcomes.
    public static func shadowRecordField(_ o: [Outcome]) -> JSONValue {
        .array(o.map { .object(["digest": .string($0.digest), "decision": .string($0.decision), "diverged": .bool($0.diverged)]) })
    }

    private static func diffBody(_ d: JObject) -> JSONValue {
        .object(K3Sig.pick(d, ["v", "shadow_digest", "enforced_digest", "action_digest", "enforced", "shadow", "widening", "at", "signer"]))
    }

    /// A well formed shadow diff signed by its signer (`signer` nil = any signer). Never throws.
    public static func verifyShadowDiff(_ dv: JSONValue?, signer: String? = nil) -> Bool {
        guard let d = dv?.asObject, d["v"]?.safeInt == 1, K3Sig.str(d["shadow_digest"], 128) != nil, K3Sig.str(d["enforced_digest"], 128) != nil,
              K3Sig.str(d["action_digest"], 128) != nil, isKind(d["enforced"]), isKind(d["shadow"]), case .bool(let widening)? = d["widening"],
              K3Sig.safeInt(d["at"]) != nil, let who = K3Sig.str(d["signer"], 128) else { return false }
        let e = d["enforced"]?.asString, s = d["shadow"]?.asString
        if e == s || widening != (rank(s) > rank(e)) { return false }
        if let signer = signer, !IV.same(signer, who) { return false }
        return PCAGrants.verifyBody(SHADOW_DIFF_DOMAIN, diffBody(K3Sig.without(d, "sig")), who, d["sig"])
    }

    /// Per-candidate counters.
    public struct Stats: Equatable {
        public var total: Int64 = 0, diverged: Int64 = 0, widened: Int64 = 0, tightened: Int64 = 0, errors: Int64 = 0
        public var json: JSONValue {
            .object(["total": .int(total), "diverged": .int(diverged), "widened": .int(widened), "tightened": .int(tightened), "errors": .int(errors)])
        }
    }

    /// Collects the signed diffs and counters per candidate. In memory: persist `diffs(_:)` to the decision log for the audit trail.
    public final class ShadowLog: @unchecked Sendable {
        private var stat: [String: Stats] = [:]
        private var list: [String: [JObject]] = [:]
        private let secret: PCAEdKey
        private let lock = PCALock()
        public init(_ secret: PCAEdKey) { self.secret = secret }

        public var signer: String { PCAGrants.signerOf(secret) }

        /// Count one observation; sign and keep a diff when the candidate diverged. Returns the diff or nil.
        @discardableResult
        public func observe(enforcedDigest: String, actionDigest: String, enforced: String?, outcome: Outcome, at: Int64) throws -> JObject? {
            lock.lock(); defer { lock.unlock() }
            var s = stat[outcome.digest] ?? Stats()
            s.total += 1
            if outcome.decision == "error" { s.errors += 1; stat[outcome.digest] = s; return nil }
            if !outcome.diverged { stat[outcome.digest] = s; return nil }
            s.diverged += 1
            if outcome.widening { s.widened += 1 } else { s.tightened += 1 }
            stat[outcome.digest] = s
            var base: JObject = ["v": .int(1), "shadow_digest": .string(outcome.digest), "enforced_digest": .string(enforcedDigest), "action_digest": .string(actionDigest),
                                 "shadow": .string(outcome.decision), "widening": .bool(outcome.widening), "at": .int(at), "signer": .string(signer)]
            if let e = enforced { base["enforced"] = .string(e) }
            var diff = base
            diff["sig"] = .string(try PCAGrants.signBody(SHADOW_DIFF_DOMAIN, diffBody(base), secret))
            list[outcome.digest, default: []].append(diff)
            return diff
        }

        public func stats(_ digest: String) -> Stats { lock.lock(); defer { lock.unlock() }; return stat[digest] ?? Stats() }
        public func diffs(_ digest: String) -> [JObject] { lock.lock(); defer { lock.unlock() }; return list[digest] ?? [] }
    }

    private static func expBody(_ e: JObject) -> JSONValue { .object(K3Sig.pick(e, ["v", "shadow_digest", "action_digest", "reason_digest", "principal"])) }

    /// A principal states that this widening is intended; `e` = `{shadow_digest, action_digest, reason_digest}`.
    public static func signWideningExplanation(_ secret: PCAEdKey, _ e: JObject) throws -> JSONValue {
        var base: JObject = ["v": .int(1)]
        for (k, v) in e { base[k] = v }
        base["principal"] = .string(PCAGrants.signerOf(secret))
        base["sig"] = .string(try PCAGrants.signBody(WIDENING_EXPLANATION_DOMAIN, expBody(base), secret))
        return .object(base)
    }

    private static func verifyExplanation(_ eo: JSONValue?) -> Bool {
        guard let e = eo?.asObject, e["v"]?.safeInt == 1, K3Sig.str(e["shadow_digest"], 128) != nil, K3Sig.str(e["action_digest"], 128) != nil,
              K3Sig.str(e["reason_digest"], 128) != nil, let p = K3Sig.str(e["principal"], 128) else { return false }
        return PCAGrants.verifyBody(WIDENING_EXPLANATION_DOMAIN, expBody(e), p, e["sig"])
    }

    private static func apBody(_ a: JObject) -> JSONValue { .object(K3Sig.pick(a, ["v", "shadow_digest", "enforced_digest", "at", "principal"])) }

    /// `a` = `{shadow_digest, enforced_digest, at}`.
    public static func signPromotionApproval(_ secret: PCAEdKey, _ a: JObject) throws -> JSONValue {
        var base: JObject = ["v": .int(1)]
        for (k, v) in a { base[k] = v }
        base["principal"] = .string(PCAGrants.signerOf(secret))
        base["sig"] = .string(try PCAGrants.signBody(PROMOTION_APPROVAL_DOMAIN, apBody(base), secret))
        return .object(base)
    }

    private static func verifyApproval(_ ao: JSONValue?) -> Bool {
        guard let a = ao?.asObject, a["v"]?.safeInt == 1, K3Sig.str(a["shadow_digest"], 128) != nil, K3Sig.str(a["enforced_digest"], 128) != nil,
              K3Sig.safeInt(a["at"]) != nil, let p = K3Sig.str(a["principal"], 128) else { return false }
        return PCAGrants.verifyBody(PROMOTION_APPROVAL_DOMAIN, apBody(a), p, a["sig"])
    }

    private static func no(_ code: String, _ reason: String, _ unexplained: [String]? = nil) -> JObject {
        var r: JObject = ["ok": .bool(false), "code": .string(code), "reason": .string(reason)]
        if let u = unexplained { r["unexplained"] = .array(u.map { .string($0) }) }
        return r
    }

    private static let SURFACES = ["narrower", "equal", "wider", "unknown"]

    /// May the candidate be promoted? `o` = `{shadow_digest, enforced_digest, minSamples, principals, explanations?, surface, approval?}`. Returns
    /// `{ok: true, samples, widenings, surface}` or `{ok: false, code, reason, unexplained?}`. Fails closed on any evaluation error.
    public static func promotionGate(_ log: ShadowLog, _ o: JObject) -> JObject {
        guard let shadow = K3Sig.str(o["shadow_digest"], 128), let enforced = K3Sig.str(o["enforced_digest"], 128),
              let ms = K3Sig.safeInt(o["minSamples"]), ms >= 1, let principals = o["principals"]?.asArray,
              let surface = o["surface"]?.asString, SURFACES.contains(surface) else { return no("bad_input", "bad gate options") }
        let s = log.stats(shadow)
        if s.total < ms { return no("too_few_samples", "\(s.total) observation(s), need \(ms)") }
        if s.errors > 0 { return no("shadow_errors", "\(s.errors) observation(s) where the candidate failed") }
        let diffs = log.diffs(shadow)
        let badDiff = "a recorded diff does not verify, belongs to another pair, or is missing"
        for d in diffs {
            if !(verifyShadowDiff(.object(d), signer: log.signer) && d["shadow_digest"]?.asString == shadow && d["enforced_digest"]?.asString == enforced) {
                return no("bad_diff", badDiff)
            }
        }
        if Int64(diffs.count) != s.diverged { return no("bad_diff", badDiff) }
        var explained = Set<String>()
        if let ex = o["explanations"], !ex.isNull {
            guard let list = ex.asArray else { return no("bad_input", "evaluation error (fail closed)") }
            for e in list {
                if verifyExplanation(e), let p = e.get("principal"), principals.contains(p), e.get("shadow_digest")?.asString == shadow, let a = e.get("action_digest")?.asString {
                    explained.insert(a)
                }
            }
        }
        var un = Set<String>()
        var widenings: Int64 = 0
        for d in diffs where d["widening"] == .bool(true) {
            widenings += 1
            if let a = d["action_digest"]?.asString, !explained.contains(a) { un.insert(a) }
        }
        if !un.isEmpty {
            let sorted = un.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            return no("unexplained_widening", "\(sorted.count) widening(s) without a principal's explanation", sorted)
        }
        if surface == "wider" || surface == "unknown" {
            let a = o["approval"]
            if !verifyApproval(a) || !(a?.get("principal").map { principals.contains($0) } ?? false) || a?.get("shadow_digest")?.asString != shadow
                || a?.get("enforced_digest")?.asString != enforced {
                return no("advisory_wider", "the analyzer reports the candidate " + (surface == "wider" ? "wider" : "not provably narrower")
                          + " on the declared surfaces: a principal-signed approval is required")
            }
        }
        return ["ok": .bool(true), "samples": .int(s.total), "widenings": .int(widenings), "surface": .string(surface)]
    }

    /// The body of the bundle revision that makes the candidate the enforced policy: the candidate's content at revision + 1 chained to the enforced
    /// revision with the shadow list cleared. Needs a passing gate and the candidate listed in the enforced revision's shadow.
    public static func promoteShadow(_ enforced: JObject, _ candidate: JObject, _ gate: JObject, now: JSONValue?) throws -> JObject {
        guard let digest = K3.bundleDigest(.object(candidate)) else { throw PCAProducerError("promoteShadow: the candidate is not strict canonical JSON") }
        guard gate["ok"] == .bool(true) else { throw PCAProducerError("promoteShadow: the gate did not pass (\(gate["code"]?.asString ?? "undefined"))") }
        guard let sh = enforced["shadow"]?.asArray, sh.contains(.string(digest)) else {
            throw PCAProducerError("promoteShadow: the candidate is not listed in the enforced revision's shadow")
        }
        guard let at = K3Sig.safeInt(now) else { throw PCAProducerError("promoteShadow: bad time") }
        guard let rev = enforced["revision"]?.safeInt, let prev = K3.bundleDigest(.object(enforced)) else { throw PCAProducerError("promoteShadow: bad revision") }
        var out = candidate
        for k in ["sigs", "shadow", "prev"] { out[JKey(k)] = nil }
        out["revision"] = .int(rev + 1)
        out["prev"] = .string(prev)
        out["issued_at"] = .int(at)
        return out
    }
}

extension PCAGrants {
    private static func rankOf(_ k: String?) -> Int { Shadow.rank(k) }

    /// "What would have changed": re-run two pure decision functions over recorded traffic. `cases` are `{action_digest, input}`. A change is
    /// `{action_digest, before, after, direction}`. Analysis tooling: it runs outside the trusted core.
    public static func semanticDiff(_ cases: [JSONValue], old oldDecide: (JSONValue) throws -> String?, new newDecide: (JSONValue) throws -> String?) rethrows -> [JSONValue] {
        var out: [JSONValue] = []
        for co in cases {
            let input = co.get("input") ?? .null
            let before = try oldDecide(input), after = try newDecide(input)
            if before != after {
                var ch: JObject = [:]
                if let a = co.get("action_digest") { ch["action_digest"] = a }
                if let b = before { ch["before"] = .string(b) }
                if let a = after { ch["after"] = .string(a) }
                ch["direction"] = .string(rankOf(after) >= 0 && rankOf(before) >= 0 && rankOf(after) > rankOf(before) ? "widened" : "tightened")
                out.append(.object(ch))
            }
        }
        return out
    }

    /// Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift).
    public static func auditReplay(_ records: [JSONValue], _ cases: [JSONValue], decide: (JSONValue, JSONValue?) throws -> String?) rethrows -> [JSONValue] {
        var byAction: [(JSONValue?, JSONValue)] = []
        for co in cases {
            let k = co.get("action_digest"), v = co.get("input") ?? .null
            if let i = byAction.firstIndex(where: { $0.0 == k }) { byAction[i].1 = v } else { byAction.append((k, v)) }
        }
        var out: [JSONValue] = []
        for r in records {
            guard let input = byAction.first(where: { $0.0 == r.get("action_digest") })?.1 else { continue }
            let d = try decide(input, r.get("bundle_revision"))
            if d.map({ JSONValue.string($0) }) != r.get("decision") { out.append(r) }
        }
        return out
    }
}
