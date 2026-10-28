import Foundation

/// Intent Layer M2: the signed `envelope.intent` slot of a PCActn and the `intent` check. Normative rules:
/// `packages/pca/src/intent-binding.ts` and `conformance/README.md` "12. Intent binding".
///
/// Verifier-side intent policy. ACTIVE iff `require` is true or either threshold is set (non-nil, even an invalid
/// one); an active policy runs the `intent` check even for a PCActn without the slot and fails it closed. A set
/// threshold that is not a non-negative safe integer is a misconfiguration and fails the check.
public struct IntentPolicy: Equatable {
    /// Require every PCActn to carry a bound `intent`.
    public var require: Bool
    /// Deny when the claimed `fidelity_ppm` is below this. Setting it implies `require`.
    public var minFidelityPpm: Double?
    /// Deny when the claimed `residual_risk_ppm` is above this. Setting it implies `require`.
    public var maxResidualRiskPpm: Double?
    /// Goal binding v3: the digests of the Goal IR the principal signed and of the policy compiled from it. When set, the root
    /// grant's goal commitment must open to exactly that pair (a v1/v2 grant does not) and the policy is active. Both digests must be
    /// canonical base64url (32 bytes), else the `intent` check fails closed.
    public var approvedGoal: ApprovedGoalRef?
    /// `fromJSON` saw an `approved_goal` that is not a closed `{goal_digest, policy_digest}` string object: a misconfiguration.
    var approvedGoalBad: Bool = false

    public init(require: Bool = false, minFidelityPpm: Double? = nil, maxResidualRiskPpm: Double? = nil, approvedGoal: ApprovedGoalRef? = nil) {
        self.require = require
        self.minFidelityPpm = minFidelityPpm
        self.maxResidualRiskPpm = maxResidualRiskPpm
        self.approvedGoal = approvedGoal
    }

    /// True iff the policy is active.
    public var isActive: Bool { require || minFidelityPpm != nil || maxResidualRiskPpm != nil || approvedGoal != nil || approvedGoalBad }

    /// Lenient construction from a JSON object `{require?, min_fidelity_ppm?, max_residual_risk_ppm?}`: a threshold
    /// keeps its NUMERIC VALUE whatever its lexical form (`950000.0`, `1e6` are valid integers; `-0` is -0.0), so the
    /// check accepts exactly the non-negative safe integers and fails closed on anything else (negative, fractional,
    /// -0, > 2^53-1). A present non-numeric threshold (null, bool, string, ...) becomes NaN (misconfigured). nil when
    /// `v` is not an object.
    public static func fromJSON(_ v: JSONValue) -> IntentPolicy? {
        guard let o = v.asObject else { return nil }
        func num(_ k: String) -> Double? {
            guard let x = o[JKey(k)] else { return nil }
            switch x {
            case let .int(i): return Double(i)
            case let .double(d): return d
            default: return .nan
            }
        }
        var require = false
        if case .bool(true) = o["require"] { require = true }
        var p = IntentPolicy(require: require, minFidelityPpm: num("min_fidelity_ppm"), maxResidualRiskPpm: num("max_residual_risk_ppm"))
        if let x = o["approved_goal"] {
            // closed object: exactly goal_digest and policy_digest, both strings; anything else is a misconfiguration
            if case let .object(ag) = x, ag.count == 2, case let .string(g)? = ag["goal_digest"], case let .string(d)? = ag["policy_digest"] {
                p.approvedGoal = ApprovedGoalRef(goalDigest: g, policyDigest: d)
            } else {
                p.approvedGoalBad = true
            }
        }
        return p
    }

    /// Parse raw policy JSON text with the lenient loader (any JSON number form) and apply `fromJSON`. nil when the
    /// text does not parse or is not an object.
    public static func fromJSONText(_ text: String) -> IntentPolicy? {
        guard let v = try? StrictJSON.parseLenient(text) else { return nil }
        return fromJSON(v)
    }
}

/// The closed object `{goal_digest, policy_digest}` of goal binding v3 (both canonical base64url, 32 bytes).
public struct ApprovedGoalRef: Equatable, Sendable {
    public var goalDigest: String
    public var policyDigest: String
    public init(goalDigest: String, policyDigest: String) {
        self.goalDigest = goalDigest
        self.policyDigest = policyDigest
    }
    /// Both digests canonical base64url, exactly 32 bytes.
    public var isValid: Bool { Base64URLStrict.isValid(goalDigest, length: 32) && Base64URLStrict.isValid(policyDigest, length: 32) }
}

enum Intent {
    static let GOAL_PREFIX = "pca-intent:v1:"
    static let GOAL_V3_PREFIX = "pca-intent:v3:"
    static let GOAL_COMMIT_DOMAIN = "atlas-pca/goal/v1\u{0}"
    static let PPM_ONE: Int64 = 1_000_000
    static let MAX_GOAL_SALT_LEN = 128
    /// Closed (all-required) member set of `envelope.intent`.
    static let FIELDS = ["ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm"]

    /// base64url(sha256(strictCanonical({d, goal: "pca-intent:v1:" + ref + ":" + mapDigest, salt}))); nil when the
    /// strings are not strict-canonical-encodable.
    static func goalCommit(ref: String, mapDigest: String, goalSalt: String, session: String? = nil, mapForm: String? = nil) -> String? {
        // Intent Layer v2 (rule 13 amends step 2): with a wire-valid `intent_session` the goal is
        // "pca-intent:v2:" + session + ":" + map_digest (the ref is then bound through the session root).
        // rule 19: over a committed map the goal is "pca-intent:v2c:" + session + ":" + map_digest
        let v2 = mapForm == IntentMap.FORM_COMMIT ? IntentSession.GOAL_V2C_PREFIX : IntentSession.GOAL_V2_PREFIX
        let goal = session.map { v2 + $0 + ":" + mapDigest } ?? (GOAL_PREFIX + ref + ":" + mapDigest)
        let v: JSONValue = .object([
            "d": .string(GOAL_COMMIT_DOMAIN),
            "goal": .string(goal),
            "salt": .string(goalSalt),
        ])
        guard let bytes = try? Canonical.canonicalBytes(v) else { return nil }
        return Base64URLStrict.encode(Canonical.sha256(bytes))
    }

    /// The v3 goal string `pca-intent:v3:<goal_digest>:<policy_digest>`; nil for a malformed digest (never commit to garbage).
    static func goalV3(_ ref: ApprovedGoalRef) -> String? {
        ref.isValid ? GOAL_V3_PREFIX + ref.goalDigest + ":" + ref.policyDigest : nil
    }

    /// base64url(sha256(strictCanonical({d, goal: goalV3(ref), salt}))); nil for a malformed digest.
    static func goalCommitV3(_ ref: ApprovedGoalRef, goalSalt: String) -> String? {
        guard let goal = goalV3(ref) else { return nil }
        let v: JSONValue = .object(["d": .string(GOAL_COMMIT_DOMAIN), "goal": .string(goal), "salt": .string(goalSalt)])
        guard let bytes = try? Canonical.canonicalBytes(v) else { return nil }
        return Base64URLStrict.encode(Canonical.sha256(bytes))
    }

    /// Wire validation of a present `intent` slot: nil when well-formed, else the wire reason.
    static func validateWire(_ v: JSONValue) -> String? {
        guard let o = v.asObject else { return "'intent' must be an object" }
        for k in o.keys where !FIELDS.contains(where: { JKey($0) == k }) { return "unknown field 'intent.\(k.s)'" }
        for k in FIELDS where o[JKey(k)] == nil { return "missing field 'intent.\(k)'" }
        if !(o["ref"]?.asString.map { Base64URLStrict.isValid($0, length: 32) } ?? false) {
            return "'intent.ref' is not canonical base64url (32 bytes)"
        }
        if !(o["map_digest"]?.asString.map { Base64URLStrict.isValid($0, length: 32) } ?? false) {
            return "'intent.map_digest' is not canonical base64url (32 bytes)"
        }
        guard let salt = o["goal_salt"]?.asString, !salt.isEmpty, salt.utf8.count <= MAX_GOAL_SALT_LEN else {
            return "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)"
        }
        guard let f = o["fidelity_ppm"]?.safeInt, f >= 0, f <= PPM_ONE else {
            return "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]"
        }
        guard let r = o["residual_risk_ppm"]?.safeInt, r >= 0 else {
            return "'intent.residual_risk_ppm' must be a non-negative safe integer"
        }
        return nil
    }

    /// The FIRST `envelope` caveat of the verifier's root grant: its string `goal_commit`.
    static func rootGoalCommit(_ grant: JSONValue) -> String? {
        guard let cav = grant.get("caveats")?.asArray,
              let env = cav.first(where: { $0.get("type")?.asString == "envelope" }) else { return nil } // non-objects have no `type`
        return env.get("goal_commit")?.asString
    }

    static func okThreshold(_ x: Double?) -> Bool {
        guard let d = x else { return true }
        // NaN fails rounded() == d, -Inf / -0 / negatives fail the sign test, +Inf fails the upper bound
        return d.rounded() == d && d.sign == .plus && d <= Double(Canonical.MAX_SAFE)
    }

    /// The `intent` check (rules 0-4) on a wire-valid PCActn. nil = not reported. Never traps.
    /// `session`: the PCActn's wire-valid `intent_session.session` (Intent Layer v2), which selects the v2 goal.
    static func decide(_ intent: JSONValue?, grant: JSONValue, policy: IntentPolicy?, session: String? = nil, mapForm: String? = nil) -> (ok: Bool, why: String)? {
        let active = policy?.isActive ?? false
        if intent == nil && !active { return nil }
        // an inactive policy has no thresholds, so this only bites when active
        if let pol = policy, !okThreshold(pol.minFidelityPpm) || !okThreshold(pol.maxResidualRiskPpm) {
            return (false, "intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)")
        }
        if active, let pol = policy, pol.approvedGoalBad || !(pol.approvedGoal?.isValid ?? true) {
            return (false, "intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)")
        }
        guard let i = intent else { return (false, "this verifier requires an intent binding but the PCActn carries none") }
        guard let commit = rootGoalCommit(grant) else {
            return (false, "the root grant carries no envelope goal commitment to bind the intent to")
        }
        if let ag = policy?.approvedGoal {
            guard let w = goalCommitV3(ag, goalSalt: i.get("goal_salt")?.asString ?? ""), w.unicodeScalars.elementsEqual(commit.unicodeScalars) else {
                return (false, "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)")
            }
            return floors(i, policy)
        }
        let want = goalCommit(ref: i.get("ref")?.asString ?? "", mapDigest: i.get("map_digest")?.asString ?? "",
                              goalSalt: i.get("goal_salt")?.asString ?? "", session: session, mapForm: mapForm)
        guard let w = want, w.unicodeScalars.elementsEqual(commit.unicodeScalars) else {
            return (false, "intent ref / map_digest / goal_salt do not open the root grant's goal commitment")
        }
        return floors(i, policy)
    }

    /// The fidelity / residual-risk floors, after the goal commitment opened.
    static func floors(_ i: JSONValue, _ policy: IntentPolicy?) -> (ok: Bool, why: String) {
        let fid = i.get("fidelity_ppm")?.safeInt ?? -1
        let res = i.get("residual_risk_ppm")?.safeInt ?? Int64.max
        if let lo = policy?.minFidelityPpm, Double(fid) < lo {
            return (false, "intent fidelity \(fid) ppm is below the policy minimum \(Int64(lo))")
        }
        if let hi = policy?.maxResidualRiskPpm, Double(res) > hi {
            return (false, "intent residual risk \(res) ppm exceeds the policy maximum \(Int64(hi))")
        }
        return (true, "")
    }
}

extension PCA {
    /// The goal commitment a root grant minted for this IntentStatement and Intent Map carries (Intent Layer M2):
    /// `base64url(sha256(strictCanonical({d: "atlas-pca/goal/v1\0", goal: "pca-intent:v1:" + ref + ":" + mapDigest, salt})))`.
    public static func intentGoalCommit(ref: String, mapDigest: String, goalSalt: String) -> String? {
        Intent.goalCommit(ref: ref, mapDigest: mapDigest, goalSalt: goalSalt)
    }

    /// The v3 goal string `pca-intent:v3:<goal_digest>:<policy_digest>` (what a minting wallet commits to); nil when a digest is not
    /// canonical base64url (32 bytes).
    public static func intentGoalV3(_ ref: ApprovedGoalRef) -> String? { Intent.goalV3(ref) }

    /// The v3 goal commitment for a salt (`intentGoalCommit`'s hash over the v3 goal); nil when a digest is malformed.
    public static func intentGoalCommitV3(_ ref: ApprovedGoalRef, goalSalt: String) -> String? { Intent.goalCommitV3(ref, goalSalt: goalSalt) }
}
