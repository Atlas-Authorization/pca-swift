import Foundation

/// The decision-to-effect binding and the claimed-fidelity gate of goal-to-decision.
public enum PCAGoalBinding {
    /// Digest of exactly the action that was decided: verb, resource and every parameter.
    public static func actionDigest(_ act: JSONValue) throws -> String {
        return try PCAGoalDigests.hashCanonical(GV.obj([("d", JSONValue.string("atlas-pca/goal-action/v1")), ("act", act)]))
    }

    /// Bind a decision to the action it was made for: {decision, action_digest}.
    public static func bindDecision(_ act: JSONValue, _ decision: String) throws -> JSONValue {
        return GV.obj([("decision", JSONValue.string(decision)), ("action_digest", JSONValue.string(try actionDigest(act)))])
    }

    /// Constant-time equality of the UTF-8 bytes (different lengths are unequal).
    private static func ctEq(_ x: String, _ y: String) -> Bool {
        let a = Array(x.utf8)
        let b = Array(y.utf8)
        if a.count != b.count { return false }
        var d: UInt8 = 0
        for i in 0..<a.count { d |= a[i] ^ b[i] }
        return d == 0
    }

    /// Run guard: true only for an `allow` bound to exactly this action. Total.
    public static func guardExecute(_ bound: JSONValue, _ executed: JSONValue) -> Bool {
        guard let dec = GV.get(bound, "decision")?.asString, IV.same(dec, "allow") else { return false }
        guard let d = GV.get(bound, "action_digest")?.asString else { return false }
        guard let want = try? actionDigest(executed) else { return false }
        return ctEq(d, want)
    }

    /// An agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, and only downward.
    /// `replayedPpm` nil = not replayed; a NaN replay is unconfirmed and tightens.
    public static func claimGate(_ base: String, _ minPpm: Double, _ replayedPpm: Double?) -> String {
        if let r = replayedPpm, !(r >= minPpm) { return PCA.tightenDecision(base, signal: JSONValue.string("escalate")) }
        return base
    }

    /// Hiding goal commitment (goal binding v3).
    public static func goalCommit(_ goalDigest: String, _ policyDigest: String, _ salt: String) -> String {
        let h = Canonical.sha256(Canonical.utf8("pca-goal:v3:commit:" + goalDigest + ":" + policyDigest + ":" + salt))
        return Base64URLStrict.encode(h)
    }

    /// Constant-time check that `commit` opens to (goal, policy, salt).
    public static func openCommit(_ commit: String, _ goalDigest: String, _ policyDigest: String, _ salt: String) -> Bool {
        return ctEq(commit, goalCommit(goalDigest, policyDigest, salt))
    }
}
