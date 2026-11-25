import Foundation

/// The content digests of the goal-to-decision flow (strict canonical JSON: safe integers only; a float or lone surrogate throws).
public enum PCAGoalDigests {
    /// base64url(sha256(strictCanonical(v))); throws where the strict canonical form refuses the value.
    static func hashCanonical(_ v: JSONValue) throws -> String {
        guard let h = IV.strictHash(v) else { throw JSError("hashCanonical: " + (IV.strictCanonError(v) ?? "outside the strict JSON profile")) }
        return h
    }

    /// Digest of the whole signed Goal.
    public static func goalDigest(_ goal: JSONValue) throws -> String {
        return try hashCanonical(GV.obj([("d", JSONValue.string("atlas-pca/goal-ir/v1")), ("goal", goal)]))
    }

    /// Digest of the instruction text a goal was interpreted from.
    public static func nlDigest(_ instruction: String) throws -> String {
        return try hashCanonical(GV.obj([("d", JSONValue.string("atlas-pca/goal-nl/v1")), ("text", JSONValue.string(instruction))]))
    }

    /// Digest of the model set: sorted (code-unit order), de-duplicated ids.
    public static func modelSetDigest(_ models: [String]) throws -> String {
        var seen = Set<JKey>()
        var ids: [String] = []
        for m in models where seen.insert(JKey(m)).inserted { ids.append(m) }
        ids.sort(by: { GV.less($0, $1) })
        return try hashCanonical(GV.obj([("d", JSONValue.string("atlas-pca/goal-model-set/v1")), ("models", JSONValue.array(ids.map { JSONValue.string($0) }))]))
    }

    /// Digest of an approval's covered fields (the digests it pins plus its expiry).
    public static func approvalDigest(_ body: JSONValue) throws -> String {
        return try hashCanonical(GV.obj([("d", JSONValue.string("atlas-pca/goal-approval-body/v1")), ("body", body)]))
    }
}
