import AtlasPCAVerify

/// TypeScript export names of `pca-abe` that this SDK carries under another name.
public typealias PcaEncryptionError = JSError

extension Abe {
    /// The deepest gate nesting an encryptable policy may have (the reference's `MAX_POLICY_DEPTH`).
    public static let MAX_POLICY_DEPTH = AbePolicy.maxDepth
    /// The most nodes an encryptable policy may have (the reference's `MAX_POLICY_NODES`).
    public static let MAX_POLICY_NODES = AbePolicy.maxNodes
}
