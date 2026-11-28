import Foundation

extension PCA {
    /// True only if the result allowed exactly this operation: same verb and resource, and `operation.params` hashes (strict canonical) to the
    /// bound digest. Call it where the side effect runs, with the values it is about to use. Anything odd (no bound operation, an empty
    /// verb or resource, params that are not an object or not canonicalizable) is false.
    public static func isAuthorizedFor(allow: Bool, bound: AuthorizedOperation?, operation: Operation) -> Bool {
        guard allow, let b = bound, operation.isValid, let d = IV.strictHash(operation.params) else { return false }
        return IV.same(b.verb, operation.verb) && IV.same(b.resource, operation.resource) && IV.same(b.paramsDigest, d)
    }

    public static func isAuthorizedFor(_ result: AuthorizeResult, _ operation: Operation) -> Bool {
        isAuthorizedFor(allow: result.allow, bound: result.operation, operation: operation)
    }
}
