import Foundation

/// TypeScript export names of the small adapter packages that this SDK carries under another name, so an import by the TypeScript name resolves.
///
/// The TypeScript error classes (`DpopVerificationError`, `OidcVerificationError`, ...) are thrown here as `JSError` with the same stable `code`; the
/// aliases name that type, and `catch let e as DpopVerificationError` matches exactly those errors (check `e.code`).
public typealias DpopVerificationError = JSError
public typealias OidcDiscoveryError = JSError
public typealias OidcVerificationError = JSError
public typealias IdJagVerificationError = JSError
public typealias GnapError = JSError
public typealias TxnTokenError = JSError
public typealias TraceRuleError = JSError
public typealias Ap2Error = JSError
public typealias AccumulatorError = JSError
public typealias ChargeStoreError = JSError
public typealias MandateGrantError = JSError
public typealias CibaProviderError = JSError
public typealias ApprovalStoreError = JSError

extension PCAPqThreshold {
    /// The algorithm label of the post-quantum quorum of a hybrid step-up artifact (the reference's `HYBRID_PQ_ALG`).
    public static let HYBRID_PQ_ALG = PQ_QUORUM_ALG
    /// The group suite a FROST group descriptor pins (the reference's `GROUP_SUITE`).
    public static let GROUP_SUITE = PCAGroupDescriptor.SUITE
}

extension PCAWallet {
    /// The friction thresholds applied when none are given: tap above harm 5, device above harm 100000 (the reference's `DEFAULT_FRICTION_THRESHOLDS`).
    public static let DEFAULT_FRICTION_THRESHOLDS: JSONValue = .object(["hTap": .int(5), "hDevice": .int(100_000)])
}

extension PCACiba {
    /// A fresh `client_notification_token` (CIBA Core 7.1: at least 128 bits of entropy, at most 1024 characters): 32 random bytes, base64url.
    public static func newClientNotificationToken() -> String {
        var g = SystemRandomNumberGenerator()
        return Base64URLStrict.encode((0..<32).map { _ in UInt8.random(in: 0...255, using: &g) })
    }
}
