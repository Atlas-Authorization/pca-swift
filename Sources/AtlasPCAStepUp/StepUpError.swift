import Foundation

/// Everything the step-up module can throw.
public enum StepUpError: Error, Equatable, Sendable {
    /// No principal key is stored yet; call `PrincipalDeviceKey.generate/importSecret` first.
    case noDeviceKey
    /// The principal secret is not 32 raw bytes of base64url.
    case invalidSecret
    /// The server's `threshold_message` is not valid base64url.
    case invalidThresholdMessage
    /// 403: this device key is not the grant's principal key. The message is the server's guidance.
    case principalMismatch(String)
    /// Any other non-2xx answer (409 already approved/denied/expired, 401, 404, 422 ...).
    case api(status: Int, message: String)
    /// Network / URLSession failure or an unreadable body.
    case transport(String)
    /// The secure store (Keychain / Keystore) failed; payload is the OS status or reason.
    case storage(String)
}

extension StepUpError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noDeviceKey: return "No principal device key is stored on this device."
        case .invalidSecret: return "The principal secret must be a base64url-encoded 32-byte Ed25519 seed."
        case .invalidThresholdMessage: return "The step-up's threshold message is not valid base64url."
        case let .principalMismatch(m): return m
        case let .api(status, m): return "HTTP \(status): \(m)"
        case let .transport(m): return m
        case let .storage(m): return "Secure storage error: \(m)"
        }
    }
}
