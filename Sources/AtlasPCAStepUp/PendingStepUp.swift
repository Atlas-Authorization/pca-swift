import Foundation

/// A t=3 action waiting for the principal's device signature.
public struct PendingStepUp: Equatable, Sendable, Identifiable {
    public let id: String
    public let grantRef: String
    public let actionVerb: String
    public let actionResource: String
    public let requiredT: Int
    /// base64url of the exact bytes the principal key must sign.
    public let thresholdMessageB64u: String
    public let expiresAt: Date

    public init(id: String, grantRef: String, actionVerb: String, actionResource: String,
                requiredT: Int, thresholdMessageB64u: String, expiresAt: Date) {
        self.id = id; self.grantRef = grantRef; self.actionVerb = actionVerb
        self.actionResource = actionResource; self.requiredT = requiredT
        self.thresholdMessageB64u = thresholdMessageB64u; self.expiresAt = expiresAt
    }

    /// Human summary for a confirmation sheet, e.g. "payments.refund on order/1234".
    public var summary: String { "\(actionVerb) on \(actionResource)" }
}

/// Result of an approval. `anchored` is true once enough roles signed and the action was released.
public struct ApproveResult: Sendable, Equatable {
    public let status: String
    public let anchored: Bool
    public let httpStatus: Int
}

// Wire shape of GET .../pca/stepups (snake_case, per apps/api/src/routes/dashboard-pca.ts).
struct WireStepUp: Decodable {
    struct Action: Decodable { let verb: String; let resource: String }
    let id: String
    let grant_ref: String
    let action: Action
    let required_t: Int
    let threshold_message: String
    let expires_at: String
    let status: String?
}
struct WireList: Decodable { let stepups: [WireStepUp] }

enum ISO8601 {
    static func parse(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }
}
