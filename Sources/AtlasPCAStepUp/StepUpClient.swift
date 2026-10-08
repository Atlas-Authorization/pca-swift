import Foundation

/// Lists, approves and denies PCA step-ups from the principal's phone.
///
/// Two endpoints are involved:
///  - `dashboardURL` + a dashboard bearer token (a `dsk_` service key or a console session
///    token) for `GET/POST .../pca/stepups` (list, deny). Deny requires an owner/admin role.
///  - `instanceURL` (the Atlas instance host the agent talks to) for the public, self-
///    authenticating `POST /v1/pca/stepups/:id/cosign`; no token is needed — the device
///    signature is the credential.
public struct StepUpClient: Sendable {
    public let dashboardURL: URL
    public let instanceURL: URL
    public let accountId: String
    public let instanceId: String
    public let key: PrincipalDeviceKey
    private let token: @Sendable () async throws -> String
    private let session: URLSession

    public init(dashboardURL: URL, instanceURL: URL, accountId: String, instanceId: String,
                token: @escaping @Sendable () async throws -> String,
                key: PrincipalDeviceKey = PrincipalDeviceKey(),
                session: URLSession = .shared) {
        self.dashboardURL = dashboardURL; self.instanceURL = instanceURL
        self.accountId = accountId; self.instanceId = instanceId
        self.token = token; self.key = key; self.session = session
    }

    private var stepupsPath: String { "v1/dashboard/accounts/\(accountId)/instances/\(instanceId)/pca/stepups" }

    /// Pending step-ups awaiting this principal. Already-expired entries are filtered out.
    public func pending() async throws -> [PendingStepUp] {
        var comps = URLComponents(url: dashboardURL.appendingPathComponent(stepupsPath), resolvingAgainstBaseURL: false)!
        comps.queryItems = [URLQueryItem(name: "status", value: "pending")]
        var req = URLRequest(url: comps.url!)
        req.setValue("Bearer \(try await token())", forHTTPHeaderField: "Authorization")
        let (data, status) = try await send(req)
        try Self.check(status, data)
        guard let list = try? JSONDecoder().decode(WireList.self, from: data) else {
            throw StepUpError.transport("Unreadable step-up list.")
        }
        let now = Date()
        return list.stepups.compactMap { w in
            guard let exp = ISO8601.parse(w.expires_at), exp > now else { return nil }
            return PendingStepUp(id: w.id, grantRef: w.grant_ref, actionVerb: w.action.verb,
                                 actionResource: w.action.resource, requiredT: w.required_t,
                                 thresholdMessageB64u: w.threshold_message, expiresAt: exp)
        }
    }

    /// Sign the step-up's threshold message with the device key and submit it.
    /// Throws `.principalMismatch` (server 403) when this key is not the grant's principal.
    @discardableResult
    public func approve(_ stepUp: PendingStepUp) async throws -> ApproveResult {
        guard let message = Base64URL.decode(stepUp.thresholdMessageB64u) else { throw StepUpError.invalidThresholdMessage }
        let body: [String: String] = ["role": "principal", "publicKey": try key.publicKey(), "sig": try key.sign(message)]
        var req = URLRequest(url: instanceURL.appendingPathComponent("v1/pca/stepups/\(stepUp.id)/cosign"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, status) = try await send(req)
        try Self.check(status, data)
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        // 200 + allow:true = anchored; 202 = more roles still required.
        return ApproveResult(status: json?["status"] as? String ?? "", anchored: (json?["allow"] as? Bool) ?? false, httpStatus: status)
    }

    /// Deny a pending step-up (dashboard endpoint; audited; owner/admin).
    public func deny(_ stepUp: PendingStepUp, reason: String? = nil) async throws {
        var req = URLRequest(url: dashboardURL.appendingPathComponent("\(stepupsPath)/\(stepUp.id)/deny"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(try await token())", forHTTPHeaderField: "Authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: reason.map { ["reason": $0] } ?? [String: String]())
        let (data, status) = try await send(req)
        try Self.check(status, data)
    }

    // MARK: transport

    private func send(_ req: URLRequest) async throws -> (Data, Int) {
        do {
            let (data, resp) = try await session.data(for: req)
            return (data, (resp as? HTTPURLResponse)?.statusCode ?? 0)
        } catch {
            throw StepUpError.transport(error.localizedDescription)
        }
    }

    static func check(_ status: Int, _ data: Data) throws {
        guard !(200..<300).contains(status) else { return }
        // §9.1 envelope: { errors: [{ code, message }] }
        var message = "The request failed."
        if let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           let first = (obj["errors"] as? [[String: Any]])?.first, let m = first["message"] as? String {
            message = m
        }
        if status == 403 { throw StepUpError.principalMismatch(message) }
        throw StepUpError.api(status: status, message: message)
    }
}
