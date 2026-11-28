import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A network client for a real OpenID Provider's CIBA endpoints (OpenID CIBA Core 1.0): start a backchannel authentication request and wait for the human's
/// decision by POLL or PING. It is the relying-party side that the in-memory broker models.
///
/// Poll discipline follows CIBA Core 7.3 / 11: the client never polls faster than the `interval` the OP returned, adds at least 5 seconds to it on every
/// `slow_down`, and stops at `expires_in`. A terminal answer (approved / denied / expired) is cached, so a settled flow is never re-sent to the token endpoint
/// (an approved `auth_req_id` is single-use at real providers). The client authenticates with `client_secret_basic`. The returned tokens are the OP's
/// response, not verified here: a caller that relies on the ID token must verify it with its own JOSE library.
extension PCACiba {
    static let CIBA_GRANT = "urn:openid:params:grant-type:ciba"
    /// CIBA Core 11: on `slow_down` the interval grows by at least 5 seconds.
    static let SLOW_DOWN_STEP_SEC = 5.0
    static let MIN_NOTIFICATION_TOKEN_CHARS = 22
    static let MAX_NOTIFICATION_TOKEN_CHARS = 1024
    static let DEFAULT_TIMEOUT_MS = 30_000.0
    static let MAX_BACKOFF_MS = 60_000.0
    static let MAX_CONSECUTIVE_TRANSIENT = 5

    /// An error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply. `retryable` is true for failures worth retrying (network error,
    /// timeout, 5xx, non-JSON reply), not for a definitive OP answer.
    public struct ProviderError: Error, CustomStringConvertible {
        public let status: Int
        public let error: String
        public let errorDescription: String?
        public let retryable: Bool
        public var description: String { "ciba: provider returned \(status) \(error)" + (errorDescription.map { " (\($0))" } ?? "") }
        init(_ status: Int, _ error: String, _ errorDescription: String? = nil, retryable: Bool = false) {
            self.status = status; self.error = error; self.errorDescription = errorDescription; self.retryable = retryable
        }
    }

    /// The transport: POST a form body with the given headers, answer the status and the response text. A throw is a network failure.
    public typealias ClientFetch = (_ url: String, _ headers: [String: String], _ body: String, _ timeoutMs: Double) throws -> (status: Int, body: String)

    public struct ClientConfig {
        public var backchannelAuthenticationEndpoint: String
        public var tokenEndpoint: String
        public var clientId: String
        public var clientSecret: String
        /// Injectable for tests. Default a blocking POST over URLSession.
        public var fetch: ClientFetch?
        /// Injectable for tests (ms). Default a wait that `notify()` and an abort end early.
        public var sleep: ((Double) -> Void)?
        /// Clock in ms. Default the wall clock.
        public var now: (() -> Double)?
        /// Per-request timeout in ms for every call to the OP. Default 30000.
        public var timeoutMs: Double?
        /// Permit `http://` endpoints (the client secret and the `auth_req_id` travel on these requests: local test providers only).
        public var allowInsecureHttp: Bool
        public init(backchannelAuthenticationEndpoint: String, tokenEndpoint: String, clientId: String, clientSecret: String, fetch: ClientFetch? = nil,
                    sleep: ((Double) -> Void)? = nil, now: (() -> Double)? = nil, timeoutMs: Double? = nil, allowInsecureHttp: Bool = false) {
            self.backchannelAuthenticationEndpoint = backchannelAuthenticationEndpoint; self.tokenEndpoint = tokenEndpoint
            self.clientId = clientId; self.clientSecret = clientSecret; self.fetch = fetch; self.sleep = sleep; self.now = now
            self.timeoutMs = timeoutMs; self.allowInsecureHttp = allowInsecureHttp
        }
    }

    public struct InitiateOptions {
        /// Exactly one identifying hint is allowed (CIBA Core 7.1).
        public var loginHint: String?
        public var loginHintToken: String?
        public var idTokenHint: String?
        /// `ping` sends a `client_notification_token` (generated if not given); `poll` (default) sends none.
        public var delivery: String?
        public var clientNotificationToken: String?
        public var acrValues: String?
        public var userCode: String?
        /// The remaining `toCibaAuthRequest` options (`expiresInSec`, `authReqId`, `bindingMessage`, `interval`, `actsFor`, ...).
        public var request: JObject
        public init(loginHint: String? = nil, loginHintToken: String? = nil, idTokenHint: String? = nil, delivery: String? = nil, clientNotificationToken: String? = nil,
                    acrValues: String? = nil, userCode: String? = nil, request: JObject = [:]) {
            self.loginHint = loginHint; self.loginHintToken = loginHintToken; self.idTokenHint = idTokenHint; self.delivery = delivery
            self.clientNotificationToken = clientNotificationToken; self.acrValues = acrValues; self.userCode = userCode; self.request = request
        }
    }

    public struct Flow {
        /// The OP-issued `auth_req_id`.
        public let authReqId: String
        public let expiresInSec: Int64
        /// Interval the OP asked for, in seconds.
        public let intervalSec: Int64
        /// ms epoch the OP answered.
        public let startedAt: Double
        public let delivery: String
        public let clientNotificationToken: String?
        /// The request PCA derived (scope, binding message, ...) that was sent.
        public let request: JSONValue
    }

    public enum PollResult: Equatable {
        case pending(intervalSec: Double)
        case approved(tokens: JSONValue)
        case denied(error: String)
        case expired
    }

    /// A cancellation flag for `poll` / `wait`.
    public final class AbortSignal: @unchecked Sendable {
        private let lock = NSLock()
        private var flag = false
        public init() {}
        public var aborted: Bool { lock.lock(); defer { lock.unlock() }; return flag }
        public func abort() { lock.lock(); flag = true; lock.unlock() }
    }

    private static func formEncode(_ pairs: [(String, String)]) -> String {
        var ok = CharacterSet.alphanumerics.intersection(CharacterSet(charactersIn: Unicode.Scalar(0)..<Unicode.Scalar(128)))
        ok.insert(charactersIn: "*-._")
        func enc(_ s: String) -> String { (s.addingPercentEncoding(withAllowedCharacters: ok) ?? s).replacingOccurrences(of: "%20", with: "+") }
        return pairs.map { enc($0.0) + "=" + enc($0.1) }.joined(separator: "&")
    }

    private static func checkEndpoint(_ name: String, _ value: String, _ allowInsecure: Bool) throws {
        guard let u = WhatwgURL.parse(value) else { throw JSError("RangeError: ciba: \(name) is not a valid URL") }
        if u.scheme == "https" || (u.scheme == "http" && allowInsecure) { return }
        throw JSError("RangeError: ciba: \(name) must be an https:// URL (set allowInsecureHttp only for a local test provider)")
    }

    private final class Reply: @unchecked Sendable { var status = 0; var body = ""; var err: Error? }

    static func urlSessionFetch(_ url: String, _ headers: [String: String], _ body: String, _ timeoutMs: Double) throws -> (status: Int, body: String) {
        guard let u = URL(string: url) else { throw JSError("ciba: bad url") }
        var req = URLRequest(url: u, timeoutInterval: timeoutMs / 1000)
        req.httpMethod = "POST"
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = Data(body.utf8)
        let box = Reply(), sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { d, r, e in
            box.status = (r as? HTTPURLResponse)?.statusCode ?? 0
            box.body = d.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            box.err = e
            sem.signal()
        }.resume()
        sem.wait()
        if let e = box.err { throw e }
        return (box.status, box.body)
    }

    public final class Client {
        let cfg: ClientConfig
        let doFetch: ClientFetch
        let clock: () -> Double
        let timeoutMs: Double
        let basic: String

        init(_ cfg: ClientConfig) throws {
            self.cfg = cfg
            doFetch = cfg.fetch ?? PCACiba.urlSessionFetch
            clock = cfg.now ?? { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
            timeoutMs = cfg.timeoutMs ?? PCACiba.DEFAULT_TIMEOUT_MS
            guard timeoutMs.isFinite, timeoutMs > 0 else { throw JSError("RangeError: ciba: timeoutMs must be a positive number") }
            try PCACiba.checkEndpoint("backchannelAuthenticationEndpoint", cfg.backchannelAuthenticationEndpoint, cfg.allowInsecureHttp)
            try PCACiba.checkEndpoint("tokenEndpoint", cfg.tokenEndpoint, cfg.allowInsecureHttp)
            func uri(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()")) ?? s }
            basic = "Basic " + Data((uri(cfg.clientId) + ":" + uri(cfg.clientSecret)).utf8).base64EncodedString()
        }

        /// One request with a hard timeout (the transport's); a network failure is a retryable provider error.
        func post(_ url: String, _ form: [(String, String)]) throws -> (status: Int, body: String) {
            do {
                return try doFetch(url, ["authorization": basic, "content-type": "application/x-www-form-urlencoded", "accept": "application/json"], PCACiba.formEncode(form), timeoutMs)
            } catch {
                throw ProviderError(0, "network_error", "\(error)", retryable: true)
            }
        }

        static func readJson(_ r: (status: Int, body: String)) throws -> JObject {
            guard let parsed = try? StrictJSON.parseLenient(r.body) else { throw ProviderError(r.status, "invalid_response", "the provider reply was not JSON", retryable: true) }
            guard case let .object(o) = parsed else { throw ProviderError(r.status, "invalid_response", "the provider reply was not a JSON object") }
            return o
        }

        static func providerError(_ status: Int, _ body: JObject) -> ProviderError {
            ProviderError(status, body["error"]?.asString ?? "invalid_response", body["error_description"]?.asString)
        }

        static func positiveInt(_ v: JSONValue?, _ name: String, _ status: Int) throws -> Int64 {
            guard let d = IV.num(v), d.isFinite, d.rounded() == d, d > 0, d <= 9_007_199_254_740_991 else { throw ProviderError(status, "invalid_response", "\(name) must be a positive integer") }
            return Int64(d)
        }

        /// Start a backchannel authentication request for a step-up.
        public func initiate(_ stepUp: JSONValue, _ opts: InitiateOptions = InitiateOptions()) throws -> Flow {
            let hints = [opts.loginHint, opts.loginHintToken, opts.idTokenHint].compactMap { $0 }
            if hints.count != 1 { throw JSError("RangeError: ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)") }
            let delivery = opts.delivery ?? "poll"
            let notificationToken = delivery == "ping" ? (opts.clientNotificationToken ?? PCACiba.newClientNotificationToken()) : nil
            if let t = opts.clientNotificationToken {
                let n = t.utf16.count
                if n < PCACiba.MIN_NOTIFICATION_TOKEN_CHARS || n > PCACiba.MAX_NOTIFICATION_TOKEN_CHARS || !t.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value <= 0x7e }) {
                    throw JSError("RangeError: ciba: clientNotificationToken must be \(PCACiba.MIN_NOTIFICATION_TOKEN_CHARS)..\(PCACiba.MAX_NOTIFICATION_TOKEN_CHARS) printable characters (>= 128 bits, CIBA Core 7.1)")
                }
            }
            var ro = opts.request
            if let h = opts.loginHint { ro["loginHint"] = .string(h) }
            let request = try PCACiba.toCibaAuthRequest(stepUp, ro)
            var form: [(String, String)] = [("scope", JS.toString(request.get("scope"))), ("binding_message", JS.toString(request.get("binding_message"))),
                                            ("requested_expiry", JS.toString(request.get("requested_expiry")))]
            if let v = opts.loginHint { form.append(("login_hint", v)) }
            if let v = opts.loginHintToken { form.append(("login_hint_token", v)) }
            if let v = opts.idTokenHint { form.append(("id_token_hint", v)) }
            if let v = opts.acrValues { form.append(("acr_values", v)) }
            if let v = opts.userCode { form.append(("user_code", v)) }
            if let v = notificationToken { form.append(("client_notification_token", v)) }
            let res = try post(cfg.backchannelAuthenticationEndpoint, form)
            let body = try Client.readJson(res)
            if !(200..<300).contains(res.status) { throw Client.providerError(res.status, body) }
            guard let authReqId = body["auth_req_id"]?.asString, !authReqId.isEmpty else { throw ProviderError(res.status, "invalid_response", "auth_req_id missing") }
            let expires = try Client.positiveInt(body["expires_in"], "expires_in", res.status)
            // CIBA Core 7.3: `interval` is optional and defaults to 5 seconds.
            let interval: Int64
            if body["interval"] == nil { interval = 5 } else { interval = try Client.positiveInt(body["interval"], "interval", res.status) }
            return Flow(authReqId: authReqId, expiresInSec: expires, intervalSec: interval, startedAt: clock(), delivery: delivery, clientNotificationToken: notificationToken, request: request)
        }

        /// The poller of a started flow.
        public func poller(_ flow: Flow) -> Poller { Poller(self, flow) }
    }

    public final class Poller {
        private let client: Client
        private let flow: Flow
        private var intervalMs: Double
        private var nextAt: Double
        private let deadline: Double
        private var settled: PollResult?
        private var failures = 0
        private let stateLock = NSLock()
        private let pollLock = NSLock()
        private let wakeSem = DispatchSemaphore(value: 0)

        init(_ c: Client, _ f: Flow) {
            client = c; flow = f
            intervalMs = Double(f.intervalSec) * 1000
            nextAt = f.startedAt + intervalMs
            deadline = f.startedAt + Double(f.expiresInSec) * 1000
        }

        /// Current poll interval in seconds (grows on `slow_down`).
        public func intervalSec() -> Double { stateLock.lock(); defer { stateLock.unlock() }; return intervalMs / 1000 }

        /// A PING arrived: the next `poll()` may go out immediately, and a `poll()` / `wait()` that is sleeping wakes now.
        public func notify() {
            stateLock.lock(); nextAt = client.clock(); stateLock.unlock()
            wakeSem.signal()
        }

        private func pause(_ ms: Double, _ signal: AbortSignal?) throws {
            if let s = client.cfg.sleep { s(ms) } else {
                let end = client.clock() + ms
                while client.clock() < end, signal?.aborted != true {
                    // wake on notify(); re-check an abort at least every 50 ms
                    if wakeSem.wait(timeout: .now() + .milliseconds(Int(min(50, max(1, end - client.clock()).rounded(.up))))) == .success { break }
                }
            }
            if signal?.aborted == true { throw JSError("ciba: wait aborted") }
        }

        private func backoff() {
            failures += 1
            stateLock.lock(); defer { stateLock.unlock() }
            nextAt = client.clock() + min(PCACiba.MAX_BACKOFF_MS, intervalMs * pow(2, Double(min(failures, 6))))
        }

        private func settle(_ r: PollResult) -> PollResult { settled = r; return r }

        /// Sleep until the interval allows it, then ask the token endpoint once. Concurrent callers are serialised; a settled flow answers from its cache.
        public func poll(_ signal: AbortSignal? = nil) throws -> PollResult {
            pollLock.lock(); defer { pollLock.unlock() }
            if let s = settled { return s }
            if signal?.aborted == true { throw JSError("ciba: wait aborted") }
            stateLock.lock(); let wait = nextAt - client.clock(); stateLock.unlock()
            if wait > 0 { try pause(wait, signal) }
            if let s = settled { return s }
            if client.clock() >= deadline { return settle(.expired) }
            let res: (status: Int, body: String)
            let body: JObject
            do {
                res = try client.post(client.cfg.tokenEndpoint, [("grant_type", PCACiba.CIBA_GRANT), ("auth_req_id", flow.authReqId)])
                if res.status >= 500 { throw ProviderError(res.status, "server_error", "the provider answered with a server error", retryable: true) }
                body = try Client.readJson(res)
            } catch let e as ProviderError {
                if e.retryable { backoff() }
                throw e
            }
            failures = 0
            stateLock.lock(); nextAt = client.clock() + intervalMs; stateLock.unlock()
            if (200..<300).contains(res.status) {
                guard body["access_token"]?.asString != nil, body["token_type"]?.asString != nil else {
                    throw ProviderError(res.status, "invalid_response", "token response lacks access_token / token_type")
                }
                return settle(.approved(tokens: .object(body)))
            }
            let err = Client.providerError(res.status, body)
            switch err.error {
            case "authorization_pending":
                return .pending(intervalSec: intervalSec())
            case "slow_down":
                stateLock.lock(); intervalMs += PCACiba.SLOW_DOWN_STEP_SEC * 1000; nextAt = client.clock() + intervalMs; stateLock.unlock()
                return .pending(intervalSec: intervalSec())
            case "access_denied": return settle(.denied(error: err.error))
            case "expired_token": return settle(.expired)
            default: throw err
            }
        }

        /// Poll until the flow settles; honours `signal`. Up to 5 consecutive transient failures are retried.
        public func wait(_ signal: AbortSignal? = nil) throws -> PollResult {
            var transient = 0
            while true {
                if signal?.aborted == true { throw JSError("ciba: wait aborted") }
                do {
                    let r = try poll(signal)
                    transient = 0
                    if case .pending = r { continue }
                    return r
                } catch let e as ProviderError {
                    transient += 1
                    if !e.retryable || transient >= PCACiba.MAX_CONSECUTIVE_TRANSIENT { throw e }
                }
            }
        }
    }

    public static func createCibaClient(_ cfg: ClientConfig) throws -> Client { try Client(cfg) }
}
