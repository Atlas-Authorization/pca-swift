import Foundation

/// One-time-use guard for a signature-verified PCActn (the guard behind `guardPCActnReplay`): the nonce is consumed once under a key that binds the
/// audience, the grant and the leaf holder; optionally the (audience, grant, leaf holder) counter stream is advanced after it. Run it only AFTER the
/// PCActn verified, last of the authorization checks. Never throws: a store failure is a denial. Check order follows the formally verified replay
/// decision (no store call before every pre-check passed).
public enum PCAReplayGuard {
    /// The shortest time a consumed nonce must be retained after it was consumed: the longest action lifetime plus the clock-skew allowance in both
    /// directions. A pruning horizon below this can free a still-valid nonce.
    public static let REPLAY_MIN_RETENTION_MS: Int64 = PCA.MAX_LIFETIME_MS + 2 * PCA.MAX_SKEW_MS

    /// The guard's options. Defaults: skew `PCA.MAX_SKEW_MS` (also the ceiling), a nonce required, no counter stream.
    public struct Options {
        /// Clock skew tolerated in both directions (ms); a negative or non-finite value means the default, a larger one the ceiling.
        public var clockSkewMs: Double?
        /// When true (default) a PCActn without a `nonce` is refused; when false the counter alone guards it.
        public var requireNonce: Bool
        /// When true the (aud, grant, leaf holder) counter stream is advanced through `store.claim` after the nonce.
        public var counters: Bool
        public init(clockSkewMs: Double? = nil, requireNonce: Bool = true, counters: Bool = false) {
            self.clockSkewMs = clockSkewMs
            self.requireNonce = requireNonce
            self.counters = counters
        }
    }

    /// `ok`, else a denial `code` (malformed, audience, not_yet_valid, expired, replay, store_unavailable) and a `reason`.
    public struct Verdict: Equatable, Sendable {
        public let ok: Bool
        public let code: String?
        public let reason: String?
        static func deny(_ code: String, _ reason: String) -> Verdict { Verdict(ok: false, code: code, reason: reason) }
    }

    private static func wellFormed(_ s: String) -> Bool { !s.isEmpty && !IV.hasSentinel(.string(s)) && s.utf8.count <= 512 }

    public static func guardReplay(store: PCAStateStore, pcactn p: JSONValue?, aud: String?, now: Int64, options: Options = Options()) -> Verdict {
        let safe = Double(Canonical.MAX_SAFE)
        var skew = Swift.min(options.clockSkewMs.flatMap { $0.isFinite && $0 >= 0 ? $0 : nil } ?? Double(PCA.MAX_SKEW_MS), Double(PCA.MAX_SKEW_MS))
        if skew.isNaN { skew = Double(PCA.MAX_SKEW_MS) }
        let skewFloor = Int64(skew.rounded(.down)), skewCeil = Int64(skew.rounded(.up))
        let objectOk = p?.isObject == true
        let leaf = p?.get("cap_chain")?.asArray?.last
        let holder = leaf?.get("holder")?.asString
        let grantRef = p?.get("grant_ref")?.asString
        let leafOk = leaf?.isObject == true && holder != nil && grantRef != nil
        let componentsOk = leafOk && wellFormed(grantRef!) && wellFormed(holder!)
        let nonceV = p?.get("nonce")
        let nonce = nonceV?.asString
        let nonceOk = nonce.map { !$0.isEmpty && $0.utf8.count <= 128 && !IV.hasSentinel(.string($0)) } ?? false

        let nowOk = Double(now) >= -safe && Double(now) <= safe
        let verifierAudOk = aud.map { !$0.isEmpty && $0.utf8.count <= 256 && !IV.hasSentinel(.string($0)) } ?? false
        let audMatches = p?.get("aud")?.asString.map { IV.same($0, aud) } ?? false
        func nonNeg(_ v: JSONValue?) -> Int64? { IV.nonNeg(v) }
        let iat = nonNeg(p?.get("iat")), exp = nonNeg(p?.get("exp"))
        let windowOk = iat != nil && exp != nil && exp! > iat! && exp! - iat! <= PCA.MAX_LIFETIME_MS

        if !nowOk || !verifierAudOk || !objectOk { return .deny("malformed", !nowOk ? "verifier clock is not an integer epoch-ms" : !verifierAudOk ? "verifier audience is invalid" : "not a PCActn") }
        guard let a = aud, let pcactn = p else { return .deny("malformed", "not a PCActn") }
        if !audMatches { return .deny("audience", "the PCActn is for another audience") }
        if !windowOk { return .deny("malformed", "iat / exp are not a valid bounded window") }
        guard let iatV = iat, let expV = exp else { return .deny("malformed", "iat / exp are not a valid bounded window") }
        if iatV > now &+ skewFloor { return .deny("not_yet_valid", "iat is in the future beyond the clock-skew allowance") }
        if now > expV { return .deny("expired", "the PCActn has expired") }
        if !leafOk { return .deny("malformed", "no leaf holder / grant") }
        if !componentsOk { return .deny("malformed", "grant / holder is not a bounded string") }
        guard let counter = nonNeg(pcactn.get("counter")) else { return .deny("malformed", "counter is not a non-negative safe integer") }
        if expV + skewCeil > Canonical.MAX_SAFE { return .deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)") }
        let retainUntil = expV + skewCeil
        if nonceV != nil ? !nonceOk : options.requireNonce { return .deny("malformed", nonceV != nil ? "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" : "a nonce is required") }
        do {
            if let n = nonce, try !store.consumeOnce(key: PCAConnect.replayKey("pca-nonce/v1", [a, grantRef!, holder!, n]), retainUntil: retainUntil, now: now) {
                return .deny("replay", "nonce already consumed")
            }
            if options.counters, try !store.claim(key: PCAConnect.replayKey("pca-counter/v1", [a, grantRef!, holder!]), counter: counter).ok {
                return .deny("replay", "counter is not greater than the last accepted")
            }
        } catch {
            return .deny("store_unavailable", "replay store failed closed: \(error)")
        }
        return Verdict(ok: true, code: nil, reason: nil)
    }
}
