import Foundation
import CryptoKit

/// Networked FROST(Ed25519) signing where every signer is a separate service: the policy authority's signed allow token, the signer's proof of possession of its share
/// (the rogue-key defence), an equivocation guard, the signer service (round 1 commits, round 2 signs only for a valid token over exactly the message) and the
/// coordinator that drives a signing session over injected transports. The wire objects are the JSON of the protocol.
public enum PCAFrostNet {
    public static let ALLOW_TOKEN_TYP = "pca.frost.allow.v1"
    public static let SIGNER_POP_DST = "pca.frost.signer-pop.v1"
    public static let MAX_FROST_SIGNING_SET = 256

    /// The source of the 32 random bytes a draw needs (the signer's PoP nonce, its hiding and binding nonce randomness, a session id, an allow-token nonce).
    public typealias RandomBytes = () throws -> [UInt8]
    public static let systemRandom: RandomBytes = { (0..<32).map { _ in UInt8.random(in: 0...255) } }

    static func text(_ e: Error) -> String { (e as? JSError)?.message ?? (e as? PCAProducerError)?.message ?? "\(e)" }
    private static func b64(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }
    /// An object of the members that are present (`JSON.stringify` drops an undefined one; an explicit null stays).
    static func present(_ pairs: [(String, JSONValue?)]) -> JSONValue {
        var o: JObject = [:]
        for (k, v) in pairs { if let v = v { o[JKey(k)] = v } }
        return .object(o)
    }
    private static func isObjOrArray(_ v: JSONValue?) -> Bool { v?.isObject == true || v?.asArray != nil }
    private static func safeInt(_ v: JSONValue?) -> Int64? {
        guard let d = IV.safe(v), d == d.rounded(), abs(d) <= 9_007_199_254_740_991 else { return nil }
        return Int64(d)
    }
    private static func posId(_ v: JSONValue?) -> Int64? { safeInt(v).flatMap { $0 > 0 ? $0 : nil } }

    /// `JSON.stringify`-like canonical bytes of an arbitrary JSON value (the lenient profile: fractions are fine, NaN and Infinity are refused).
    static func canonicalLenient(_ v: JSONValue) throws -> [UInt8] {
        func scan(_ x: JSONValue) throws {
            switch x {
            case let .double(d): if !d.isFinite { throw JSError("canonicalize: non-finite number") }
            case let .array(a): for e in a { try scan(e) }
            case let .object(o): for (_, e) in o { try scan(e) }
            default: break
            }
        }
        try scan(v)
        return Array(Canonical.canonicalize(v).utf8)
    }

    // ---- allow token ----

    /// base64url(sha256(message)).
    public static func frostActionDigest(_ message: [UInt8]) -> String { b64(Canonical.sha256(message)) }

    /// The policy authority's signed permission to sign one action with one group key. The digest comes from `frostActionDigest` when given (even when empty, which is
    /// refused), else from `message`. `nonce` defaults to a fresh random draw. Refused when there is neither a message nor a digest.
    public static func issueAllowToken(policySecret: [UInt8]?, message: [UInt8]?, frostActionDigest digestIn: String?, groupPublicKey: [UInt8]?, nonce: String?,
                                       notBefore: JSONValue?, expiresAt: JSONValue?, random: RandomBytes = systemRandom) throws -> JSONValue {
        let digest = digestIn ?? message.map { frostActionDigest($0) }
        guard let d = digest, !d.isEmpty else { throw JSError("issueAllowToken: provide message or frostActionDigest") }
        guard let gpk = groupPublicKey else { throw JSError("radix2.encode input should be Uint8Array") }
        let n = try nonce ?? b64(random())
        var body: JObject = ["typ": .string(ALLOW_TOKEN_TYP), "action_digest": .string(d), "group_pk": .string(b64(gpk)), "nonce": .string(n)]
        if let nb = notBefore { body["not_before"] = nb }
        if let ex = expiresAt { body["expires_at"] = ex }
        guard let sk = policySecret else { throw JSError("private key must be hex string or Uint8Array") }
        guard sk.count == 32 else { throw JSError("private key of length 32 expected, got \(sk.count)") }
        let key = try PCAEdKey(seed: sk)
        let sig = try key.sign(try canonicalLenient(.object(body)))
        return .object(["body": .object(body), "authority": .string(b64(key.pub)), "sig": .string(b64(sig))])
    }

    /// `{ok, reason?}`. Never throws: a malformed token or any internal error is a refusal (`... verification error (fail closed): ...`).
    public static func verifyAllowToken(_ token: JSONValue?, policyAuthorityPublicKey: [UInt8]?, groupPublicKey: [UInt8]?, message: [UInt8]?, now: JSONValue?) -> JSONValue {
        func no(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        guard isObjOrArray(token) else { return no("allow token missing or malformed") }
        guard isObjOrArray(token?.get("body")) else { return no("allow token has no body") }
        let body = token!.get("body")!
        if !IV.same(body.get("typ")?.asString, ALLOW_TOKEN_TYP) { return no("allow token wrong typ (\(JS.toString(body.get("typ"))))") }
        guard case let .string(sigText)? = token?.get("sig") else { return no("allow token missing signature") }
        guard let sig = Base64URLStrict.decode(sigText, length: 64) else { return no("allow token signature not canonical base64url") }
        do {
            let bodyBytes = try canonicalLenient(body)
            let verified = policyAuthorityPublicKey.map { Ed25519Strict.verifyB64u(b64($0), bodyBytes, b64(sig)) } ?? false
            if !verified { return no("allow token not signed by the trusted policy authority") }
            guard let gpk = groupPublicKey else { throw JSError("radix2.encode input should be Uint8Array") }
            if !IV.same(body.get("group_pk")?.asString, b64(gpk)) { return no("allow token authorizes a different group key") }
            guard let m = message else { throw JSError("frostActionDigest: message must be bytes") }
            if !IV.same(body.get("action_digest")?.asString, frostActionDigest(m)) { return no("allow token authorizes a different action digest") }
            guard let nowV = now, nowV.isNumber, let t = IV.num(nowV), t.isFinite else { return no("invalid verification time") }
            if let nb = body.get("not_before"), t < JS.toNumber(nb) { return no("allow token not yet valid") }
            if let ex = body.get("expires_at"), t >= JS.toNumber(ex) { return no("allow token expired") }
            return .object(["ok": .bool(true)])
        } catch {
            return no("allow token verification error (fail closed): \(text(error))")
        }
    }

    // ---- signer proof of possession ----

    private static func popChallenge(_ gpk: [UInt8], _ id: Int64, _ pk: [UInt8], _ r: [UInt8]) throws -> [UInt8] {
        let e = try PCAFrost.bytesToScalar(PCAFrost.sha512(Array(SIGNER_POP_DST.utf8) + gpk + PCAFrost.scalarOf(id: id) + pk + r))
        return PCAFrost.isZero(e) ? PCAFrost.scalarOf(id: 1) : e
    }

    /// A Schnorr proof that the signer knows the secret behind its verification share, bound to the group key and its identifier (`{identifier, publicKey, R, s}`).
    /// `nonce` fixes the proof's nonce (reproducible vectors); otherwise it is drawn from `random`, again if it reduces to zero.
    public static func createSignerPoP(identifier: Int64, share: [UInt8], groupPublicKey: [UInt8], nonce: [UInt8]? = nil, random: RandomBytes = systemRandom) throws -> JSONValue {
        if identifier <= 0 { throw JSError("createSignerPoP: identifier must be a positive integer") }
        if share.count != 32 { throw JSError("createSignerPoP: share must be 32 bytes") }
        if groupPublicKey.count != 32 { throw JSError("createSignerPoP: groupPublicKey must be 32 bytes") }
        let x = try PCAFrost.bytesToScalar(share)
        let pk = PCAFrost.mulBase(x)
        var k = try nonce.map { try PCAFrost.bytesToScalar($0) } ?? [UInt8](repeating: 0, count: 32)
        while PCAFrost.isZero(k) { k = try PCAFrost.bytesToScalar(random()) }
        let r = PCAFrost.mulBase(k)
        let e = try popChallenge(groupPublicKey, identifier, pk, r)
        let s = PCAFrost.sAdd(k, PCAFrost.sMul(e, x))
        return .object(["identifier": .int(identifier), "publicKey": .string(b64(pk)), "R": .string(b64(r)), "s": .string(b64(s))])
    }

    /// Whether a proof of possession is valid for the group key. Never throws.
    public static func verifySignerPoP(_ pop: JSONValue?, groupPublicKey: [UInt8]?) -> Bool {
        guard isObjOrArray(pop), let id = posId(pop?.get("identifier")), let gpk = groupPublicKey, gpk.count == 32 else { return false }
        guard case let .string(a)? = pop?.get("publicKey"), let pk = Base64URLStrict.decode(a, length: 32),
              case let .string(b)? = pop?.get("R"), let rb = Base64URLStrict.decode(b, length: 32),
              case let .string(c)? = pop?.get("s"), let sb = Base64URLStrict.decode(c, length: 32) else { return false }
        do {
            try PCAFrost.decodeSafePoint(pk)
            try PCAFrost.decodeSafePoint(rb)
            guard PCAFrost.isCanonicalScalar(sb) else { return false }
            let e = try popChallenge(gpk, id, pk, rb)
            return PCAFrost.mulBase(try PCAFrost.bytesToScalar(sb)) == (try PCAFrost.add(rb, PCAFrost.mulPoint(pk, e)))
        } catch { return false }
    }

    public struct PoPError: Error, Equatable {
        public let message: String
        public let identifier: Int64?
        public init(_ message: String, _ identifier: Int64? = nil) { self.message = message; self.identifier = identifier }
    }

    /// One signer's claim to a verification share.
    public struct Enrollment {
        public var identifier: JSONValue?
        public var publicKey: [UInt8]?
        public var pop: JSONValue?
        public init(identifier: JSONValue?, publicKey: [UInt8]?, pop: JSONValue?) { self.identifier = identifier; self.publicKey = publicKey; self.pop = pop }
    }

    /// The verification shares of the enrolled signers, accepted only with a valid proof of possession each (a rogue key is refused).
    public static func enrollVerificationShares(_ enrollments: [Enrollment?]?, groupPublicKey: [UInt8]?) throws -> [(identifier: Int64, publicKey: [UInt8])] {
        guard let list = enrollments, !list.isEmpty else { throw PoPError("enrollVerificationShares: no signer enrollments") }
        guard let gpk = groupPublicKey, gpk.count == 32 else { throw PoPError("enrollVerificationShares: groupPublicKey must be 32 bytes") }
        var out: [(Int64, [UInt8])] = []
        var seen = Set<Int64>()
        for e in list {
            guard let e = e, let id = posId(e.identifier) else { throw PoPError("enrollVerificationShares: enrollment with invalid identifier") }
            if !seen.insert(id).inserted { throw PoPError("enrollVerificationShares: duplicate enrollment for signer \(id)", id) }
            guard let pk = e.publicKey, pk.count == 32 else { throw PoPError("enrollVerificationShares: signer \(id) verification share must be 32 bytes", id) }
            guard isObjOrArray(e.pop), posId(e.pop?.get("identifier")) == id, IV.same(e.pop?.get("publicKey")?.asString, b64(pk)) else {
                throw PoPError("enrollVerificationShares: signer \(id) missing or mismatched proof-of-possession (rogue key rejected)", id)
            }
            if !verifySignerPoP(e.pop, groupPublicKey: gpk) { throw PoPError("enrollVerificationShares: signer \(id) invalid proof-of-possession (rogue key rejected)", id) }
            out.append((id, pk))
        }
        return out
    }

    // ---- equivocation guard ----

    public struct EquivocationError: Error {
        public let sessionId: String, round: Int64, identifier: Int64, previousDigest: String, offendingDigest: String
        public var message: String { "equivocation: signer \(identifier) sent two different messages for session '\(sessionId)' round \(round)" }
    }

    /// Remembers, per (session, round, signer), the digest of the one message that signer sent; a different message for the same slot is equivocation.
    public final class EquivocationGuard {
        private var seen: [String: String] = [:]
        private let lock = NSLock()
        public init() {}
        public func observe(_ sessionId: JSONValue?, _ round: JSONValue?, _ identifier: JSONValue?, _ message: JSONValue) throws {
            guard case let .string(sid)? = sessionId, !sid.isEmpty else { throw JSError("EquivocationGuard: session_id must be a non-empty string") }
            guard let r = safeInt(round), r >= 1 else { throw JSError("EquivocationGuard: round must be a positive integer") }
            guard let id = posId(identifier) else { throw JSError("EquivocationGuard: identifier must be a positive integer") }
            let digest = b64(Canonical.sha256(try canonicalLenient(message)))
            let key = "\(sid)\u{0}\(r)\u{0}\(id)"
            lock.lock(); defer { lock.unlock() }
            guard let prev = seen[key] else { seen[key] = digest; return }
            if prev != digest { throw EquivocationError(sessionId: sid, round: r, identifier: id, previousDigest: prev, offendingDigest: digest) }
        }
        public func forget(_ sessionId: String) {
            lock.lock(); defer { lock.unlock() }
            for k in seen.keys where k.hasPrefix(sessionId + "\u{0}") { seen[k] = nil }
        }
    }

    // ---- wire decoding ----

    public static func decodeCommitment(_ w: JSONValue?) throws -> PCAFrost.Commitment {
        guard isObjOrArray(w) else { throw JSError("bad commitment") }
        let hiding = w?.get("hiding")?.asString.flatMap { Base64URLStrict.decode($0, length: 32) }
        let binding = w?.get("binding")?.asString.flatMap { Base64URLStrict.decode($0, length: 32) }
        guard let id = posId(w?.get("identifier")) else { throw JSError("bad commitment identifier") }
        guard let h = hiding, let b = binding else { throw JSError("bad commitment point encoding") }
        return PCAFrost.Commitment(identifier: id, hiding: h, binding: b)
    }

    public static func decodeCommitments(_ list: JSONValue?) throws -> [PCAFrost.Commitment] {
        guard case let .array(a)? = list else { throw JSError("commitments must be a list") }
        if a.count > MAX_FROST_SIGNING_SET { throw JSError("commitments list exceeds the maximum signing set") }
        return try a.map { try decodeCommitment($0) }
    }

    public static func decodeVerificationShares(_ list: JSONValue?) throws -> [PCAFrost.VerificationShare] {
        guard case let .array(a)? = list else { throw JSError("verification_shares must be a list") }
        if a.count > MAX_FROST_SIGNING_SET { throw JSError("verification_shares list exceeds the maximum signing set") }
        return try a.map { v in
            guard isObjOrArray(v) else { throw JSError("bad verification share") }
            let pk = v.get("publicKey")?.asString.flatMap { Base64URLStrict.decode($0, length: 32) }
            guard let id = posId(v.get("identifier")) else { throw JSError("bad verification-share identifier") }
            guard let k = pk else { throw JSError("bad verification-share key encoding") }
            return PCAFrost.VerificationShare(identifier: id, publicKey: k)
        }
    }

    static func encodeCommitment(_ c: PCAFrost.Commitment) -> JSONValue {
        .object(["identifier": .int(c.identifier), "hiding": .string(b64(c.hiding)), "binding": .string(b64(c.binding))])
    }

    // ---- the signer service ----

    /// The service of one guardian: holds one share, answers round 1 with a commitment and round 2 with a signature share, only for a valid allow token over exactly
    /// the message. A session signs once. With a `nonceStore` the round-1 state survives a restart and a spent session stays spent.
    public final class GuardianSignerService {
        public let identifier: Int64
        public let verificationShare: [UInt8]
        public let proofOfPossession: JSONValue
        private let share: [UInt8]
        private let groupPublicKey: [UInt8]
        private let threshold: Int64
        private let policyAuthorityPublicKey: [UInt8]
        private let sessionTtlMs: Double?
        private let now: () -> Double
        private let store: PCAFrostNonceStore?
        private let random: RandomBytes
        private var sessions: [String: (nonces: PCAFrost.Nonces, commitment: PCAFrost.Commitment, createdAt: Double)] = [:]
        private var spentIds = Set<String>()
        private let lock = NSLock()

        public init(identifier: JSONValue?, share: [UInt8]?, groupPublicKey: [UInt8]?, threshold: JSONValue?, policyAuthorityPublicKey: [UInt8]?, sessionTtlMs: JSONValue? = nil,
                    now: (() -> Double)? = nil, nonceStore: PCAFrostNonceStore? = nil, random: @escaping RandomBytes = PCAFrostNet.systemRandom) throws {
            guard let id = PCAFrostNet.posId(identifier) else { throw JSError("GuardianSignerService: identifier must be a positive integer") }
            guard let sh = share, sh.count == 32 else { throw JSError("GuardianSignerService: share must be 32 bytes") }
            guard let g = groupPublicKey, g.count == 32 else { throw JSError("GuardianSignerService: groupPublicKey must be 32 bytes") }
            guard let t = PCAFrostNet.safeInt(threshold), t >= 1 else { throw JSError("GuardianSignerService: threshold must be a positive integer") }
            guard let pa = policyAuthorityPublicKey, pa.count == 32 else { throw JSError("GuardianSignerService: policyAuthorityPublicKey must be 32 bytes") }
            var ttl: Double? = nil
            if let s = sessionTtlMs {
                guard s.isNumber, let d = IV.num(s), d.isFinite, d > 0 else { throw JSError("GuardianSignerService: sessionTtlMs must be a positive finite number") }
                ttl = d
            }
            self.identifier = id; self.share = sh; self.groupPublicKey = g; self.threshold = t; self.policyAuthorityPublicKey = pa; self.sessionTtlMs = ttl
            self.now = now ?? { Date().timeIntervalSince1970 * 1000 }
            self.store = nonceStore
            self.random = random
            self.verificationShare = try PCAFrost.verifyingShare(sh)
            self.proofOfPossession = try PCAFrostNet.createSignerPoP(identifier: id, share: sh, groupPublicKey: g, random: random)
        }

        public func enrollment() -> JSONValue { .object(["identifier": .int(identifier), "publicKey": .string(PCAFrostNet.b64(verificationShare)), "pop": proofOfPossession]) }

        /// Round 1: a fresh nonce pair for the session, answered with its commitment and the proof of possession.
        public func round1(_ req: JSONValue?) -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            func refuse(_ r: String) -> JSONValue { .object(["ok": .bool(false), "identifier": .int(identifier), "reason": .string(r)]) }
            guard PCAFrostNet.isObjOrArray(req), IV.same(req?.get("typ")?.asString, "pca.frost.round1.v1"), case let .string(sid)? = req?.get("session_id"), !sid.isEmpty else {
                return refuse("malformed round-1 request")
            }
            do {
                if try spentIds.contains(sid) || (try store?.isSpent(sid)) == true { return refuse("session already signed") }
                if try sessions[sid] != nil || (try store?.load(sid)) != nil { return refuse("duplicate round-1 for session") }
                let c = try PCAFrost.commit(PCAFrost.ParticipantShare(identifier: identifier, share: share, publicKey: verificationShare), hidingRandomness: try random(), bindingRandomness: try random())
                let created = now()
                try store?.create(sid, PCAFrostNonceRecord(hiding: c.hidingNonce, binding: c.bindingNonce, hidingCommitment: c.commitment.hiding, bindingCommitment: c.commitment.binding, createdAt: created))
                sessions[sid] = (PCAFrost.Nonces(hiding: c.hidingNonce, binding: c.bindingNonce), c.commitment, created)
                return .object(["ok": .bool(true), "identifier": .int(identifier), "commitment": PCAFrostNet.encodeCommitment(c.commitment), "pop": proofOfPossession])
            } catch { return refuse(PCAFrostNet.text(error)) }
        }

        /// Round 2: the signature share, once, for a valid allow token over exactly this message and a signing set that holds our round-1 commitment.
        public func round2(_ req: JSONValue?) -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            func refuse(_ r: String) -> JSONValue { .object(["ok": .bool(false), "identifier": .int(identifier), "refused": .bool(true), "reason": .string(r)]) }
            guard PCAFrostNet.isObjOrArray(req), IV.same(req?.get("typ")?.asString, "pca.frost.round2.v1"), case let .string(sid)? = req?.get("session_id"), let req = req else {
                return refuse("malformed round-2 request")
            }
            do {
                if try spentIds.contains(sid) || (try store?.isSpent(sid)) == true { return refuse("session already signed (one-shot)") }
                var state = sessions[sid]
                if state == nil, let st = store, let rec = try st.load(sid) {
                    state = (PCAFrost.Nonces(hiding: rec.hiding, binding: rec.binding), PCAFrost.Commitment(identifier: identifier, hiding: rec.hidingCommitment, binding: rec.bindingCommitment), rec.createdAt)
                    sessions[sid] = state
                }
                guard let s = state else { return refuse("no round-1 state for this session") }
                let sessionAge = now() - s.createdAt
                if let ttl = sessionTtlMs, !(sessionAge.isFinite && sessionAge <= ttl) {
                    sessions[sid] = nil
                    try store?.drop(sid)
                    return refuse("session expired (stale-session guard: round-1 older than \(JS.number(ttl))ms)")
                }
                guard case let .string(mtext)? = req.get("message"), let message = Base64URLStrict.decode(mtext) else { return refuse("message not canonical base64url") }
                if !IV.same(req.get("group_pk")?.asString, PCAFrostNet.b64(groupPublicKey)) { return refuse("request names a different group key") }
                let allow = PCAFrostNet.verifyAllowToken(req.get("allow"), policyAuthorityPublicKey: policyAuthorityPublicKey, groupPublicKey: groupPublicKey, message: message, now: .double(now()))
                if allow.get("ok") != .bool(true) { return refuse("policy authorization failed: \(allow.get("reason")?.asString ?? "undefined")") }
                let commitments = try PCAFrostNet.decodeCommitments(JS.present(req.get("commitments")) ?? .array([]))
                if Int64(commitments.count) < threshold { return refuse("signing set below threshold t=\(threshold)") }
                guard let own = commitments.first(where: { $0.identifier == identifier }) else { return refuse("our commitment is not in the signing set") }
                if own.hiding != s.commitment.hiding || own.binding != s.commitment.binding {
                    return refuse("equivocation detected: our commitment in the signing set differs from our round-1 commitment")
                }
                let vshares = try PCAFrostNet.decodeVerificationShares(req.get("verification_shares"))
                try store?.spend(sid)
                let sig = try PCAFrost.sign(identifier, share, groupPublicKey, s.nonces, message, commitments,
                                            PCAFrost.SignOpts(threshold: .int(threshold), verificationShare: verificationShare, verificationShares: vshares))
                sessions[sid] = nil
                spentIds.insert(sid)
                return .object(["ok": .bool(true), "identifier": .int(identifier), "sig_share": .string(PCAFrostNet.b64(sig.sigShare))])
            } catch { return refuse(PCAFrostNet.text(error)) }
        }
    }

    // ---- the coordinator ----

    public typealias SignerTransport = PCAFrostSignerTransport

    public struct CoordinatorError: Error {
        public let message: String
        public let refusals: [JSONValue]
        /// Set for the window that closed before the threshold was reached.
        public let timeoutMs: Double?
        public init(_ message: String, refusals: [JSONValue] = [], timeoutMs: Double? = nil) { self.message = message; self.refusals = refusals; self.timeoutMs = timeoutMs }
    }

    public struct SignResult { public let signature: [UInt8]; public let sessionId: String; public let signers: [Int64] }

    /// Drives one signing session at a time over the transports: round 1 to the first `threshold` signers (or the chosen ones), a proof-of-possession and equivocation check on
    /// every answer, round 2 to the first `threshold` that committed, then the aggregate, verified under the group key. Refusals are collected, never hidden.
    public final class NetworkCoordinator {
        private let groupPublicKey: [UInt8]
        private let threshold: Int64
        private let signers: [SignerTransport]
        private let verificationShares: [PCAFrost.VerificationShare]
        private let pkById: [Int64: String]
        private let equivocation = EquivocationGuard()
        private let newSessionId: () throws -> String
        private let timeoutMs: Double?

        public init(groupPublicKey: [UInt8]?, threshold: JSONValue?, signers: [SignerTransport], verificationShares: [PCAFrost.VerificationShare]? = nil, enroll: [Enrollment?]? = nil,
                    newSessionId: (() throws -> String)? = nil, timeoutMs: JSONValue? = nil) throws {
            guard let g = groupPublicKey, g.count == 32 else { throw JSError("NetworkCoordinator: groupPublicKey must be 32 bytes") }
            guard let t = PCAFrostNet.safeInt(threshold), t >= 1 else { throw JSError("NetworkCoordinator: threshold must be a positive integer") }
            var window: Double? = nil
            if let w = timeoutMs {
                guard w.isNumber, let d = IV.num(w), d.isFinite, d > 0 else { throw JSError("NetworkCoordinator: timeoutMs must be a positive finite number") }
                window = d
            }
            self.groupPublicKey = g; self.threshold = t; self.signers = signers
            if let e = enroll {
                self.verificationShares = try PCAFrostNet.enrollVerificationShares(e, groupPublicKey: g).map { PCAFrost.VerificationShare(identifier: $0.identifier, publicKey: $0.publicKey) }
            } else if let v = verificationShares {
                self.verificationShares = v
            } else { throw JSError("NetworkCoordinator: provide verificationShares or enroll") }
            var map: [Int64: String] = [:]
            for v in self.verificationShares { map[v.identifier] = PCAFrostNet.b64(v.publicKey) }
            self.pkById = map
            self.newSessionId = newSessionId ?? { PCAFrostNet.b64(try PCAFrostNet.systemRandom()) }
            self.timeoutMs = window
        }

        /// One signing session. `timeoutMs` overrides the coordinator's window for this call; a window that is not a positive finite number means no deadline. When the
        /// window closes first the call throws a `CoordinatorError` with `timeoutMs` set (the session keeps running in the background, as in the reference).
        public func sign(_ message: [UInt8], allow: JSONValue, signerIds: [Int64]? = nil, timeoutMs call: Double? = nil) throws -> SignResult {
            let window = call ?? timeoutMs
            guard let w = window, w.isFinite, w > 0 else { return try drive(message, allow, signerIds) }
            let box = ResultBox()
            let done = DispatchSemaphore(value: 0)
            Thread.detachNewThread {
                box.result = Result { try self.drive(message, allow, signerIds) }
                done.signal()
            }
            if done.wait(timeout: .now() + .milliseconds(Int(w))) == .timedOut {
                throw CoordinatorError("coordinator: signing session did not reach threshold within \(JS.number(w))ms", timeoutMs: w)
            }
            return try box.result!.get()
        }

        private final class ResultBox: @unchecked Sendable { var result: Result<SignResult, Error>? }
        private final class Slots<U>: @unchecked Sendable { var v: [U?]; init(_ n: Int) { v = Array(repeating: nil, count: n) } }

        private func concurrently<T>(_ items: [SignerTransport], _ f: @escaping (SignerTransport) -> T) -> [T] {
            let slots = Slots<T>(items.count)
            let lock = NSLock()
            DispatchQueue.concurrentPerform(iterations: items.count) { i in
                let r = f(items[i])
                lock.lock(); slots.v[i] = r; lock.unlock()
            }
            return slots.v.map { $0! }
        }

        private func drive(_ message: [UInt8], _ allow: JSONValue, _ signerIds: [Int64]?) throws -> SignResult {
            let chosen = signerIds.map { ids in signers.filter { ids.contains($0.identifier) } } ?? Array(signers.prefix(Int(threshold)))
            if Int64(chosen.count) < threshold { throw CoordinatorError("coordinator: only \(chosen.count) signer(s) selected, need t=\(threshold)") }
            let sessionId = try newSessionId()
            let r1 = concurrently(chosen) { s -> (SignerTransport, JSONValue) in
                do { return (s, try s.round1(.object(["typ": .string("pca.frost.round1.v1"), "session_id": .string(sessionId)]))) }
                catch { return (s, .object(["ok": .bool(false), "identifier": .int(s.identifier), "reason": .string(PCAFrostNet.text(error))])) }
            }
            var refusals: [JSONValue] = []
            func refusal(_ id: JSONValue?, _ reason: String) { refusals.append(PCAFrostNet.present([("identifier", id), ("reason", .string(reason))])) }
            var committed: [(transport: SignerTransport, commitment: JSONValue)] = []
            for (s, resp) in r1 {
                if !JS.truthy(resp.get("ok")) { refusals.append(PCAFrostNet.present([("identifier", resp.get("identifier")), ("reason", resp.get("reason"))])); continue }
                let id = resp.get("identifier")
                guard let rid = PCAFrostNet.safeInt(id), let expected = pkById[rid] else { refusal(id, "no verification share on record for this signer"); continue }
                let pop = resp.get("pop")
                if !(pop != nil && PCAFrostNet.safeInt(pop?.get("identifier")) == rid && IV.same(pop?.get("publicKey")?.asString, expected) && PCAFrostNet.verifySignerPoP(pop, groupPublicKey: groupPublicKey)) {
                    refusal(id, "invalid or missing proof-of-possession (rogue-key defense)"); continue
                }
                // an absent member is JavaScript's undefined, which the canonical form refuses (a present null is fine)
                guard let wireCommitment = resp.get("commitment") else { refusal(id, "equivocation check failed"); continue }
                do { try equivocation.observe(.string(sessionId), .int(1), id, wireCommitment) }
                catch let e as EquivocationError { refusal(id, e.message); continue }
                catch { refusal(id, "equivocation check failed"); continue }
                committed.append((s, wireCommitment))
            }
            if Int64(committed.count) < threshold { throw CoordinatorError("coordinator: round 1 produced \(committed.count) commitment(s), need t=\(threshold)", refusals: refusals) }
            let set = Array(committed.prefix(Int(threshold)))
            let commitments = set.map { $0.commitment }
            let setIds = Set(set.compactMap { PCAFrostNet.safeInt($0.commitment.get("identifier")) })
            let vshares = verificationShares.filter { setIds.contains($0.identifier) }.map { JSONValue.object(["identifier": .int($0.identifier), "publicKey": .string(PCAFrostNet.b64($0.publicKey))]) }
            if vshares.count != set.count { throw CoordinatorError("coordinator: missing a verification share for a signer in the set") }
            let req2: JSONValue = .object(["typ": .string("pca.frost.round2.v1"), "session_id": .string(sessionId), "message": .string(PCAFrostNet.b64(message)), "group_pk": .string(PCAFrostNet.b64(groupPublicKey)),
                                           "commitments": .array(commitments), "verification_shares": .array(vshares), "allow": allow])
            let r2 = concurrently(set.map { $0.transport }) { t -> JSONValue in
                do { return try t.round2(req2) }
                catch { return .object(["ok": .bool(false), "identifier": .int(t.identifier), "refused": .bool(true), "reason": .string(PCAFrostNet.text(error))]) }
            }
            var shares: [PCAFrost.SigShare] = []
            for resp in r2 {
                let id = resp.get("identifier")
                if !JS.truthy(resp.get("ok")) { refusals.append(PCAFrostNet.present([("identifier", id), ("reason", resp.get("reason"))])); continue }
                guard let wireShare = resp.get("sig_share") else { refusal(id, "equivocation check failed"); continue }
                do { try equivocation.observe(.string(sessionId), .int(2), id, .object(["sig_share": wireShare])) }
                catch let e as EquivocationError { refusal(id, e.message); continue }
                catch { refusal(id, "equivocation check failed"); continue }
                guard case let .string(t)? = resp.get("sig_share"), let sb = Base64URLStrict.decode(t, length: 32), let rid = PCAFrostNet.safeInt(id) else { refusal(id, "malformed signature share"); continue }
                shares.append(PCAFrost.SigShare(identifier: rid, sigShare: sb))
            }
            if Int64(shares.count) < threshold { throw CoordinatorError("coordinator: round 2 produced \(shares.count) share(s), need t=\(threshold)", refusals: refusals) }
            let agg = try PCAFrostNet.decodeCommitments(.array(commitments))
            let sig = try PCAFrost.aggregate(message, agg, shares, groupPublicKey, threshold: .int(threshold), verificationShares: verificationShares.filter { setIds.contains($0.identifier) })
            return SignResult(signature: sig, sessionId: sessionId, signers: set.compactMap { PCAFrostNet.safeInt($0.commitment.get("identifier")) })
        }
    }
}

/// A signer as the coordinator sees it. A thrown error is an unreachable signer.
public protocol PCAFrostSignerTransport {
    var identifier: Int64 { get }
    func round1(_ req: JSONValue) throws -> JSONValue
    func round2(_ req: JSONValue) throws -> JSONValue
}
