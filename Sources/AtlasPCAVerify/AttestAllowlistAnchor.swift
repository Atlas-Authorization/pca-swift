import Foundation

/// The transparency anchor of allowlist manifests: the commitment of an anchored (issuer, version, digest), an operator log with a signed head, the
/// evidence a verifier takes (head, the full entry feed, an inclusion proof and, against a cached head, a consistency proof), and the verifier that
/// proves a manifest is the highest one the pinned log anchors for its issuer. Entries, heads and evidence are the language-neutral JSON of the wire.
public enum PCAAllowlistAnchor {
    static let DOMAIN = "pca-attest-allowlist-anchor/v1"
    private static let MAX_FEED = 100_000
    private static let DAY: Double = 86_400_000

    private static func err(_ m: String) -> JSError { JSError(m) }
    private static func hashStrict(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }

    /// The ledger commitment of an entry: hashCanonical({domain, issuer, version, digest}).
    public static func allowlistAnchorCommit(_ e: JSONValue?) throws -> String {
        func need(_ k: String) throws -> JSONValue { guard let v = e?.get(k) else { throw err("canonicalize: unsupported type undefined") }; return v }
        return try hashStrict(.object(["domain": .string(DOMAIN), "issuer": try need("issuer"), "version": try need("version"), "digest": try need("digest")]))
    }

    /// `{issuer (1..200 chars), version (integer >= 1), digest (43 base64url chars)}` and nothing else.
    static func validEntry(_ e: JSONValue?) -> Bool {
        guard let r = e?.asObject, r.count == 3, case let .string(i)? = r["issuer"], !i.isEmpty, i.utf16.count <= 200, let v = IV.num(r["version"]), v.isFinite,
              v.rounded() == v, abs(v) <= IV.MAX_SAFE, v >= 1, case let .string(d)? = r["digest"] else { return false }
        let u = Array(d.unicodeScalars)
        return u.count == 43 && u.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0.value == 45 || $0.value == 95 }
    }

    /// The entry `{issuer, version, digest}` of a verified manifest.
    public static func anchorEntryOf(_ v: JSONValue) -> JSONValue { .object(["issuer": v.get("issuer") ?? .null, "version": v.get("version") ?? .null, "digest": v.get("digest") ?? .null]) }

    // MARK: the operator log

    /// An append-only log of anchored entries over a transparency ledger, with the last signed head.
    public final class Log {
        public let ledger: PCATransparencyLedger
        public let instanceId: String
        public let principal: String
        var entriesList: [JSONValue] = []
        var latestHead: JSONValue?
        fileprivate let lock = NSLock()

        public init(instanceId: String, principal: String) {
            self.instanceId = instanceId; self.principal = principal
            ledger = PCATransparencyLedger(principal: principal)
        }

        public func entries() -> [JSONValue] { lock.lock(); defer { lock.unlock() }; return entriesList }
        public func latest() -> JSONValue? { lock.lock(); defer { lock.unlock() }; return latestHead }
    }

    public static func createAllowlistAnchorLog(instanceId: String, principal: String) -> Log { Log(instanceId: instanceId, principal: principal) }

    /// How to sign a head: the guardian key (a post-quantum suite makes the record post-quantum accountable) and the head's timestamp.
    public struct SignOptions {
        public var guardian: PCASuiteKey
        public var nowMs: Double
        public init(guardian: PCASuiteKey, nowMs: Double) { self.guardian = guardian; self.nowMs = nowMs }
    }

    private static func signHead(_ log: Log, _ o: SignOptions) throws -> JSONValue {
        let h = log.ledger.head()
        let sth = try Ledger.signTreeHead(o.guardian, .object(["instance_id": .string(log.instanceId), "principal": .string(log.principal), "size": h.get("size") ?? .int(0),
                                                                 "root": h.get("root") ?? .string(""), "prev_root": log.latestHead?.get("root") ?? .string(""),
                                                                 "timestamp": StoreJ.num(o.nowMs)]))
        log.latestHead = sth
        return sth
    }

    /// Anchors an entry (or a verified manifest, which is reduced to its entry) and returns the evidence for it. Re-anchoring the same entry returns its
    /// evidence again; the same version with another digest, or a version below the highest anchored for the issuer, throws.
    public static func anchorAllowlistHead(_ log: Log, _ what: JSONValue, _ opts: SignOptions) throws -> JSONValue {
        log.lock.lock(); defer { log.lock.unlock() }
        let entry: JSONValue = what.get("body") != nil ? anchorEntryOf(what) : what
        guard validEntry(entry) else { throw err("anchorAllowlistHead: malformed entry") }
        let issuer = entry.get("issuer")!.asString!, version = IV.num(entry.get("version"))!, digest = entry.get("digest")!.asString!
        let same = log.entriesList.firstIndex { IV.same($0.get("issuer")?.asString, issuer) && IV.num($0.get("version")) == version }
        let index: Int
        if let s = same {
            if !IV.same(log.entriesList[s].get("digest")?.asString, digest) { throw err("anchorAllowlistHead: this version is already anchored with a different digest") }
            index = s
        } else {
            let max = log.entriesList.filter { IV.same($0.get("issuer")?.asString, issuer) }.reduce(0.0) { Swift.max($0, IV.num($1.get("version")) ?? 0) }
            if version < max { throw err("anchorAllowlistHead: version \(JS.number(version)) is lower than the anchored \(JS.number(max))") }
            index = try log.ledger.appendCommitment(try allowlistAnchorCommit(entry)).index
            log.entriesList.append(entry)
            _ = try signHead(log, opts)
        }
        if log.latestHead == nil { _ = try signHead(log, opts) }
        return try evidenceForLocked(log, Double(index), nil)
    }

    /// Signs a fresh head over the current ledger (a monitor's heartbeat). Throws when nothing is anchored yet.
    public static func refreshAnchorHead(_ log: Log, _ opts: SignOptions) throws -> JSONValue {
        log.lock.lock(); defer { log.lock.unlock() }
        if log.ledger.size == 0 { throw err("refreshAnchorHead: nothing anchored yet") }
        return try signHead(log, opts)
    }

    /// The evidence for the entry at `index`: the latest head, the full feed, the inclusion proof and, when `cachedSize` is a smaller non-empty size, the
    /// consistency proof from it.
    public static func evidenceFor(_ log: Log, _ index: Double, cachedSize: Double? = nil) throws -> JSONValue {
        log.lock.lock(); defer { log.lock.unlock() }
        return try evidenceForLocked(log, index, cachedSize)
    }

    private static func evidenceForLocked(_ log: Log, _ index: Double, _ cachedSize: Double?) throws -> JSONValue {
        guard let head = log.latestHead else { throw err("evidenceFor: log has no signed head") }
        var o: JObject = ["head": head, "entries": .array(log.entriesList), "proof": try log.ledger.inclusionProof(StoreJ.num(index))]
        if let c = cachedSize, c > 0, let hs = IV.num(head.get("size")), c < hs { o["consistency"] = try log.ledger.consistencyProof(StoreJ.num(c), StoreJ.num(hs)) }
        return .object(o)
    }

    // MARK: verification

    public struct VerifyOptions {
        /// `{logKey, instanceId, principal, witnesses?, pqPins?}`: the pinned operator log.
        public var trust: JSONValue
        public var nowMs: Double
        public var maxHeadAgeMs: JSONValue?
        public var clockSkewMs: JSONValue?
        public var cachedHead: JSONValue?
        public init(trust: JSONValue, nowMs: Double, maxHeadAgeMs: JSONValue? = nil, clockSkewMs: JSONValue? = nil, cachedHead: JSONValue? = nil) {
            self.trust = trust; self.nowMs = nowMs; self.maxHeadAgeMs = maxHeadAgeMs; self.clockSkewMs = clockSkewMs; self.cachedHead = cachedHead
        }
    }

    private static func no(_ code: String, _ reason: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(code), "reason": .string(reason)]) }

    /// Proves that `verified` (`{issuer, version, digest}` of a verified manifest) is anchored in the pinned log and is the highest version anchored for its
    /// issuer: the head is signed by the pinned key (and its witnesses), belongs to this log and is fresh; a cached head is not rolled back, forked or
    /// left unproven; the feed reproduces the signed root; the log never anchors two digests for one version; the inclusion proof places the manifest;
    /// no higher version is anchored. Returns `{ok: true, issuer, version, digest, highestAnchoredVersion, head}` or `{ok: false, code, reason}`.
    public static func verifyAllowlistAnchored(_ verified: JSONValue, _ evidence: JSONValue?, _ opts: VerifyOptions) -> JSONValue {
        do {
            guard let ev = evidence, ev.isObject, let proof = ev.get("proof"), let head = ev.get("head"), case let .array(entries)? = ev.get("entries") else {
                return no("missing-proof", "no anchor evidence (head + entries + inclusion proof) supplied")
            }
            let trust = opts.trust
            guard opts.nowMs.isFinite, opts.nowMs.rounded() == opts.nowMs, abs(opts.nowMs) <= IV.MAX_SAFE else { return no("bad-head", "nowMs must be an integer") }
            guard let logKey = trust.get("logKey")?.asString else { return no("bad-head", "tree head is not signed by the pinned log key (or lacks the required witness cosignatures)") }
            var pins: [String: String]? = nil
            if let p = trust.get("pqPins")?.asObject { var m: [String: String] = [:]; for (k, v) in p { if let t = v.asString { m[k.s] = t } }; pins = m }
            let witnesses = trust.get("witnesses")?.asObject
            if !Ledger.verifyTreeHead(head, logKey, witnesses, pins) { return no("bad-head", "tree head is not signed by the pinned log key (or lacks the required witness cosignatures)") }
            if !IV.same(head.get("instance_id")?.asString, trust.get("instanceId")?.asString) || !IV.same(head.get("principal")?.asString, trust.get("principal")?.asString) {
                return no("bad-head", "tree head is for a different log")
            }
            func finiteOpt(_ v: JSONValue?) -> Bool { v == nil || (IV.num(v).map { $0.isFinite } ?? false) }
            if !finiteOpt(opts.clockSkewMs) { return no("bad-head", "clockSkewMs must be a finite number") }
            if !finiteOpt(opts.maxHeadAgeMs) { return no("bad-head", "maxHeadAgeMs must be a finite number") }
            let skew = Swift.max(0, IV.num(opts.clockSkewMs) ?? 60_000), maxAge = IV.num(opts.maxHeadAgeMs) ?? DAY
            guard let ts = head.get("timestamp").flatMap({ $0.safeInt }).map({ Double($0) }) else { return no("stale-head", "tree head is timestamped in the future") }
            if !(ts <= opts.nowMs + skew) { return no("stale-head", "tree head is timestamped in the future") }
            if !(opts.nowMs - ts <= maxAge) { return no("stale-head", "tree head is older than maxHeadAgeMs (\(JS.number(maxAge)))") }
            let headSize = IV.num(head.get("size")) ?? .nan

            if let cached = opts.cachedHead {
                guard Ledger.verifyTreeHead(cached, logKey, witnesses, pins), IV.same(cached.get("instance_id")?.asString, trust.get("instanceId")?.asString),
                      IV.same(cached.get("principal")?.asString, trust.get("principal")?.asString) else { return no("bad-cache", "the cached head does not verify under the pinned log key") }
                let cs = IV.num(cached.get("size")) ?? .nan
                if headSize < cs { return no("log-rollback", "head size \(JS.number(headSize)) < cached \(JS.number(cs)): the log shrank") }
                if headSize == cs {
                    if !IV.same(head.get("root")?.asString, cached.get("root")?.asString) { return no("split-view", "two different roots at the same size: split view / fork") }
                } else if !Ledger.verifyHeadConsistency(cached, head, ev.get("consistency"), logKey, witnesses, pins) {
                    return no("inconsistent-with-cache", "no valid consistency proof from the cached head: forked or truncated log")
                }
            }

            guard entries.count <= MAX_FEED, Double(entries.count) == headSize, entries.allSatisfy({ validEntry($0) }) else { return no("feed-mismatch", "entries do not match the signed tree size") }
            let commits = try entries.map { try allowlistAnchorCommit($0) }
            if !IV.same(PCATransparencyLedger.rootOf(commits), head.get("root")?.asString) { return no("feed-mismatch", "entries do not reproduce the signed root") }

            let issuer = verified.get("issuer")?.asString ?? "", version = IV.num(verified.get("version")) ?? .nan, digest = verified.get("digest")?.asString ?? ""
            let mine = entries.filter { IV.same($0.get("issuer")?.asString, issuer) }
            // the log must not anchor two digests for one version of this issuer (decided before the proof checks, as the reference does)
            var byVersion: [Double: String] = [:]
            for e in mine {
                let v = IV.num(e.get("version"))!, d = e.get("digest")!.asString!
                if let prior = byVersion[v], !IV.same(prior, d) { return no("log-conflict", "log anchors two different digests for version \(JS.number(v))") }
                byVersion[v] = d
            }
            let highest = mine.reduce(0.0) { Swift.max($0, IV.num($1.get("version"))!) }
            if IV.num(proof.get("size")) != headSize { return no("bad-proof", "inclusion proof size does not match the signed head size") }
            let myCommit = try allowlistAnchorCommit(.object(["issuer": .string(issuer), "version": verified.get("version") ?? .null, "digest": .string(digest)]))
            if !Ledger.verifyInclusion(head.get("root")?.asString ?? "", proof, .string(myCommit)) { return no("bad-proof", "inclusion proof does not place this manifest under the signed root") }
            if version < highest { return no("anchored-rollback", "manifest version \(JS.number(version)) < highest anchored \(JS.number(highest)) for '\(issuer)'") }
            if !mine.contains(where: { IV.num($0.get("version")) == version && IV.same($0.get("digest")?.asString, digest) }) { return no("not-anchored", "this manifest digest is not the one anchored for its version") }
            return .object(["ok": .bool(true), "issuer": .string(issuer), "version": verified.get("version") ?? .null, "digest": .string(digest), "highestAnchoredVersion": StoreJ.num(highest), "head": head])
        } catch {
            return no("bad-head", (error as? JSError)?.message ?? "anchor verification error")
        }
    }
}
