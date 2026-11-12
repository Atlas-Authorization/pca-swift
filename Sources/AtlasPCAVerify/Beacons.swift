import Foundation

// Dead-man liveness beacons v2: a port of `beacons.ts` (the TypeScript is authoritative). An issuer (the grant's principal, or the operator /
// guardian) signs short-lived beacons; authority is live only while a valid beacon covers the current moment, and the PCActn binds one through
// its signed `freshness.beacon_ref` (= `Beacons.beaconRef(b)`). Fail closed: an absent, stale, unpinned-issuer, wrong-scope or replayed beacon is
// frozen. Every signature suite this SDK verifies is accepted; a PQ half verifies only under a pin for the issuer.

/// `{ok, reason?}` of a beacon check.
public struct BeaconVerdict: Equatable, Sendable {
    public let ok: Bool
    public let reason: String?
    static let pass = BeaconVerdict(ok: true, reason: nil)
    static func no(_ r: String) -> BeaconVerdict { BeaconVerdict(ok: false, reason: r) }
}

public enum Beacons {
    public static let GLOBAL_SCOPE = "*"
    public static let LIVENESS_DOMAIN = "atlas-pca/beacon/v2\u{0}"
    /// Length of one beacon epoch.
    public static let BEACON_EPOCH_MS: Int64 = 60_000
    /// HARD ceiling on `not_after - issued_at`: no issuer can mint a longer-lived beacon.
    public static let BEACON_MAX_VALIDITY_MS: Int64 = 60 * 60_000
    /// Tolerated clock skew for a beacon issued "in the future".
    public static let BEACON_CLOCK_SKEW_MS: Int64 = 30_000
    static let BODY_KEYS = ["v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer"]

    /// A signed beacon. `validityMs` defaults to five epochs and may not exceed the hard maximum; the signature suite is the issuer key's.
    public static func issueLivenessBeacon(issuer: PCASuiteKey, instance: String, seq: Int64, issuedAt: Int64, scope: String = GLOBAL_SCOPE, validityMs: Int64? = nil) throws -> JSONValue {
        let validity = validityMs ?? 5 * BEACON_EPOCH_MS
        if seq < 0 { throw PCAProducerError("issueLivenessBeacon: seq must be a non-negative integer") }
        if issuedAt < 0 { throw PCAProducerError("issueLivenessBeacon: issuedAt must be an integer") }
        if validity <= 0 || validity > BEACON_MAX_VALIDITY_MS { throw PCAProducerError("issueLivenessBeacon: validity must be in (0, \(BEACON_MAX_VALIDITY_MS)] ms") }
        guard let id = issuer.ed?.id else { throw PCAProducerError("issueLivenessBeacon: the issuer needs an Ed25519 identity") }
        let body: JSONValue = .object([
            "v": .int(2), "instance": .string(instance), "scope": .string(scope), "epoch": .int(issuedAt / BEACON_EPOCH_MS), "seq": .int(seq),
            "issued_at": .int(issuedAt), "not_after": .int(issuedAt + validity), "issuer": .string(id),
        ])
        return .object(try PCAIssue.signArtifact(domain: LIVENESS_DOMAIN, body: body, signer: issuer))
    }

    /// The stable reference to a beacon: what the PCActn commits in `freshness.beacon_ref`. Throws where the reference throws.
    public static func beaconRef(_ b: JSONValue) throws -> String {
        guard let canon = IV.strictCanon(b) else { throw PDFail(what: "canonicalize") }
        return Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(canon)))
    }

    /// Signature, pinned issuer, instance and scope binding, the HARD maximum validity and the freshness window. `scope` (the grant id being
    /// exercised) must be covered by the beacon's (`*` or equal). `pqPins`: issuer identity -> pinned ML-DSA key. Never throws.
    public static func verifyLivenessBeacon(_ b: JSONValue?, issuers: [String], now: Int64, instance: String, scope: String? = nil, pqPins: [String: String]? = nil) -> BeaconVerdict {
        guard case let .object(m)? = b, IV.num(m["v"]) == 2, let alg = IV.sigAlg(m["alg"]), PCASuites.registered.contains(alg) else { return .no("malformed beacon") }
        if !IV.same(m["instance"]?.asString, instance) { return .no("wrong instance") }
        guard let issuer = m["issuer"]?.asString, issuers.contains(where: { IV.same($0, issuer) }) else { return .no("issuer not pinned") }
        guard let base = Ledger.pick(m, BODY_KEYS) else { return .no("malformed beacon") }
        if let bound = IV.bindSuite(base, alg: m["alg"], pqPk: m["pq_pk"]), IV.strictCanon(.object(bound)) == nil { return .no("malformed beacon") }
        if !Ledger.signed(issuer, LIVENESS_DOMAIN, base, m, pqPins) { return .no("bad signature") }
        let keys = ["epoch", "seq", "issued_at", "not_after"]
        guard keys.allSatisfy({ PD.isInteger(m[JKey($0)]) }), let epoch = IV.num(m["epoch"]), let seq = IV.num(m["seq"]), let issuedAt = IV.num(m["issued_at"]),
              let notAfter = IV.num(m["not_after"]), seq >= 0 else { return .no("malformed window") }
        if notAfter <= issuedAt || notAfter - issuedAt > Double(BEACON_MAX_VALIDITY_MS) { return .no("validity exceeds the hard maximum") }
        if epoch != (issuedAt / Double(BEACON_EPOCH_MS)).rounded(.down) { return .no("epoch does not match issued_at") }
        let n = Double(now)
        if n + Double(BEACON_CLOCK_SKEW_MS) < issuedAt { return .no("not yet valid") }
        if n > notAfter { return .no("expired") }
        if let sc = scope, !IV.same(m["scope"]?.asString, GLOBAL_SCOPE), !IV.same(m["scope"]?.asString, sc) { return .no("scope not covered") }
        return .pass
    }

    /// Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher `seq`. Total: a malformed beacon is refused.
    public static func acceptBeacon(prevSeq: JSONValue?, next: JSONValue?) -> BeaconVerdict {
        guard let nx = next, PD.isObj(nx), let seqV = nx.get("seq"), let seq = IV.num(seqV), PD.isInteger(seqV), abs(seq) <= Double(Canonical.MAX_SAFE), seq >= 0, !PD.negZero(seqV) else {
            return .no("malformed beacon")
        }
        if let p = prevSeq, !p.isNull {
            let ps = IV.num(p)
            if !(ps != nil && seq > ps!) { return .no("replayed beacon: seq \(PD.numStr(seq)) <= \(PD.js(p))") }
        }
        return .pass
    }

    /// Frozen unless at least one beacon verifies for (instance, scope, now). Absence is a freeze.
    public static func isFrozenLiveness(_ beacons: [JSONValue], issuers: [String], now: Int64, instance: String, scope: String? = nil, pqPins: [String: String]? = nil) -> Bool {
        !beacons.contains { verifyLivenessBeacon($0, issuers: issuers, now: now, instance: instance, scope: scope, pqPins: pqPins).ok }
    }

    /// `verifiedBeaconDecision`: `rejected`, `replayed`, `unbound`, `pass` or `not-enforced`.
    public static func beaconDecision(present: Bool, ok: Bool, replayed: Bool, refBinds: Bool) -> String {
        if !present { return "not-enforced" }
        if !ok { return "rejected" }
        if replayed { return "replayed" }
        return refBinds ? "pass" : "unbound"
    }

    /// Durable replay protection: keeps the highest accepted `seq` per (instance, scope, issuer) in an atomic key-value store, under one atomic
    /// read-modify-write. FAIL CLOSED: when the store cannot decide the beacon is refused with `beacon state unavailable`.
    public final class Acceptor: @unchecked Sendable {
        private let kv: AtomicKV
        public init(kv: AtomicKV) { self.kv = kv }

        static func key(_ b: JObject) -> String {
            "beacon-seq/v1/" + Canonical.canonicalize(.array([b["instance"] ?? .null, b["scope"] ?? .null, b["issuer"] ?? .null]))
        }

        public func accept(_ b: JSONValue, issuers: [String], now: Int64, instance: String, scope: String? = nil, pqPins: [String: String]? = nil) -> BeaconVerdict {
            let v = Beacons.verifyLivenessBeacon(b, issuers: issuers, now: now, instance: instance, scope: scope, pqPins: pqPins)
            if !v.ok { return v }
            guard case let .object(m) = b, let seq = IV.num(m["seq"]) else { return .no("malformed beacon") }
            var replayOf: Double?
            var junk = false
            do {
                try kv.update(Acceptor.key(m)) { prev in
                    if let p = prev {
                        guard PD.isInteger(p), let pv = IV.num(p), pv >= 0, pv <= Double(Canonical.MAX_SAFE), !PD.negZero(p) else {
                            junk = true // junk on disk: refused below
                            return nil
                        }
                        if !(seq > pv) {
                            replayOf = pv
                            return nil
                        }
                    }
                    return PD.num(seq)
                }
            } catch {
                return .no("beacon state unavailable")
            }
            if junk { return .no("beacon state unavailable") }
            if let r = replayOf { return .no("replayed beacon: seq \(PD.numStr(seq)) <= \(PD.numStr(r))") }
            return .pass
        }
    }
}
