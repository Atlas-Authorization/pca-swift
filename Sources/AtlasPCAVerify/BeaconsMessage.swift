import Foundation

extension Beacons {
    /// The signed message of a beacon: the domain `atlas-pca/beacon/v2\0`, then the strict canonical JSON of `{v, instance, scope, epoch, seq, issued_at,
    /// not_after, issuer}`, with `alg` and `pq_pk` bound in for a suite other than ed25519. Throws where the strict canonical form does (a missing member,
    /// a non-integer, a negative zero, a non-finite number).
    public static func livenessBeaconMessage(_ body: JSONValue) throws -> [UInt8] {
        guard case let .object(m) = body, let base = Ledger.pick(m, BODY_KEYS) else { throw JSError("canonicalize: unsupported type undefined") }
        let bound = IV.bindSuite(base, alg: m["alg"], pqPk: m["pq_pk"]) ?? base
        return try PCAIntentKit.message(LIVENESS_DOMAIN, .object(bound))
    }
}
