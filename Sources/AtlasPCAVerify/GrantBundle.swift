import Foundation

/// Signed policy bundles and decision records of `pca-grants` (bundle.ts): the signing, masking, log and batch sides. Verification (`K3.verifyBundle`,
/// `K3.verifyLogHead`, `K3.verifyRecordInclusion`, `K3.verifyBatch`, `K3.bundleDigest`, `K3.compareVersion`, `K3.recordCommit`) is carried by `K3`.
extension PCAGrants {
    public static let BUNDLE_DOMAIN = K3.BUNDLE_DOMAIN
    public static let RECORD_DOMAIN = K3.RECORD_DOMAIN
    public static let LOG_HEAD_DOMAIN = K3.LOG_HEAD_DOMAIN

    /// The commit of one decision record; throws outside the strict profile, like the reference.
    public static func recordCommit(_ record: JSONValue) throws -> String {
        guard let c = K3.recordCommit(record) else { throw PCAProducerError("recordCommit: not strict-canonical") }
        return c
    }

    private static func bodyOf(_ b: JObject) -> JObject {
        var out = b
        out[JKey("sigs")] = nil
        return out
    }

    /// One signer's `{signer, sig}` over the bundle body. Collect k of them and call `assembleBundle`. Throws on a malformed body.
    public static func signBundle(_ body: JObject, _ secret: PCAEdKey) throws -> JSONValue {
        if let e = K3.bundleShapeError(.object(body)) { throw PCAProducerError("signBundle: " + e) }
        return .object(["signer": .string(secret.id), "sig": .string(try signBody(BUNDLE_DOMAIN, .object(bodyOf(body)), secret))])
    }

    public static func assembleBundle(_ body: JObject, _ sigs: [JSONValue]) -> JSONValue {
        var b = bodyOf(body)
        b["sigs"] = .array(sigs)
        return .object(b)
    }

    /// Mask by data CLASS: every detail field whose class is in `maskClasses` becomes a commitment. Returns the record itself when it has no detail or classes.
    public static func maskRecord(_ r: JObject, _ maskClasses: [String]) throws -> JObject {
        guard let detail = r["detail"]?.asObject, let classes = r["classes"]?.asObject else { return r }
        var out: JObject = [:]
        for (k, v) in detail {
            if let cls = classes[k]?.asString, maskClasses.contains(where: { IV.same($0, cls) }) {
                guard let h = IV.strictHash(.object(["d": .string("atlas-pca/mask/v1"), "k": .string(k.s), "v": v])) else { throw PCAProducerError("maskRecord: not strict-canonical") }
                out[k] = .string("masked:" + cls + ":" + h)
            } else {
                out[k] = v
            }
        }
        var res = r
        res["detail"] = .object(out)
        return res
    }

    /// RFC 6962 inclusion proof `{index, size, path: [{side, hash}]}` (leaf to root) for leaf `index`; throws when out of range.
    public static func merkleProof(_ leaves: [JSONValue], _ index: Int) throws -> JSONValue {
        guard index >= 0, index < leaves.count else { throw PCAProducerError("merkleProof: index out of range") }
        let hs = leaves.map { Merkle.leafHash($0) }
        var path: [JSONValue] = []
        func prove(_ h: ArraySlice<[UInt8]>, _ idx: Int) {
            if h.count == 1 { return }
            let k = Int(Merkle.split(UInt64(h.count)))
            let arr = Array(h)
            if idx < k {
                prove(arr[..<k], idx)
                path.append(.object(["side": .string("R"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(arr[k...]))))]))
            } else {
                prove(arr[k...], idx - k)
                path.append(.object(["side": .string("L"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(arr[..<k]))))]))
            }
        }
        prove(hs[...], index)
        return .object(["index": .int(Int64(index)), "size": .int(Int64(leaves.count)), "path": .array(path)])
    }

    /// Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs.
    public final class DecisionLog: @unchecked Sendable {
        private var recs: [JObject] = []
        private let secret: PCAEdKey
        private let maskClasses: [String]
        private let lock = PCALock()

        public init(_ secret: PCAEdKey, maskClasses: [String] = []) { self.secret = secret; self.maskClasses = maskClasses }

        public var size: Int { lock.lock(); defer { lock.unlock() }; return recs.count }

        /// Mask, chain and store a record (without v, seq, prev); returns the stored record.
        public func append(_ r: JObject) throws -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            let masked = try PCAGrants.maskRecord(r, maskClasses)
            var rec: JObject = ["v": .int(1)]
            for (k, v) in masked { rec[k] = v }
            rec["seq"] = .int(Int64(recs.count))
            rec["prev"] = .string(try recs.last.map { try PCAGrants.recordCommit(.object($0)) } ?? "")
            recs.append(rec)
            return .object(rec)
        }

        private func commits() throws -> [JSONValue] { try recs.map { .string(try PCAGrants.recordCommit(.object($0))) } }

        public func head(_ now: Int64) throws -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            guard let last = recs.last else { throw PCAProducerError("head: an empty log has no root") }
            guard let root = Merkle.merkleRoot(try commits()) else { throw PCAProducerError("head: an empty log has no root") }
            let base: JObject = ["v": .int(1), "size": .int(Int64(recs.count)), "root": .string(root), "last_commit": .string(try PCAGrants.recordCommit(.object(last))),
                                 "issued_at": .int(now), "signer": .string(secret.id)]
            var out = base
            out["sig"] = .string(try PCAGrants.signBody(PCAGrants.LOG_HEAD_DOMAIN, .object(base), secret))
            return .object(out)
        }

        public func proof(_ seq: Int) throws -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            return try PCAGrants.merkleProof(try commits(), seq)
        }

        /// Records [from, to) clamped to the log (JavaScript slice semantics for non-negative bounds).
        public func slice(_ from: Int, _ to: Int) -> [JSONValue] {
            lock.lock(); defer { lock.unlock() }
            let a = min(max(from, 0), recs.count)
            let b = min(max(to, a), recs.count)
            return recs[a..<b].map { .object($0) }
        }
    }

    /// The next batch of at most `max` records from `from` with a freshly signed head: `{from, records, head}`.
    public static func nextBatch(_ log: DecisionLog, from: JSONValue?, max: JSONValue?, now: JSONValue?) throws -> JSONValue {
        guard let f = K3Sig.safeInt(from), let m = IV.safe(max), m >= 1, let nowMs = IV.safe(now) else { throw PCAProducerError("nextBatch: bad cursor or size") }
        let lo = Int(Swift.min(f, Int64(Int32.max))), hi = Int(Swift.min(f + Int64(m), Int64(Int32.max)))
        return .object(["from": .int(f), "records": .array(log.slice(lo, hi)), "head": try log.head(Int64(nowMs))])
    }
}
