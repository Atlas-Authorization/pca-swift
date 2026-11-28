import Foundation

/// What the caveat language needs to know about a chain: how many hops, the leaf, and per hop its hash and the length of its (cumulative)
/// caveat list. A full chain gives it directly; a compact chain gives it from a verified memo without the middle hops.
public struct ChainView {
    public let n: Int
    public let leaf: JSONValue
    public let hash: (Int) -> String
    public let count: (Int) -> Int
    public init(n: Int, leaf: JSONValue, hash: @escaping (Int) -> String, count: @escaping (Int) -> Int) {
        self.n = n
        self.leaf = leaf
        self.hash = hash
        self.count = count
    }
}

/// Chain compaction: a long delegation chain folds into one handle, a Merkle root over the ordered hop hashes, plus the leaf hop. A verifier that has
/// verified the full chain once remembers it under that root (`Memo`); later presentations carry only `{depth, hops_root, leaf}`. The root commits to
/// the order and the number of hops. Nothing is trusted from the presentation: a compact chain is accepted only when the verifier's OWN memo holds an
/// entry for `hops_root` that its own chain verification produced (`rememberVerified` runs the verification itself), the depth equals the memoized
/// depth and the presented leaf hashes to the memoized last hop.
public enum PCAChainCompact {
    public static let CHAIN_HOP_DOMAIN = "atlas-pca/chain-hop/v1"
    /// A memo entry lives at most this long.
    public static let CHAIN_MEMO_MAX_TTL_MS: Double = 3_600_000
    public static let CHAIN_MEMO_DEFAULT_MAX_ENTRIES = 10_000
    public static let MAX_CHAIN_DEPTH = Capability.MAX_CHAIN_DEPTH

    /// The Merkle leaf of one hop: its content hash under a domain tag, `{d, hop}`.
    public static func hopLeaf(_ hop: JSONValue) -> JSONValue { .object(["d": .string(CHAIN_HOP_DOMAIN), "hop": .string(Capability.capHash(hop))]) }

    /// The handle of a chain: Merkle root over the ordered hop leaves. Throws on an empty chain.
    public static func hopsRoot(_ chain: [JSONValue]) throws -> String {
        guard let r = Merkle.merkleRoot(chain.map(hopLeaf)) else { throw JSError("merkleRoot: empty leaf set") }
        return r
    }

    /// Fold a chain into `{v:1, kind, depth, hops_root, leaf}`. Throws on an empty or over-deep chain. Does not verify it (the memo does).
    public static func compactChain(_ chain: [JSONValue]) throws -> JSONValue {
        guard !chain.isEmpty, chain.count <= MAX_CHAIN_DEPTH else { throw JSError("compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops") }
        return .object(["v": .int(1), "kind": .string("pca-chain-compact"), "depth": .int(Int64(chain.count)), "hops_root": .string(try hopsRoot(chain)), "leaf": chain[chain.count - 1]])
    }

    /// Why a presented compact chain is malformed, or nil.
    public static func compactChainShapeError(_ c: JSONValue?) -> String? {
        guard let o = c?.asObject else { return "not an object" }
        if let e = IntentWB.closedMembersError(o, ["v", "kind", "depth", "hops_root", "leaf"], [], "compact chain") { return e }
        if o["v"] != .int(1) && o["v"] != .double(1) || o["kind"]?.asString != "pca-chain-compact" { return "not a pca-chain-compact v1" }
        guard let d = o["depth"]?.safeInt, d >= 1, d <= Int64(MAX_CHAIN_DEPTH) else { return "depth must be 1..\(MAX_CHAIN_DEPTH)" }
        _ = d
        guard let r = o["hops_root"]?.asString, r.utf16.count == 43 else { return "hops_root must be a 43 character digest" }
        _ = r
        guard o["leaf"]?.isObject == true else { return "leaf must be a capability" }
        return nil
    }

    private static func safeClock(_ now: Double) -> Bool { now.isFinite && now.rounded() == now && abs(now) <= 9_007_199_254_740_991 }

    private static func caveatCount(_ h: JSONValue) -> Int { h.get("caveats")?.asArray?.count ?? 0 }

    /// The view of a full chain (root first), else of the grant alone.
    public static func viewOfChain(_ grant: JSONValue, _ chain: [JSONValue]?) -> ChainView {
        let hops: [JSONValue] = (chain?.isEmpty == false) ? chain! : [grant]
        final class Cache: @unchecked Sendable { var m: [Int: String] = [:] }
        let cache = Cache()
        return ChainView(n: hops.count, leaf: hops[hops.count - 1], hash: { i in
            if let h = cache.m[i] { return h }
            let h = Capability.capHash(hops[i])
            cache.m[i] = h
            return h
        }, count: { caveatCount(hops[$0]) })
    }

    /// The outcome of `Memo.resolve`: `view` when ok, else `reason`.
    public struct Resolved {
        public let ok: Bool
        public let view: ChainView?
        public let reason: String?
    }

    private struct Entry {
        let depth: Int
        let hashes: [String]
        let counts: [Int]
        let expiresAt: Double
    }

    /// The verifier's memory of chains it verified itself. Thread-safe.
    public final class Memo: @unchecked Sendable {
        private let lock = NSLock()
        private var entries: [String: Entry] = [:]
        private let maxEntries: Int
        private let ttlMs: Double

        public init(maxEntries: Int? = nil, ttlMs: Double? = nil) {
            self.maxEntries = maxEntries ?? PCAChainCompact.CHAIN_MEMO_DEFAULT_MAX_ENTRIES
            self.ttlMs = Swift.min(ttlMs ?? PCAChainCompact.CHAIN_MEMO_MAX_TTL_MS, PCAChainCompact.CHAIN_MEMO_MAX_TTL_MS)
        }

        public var size: Int { lock.lock(); defer { lock.unlock() }; return entries.count }

        /// Verify `chain` (rooted at `expectedRootIssuer`) with the full verifier and remember it; answers the compact form a holder presents. Throws when
        /// the chain does not verify or the memo is full of live entries (a full memo never evicts a live entry, so one tenant cannot push another out).
        public func rememberVerified(_ chain: [JSONValue], expectedRootIssuer: String?, now: Double, allowedSuites: [String]? = nil,
                                     pqPins: [String: String]? = nil, trustedRoot: JSONValue? = nil) throws -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            guard PCAChainCompact.safeClock(now) else { throw JSError("rememberVerified: the clock is not a safe integer") }
            if let why = Capability.verifyChain(chain, expectedRootIssuer: expectedRootIssuer, allowedSuites: allowedSuites, pqPins: pqPins, trustedRoot: trustedRoot) {
                throw JSError("rememberVerified: the chain does not verify: \(why)")
            }
            let compact = try PCAChainCompact.compactChain(chain)
            pruneLocked(now)
            let root = compact.get("hops_root")?.asString ?? ""
            if entries[root] == nil && entries.count >= maxEntries { throw JSError("rememberVerified: the memo is full of live entries") }
            entries[root] = Entry(depth: chain.count, hashes: chain.map { Capability.capHash($0) }, counts: chain.map(PCAChainCompact.caveatCount), expiresAt: now + ttlMs)
            return compact
        }

        private func pruneLocked(_ now: Double) { entries = entries.filter { now.isFinite && $0.value.expiresAt >= now } }

        /// Drop entries whose time is up.
        public func prune(_ now: Double) { lock.lock(); defer { lock.unlock() }; pruneLocked(now) }

        /// Forget a chain (for example when it is revoked).
        @discardableResult
        public func forget(_ hopsRoot: String) -> Bool { lock.lock(); defer { lock.unlock() }; return entries.removeValue(forKey: hopsRoot) != nil }

        private func no(_ r: String) -> Resolved { Resolved(ok: false, view: nil, reason: r) }

        /// Resolve a presented compact chain against the memo. Total.
        public func resolve(_ compact: JSONValue?, now: Double) -> Resolved {
            lock.lock(); defer { lock.unlock() }
            guard PCAChainCompact.safeClock(now) else { return no("the verifier clock is not a safe integer (fail closed)") }
            if let e = PCAChainCompact.compactChainShapeError(compact) { return no("malformed compact chain: \(e)") }
            guard let c = compact, let root = c.get("hops_root")?.asString, let leaf = c.get("leaf"), let depth = c.get("depth")?.safeInt else { return no("compact chain error (fail closed): malformed") }
            guard let m = entries[root] else { return no("the chain is not in this verifier memo (present the full chain)") }
            if !(m.expiresAt >= now) {
                entries.removeValue(forKey: root)
                return no("the memoized chain has expired (present the full chain)")
            }
            if Int64(m.depth) != depth { return no("the depth differs from the memoized chain") }
            if Capability.capHash(leaf) != m.hashes[m.depth - 1] { return no("the leaf is not the memoized last hop") }
            guard leaf.get("caveats")?.asArray != nil, PCAChainCompact.caveatCount(leaf) == m.counts[m.depth - 1] else { return no("the leaf caveats differ from the memoized chain") }
            return Resolved(ok: true, view: ChainView(n: m.depth, leaf: leaf, hash: { m.hashes[$0] }, count: { m.counts[$0] }), reason: nil)
        }
    }
}
