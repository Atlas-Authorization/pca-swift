import Foundation

/// RFC 9162 section 2.1 Merkle tree (SHA-256): tree hash, inclusion paths and consistency proofs, with the verification algorithms of
/// sections 2.1.3.2 and 2.1.4.2. Leaf inputs are the raw entry bytes (`SHA-256(0x00 || entry)`), so any independent RFC 9162 / RFC 6962
/// verifier can check a proof given the same entry bytes.
public enum PCARfc9162 {
    /// Root hash of the empty tree: SHA-256 of the empty string.
    public static func emptyRoot() -> [UInt8] { Canonical.sha256([]) }

    public static func leafHash(_ entry: [UInt8]) -> [UInt8] { Canonical.sha256([0x00] + entry) }

    public static func nodeHash(_ left: [UInt8], _ right: [UInt8]) -> [UInt8] { Canonical.sha256([0x01] + left + right) }

    /// Largest power of two strictly less than n (n >= 2).
    static func splitPoint(_ n: Int) -> Int {
        var k = 1
        while k * 2 < n { k *= 2 }
        return k
    }

    /// MTH over already-hashed leaves (section 2.1.1).
    public static func treeHash(_ leafHashes: [[UInt8]]) -> [UInt8] {
        let n = leafHashes.count
        if n == 0 { return emptyRoot() }
        if n == 1 { return leafHashes[0] }
        let k = splitPoint(n)
        return nodeHash(treeHash(Array(leafHashes[..<k])), treeHash(Array(leafHashes[k...])))
    }

    /// Inclusion path for leaf `index` (section 2.1.3.1), bottom-up.
    public static func inclusionPath(_ leafHashes: [[UInt8]], _ index: Int64) throws -> [[UInt8]] {
        let n = leafHashes.count
        guard index >= 0, index < Int64(n) else { throw JSError("rfc9162: leaf index out of range") }
        if n == 1 { return [] }
        let k = splitPoint(n)
        if index < Int64(k) { return try inclusionPath(Array(leafHashes[..<k]), index) + [treeHash(Array(leafHashes[k...]))] }
        return try inclusionPath(Array(leafHashes[k...]), index - Int64(k)) + [treeHash(Array(leafHashes[..<k]))]
    }

    /// Recompute the root from a leaf hash and its inclusion path (section 2.1.3.2); nil when (index, size, path length) is invalid.
    public static func rootFromInclusionPath(_ leaf: [UInt8], _ index: Int64, _ size: Int64, _ path: [[UInt8]]) -> [UInt8]? {
        let maxSafe = Canonical.MAX_SAFE
        if index < 0 || size < 1 || index >= size || index > maxSafe || size > maxSafe { return nil }
        if leaf.count != 32 || path.contains(where: { $0.count != 32 }) { return nil }
        var fn = UInt64(index)
        var sn = UInt64(size) - 1
        var r = leaf
        for p in path {
            if sn == 0 { return nil }
            if fn & 1 == 1 || fn == sn {
                r = nodeHash(p, r)
                if fn & 1 == 0 {
                    while fn & 1 == 0 && fn != 0 { fn >>= 1; sn >>= 1 }
                }
            } else {
                r = nodeHash(r, p)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 ? r : nil
    }

    public static func verifyInclusionPath(_ leaf: [UInt8], _ index: Int64, _ size: Int64, _ path: [[UInt8]], _ root: [UInt8]) -> Bool {
        guard let computed = rootFromInclusionPath(leaf, index, size, path) else { return false }
        return computed == root
    }

    private static func subproof(_ m: Int, _ d: [[UInt8]], _ complete: Bool) -> [[UInt8]] {
        let n = d.count
        if m == n { return complete ? [] : [treeHash(d)] }
        let k = splitPoint(n)
        if m <= k { return subproof(m, Array(d[..<k]), complete) + [treeHash(Array(d[k...]))] }
        return subproof(m - k, Array(d[k...]), false) + [treeHash(Array(d[..<k]))]
    }

    /// Consistency proof between the first `m` leaves and all of `leafHashes` (section 2.1.4.1).
    public static func consistencyPath(_ leafHashes: [[UInt8]], _ m: Int64) throws -> [[UInt8]] {
        guard m >= 1, m <= Int64(leafHashes.count) else { throw JSError("rfc9162: consistency size out of range") }
        return subproof(Int(m), leafHashes, true)
    }

    /// Verify a consistency proof between a tree of `first` leaves (root `firstRoot`) and one of `second` leaves (root `secondRoot`)
    /// per section 2.1.4.2. A proof from an empty tree is rejected.
    public static func verifyConsistencyPath(_ first: Int64, _ second: Int64, _ firstRoot: [UInt8], _ secondRoot: [UInt8], _ path: [[UInt8]]) -> Bool {
        let maxSafe = Canonical.MAX_SAFE
        if first < 1 || second < first || first > maxSafe || second > maxSafe { return false }
        if firstRoot.count != 32 || secondRoot.count != 32 || path.contains(where: { $0.count != 32 }) { return false }
        if first == second { return path.isEmpty && firstRoot == secondRoot }
        if path.isEmpty { return false }
        var nodes = path
        if first & (first - 1) == 0 { nodes.insert(firstRoot, at: 0) } // first is an exact power of two
        var fn = UInt64(first) - 1
        var sn = UInt64(second) - 1
        while fn & 1 == 1 { fn >>= 1; sn >>= 1 }
        var fr = nodes[0]
        var sr = nodes[0]
        for c in nodes.dropFirst() {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                fr = nodeHash(c, fr)
                sr = nodeHash(c, sr)
                if fn & 1 == 0 {
                    while fn & 1 == 0 && fn != 0 { fn >>= 1; sn >>= 1 }
                }
            } else {
                sr = nodeHash(sr, c)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 && fr == firstRoot && sr == secondRoot
    }
}
