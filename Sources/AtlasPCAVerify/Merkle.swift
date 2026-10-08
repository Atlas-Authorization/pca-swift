import Foundation

/// RFC-6962-shaped Merkle tree + plan-leaf construction, mirroring `merkle.ts` / the Rust reference.
/// Leaf = H(0x00 ‖ canon(leaf)), node = H(0x01 ‖ L ‖ R), split at the largest power of two < n.
enum Merkle {
    static let DEFAULT_REVERSIBILITY_CLASS = "reversible"

    static func leafHash(_ leaf: JSONValue) -> [UInt8] {
        var m: [UInt8] = [0x00]
        m.append(contentsOf: Canonical.utf8(Canonical.canonicalize(leaf)))
        return Canonical.sha256(m)
    }

    static func nodeHash(_ l: [UInt8], _ r: [UInt8]) -> [UInt8] {
        var m: [UInt8] = [0x01]
        m.append(contentsOf: l)
        m.append(contentsOf: r)
        return Canonical.sha256(m)
    }

    /// Largest power of two strictly less than n.
    static func split(_ n: UInt64) -> UInt64 {
        var k: UInt64 = 1
        while k * 2 < n { k *= 2 }
        return k
    }

    static func build(_ hs: [[UInt8]]) -> [UInt8] {
        if hs.count == 1 { return hs[0] }
        let k = Int(split(UInt64(hs.count)))
        return nodeHash(build(Array(hs[..<k])), build(Array(hs[k...])))
    }

    static func merkleRoot(_ leaves: [JSONValue]) -> String? {
        if leaves.isEmpty { return nil }
        return Base64URLStrict.encode(build(leaves.map(leafHash)))
    }

    /// Sibling sides (leaf → root) for leaf `index` in a tree of `size` leaves (RFC 6962 split).
    static func pathShape(_ index: UInt64, _ size: UInt64) -> [UInt8] {
        var out = [UInt8]()
        var idx = index
        var n = size
        while n > 1 {
            let k = split(n)
            if idx < k { out.append(UInt8(ascii: "R")); n = k }
            else { out.append(UInt8(ascii: "L")); idx -= k; n -= k }
        }
        out.reverse()
        return out
    }

    /// Never throws; malformed proofs return false. `index`/`size` are bound to the path shape.
    static func verifyInclusion(_ root: String, _ proof: [String: JSONValue]?, _ leaf: JSONValue) -> Bool {
        guard let proof = proof,
              let path = proof["path"]?.asArray,
              let index = proof["index"]?.safeInt,
              let size = proof["size"]?.safeInt else { return false }
        if size < 1 || index < 0 || index >= size { return false }
        let shape = pathShape(UInt64(index), UInt64(size))
        if shape.count != path.count { return false }
        var h = leafHash(leaf)
        for (i, step) in path.enumerated() {
            guard let s = step.asObject else { return false }
            let side = s["side"]?.asString ?? ""
            if Array(side.utf8) != [shape[i]] { return false }
            guard let sibStr = s["hash"]?.asString, let sib = Base64URLStrict.decode(sibStr, length: 32) else { return false }
            h = side == "L" ? nodeHash(sib, h) : nodeHash(h, sib)
        }
        return Base64URLStrict.encode(h) == root
    }

    /// hashCanonical(params ?? {}).
    static func paramsDigest(_ params: JSONValue?) -> String {
        if let p = params, !p.isNull { return Canonical.hashCanonical(p) }
        return Canonical.hashCanonical(.object([:]))
    }

    static func conditionsDigestDefault() -> String {
        Canonical.hashCanonical(.object(["pre": .null, "post": .null]))
    }

    /// Recompute the committed plan leaf for an action (the verifier never trusts the carried leaf).
    static func planLeaf(_ nodeId: JSONValue?, _ action: [String: JSONValue]?, _ cond: String) -> JSONValue? {
        guard let nodeId = nodeId, !nodeId.isNull else { return nil }
        func get(_ k: String) -> JSONValue { action?[k] ?? .null }
        let pd: JSONValue
        if case .null = get("params_digest") { pd = .string(paramsDigest(nil)) } else { pd = get("params_digest") }
        let rc: JSONValue
        if case .null = get("reversibility_class") { rc = .string(DEFAULT_REVERSIBILITY_CLASS) } else { rc = get("reversibility_class") }
        return .object([
            "node_id": nodeId,
            "verb": get("verb"),
            "resource": get("resource"),
            "params_digest": pd,
            "reversibility_class": rc,
            "conditions": .string(cond),
        ])
    }
}
