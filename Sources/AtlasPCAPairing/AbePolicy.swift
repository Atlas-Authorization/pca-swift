import Foundation
import AtlasPCAVerify

/// Access structures for ciphertext-policy ABE: a monotone boolean formula as a threshold tree.
///
///     {attr}                      leaf
///     {allOf: [...]}              AND (n-of-n)
///     {anyOf: [...]}              OR  (1-of-n)
///     {threshold: k, of: [...]}   k-of-n
///
/// Attribute names compare by Unicode scalars (`JKey`), never by Swift's canonical equivalence.
final class AbeTree {
    let isLeaf: Bool
    let attr: JKey
    let t: Int
    let of: [AbeTree]

    init(leaf attr: String) { isLeaf = true; self.attr = JKey(attr); t = 0; of = [] }
    init(t: Int, of: [AbeTree]) { isLeaf = false; attr = JKey(""); self.t = t; self.of = of }

    /// The wire form {kind:"leaf",attr} / {kind:"gate",t,of}.
    func toJSON() -> JSONValue {
        if isLeaf { return .object(["kind": .string("leaf"), "attr": .string(attr.s)]) }
        return .object(["kind": .string("gate"), "t": .int(Int64(t)), "of": .array(of.map { $0.toJSON() })])
    }

    var leafCount: Int { isLeaf ? 1 : of.reduce(0) { $0 + $1.leafCount } }

    func leafAttrs(_ out: inout [JKey]) {
        if isLeaf { out.append(attr); return }
        for k in of { k.leafAttrs(&out) }
    }

    /// The first attribute named by two leaves (nil when none).
    func firstRepeatedAttribute() -> JKey? {
        var attrs: [JKey] = []
        leafAttrs(&attrs)
        var seen = Set<JKey>()
        for a in attrs { if !seen.insert(a).inserted { return a } }
        return nil
    }

    func satisfies(_ has: (JKey) -> Bool) -> Bool {
        if isLeaf { return has(attr) }
        return of.filter { $0.satisfies(has) }.count >= t
    }
}

enum AbePolicy {
    static let maxNodes = 1024
    /// Bounds gate nesting so that "encryptable" implies "decryptable" under the canonical JSON depth cap.
    static let maxDepth = 10

    static func num(_ v: JSONValue?) -> Double? {
        switch v { case let .int(i)?: return Double(i); case let .double(d)?: return d; default: return nil }
    }

    /// A JSON number that is a positive integer (JavaScript Number.isInteger semantics).
    static func posInt(_ v: JSONValue?) -> Double? {
        guard let f = num(v), f.isFinite, f > 0, f == f.rounded(.towardZero) else { return nil }
        return f
    }

    static func isNum(_ v: JSONValue?, _ want: Double) -> Bool { num(v) == want }

    static func fmtNum(_ f: Double) -> String { f < 1e21 && f == f.rounded() ? String(format: "%.0f", f) : "\(f)" }

    static func has(_ o: JObject, _ k: String) -> Bool { o[JKey(k)] != nil }

    /// Validates and normalises an access structure; on failure returns the reason (fails closed on any malformed node, empty gate,
    /// out-of-range threshold or oversized tree).
    static func normalize(_ policy: JSONValue) -> (tree: AbeTree?, reason: String?) {
        var nodes = 0
        func walk(_ p: JSONValue, _ path: String, _ gates: Int) -> (AbeTree?, String?) {
            nodes += 1
            if nodes > maxNodes { return (nil, "policy too large (> \(maxNodes) nodes)") }
            guard let m = p.objectValue else { return (nil, path + ": not an object") }
            if has(m, "attr") {
                guard let s = m[JKey("attr")]?.stringValue, !s.isEmpty else { return (nil, path + ": 'attr' must be a non-empty string") }
                if has(m, "allOf") || has(m, "anyOf") || has(m, "threshold") || has(m, "of") { return (nil, path + ": a leaf must not mix 'attr' with a gate") }
                return (AbeTree(leaf: s), nil)
            }
            var gateKeys: [String] = []
            for k in ["allOf", "anyOf", "threshold", "of"] where has(m, k) && (k != "of" || !has(m, "threshold")) { gateKeys.append(k) }
            if gateKeys.count > 1 {
                return (nil, "\(path): ambiguous node (\(gateKeys.joined(separator: ", "))); a gate must use exactly one of allOf/anyOf/threshold")
            }
            if gateKeys.count == 1 && gates + 1 > maxDepth { return (nil, "\(path): policy nested deeper than \(maxDepth) gates") }
            func children(_ raw: JSONValue?, _ key: String) -> ([AbeTree]?, String?) {
                guard let l = raw?.arrayValue, !l.isEmpty else { return (nil, "\(path): '\(key)' must be a non-empty array") }
                var out: [AbeTree] = []
                for (i, c) in l.enumerated() {
                    let (k, why) = walk(c, "\(path).\(key)[\(i)]", gates + 1)
                    if let w = why { return (nil, w) }
                    out.append(k!)
                }
                return (out, nil)
            }
            if has(m, "allOf") {
                let (kids, why) = children(m[JKey("allOf")], "allOf")
                if let w = why { return (nil, w) }
                return (AbeTree(t: kids!.count, of: kids!), nil)
            }
            if has(m, "anyOf") {
                let (kids, why) = children(m[JKey("anyOf")], "anyOf")
                if let w = why { return (nil, w) }
                return (AbeTree(t: 1, of: kids!), nil)
            }
            if has(m, "threshold") {
                guard let f = posInt(m[JKey("threshold")]) else { return (nil, path + ": 'threshold' must be a positive integer") }
                let (kids, why) = children(m[JKey("of")], "of")
                if let w = why { return (nil, w) }
                if f > Double(kids!.count) { return (nil, "\(path): threshold \(fmtNum(f)) exceeds the number of branches (\(kids!.count))") }
                return (AbeTree(t: Int(f), of: kids!), nil)
            }
            return (nil, path + ": unknown policy node (expected attr/allOf/anyOf/threshold)")
        }
        let (t, why) = walk(policy, "policy", 0)
        return why == nil ? (t, nil) : (nil, why)
    }

    /// Validates an untrusted ciphertext tree (nil on any deviation); a bounded node budget limits the work.
    static func parseTree(_ x: JSONValue?, _ gates: Int, _ nodes: inout Int) -> AbeTree? {
        nodes += 1
        guard nodes <= maxNodes, let m = x?.objectValue else { return nil }
        switch m[JKey("kind")]?.stringValue {
        case "leaf":
            guard let attr = m[JKey("attr")]?.stringValue, !attr.isEmpty, m.count == 2 else { return nil }
            return AbeTree(leaf: attr)
        case "gate":
            guard gates + 1 <= maxDepth, m.count == 3, let tf = posInt(m[JKey("t")]), let of = m[JKey("of")]?.arrayValue,
                  !of.isEmpty, tf <= Double(of.count), of.count < maxNodes else { return nil }
            var kids: [AbeTree] = []
            for b in of {
                guard let sub = parseTree(b, gates + 1, &nodes) else { return nil }
                kids.append(sub)
            }
            return AbeTree(t: Int(tf), of: kids)
        default:
            return nil
        }
    }

    /// The pure, non-cryptographic check that the attribute set satisfies the tree.
    static func satisfies(_ tree: JSONValue, _ attrs: [String]) -> Bool {
        var nodes = 0
        guard let t = parseTree(tree, 0, &nodes) else { return false }
        let set = Set(attrs.map { JKey($0) })
        return t.satisfies { set.contains($0) }
    }

    /// Every attribute named by the tree, unique and sorted; nil for an invalid tree.
    static func policyAttributes(_ tree: JSONValue) -> [String]? {
        var nodes = 0
        guard let t = parseTree(tree, 0, &nodes) else { return nil }
        var attrs: [JKey] = []
        t.leafAttrs(&attrs)
        return Array(Set(attrs)).sorted().map { $0.s }
    }
}
