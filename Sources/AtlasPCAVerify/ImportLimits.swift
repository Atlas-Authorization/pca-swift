import Foundation

/// The bounds every importer enforces before it believes a byte of foreign input: size, depth, node count and reference expansion.
public struct ImportLimits: Sendable {
    public let maxBytes: Int64, maxOps: Int64, maxJsonDepth: Int64, maxNodes: Int64, maxRefNodes: Int64, maxRefDepth: Int64

    public init(maxBytes: Int64, maxOps: Int64, maxJsonDepth: Int64, maxNodes: Int64, maxRefNodes: Int64, maxRefDepth: Int64) {
        self.maxBytes = maxBytes; self.maxOps = maxOps; self.maxJsonDepth = maxJsonDepth; self.maxNodes = maxNodes; self.maxRefNodes = maxRefNodes; self.maxRefDepth = maxRefDepth
    }

    private func of(_ i: Int) -> Int64 { [maxBytes, maxOps, maxJsonDepth, maxNodes, maxRefNodes, maxRefDepth][i] }

    /// The limits as the reference spells them.
    public var json: JSONValue {
        AK.obj(["max_bytes": .int(maxBytes), "max_ops": .int(maxOps), "max_json_depth": .int(maxJsonDepth), "max_nodes": .int(maxNodes), "max_ref_nodes": .int(maxRefNodes), "max_ref_depth": .int(maxRefDepth)])
    }

    /// Size check of a text source (UTF-8 bytes).
    public func textSizeCheck(_ text: String) throws {
        if Int64(text.utf16.count) * 3 > maxBytes && Int64(text.utf8.count) > maxBytes { throw ActionKitError(code: "import_limit", message: "the source is larger than \(maxBytes) bytes") }
    }

    /// Walk a parsed source iteratively and refuse it when it is not plain JSON data, or is deeper or larger than the limits. Returns the node count.
    @discardableResult
    public func checkParsed(_ root: JSONValue?) throws -> Int64 {
        var nodes: Int64 = 0, bytes: Int64 = 0
        var stack: [(JSONValue?, Int64)] = [(root, 0)]
        while let (v, d) = stack.popLast() {
            nodes += 1
            if nodes > maxNodes { throw ActionKitError(code: "import_limit", message: "the source has more than \(maxNodes) nodes") }
            if d > maxJsonDepth { throw ActionKitError(code: "import_limit", message: "the source nests deeper than \(maxJsonDepth)") }
            switch v {
            case nil, .null?, .bool?: bytes += 4
            case let .string(s)?: bytes += Int64(s.utf16.count)
            case let .array(a)?:
                bytes += 2 + Int64(a.count)
                for x in a { stack.append((x, d + 1)) }
            case let .object(o)?:
                for (k, x) in o {
                    bytes += Int64(k.s.utf16.count) + 4
                    stack.append((x, d + 1))
                }
            case let .int(i)?:
                _ = i
                bytes += 8
            case let .double(x)?:
                if x.isNaN || x.isInfinite { throw ActionKitError(code: "bad_source", message: "the source holds a non-finite number") }
                bytes += 8
            }
            if bytes > maxBytes { throw ActionKitError(code: "import_limit", message: "the source is larger than \(maxBytes) bytes") }
        }
        return nodes
    }

    public static let DEFAULT = ImportLimits(maxBytes: 64 * 1024 * 1024, maxOps: 20_000, maxJsonDepth: 64, maxNodes: 6_000_000, maxRefNodes: 20_000, maxRefDepth: 8)

    /// Ceilings no caller may raise past: a caller-supplied limit is clamped to these.
    public static let HARD = ImportLimits(maxBytes: 256 * 1024 * 1024, maxOps: 50_000, maxJsonDepth: 128, maxNodes: 20_000_000, maxRefNodes: 200_000, maxRefDepth: 16)

    private static let KEYS = ["max_bytes", "max_ops", "max_json_depth", "max_nodes", "max_ref_nodes", "max_ref_depth"]

    /// Defaults, overridden member by member (clamped to the hard ceilings); a member that is not a positive safe integer is refused.
    public static func resolve(_ over: JSONValue?) throws -> ImportLimits {
        var out = [Int64](repeating: 0, count: 6)
        for i in 0..<6 {
            out[i] = DEFAULT.of(i)
            guard case let .object(o)? = over, let v = o[JKey(KEYS[i])] else { continue }
            guard Jx.isSafe(v), let d = IV.num(v), d >= 1 else { throw ActionKitError(code: "bad_limit", message: "limit \(KEYS[i]) must be a positive safe integer") }
            out[i] = min(Int64(d), HARD.of(i))
        }
        return ImportLimits(maxBytes: out[0], maxOps: out[1], maxJsonDepth: out[2], maxNodes: out[3], maxRefNodes: out[4], maxRefDepth: out[5])
    }
}
