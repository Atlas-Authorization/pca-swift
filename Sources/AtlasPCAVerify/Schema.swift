import Foundation

/// The published JSON Schemas of the PCA wire types (PCActn, Capability, the discovery document) and the small structural validator
/// (reference: @atlasauth/pca-schema). The schemas describe structure only; they cannot express the verifier's invariants (signatures,
/// attenuation, plan inclusion). The validator checks the JSON type, required members, enum, `additionalProperties: false`, items and
/// local `#/...` references, and reports errors in the reference's order and wording. Member order matters for that order, so the
/// validator works on `PCASchema.Node`, an ordered JSON tree (a parsed `JSONValue` has no member order; `Node(json:)` uses the
/// code-unit order, index-like keys first).
public enum PCASchema {
    public indirect enum Node: Equatable {
        case null
        case bool(Bool)
        case num(Double)
        case str(String)
        case arr([Node])
        /// Members in the order JavaScript enumerates them (index-like keys ascending, then the rest in insertion order).
        case obj([(key: String, value: Node)])

        public static func == (a: Node, b: Node) -> Bool { PCASchema.stringify(a) == PCASchema.stringify(b) }

        public init(json: JSONValue) {
            switch json {
            case .null: self = .null
            case let .bool(b): self = .bool(b)
            case let .int(i): self = .num(Double(i))
            case let .double(d): self = .num(d)
            case let .string(s): self = .str(s)
            case let .array(a): self = .arr(a.map { Node(json: $0) })
            case let .object(o): self = .obj(o.keys.map { $0.s }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.map { (key: $0, value: Node(json: o[JKey($0)]!)) }.reordered())
            }
        }

        func member(_ k: String) -> Node? {
            if case let .obj(m) = self { return m.first { $0.key.unicodeScalars.elementsEqual(k.unicodeScalars) }?.value }
            return nil
        }

        var isRecord: Bool { if case .obj = self { return true }; return false }
        var isArray: Bool { if case .arr = self { return true }; return false }
        var isNull: Bool { if case .null = self { return true }; return false }
        /// JS truthiness.
        var truthy: Bool {
            switch self {
            case .null: return false
            case let .bool(b): return b
            case let .num(d): return d != 0 && !d.isNaN
            case let .str(s): return !s.isEmpty
            default: return true
            }
        }
    }

    // MARK: ordered JSON text

    /// Parses JSON text keeping member order; refuses what JSON refuses (a duplicate key keeps its first position and the last value, like JSON.parse).
    public static func parse(_ text: String) throws -> Node {
        var p = Parser(Array(text.utf8))
        let v = try p.value(0)
        p.ws()
        guard p.i == p.b.count else { throw JSError("JSON: trailing characters") }
        return v
    }

    struct Parser {
        let b: [UInt8]
        var i = 0
        init(_ b: [UInt8]) { self.b = b }

        mutating func ws() { while i < b.count, b[i] == 0x20 || b[i] == 0x0A || b[i] == 0x0D || b[i] == 0x09 { i += 1 } }

        mutating func value(_ depth: Int) throws -> Node {
            guard depth < 512 else { throw JSError("JSON: too deep") }
            ws()
            guard i < b.count else { throw JSError("JSON: unexpected end") }
            switch b[i] {
            case UInt8(ascii: "{"):
                i += 1
                var m: [(key: String, value: Node)] = []
                ws()
                if i < b.count, b[i] == UInt8(ascii: "}") { i += 1; return .obj(m) }
                while true {
                    ws()
                    guard i < b.count, b[i] == UInt8(ascii: "\"") else { throw JSError("JSON: expected a key") }
                    let k = try string()
                    ws()
                    guard i < b.count, b[i] == UInt8(ascii: ":") else { throw JSError("JSON: expected ':'") }
                    i += 1
                    let v = try value(depth + 1)
                    if let at = m.firstIndex(where: { $0.key.unicodeScalars.elementsEqual(k.unicodeScalars) }) { m[at].value = v } else { m.append((k, v)) }
                    ws()
                    guard i < b.count else { throw JSError("JSON: unexpected end") }
                    if b[i] == UInt8(ascii: ",") { i += 1; continue }
                    if b[i] == UInt8(ascii: "}") { i += 1; break }
                    throw JSError("JSON: expected ',' or '}'")
                }
                return .obj(m).reorderedObject()
            case UInt8(ascii: "["):
                i += 1
                var a: [Node] = []
                ws()
                if i < b.count, b[i] == UInt8(ascii: "]") { i += 1; return .arr(a) }
                while true {
                    a.append(try value(depth + 1))
                    ws()
                    guard i < b.count else { throw JSError("JSON: unexpected end") }
                    if b[i] == UInt8(ascii: ",") { i += 1; continue }
                    if b[i] == UInt8(ascii: "]") { i += 1; break }
                    throw JSError("JSON: expected ',' or ']'")
                }
                return .arr(a)
            case UInt8(ascii: "\""): return .str(try string())
            case UInt8(ascii: "t"): try lit("true"); return .bool(true)
            case UInt8(ascii: "f"): try lit("false"); return .bool(false)
            case UInt8(ascii: "n"): try lit("null"); return .null
            default: return .num(try number())
            }
        }

        mutating func lit(_ s: String) throws {
            let u = Array(s.utf8)
            guard i + u.count <= b.count, Array(b[i..<(i + u.count)]) == u else { throw JSError("JSON: bad literal") }
            i += u.count
        }

        mutating func number() throws -> Double {
            let s = i
            if i < b.count, b[i] == UInt8(ascii: "-") { i += 1 }
            while i < b.count, (b[i] >= 0x30 && b[i] <= 0x39) || b[i] == UInt8(ascii: ".") || b[i] == UInt8(ascii: "e") || b[i] == UInt8(ascii: "E") || b[i] == UInt8(ascii: "+") || b[i] == UInt8(ascii: "-") { i += 1 }
            guard let d = Double(String(decoding: b[s..<i], as: UTF8.self)), i > s else { throw JSError("JSON: bad number") }
            return d
        }

        mutating func hex4() throws -> UInt32 {
            guard i + 4 <= b.count, let v = UInt32(String(decoding: b[i..<(i + 4)], as: UTF8.self), radix: 16) else { throw JSError("JSON: bad \\u escape") }
            i += 4
            return v
        }

        mutating func string() throws -> String {
            i += 1
            var out: [UInt8] = []
            while true {
                guard i < b.count else { throw JSError("JSON: unterminated string") }
                let c = b[i]
                i += 1
                if c == UInt8(ascii: "\"") { break }
                if c < 0x20 { throw JSError("JSON: control character in a string") }
                if c != UInt8(ascii: "\\") { out.append(c); continue }
                guard i < b.count else { throw JSError("JSON: bad escape") }
                let e = b[i]
                i += 1
                switch e {
                case UInt8(ascii: "\""): out.append(0x22)
                case UInt8(ascii: "\\"): out.append(0x5C)
                case UInt8(ascii: "/"): out.append(0x2F)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    var v = try hex4()
                    if v >= 0xD800 && v < 0xDC00 {
                        guard i + 6 <= b.count, b[i] == UInt8(ascii: "\\"), b[i + 1] == UInt8(ascii: "u") else { throw JSError("JSON: lone surrogate") }
                        i += 2
                        let lo = try hex4()
                        guard lo >= 0xDC00 && lo < 0xE000 else { throw JSError("JSON: lone surrogate") }
                        v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00)
                    } else if v >= 0xDC00 && v < 0xE000 { throw JSError("JSON: lone surrogate") }
                    guard let sc = Unicode.Scalar(v) else { throw JSError("JSON: bad scalar") }
                    out += Array(String(Character(sc)).utf8)
                default: throw JSError("JSON: bad escape")
                }
            }
            return String(decoding: out, as: UTF8.self)
        }
    }

    // MARK: JSON.stringify of a node (compact)

    static func quote(_ s: String) -> String {
        var o = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": o += "\\\""
            case "\\": o += "\\\\"
            case "\u{08}": o += "\\b"
            case "\u{0C}": o += "\\f"
            case "\n": o += "\\n"
            case "\r": o += "\\r"
            case "\t": o += "\\t"
            default:
                if u.value < 0x20 { o += String(format: "\\u%04x", u.value) } else { o.unicodeScalars.append(u) }
            }
        }
        return o + "\""
    }

    public static func stringify(_ n: Node) -> String {
        switch n {
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case let .num(d): return d.isFinite ? IntentV2.jsString(.double(d)) : "null"
        case let .str(s): return quote(s)
        case let .arr(a): return "[" + a.map { stringify($0) }.joined(separator: ",") + "]"
        case let .obj(m): return "{" + m.map { quote($0.key) + ":" + stringify($0.value) }.joined(separator: ",") + "}"
        }
    }

    /// `String(x)` for a node used as a property key or inside `Array#join` (null joins as the empty string).
    static func text(_ n: Node) -> String {
        switch n {
        case .null: return ""
        case let .bool(b): return b ? "true" : "false"
        case let .num(d): return IntentV2.jsString(.double(d))
        case let .str(s): return s
        case let .arr(a): return a.map { text($0) }.joined(separator: ",")
        case .obj: return "[object Object]"
        }
    }

    // MARK: the validator

    public struct Result { public let valid: Bool; public let errors: [String] }

    static func jsonType(_ n: Node) -> String {
        switch n {
        case .null: return "null"
        case .arr: return "array"
        case let .num(d): return d.isFinite && d.rounded(.towardZero) == d ? "integer" : "number"
        case .bool: return "boolean"
        case .str: return "string"
        case .obj: return "object"
        }
    }

    static func matches(_ expected: Node, _ v: Node) -> Bool {
        guard case let .str(t) = expected else { return false }
        switch t {
        case "object": return v.isRecord
        case "array": return v.isArray
        case "string": if case .str = v { return true }; return false
        case "number": if case let .num(d) = v { return d.isFinite }; return false
        case "integer": if case let .num(d) = v { return d.isFinite && d.rounded(.towardZero) == d && !(d == 0 && d.sign == .minus) }; return false
        case "boolean": if case .bool = v { return true }; return false
        case "null": return v.isNull
        default: return false
        }
    }

    static func strictEqual(_ a: Node, _ b: Node) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case let (.bool(x), .bool(y)): return x == y
        case let (.num(x), .num(y)): return x == y
        case let (.str(x), .str(y)): return x.unicodeScalars.elementsEqual(y.unicodeScalars)
        default: return false // objects and arrays compare by identity: two parsed values are never the same object
        }
    }

    static func resolve(_ root: Node, _ ref: String) -> Node? {
        guard ref.hasPrefix("#/") else { return nil }
        var cur = root
        for token in ref.dropFirst(2).split(separator: "/", omittingEmptySubsequences: false) {
            guard let next = cur.member(String(token)) else { return nil }
            cur = next
        }
        return cur.isRecord ? cur : nil
    }

    static func label(_ p: String) -> String { p.isEmpty ? "(root)" : p }

    static func check(_ schema: Node, _ value: Node, _ path: String, _ root: Node, _ errors: inout [String], _ depth: Int) throws {
        guard depth < 400 else { throw JSError("Maximum call stack size exceeded") }
        if schema.isNull { throw JSError("Cannot read properties of null (reading '$ref')") }
        guard case .obj = schema else { return }
        if case let .str(ref)? = schema.member("$ref") {
            guard let resolved = resolve(root, ref) else { errors.append("\(label(path)): unresolved $ref '\(ref)'"); return }
            try check(resolved, value, path, root, &errors, depth + 1)
            return
        }
        if let t = schema.member("type") {
            let types: [Node]
            if case let .arr(a) = t { types = a } else { types = [t] }
            if !types.contains(where: { matches($0, value) }) {
                errors.append("\(label(path)): expected type \(types.map { text($0) }.joined(separator: "|")), got \(jsonType(value))")
                return
            }
        }
        if case let .arr(en)? = schema.member("enum"), !en.contains(where: { strictEqual($0, value) }) {
            errors.append("\(label(path)): value is not one of [\(en.map { stringify($0) }.joined(separator: ", "))]")
        }
        let prefix = path.isEmpty ? "" : path + "."
        if case let .obj(vm) = value {
            if case let .arr(req)? = schema.member("required") {
                for k in req {
                    let key = text(k)
                    if !vm.contains(where: { $0.key.unicodeScalars.elementsEqual(key.unicodeScalars) }) { errors.append("\(prefix)\(key): missing required property '\(key)'") }
                }
            }
            let props = schema.member("properties")
            var entries: [(key: String, value: Node)] = []
            if case let .obj(pm)? = props { entries = pm } else if case let .arr(pa)? = props { entries = pa.enumerated().map { (String($0.offset), $0.element) } }
            for (k, sub) in entries {
                if let v = vm.first(where: { $0.key.unicodeScalars.elementsEqual(k.unicodeScalars) })?.value { try check(sub, v, "\(prefix)\(k)", root, &errors, depth + 1) }
            }
            if case .bool(false)? = schema.member("additionalProperties"), props?.truthy ?? false {
                let allowed = entries.map { $0.key }
                for (k, _) in vm where !allowed.contains(where: { $0.unicodeScalars.elementsEqual(k.unicodeScalars) }) {
                    errors.append("\(prefix)\(k): additional property not allowed")
                }
            }
        }
        if case let .arr(items) = value, let it = schema.member("items"), it.truthy {
            for (i, el) in items.enumerated() { try check(it, el, "\(path)[\(i)]", root, &errors, depth + 1) }
        }
    }

    /// Validates a value against a schema; a null schema (or a runaway `$ref` cycle) throws, like the reference.
    public static func validate(_ schema: Node, _ value: Node) throws -> Result {
        var errors: [String] = []
        try check(schema, value, "", schema, &errors, 0)
        return Result(valid: errors.isEmpty, errors: errors)
    }

    // MARK: the published schemas

    /// The three schemas as the reference publishes them (JSON, member order preserved).
    static let allText = #"""
{"PCActn":{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://atlasauth.net/schemas/pca/pcactn.schema.json","title":"PCActn","description":"Proof-Carrying Authority action object (spec §7, wire format v2).","type":"object","required":["ver","action","grant_ref","cap_chain","plan","attestation","provenance","freshness","counter","risk_claim","aud","iat","exp","sig"],"properties":{"ver":{"type":"integer"},"action":{"$ref":"#/$defs/action"},"grant_ref":{"type":"string"},"cap_chain":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/capability"}},"plan":{"$ref":"#/$defs/plan"},"attestation":{"$ref":"#/$defs/attestation"},"provenance":{"$ref":"#/$defs/provenance"},"freshness":{"$ref":"#/$defs/freshness"},"counter":{"type":"integer"},"risk_claim":{"$ref":"#/$defs/riskClaim"},"aud":{"type":"string"},"iat":{"type":"integer"},"exp":{"type":"integer"},"nonce":{"type":"string"},"caution":{"type":"number"},"rationale_commitment":{"type":"string"},"progress_step":{"type":"object","additionalProperties":true},"prohibition_evidence":{"type":["object","array"]},"tool_binding":{"type":"string"},"alg":{"type":"string","enum":["ed25519","ml-dsa-65","hybrid-ed25519-ml-dsa-65"]},"pq_pk":{"type":"string"},"sig":{"type":"string"},"pq_sig":{"type":"string"},"threshold":{"type":"object","additionalProperties":true},"zk_compliance":{"description":"Opaque zk-compliance proof; shape is verifier-defined."},"bond_ref":{"type":"string"}},"additionalProperties":true,"$defs":{"caveat":{"type":"object","required":["type"],"properties":{"type":{"type":"string"}},"additionalProperties":true},"capability":{"type":"object","required":["id","issuer","holder","caveats","body_digest","sig"],"properties":{"id":{"type":"string"},"issuer":{"type":"string"},"holder":{"type":"string"},"caveats":{"type":"array","items":{"$ref":"#/$defs/caveat"}},"parent":{"type":"string"},"body_digest":{"type":"string"},"sig":{"type":"string"},"alg":{"type":"string","enum":["ed25519","ml-dsa-65","hybrid-ed25519-ml-dsa-65"]},"pq_pk":{"type":"string"},"pq_sig":{"type":"string"}},"additionalProperties":true},"action":{"type":"object","required":["verb","resource","params_digest","reversibility_class"],"properties":{"verb":{"type":"string"},"resource":{"type":"string"},"params_digest":{"type":"string"},"reversibility_class":{"type":"string"}},"additionalProperties":true},"inclusionProof":{"type":"object","required":["index","size","path"],"properties":{"index":{"type":"integer"},"size":{"type":"integer"},"path":{"type":"array","items":{"type":"object","additionalProperties":true}}},"additionalProperties":true},"plan":{"type":"object","required":["root","inclusion_proof","node_id"],"properties":{"root":{"type":"string"},"inclusion_proof":{"$ref":"#/$defs/inclusionProof"},"node_id":{"type":"string"},"conditions_digest":{"type":"string"}},"additionalProperties":true},"riskClaim":{"type":"object","required":["r","inputs"],"properties":{"r":{"type":"number"},"inputs":{"type":"object","additionalProperties":true}},"additionalProperties":true},"attestation":{"type":"object","required":["quote_digest","epoch","model_id","measurement","operator"],"properties":{"quote_digest":{"type":"string"},"epoch":{"type":"integer"},"model_id":{"type":"string"},"measurement":{"type":"string"},"operator":{"type":"string"}},"additionalProperties":true},"provenance":{"type":"object","required":["causal_hash","taint_level","trusted_refs"],"properties":{"causal_hash":{"type":"string"},"taint_level":{"type":"number"},"trusted_refs":{"type":"array","items":{"type":"string"}}},"additionalProperties":true},"freshness":{"type":"object","required":["beacon_ref","epoch","accumulator_witness"],"properties":{"beacon_ref":{"type":"string"},"epoch":{"type":"integer"},"accumulator_witness":{"type":"string"}},"additionalProperties":true}}},"Capability":{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://atlasauth.net/schemas/pca/capability.schema.json","title":"Capability","description":"An attenuable capability chain hop (spec §5.2).","type":"object","required":["id","issuer","holder","caveats","body_digest","sig"],"properties":{"id":{"type":"string"},"issuer":{"type":"string"},"holder":{"type":"string"},"caveats":{"type":"array","items":{"$ref":"#/$defs/caveat"}},"parent":{"type":"string"},"body_digest":{"type":"string"},"sig":{"type":"string"},"alg":{"type":"string","enum":["ed25519","ml-dsa-65","hybrid-ed25519-ml-dsa-65"]},"pq_pk":{"type":"string"},"pq_sig":{"type":"string"}},"additionalProperties":true,"$defs":{"caveat":{"type":"object","required":["type"],"properties":{"type":{"type":"string"}},"additionalProperties":true}}},"PcaDiscoveryDocument":{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://atlasauth.net/schemas/pca/discovery.schema.json","title":"PcaDiscoveryDocument","description":"The .well-known/pca-configuration discovery document (internet-wide integration).","type":"object","required":["audience","pca_versions","signature_suites","action_header"],"properties":{"audience":{"type":"string"},"pca_versions":{"type":"array","items":{"type":"integer"}},"signature_suites":{"type":"array","items":{"type":"string"}},"action_header":{"type":"string"},"required_checks":{"type":"array","items":{"type":"string"}},"endpoints":{"$ref":"#/$defs/endpoints"},"trusted_roots":{"type":"array","items":{"type":"string"}},"metadata":{"type":"object","additionalProperties":true}},"additionalProperties":true,"$defs":{"endpoints":{"type":"object","properties":{"attestation_challenge":{"type":"string"},"revocation_epoch":{"type":"string"},"liveness_beacon":{"type":"string"},"stepup":{"type":"string"},"grant":{"type":"string"}},"additionalProperties":true}}}}
"""#

    /// `{PCActn, Capability, PcaDiscoveryDocument}` in the reference's member order.
    public static let all: Node = try! parse(allText)
    public static func named(_ name: String) -> Node? { all.member(name) }
    public static var pcactn: Node { all.member("PCActn")! }
    public static var capability: Node { all.member("Capability")! }
    public static var discovery: Node { all.member("PcaDiscoveryDocument")! }
    public static func validate(named name: String, _ value: Node) throws -> Result {
        guard let s = named(name) else { throw JSError("unknown schema \(name)") }
        return try validate(s, value)
    }
}

extension PCASchema.Node {
    /// Index-like keys first (ascending), then the rest in the order given.
    func reorderedObject() -> PCASchema.Node {
        guard case let .obj(m) = self else { return self }
        return .obj(m.reordered())
    }
}

extension Array where Element == (key: String, value: PCASchema.Node) {
    func reordered() -> [(key: String, value: PCASchema.Node)] {
        let idx = self.compactMap { e in JS.indexKey(e.key).map { ($0, e) } }.sorted { $0.0 < $1.0 }.map { $0.1 }
        return idx + self.filter { JS.indexKey($0.key) == nil }
    }
}
