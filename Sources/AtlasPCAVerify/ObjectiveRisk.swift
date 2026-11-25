import Foundation

/// The objective risk functional (the reference's `objective-risk`): every input of the risk of an action is recomputed from COMMITTED facts and the
/// CANONICAL action only (a registry of verified inverses, a resource graph, a committed embedder and goal, a calibration set, a harm currency); nothing
/// the agent asserts is read. Any commitment mismatch gives r = 1 with `valid: false`. Digests are the LENIENT canonical hash (any finite double, printed
/// as ECMAScript prints it). Actions, goals, configs and results are the reference's objects as JSON trees; a refusal throws a `JSError` with the
/// reference's message (the verify and distance paths return it as their reason).
public enum PCAObjectiveRisk {
    public static let METRIC = "half-chord-v1"
    public static let DEFAULT_EPSILON = 1.0 / 4096.0
    public static let NATIVE_SCHEME = "pca-native-hash-ngram-v1"
    public static let DEFAULT_MAX_PARAM_LEAVES = 256
    public static let DEFAULT_NATIVE_CONFIG: JSONValue = .object([
        "dims": .int(256), "ngramMin": .int(2), "ngramMax": .int(4), "seed": .string("pca-native-v1"),
        "fieldWeights": .object(["verb": .int(4), "resource": .int(2), "param": .int(1)]),
    ])

    // ---- JavaScript value semantics ----

    private static func n(_ d: Double) -> JSONValue { d.isFinite ? PCAFacade.jsNum(d) : .double(d) }
    private static func fin(_ v: JSONValue?) -> Double? { ToolSchema.fin(v) }
    /// Number.isSafeInteger
    private static func safeInt(_ v: JSONValue?) -> Int64? { v?.safeInt }
    private static func jsMin(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return .nan }
        if a == 0 && b == 0 { return a.sign == .minus ? a : b }
        return Swift.min(a, b)
    }
    private static func jsMax(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return .nan }
        if a == 0 && b == 0 { return a.sign == .minus ? b : a }
        return Swift.max(a, b)
    }
    /// The file's own `clamp01`: a non-finite value is the worst case 1.
    private static func clamp01(_ x: Double) -> Double { x.isFinite ? (x < 0 ? 0 : (x > 1 ? 1 : x)) : 1 }
    /// `a < b` over JavaScript strings (UTF-16 code units).
    private static func lessU16(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }
    private static func sameU16(_ a: String, _ b: String) -> Bool { a.utf16.elementsEqual(b.utf16) }
    /// JavaScript `===` / SameValueZero over JSON values (numbers by value, strings by code unit).
    private static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if let x = fin(a), let y = fin(b) { return x == y }
        if case let .string(x)? = a, case let .string(y)? = b { return sameU16(x, y) }
        if a?.isNumber == true || b?.isNumber == true { return false }
        return a == b
    }
    private static func err(_ m: String) -> JSError { JSError(m) }

    /// ECMAScript `String.prototype.trim` (WhiteSpace and LineTerminator).
    static func jsTrim(_ s: String) -> String {
        func ws(_ u: Unicode.Scalar) -> Bool {
            switch u.value {
            case 0x09...0x0D, 0x20, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF: return true
            default: return false
            }
        }
        var sc = Array(s.unicodeScalars)
        while let l = sc.last, ws(l) { sc.removeLast() }
        var i = 0
        while i < sc.count, ws(sc[i]) { i += 1 }
        var out = String.UnicodeScalarView()
        out.append(contentsOf: sc[i...])
        return String(out)
    }

    /// ECMAScript `String.prototype.toLowerCase`: the locale-independent full mapping (`İ` becomes `i` and U+0307) with the final-sigma rule.
    static func jsLower(_ s: String) -> String {
        let sc = Array(s.unicodeScalars)
        func cased(_ u: Unicode.Scalar) -> Bool { u.properties.isCased }
        func ignorable(_ u: Unicode.Scalar) -> Bool { u.properties.isCaseIgnorable }
        var out = ""
        for (i, u) in sc.enumerated() {
            if u.value == 0x3A3 {
                var j = i - 1
                while j >= 0, ignorable(sc[j]) { j -= 1 }
                let before = j >= 0 && cased(sc[j])
                var k = i + 1
                while k < sc.count, ignorable(sc[k]) { k += 1 }
                let after = k < sc.count && cased(sc[k])
                out += (before && !after) ? "\u{3C2}" : "\u{3C3}"
            } else {
                out += u.properties.lowercaseMapping
            }
        }
        return out
    }

    private static func nfc(_ s: String) -> String { s.precomposedStringWithCanonicalMapping }

    private static func hasNonFinite(_ v: JSONValue) -> Bool {
        switch v {
        case let .double(d): return !d.isFinite
        case let .array(a): return a.contains(where: hasNonFinite)
        case let .object(o): return o.values.contains(where: hasNonFinite)
        default: return false
        }
    }

    /// The lenient canonical text; throws the reference's TypeError for what has no stable encoding.
    static func canon(_ v: JSONValue) throws -> String {
        let s = Canonical.canonicalize(v)
        if s.isEmpty { throw err(hasNonFinite(v) ? "canonicalize: non-finite number" : "canonicalize: nesting too deep") }
        return s
    }

    static func hash(_ v: JSONValue) throws -> String { _ = try canon(v); return Canonical.hashCanonical(v) }

    /// A member that is absent in the reference (`undefined`) cannot be encoded.
    private static func req(_ v: JSONValue?) throws -> JSONValue {
        guard let v = v else { throw err("canonicalize: unsupported type undefined") }
        return v
    }

    // ---- canonical action ----

    private static func normValue(_ v: JSONValue) throws -> JSONValue {
        switch v {
        case let .string(s): return .string(nfc(s))
        case let .array(a): return .array(try a.map(normValue))
        case let .object(o):
            var out = JObject()
            for k in JS.keyOrder(o) {
                let nk = JKey(nfc(k.s))
                if out[nk] != nil { throw err("canonicalAction: duplicate key after NFC normalization") }
                out[nk] = try normValue(o[k]!)
            }
            return .object(out)
        default: return v
        }
    }

    /// Verb trimmed, lower-cased and NFC; resource trimmed and NFC; every string and key of the params NFC; the whole validated by the canonical
    /// encoder. `{verb, resource, params}`. Re-encodings that do not change the action collapse to one form.
    public static func canonicalAction(_ a: JSONValue?) throws -> JSONValue {
        guard case let .string(v0)? = a?.get("verb"), case let .string(r0)? = a?.get("resource") else { throw err("canonicalAction: verb/resource must be strings") }
        let verb = jsLower(jsTrim(nfc(v0))), resource = jsTrim(nfc(r0))
        if verb.isEmpty || resource.isEmpty { throw err("canonicalAction: empty verb/resource") }
        let params = try normValue(JS.present(a?.get("params")) ?? .object([:]))
        guard case .object = params else { throw err("canonicalAction: params must be an object") }
        let c: JSONValue = .object(["verb": .string(verb), "resource": .string(resource), "params": params])
        _ = try canon(c)
        return c
    }

    public static func canonicalActionJson(_ c: JSONValue) throws -> String { try canon(c) }
    public static func canonicalActionDigest(_ c: JSONValue) throws -> String { try hash(c) }

    // ---- reversibility: a committed registry of verified inverses ----

    /// The committed registry of verified inverses: `lookup(verb)` is exact (no canonicalisation); `digest()` commits every entry and the trusted verifiers.
    public final class InverseRegistry {
        private var trusted: [String] = []
        private var m: [[UInt16]: (verb: String, entry: JSONValue)] = [:]
        public init(trustedVerifiers: [String] = []) {
            var seen: [[UInt16]] = []
            var uniq: [String] = []
            for t in trustedVerifiers where !seen.contains(Array(t.utf16)) { seen.append(Array(t.utf16)); uniq.append(t) }
            trusted = uniq.sorted { PCAObjectiveRisk.lessU16($0, $1) }
        }
        @discardableResult
        public func register(_ verb: String, _ e: JSONValue) -> Self {
            m[Array(verb.utf16)] = (verb, e)
            return self
        }
        public func lookup(_ verb: String) -> JSONValue? { m[Array(verb.utf16)]?.entry }
        public func trustedVerifiers() -> [String] { trusted }
        public func digest() throws -> String {
            let entries = try m.values.sorted { PCAObjectiveRisk.lessU16($0.verb, $1.verb) }.map { x -> JSONValue in
                .object(["verb": .string(x.verb), "inverseKind": try PCAObjectiveRisk.req(x.entry.get("inverseKind")), "fidelity": try PCAObjectiveRisk.req(x.entry.get("fidelity")),
                         "verification": JS.present(x.entry.get("verification")) ?? .null])
            }
            return try PCAObjectiveRisk.hash(.object(["v": .int(1), "trusted": .array(trusted.map { .string($0) }), "entries": .array(entries)]))
        }
    }

    /// `{class, value, inverseKind?}`: reversible (1) or compensable (0.5) iff the registry holds an inverse verified by a TRUSTED verifier AND the
    /// inverse verb is authorized; anything else is irreversible (0). `fidelity` `exact` is reversible, any other fidelity compensable.
    public static func reversibility(verb: JSONValue?, registry: InverseRegistry, authorizedKinds: [String]) -> JSONValue {
        let irreversible: JSONValue = .object(["class": .string("irreversible"), "value": .int(0)])
        guard case let .string(v)? = verb, let e = registry.lookup(v) else { return irreversible }
        var trusted = false
        if let ver = JS.present(e.get("verification")), case let .string(id)? = ver.get("verifierId") {
            trusted = registry.trustedVerifiers().contains { sameU16($0, id) }
        }
        guard trusted, case let .string(kind)? = e.get("inverseKind"), authorizedKinds.contains(where: { sameU16($0, kind) }) else { return irreversible }
        let exact = e.get("fidelity") == .string("exact")
        return .object(["class": .string(exact ? "reversible" : "compensable"), "value": exact ? .int(1) : .double(0.5), "inverseKind": .string(kind)])
    }

    // ---- blast radius: reachability over a committed resource graph ----

    /// Adjacency model with a content digest. A node added again replaces the node and keeps its edges; an edge needs both endpoints.
    public final class ResourceGraph {
        private var nodes: [[UInt16]: JSONValue] = [:]
        private var order: [String] = []
        private var out: [[UInt16]: [JSONValue]] = [:]
        public init() {}
        @discardableResult
        public func addNode(_ node: JSONValue) throws -> Self {
            guard case let .string(id)? = node.get("id") else { throw JSError("graph node needs a string id") }
            let k = Array(id.utf16)
            if nodes[k] == nil { order.append(id) }
            nodes[k] = node
            if out[k] == nil { out[k] = [] }
            return self
        }
        @discardableResult
        public func addEdge(_ e: JSONValue) throws -> Self {
            guard case let .string(f)? = e.get("from"), case let .string(t)? = e.get("to"), nodes[Array(f.utf16)] != nil, nodes[Array(t.utf16)] != nil else {
                throw JSError("edge endpoints must exist")
            }
            out[Array(f.utf16), default: []].append(e)
            return self
        }
        public var size: Int { nodes.count }
        public func node(_ id: JSONValue?) -> JSONValue? { if case let .string(s)? = id { return nodes[Array(s.utf16)] }; return nil }

        /// The reachable set from `start` (including it), restricted by edge kind and depth, sorted by code unit.
        public func reachable(_ start: JSONValue?, _ scope: JSONValue? = nil) -> [String] {
            guard case let .string(s)? = start, nodes[Array(s.utf16)] != nil else { return [] }
            let kinds = scope?.get("edgeKinds")?.asArray
            let maxDepth: Double = JS.present(scope?.get("maxDepth")).map { JS.toNumber($0) } ?? .infinity
            var seen: [[UInt16]] = [Array(s.utf16)]
            var seenSet: Set<[UInt16]> = [Array(s.utf16)]
            var frontier = [s]
            var d = 0.0
            while d < maxDepth && !frontier.isEmpty {
                var next: [String] = []
                for u in frontier {
                    for e in out[Array(u.utf16)] ?? [] {
                        guard case let .string(to)? = e.get("to") else { continue }
                        if let ks = kinds, !ks.contains(where: { PCAObjectiveRisk.same($0, e.get("kind")) }) { continue }
                        if seenSet.insert(Array(to.utf16)).inserted { seen.append(Array(to.utf16)); next.append(to) }
                    }
                }
                frontier = next
                d += 1
            }
            return seen.map { String(decoding: $0, as: UTF16.self) }.sorted { PCAObjectiveRisk.lessU16($0, $1) }
        }

        public func digest() throws -> String {
            let ns = nodes.values.map { x -> (String, JSONValue) in
                (x.get("id")?.asString ?? "", .object(["id": x.get("id") ?? .null, "harm": JS.present(x.get("harm")) ?? .object([:])]))
            }.sorted { PCAObjectiveRisk.lessU16($0.0, $1.0) }.map { $0.1 }
            var es: [(String, JSONValue)] = []
            for list in out.values {
                for e in list {
                    let key = "\(e.get("from")?.asString ?? "")\u{0}\(e.get("to")?.asString ?? "")\u{0}\(JS.toString(e.get("kind")))"
                    es.append((key, .object(["from": try PCAObjectiveRisk.req(e.get("from")), "to": try PCAObjectiveRisk.req(e.get("to")), "kind": try PCAObjectiveRisk.req(e.get("kind"))])))
                }
            }
            return try PCAObjectiveRisk.hash(.object(["v": .int(1), "n": .array(ns), "e": .array(es.sorted { PCAObjectiveRisk.lessU16($0.0, $1.0) }.map { $0.1 })]))
        }
    }

    /// `{count, reachable, normalized, harm}`: the reachable count over the graph size (an unknown resource or an empty graph is 1, fail closed), and
    /// the per-denomination harm of the reachable nodes (finite positive values only).
    public static func blastRadius(resource: JSONValue?, graph: ResourceGraph, scope: JSONValue? = nil) -> JSONValue {
        let reach = graph.reachable(resource, scope)
        if reach.isEmpty || graph.size == 0 { return .object(["count": .int(0), "reachable": .array(reach.map { .string($0) }), "normalized": .int(1), "harm": .object([:])]) }
        var harm = JObject()
        for id in reach {
            guard case let .object(h)? = graph.node(.string(id))?.get("harm") else { continue }
            for (k, v) in h { if let x = fin(v), x > 0 { harm[k] = n((fin(harm[k]) ?? 0) + x) } }
        }
        return .object(["count": .int(Int64(reach.count)), "reachable": .array(reach.map { .string($0) }), "normalized": n(Double(reach.count) / Double(graph.size)), "harm": .object(harm)])
    }

    // ---- committed embeddings ----

    /// Maps the canonical action to an integer vector (a JSON array; a custom embedder may return anything and is validated by the callers).
    public struct Embedder {
        public var modelId: JSONValue
        /// The committed descriptor behind `modelId` (the native config or the BYO descriptor).
        public var config: JSONValue
        public var dims: Double
        public var embed: (JSONValue) throws -> JSONValue
        public init(modelId: JSONValue, config: JSONValue, dims: Double, embed: @escaping (JSONValue) throws -> JSONValue) {
            self.modelId = modelId; self.config = config; self.dims = dims; self.embed = embed
        }
    }

    private static func maxComponent(_ dims: Double) -> Double { floor(sqrt(Double(Canonical.MAX_SAFE) / (2 * jsMax(1, dims)))) }

    /// Exactly `dims` safe integers, each within the range that keeps a dot product of two such vectors exact; `-0` becomes 0.
    public static func validateVector(_ v: JSONValue?, _ dims: Double) throws -> [JSONValue] {
        guard case let .array(a)? = v, Double(a.count) == dims else { throw err("vector must have exactly \(JS.toString(n(dims))) components") }
        let lim = maxComponent(dims)
        for x in a {
            guard safeInt(x) != nil else { throw err("vector components must be safe integers") }
            if abs(fin(x)!) > lim { throw err("vector component out of range") }
        }
        return a.map { safeInt($0).map { JSONValue.int($0) } ?? $0 }
    }

    private static func nativeConfigError(_ c: JSONValue?) -> String? {
        func okInt(_ v: JSONValue?, _ lo: Double, _ hi: Double) -> Bool { safeInt(v) != nil && fin(v)! >= lo && fin(v)! <= hi }
        if !okInt(c?.get("dims"), 8, 65536) { return "native config: dims must be an integer in [8, 65536]" }
        let nmin = c?.get("ngramMin")
        if !okInt(nmin, 1, 8) || !okInt(c?.get("ngramMax"), fin(nmin) ?? 1, 8) { return "native config: need 1 <= ngramMin <= ngramMax <= 8" }
        guard case let .string(seed)? = c?.get("seed"), !seed.isEmpty else { return "native config: seed required" }
        for k in ["verb", "resource", "param"] where !okInt(c?.get("fieldWeights")?.get(k), 0, 1000) { return "native config: fieldWeights.\(k) must be an integer in [0, 1000]" }
        if let m = c?.get("maxParamLeaves"), !okInt(m, 1, 1_000_000) { return "native config: maxParamLeaves must be an integer in [1, 1000000]" }
        if let p = c?.get("paramMode"), p != .string("leaves"), p != .string("digest") { return "native config: paramMode must be 'leaves' or 'digest'" }
        return nil
    }

    /// Flatten params to `path=value` leaves (object keys in UTF-8 order, arrays by index).
    private static func paramLeaves(_ v: JSONValue, _ path: String, _ out: inout [String]) throws {
        switch v {
        case let .array(a): for (i, x) in a.enumerated() { try paramLeaves(x, "\(path)[\(i)]", &out) }
        case let .object(o):
            for k in o.keys.sorted(by: { Canonical.compareUtf8($0.s, $1.s) < 0 }) { try paramLeaves(o[k]!, path.isEmpty ? k.s : "\(path).\(k.s)", &out) }
        default: out.append("\(path)=\(try canon(v))")
        }
    }

    /// Code-point n-grams of `U+0002 text U+0003` for n in nmin...nmax (`<prefix>c<n>:<gram>`), then the lower-cased words, the runs of letters and digits.
    private static func textFeatures(_ prefix: String, _ text: String, _ nmin: Int, _ nmax: Int) -> [String] {
        var out: [String] = []
        let cps = Array("\u{2}\(text)\u{3}".unicodeScalars)
        for n in nmin...nmax where n <= cps.count {
            for i in 0...(cps.count - n) {
                var g = String.UnicodeScalarView()
                g.append(contentsOf: cps[i..<(i + n)])
                out.append("\(prefix)c\(n):\(String(g))")
            }
        }
        var word = String.UnicodeScalarView()
        func flush() { if !word.isEmpty { out.append("\(prefix)w:\(jsLower(String(word)))"); word = String.UnicodeScalarView() } }
        for u in text.unicodeScalars {
            let gc = u.properties.generalCategory
            switch gc {
            case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter, .decimalNumber, .letterNumber, .otherNumber: word.append(u)
            default: flush()
            }
        }
        flush()
        return out
    }

    /// The native embedder: integer feature hashing over the canonical action. Each feature is hashed as SHA-256(seed, 0x1F, feature); the bucket is the
    /// big-endian u32 of its first four bytes modulo `dims` and the sign the low bit of the fifth byte; the bucket accumulates the field weight with that
    /// sign. More param leaves than the cap fail closed. `modelId = "native:" + hash({scheme, ...config})`.
    public static func nativeHashEmbedder(_ config: JSONValue? = nil) throws -> Embedder {
        let cfg = config ?? DEFAULT_NATIVE_CONFIG
        if let m = nativeConfigError(cfg) { throw err(m) }
        guard var committed = cfg.asObject else { throw err("native config: dims must be an integer in [8, 65536]") }
        committed["scheme"] = .string(NATIVE_SCHEME)
        let committedV = JSONValue.object(committed)
        let modelId = "native:" + (try hash(committedV))
        let dims = Int(safeInt(cfg.get("dims"))!), nmin = Int(safeInt(cfg.get("ngramMin"))!), nmax = Int(safeInt(cfg.get("ngramMax"))!)
        let seed = Array("\(cfg.get("seed")!.asString!)\u{1F}".utf8)
        let wv = Int(safeInt(cfg.get("fieldWeights")?.get("verb"))!), wr = Int(safeInt(cfg.get("fieldWeights")?.get("resource"))!), wp = Int(safeInt(cfg.get("fieldWeights")?.get("param"))!)
        let cap = safeInt(cfg.get("maxParamLeaves")).map { Int($0) } ?? DEFAULT_MAX_PARAM_LEAVES
        let digestMode = cfg.get("paramMode") == .string("digest")
        return Embedder(modelId: .string(modelId), config: committedV, dims: Double(dims)) { a in
            var v = [Int](repeating: 0, count: dims)
            func add(_ feat: String, _ w: Int) {
                if w == 0 { return }
                let h = Canonical.sha256(seed + Array(feat.utf8))
                var word: UInt32 = UInt32(h[0])
                word = (word << 8) | UInt32(h[1])
                word = (word << 8) | UInt32(h[2])
                word = (word << 8) | UInt32(h[3])
                let bucket = Int(word % UInt32(dims))
                v[bucket] += (h[4] & 1) == 0 ? w : -w
            }
            guard case let .string(verb)? = a.get("verb"), case let .string(resource)? = a.get("resource") else { throw err("Cannot read properties of undefined (reading 'verb')") }
            for f in textFeatures("v:", verb, nmin, nmax) { add(f, wv) }
            for f in textFeatures("r:", resource, nmin, nmax) { add(f, wr) }
            var leaves: [String] = []
            try paramLeaves(a.get("params") ?? .null, "", &leaves)
            if leaves.count > cap { throw err("param leaf count \(leaves.count) exceeds cap \(cap)") }
            if digestMode {
                add("p#:" + (try hash(.object(["t": .string("pca-objrisk-params-v1"), "params": try req(a.get("params"))]))), wp)
            } else {
                for leaf in leaves { for f in textFeatures("p:", leaf, nmin, nmax) { add(f, wp) } }
            }
            return .array(v.map { .int(Int64($0)) })
        }
    }

    public static func byoModelId(_ d: JSONValue) throws -> String { "byo:" + (try hash(d)) }

    /// A customer-supplied model that meets the determinism contract: `infer` receives the canonical action JSON and returns the integer vector, whose
    /// components must lie within the declared quantization range. A claimed model id must equal the descriptor hash.
    public static func byoEmbedder(_ descriptor: JSONValue, claimedModelId: String? = nil, infer: @escaping (String) throws -> JSONValue) throws -> Embedder {
        guard let dims = safeInt(descriptor.get("dims")), dims >= 1 else { throw err("byo: dims must be a positive integer") }
        guard let q = descriptor.get("quantization"), q != .null else { throw err("Cannot read properties of undefined (reading 'bits')") }
        guard let bits = safeInt(q.get("bits")), bits >= 2, bits <= 31, JS.toNumber(q.get("scale")) > 0 else { throw err("byo: invalid quantization") }
        if descriptor.get("inputEncoding") != .string("pca-canonical-action-json-v1") { throw err("byo: unsupported inputEncoding") }
        let modelId = try byoModelId(descriptor)
        if let c = claimedModelId, !sameU16(c, modelId) { throw err("byo: modelId does not match the committed descriptor") }
        let qmax = pow(2.0, Double(bits - 1)) - 1
        return Embedder(modelId: .string(modelId), config: descriptor, dims: Double(dims)) { a in
            let v = try validateVector(try infer(try canonicalActionJson(a)), Double(dims))
            for x in v where abs(fin(x)!) > qmax { throw err("byo: component exceeds declared quantization range") }
            return .array(v)
        }
    }

    /// True iff every case `{action, vector}` shipped with a model reproduces exactly.
    public static func conformanceCheck(_ e: Embedder, _ cases: [JSONValue]) -> Bool {
        do {
            return try cases.allSatisfy { c in
                let v = try e.embed(try canonicalAction(c.get("action")))
                guard case let .array(got) = v, case let .array(want)? = c.get("vector"), got.count == want.count else { return false }
                return zip(got, want).allSatisfy { same($0, $1) }
            }
        } catch { return false }
    }

    // ---- goal commitment and distance ----

    private static func goalCommitInput(_ g: JSONValue) throws -> JSONValue {
        .object(["embedderModelId": try req(g.get("embedderModelId")), "config": try req(g.get("config")), "goalVector": try req(g.get("goalVector")),
                 "metric": try req(g.get("metric")), "epsilon": try req(g.get("epsilon"))])
    }

    /// Embed the goal's CANONICAL action and bind it to this embedder; `epsilon` (default 1/4096) must lie in (0, 1].
    public static func commitGoal(_ embedder: Embedder, _ goalAction: JSONValue?, epsilon: JSONValue? = nil) throws -> JSONValue {
        let eps = epsilon ?? n(DEFAULT_EPSILON)
        let e = JS.toNumber(eps)
        if !(e > 0 && e <= 1) { throw err("epsilon must be in (0, 1]") }
        let vec = try validateVector(try embedder.embed(try canonicalAction(goalAction)), embedder.dims)
        let g: JSONValue = .object(["embedderModelId": embedder.modelId, "config": embedder.config, "goalVector": .array(vec), "metric": .string(METRIC), "epsilon": eps])
        var o = g.asObject!
        o["commit"] = .string(try hash(try goalCommitInput(g)))
        return .object(o)
    }

    /// Verifies the commitment hashes AND that it is bound to exactly this embedder (id, config, dims). The FIRST failing reason (metric, epsilon, commit
    /// hash, model id, config hash, vector), or nil; a fault is its message.
    public static func verifyGoalCommitment(_ g: JSONValue?, _ embedder: Embedder) -> String? {
        do {
            guard let g = g, g != .null else { throw err("Cannot read properties of null (reading 'metric')") }
            if g.get("metric") != .string(METRIC) { return "unknown metric" }
            let e = JS.toNumber(g.get("epsilon"))
            if !(e > 0 && e <= 1) { return "bad epsilon" }
            let expected = try hash(try goalCommitInput(g))
            guard case let .string(commit)? = g.get("commit"), sameU16(commit, expected) else { return "goal commitment hash mismatch" }
            if !same(g.get("embedderModelId"), embedder.modelId) { return "embedder modelId mismatch" }
            if try hash(try req(g.get("config"))) != (try hash(embedder.config)) { return "embedder config mismatch" }
            _ = try validateVector(g.get("goalVector"), embedder.dims)
            return nil
        } catch { return (error as? JSError)?.message ?? "invalid goal commitment" }
    }

    private static func numbers(_ v: JSONValue?) -> [Double] { (v?.asArray ?? []).map { JS.toNumber($0) } }

    /// Integer vectors to `sin(theta/2) = sqrt((1 - cos) / 2)`, rounded UP to the `epsilon` grid (default 1/4096). Only IEEE `*`, `+`, `/` and `sqrt`
    /// in the reference's order; no fused multiply-add. Length mismatch, a zero vector and NaN results are 1; identical vectors 0.
    public static func vectorDistance(_ a: [Double], _ b: [Double], epsilon: Double = DEFAULT_EPSILON) -> Double {
        if a.count != b.count { return 1 }
        var dot = 0.0, na = 0.0, nb = 0.0, same = true
        for i in 0..<a.count {
            let p = a[i] * b[i]; dot = dot + p
            let x = a[i] * a[i]; na = na + x
            let y = b[i] * b[i]; nb = nb + y
            if a[i] != b[i] { same = false }
        }
        if na == 0 || nb == 0 { return 1 }
        if same { return 0 }
        let prod = na * nb
        let cos = jsMax(-1, jsMin(1, dot / prod.squareRoot()))
        let d = ((1 - cos) / 2).squareRoot()
        if d < 1e-9 { return 0 }
        let q = (d / epsilon).rounded(.up)
        return clamp01(q * epsilon)
    }

    /// The distance to the committed goal as `{ok: true, value}`, or `{ok: false, reason}` on any commitment or embedding failure (the distance is then 1).
    public static func committedDistanceChecked(_ action: JSONValue, _ goal: JSONValue?, _ embedder: Embedder) -> JSONValue {
        if let bad = verifyGoalCommitment(goal, embedder), !bad.isEmpty { return .object(["ok": .bool(false), "reason": .string(bad)]) }
        do {
            let v = try validateVector(try embedder.embed(action), embedder.dims)
            let eps = JS.toNumber(goal?.get("epsilon"))
            return .object(["ok": .bool(true), "value": n(vectorDistance(v.map { JS.toNumber($0) }, numbers(goal?.get("goalVector")), epsilon: eps))])
        } catch { return .object(["ok": .bool(false), "reason": .string((error as? JSError)?.message ?? "embedding failed")]) }
    }

    /// Accepts an agent submission, canonicalizes it, returns the distance (1 on any failure; never throws).
    public static func committedDistance(_ action: JSONValue?, _ goal: JSONValue?, _ embedder: Embedder) -> Double {
        guard let c = try? canonicalAction(action) else { return 1 }
        let r = committedDistanceChecked(c, goal, embedder)
        return r.get("ok") == .bool(true) ? JS.toNumber(r.get("value")) : 1
    }

    // ---- split-conformal calibration ----

    /// `1 - (1 + #{s >= raw}) / (n + 1)`: the conformal p-value complement. An empty set or a non-finite raw score is 1.
    public static func calibrate(_ raw: Double, _ scores: [Double]) -> Double {
        if scores.isEmpty || !raw.isFinite { return 1 }
        var ge = 0
        for s in scores where s >= raw { ge += 1 }
        return 1 - (1 + Double(ge)) / Double(scores.count + 1)
    }

    /// The split-conformal quantile (infinity when `n` is too small); nil where the reference returns `undefined` (`alpha >= 1`).
    public static func conformalThreshold(_ scores: [Double], _ alpha: Double) -> Double? {
        let cnt = Double(scores.count)
        let k = ((cnt + 1) * (1 - alpha)).rounded(.up)
        if scores.isEmpty || k > cnt { return .infinity }
        if k.isNaN || k - 1 < 0 { return nil }
        return scores.sorted()[Int(k) - 1]
    }

    /// The digest the grant commits for a calibration set; a non-finite score throws.
    public static func calibrationDigest(_ scores: [Double]) throws -> String {
        try hash(.object(["v": .int(1), "scores": .array(scores.sorted().map { n($0) })]))
    }

    // ---- harm currency ----

    /// `{units, normalized}`: the weighted saturating normalization of per-denomination harm in [0, 1]; denominations with a weight or ceiling not above
    /// 0 are skipped, only OWN members of `units` are read, and no denomination at all is 1.
    public static func harmReport(_ units: JSONValue?, _ denominations: [JSONValue]) -> JSONValue {
        var num = 0.0, den = 0.0
        for d in denominations {
            let w = JS.toNumber(d.get("weight")), c = JS.toNumber(d.get("ceiling"))
            if !(w > 0) || !(c > 0) { continue }
            var u = 0.0
            if case let .object(o)? = units, let x = o[JKey(JS.toString(d.get("id")))] { u = JS.toNumber(x) }
            num += w * jsMin(1, jsMax(0, u) / c)
            den += w
        }
        return .object(["units": units ?? .null, "normalized": n(den == 0 ? 1 : clamp01(num / den))])
    }

    // ---- composition ----

    /// What the verifier holds: the committed registry, graph, embedder, goal, harm currency and weights, with the digests the grant committed.
    public struct Context {
        public var registry: InverseRegistry
        public var authorizedKinds: [String]
        public var graph: ResourceGraph
        public var scope: JSONValue?
        public var embedder: Embedder
        public var goal: JSONValue
        /// `{registryDigest, graphDigest, calibrationDigest?}`
        public var commitments: JSONValue
        public var denominations: [JSONValue]
        public var weights: JSONValue
        public var taint: Double
        public var age: Double
        public var attestedUncertainty: Double?
        public var calibration: [Double]?
        public init(registry: InverseRegistry, authorizedKinds: [String], graph: ResourceGraph, scope: JSONValue? = nil, embedder: Embedder, goal: JSONValue,
                    commitments: JSONValue, denominations: [JSONValue], weights: JSONValue, taint: Double, age: Double, attestedUncertainty: Double? = nil,
                    calibration: [Double]? = nil) {
            self.registry = registry; self.authorizedKinds = authorizedKinds; self.graph = graph; self.scope = scope; self.embedder = embedder; self.goal = goal
            self.commitments = commitments; self.denominations = denominations; self.weights = weights; self.taint = taint; self.age = age
            self.attestedUncertainty = attestedUncertainty; self.calibration = calibration
        }
    }

    private static let INPUT_KEYS = ["semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"]

    private static func reject(_ reasons: [String]) -> JSONValue {
        var inputs = JObject()
        for (i, k) in INPUT_KEYS.enumerated() { inputs[JKey(k)] = n(Risk.WORST[i]) }
        return .object([
            "r": .int(1), "valid": .bool(false), "reasons": .array(reasons.map { .string($0) }), "raw": .int(1), "inputs": .object(inputs),
            "reversibility": .object(["class": .string("irreversible"), "value": .int(0)]),
            "blast": .object(["count": .int(0), "reachable": .array([]), "normalized": .int(1), "harm": .object([:])]),
            "harm": .object(["units": .object([:]), "normalized": .int(1)]), "evidenceDigest": .string(""),
        ])
    }

    /// The risk of a submitted action as `{r, valid, reasons, raw, inputs, reversibility, blast, harm, evidenceDigest}`: a pure function of the canonical
    /// action and the committed context. Any mismatch (registry, graph, calibration set, goal / embedder binding) or an action without a stable encoding is
    /// the fail-closed `r = 1`, `valid: false` with every reason in the fixed order. Throws only where the reference does: a graph with a non-finite harm
    /// weight or a calibration set with a non-finite score cannot be digested.
    public static func objectiveRisk(_ submitted: JSONValue?, _ ctx: Context) throws -> JSONValue {
        let action: JSONValue
        do { action = try canonicalAction(submitted) } catch { return reject(["action: \((error as? JSError)?.message ?? "not canonicalizable")"]) }
        var reasons: [String] = []
        let cm = ctx.commitments
        if cm.get("registryDigest") != .string(try ctx.registry.digest()) { reasons.append("registry digest does not match the committed digest") }
        if cm.get("graphDigest") != .string(try ctx.graph.digest()) { reasons.append("graph digest does not match the committed digest") }
        if let cal = ctx.calibration {
            if cm.get("calibrationDigest") == nil { reasons.append("calibration set used without a committed digest") }
            else if cm.get("calibrationDigest") != .string(try calibrationDigest(cal)) { reasons.append("calibration digest does not match the committed digest") }
        }
        let dist = committedDistanceChecked(action, ctx.goal, ctx.embedder)
        if dist.get("ok") != .bool(true) { reasons.append("goal/embedder: \(dist.get("reason")?.asString ?? "")") }
        if !reasons.isEmpty { return reject(reasons) }

        let rev = reversibility(verb: action.get("verb"), registry: ctx.registry, authorizedKinds: ctx.authorizedKinds)
        let blast = blastRadius(resource: action.get("resource"), graph: ctx.graph, scope: ctx.scope)
        let harm = harmReport(blast.get("harm"), ctx.denominations)
        let uncertainty = clamp01(ctx.attestedUncertainty ?? 0)
        let hasHarm = !ctx.denominations.isEmpty && !(blast.get("harm")?.asObject?.isEmpty ?? true)
        let blastIn = jsMax(JS.toNumber(blast.get("normalized")), hasHarm ? JS.toNumber(harm.get("normalized")) : 0)
        let vals: [Double] = [JS.toNumber(dist.get("value")), JS.toNumber(rev.get("value")), blastIn, ctx.taint.isFinite ? ctx.taint : 1, 1 - uncertainty, ctx.age.isFinite ? ctx.age : 1]
        var inputs = JObject()
        for (i, k) in INPUT_KEYS.enumerated() { inputs[JKey(k)] = n(vals[i]) }
        let raw = Risk.riskScore(vals.map { Optional($0) }, weights: ctx.weights.asObject ?? [:])
        let r = ctx.calibration.map { calibrate(raw, $0) } ?? raw
        var edgeKinds: JSONValue = .null
        if let ek = ctx.scope?.get("edgeKinds"), JS.truthy(ek) { edgeKinds = .array((ek.asArray ?? []).sorted { lessU16(JS.toString($0), JS.toString($1)) }) }
        let evidence = try hash(.object([
            "action": .string(try canonicalActionDigest(action)),
            "scope": .object(["edgeKinds": edgeKinds, "maxDepth": JS.present(ctx.scope?.get("maxDepth")) ?? .null]),
            "authorized": .array(ctx.authorizedKinds.sorted { lessU16($0, $1) }.map { .string($0) }),
            "registry": try req(cm.get("registryDigest")), "graph": try req(cm.get("graphDigest")), "goal": try req(ctx.goal.get("commit")),
            "calibration": JS.present(cm.get("calibrationDigest")) ?? .null, "inputs": .object(inputs),
        ]))
        return .object(["r": n(r), "valid": .bool(true), "reasons": .array([]), "raw": n(raw), "inputs": .object(inputs), "reversibility": rev, "blast": blast,
                        "harm": harm, "evidenceDigest": .string(evidence)])
    }

    /// The oracle for the contestable dispute game, backed by the objective risk functional: it recomputes a disputed input (`reversibility_class`,
    /// `reversibility`, `blastRadius`, `semanticDistance`) from the committed facts over the frozen snapshot's canonical action. Fails closed: any mismatch
    /// or fault is `{input, valid: false, reason}`. Never throws.
    public static func objectiveRiskOracle(_ ctx: Context, input: JSONValue, snapshot: JSONValue?) -> JSONValue {
        func bad(_ why: String) -> JSONValue { .object(["input": input, "valid": .bool(false), "reason": .string(why)]) }
        do {
            guard let a = snapshot?.get("action")?.get("action"), case .object = a, case .string? = a.get("verb"), case .string? = a.get("resource") else {
                return bad("snapshot action is missing a canonical verb/resource")
            }
            var sub: JObject = ["verb": a.get("verb")!, "resource": a.get("resource")!]
            sub["params"] = a.get("params")?.isObject == true ? a.get("params")! : .object([:])
            let res = try objectiveRisk(.object(sub), ctx)
            if res.get("valid") != .bool(true) {
                let why = (res.get("reasons")?.asArray ?? []).compactMap { $0.asString }.joined(separator: "; ")
                return bad(why.isEmpty ? "objective risk could not be reproduced" : why)
            }
            switch input.asString {
            case "reversibility_class"?: return .object(["input": input, "class": res.get("reversibility")?.get("class") ?? .null, "valid": .bool(true)])
            case "reversibility"?: return .object(["input": input, "value": res.get("inputs")?.get("reversibility") ?? .null, "valid": .bool(true)])
            case "blastRadius"?: return .object(["input": input, "value": res.get("inputs")?.get("blastRadius") ?? .null, "valid": .bool(true)])
            case "semanticDistance"?: return .object(["input": input, "value": res.get("inputs")?.get("semanticDistance") ?? .null, "valid": .bool(true)])
            default: return bad("unknown disputed input: \(JS.toString(input))")
            }
        } catch { return bad("objective oracle error (fail closed): \((error as? JSError)?.message ?? "unknown")") }
    }
}
