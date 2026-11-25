import Foundation

/// Trace rules: "never B after A within <window>" guardrails (the toxic-flow shape of Invariant Labs' guardrails) lowered to derive
/// caveats that every verifier evaluates over its own signed action history. A caveat only removes authority, so a compiled rule is
/// a restriction by construction.
///
///     rule  never <B> after <A> within <duration>
///     sel   atom (',' atom)*      atom: tool:<verb> | trait:<trait id> | resource:<prefix> (A side only) | any
///
/// Fail-strict: anything the target cannot express exactly is an error (a `JSError` carrying the reference's code), never skipped.
public enum PCATraceRules {
    public static let MAX_TRACE_CAVEATS = 64
    static let B_CHUNK = 8 // 7 + 3k expression nodes stay within the derive node budget

    /// Traits that mean "reads private data".
    public static let PRIVATE_READ_TRAITS = ["pca.pii_access", "pca.financial_data_read", "pca.credential_access", "pca.regulated_data"]
    /// Traits that mean "can send data out".
    public static let EXTERNAL_SEND_TRAITS = ["pca.external_communication", "pca.network_egress", "pca.data_export", "pca.public_exposure"]

    public struct Selector {
        public var tools: [String] = []
        public var traits: [String] = []
        /// Resource prefixes (the earlier side only: the history records the resource of past actions).
        public var resources: [String] = []
        /// Every action in the verb table.
        public var any = false
        public init(tools: [String] = [], traits: [String] = [], resources: [String] = [], any: Bool = false) {
            self.tools = tools; self.traits = traits; self.resources = resources; self.any = any
        }
        public var json: JSONValue {
            .object(["tools": PCADataflow.strs(tools), "traits": PCADataflow.strs(traits), "resources": PCADataflow.strs(resources), "any": .bool(any)])
        }
    }

    public struct Rule {
        public var id: String
        public var never: Selector
        public var after: Selector
        public var withinMs: Int64
        /// Carried as given (a null reason stays null); nil = absent.
        public var reason: JSONValue?
        public init(id: String, never: Selector, after: Selector, withinMs: Int64, reason: JSONValue? = nil) {
            self.id = id; self.never = never; self.after = after; self.withinMs = withinMs; self.reason = reason
        }
        public var json: JSONValue {
            var o: JObject = ["id": .string(id), "never": never.json, "after": after.json, "within_ms": .int(withinMs)]
            if let r = reason { o["reason"] = r }
            return .object(o)
        }
    }

    /// A verb's effective traits and effects.
    public struct VerbDef {
        public var traits: [String]
        public var effects: [String]?
        public init(traits: [String], effects: [String]? = nil) { self.traits = traits; self.effects = effects }
    }
    public typealias VerbTable = [JKey: VerbDef]

    public enum EdgeFrom {
        case tool(String)
        case resource(String)
    }

    /// The rule forbids `to` within `withinMs` after `from`.
    public struct Edge {
        public var rule: String
        public var from: EdgeFrom
        public var to: String
        public var withinMs: Int64
        public init(rule: String, from: EdgeFrom, to: String, withinMs: Int64) { self.rule = rule; self.from = from; self.to = to; self.withinMs = withinMs }
        public var json: JSONValue {
            let f: JSONValue
            switch from {
            case let .tool(t): f = .object(["tool": .string(t)])
            case let .resource(r): f = .object(["resource": .string(r)])
            }
            return .object(["rule": .string(rule), "from": f, "to": .string(to), "within_ms": .int(withinMs)])
        }
    }

    public struct CompiledTrace {
        public var caveats: [JSONValue]
        public var edges: [Edge]
        /// hashCanonical({d: "atlas-pca/trace-rules/v1", caveats}): what a grant or a review pins.
        public var digest: String
        public var json: JSONValue { .object(["caveats": .array(caveats), "edges": .array(edges.map { $0.json }), "digest": .string(digest)]) }
    }

    public struct InvariantImport {
        public var rule: Rule
        /// Conditions removed under dropUnsupported (each removal makes the rule refuse more, never less).
        public var dropped: [String]
        public var json: JSONValue { .object(["rule": rule.json, "dropped": PCADataflow.strs(dropped)]) }
    }

    static func fail(_ code: String, _ m: String) -> JSError { JSError(m, code: code) }

    // ---- JS regular-expression classes: \s (Unicode white space), \S, . (anything but a line terminator), \w ----
    static let S = #"[\t\n\x{0B}\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]"#
    static let NS = #"[^\t\n\x{0B}\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]"#
    static let DOT = #"[^\n\r\x{2028}\x{2029}]"#
    static let W = "[A-Za-z0-9_]"

    // a whole-string match: ICU `$` also matches before a final line terminator, JS `$` does not, so `\z`
    static let ruleRe = re(#"\A"# + S + "*never" + S + "+(" + DOT + "+?)" + S + "+after" + S + "+(" + DOT + "+?)" + S + "+within" + S + "+(" + NS + "+)" + S + #"*\z"#)
    static let headRe = re(#"\Araise"# + S + #"+(?:"([^"]*)"|'([^']*)')"# + S + #"+if:\z"#)
    static let flowRe = re(#"\A\(("# + W + "+):" + S + "*(ToolCall|ToolOutput|Message)\\)" + S + "*->" + S + #"*\(("# + W + "+):" + S + "*(ToolCall|ToolOutput|Message)\\)\\z")
    static let isRe = re(#"\A("# + W + "+)" + S + "+is" + S + #"+tool:([A-Za-z0-9_.:/-]+)(\("# + DOT + #"*\))?\z"#)

    private static func re(_ p: String) -> NSRegularExpression {
        // a fixed, reviewed pattern: failing to compile is a programming error, never an input error
        try! NSRegularExpression(pattern: p)
    }

    /// The capture groups of a whole-string match (nil for a group that did not take part), or nil when it does not match.
    static func match(_ r: NSRegularExpression, _ s: String) -> [String?]? {
        let ns = s as NSString
        guard let m = r.firstMatch(in: s, options: [.anchored], range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (1..<m.numberOfRanges).map { i in m.range(at: i).location == NSNotFound ? nil : ns.substring(with: m.range(at: i)) }
    }

    /// `^[a-z][a-z0-9_]{0,39}$`.
    static func ruleIdOk(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        guard u.count >= 1, u.count <= 40, u[0].value >= 97, u[0].value <= 122 else { return false }
        return u.dropFirst().allSatisfy { ($0.value >= 97 && $0.value <= 122) || ($0.value >= 48 && $0.value <= 57) || $0 == "_" }
    }

    /// `^[A-Za-z0-9_.:/-]{1,256}$`.
    static func verbOk(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        guard u.count >= 1, u.count <= 256 else { return false }
        return u.allSatisfy { ($0.value >= 97 && $0.value <= 122) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 48 && $0.value <= 57) || "_.:/-".unicodeScalars.contains($0) }
    }

    static let UNIT: [String: Int64] = ["ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000]

    /// `^([1-9][0-9]{0,9})(ms|s|m|h|d)$` as milliseconds, at most the 30-day history the verifier keeps.
    static func duration(_ t: String) throws -> Int64 {
        let u = Array(t.unicodeScalars)
        var i = 0
        while i < u.count, u[i].value >= 48, u[i].value <= 57 { i += 1 }
        let unit = String(String.UnicodeScalarView(u[i...]))
        guard i >= 1, i <= 10, u[0] != "0", let mult = UNIT.first(where: { IV.same($0.key, unit) })?.value, let n = Int64(String(String.UnicodeScalarView(u[..<i]))) else {
            throw fail("duration", "'\(t)' is not a duration like 10m, 2h or 7d")
        }
        let ms = n * mult
        if ms > PCA.DERIVE_MAX_WINDOW_MS { throw fail("window", "a window of \(t) exceeds the 30-day history the verifier keeps") }
        return ms
    }

    static func selector(_ text: String, never: Bool) throws -> Selector {
        var s = Selector()
        for raw in IV.split(text, ",") {
            let a = Attest.jsTrim(raw)
            if IV.same(a, "any") { s.any = true }
            else if IV.startsWith(a, "tool:"), verbOk(IV.dropPrefix(a, 5)) { s.tools.append(IV.dropPrefix(a, 5)) }
            else if IV.startsWith(a, "trait:"), verbOk(IV.dropPrefix(a, 6)) { s.traits.append(IV.dropPrefix(a, 6)) }
            else if IV.startsWith(a, "resource:"), a.utf16.count > 9, a.utf16.count <= 9 + 256 {
                if never { throw fail("resource_on_effect", "a resource selector can only name the earlier action (the check reads the current verb)") }
                s.resources.append(IV.dropPrefix(a, 9))
            } else { throw fail("selector", "'\(a)' is not tool:<verb>, trait:<id>, resource:<prefix> or any") }
        }
        return s
    }

    static func idError(_ id: String) -> JSError { fail("id", "rule id '\(id)' must match ^[a-z][a-z0-9_]{0,39}$") }

    /// Parse `never <B> after <A> within <duration>`. `reason` is carried as given.
    public static func parseTraceRule(_ id: String, _ text: String, reason: JSONValue? = nil) throws -> Rule {
        if !ruleIdOk(id) { throw idError(id) }
        guard let m = match(ruleRe, text) else { throw fail("syntax", "expected 'never <selector> after <selector> within <duration>', got '\(text)'") }
        return Rule(id: id, never: try selector(m[0]!, never: true), after: try selector(m[1]!, never: false), withinMs: try duration(m[2]!), reason: reason)
    }

    /// The names an object literal inherits (`tools["constructor"]` is not undefined in the reference, so `.push` on it throws).
    static let PROTO_NAMES: Set<String> = ["constructor", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
                                           "__proto__", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"]

    /// Import the Invariant subset `raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)` plus `x is tool:<name>` lines.
    /// `horizon` (a duration like 7d) is required: Invariant's `->` spans the whole trace, PCA's check the history window.
    public static func parseInvariantRule(_ id: String, _ text: String, horizon: String?, dropUnsupported: Bool = false) throws -> InvariantImport {
        if !ruleIdOk(id) { throw idError(id) }
        guard let horizon = horizon else { throw fail("horizon", "an Invariant rule has no window: pass the horizon explicitly") }
        let within = try duration(horizon)
        let lines = IV.split(text, "\n").map { Attest.jsTrim($0) }.filter { !$0.isEmpty && !IV.startsWith($0, "#") }
        func line(_ i: Int) -> String { i < lines.count ? lines[i] : "" }
        guard let head = match(headRe, line(0)) else { throw fail("syntax", "the first line must be raise \"<message>\" if:") }
        guard let flow = match(flowRe, line(1)) else {
            throw fail("unsupported", "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)")
        }
        let a = flow[0]!, ta = flow[1]!, b = flow[2]!, tb = flow[3]!
        if ta == "Message" || tb != "ToolCall" { throw fail("unsupported", "only a tool call or tool output followed by a tool call can be compiled") }
        if IV.same(a, b) { throw fail("syntax", "the two events need distinct names") }
        var tools: [JKey: [String]] = [JKey(a): [], JKey(b): []]
        var dropped: [String] = []
        func push(_ name: String, _ tool: String) throws {
            if tools[JKey(name)] != nil { tools[JKey(name)]!.append(tool) } else { throw JSError("tools[name].push is not a function") }
        }
        for l in lines.dropFirst(2) {
            let m = match(isRe, l)
            let known = m.map { tools[JKey($0[0]!)] != nil || PROTO_NAMES.contains($0[0]!) } ?? false
            if let m = m, known, m[2] == nil {
                try push(m[0]!, m[1]!)
                continue
            }
            if dropUnsupported {
                // `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
                if let m = m, known { try push(m[0]!, m[1]!) }
                dropped.append(l)
                continue
            }
            throw fail("unsupported", "'\(l)' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead")
        }
        for v in [a, b] where tools[JKey(v)]!.count > 1 { throw fail("unsatisfiable", "'\(v)' is constrained to two different tools, so the rule can never fire") }
        func sel(_ v: String) -> Selector { let t = tools[JKey(v)]!; return Selector(tools: t, any: t.isEmpty) }
        let reason = head[0] ?? head[1] ?? ""
        return InvariantImport(rule: Rule(id: id, never: sel(b), after: sel(a), withinMs: within, reason: .string(reason)), dropped: dropped)
    }

    static func expand(_ s: Selector, _ table: VerbTable, _ what: String) throws -> [String] {
        let verbs = PCADataflow.jsSorted(table.keys.map { $0.s })
        var out: [String] = []
        if s.any { out += verbs }
        for t in s.tools {
            guard table[JKey(t)] != nil else { throw fail("unknown_tool", "\(what): tool '\(t)' is not an action in the verb table") }
            out.append(t)
        }
        for tr in s.traits {
            let hit = verbs.filter { PCADataflow.has(table[JKey($0)]!.traits, tr) }
            if hit.isEmpty { throw fail("empty_selector", "\(what): trait '\(tr)' matches no action") }
            out += hit
        }
        return PCADataflow.jsSorted(PCADataflow.distinct(out))
    }

    static func obj(_ o: JObject) -> JSONValue { .object(o) }

    /// Lower rules to derive caveats over the verifier's history. Throws on anything not expressible.
    public static func compileTraceRules(_ rules: [Rule], _ table: VerbTable) throws -> CompiledTrace {
        var caveats: [JSONValue] = []
        var edges: [Edge] = []
        var ids = Set<JKey>()
        for r in rules {
            if !ruleIdOk(r.id) || ids.contains(JKey(r.id)) { throw fail("id", "rule id '\(r.id)' is malformed or repeated") }
            ids.insert(JKey(r.id))
            if r.withinMs < 1 || r.withinMs > PCA.DERIVE_MAX_WINDOW_MS { throw fail("window", "rule '\(r.id)': within_ms must be 1..30 days") }
            if !r.never.resources.isEmpty { throw fail("resource_on_effect", "rule '\(r.id)': a resource selector cannot name the later action") }
            let bs = try expand(r.never, table, "rule '\(r.id)' never")
            var aSide: [(key: String, val: String)] = try expand(r.after, table, "rule '\(r.id)' after").map { ("verb", $0) }
            aSide += PCADataflow.jsSorted(PCADataflow.distinct(r.after.resources)).map { ("resource_prefix", $0) }
            if bs.isEmpty || aSide.isEmpty { throw fail("empty_selector", "rule '\(r.id)': a side matches nothing") }
            var n = 0
            for a in aSide {
                var i = 0
                while i < bs.count {
                    let chunk = Array(bs[i..<min(i + B_CHUNK, bs.count)])
                    i += B_CHUNK
                    let isB = obj(["op": .string("or"), "args": .array(chunk.map { v in
                        obj(["op": .string("eq"), "a": obj(["ref": .string("verb")]), "b": obj(["const": .string(v)])])
                    })])
                    let c = obj([
                        "type": .string("derive"),
                        "id": .string("trace.\(r.id).\(n)"),
                        "defs": .array([
                            obj(["name": .string("seen"), "kind": .string("count"), "window_ms": .int(r.withinMs), JKey(a.key): .string(a.val)]),
                            obj(["name": .string("verb"), "kind": .string("action"), "field": .string("verb")]),
                            obj(["name": .string("is_b"), "kind": .string("expr"), "expr": isB]),
                        ]),
                        // refused iff an A happened within the window AND this action is a B; unknown (no history, no verb) refuses too
                        "check": obj(["op": .string("not"), "arg": obj(["op": .string("and"), "args": .array([
                            obj(["op": .string("gt"), "a": obj(["ref": .string("seen")]), "b": obj(["const": .int(0)])]),
                            obj(["ref": .string("is_b")]),
                        ])])]),
                    ])
                    n += 1
                    if let e = PCA.deriveError(c) { throw fail("internal", "rule '\(r.id)' compiled to an invalid caveat: \(e)") }
                    caveats.append(c)
                    if caveats.count > MAX_TRACE_CAVEATS { throw fail("too_large", "more than \(MAX_TRACE_CAVEATS) caveats: split the rule set or narrow the selectors") }
                }
                for v in bs { edges.append(Edge(rule: r.id, from: a.key == "verb" ? .tool(a.val) : .resource(a.val), to: v, withinMs: r.withinMs)) }
            }
        }
        guard let digest = IV.strictHash(obj(["d": .string("atlas-pca/trace-rules/v1"), "caveats": .array(caveats)])) else {
            throw JSError("trace rules: the caveats are outside the strict JSON profile")
        }
        return CompiledTrace(caveats: caveats, edges: edges, digest: digest)
    }

    // ---- lethal trifecta lint ----

    public struct TrifectaFinding {
        /// The send action left open.
        public var send: String
        /// Untrusted-content reads with no rule to `send`.
        public var fromUntrusted: [String]
        /// Private reads with no rule to `send`.
        public var fromPrivate: [String]
    }

    public struct TrifectaReport {
        public var privateReads: [String]
        public var untrustedReads: [String]
        public var sends: [String]
        /// Empty when the set does not form the trifecta or every send is cut off.
        public var findings: [TrifectaFinding]
        public var json: JSONValue {
            .object(["private_reads": PCADataflow.strs(privateReads), "untrusted_reads": PCADataflow.strs(untrustedReads), "sends": PCADataflow.strs(sends),
                     "findings": .array(findings.map { .object(["send": .string($0.send), "from_untrusted": PCADataflow.strs($0.fromUntrusted), "from_private": PCADataflow.strs($0.fromPrivate)]) })])
        }
    }

    /// The lethal trifecta: private data, untrusted content and a way out in one action set. A send is cut off when every untrusted
    /// read, or every private read, has an edge rule to it. Untrusted reads are the verbs in `untrusted`, those with a trait in
    /// `untrustedTraits`, and read-only actions with `pca.network_egress`. A lint only: it reports, it does not enforce.
    public static func lethalTrifecta(_ table: VerbTable, _ edges: [Edge], untrusted: [String] = [], untrustedTraits: [String] = []) -> TrifectaReport {
        let verbs = PCADataflow.jsSorted(table.keys.map { $0.s })
        func def(_ v: String) -> VerbDef { table[JKey(v)]! }
        func has(_ v: String, _ ts: [String]) -> Bool { def(v).traits.contains { PCADataflow.has(ts, $0) } }
        func readOnly(_ v: String) -> Bool { let e = def(v).effects ?? []; return !e.isEmpty && e.allSatisfy { IV.same($0, "read") } }
        let priv = verbs.filter { has($0, PRIVATE_READ_TRAITS) }
        let untr = verbs.filter { PCADataflow.has(untrusted, $0) || has($0, untrustedTraits) || (readOnly($0) && PCADataflow.has(def($0).traits, "pca.network_egress")) }
        let sends = verbs.filter { has($0, EXTERNAL_SEND_TRAITS) && !readOnly($0) }
        var findings: [TrifectaFinding] = []
        if !priv.isEmpty && !untr.isEmpty && !sends.isEmpty {
            func ruled(_ from: String, _ to: String) -> Bool {
                edges.contains { e in
                    if case let .tool(t) = e.from { return IV.same(t, from) && IV.same(e.to, to) }
                    return false
                }
            }
            for s in sends {
                let fu = untr.filter { !ruled($0, s) }, fp = priv.filter { !ruled($0, s) }
                if !fu.isEmpty && !fp.isEmpty { findings.append(TrifectaFinding(send: s, fromUntrusted: fu, fromPrivate: fp)) }
            }
        }
        return TrifectaReport(privateReads: priv, untrustedReads: untr, sends: sends, findings: findings)
    }
}
