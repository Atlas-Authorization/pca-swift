import Foundation

/// Deterministic plain-language rendering of grants, questions and actions, and the back-translation diff. Every sentence is a fixed
/// template over the data (no model anywhere), so the same grant always renders the same text. Anything the templates do not know is
/// rendered as an explicit "not understood" line. Policies, caveats and conditions are JSON trees (`nil` is a JavaScript `undefined`,
/// `.null` is `null`); an outcome space is the wallet's `WalletOmega`.
public enum PCAIntentRender {
    /// The default action catalog (built once).
    public static let defaultCatalog: PCACatalog = PCACatalog.default

    private static func fail(_ what: String) -> JSError { return JSError("pca-intent: \(what)") }

    /// `o[k]` of the reference: a read of null throws, of anything that is not an object is `undefined` (nil).
    static func prop(_ o: JSONValue?, _ k: String) throws -> JSONValue? {
        guard let v = o else { return nil }
        if v.isNull { throw fail("cannot read \(k) of null") }
        guard let m = v.asObject else { return nil }
        return m[JKey(k)]
    }

    /// A number as JavaScript prints it.
    static func jsNum(_ d: Double) -> String {
        if d.isNaN { return "NaN" }
        if d.isInfinite { return d < 0 ? "-Infinity" : "Infinity" }
        return JS.number(d)
    }

    /// `String(v)` for a JSON tree value.
    static func str(_ v: JSONValue?) -> String {
        guard let x = v else { return "undefined" }
        switch x {
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case .int, .double: return jsNum(IV.num(x) ?? Double.nan)
        case let .string(s): return s
        case let .array(a): return a.map { $0.isNull ? "" : str($0) }.joined(separator: ",")
        case .object: return "[object Object]"
        }
    }

    // MARK: dates

    private static func pad(_ n: Int64, _ w: Int) -> String {
        let s = String(n)
        return s.count >= w ? s : String(repeating: "0", count: w - s.count) + s
    }

    private static func floorDiv(_ a: Int64, _ b: Int64) -> Int64 {
        let q = a / b
        return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q
    }

    /// `new Date(ms).toISOString()`; throws for an invalid date like the reference.
    static func isoString(_ ms: Double) throws -> String {
        if ms.isNaN || ms.isInfinite || abs(ms) > 8.64e15 { throw JSError("Invalid time value") }
        let t = Int64(ms.rounded(.towardZero))
        let days = floorDiv(t, 86_400_000)
        let rem = t - days * 86_400_000
        let z = days + 719_468
        let era = floorDiv(z, 146_097)
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        let y = yoe + era * 400 + (m <= 2 ? 1 : 0)
        let year: String = (y >= 0 && y <= 9999) ? pad(y, 4) : (y < 0 ? "-" : "+") + pad(abs(y), 6)
        let h = rem / 3_600_000
        let mi = (rem / 60_000) % 60
        let s = (rem / 1000) % 60
        let milli = rem % 1000
        return "\(year)-\(pad(m, 2))-\(pad(d, 2))T\(pad(h, 2)):\(pad(mi, 2)):\(pad(s, 2)).\(pad(milli, 3))Z"
    }

    // MARK: strings

    /// `s.replace(a, b)` for single ASCII characters: the first occurrence only.
    static func replaceFirst(_ s: String, _ a: Unicode.Scalar, _ b: Unicode.Scalar) -> String {
        var out = String.UnicodeScalarView()
        var done = false
        for c in s.unicodeScalars {
            if !done && c == a { out.append(b); done = true } else { out.append(c) }
        }
        return String(out)
    }

    static func stripDot(_ d: String) -> String {
        return d.unicodeScalars.last == "." ? IV.text(d.unicodeScalars.dropLast()) : d
    }

    /// `d.replace(/\.$/, '').replace(/^./, c => c.toLowerCase())`.
    static func lowerFirst(_ d: String) -> String {
        let s = stripDot(d)
        let u = Array(s.utf16)
        if u.isEmpty { return s }
        let c = u[0]
        if c == 0x0A || c == 0x0D || c == 0x2028 || c == 0x2029 { return s }
        // the first half of a surrogate pair lowercases to itself
        if c >= 0xD800 && c <= 0xDFFF { return s }
        let first = String(utf16CodeUnits: [c], count: 1).lowercased()
        return first + String(decoding: u[1...], as: UTF16.self)
    }

    public static func labelOf(_ path: String) -> String { return WalletOmegaMath.labelOf(path) }

    static func fmt(_ v: JSONValue?) -> String {
        if let x = v {
            if case let .string(s) = x { return "\"" + s + "\"" }
            if case let .array(a) = x { return a.map { fmt($0) }.joined(separator: ", ") }
        }
        return str(v)
    }

    private static let UNREADABLE = "an unreadable condition (not understood)"

    /// `(xs ?? []).map(renderCondition).map(s => "(s)").join(sep)`; a non-array throws like `.map` would.
    private static func joined(_ xs: JSONValue?, _ sep: String) throws -> String {
        guard let x = xs, !x.isNull else { return "" }
        guard let a = x.asArray else { throw fail("map is not a function") }
        var parts: [String] = []
        for c in a { parts.append("(" + (try renderCondition(c)) + ")") }
        return parts.joined(separator: sep)
    }

    public static func renderCondition(_ c: JSONValue?) throws -> String {
        guard let m = c?.asObject else { return UNREADABLE }
        if m[JKey("all_of")] != nil || m[JKey("any_of")] != nil || m[JKey("not")] != nil {
            if m[JKey("all_of")] != nil { return "all of: " + (try joined(m[JKey("all_of")], " and ")) }
            if m[JKey("any_of")] != nil { return "either " + (try joined(m[JKey("any_of")], " or ")) }
            return "it is not the case that " + (try renderCondition(m[JKey("not")]))
        }
        guard let field = m[JKey("field")]?.asString else { return UNREADABLE }
        let l = "the " + labelOf(field)
        let op = m[JKey("op")]
        let v: String
        if let r = m[JKey("ref")] {
            guard let rs = r.asString else { throw fail("labelOf of a non-string") }
            v = "the " + labelOf(rs)
        } else {
            v = fmt(m[JKey("value")])
        }
        switch op?.asString ?? "\u{0}" {
        case "eq": return "\(l) is \(v)"
        case "ne": return "\(l) is not \(v)"
        case "in": return "\(l) is one of \(v)"
        case "nin": return "\(l) is none of \(v)"
        case "lt": return "\(l) is less than \(v)"
        case "lte": return "\(l) is at most \(v)"
        case "gt": return "\(l) is more than \(v)"
        case "gte": return "\(l) is at least \(v)"
        case "prefix": return "\(l) starts with \(v)"
        case "exists":
            if case .bool(false)? = m[JKey("value")] { return "\(l) is absent" }
            return "\(l) is present"
        case "like": return "\(l) matches the pattern \(v)"
        case "matches": return "\(l) matches the regular expression \(v)"
        case "is_a": return "\(l) is of type \(v)"
        case "member_of": return "\(l) belongs to \(v)"
        default: return l + " has an unrecognised test \"" + str(op) + "\" (not understood)"
        }
    }

    private static func renderResource(_ r: JSONValue?) -> String {
        guard let x = r else { return "on any resource" }
        guard let s = x.asString else { return "on an unreadable resource matcher (not understood)" }
        if IV.same(s, "*") { return "on any resource" }
        if IV.startsWith(s, "re:") { return "on resources matching the regular expression \"" + IV.dropPrefix(s, 3) + "\"" }
        if IV.endsWith(s, "*") { return "on resources under \"" + IV.text(s.unicodeScalars.dropLast()) + "\"" }
        return "only on resource \"" + s + "\""
    }

    private static func oneVerb(_ x: String, _ catalog: PCACatalog) -> String {
        if IV.same(x, "*") { return "ANY action of any connector" }
        if let s = catalog.get(x) {
            return lowerFirst(s.description) + " [" + x + ", " + replaceFirst(s.reversibility, "_", "-") + "]"
        }
        return "\"" + x + "\" [uncatalogued: treated as irreversible]"
    }

    private static func renderVerb(_ v: JSONValue?, _ catalog: PCACatalog) -> String {
        if let a = v?.asArray { return a.map { oneVerb(str($0), catalog) }.joined(separator: "; or ") }
        return oneVerb(str(v), catalog)
    }

    public static func renderCaveat(_ c: JSONValue?) throws -> String {
        var type: JSONValue? = nil
        if let x = c, !x.isNull { type = try prop(x, "type") }
        switch type?.asString ?? "\u{0}" {
        case "expires": return "The grant expires at " + (try isoString(JS.toNumber(try prop(c, "at")))) + "."
        case "not_before": return "The grant is not valid before " + (try isoString(JS.toNumber(try prop(c, "at")))) + "."
        case "rate": return "At most " + str(try prop(c, "max")) + " actions in any " + str(try prop(c, "per_secs")) + " seconds."
        case "max_blast_radius": return "No action whose blast radius exceeds " + str(try prop(c, "max")) + " (on a 0\u{2013}1 scale)."
        case "reversibility_max":
            return "Nothing more severe than \"" + replaceFirst(str(try prop(c, "class")), "_", "-") + "\" (reversible < rate-limited < irreversible)."
        case "delegation_depth": return "It may be re-delegated at most " + str(try prop(c, "max")) + " level(s) deep."
        case "budget_alloc": return "A trust-budget allocation of " + str(try prop(c, "limit")) + " is carried for sub-delegation."
        default:
            return "An unrecognised constraint of type \"" + str(type) + "\" (NOT UNDERSTOOD: do not rely on this grant until it is explained)."
        }
    }

    /// `{predicates, caveats}` of a policy: a non-array member counts as empty.
    static func normalizePolicy(_ p: JSONValue?) throws -> (predicates: [JSONValue], caveats: [JSONValue]) {
        // `'caveats' in p` is a TypeError for a truthy primitive (a number, a string, true); a nullish or falsy value skips it
        if let v = p, JS.truthy(v), !v.isObject, v.asArray == nil { throw fail("Cannot use 'in' operator to search for 'caveats' in \(JS.toString(v))") }
        return (p?.get("predicates")?.asArray ?? [], p?.get("caveats")?.asArray ?? [])
    }

    /// A grant as numbered plain-language sentences.
    public static func renderGrant(_ policy: JSONValue?, _ catalog: PCACatalog = defaultCatalog) throws -> String {
        let np = try normalizePolicy(policy)
        if np.predicates.isEmpty { return "This grant allows nothing." }
        var lines: [String] = ["The agent may do the following, and nothing else:"]
        for (i, p) in np.predicates.enumerated() {
            let whereV = try prop(p, "where")
            var conds: [String] = []
            if let w = whereV, !w.isNull {
                guard let wa = w.asArray else { throw fail("map is not a function") }
                for c in wa { conds.append(try renderCondition(c)) }
            }
            let verb = renderVerb(try prop(p, "verb"), catalog)
            let res = renderResource(try prop(p, "resource"))
            let whenText: String = conds.isEmpty ? "" : ", only when " + conds.joined(separator: ", and ")
            lines.append("\(i + 1). \(verb), \(res)\(whenText).")
        }
        if !np.caveats.isEmpty {
            lines.append("Limits that apply to everything above:")
            for c in np.caveats { lines.append("- " + (try renderCaveat(c))) }
        }
        return lines.joined(separator: "\n")
    }

    // MARK: outcome / question rendering

    private static func renderDimCell(_ d: WalletDim, _ i: Int) throws -> String {
        let l = labelOf(d.path)
        if d.isNum {
            let cells = WalletOmegaMath.numCells(d)
            if i < 0 || i >= cells.count { throw fail("cell index out of range") }
            let c = cells[i]
            if c.lo == c.hi { return l + " exactly " + String(c.lo) }
            let eg: Int = i > 0 ? c.lo : c.hi
            return "any \(l) from \(c.lo) to \(c.hi) (e.g. \(eg))"
        }
        if i < 0 || i >= d.values.count { throw fail("cell index out of range") }
        let v = d.values[i]
        if v.kind == "exact" { return l + " \"" + v.value + "\"" }
        if v.kind == "prefix" { return "a " + l + " under \"" + v.value + "\" (not otherwise named)" }
        return "a \(l) not named anywhere in the grant or your request"
    }

    public static func renderQuestion(_ vs: WalletVerb, _ cell: [Int], _ catalog: PCACatalog = defaultCatalog) throws -> String {
        let what: String
        if let s = catalog.get(vs.verb) { what = stripDot(s.description) + " [" + vs.verb + "]" } else { what = "perform \"" + vs.verb + "\"" }
        var parts: [String] = []
        for k in 0..<vs.dims.count {
            if k >= cell.count { throw fail("cell index out of range") }
            parts.append(try renderDimCell(vs.dims[k], cell[k]))
        }
        return "Should the agent be allowed to: " + what + (parts.isEmpty ? "" : ", with " + parts.joined(separator: ", ")) + "?"
    }

    // MARK: admission oracle (the analyzer's model of a policy)

    /// A compiled admission oracle for one policy (compile once, query many times).
    struct Admitter {
        let model: PCAAnalyzer.Model

        init(_ policy: JSONValue?) throws { model = try PCAAnalyzer.toModel(policy) }

        private static func setPath(_ root: inout JObject, _ segs: [String], _ from: Int, _ value: JSONValue) {
            let k = JKey(segs[from])
            if from == segs.count - 1 { root[k] = value; return }
            var child = root[k]?.asObject ?? JObject()
            setPath(&child, segs, from + 1, value)
            root[k] = .object(child)
        }

        /// The outcome (values in dimension order) as the analyzer's concrete action.
        static func action(_ vs: WalletVerb, _ values: [(String, JSONValue)]) -> JSONValue {
            var params = JObject(), env = JObject(), subject = JObject()
            var resource = "resource:any"
            for (path, value) in values {
                let segs = IV.split(path, ".")
                if IV.same(path, "action.resource") { resource = PCAIntentRender.str(value) }
                else if segs.count > 2 && IV.same(segs[0], "action") && IV.same(segs[1], "params") { setPath(&params, segs, 2, value) }
                else if segs.count > 1 && IV.same(segs[0], "env") { setPath(&env, segs, 1, value) }
                else if segs.count > 1 && IV.same(segs[0], "subject") { setPath(&subject, segs, 1, value) }
            }
            var a: JObject = ["verb": .string(vs.verb), "resource": .string(resource), "params": .object(params), "reversibilityClass": .string(vs.reversibility)]
            if !env.isEmpty { a["env"] = .object(env) }
            if !subject.isEmpty { a["subject"] = .object(subject) }
            return .object(a)
        }

        /// Does the policy admit the representative outcome of cell `idx`?
        func admits(_ vs: WalletVerb, _ idx: [Int]) throws -> Bool {
            var values: [(String, JSONValue)] = []
            for (k, d) in vs.dims.enumerated() {
                if k >= idx.count { throw JSError("pca-intent: cell index out of range") }
                values.append((d.path, WalletOmegaMath.repValue(d, idx[k])))
            }
            return try PCAAnalyzer.admitsAction(model, Admitter.action(vs, values))
        }
    }

    // MARK: back-translation diff

    /// What a rendering asserts about one dimension (numeric: [min, max] of accepted values; categorical: value labels).
    public struct DimClaim {
        public let path: String
        public let any: Bool
        public let range: (lo: Int, hi: Int)?
        public let values: [String]?

        func sameAs(_ o: DimClaim) -> Bool {
            if !IV.same(path, o.path) || any != o.any { return false }
            switch (range, o.range) {
            case (nil, nil): break
            case let (a?, b?): if a.lo != b.lo || a.hi != b.hi { return false }
            default: return false
            }
            switch (values, o.values) {
            case (nil, nil): return true
            case let (a?, b?): return a.count == b.count && zip(a, b).allSatisfy { IV.same($0, $1) }
            default: return false
            }
        }

        public func toJson() -> JSONValue {
            var m: JObject = ["path": .string(path), "any": .bool(any)]
            if let r = range { m["range"] = .array([.int(Int64(r.lo)), .int(Int64(r.hi))]) }
            if let v = values { m["values"] = .array(v.map { JSONValue.string($0) }) }
            return .object(m)
        }
    }

    public struct VerbClaim {
        public let verb: String
        public let allowed: Bool
        public let boxShaped: Bool
        public let dims: [DimClaim]

        public func toJson() -> JSONValue {
            return .object(["verb": .string(verb), "allowed": .bool(allowed), "boxShaped": .bool(boxShaped), "dims": .array(dims.map { $0.toJson() })])
        }
    }

    /// What the policy asserts over the space, verb by verb and dimension by dimension.
    public static func claimsOf(_ policy: JSONValue?, _ omega: WalletOmega) throws -> [VerbClaim] {
        let a = try Admitter(policy)
        var out: [VerbClaim] = []
        for vs in omega.verbs {
            let n = WalletOmegaMath.verbCellCount(vs)
            var acc: [[Int]] = []
            for c in 0..<n {
                let idx = WalletOmegaMath.decodeCell(vs, c)
                if try a.admits(vs, idx) { acc.append(idx) }
            }
            var proj: [[Int]] = []
            for k in 0..<vs.dims.count { proj.append(Array(Set(acc.map { $0[k] })).sorted()) }
            var boxCount = 1.0
            for s in proj { boxCount *= Double(s.count) }
            var dims: [DimClaim] = []
            for k in 0..<vs.dims.count {
                let d = vs.dims[k]
                let s = proj[k]
                let total = WalletOmegaMath.cellCount(d)
                let anyValue = s.count == total
                if d.isNum {
                    var range: (lo: Int, hi: Int)? = nil
                    if let f = s.first, let l = s.last {
                        let cells = WalletOmegaMath.numCells(d)
                        range = (cells[f].lo, cells[l].hi)
                    }
                    dims.append(DimClaim(path: d.path, any: anyValue, range: range, values: nil))
                } else {
                    let vals: [String] = s.map { i in
                        let v = d.values[i]
                        return v.kind == "prefix" ? v.value + "*" : v.value
                    }
                    dims.append(DimClaim(path: d.path, any: anyValue, range: nil, values: vals))
                }
            }
            out.append(VerbClaim(verb: vs.verb, allowed: !acc.isEmpty, boxShaped: Double(acc.count) == boxCount, dims: dims))
        }
        return out
    }

    /// One difference between two readings, with the sentence shown to the principal.
    public struct ClaimDiff {
        public let verb: String
        public let kind: String
        public let path: String?
        public let text: String

        public func toJson() -> JSONValue {
            var m: JObject = ["verb": .string(verb), "kind": .string(kind), "text": .string(text)]
            if let p = path { m["path"] = .string(p) }
            return .object(m)
        }
    }

    private static func dimText(_ c: DimClaim?) -> String {
        guard let c = c else { return "anything" }
        if c.any { return "any value" }
        if let r = c.range { return "\(r.lo) to \(r.hi)" }
        if let v = c.values, !v.isEmpty { return v.joined(separator: ", ") }
        return "nothing"
    }

    private struct Wording {
        let extra: (String) -> String
        let missing: (String) -> String
        let shape: (String) -> String
        let dim: (String, String, String, String) -> String
    }

    private static func includesAll(_ xs: [String], _ ys: [String]) -> Bool {
        return ys.allSatisfy { y in xs.contains { IV.same($0, y) } }
    }

    private static func diffClaims(_ g: [VerbClaim], _ s: [VerbClaim], _ w: Wording) throws -> [ClaimDiff] {
        var out: [ClaimDiff] = []
        if g.count != s.count { throw fail("claim lists differ in length") }
        for i in 0..<g.count {
            let gc = g[i]
            let sc = s[i]
            if gc.allowed && !sc.allowed { out.append(ClaimDiff(verb: gc.verb, kind: "extra-verb", path: nil, text: w.extra(gc.verb))); continue }
            if !gc.allowed && sc.allowed { out.append(ClaimDiff(verb: gc.verb, kind: "missing-verb", path: nil, text: w.missing(gc.verb))); continue }
            if !gc.allowed { continue }
            if gc.boxShaped != sc.boxShaped { out.append(ClaimDiff(verb: gc.verb, kind: "shape", path: nil, text: w.shape(gc.verb))) }
            for k in 0..<gc.dims.count {
                let gd = gc.dims[k]
                if k >= sc.dims.count { throw fail("claim lists differ in length") }
                let sd = sc.dims[k]
                if gd.sameAs(sd) { continue }
                var kind = "different"
                if let gr = gd.range, let sr = sd.range {
                    if gr.lo <= sr.lo && gr.hi >= sr.hi { kind = "looser" }
                    else if gr.lo >= sr.lo && gr.hi <= sr.hi { kind = "tighter" }
                    else { kind = "different" }
                } else if let gv = gd.values, let sv = sd.values {
                    if includesAll(gv, sv) { kind = "looser" } else if includesAll(sv, gv) { kind = "tighter" } else { kind = "different" }
                } else if gd.any && !sd.any { kind = "looser" }
                out.append(ClaimDiff(verb: gc.verb, kind: kind, path: gd.path, text: w.dim(gc.verb, gd.path, dimText(gd), dimText(sd))))
            }
        }
        return out
    }

    /// Render the grant and the intent slots into the same claim form over the space and list every difference.
    public static func backTranslationDiff(_ grant: JSONValue?, _ slots: JSONValue?, _ omega: WalletOmega) throws -> [ClaimDiff] {
        let w = Wording(
            extra: { "The grant allows \($0), which your request did not mention." },
            missing: { "Your request mentions \($0), but the grant does not allow it." },
            shape: { "The grant's rule for \($0) is a combination of cases that your request did not describe." },
            dim: { v, path, a, b in "For \(v), the grant allows \(labelOf(path)) \(a); your request said \(b)." })
        return try diffClaims(try claimsOf(grant, omega), try claimsOf(try PCAIntentDerive.slotsToPolicy(slots), omega), w)
    }

    /// The same claim diff between two grants; `kind` is from a's point of view (looser = a allows more).
    public static func claimDiff(_ a: JSONValue?, _ b: JSONValue?, _ omega: WalletOmega, _ n0: String = "the first reading", _ n1: String = "the second reading") throws -> [ClaimDiff] {
        let w = Wording(
            extra: { "\(n0) allows \($0); \(n1) does not." },
            missing: { "\(n1) allows \($0); \(n0) does not." },
            shape: { "\(n0) and \(n1) describe \($0) with differently shaped rules." },
            dim: { v, path, x, y in "For \(v), \(n0) allows \(labelOf(path)) \(x); \(n1) allows \(y)." })
        return try diffClaims(try claimsOf(a, omega), try claimsOf(b, omega), w)
    }

    /// A concrete action in plain language; values are printed verbatim, so nothing is hidden.
    public static func renderAction(_ vs: WalletVerb, _ values: JSONValue?, _ catalog: PCACatalog = defaultCatalog) throws -> String {
        let what: String
        if let s = catalog.get(vs.verb) {
            // an action is described as the catalog words it (only the trailing period is dropped; the question forms lower-case the first letter)
            what = stripDot(s.description) + " [" + vs.verb + ", " + replaceFirst(vs.reversibility, "_", "-") + "]"
        } else {
            what = "perform \"" + vs.verb + "\" [uncatalogued: treated as irreversible]"
        }
        guard let o = values?.asObject else { throw fail("values must be an object") }
        let keys = o.keys.map { $0.s }.sorted { WJ.u16Less($0, $1) }
        var parts: [String] = []
        for k in keys {
            let v = o[JKey(k)]
            if let s = v?.asString { parts.append(labelOf(k) + " \"" + s + "\"") } else { parts.append(labelOf(k) + " " + str(v)) }
        }
        return "The agent wants to: " + what + (parts.isEmpty ? "" : ", with " + parts.joined(separator: ", ")) + "."
    }
}
