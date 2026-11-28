import Foundation

/// Import external authorization policy into PCA predicates: Cedar permit / forbid policies, OPA / Rego allow rules, an OpenFGA model
/// with its relationship tuples and strict CEL conditions (one file each: PolicyBridgeCedar / Rego / OpenFga / Cel). Every translator
/// returns `{predicates, denies, caveats, report: {source, translated, skipped, errors}}` as a `JSONValue`; whatever is not modeled
/// fails closed (a dropped `forbid` is an error, a dropped `permit` grants nothing). `decide` applies deny-overrides-permit on top of the
/// core predicate evaluator.
///
/// Text is read the way the reference reads it: UTF-16 code units, the JavaScript whitespace set, ASCII word characters, UTF-16
/// offsets in the CEL positions and in message truncation. The recursive parsers are bounded (`MAX_FRAMES`): past it a statement reports
/// the reference's own stack-overflow message and is dropped (fail closed).
///
/// shortcut: a lone UTF-16 surrogate cannot live in a Swift String, so a message that the reference cuts mid-pair (an
/// unexpected-character message, a truncation at 77 units) carries U+FFFD there.
public enum PCAPolicyBridge {
    /// Member order of an object as the producer wrote it (a parsed `JSONValue` object has none). The translators put the JavaScript
    /// own-key rule (array-index keys first) on top of what this returns; the default is `JSLoose.keys`.
    public typealias KeyOrder = (JObject) -> [String]

    static let STACK = "Maximum call stack size exceeded"
    static let MAX_FRAMES = 1000

    /// A refusal inside one statement / expression (caught by the translator and reported).
    struct Fail: Error { let message: String }

    final class Report {
        let source: String
        var translated: [String] = []
        var skipped: [String] = []
        var errors: [String] = []
        init(_ source: String) { self.source = source }
        var json: JSONValue {
            .object(["source": .string(source), "translated": PCAPolicyBridge.strs(translated), "skipped": PCAPolicyBridge.strs(skipped), "errors": PCAPolicyBridge.strs(errors)])
        }
    }

    static func strs(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }

    static func bridgeResult(_ predicates: [JSONValue], _ denies: [JSONValue], _ report: Report) -> JSONValue {
        .object(["predicates": .array(predicates), "denies": .array(denies), "caveats": .array([]), "report": report.json])
    }

    /// A leaf condition `{field, op, value?, ref?, collection?}`.
    static func leaf(_ field: String, _ op: String, value: JSONValue? = nil, ref: String? = nil, collection: String? = nil) -> JSONValue {
        var o: JObject = ["field": .string(field), "op": .string(op)]
        if let v = value { o["value"] = v }
        if let r = ref { o["ref"] = .string(r) }
        if let c = collection { o["collection"] = .string(c) }
        return .object(o)
    }

    static func allOf(_ xs: [JSONValue]) -> JSONValue { xs.count == 1 ? xs[0] : .object(["all_of": .array(xs)]) }
    static func anyOf(_ xs: [JSONValue]) -> JSONValue { xs.count == 1 ? xs[0] : .object(["any_of": .array(xs)]) }
    static func not(_ x: JSONValue) -> JSONValue { .object(["not": x]) }

    /// `Number(s)` of a decimal literal as the JSON value `JSON.stringify` would write (-0 is 0, a non-finite number is null).
    static func numberValue(_ s: String) -> JSONValue {
        let d = IV.jsNumber(s)
        if !d.isFinite { return .null }
        if d == d.rounded(.towardZero) && abs(d) <= Double(Canonical.MAX_SAFE) { return .int(Int64(d)) }
        return .double(d)
    }

    /// A predicate `{verb, resource?, where?}`.
    static func predicate(verb: JSONValue, resource: String?, where w: [JSONValue]) -> JSONValue {
        var o: JObject = ["verb": verb]
        if let r = resource { o["resource"] = .string(r) }
        if !w.isEmpty { o["where"] = .array(w) }
        return .object(o)
    }

    /// `Object.entries(o)` key order: array-index keys ascending, then the producer's order (`order`), else the code-unit order.
    static func orderedKeys(_ o: JObject, _ order: KeyOrder?) -> [String] {
        guard let order = order else { return JSLoose.keys(.object(o)) }
        let given = order(o)
        if given.count != o.count || Set(given.map { JKey($0) }) != Set(o.keys) { return JSLoose.keys(.object(o)) }
        let idx = given.compactMap { k in JS.indexKey(k).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        return idx + given.filter { JS.indexKey($0) == nil }
    }

    // ---- decide ----------------------------------------------------------------------------------------------------------------

    /// `evaluatePredicates(predicates, ctx)` as `{allowed, matched?, reason?}`: some predicate permits the action, else why not.
    static func evaluatePredicates(_ preds: JSONValue?, _ ctx: JSONValue) -> JSONValue {
        guard case let .array(ps)? = preds, !ps.isEmpty else { return .object(["allowed": .bool(false), "reason": .string("envelope grants no predicates")]) }
        let budget = SafeRegex.Budget()
        for p in ps where Predicates.predicateMatches(p, ctx, budget) { return .object(["allowed": .bool(true), "matched": p]) }
        let why = PCA.envelopePredicatesError(preds, ctx, budget) ?? "no predicate permits this action"
        return .object(["allowed": .bool(false), "reason": .string(why)])
    }

    /// Decide one action under a translation with deny-overrides-permit (Cedar's combining rule) on the core evaluator: any matching
    /// deny denies; otherwise the permit predicates decide. A translation that carries a report with errors denies everything (fail
    /// closed). A result of a shape the reference cannot read (no `denies`, a report without `errors`) is refused, as it throws there.
    public static func decide(_ result: JSONValue?, _ ctx: JSONValue?) throws -> JSONValue {
        let report = try JSLoose.rd(result, "report")
        if JS.truthy(report) {
            let errs = try JSLoose.rd(report, "errors")
            if JSLoose.lt(.int(0), try JSLoose.rd(errs, "length")) {
                return .object(["allowed": .bool(false), "reason": .string("translation incomplete (fail closed)")])
            }
        }
        let c = ctx ?? .null
        let denies = try JSLoose.rd(result, "denies")
        if JSLoose.lt(.int(0), try JSLoose.rd(denies, "length")) {
            let denied = evaluatePredicates(denies, c)
            if denied.get("allowed") == .bool(true) {
                var o: JObject = ["allowed": .bool(false), "reason": .string("forbidden by deny policy")]
                if let m = denied.get("matched") { o["matched"] = m }
                return .object(o)
            }
        }
        return evaluatePredicates(JSLoose.get(result, "predicates"), c)
    }
}

/// UTF-16 text helpers shared by the translators (the reference runs its regexes over UTF-16 code units).
enum PBT {
    typealias U = [UInt16]

    static func u(_ s: String) -> U { Array(s.utf16) }
    static func str(_ x: U) -> String { String(decoding: x, as: UTF16.self) }

    /// `x.slice(a, b)` for non-negative bounds (clamped).
    static func sub(_ x: U, _ a: Int, _ b: Int) -> U {
        let lo = max(0, min(a, x.count)), hi = max(lo, min(b, x.count))
        return Array(x[lo..<hi])
    }

    /// JavaScript `\s` and `trim`: whitespace plus line terminators.
    static func isWS(_ c: UInt16) -> Bool {
        switch c {
        case 0x09...0x0d, 0x20, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff: return true
        default: return false
        }
    }
    /// `\w`: ASCII word character.
    static func isWord(_ c: UInt16) -> Bool { (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c == 0x5f }
    /// `[A-Za-z_]`.
    static func isIdentStart(_ c: UInt16) -> Bool { (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c == 0x5f }
    static func isLineTerminator(_ c: UInt16) -> Bool { c == 0x0a || c == 0x0d || c == 0x2028 || c == 0x2029 }
    static func lower(_ c: UInt16) -> UInt16 { (c >= 0x41 && c <= 0x5a) ? c + 32 : c }

    static func trim(_ x: U) -> U {
        var a = 0, b = x.count
        while a < b && isWS(x[a]) { a += 1 }
        while b > a && isWS(x[b - 1]) { b -= 1 }
        return (a == 0 && b == x.count) ? x : Array(x[a..<b])
    }

    static func skipWS(_ x: U, _ from: Int) -> Int {
        var i = from
        while i < x.count && isWS(x[i]) { i += 1 }
        return i
    }

    static func startsWith(_ x: U, _ p: U, _ at: Int) -> Bool {
        if at < 0 || at + p.count > x.count { return false }
        var i = 0
        while i < p.count { if x[at + i] != p[i] { return false }; i += 1 }
        return true
    }

    static func indexOf(_ x: U, _ c: UInt16, from: Int = 0) -> Int {
        var i = max(0, from)
        while i < x.count { if x[i] == c { return i }; i += 1 }
        return -1
    }

    /// The message form of a source fragment: whitespace runs folded to one space, trimmed, cut to 77 units + "..." past 80.
    static func truncate(_ x: U) -> String {
        var out = U()
        var inWS = false
        for c in x {
            if isWS(c) { if !inWS { out.append(0x20); inWS = true } } else { out.append(c); inWS = false }
        }
        let t = trim(out)
        if t.count > 80 { return str(sub(t, 0, 77)) + "..." }
        return str(t)
    }

    /// Index of `token` at bracket / quote depth 0, or -1 (a bracket character is never a token start).
    static func indexOfTopLevel(_ text: U, _ token: U) -> Int {
        var depth = 0
        var inStr = false
        var i = 0
        while i < text.count {
            let ch = text[i]
            if inStr {
                if ch == 0x22 { inStr = false }
                i += 1
                continue
            }
            if ch == 0x22 {
                inStr = true
                i += 1
                continue
            }
            if ch == 0x28 || ch == 0x5b || ch == 0x7b { depth += 1 }
            else if ch == 0x29 || ch == 0x5d || ch == 0x7d { depth -= 1 }
            else if depth == 0 && startsWith(text, token, i) { return i }
            i += 1
        }
        return -1
    }

    /// Split on a delimiter at bracket / quote depth 0 (a quote ends at the next quote: there are no escapes).
    static func splitTopLevel(_ text: U, _ delim: U) -> [U] {
        var out: [U] = []
        var depth = 0
        var inStr = false
        var start = 0
        var i = 0
        while i < text.count {
            let ch = text[i]
            if inStr {
                if ch == 0x22 { inStr = false }
                i += 1
                continue
            }
            if ch == 0x22 {
                inStr = true
                i += 1
                continue
            }
            if ch == 0x28 || ch == 0x5b || ch == 0x7b { depth += 1 }
            else if ch == 0x29 || ch == 0x5d || ch == 0x7d { depth -= 1 }
            if depth == 0 && startsWith(text, delim, i) {
                out.append(sub(text, start, i))
                i += delim.count
                start = i
                continue
            }
            i += 1
        }
        out.append(sub(text, start, text.count))
        return out
    }

    /// Index of the delimiter closing the one at `open`, or -1.
    static func matchDelim(_ text: U, _ open: Int, _ o: UInt16, _ c: UInt16) -> Int {
        var depth = 0
        var inStr = false
        var i = open
        while i < text.count {
            let ch = text[i]
            if inStr {
                if ch == 0x22 { inStr = false }
            } else if ch == 0x22 {
                inStr = true
            } else if ch == o {
                depth += 1
            } else if ch == c {
                depth -= 1
                if depth == 0 { return i }
            }
            i += 1
        }
        return -1
    }

    /// `text.replace(/<comment-lead>[^\n]*/g, '')`: from each occurrence of `lead` to (not including) the next newline.
    static func stripComments(_ text: U, lead: U) -> U {
        var out = U()
        out.reserveCapacity(text.count)
        var i = 0
        while i < text.count {
            if startsWith(text, lead, i) {
                while i < text.count && text[i] != 0x0a { i += 1 }
                continue
            }
            out.append(text[i])
            i += 1
        }
        return out
    }

    /// `^[\w.]+$`-style run test.
    static func allWordOrDot(_ x: U) -> Bool { x.allSatisfy { isWord($0) || $0 == 0x2e } }

    /// `s.slice(1, -1)`.
    static func inner(_ x: U) -> U { x.count < 2 ? [] : sub(x, 1, x.count - 1) }
}
