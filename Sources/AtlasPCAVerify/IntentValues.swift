import Foundation

/// Shared value rules of Intent Layer v2 (conformance rules 13-18), so this verifier reaches the SAME verdict as the
/// reference and the other natives on every input: numbers are IEEE-754 binary64 (an integer lexeme and a fractional
/// lexeme of the same value are the same number), strings compare by code point (never by Swift's canonical equivalence),
/// the `^[...]{m,n}$` name patterns are ASCII, and the strict canonical form is the shared `Canonical.canonicalizeStrict`
/// (a string carrying the lone-surrogate sentinel is refused, like a lone surrogate in the reference).
enum IV {
    static let MAX_SAFE = Double(Canonical.MAX_SAFE)

    // ---- numbers ----

    /// The binary64 value of a JSON number (`typeof x === 'number'`), else nil.
    static func num(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        default: return nil
        }
    }

    static func isNegZero(_ d: Double) -> Bool { d == 0 && d.sign == .minus }

    /// `Number.isSafeInteger(x)` (accepts -0).
    static func safe(_ v: JSONValue?) -> Double? {
        guard let d = num(v), d.isFinite, d.rounded(.towardZero) == d, abs(d) <= MAX_SAFE else { return nil }
        return d
    }

    /// A safe integer that is not -0 (`isSafeInt` of intent-artifacts.ts, `isInt` of action-schema.ts / intent-session.ts).
    static func int(_ v: JSONValue?) -> Int64? {
        guard let d = safe(v), !isNegZero(d) else { return nil }
        return Int64(d)
    }

    /// A non-negative safe integer that is not -0.
    static func nonNeg(_ v: JSONValue?) -> Int64? {
        guard let i = int(v), i >= 0 else { return nil }
        return i
    }

    /// `Number.isSafeInteger(d)` on a computed binary64.
    static func isSafeDouble(_ d: Double) -> Bool { d.isFinite && d.rounded(.towardZero) == d && abs(d) <= MAX_SAFE }

    // ---- strings ----

    static func str(_ v: JSONValue?) -> String? { v?.asString }

    /// A string from a sequence of scalars.
    static func text<S: Sequence>(_ scalars: S) -> String where S.Element == Unicode.Scalar {
        var v = String.UnicodeScalarView()
        v.append(contentsOf: scalars)
        return String(v)
    }

    /// Code-point string equality (never Swift canonical equivalence).
    static func same(_ a: String, _ b: String) -> Bool { a.unicodeScalars.elementsEqual(b.unicodeScalars) }
    static func same(_ a: String?, _ b: String?) -> Bool {
        guard let x = a, let y = b else { return false }
        return same(x, y)
    }

    static func startsWith(_ s: String, _ p: String) -> Bool { s.unicodeScalars.starts(with: p.unicodeScalars) }
    static func endsWith(_ s: String, _ p: String) -> Bool {
        let a = Array(s.unicodeScalars), b = Array(p.unicodeScalars)
        return a.count >= b.count && Array(a[(a.count - b.count)...]) == b
    }
    /// `s.slice(n)` for an ASCII prefix of length n.
    static func dropPrefix(_ s: String, _ n: Int) -> String { text((s.unicodeScalars.dropFirst(n))) }
    static func split(_ s: String, _ sep: Unicode.Scalar) -> [String] {
        s.unicodeScalars.split(separator: sep, omittingEmptySubsequences: false).map { text(($0)) }
    }
    static func u8(_ s: String) -> Int { s.utf8.count }
    /// UTF-16 length (`s.length`).
    static func u16(_ s: String) -> Int { s.utf16.count }

    /// `isBoundedString`: a non-empty string of at most `max` UTF-8 bytes.
    static func bounded(_ v: JSONValue?, _ max: Int) -> String? {
        guard let s = v?.asString, !s.isEmpty, u8(s) <= max else { return nil }
        return s
    }

    /// Canonical base64url of exactly 32 bytes.
    static func digest(_ v: JSONValue?) -> String? {
        guard let s = v?.asString, Base64URLStrict.isValid(s, length: 32) else { return nil }
        return s
    }

    static func contains(_ xs: [String], _ x: String) -> Bool { xs.contains { same($0, x) } }

    /// `[...new Set(xs)].length === xs.length` over strings.
    static func distinct(_ xs: [String]) -> Bool { Set(xs.map { JKey($0) }).count == xs.count }

    /// UTF-8 byte order (compareUtf8), as a sort predicate.
    static func utf8Less(_ a: String, _ b: String) -> Bool { a.utf8.lexicographicallyPrecedes(b.utf8) }

    // ---- ASCII name patterns ----

    private static func alnum(_ c: Unicode.Scalar) -> Bool {
        (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A)
    }
    private static func lowerDigitUnderscore(_ c: Unicode.Scalar) -> Bool {
        (c.value >= 0x61 && c.value <= 0x7A) || (c.value >= 0x30 && c.value <= 0x39) || c == "_"
    }

    /// `^[A-Za-z0-9_]{1,64}$`
    static func isId(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        return (1...64).contains(u.count) && u.allSatisfy { alnum($0) || $0 == "_" }
    }
    /// `^action\.params\.[A-Za-z0-9_]{1,64}$`
    static func isTopParamPath(_ s: String) -> Bool { startsWith(s, "action.params.") && isId(dropPrefix(s, 14)) }
    /// `^[a-z0-9_]+(?:\.[a-z0-9_]+)*$`
    static func isUnitId(_ s: String) -> Bool {
        split(s, ".").allSatisfy { !$0.isEmpty && $0.unicodeScalars.allSatisfy(lowerDigitUnderscore) }
    }
    /// `^[a-z][a-z0-9_]{0,63}$`
    static func isName(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        guard (1...64).contains(u.count), u[0].value >= 0x61, u[0].value <= 0x7A else { return false }
        return u.dropFirst().allSatisfy(lowerDigitUnderscore)
    }
    /// `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`
    static func isDataClass(_ s: String) -> Bool {
        let segs = split(s, ".")
        guard let first = segs.first, let c0 = first.unicodeScalars.first, c0.value >= 0x61, c0.value <= 0x7A,
              first.unicodeScalars.allSatisfy(lowerDigitUnderscore) else { return false }
        return segs.dropFirst().allSatisfy { !$0.isEmpty && $0.unicodeScalars.allSatisfy(lowerDigitUnderscore) }
    }
    static let FORBIDDEN_SEGMENTS: Set<String> = ["__proto__", "constructor", "prototype"]
    /// `^[A-Za-z0-9_-]{1,64}$` and not a prototype name.
    static func isPathSegment(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        return (1...64).contains(u.count) && u.allSatisfy { alnum($0) || $0 == "_" || $0 == "-" } && !FORBIDDEN_SEGMENTS.contains(s)
    }

    // ---- values ----

    /// Primitive equality: same JSON type and value (numbers as binary64, strings by code point); containers are never equal.
    static func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case (.null?, .null?): return true
        case let (.bool(x)?, .bool(y)?): return x == y
        case let (.string(x)?, .string(y)?): return same(x, y)
        default:
            if let x = num(a), let y = num(b) { return x == y }
            return false
        }
    }

    /// A wire scalar: a string, a boolean or a safe integer (not -0).
    static func isScalar(_ v: JSONValue?) -> Bool {
        switch v {
        case .string?, .bool?: return true
        default: return int(v) != nil
        }
    }

    /// Scalar equality: same JSON type and value (`1 !== "1"`, `true !== 1`).
    static func scalarEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.bool(x)?, .bool(y)?): return x == y
        case let (.string(x)?, .string(y)?): return same(x, y)
        default:
            if let x = num(a), let y = num(b) { return x == y }
            return false
        }
    }

    static func hasSentinel(_ v: JSONValue) -> Bool {
        switch v {
        case let .string(s): return Canonical.hasLoneSurrogate(s)
        case let .array(a): return a.contains(where: hasSentinel)
        case let .object(o): return o.contains { Canonical.hasLoneSurrogate($0.key.s) || hasSentinel($0.value) }
        default: return false
        }
    }

    /// `canonicalizeStrict(v)`: nil where the reference throws (non-strict number, lone surrogate, depth > 32).
    static func strictCanon(_ v: JSONValue) -> String? {
        if hasSentinel(v) { return nil }
        return try? Canonical.canonicalizeStrict(v)
    }

    /// The reference's message when `canonicalizeStrict(v)` throws (nil when it does not).
    static func strictCanonError(_ v: JSONValue) -> String? {
        if hasSentinel(v) { return "canonicalize: lone surrogate in string" }
        do { _ = try Canonical.canonicalizeStrict(v); return nil } catch { return (error as? Canonical.CanonicalError)?.message ?? "\(error)" }
    }

    /// `hashCanonical(v)` = base64url(sha256(strictCanonical(v))); nil where the reference throws.
    static func strictHash(_ v: JSONValue) -> String? {
        guard let c = strictCanon(v) else { return nil }
        return Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(c)))
    }

    /// `utf8(domain) || strictCanonical(v)`; nil where the reference throws.
    static func message(_ domain: String, _ v: JSONValue) -> [UInt8]? {
        guard let c = strictCanon(v) else { return nil }
        return Canonical.utf8(domain) + Canonical.utf8(c)
    }

    /// Normalise a value loaded by the lenient parser to what `JSON.parse` yields: an integer lexeme outside the safe range
    /// becomes the nearest binary64 (a JSON number is a binary64 in every verifier).
    static func normalized(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .int(i): return (i >= -Canonical.MAX_SAFE && i <= Canonical.MAX_SAFE) ? v : .double(Double(i))
        case let .array(a): return .array(a.map(normalized))
        case let .object(o): return .object(o.mapValues(normalized))
        default: return v
        }
    }

    /// The suite an artifact names: absent = "ed25519", a string = that name (whether this verifier implements it is the
    /// suite dispatch's decision, `PQ.resolve`), anything else = nil (malformed).
    static func sigAlg(_ v: JSONValue?) -> String? {
        guard let v = v else { return "ed25519" }
        return v.asString
    }

    /// `bindSuiteFields(base, alg, pqPk)`: a non-ed25519 suite binds `alg` and `pq_pk` into the signed body (a missing
    /// `pq_pk` cannot be encoded: nil).
    static func bindSuite(_ base: JObject, alg: JSONValue?, pqPk: JSONValue?) -> JObject? {
        guard let a = sigAlg(alg) else { return nil }
        if a == "ed25519" { return base }
        guard let pk = pqPk else { return nil }
        var o = base
        o["alg"] = .string(a)
        o["pq_pk"] = pk
        return o
    }

    /// Outcome of a suite-agile signature check.
    enum SuiteVerdict { case valid, invalid, unsupported }
    static let UNSUPPORTED_SUITE = "unsupported_suite"

    /// Suite capability of an artifact's `alg`: absent = ed25519 (nil); a non-string is malformed; a string the suite
    /// dispatch does not resolve is `unsupported_suite` (never accepted, never another reason).
    static func suiteError(_ alg: JSONValue?) -> String? {
        guard let a = alg else { return nil }
        guard let s = a.asString else { return "alg must be a string" }
        return PQ.resolve(s) == nil ? "\(UNSUPPORTED_SUITE): '\(s)'" : nil
    }

    /// Names the predicate DSL cannot address; refused as accumulator, monitor and schema parameter names.
    static let RESERVED_NAMES: Set<String> = ["__proto__", "constructor", "prototype"]
    static func isReserved(_ s: String) -> Bool { RESERVED_NAMES.contains { same($0, s) } }

    /// A non-negative safe integer that is not -0 (`isSafeNonNeg`).
    static func isSafeNonNeg(_ v: JSONValue?) -> Bool { nonNeg(v) != nil }

    /// `verifyPinnedSuite(alg, identity, artifactPqPk, msg, {sig, pq_sig}, pin)` through the SDK's suite dispatch: an alg the
    /// dispatch does not resolve is `unsupported` (fail closed with reason `unsupported_suite`); a PQ half verifies only
    /// under the artifact's `pq_pk` when it equals the verifier's pin for `identity`.
    static func verifyPinned(alg: JSONValue?, identity: String, artifactPqPk: JSONValue?, msg: [UInt8], sig: JSONValue?,
                             pqSig: JSONValue?, pin: String?) -> SuiteVerdict {
        guard let a = sigAlg(alg) else { return .invalid }
        guard let suite = PQ.resolve(a) else { return .unsupported }
        var key: PinnedPQ?
        if suite.needsPqPk {
            guard let p = pin, let apk = artifactPqPk?.asString, !apk.isEmpty,
                  let k = PQ.resolvePqKey(identity: identity, artifactPk: apk, pqPins: [identity: p]) else { return .invalid }
            key = k
        }
        return PQ.verifySuite(alg: a, holder: identity, pq: key, message: msg, sig: sig?.asString, pqSig: pqSig?.asString) ? .valid : .invalid
    }

    /// `verifyB64u(pk, msg, sig)` over a strict Ed25519 signature (the W-B artifacts, rules 16-18).
    static func verifyEd(_ pk: String, _ msg: [UInt8], _ sig: JSONValue?) -> Bool {
        guard let s = sig?.asString else { return false }
        return Ed25519Strict.verifyB64u(pk, msg, s)
    }
}
