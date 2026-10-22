import Foundation
import CryptoKit

/// Canonical JSON, the strict JSON profile, strict base64url and SHA-256 — ported byte-for-byte from
/// `@atlasauth/pca`'s `hash.ts` / `strict-json.ts` (and matching the Rust / Go / .NET verifiers). This is
/// the make-or-break cross-language layer: every digest and signed message is computed over these bytes.
enum Canonical {
    static let MAX_SAFE: Int64 = 9_007_199_254_740_991 // 2^53 - 1
    static let MAX_JSON_DEPTH = 32
    /// Recursion bound of the NON-strict paths (lenient canonicalization of a caller-supplied grant / Merkle leaf and the
    /// lenient corpus loader). Far above anything signable (the strict profile stops at MAX_JSON_DEPTH), so it never
    /// changes a verdict; it only turns a stack overflow on a hostile, absurdly deep tree into a clean refusal.
    static let MAX_LENIENT_DEPTH = 1024
    static let MAX_JSON_BYTES = 1 << 20
    static let MAX_DECIMAL_DIGITS = 15

    /// Sentinel scalar the conformance TEST HARNESS substitutes for a lone surrogate (which a Swift `String` cannot
    /// hold) when it loads object-form vectors; the harness itself treats a tree carrying it as a `wire` failure.
    /// It is a Unicode NONCHARACTER (never a legitimate interchange scalar and absent from the corpus). The library
    /// does NOT interpret it: the strict parser already rejects every lone surrogate in raw text, and an earlier
    /// version that used U+10FFFF here wrongly rejected a VALID U+10FFFF (`\uDBFF\uDFFF`) in signed content.
    static let LONE_SURROGATE_SENTINEL: Unicode.Scalar = Unicode.Scalar(0xFDD0)!

    static func hasLoneSurrogate(_ s: String) -> Bool {
        s.unicodeScalars.contains(LONE_SURROGATE_SENTINEL)
    }

    // ---- hashing / base64url ----

    static func sha256(_ bytes: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: Data(bytes))) }
    static func utf8(_ s: String) -> [UInt8] { Array(s.utf8) }

    /// UTF-8 bytewise comparison (== Unicode code point order).
    static func compareUtf8(_ a: String, _ b: String) -> Int {
        let x = Array(a.utf8), y = Array(b.utf8)
        let n = min(x.count, y.count)
        var i = 0
        while i < n {
            if x[i] != y[i] { return Int(x[i]) - Int(y[i]) }
            i += 1
        }
        return x.count - y.count
    }

    // ---- canonical number form (matches ECMAScript Number::toString for the in-profile range) ----

    /// Strict-profile check of one double. Returns an error string, or nil when acceptable.
    static func doubleError(_ d: Double) -> String? {
        if !d.isFinite { return "non-finite number" }
        if d == 0 && d.sign == .minus { return "negative zero" }
        if d.rounded() == d { return abs(d) > Double(MAX_SAFE) ? "integer outside the safe range (|n| > 2^53-1)" : nil }
        if abs(d) < 1e-6 { return "non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)" }
        let plain = numberString(abs(d))
        let noDot = plain.filter { $0 != "." }
        let sig = noDot.drop(while: { $0 == "0" })
        if sig.count > MAX_DECIMAL_DIGITS { return "non-integer number has more than 15 significant digits" }
        return nil
    }

    static func intError(_ i: Int64) -> String? {
        (i < -MAX_SAFE || i > MAX_SAFE) ? "integer outside the safe range (|n| > 2^53-1)" : nil // not abs(): abs(Int64.min) traps
    }

    /// The canonical decimal for a double: shortest round-trip (via Swift's `description`) re-rendered as a
    /// PLAIN decimal with no exponent, no trailing `.0`, no leading `+`/zeros — i.e. JS `Number.toString`.
    static func numberString(_ d: Double) -> String {
        if d == 0 { return "0" }
        let neg = d < 0
        let a = abs(d)
        if a.rounded() == a && a < 9_007_199_254_740_992.0 { // 2^53: representable integer, print as integer
            return (neg ? "-" : "") + String(Int64(a))
        }
        var s = "\(a)" // Swift shortest round-trip, e.g. "1.5", "1e-05", "1.23e+18", "123456789012.5"
        var exp = 0
        if let eIdx = s.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            exp = Int(s[s.index(after: eIdx)...]) ?? 0
            s = String(s[..<eIdx])
        }
        var intPart = s
        var fracPart = ""
        if let dot = s.firstIndex(of: ".") {
            intPart = String(s[..<dot])
            fracPart = String(s[s.index(after: dot)...])
        }
        var digits = Array(intPart + fracPart)
        var e10 = exp - fracPart.count
        while digits.count > 1 && digits.first == "0" { digits.removeFirst() }
        while digits.count > 1 && digits.last == "0" { digits.removeLast(); e10 += 1 }
        if digits == ["0"] { return "0" }
        let n = digits.count
        let out: String
        if e10 >= 0 {
            out = String(digits) + String(repeating: "0", count: e10)
        } else {
            let k = -e10
            if k < n {
                out = String(digits[0..<(n - k)]) + "." + String(digits[(n - k)...])
            } else {
                out = "0." + String(repeating: "0", count: k - n) + String(digits)
            }
        }
        return (neg ? "-" : "") + out
    }

    // ---- canonical serialization ----

    struct CanonicalError: Error { let message: String }

    /// Lenient canonical JSON (capability content addressing, Merkle leaves). Never throws for in-profile data.
    /// Out-of-profile input (non-finite number, nesting deeper than MAX_LENIENT_DEPTH) yields "" (whose hash matches no
    /// real canonical form), never a truncated prefix that two different trees could share.
    static func canonicalize(_ v: JSONValue) -> String {
        var out = ""
        do { try ser(&out, v, strict: false, depth: 1) } catch { return "" }
        return out
    }

    /// Strict canonical form of a signed body (wire v2). Throws on any out-of-profile value.
    static func canonicalizeStrict(_ v: JSONValue) throws -> String {
        var out = ""
        try ser(&out, v, strict: true, depth: 1)
        return out
    }

    private static func jsString(_ out: inout String, _ s: String) {
        out.append("\"")
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out.append("\\\"")
            case "\\": out.append("\\\\")
            case "\u{08}": out.append("\\b")
            case "\u{0C}": out.append("\\f")
            case "\n": out.append("\\n")
            case "\r": out.append("\\r")
            case "\t": out.append("\\t")
            default:
                if scalar.value < 0x20 {
                    out.append(String(format: "\\u%04x", scalar.value))
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out.append("\"")
    }

    private static func ser(_ out: inout String, _ v: JSONValue, strict: Bool, depth: Int) throws {
        switch v {
        case .null: out.append("null")
        case let .bool(b): out.append(b ? "true" : "false")
        case let .string(s):
            jsString(&out, s)
        case let .int(i):
            if strict, let e = intError(i) { throw CanonicalError(message: "canonicalize: \(e)") }
            out.append(String(i))
        case let .double(d):
            if strict {
                if let e = doubleError(d) { throw CanonicalError(message: "canonicalize: \(e)") }
            } else if !d.isFinite {
                throw CanonicalError(message: "canonicalize: non-finite number")
            }
            out.append(numberString(d))
        case let .array(a):
            if depth > (strict ? MAX_JSON_DEPTH : MAX_LENIENT_DEPTH) { throw CanonicalError(message: "canonicalize: nesting too deep") }
            out.append("[")
            for (i, x) in a.enumerated() {
                if i > 0 { out.append(",") }
                try ser(&out, x, strict: strict, depth: depth + 1)
            }
            out.append("]")
        case let .object(o):
            if depth > (strict ? MAX_JSON_DEPTH : MAX_LENIENT_DEPTH) { throw CanonicalError(message: "canonicalize: nesting too deep") }
            let keys = o.keys.sorted { compareUtf8($0.s, $1.s) < 0 }
            out.append("{")
            for (i, k) in keys.enumerated() {
                if i > 0 { out.append(",") }
                jsString(&out, k.s)
                out.append(":")
                try ser(&out, o[k]!, strict: strict, depth: depth + 1)
            }
            out.append("}")
        }
    }

    static func canonicalBytes(_ v: JSONValue) throws -> [UInt8] { try utf8(canonicalizeStrict(v)) }

    /// base64url(sha256(lenient canonical(v))).
    static func hashCanonical(_ v: JSONValue) -> String {
        Base64URLStrict.encode(sha256(utf8(canonicalize(v))))
    }
}
