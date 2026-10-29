import Foundation

/// Shared helpers of the K3 operational-plane artifacts (consistency tokens, policy bundles, decision logs, list receipts,
/// grant management): domain-separated Ed25519 signatures over `domain || strictCanonical(body)`. Every function is total.
enum K3Sig {
    /// A JSON number that is a non-negative safe integer.
    static func safeInt(_ v: JSONValue?) -> Int64? {
        guard let d = IV.safe(v), d >= 0 else { return nil }
        return Int64(d)
    }

    /// A non-empty string of at most `max` UTF-16 code units.
    static func str(_ v: JSONValue?, _ max: Int = 512) -> String? {
        guard let s = v?.asString, !s.isEmpty, IV.u16(s) <= max else { return nil }
        return s
    }

    /// Code-point string equality against an optional value (nil is never equal).
    static func eq(_ a: String?, _ b: String) -> Bool {
        guard let a = a else { return false }
        return IV.same(a, b)
    }

    /// True iff `sig` is a canonical 64-byte base64url signature by `signer` over exactly `domain || strictCanonical(body)`.
    static func verifyBody(_ domain: String, _ body: JSONValue, signer: String, sig: JSONValue?) -> Bool {
        guard let s = sig?.asString, Base64URLStrict.decode(s, length: 64) != nil,
              let msg = IV.message(domain, body) else { return false }
        return Ed25519Strict.verifyB64u(signer, msg, s)
    }

    static func without(_ o: JObject, _ key: String) -> JObject {
        var b = o
        b[JKey(key)] = nil
        return b
    }

    static func pick(_ o: JObject, _ keys: [String]) -> JObject {
        var out: JObject = [:]
        for k in keys { if let v = o[JKey(k)] { out[JKey(k)] = v } }
        return out
    }

    /// base64url(sha256(strictCanonical({d: domain, <key>: value}))); nil where the reference throws.
    static func digest(_ domain: String, _ key: String, _ value: JSONValue) -> String? {
        IV.strictHash(.object([JKey("d"): .string(domain), JKey(key): value]))
    }
}
