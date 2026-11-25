import Foundation
import CAda

/// Algorithms with no vetted implementation inside AtlasPCAVerify. The opt-in AtlasPCAOpenSSL product registers them (libcrypto);
/// while a hook is nil the caller refuses (fails closed), it never falls back to another algorithm.
public enum PCAExtraCrypto {
    /// RS256/384/512 and PS256/384/512 signing: (alg, the decoded private JWK members n, e, d, p, q, dp, dq, qi as big-endian bytes, message) -> signature.
    public static var rsaSign: ((String, [String: [UInt8]], [UInt8]) throws -> [UInt8])?

    /// Ed448 (RFC 8032): verify (57-byte public key, message, 114-byte signature), sign (57-byte private seed, message) and the public key of a seed.
    public static var ed448Verify: (([UInt8], [UInt8], [UInt8]) -> Bool)?
    public static var ed448Sign: (([UInt8], [UInt8]) throws -> [UInt8])?
    public static var ed448PublicKey: (([UInt8]) -> [UInt8]?)?

    /// The WHATWG host parser's domain-to-ASCII (UTS 46, as Node's `url.domainToASCII`); nil or "" = refused. Ada (CAda, linked into the verifier) by default; a registered replacement wins, nil refuses a non-ASCII host.
    public static var domainToASCII: ((String) -> String?)? = { adaDomainToASCII($0) }

    static func adaDomainToASCII(_ host: String) -> String? {
        let bytes = Array(host.utf8)
        var out = [UInt8](repeating: 0, count: 2048)
        var n = 0
        guard atlas_ada_domain_to_ascii(bytes, bytes.count, &out, out.count, &n) == 1, n > 0, n <= out.count else { return nil }
        return String(decoding: out[0..<n], as: UTF8.self)
    }

    static let rsaMembers = ["n", "e", "d", "p", "q", "dp", "dq", "qi"]

    /// The RSA private JWK members as bytes; every CRT member is required (fail closed otherwise).
    static func rsaPrivateParts(_ jwk: JObject) throws -> [String: [UInt8]] {
        var out: [String: [UInt8]] = [:]
        for m in rsaMembers {
            guard let s = jwk[JKey(m)]?.asString, let b = Base64URLStrict.decode(s), !b.isEmpty else { throw JSError("Invalid JWK RSA key") }
            out[m] = b
        }
        return out
    }
}
