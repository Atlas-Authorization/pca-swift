import Foundation
import CryptoKit

// Hash-suite agility of core pca: the default suite, the digest length per suite, the dispatch over raw bytes and the canonical base64url length helpers,
// plus the named limits and domains of the pca_grant and pca_need protocols.
extension PCA {
    /// The DEFAULT suite. Absence of an explicit `hash_suite` MUST be read as this (back-compat).
    public static let DEFAULT_HASH_SUITE = "sha256"
    /// Digest byte length per suite.
    public static let HASH_LEN: [String: Int] = ["sha256": 32, "sha384": 48]

    /// True iff `s` is a known hash suite. Anything else MUST fail closed at the caller.
    public static func isHashSuite(_ s: JSONValue?) -> Bool { s == .string("sha256") || s == .string("sha384") }

    /// Dispatch a raw-byte hash over the selected suite (the default is byte-identical to a bare SHA-256). Throws on an unknown suite.
    public static func hashWithSuite(_ bytes: [UInt8], suite: String = DEFAULT_HASH_SUITE) throws -> [UInt8] {
        switch suite {
        case "sha256": return Canonical.sha256(bytes)
        case "sha384": return Array(SHA384.hash(data: Data(bytes)))
        default: throw JSError("hashWithSuite: unknown hash suite '\(suite)'")
        }
    }

    /// Encoded (unpadded) base64url length of `n` bytes.
    public static func b64uLen(_ n: Int) -> Int { (n * 4 + 2) / 3 }

    /// True iff `s` is canonical base64url (optionally of an exact decoded byte length).
    public static func isCanonicalB64u(_ s: JSONValue?, length: Int? = nil) -> Bool { s?.asString.map { Base64URLStrict.decode($0, length: length) != nil } ?? false }

    /// The domain of the digest over a pca_grant chain (`PcaGrant.chainDigest`).
    public static let PCA_GRANT_DOMAIN = PcaGrant.DOMAIN
    /// The most `pca_grant` details one authorization_details list may carry, and the longest chain one of them names.
    public static let PCA_GRANT_MAX_DETAILS = 16
    public static let PCA_GRANT_MAX_CHAIN_LEN = 16
    /// The digest an authorization server writes and a resource server recomputes: over the first hops' capability ids, in order.
    public static func pcaChainDigest(_ capIds: [String]) -> String { PcaGrant.chainDigest(capIds) }

    /// The domain of a `pca_need` digest, and the digest itself.
    public static let PCA_NEED_DOMAIN = "atlas-pca/need/v1"
    public static func pcaNeedDigest(_ need: JSONValue) -> String { A2a.needDigest(need) }
}
