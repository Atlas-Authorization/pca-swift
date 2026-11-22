import Foundation
import CryptoKit

/// The wire primitives the opt-in pairing packages (AtlasPCAPairing) share with this verifier: canonical JSON, the canonical
/// hash, strict base64url and SHA-256, exactly as the core checks use them. A thin public face over the internal types.
public enum PCAWire {
    /// base64url(sha256(canonical(v))), the identity hash of every signed artifact.
    public static func hashCanonical(_ v: JSONValue) -> String { Canonical.hashCanonical(v) }

    /// The strict form of `hashCanonical` (throws outside the strict profile), as the reference's `hashCanonical` does.
    public static func hashCanonicalStrict(_ v: JSONValue) throws -> String {
        b64uEncode(sha256(Array(try Canonical.canonicalizeStrict(v).utf8)))
    }

    /// RFC 8785-style canonical text of `v`; throws when `v` is outside the strict profile.
    public static func canonicalStrict(_ v: JSONValue) throws -> String { try Canonical.canonicalizeStrict(v) }

    /// Canonical text of a value from a lenient source (a caller-supplied capability).
    public static func canonical(_ v: JSONValue) -> String { Canonical.canonicalize(v) }

    public static func b64uEncode(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }

    /// Strict (unpadded, canonical-final-character) base64url; nil on any deviation.
    public static func b64uDecode(_ s: String) -> [UInt8]? { Base64URLStrict.decode(s) }

    public static func sha256(_ b: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: Data(b))) }

    /// The signed message of a PCActn leaf: SIG_DOMAIN || sha256(strictCanonical(leaf without sig, threshold, pq_sig)). Throws unless `leaf` is a strict-profile object.
    public static func leafMessage(_ leaf: JSONValue) throws -> [UInt8] {
        guard case let .object(o) = leaf else { throw PCAProducerError("leafMessage: the leaf must be an object") }
        return try PCA.thresholdMessage(o)
    }

    /// Strict RFC 8032 Ed25519 verification (S < L, small-/mixed-order keys and R refused) of base64url public key and signature over `msg`.
    public static func ed25519Verify(publicKeyB64u: String, message: [UInt8], signatureB64u: String) -> Bool {
        Ed25519Strict.verifyB64u(publicKeyB64u, message, signatureB64u)
    }

    /// Lenient JSON parse (JSON.parse semantics); throws on malformed text.
    public static func parseLenient(_ text: String) throws -> JSONValue { try StrictJSON.parseLenient(text) }

    /// Capability-chain verification (root first): nil when the chain verifies, else the refusal reason. `expectedRootIssuer` pins
    /// the root issuer; `pqPins` pins post-quantum root authority by Ed25519 root identity.
    public static func verifyChain(_ chain: [JSONValue], expectedRootIssuer: String?, pqPins: [String: String]?) -> String? {
        Capability.verifyChain(chain, expectedRootIssuer: expectedRootIssuer, pqPins: pqPins)
    }

    /// The grant's policy envelope (its first `envelope` caveat without `type`), or nil when absent or malformed.
    public static func readEnvelope(_ grant: JSONValue) -> JSONValue? { PCA.readEnvelope(grant) }

    /// A `JSONValue` member (nil when `v` is not an object or the key is absent).
    public static func member(_ v: JSONValue, _ key: String) -> JSONValue? { v.get(key) }
}

extension JSONValue {
    public var stringValue: String? { asString }
    public var arrayValue: [JSONValue]? { asArray }
    public var objectValue: JObject? { asObject }
}
