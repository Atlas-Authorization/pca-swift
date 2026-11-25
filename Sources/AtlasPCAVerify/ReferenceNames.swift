import Foundation
import CryptoKit

// The reference package's flat helper names that the lane implements under other spellings or only internally: each is a thin public form over the implementation that
// already replays the reference's corpora.

extension PCA {
    /// SHA-384 of `bytes`.
    public static func sha384(_ bytes: [UInt8]) -> [UInt8] { Array(SHA384.hash(data: Data(bytes))) }

    /// The base64url (unpadded) text of a public key (the reference's `encodeKey`).
    public static func encodeKey(_ key: [UInt8]) -> String { Base64URLStrict.encode(key) }

    /// Strict RFC 8032 verification over a base64url public key (32 bytes) and signature (64 bytes); false on a non-canonical encoding, a wrong length or a failed check.
    public static func verifyB64u(_ publicKeyB64u: String, _ message: [UInt8], _ signatureB64u: String) -> Bool {
        Ed25519Strict.verifyB64u(publicKeyB64u, message, signatureB64u)
    }

    /// The RSA public-key rule applied before any verify: modulus 512...16384 bits, an odd public exponent >= 3 that fits 32 bits (big-endian magnitudes). (Other key types pass in the
    /// reference; there is no other type here.)
    public static func rsaKeyOk(modulus: [UInt8], exponent: [UInt8]) -> Bool { ACrypto.rsaKeyOK(n: modulus, e: exponent) }

    /// The strict RFC 5280 Time of a certificate field, in epoch milliseconds: tag 0x17 UTCTime "YYMMDDHHMMSSZ" (YY >= 50 is 19YY) or tag 0x18 GeneralizedTime "YYYYMMDDHHMMSSZ", every field in
    /// range, no roll-over, no fraction, no offset. NaN for anything else (fail closed).
    public static func parseDerTime(_ tag: Int, _ text: String) -> Double { DER.parseDerTime(tag, Array(text.utf8)).map { Double($0) } ?? .nan }

    /// G-T9: a model can only tighten; `tighten(d, s) <= d` for every signal, and `tighten(d, "ok") = d` (the reference's name for `tightenDecision`).
    public static func tighten(_ base: String, _ signal: JSONValue?) -> String { tightenDecision(base, signal: signal) }

    /// The reference's `evaluatePredicates(predicates, ctx)`: `{allowed: true, matched}` for the first predicate that matches (verb AND resource AND every `where`), else
    /// `{allowed: false, reason}`. Default-deny: an empty or non-list predicate set allows nothing.
    public static func evaluatePredicates(_ predicates: JSONValue?, _ ctx: JSONValue) -> JSONValue {
        guard case let .array(ps)? = predicates, !ps.isEmpty else { return .object(["allowed": .bool(false), "reason": .string("envelope grants no predicates")]) }
        let budget = SafeRegex.Budget()
        if let p = ps.first(where: { Predicates.predicateMatches($0, ctx, budget) }) { return .object(["allowed": .bool(true), "matched": p]) }
        return .object(["allowed": .bool(false), "reason": .string(envelopePredicatesError(predicates, ctx, budget) ?? "no predicate permits this action")])
    }
}

extension Workflow {
    /// A receipt output for the scalar `value` (a string, a boolean or a safe integer): `{digest, num, unit, labels}`; `num` is carried only for an integer an edge may compare.
    /// Labels are sorted (UTF-16 order, as the reference's `sort()`); nil for a value that is not a scalar.
    public static func wfOutput(_ value: JSONValue, labels: [String] = [], unit: String? = nil, num: Bool = false) -> JSONValue? {
        switch value {
        case .string, .bool: break
        case let .int(i) where i >= -Canonical.MAX_SAFE && i <= Canonical.MAX_SAFE: break
        default: return nil
        }
        guard let d = valueDigest(value) else { return nil }
        var n: JSONValue = .null
        if num, case .int = value { n = value }
        return .object(["digest": .string(d), "num": n, "unit": unit.map { .string($0) } ?? .null,
                        "labels": .array(labels.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.map { .string($0) })])
    }
}
