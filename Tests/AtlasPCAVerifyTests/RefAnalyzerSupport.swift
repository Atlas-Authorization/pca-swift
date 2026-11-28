import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Shared plumbing of the policy-analyzer replays. The corpus spells a non-finite number as {"$num": "Infinity"} (JSON has none) and
/// a key as "$key:LABEL" (the public key of the Ed25519 seed sha256("atlas-pca-conformance/" + LABEL)).
enum RefAnalyzer {
    static let file = "ref-analyzer.json.gz"

    /// {"$num": "Infinity" | "-Infinity" | "NaN"} -> the number (arguments).
    static func revive(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(revive))
        case let .object(o):
            if o.count == 1, let s = o["$num"]?.asString { return .double(s == "Infinity" ? .infinity : s == "-Infinity" ? -.infinity : .nan) }
            return .object(o.mapValues(revive))
        default: return v
        }
    }

    /// A non-finite number -> {"$num": ...} (results), as the reference spells it.
    static func out(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .double(d) where d.isNaN: return .object(["$num": .string("NaN")])
        case let .double(d) where d.isInfinite: return .object(["$num": .string(d > 0 ? "Infinity" : "-Infinity")])
        case let .array(a): return .array(a.map(out))
        case let .object(o): return .object(o.mapValues(out))
        default: return v
        }
    }

    static func seed(_ label: String) -> [UInt8] { Canonical.sha256(Array("atlas-pca-conformance/\(label)".utf8)) }

    /// The key of a label (deterministic RFC 8032 signing, as the reference signs).
    static func key(_ label: String) throws -> PCAEdKey { try Ed25519Deterministic.key(seed: seed(label)) }

    /// "$key:LABEL" -> the base64url public key of the label, anywhere in the value.
    static func keyed(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .string(s) where s.hasPrefix("$key:"): return .string(Base64URLStrict.encode(Ed25519Deterministic.publicKey(seed: seed(String(s.dropFirst(5))))))
        case let .array(a): return .array(a.map(keyed))
        case let .object(o): return .object(o.mapValues(keyed))
        default: return v
        }
    }

    /// Runs a call over revived arguments; its result is spelled like the reference's; a throw is a refusal.
    static func run(_ f: () throws -> JSONValue) -> BaseGot { Ref.v { out(try f()) } }

    /// The i-th argument, revived (nil when absent).
    static func arg(_ c: BaseCase, _ i: Int) -> JSONValue? { c.arg(i).map(revive) }
}
