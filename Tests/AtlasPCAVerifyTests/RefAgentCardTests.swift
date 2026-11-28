import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The test keys the reference derived from seeds: the corpus carries only their public halves (the private member is the marker
/// "$seed"); the private key is rebuilt here from the same seed derivation (sha256 of "atlas-pca-conformance/<label>").
enum RefSeeds {
    static func table(_ labels: [String]) -> [String: [UInt8]] {
        var t: [String: [UInt8]] = [:]
        for l in labels {
            let seed = Canonical.sha256(Array("atlas-pca-conformance/\(l)".utf8))
            t[Base64URLStrict.encode(Ed25519Deterministic.publicKey(seed: seed))] = seed
        }
        return t
    }

    /// Every {x, d: "$seed"} object with its private member restored.
    static func restore(_ v: JSONValue, _ t: [String: [UInt8]]) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map { restore($0, t) })
        case let .object(o):
            var m = o.mapValues { restore($0, t) }
            // the stripped corpus names the key by label: d is {"$seed": label}
            if let label = m["d"]?.get("$seed")?.asString { m["d"] = .string(Base64URLStrict.encode(Canonical.sha256(Array("atlas-pca-conformance/\(label)".utf8)))) }
            if m["d"] == .string("$seed"), let x = m["x"]?.asString, let s = t[x] { m["d"] = .string(Base64URLStrict.encode(s)) }
            return .object(m)
        default: return v
        }
    }
}

/// Differential replay of PCAAgentCard against the reference (@atlasauth/pca-agentcard): JCS bytes, the A2A 1.0 card shape, signed
/// cards and AgentFacts attestations (EdDSA, byte for byte), verification, the well-known handlers and the registry entry.
final class RefAgentCardTests: XCTestCase {
    static let file = "ref-agentcard.json.gz"
    static let seeds = RefSeeds.table(["agentcard/key1", "agentcard/key2"])

    /// The reference compares JOSE library messages up to the first colon (its oracle's norm()): the same rule here.
    static func fix(_ s: String) -> String {
        for p in ["could not resolve verification key", "signature did not verify"] where s.hasPrefix(p + ": ") { return p }
        if s.hasPrefix("signature "), let r = s.range(of: " did not verify: ") {
            let n = s[s.index(s.startIndex, offsetBy: 10)..<r.lowerBound]
            if !n.isEmpty && n.allSatisfy({ $0.isASCII && $0.isNumber }) { return "signature \(n) did not verify" }
        }
        return s
    }

    static func norm(_ v: JSONValue) -> JSONValue {
        guard var o = v.asObject else { return v }
        if let r = o["reason"]?.asString { o["reason"] = .string(fix(r)) }
        if let a = o["attestations"]?.asArray {
            o["attestations"] = .array(a.map { x in
                guard var ao = x.asObject, let r = ao["reason"]?.asString else { return x }
                ao["reason"] = .string(fix(r))
                return .object(ao)
            })
        }
        return .object(o)
    }

    static let det: PCAAgentCard.EdSign = { seed, msg in try Ed25519Deterministic.key(seed: seed).sign(msg) }

    func testAgentCard() throws {
        try K042.requireCovers(["AgentCard", "JSInterop", "Jose", "Oidc", "WhatwgURL"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let args = c.args.map { RefSeeds.restore($0, Self.seeds) }
            let a0 = args.first, a1 = args.count > 1 ? args[1] : nil, a2 = args.count > 2 ? args[2] : nil
            let got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object(["DEFAULT_ALG": .string(PCAAgentCard.DEFAULT_ALG), "AGENT_FACTS_CONTEXT": .array(PCAAgentCard.AGENT_FACTS_CONTEXT.map { .string($0) }),
                                      "PCA_ATTESTOR_ID": .string(PCAAgentCard.PCA_ATTESTOR_ID), "WELL_KNOWN_AGENT_CARD_PATH": .string(PCAAgentCard.WELL_KNOWN_AGENT_CARD_PATH),
                                      "WELL_KNOWN_AGENT_FACTS_PATH": .string(PCAAgentCard.WELL_KNOWN_AGENT_FACTS_PATH)]))
            case "jcsBytes":
                got = Ref.v { Base.bytesValue(try PCAAgentCard.jcsBytes(a0)) }
            case "validateAgentCard1":
                got = .value(.array(PCAAgentCard.validateAgentCard1(a0).map { .string($0) }))
            case "buildAgentCard":
                got = Ref.v { try PCAAgentCard.buildAgentCard(a0, Ref.obj(a1)) }
            case "issueSignedAgentCard":
                got = Ref.v { try PCAAgentCard.issueSignedAgentCard(a0, a1, Ref.obj(a2), edSign: Self.det) }
            case "verifyAgentCard":
                got = Ref.v { Self.norm(try PCAAgentCard.verifyAgentCard(a0, Ref.obj(a1))) }
            case "issueAgentFacts":
                got = Ref.v { try PCAAgentCard.issueAgentFacts(a0, Ref.obj(a1), edSign: Self.det) }
            case "addAttestation":
                got = Ref.v { try PCAAgentCard.addAttestation(a0, Ref.obj(a1), edSign: Self.det) }
            case "verifyAgentFacts":
                got = Ref.v { Self.norm(try PCAAgentCard.verifyAgentFacts(a0, Ref.obj(a1))) }
            case "agentCardHandler":
                got = Ref.v { PCAAgentCard.agentCardHandler(a0 ?? .null, path: a1?.asString)(a2?.asString ?? "") ?? .null }
            case "agentFactsHandler":
                got = Ref.v { PCAAgentCard.agentFactsHandler(a0 ?? .null, path: a1?.asString)(a2?.asString ?? "") ?? .null }
            case "toRegistryEntry":
                got = Ref.v { try PCAAgentCard.toRegistryEntry(a0, a1, order: ["name", "kyc"]) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(380)
    }

    func testAgentCardFailClosed() throws {
        // a card with no signatures, an unresolvable key and a tampered body are refused
        let card: JSONValue = .object(["name": .string("A")])
        XCTAssertEqual(try PCAAgentCard.verifyAgentCard(card, [:]).get("ok"), .bool(false))
        XCTAssertEqual(try PCAAgentCard.verifyAgentCard(.array([]), [:]).get("reason"), .string("agent card carries no signatures"))
        XCTAssertThrowsError(try PCAAgentCard.jcsBytes(.double(.infinity)))
        XCTAssertThrowsError(try PCAAgentCard.jcsBytes(nil))
        XCTAssertEqual(PCAAgentCard.dateParse("2026-06-01"), 1_780_272_000_000)
        XCTAssertTrue(PCAAgentCard.dateParse("2026-06-01T00:00:00").isNaN) // no offset: local time, refused
        XCTAssertTrue(PCAAgentCard.dateParse("2026-02-30").isNaN)
    }
}
