import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// Differential replay of PCANotary against the reference (@atlasauth/pca-notary): the notary message, notarizeResponse (hiding salts
/// replayed from the corpus counter: salt_i = sha256("notary-oracle-salt/" + i)[:16]), discloseField, the attestation and disclosure
/// verifiers, the PCActn two-way binding, the attested_fact caveat and the key ring. The corpus carries a test notary key as a seed label
/// ("fill:<n>" = 32 bytes of n); the key is derived here.
final class RefNotaryTests: XCTestCase {
    static let file = "ref-notary.json.gz"
    static let errorPrefix = "attested_fact evaluation error (fail closed)"

    static func key(_ v: JSONValue?) -> PCANotary.NotaryKey? {
        switch v {
        case let .string(s)?: return .b64u(s)
        case let o? where o.isObject:
            if let b = Base.bytes(o) { return .bytes(b) }
            if let b = Base.bytes(o.get("publicKey")) { return .bytes(b) }
            return nil
        default: return nil
        }
    }

    static func notaryKey(_ v: JSONValue?) throws -> PCAEdKey {
        // the oracle wraps the key as {notaryKey: {secretKey: {"$seed": label}}} (older corpora put secretKey at the top)
        let sk = (v?.get("notaryKey") ?? v)?.get("secretKey")
        guard let label = (sk?.get("$seed") ?? sk?.get("$bytes")?.get("$seed"))?.asString, label.hasPrefix("fill:"), let n = UInt8(label.dropFirst(5)) else { throw JSError("no key in the case") }
        return try Ed25519Deterministic.key(seed: [UInt8](repeating: n, count: 32))
    }

    /// Two header names that differ only in case with different values: the reference keeps the last inserted, which a parsed object cannot say.
    static func ambiguousHeaders(_ input: JSONValue?) -> Bool {
        guard let h = input?.get("request")?.get("headers")?.asObject else { return false }
        var seen: [String: JSONValue] = [:]
        for (k, v) in h {
            let l = k.s.lowercased()
            if let o = seen[l], o != v { return true }
            seen[l] = v
        }
        return false
    }

    func testNotary() throws {
        try K042.requireCovers(["Notary", "Merkle", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            if Base.negZero(.array(c.args)) { d.skip("negative zero argument"); return }
            let got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object(["BODY_COMMIT_ALG": .string(PCANotary.BODY_COMMIT_ALG), "ATTESTED_FACT_CAVEAT": .string(PCANotary.ATTESTED_FACT_CAVEAT)]))
            case "notaryMessage": got = Ref.v { Base.bytesValue(try PCANotary.notaryMessage(a0 ?? .null)) }
            case "notarizeResponse":
                if Self.ambiguousHeaders(a0) { d.skip("notarizeResponse: header names differing only in case (insertion order lost)"); return }
                var i = 0
                got = Ref.v {
                    let key = try Self.notaryKey(a1)
                    return try PCANotary.notarizeResponse(a0, notaryKey: key, observedAt: a1?.get("observedAt"), textChunkSize: a1?.get("textChunkSize"), nowMs: Int64(Base.clockMs(Self.file)), salt: { // the generator ran under the header's frozen clock
                        defer { i += 1 }
                        return Array(SHA256.hash(data: Data("notary-oracle-salt/\(i)".utf8)).prefix(16))
                    })
                }
            case "discloseField": got = Ref.v { try PCANotary.discloseField(a0, a1, a2) }
            case "verifyNotaryAttestation": got = .value(.bool(PCANotary.verifyNotaryAttestation(a0, notaryKey: Self.key(a1))))
            case "verifyDisclosedField": got = .value(.bool(PCANotary.verifyDisclosedField(a0, a1, notaryKey: Self.key(a2))))
            case "factRef": got = Ref.s { try PCANotary.factRef(a0) }
            case "bindFactToPcActn": got = Ref.v { try PCANotary.bindFactToPcActn(a0, a1) }
            case "factMatchesPcActn": got = .value(.bool(PCANotary.factMatchesPcActn(a0, a1)))
            case "requireAttestedFact":
                got = Ref.v { try PCANotary.requireAttestedFact(notary: Self.key(a0?.get("notary")), path: a0?.get("path"), equals: a0?.get("equals"), url: a0?.get("url"), bindToPcActn: a0?.get("bindToPcActn")) }
            case "isAttestedFactCaveat": got = .value(.bool(PCANotary.isAttestedFactCaveat(a0)))
            case "notaryKeyUsable": got = .value(.bool(PCANotary.notaryKeyUsable(a0, a1, a2)))
            case "evaluateAttestedFactCaveat":
                let r = PCANotary.evaluateAttestedFactCaveat(a0, a1, a2)
                // the reference's error text is a JavaScript TypeError message: only the fail-closed prefix is comparable
                if let want = c.out.get("reason")?.asString, want.hasPrefix(Self.errorPrefix) {
                    let ok = r.get("ok") == .bool(false) && r.get("reason")?.asString?.hasPrefix(Self.errorPrefix) == true
                    d.add(c, ok ? nil : "\(c.name): want an error refusal got \(Base.canon(r).prefix(200))")
                    return
                }
                got = .value(r)
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1600)
    }

    func testRoundTripAndTamper() throws {
        let key = try Ed25519Deterministic.key(seed: [UInt8](repeating: 7, count: 32))
        let body: JSONValue = .object(["order": .object(["status": .string("shipped")]), "id": .string("o-1")])
        let input: JSONValue = .object(["request": .object(["method": .string("get"), "url": .string("https://api.example.com/o/1")]),
                                        "response": .object(["status": .int(200), "body": body])])
        let r = try PCANotary.notarizeResponse(input, notaryKey: key, observedAt: .int(1_700_000_000_000))
        let att = r.get("attestation"), wit = r.get("witness")
        let k = PCANotary.NotaryKey(key)
        XCTAssertTrue(PCANotary.verifyNotaryAttestation(att, notaryKey: k))
        let disc = try PCANotary.discloseField(att, wit, .array([.string("order"), .string("status")]))
        XCTAssertTrue(PCANotary.verifyDisclosedField(att, disc, notaryKey: k))
        var lie = disc.asObject!
        lie["value"] = .string("cancelled")
        XCTAssertFalse(PCANotary.verifyDisclosedField(att, .object(lie), notaryKey: k))
        let cv = try PCANotary.requireAttestedFact(notary: k, path: .array([.string("order"), .string("status")]), equals: .string("shipped"))
        let ev: JSONValue = .object(["attestation": att ?? .null, "disclosure": disc])
        XCTAssertEqual(PCANotary.evaluateAttestedFactCaveat(cv, ev, .object(["maxAgeMs": .int(1000), "now": .int(1_700_000_001_001)])).get("ok"), .bool(false))
        XCTAssertEqual(PCANotary.evaluateAttestedFactCaveat(cv, ev).get("ok"), .bool(true))
        // the wrong notary is never trusted
        let other = PCANotary.NotaryKey.b64u(Base64URLStrict.encode([UInt8](repeating: 1, count: 32)))
        XCTAssertFalse(PCANotary.verifyNotaryAttestation(att, notaryKey: other))
    }
}
