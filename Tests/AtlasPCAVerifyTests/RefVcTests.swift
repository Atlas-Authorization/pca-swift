import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAVc against the reference (@atlasauth/pca-vc): base58btc / did:key, the agent-passport SD-JWT VC and
/// RFC 9421 request signatures. The reference's clock is pinned (1700000100) and its salts are random, so passportToVC compares the
/// generator's normalized form. JS-typed option values are mapped to what the typed API expresses.
final class RefVcTests: XCTestCase {
    static let file = "ref-vc.json.gz"
    static let NOW: Double = 1_700_000_100
    struct Skip: Error { let why: String }

    /// The generator's key import (a short seed is refused with the reference's code).
    static func seed(_ v: JSONValue?) throws -> [UInt8] {
        guard let b = Base.bytes(v), b.count == 32 else { throw JSError("not enough data", code: "ERR_OSSL_ASN1_NOT_ENOUGH_DATA") }
        return b
    }

    static func headers(_ v: JSONValue?) throws -> [(String, String)] {
        guard let o = v?.asObject else { throw JSError("Cannot convert undefined or null to object") }
        if Set(o.keys.map { $0.s.lowercased() }).count != o.count { throw Skip(why: "headers differing only in case: their order is lost in the vector") }
        return try o.map { k, v in
            guard let s = v.asString else { throw JSError("v.trim is not a function") }
            return (k.s, s)
        }
    }

    static func normalize(_ sd: String) throws -> JSONValue {
        let parts = sd.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        let ds = Array(parts[1..<(parts.count - 1)])
        func dec(_ s: String) throws -> JSONValue {
            guard let b = Base64URLStrict.decode(s) else { throw JSError("bad segment") }
            return try StrictJSON.parseLenient(String(decoding: b, as: UTF8.self))
        }
        let seg = parts[0].split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var p = try dec(seg[1]).asObject ?? [:]
        var sdl: [String] = []
        if var vc = p["vc"]?.asObject, var cs = vc["credentialSubject"]?.asObject {
            sdl = (cs["_sd"]?.asArray ?? []).compactMap { $0.asString }.sorted()
            cs["_sd"] = nil
            vc["credentialSubject"] = .object(cs)
            p["vc"] = .object(vc)
        }
        var disc: [[JSONValue]] = []
        for d in ds { let a = try dec(d).asArray ?? []; disc.append([a[1], a[2]]) }
        disc.sort { ($0[0].asString ?? "") < ($1[0].asString ?? "") }
        let pub = try Ed25519Deterministic.key(seed: [UInt8](repeating: 1, count: 32)).pub
        let verified = (try? PCAVc.verifyPassportVC(sd, issuerPublicKey: pub, nowSec: NOW)) != nil
        return .object(["end": .string(parts[parts.count - 1]), "header": try dec(seg[0]), "payload": .object(p), "n": .int(Int64(ds.count)),
                        "digestsOk": .bool(ds.map { PCASdJwt.sha($0) }.sorted() == sdl), "disclosures": .array(disc.map { .array($0) }), "verified": .bool(verified)])
    }

    static func passportW(_ passport: JSONValue?, _ m: JObject) throws -> JSONValue {
        let s = try seed(m["issuer_seed"])
        var ttl: Double? = nil
        switch m["ttl_sec"] {
        case nil: break
        case let .string(t)?: throw JSError("Invalid time period format: \(t)") // `now + ttlSec` concatenates
        case let v?: ttl = JS.toNumber(v)
        }
        return try normalize(try PCAVc.passportToVC(passport, issuerSeed: s, issuerDid: m["issuer_did"]?.asString, subjectDid: m["subject_did"]?.asString,
                                                   ttlSec: ttl, nowSec: NOW))
    }

    static func signW(_ a: JObject) throws -> JSONValue {
        let url = a["url"]?.asString ?? ""
        var r = PCAVc.SignRequest(method: a["method"]?.asString ?? "", url: url, headers: try headers(a["headers"]), seed: try seed(a["key"]),
                                  keyid: a["keyid"]?.asString ?? "")
        if let c = a["created"] { r.created = c == .null ? NOW : JS.toNumber(c) } // null falls back to the (pinned) clock
        if let s = a["signature_agent"] { r.signatureAgent = JS.toString(s) }
        return try PCAVc.signRequestMessage(r)
    }

    static func verifyW(_ a: JObject, _ key: JSONValue?) throws -> Bool {
        guard let input = a["signature_input"]?.asString, let sig = a["signature"]?.asString else { return false }
        var r = PCAVc.VerifyRequest(method: a["method"]?.asString ?? "", url: a["url"]?.asString ?? "", headers: try headers(a["headers"]),
                                    signatureInput: input, signature: sig)
        r.signatureAgent = a["signature_agent"]?.asString
        if let l = a["required_components"]?.asArray { r.requiredComponents = l.map { $0.asString ?? "\u{0}" } } // a non-string is never covered
        if let x = a["max_age_sec"] { r.maxAgeSec = JS.toNumber(x) } // null compares as 0
        if let x = a["now_sec"] { r.nowSec = JS.toNumber(x) }
        return PCAVc.verifyRequestSignature(r, publicKey: Base.bytes(key) ?? [])
    }

    func testVc() throws {
        AdaOptIn.register()
        try K042.requireCovers(["Vc", "SdJwt", "Jose", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            var got: BaseGot
            do {
                switch c.fn {
                case "constants":
                    got = .value(.object([
                        "VC_CONTEXT": .string(PCAVc.VC_CONTEXT), "AGENT_PASSPORT_CONTEXT": .string(PCAVc.AGENT_PASSPORT_CONTEXT),
                        "AGENT_PASSPORT_VC_TYPE": .string(PCAVc.AGENT_PASSPORT_VC_TYPE), "AGENT_PASSPORT_CONTEXT_DIGEST": .string(PCAVc.AGENT_PASSPORT_CONTEXT_DIGEST),
                        "AGENT_PASSPORT_CONTEXT_DOC": PCAVc.AGENT_PASSPORT_CONTEXT_DOC,
                    ]))
                case "resolveAgentPassportContext":
                    got = .value(PCAVc.resolveAgentPassportContext(a0?.asString) ?? .null)
                case "base58btcEncode":
                    got = .value(.string(PCAVc.base58btcEncode(Base.bytes(a0) ?? [])))
                case "base58btcDecode":
                    got = Ref.v {
                        guard let s = a0?.asString else { throw JSError("not a string") }
                        return Base.bytesValue(try PCAVc.base58btcDecode(s))
                    }
                case "didKeyFromEd25519":
                    got = Ref.s { try PCAVc.didKeyFromEd25519(Base.bytes(a0) ?? []) }
                case "ed25519FromDidKey":
                    got = Ref.v {
                        guard let s = a0?.asString else { throw JSError("did.startsWith is not a function") }
                        return Base.bytesValue(try PCAVc.ed25519FromDidKey(s))
                    }
                case "passportToVC":
                    got = Ref.v { try Self.passportW(a0, Ref.obj(a1)) }
                case "verifyPassportVC":
                    got = Ref.v {
                        guard let s = a0?.asString else { throw JSError("vc.split is not a function") }
                        var expected: String? = nil
                        if let e = c.arg(2)?.get("expectedIssuerDid") { expected = e.asString ?? "\u{0}null" } // a null expectation matches no issuer
                        return try PCAVc.verifyPassportVC(s, issuerPublicKey: Base.bytes(a1) ?? [], expectedIssuerDid: expected, nowSec: Self.NOW)
                    }
                case "signRequestMessage":
                    let a = Ref.obj(a0)
                    if a["headers"]?.asObject != nil { _ = try Self.headers(a["headers"]) } // a case-collision skip, before the call
                    if !AdaOptIn.linked, (a["url"]?.asString ?? "").unicodeScalars.contains(where: { !$0.isASCII }) { throw Skip(why: "an IDN host: no IDNA mapping natively (refused)") }
                    got = Ref.v { try Self.signW(a) }
                case "verifyRequestSignature":
                    got = Ref.v { .bool(try Self.verifyW(Ref.obj(a0), a1)) }
                default:
                    d.skip("\(c.fn): not mapped"); return
                }
            } catch let s as Skip {
                d.skip(s.why); return
            } catch {
                got = .threw(Ref.code(error))
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(300)
    }

    func testVcFailClosed() throws {
        // a signature whose alg parameter is not ed25519, or that carries a line break, never verifies
        let seed = [UInt8](repeating: 1, count: 32)
        let pub = try Ed25519Deterministic.key(seed: seed).pub
        var s = PCAVc.SignRequest(method: "GET", url: "https://a.example/p", headers: [], seed: seed, keyid: "k")
        s.created = 1_700_000_000
        let out = try PCAVc.signRequestMessage(s)
        let input = out.get("signatureInput")!.asString!, sig = out.get("signature")!.asString!
        XCTAssertTrue(PCAVc.verifyRequestSignature(PCAVc.VerifyRequest(method: "GET", url: "https://a.example/p", headers: [], signatureInput: input, signature: sig), publicKey: pub))
        let bad = input.replacingOccurrences(of: "alg=\"ed25519\"", with: "alg=\"hmac-sha256\"")
        XCTAssertFalse(PCAVc.verifyRequestSignature(PCAVc.VerifyRequest(method: "GET", url: "https://a.example/p", headers: [], signatureInput: bad, signature: sig), publicKey: pub))
        XCTAssertThrowsError(try PCAVc.ed25519FromDidKey("did:key:z" + String(repeating: "2", count: 65)))
    }
}
