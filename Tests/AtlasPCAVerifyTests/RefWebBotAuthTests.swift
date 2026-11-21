import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// A replay cache scripted by the corpus: "always" / "never" claim, "throw" fails closed.
private final class ScriptedCache: WebBotAuthReplayCache {
    let mode: String
    init(_ mode: String) { self.mode = mode }
    func claim(_ key: String, _ expiresAtSec: Double, _ nowSec: Double) throws -> Bool {
        if mode == "throw" { throw JSError("cache down") }
        return mode == "always"
    }
}

/// Differential replay of PCAWebBotAuth against the reference (@atlasauth/pca-webbotauth): RFC 9421 message signatures in the web-bot-auth
/// profile (the RFC and draft vectors included), the signed key directory, Content-Digest, the PCA proof binding, the replay cache and the
/// scripted directory fetch. Ed25519 is deterministic, so signed output compares byte for byte. The corpus carries its test keys as a seed
/// reference ("$seed:<label>" = sha256 of "atlas-pca-conformance/<label>", "$rfc9421-b14" = the published RFC 9421 appendix test key); the
/// private member is rebuilt here.
final class RefWebBotAuthTests: XCTestCase {
    static let file = "ref-webbotauth.json.gz"

    static func seedOf(_ marker: String) -> String? {
        if marker == "$rfc9421-b14" { return "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" }
        guard marker.hasPrefix("$seed:") else { return nil }
        return Base64URLStrict.encode(Canonical.sha256(Array("atlas-pca-conformance/\(marker.dropFirst(6))".utf8)))
    }

    /// Every `secretKey` marker replaced by its base64url seed.
    static func restore(_ v: JSONValue?) -> JSONValue? {
        switch v {
        case let .array(a)?: return .array(a.map { restore($0)! })
        case let .object(o)?:
            var m = o.mapValues { restore($0)! }
            if let s = m["secretKey"]?.asString, let seed = seedOf(s) { m["secretKey"] = .string(seed) }
            // the corpus also writes a seeded key as {"$seed": label}
            else if let l = m["secretKey"]?.get("$seed")?.asString, let seed = seedOf("$seed:" + l) { m["secretKey"] = .string(seed) }
            return .object(m)
        default: return v
        }
    }

    /// The reference compares a reason's JS-engine text only where this port can reproduce it: a TypeError / platform message is cut, and the
    /// detail of a PCActn parse failure (it quotes the reference's own parser) is cut after the colon.
    static let keptMessages = ["expected a quoted string", "invalid escape in string", "unterminated string", "trailing characters after string parameter",
                               "expected parameters to start", "malformed Signature member", "malformed Signature-Input member", "Signature-Input value must be",
                               "Signature value must be", "unterminated inner list", "unsupported component parameters", "unsupported derived component",
                               "covered header \"", "member \"", "Invalid URL", "\""]
    static func normReason(_ r: String) -> String {
        if r.hasPrefix("invalid PCActn in PCA-Action: ") { return "invalid PCActn in PCA-Action" }
        let p = "verification failed (fail closed): "
        if r.hasPrefix(p), !keptMessages.contains(where: { r.dropFirst(p.count).hasPrefix($0) }) { return "verification failed (fail closed)" }
        return r
    }
    static func norm(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(norm))
        case let .object(o):
            var m = o.mapValues(norm)
            if let r = m["reason"]?.asString { m["reason"] = .string(normReason(r)) }
            return .object(m)
        default: return v
        }
    }

    static func resolver(_ spec: JObject) -> (String) throws -> WebBotAuthKey? {
        return { kid in
            guard let v = spec[JKey(kid)] else { return nil }
            if v.get("$throw") == .bool(true) { throw JSError("resolver down") }
            if let b = Base.bytes(v) { return .raw(b) }
            return v == .null ? nil : .jwk(v)
        }
    }

    static func cache(_ spec: JSONValue?) -> WebBotAuthReplayCache? {
        guard let s = spec?.asString else { return nil }
        if s == "memory" { return WebBotAuthMemoryReplayCache() }
        if s.hasPrefix("memory:"), let n = Double(s.dropFirst(7)) { return WebBotAuthMemoryReplayCache(maxEntries: n) }
        return ScriptedCache(s)
    }

    /// The oracle's options bag: resolveKey (a keyid table), maxLifetimeSec "Infinity" and a replayCache spec become real values.
    static func options(_ v: JSONValue?) -> (opts: JSONValue?, resolve: ((String) throws -> WebBotAuthKey?)?, cache: WebBotAuthReplayCache?) {
        guard var o = v?.asObject else { return (v, nil, nil) }
        var resolve: ((String) throws -> WebBotAuthKey?)?
        if let r = o["resolveKey"]?.asObject { resolve = resolver(r); o["resolveKey"] = nil }
        if o["maxLifetimeSec"]?.asString == "Infinity" { o["maxLifetimeSec"] = .double(.infinity) }
        let cache = cache(o["replayCache"])
        o["replayCache"] = nil
        return (.object(o), resolve, cache)
    }

    static func dirKeys(_ v: JSONValue?) -> [WebBotAuthDirectoryKey]? {
        guard let a = v?.asArray else { return nil }
        var out: [WebBotAuthDirectoryKey] = []
        for k in a {
            guard let pk = Base.bytes(k.get("publicKey")) else { return nil }
            out.append(WebBotAuthDirectoryKey(publicKey: pk, keyid: k.get("keyid")?.asString, use: k.get("use"), nbf: k.get("nbf"), exp: k.get("exp")))
        }
        return out
    }

    static func body(_ v: JSONValue?) -> [UInt8]? {
        if let s = v?.asString { return Array(s.utf8) }
        return Base.bytes(v)
    }

    static func fetchCase(_ a: [JSONValue]) -> JSONValue? {
        guard let url = a.first?.asString, a.count > 1 else { return nil }
        let spec = a[1]
        var called: JSONValue = .null
        let fetcher: (String, [String: String], Double) throws -> PCAWebBotAuth.FetchResponse = { u, h, _ in
            called = .object(["url": .string(u), "headers": .object(Dictionary(uniqueKeysWithValues: h.map { (JKey($0.key), JSONValue.string($0.value)) })), "redirect": .string("error")])
            guard let r = spec.get("response")?.asObject else { throw JSError("network down") }
            var hs: [String: String] = [:]
            for (k, v) in r[JKey("headers")]?.asObject ?? [:] { hs[k.s.lowercased()] = v.asString ?? "" }
            return PCAWebBotAuth.FetchResponse(status: Int(JS.toNumber(r[JKey("status")])), headers: hs, body: r[JKey("body")]?.asString ?? "")
        }
        var out: JObject = [:]
        do {
            out["directory"] = try PCAWebBotAuth.fetchKeyDirectory(url, spec.get("options"), fetch: fetcher)
        } catch {
            let msg = PCAWebBotAuth.text(error)
            out["error"] = .bool(true)
            out["message"] = .string((msg.hasPrefix("directory ") || msg == "Invalid URL") ? (msg.hasPrefix("directory signature: ") ? "directory signature" : msg) : "other")
        }
        out["called"] = called
        return .object(out)
    }

    func testWebBotAuth() throws {
        try K042.requireCovers(["WebBotAuth", "WhatwgURL", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            var got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object(["tag": .string(PCAWebBotAuth.WEB_BOT_AUTH_TAG), "alg": .string(PCAWebBotAuth.WEB_BOT_AUTH_ALG),
                                      "path": .string(PCAWebBotAuth.WELL_KNOWN_DIRECTORY_PATH), "ct": .string(PCAWebBotAuth.DIRECTORY_CONTENT_TYPE),
                                      "label": .string(PCAWebBotAuth.DEFAULT_SIGNATURE_LABEL), "exp": .double(PCAWebBotAuth.DEFAULT_EXPIRES_SEC),
                                      "agent": .string(PCAWebBotAuth.SIGNATURE_AGENT_HEADER), "pca": .string(PCAWebBotAuth.PCA_HEADER),
                                      "comp": .string(PCAWebBotAuth.PCA_PROOF_COMPONENT), "cd": .string(PCAWebBotAuth.CONTENT_DIGEST_HEADER),
                                      "algs": .array(PCAWebBotAuth.CONTENT_DIGEST_ALGS.map { .string($0) }), "dtag": .string(PCAWebBotAuth.DIRECTORY_SIGNATURE_TAG)]))
            case "jwkThumbprint":
                guard let pk = Base.bytes(a0) else { d.skip("jwkThumbprint: not bytes"); return }
                got = .value(.string(PCAWebBotAuth.jwkThumbprint(pk)))
            case "signRequest", "signRequestWithProof":
                got = Ref.v { c.fn == "signRequest" ? try PCAWebBotAuth.signRequest(Self.restore(a0)) : try PCAWebBotAuth.signRequestWithProof(Self.restore(a0)) }
            case "verifySignedRequest", "verifySignedRequestWithProof":
                let o = Self.options(a1)
                if c.fn == "verifySignedRequestWithProof" {
                    got = .value(PCAWebBotAuth.verifySignedRequestWithProof(a0, o.opts, resolveKey: o.resolve, replayCache: o.cache))
                } else {
                    let times = c.args.count > 2 ? Int(JS.toNumber(c.args[2])) : 1
                    let rs = (0..<times).map { _ in PCAWebBotAuth.verifySignedRequest(a0, o.opts, resolveKey: o.resolve, replayCache: o.cache) }
                    got = .value(c.args.count > 2 ? .array(rs) : rs[0])
                }
            case "buildKeyDirectory":
                guard let keys = Self.dirKeys(a0) else { d.skip("buildKeyDirectory: key without bytes"); return }
                got = .value(PCAWebBotAuth.buildKeyDirectory(keys))
            case "resolveFromDirectory": got = Ref.v { try PCAWebBotAuth.resolveFromDirectory(a0, a1) ?? .null }
            case "directoryHandler":
                guard let keys = Self.dirKeys(a0), let paths = a1?.asArray, paths.allSatisfy({ $0.asString != nil }) else { d.skip("directoryHandler: odd input"); return }
                let h = PCAWebBotAuth.directoryHandler(keys)
                got = .value(.array(paths.map { h($0.asString!) ?? .null }))
            case "memoryReplayCache":
                guard let ops = a1?.asArray else { d.skip("memoryReplayCache: no ops"); return }
                let cache = a0 == nil || a0 == .null ? WebBotAuthMemoryReplayCache() : WebBotAuthMemoryReplayCache(maxEntries: JS.toNumber(a0))
                got = .value(.array(ops.map { op in
                    let t = op.asArray ?? []
                    guard t.count == 3, let k = t[0].asString, let r = try? cache.claim(k, JS.toNumber(t[1]), JS.toNumber(t[2])) else { return .string("throw") }
                    return .bool(r)
                }))
            case "proofHeaders":
                got = .value(.object(Dictionary(uniqueKeysWithValues: PCAWebBotAuth.proofHeaders(a0 ?? .null).map { (JKey($0.key), JSONValue.string($0.value)) })))
            case "decodeProofHeader": got = Ref.v { try PCAWebBotAuth.decodeProofHeader(a0) }
            case "contentDigestBytes":
                guard let b = Self.body(a0) else { d.skip("contentDigestBytes: odd body"); return }
                got = Ref.v { Base.bytesValue(try PCAWebBotAuth.contentDigestBytes(b, a1?.asString ?? "")) }
            case "contentDigestHeader":
                guard let b = Self.body(a0) else { d.skip("contentDigestHeader: odd body"); return }
                if c.args.count > 1 {
                    guard let algs = a1?.asArray, algs.allSatisfy({ $0.asString != nil }) else { d.skip("contentDigestHeader: non-string algorithm list"); return }
                    got = Ref.v { .string(try PCAWebBotAuth.contentDigestHeader(b, algs.map { $0.asString! })) }
                } else {
                    got = Ref.v { .string(try PCAWebBotAuth.contentDigestHeader(b)) }
                }
            case "parseContentDigest":
                guard let s = a0?.asString else { d.skip("parseContentDigest: non-string"); return }
                got = Ref.v {
                    var o: JObject = [:]
                    for m in try PCAWebBotAuth.parseContentDigest(s) { o[JKey(m.key)] = Base.bytesValue(m.bytes) }
                    return .object(o)
                }
            case "verifyContentDigest":
                guard let b = Self.body(a1), a0 == nil || a0 == .null || a0?.asString != nil else { d.skip("verifyContentDigest: odd argument"); return }
                var req: [String]?
                if c.args.count > 2, let r = c.args[2].get("require")?.asArray {
                    guard r.allSatisfy({ $0.asString != nil }) else { d.skip("verifyContentDigest: non-string require"); return }
                    req = r.map { $0.asString! }
                }
                got = .value(PCAWebBotAuth.verifyContentDigest(a0?.asString, b, require: req))
            case "parseKeyDirectory":
                guard let s = a0?.asString else { d.skip("parseKeyDirectory: non-string"); return }
                got = Ref.v { try PCAWebBotAuth.parseKeyDirectory(s) }
            case "signDirectoryResponse": got = Ref.v { try PCAWebBotAuth.signDirectoryResponse(Self.restore(a0)) }
            case "verifyDirectoryResponse": got = .value(PCAWebBotAuth.verifyDirectoryResponse(a0))
            case "fetchKeyDirectory":
                guard let r = Self.fetchCase(c.args) else { d.skip("fetchKeyDirectory: odd input"); return }
                got = .value(r)
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            if case let .value(v) = got { got = .value(Self.norm(v)) }
            let want = BaseCase(fn: c.fn, name: c.name, args: c.args, out: Self.norm(c.out), suspect: c.suspect, raw: c.raw)
            d.add(c, Base.diff(want, got))
        }
        d.finish(1100)
    }

    func testDecodeProofHeaderRefusesNonStrict() {
        for bad in ["", "e30=", "e30 ", "e+0", "!!"] { XCTAssertThrowsError(try PCAWebBotAuth.decodeProofHeader(.string(bad)), bad) }
        XCTAssertNoThrow(try PCAWebBotAuth.decodeProofHeader(.string("e30")))
        // a JSON array is not a PCActn
        XCTAssertThrowsError(try PCAWebBotAuth.decodeProofHeader(.string("W10")))
    }

    func testSignedRequestRoundTripAndTamper() throws {
        let seed = Canonical.sha256(Array("atlas-pca-conformance/wba/roundtrip".utf8))
        let pub = Ed25519Deterministic.publicKey(seed: seed)
        let key: JSONValue = .object(["secretKey": .string(Base64URLStrict.encode(seed))])
        let req: JSONValue = .object(["method": .string("POST"), "url": .string("https://example.com/a?x=1"), "headers": .object(["content-type": .string("text/plain")]),
                                      "key": key, "keyid": .string("k"), "created": .int(1_800_000_000), "coverHeaders": .array([.string("content-type")])])
        guard case let .object(signed) = try PCAWebBotAuth.signRequest(req), let h = signed["headers"]?.asObject else { return XCTFail("no result") }
        var headers = h
        headers[JKey("content-type")] = .string("text/plain")
        func verify(_ method: String, _ hs: JObject) -> JSONValue {
            PCAWebBotAuth.verifySignedRequest(.object(["method": .string(method), "url": .string("https://example.com/a?x=1"), "headers": .object(hs)]),
                                              .object(["now": .int(1_800_000_010)]), resolveKey: { _ in .raw(pub) })
        }
        XCTAssertEqual(verify("POST", headers).get("valid"), .bool(true))
        XCTAssertEqual(verify("GET", headers).get("valid"), .bool(false))
        headers[JKey("content-type")] = .string("text/html")
        XCTAssertEqual(verify("POST", headers).get("valid"), .bool(false))
        // a signature that is not for this key never verifies
        let other = Ed25519Deterministic.publicKey(seed: Canonical.sha256(Array("atlas-pca-conformance/wba/other".utf8)))
        headers[JKey("content-type")] = .string("text/plain")
        let bad = PCAWebBotAuth.verifySignedRequest(.object(["method": .string("POST"), "url": .string("https://example.com/a?x=1"), "headers": .object(headers)]),
                                                    .object(["now": .int(1_800_000_010)]), resolveKey: { _ in .raw(other) })
        XCTAssertEqual(bad.get("valid"), .bool(false))
    }
}
