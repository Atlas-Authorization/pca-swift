import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The entropy module against the reference corpus: cutoffs, health tests, parsers, the combiner, secureSeed, the key pair helper and the HTTP
/// source. The local CSPRNG, every source and the HTTP transport are injected by the case.
final class RefEntropyTests: XCTestCase {
    typealias E = PCAEntropy
    /// A corpus argument a typed API cannot receive (the reference refuses it, or it is a JavaScript type confusion).
    struct BadArg: Error {}
    /// What an injected source, CSPRNG, hook or transport throws. `cls` is the reference's class name.
    struct Injected: Error, CustomStringConvertible {
        let cls: String
        let description: String
    }
    /// A thrown value that is not an error object in the reference (it has no message).
    struct Bare: Error { let text: String }

    final class Log { var requests: [JSONValue] = []; var locals: [Int] = []; var errors: [JSONValue] = [] }

    struct Source: PCAQrngSource {
        let name: String
        let spec: JSONValue
        let log: Log
        func fetch(_ n: Int) throws -> [UInt8] {
            log.requests.append(.int(Int64(n)))
            let message = spec.get("message")?.asString ?? ""
            switch spec.get("kind")?.asString {
            case "bytes": return Base.bytes(spec.get("value")) ?? []
            case "reject", "throwSync": throw Injected(cls: "Error", description: message)
            case "rejectString": throw Bare(text: message)
            // a typed source cannot answer with a non-byte value: the reference's wording for that answer
            case "nonbytes": throw Injected(cls: "Error", description: "QRNG: source returned non-bytes, expected \(n)")
            default: throw Injected(cls: "Error", description: "bad source spec")
            }
        }
    }

    private func num(_ v: JSONValue?) throws -> Double {
        if let s = v?.get("$num")?.asString { return s == "NaN" ? .nan : (s == "Infinity" ? .infinity : -.infinity) }
        guard let d = IV.num(v) else { throw BadArg() }
        return d
    }

    private func int(_ v: JSONValue?) throws -> Int {
        guard let n = E.integer(try num(v)) else { throw BadArg() }
        return n
    }

    private func bytes(_ v: JSONValue?) throws -> [UInt8] {
        guard let b = Base.bytes(v) else { throw BadArg() }
        return b
    }

    private func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw BadArg() }
        return s
    }

    private func health(_ v: JSONValue?) throws -> E.HealthTestOptions {
        var o = E.HealthTestOptions()
        guard let v = v, !v.isNull else { return o }
        guard v.isObject else { throw BadArg() }
        if let h = v.get("h") { o.h = try num(h) }
        if let w = v.get("window") { o.window = try num(w) }
        return o
    }

    private func errRec(_ e: Error) -> JSONValue {
        if let x = e as? E.EntropyError { return .object(["cls": .string("EntropyError"), "message": .string(x.message), "code": .string(x.code)]) }
        if let x = e as? E.Refusal { return .object(["cls": .string(x.kind), "message": .string(x.message)]) }
        if let x = e as? Injected { return .object(["cls": .string(x.cls), "message": .string(x.description)]) }
        if let x = e as? Bare { return .object(["cls": .string("string"), "message": .string(x.text)]) }
        return .object(["cls": .string("Error"), "message": .string("\(e)")])
    }

    private func seedOptions(_ o: JSONValue?, _ log: Log) throws -> E.SecureSeedOptions {
        guard let o = o, o.isObject else { throw BadArg() }
        var s = E.SecureSeedOptions()
        // null is "not given" for a member the reference reads with `??`
        func given(_ k: String) -> JSONValue? { o.get(k).flatMap { $0.isNull ? nil : $0 } }
        if let v = given("length") { s.length = try int(v) }
        if let v = given("localBytes") { s.localBytes = try int(v) }
        if let v = given("quantumBytes") { s.quantumBytes = try int(v) }
        if let v = o.get("context") { s.context = try str(v) }
        if let v = o.get("requireQuantum") { s.requireQuantum = v == .bool(true) }
        if let v = o.get("healthTest") { s.healthTest = v == .bool(false) ? nil : try health(v) }
        if let src = o.get("source"), !src.isNull { s.source = Source(name: src.get("name")?.asString ?? "test-src", spec: src, log: log) }
        if let l = o.get("local") {
            s.randomBytesImpl = { n in
                log.locals.append(n)
                switch l.get("kind")?.asString {
                case "fixed": return Base.bytes(l.get("value")) ?? []
                case "throw": throw Injected(cls: "Error", description: l.get("message")?.asString ?? "")
                default: return [] // a non-byte answer: never the requested length
                }
            }
        }
        let hook = o.get("hook")?.asString ?? "none"
        if hook != "none" {
            s.onQrngError = { e in
                log.errors.append(self.errRec(e))
                if hook == "throw" { throw Injected(cls: "Error", description: "hook boom") }
            }
        }
        return s
    }

    private func seedTail(_ log: Log) -> [(String, JSONValue)] {
        [("qrngErrors", .array(log.errors)), ("localRequested", log.locals.first.map { .int(Int64($0)) } ?? .null), ("requests", .array(log.requests))]
    }

    private func obj(_ members: [(String, JSONValue)]) -> JSONValue {
        var o: JObject = [:]
        for (k, v) in members { o[JKey(k)] = v }
        return .object(o)
    }

    private func transport(_ spec: JSONValue?, _ log: Log) -> E.QrngTransport? {
        guard let spec = spec, let kind = spec.get("kind")?.asString, kind != "none" else { return nil }
        return { url, headers, _ in
            var h: JObject = [:]
            for (k, v) in headers { h[JKey(k)] = .string(v) }
            log.requests.append(.object(["url": .string(url), "headers": .object(h), "redirect": .string("error"), "signal": .bool(true)]))
            let message = spec.get("message")?.asString ?? ""
            switch kind {
            case "throw": throw Injected(cls: "Error", description: message)
            case "throwString": throw Bare(text: message)
            case "hang": throw E.TransportTimeout()
            default: break
            }
            let status = Int(IV.int(spec.get("status")) ?? 200)
            let ok = spec.get("ok").map { $0 == .bool(true) } ?? (200...299).contains(status)
            return E.QrngHttpResponse(ok: ok, status: status,
                json: { if kind == "json" { return spec.get("body") ?? .null }; throw Injected(cls: "Error", description: "json failed") },
                text: { if kind == "text" { return spec.get("text")?.asString ?? "" }; throw Injected(cls: "Error", description: "text failed") })
        }
    }

    private func httpConfig(_ c: JSONValue?, _ log: Log, _ t: JSONValue?) throws -> E.HttpQrngConfig {
        guard let c = c, c.isObject else { throw BadArg() }
        var cfg = E.HttpQrngConfig(url: try str(c.get("url")))
        if let v = c.get("apiKey") { cfg.apiKey = try str(v) }
        if let v = c.get("apiKeyHeader") { cfg.apiKeyHeader = try str(v) }
        if let v = c.get("format") { cfg.format = try str(v) }
        if let v = c.get("timeoutMs") { cfg.timeoutMs = try int(v) }
        if let v = c.get("maxBytes") { cfg.maxBytes = try int(v) }
        if let v = c.get("lengthParam") { cfg.lengthParam = try str(v) }
        if case let .object(x)? = c.get("extraParams") { cfg.extraParams = try JS.keyOrder(x).map { ($0.s, try str(x[$0])) } }
        if let v = c.get("allowInsecureLoopback") { cfg.allowInsecureLoopback = v == .bool(true) }
        if let suffix = c.get("buildUrl")?.get("suffix")?.asString { cfg.buildUrl = { base, n in base + "/" + String(n) + suffix } }
        cfg.transport = transport(t, log)
        return cfg
    }

    private func call(_ c: BaseCase) throws -> JSONValue? {
        let a = c.arg(0), b = c.arg(1)
        func numOut(_ d: Double) -> JSONValue { d.isFinite ? PCAFacade.jsNum(d) : .object(["$num": .string(d.isNaN ? "NaN" : (d > 0 ? "Infinity" : "-Infinity"))]) }
        switch c.fn {
        case "constants":
            return .object(["MAX_HKDF_OUTPUT": .int(Int64(E.MAX_HKDF_OUTPUT)), "MIN_LOCAL_BYTES": .int(Int64(E.MIN_LOCAL_BYTES)), "DEFAULT_SEED_BYTES": .int(Int64(E.DEFAULT_SEED_BYTES)),
                            "DEFAULT_MAX_QRNG_BYTES": .int(Int64(E.DEFAULT_MAX_QRNG_BYTES)), "DEFAULT_TIMEOUT_MS": .int(Int64(E.DEFAULT_TIMEOUT_MS))])
        case "repetitionCutoff": return numOut(E.repetitionCutoff(try num(a)))
        case "proportionCutoff": return numOut(E.proportionCutoff(try num(a), try num(b)))
        case "healthTestBytes":
            let v = E.healthTestBytes(try bytes(a), try health(b))
            return obj([("ok", .bool(v.ok))] + (v.test.map { [("test", .string($0))] } ?? []))
        case "parseAnuUint8": return Base.bytesValue(try E.parseAnuUint8(a ?? .null))
        case "parseHex": return Base.bytesValue(try E.parseHex(try str(a)))
        case "parseBase64": return Base.bytesValue(try E.parseBase64(try str(a)))
        case "mixEntropy":
            let o = c.arg(2)
            // a context that is neither absent nor a string: null is refused by the reference, any other value has no length and counts as none
            if o?.get("context")?.isNull == true { throw BadArg() }
            return Base.bytesValue(try E.mixEntropy(try bytes(a), try bytes(b), length: try o?.get("length").flatMap { $0.isNull ? nil : $0 }.map { try int($0) }, context: o?.get("context")?.asString))
        case "secureSeed":
            let log = Log()
            let r = try E.secureSeed(try seedOptions(a, log))
            return obj([("seed", Base.bytesValue(r.seed)), ("usedQuantum", .bool(r.usedQuantum)), ("quantumByteCount", .int(Int64(r.quantumByteCount))),
                        ("source", r.source.map { .string($0) } ?? .null)] + seedTail(log))
        case "generateKeyPairWithEntropy":
            let log = Log()
            let r = try E.generateKeyPairWithEntropy(try seedOptions(a, log))
            return obj([("publicKey", Base.bytesValue(r.publicKey)), ("secretKeySha256", .string(Canonical.sha256(r.secretKey).map { String(format: "%02x", $0) }.joined())),
                        ("usedQuantum", .bool(r.usedQuantum))] + seedTail(log))
        case "httpQrng":
            let log = Log()
            let cfg = try httpConfig(a, log, c.arg(2))
            let src = try E.HttpQrngSource(cfg)
            do {
                let got = try src.fetch(try int(b))
                return obj([("name", .string(src.name)), ("bytes", Base.bytesValue(got)), ("requests", .array(log.requests))])
            } catch {
                // the key never appears in a refusal, and the refusal names the same source and made the same requests as the reference
                if let key = cfg.apiKey, !key.isEmpty { XCTAssertFalse("\(error)".contains(key), "\(c.name): the API key leaks into the error") }
                if let want = c.out.get("name")?.asString { XCTAssertEqual(src.name, want, c.name) }
                if !(error is BadArg), let want = c.out.get("requests") { XCTAssertEqual(K042.canon(.array(log.requests)), K042.canon(want), c.name) }
                throw error
            }
        case "nullQrng", "unavailableSource":
            let src: PCAQrngSource
            if c.fn == "nullQrng" { src = a?.asString.map { E.NullQrngSource(reason: $0) } ?? E.NullQrngSource() } else { src = E.unavailableSource(a?.asString) }
            XCTAssertEqual(src.name, c.out.get("name")?.asString, c.name)
            do { _ = try src.fetch(try int(b)) } catch { XCTAssertEqual("\(error)", c.out.get("$throws")?.asString, c.name); throw error }
            return .null
        case "entropyError":
            let e = E.EntropyError(try str(a), try str(b))
            return obj([("name", .string(e.name)), ("code", .string(e.code)), ("message", .string(e.message)), ("isError", .bool((e as Any) is Error))])
        default: return nil
        }
    }

    func testEveryCaseMatchesTheReference() throws {
        let d = Base.Diffs()
        var unhandled = Set<String>()
        let n = try Base.each("ref-entropy.json.gz") { c in
            var known = true
            // the reference's URL parser reports an unparsable URL under its own runtime code
            let got = Base.run({ ($0 as? PCAEntropy.EntropyError)?.code ?? (($0 as? PCAEntropy.Refusal)?.message == "Invalid URL" ? "ERR_INVALID_URL" : nil) }) { () throws -> JSONValue in
                guard let v = try self.call(c) else { known = false; return .null }
                return v
            }
            if !known { unhandled.insert(c.fn); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(unhandled, [], "corpus functions without a native entry point")
        XCTAssertEqual(n, 562)
        d.finish(550)
    }

    func testThePlatformGeneratorAndTheUrlShapes() throws {
        let a = try E.secureSeed(), b = try E.secureSeed()
        XCTAssertEqual(a.seed.count, 32)
        XCTAssertNotEqual(a.seed, b.seed)
        XCTAssertFalse(a.usedQuantum)
        XCTAssertNil(a.source)
        var o = E.SecureSeedOptions()
        o.requireQuantum = true
        XCTAssertThrowsError(try E.secureSeed(o)) { XCTAssertEqual(($0 as? E.EntropyError)?.code, "quantum_required") }
        XCTAssertEqual(E.urlSetParam("HTTPS://Example.COM", "length", "4"), "https://example.com/?length=4")
        XCTAssertEqual(E.urlSetParam("https://h/a?length=1&x=2&length=3", "length", "9"), "https://h/a?length=9&x=2")
        XCTAssertEqual(E.urlSetParam("https://h/a#f", "q", "a b&c"), "https://h/a?q=a+b%26c#f")
        XCTAssertNil(E.urlSetParam("not a url", "length", "4"))
        XCTAssertEqual(E.urlPart("http://[::1]:8080/x", 1), "[::1]")
        XCTAssertEqual(E.urlPart("https://h:8443/x", 2), "h:8443")
    }
}
