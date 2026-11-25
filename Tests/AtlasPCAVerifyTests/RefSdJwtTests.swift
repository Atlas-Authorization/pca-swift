import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCASdJwt against the reference (@atlasauth/pca-sdjwt): issue / present / verify / verifyRecovered.
/// Keys travel as seeds / raw public bytes ({"$bytes"}) or JWKs and options use snake_case names; JS-typed hostile option values
/// are mapped to what the typed API expresses (a value the reference refuses becomes {ok:false}). issuePcaSdJwt carries random
/// salts, so its case compares the generator's normalized form; a verify {ok:false} compares `reason` only when it is this
/// package's own (library messages are not stable across implementations).
final class RefSdJwtTests: XCTestCase {
    static let file = "ref-sdjwt.json.gz"
    struct Skip: Error { let why: String }

    static func pub(_ seed: [UInt8]) throws -> [UInt8] { try Ed25519Deterministic.key(seed: seed).pub }
    static func refuse(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }

    /// The generator's normalized issue output: header, clear payload, sorted [name, value] disclosures, digest agreement and
    /// whether the token verifies at its own iat.
    static func normalize(_ sd: String, seed: [UInt8]) throws -> JSONValue {
        let parts = sd.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        let ds = Array(parts[1..<(parts.count - 1)])
        func dec(_ s: String) throws -> JSONValue {
            guard let b = Base64URLStrict.decode(s), let t = String(bytes: b, encoding: .utf8) else { throw JSError("bad segment") }
            return try StrictJSON.parseLenient(t)
        }
        let seg = parts[0].split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let h = try dec(seg[0])
        var p = try dec(seg[1]).asObject ?? [:]
        let sdl = (p["_sd"]?.asArray ?? []).compactMap { $0.asString }.sorted()
        p["_sd"] = nil
        let dig = ds.map { PCASdJwt.sha($0) }.sorted()
        var disc: [[JSONValue]] = []
        for d in ds { let a = try dec(d).asArray ?? []; disc.append([a[1], a[2]]) }
        disc.sort { ($0[0].asString ?? "") < ($1[0].asString ?? "") }
        var vo = PCASdJwt.VerifyOptions(issuerKey: .ed25519(try pub(seed)))
        vo.nowMs = (IV.num(p["iat"]) ?? 0) * 1000
        return .object(["end": .string(parts[parts.count - 1]), "header": h, "payload": .object(p), "n": .int(Int64(ds.count)),
                        "digestsOk": .bool(dig == sdl), "disclosures": .array(disc.map { .array($0) }),
                        "verified": PCASdJwt.verifyPcaSdJwt(sd, vo).get("ok") ?? .bool(false)])
    }

    static func issueW(_ pc: JSONValue?, _ m: JObject) throws -> JSONValue {
        guard let seed = Base.bytes(m["issuer_seed"]) else { throw JSError("no seed") }
        try PCASdJwt.checkSeed(seed)
        var o = PCASdJwt.IssueOptions(issuerSeed: seed)
        if let l = m["disclosable"]?.asArray { o.disclosable = l.compactMap { $0.asString } }
        if let kb = m["key_binding"], JS.truthy(kb) {
            o.keyBinding = true
            if let hp = kb.asObject?["holder_public_key"] { o.holderPublicKey = Base.bytes(hp).map { .raw($0) } ?? .jwk(hp) }
        }
        o.iss = m["iss"]?.asString
        o.sub = m["sub"]?.asString
        o.typ = m["typ"]?.asString
        o.signingAlg = m["signing_alg"]
        return try normalize(try PCASdJwt.issuePcaSdJwt(pc, o), seed: seed)
    }

    static func presentW(_ sd: JSONValue?, _ sel: JSONValue?, _ opt: JSONValue?) throws -> String {
        var select: [String] = []
        switch sel {
        case nil, .null?: break
        case let .string(s)?: select = s.unicodeScalars.map { String($0) } // a string selector iterates its characters
        case let .array(a)?: select = a.compactMap { $0.asString }
        default: throw JSError("selector is not iterable")
        }
        var kb: PCASdJwt.PresentKeyBinding? = nil
        if let km = opt?.get("key_binding")?.asObject {
            guard let seed = Base.bytes(km["holder_seed"]) else { throw JSError("no seed") }
            try PCASdJwt.checkSeed(seed)
            var k = PCASdJwt.PresentKeyBinding(holderSeed: seed, audience: km["audience"])
            k.nonce = km["nonce"]
            if let i = km["iat"], i != .null { k.iat = i }
            if let a = km["alg"], a != .null { k.alg = a }
            kb = k
        }
        return try PCASdJwt.present(sd?.asString, select, keyBinding: kb)
    }

    static func audience(_ v: JSONValue?, kb: Bool) throws -> [String]? {
        switch v {
        // null / "": the reference then only requires an aud claim to be present; every vector's token carries one
        case nil, .null?: return nil
        case let .string(s)?:
            if !s.isEmpty { return [s] }
            if kb { throw Skip(why: "an empty KB audience: presence-only, not expressible") }
            return nil
        case let .array(a)?: return a.compactMap { $0.asString }
        default: throw JSError("audOption.includes is not a function")
        }
    }

    static func algs(_ v: JSONValue?, _ name: String) throws -> [String]? {
        guard let x = v, x != .null else { return nil }
        guard let l = Ref.strings(x) else { throw JSError("\"\(name)\" option must be an array of strings") }
        return l
    }

    static func verifyW(_ sd: JSONValue?, _ m: JObject) throws -> JSONValue {
        let key: Jose.Key
        if let b = Base.bytes(m["issuer_key"]) {
            key = try PCASdJwt.ed25519PublicKey(b)
        } else {
            // the reference imports the JWK (a private one too) and verifies with its public half
            let j = m["issuer_key"]?.asObject ?? [:]
            let curves = ["ES256": "P-256", "ES384": "P-384", "ES512": "P-521"]
            let b = { (k: String) in j[JKey(k)]?.asString.flatMap { Base64URLStrict.decode($0) } ?? [] }
            key = .ec(curve: curves[m["issuer_jwk_alg"]?.asString ?? "ES256"] ?? "P-256", point: [0x04] + b("x") + b("y"))
        }
        var o = PCASdJwt.VerifyOptions(issuerKey: key)
        do {
            if let n = m["now"] {
                let f = JS.toNumber(n)
                if abs(f) > 8.64e15 { throw Skip(why: "a clock outside the JS Date range turns the reference's time checks off; refused natively") }
                o.nowMs = f
            }
            o.expectedAudience = try audience(m["expected_audience"], kb: false)
            o.expectedKbAudience = try audience(m["expected_kb_audience"], kb: true)
            if let n = m["expected_nonce"] { o.expectedNonce = n.asString ?? "\u{0}null" } // a null expectation matches no nonce
            o.requireKeyBinding = JS.truthy(m["require_key_binding"])
            if let k = m["key_binding_key"] { o.keyBindingKey = Base.bytes(k).map { .raw($0) } ?? .jwk(k) }
            o.algorithms = try algs(m["algorithms"], "algorithms")
            o.kbAlgorithms = try algs(m["kb_algorithms"], "kbAlgorithms")
            if let l = m["required_disclosures"]?.asArray { o.requiredDisclosures = l.map { JS.toString($0) } }
            if let x = m["kb_max_age_sec"] { o.kbMaxAgeSec = JS.toNumber(x) } // null compares as 0
            switch m["clock_tolerance_sec"] {
            case nil: break
            case let v? where v.isNumber: o.clockToleranceSec = IV.num(v)
            case let .string(s)?:
                let p = s.split(separator: " ")
                if p.count == 2, Int(p[0]) != nil, p[1] == "seconds" || p[1] == "second" {
                    throw Skip(why: "a duration-string clock tolerance: refused natively (numbers only)")
                }
                throw JSError("Invalid time period format")
            default: throw JSError("Invalid clockTolerance option type")
            }
        } catch let e as JSError {
            return refuse(e.message)
        }
        return PCASdJwt.verifyPcaSdJwt(sd?.asString, o)
    }

    static let ownPrefixes = ["pca-sdjwt:", "KB-JWT", "a digest appears", "an array", "an object-property", "_sd must", "disclosure claim", "'",
                              "unsupported _sd_alg", "duplicate disclosure", "a presented disclosure", "required disclosure", "cnf key does not",
                              "key binding required"]
    static let kbInvalid = "KB-JWT signature/claims invalid: "

    static func sameRefusal(_ want: String, _ got: JSONValue) -> Bool {
        guard got.get("ok") == .bool(false), let g = got.get("reason")?.asString else { return false }
        if want.hasPrefix(kbInvalid) { return g.hasPrefix(kbInvalid) }
        return ownPrefixes.contains(where: { want.hasPrefix($0) }) ? want == g : true
    }

    func testSdJwt() throws {
        try K042.requireCovers(["SdJwt", "Jose", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object([
                    "SD_ALG": .string(PCASdJwt.SD_ALG), "PCA_SD_JWT_TYP": .string(PCASdJwt.PCA_SD_JWT_TYP), "KB_JWT_TYP": .string(PCASdJwt.KB_JWT_TYP),
                    "DEFAULT_SIGNING_ALG": .string(PCASdJwt.DEFAULT_SIGNING_ALG), "PCA_CAPABILITY_CLAIMS": .array(PCASdJwt.PCA_CAPABILITY_CLAIMS.map { .string($0) }),
                ]))
            case "ed25519PublicJwk":
                got = Ref.v { try PCASdJwt.ed25519PublicJwk(Base.bytes(a0) ?? []) }
            case "importEd25519PrivateKey":
                got = Ref.s { try PCASdJwt.checkSeed(Base.bytes(a0) ?? []); return "ok" }
            case "importEd25519PublicKey":
                got = Ref.s { _ = try PCASdJwt.ed25519PublicKey(Base.bytes(a0) ?? []); return "ok" }
            case "issuePcaSdJwt":
                got = Ref.v { try Self.issueW(a0, Ref.obj(a1)) }
            case "present":
                got = Ref.s { try Self.presentW(a0, a1, c.arg(2)) }
            case "verifyPcaSdJwt":
                let name = c.name
                if name.hasSuffix("cnf jwk with d") { d.skip("a cnf carrying private key material: refused natively"); return }
                let r: JSONValue
                do { r = try Self.verifyW(a0, Ref.obj(a1)) } catch let s as Skip { d.skip(s.why); return } catch {
                    d.add(c, Base.diff(c, .threw(Ref.code(error)))); return
                }
                if let w = c.out.asObject, w["ok"] == .bool(false), let wr = w["reason"]?.asString {
                    d.add(c, Self.sameRefusal(wr, r) ? nil : "refusal: want \(wr), got \(Base.canon(r))")
                    return
                }
                got = .value(r)
            case "verifyRecovered":
                let m = Ref.obj(a1)
                let aud: PCA.Audience
                switch m["audience"] {
                case nil: aud = .unset
                case .null?: aud = .any
                case let .string(s)?: aud = .id(s)
                default: d.skip("verifyRecovered: non-string audience"); return
                }
                let v = PCASdJwt.verifyRecovered(a0 ?? .null, grant: m["grant"] ?? .null, now: Int64(IV.num(m["now"]) ?? 0), audience: aud,
                                                 insecureSkipPlanRootCheck: m["insecure_skip_plan_root_check"] == .bool(true))
                var out: JObject = ["allow": .bool(v.allow)]
                if !v.reason.isEmpty { out["reason"] = .string(v.reason) }
                got = .value(.object(out))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(300)
    }

    func testSdJwtFailClosed() throws {
        let seed = [UInt8](repeating: 1, count: 32)
        var o = PCASdJwt.VerifyOptions(issuerKey: .ed25519(try Self.pub(seed)))
        // a non-finite or out-of-range clock, a non-finite KB window: refused before anything else
        for n in [Double.nan, .infinity, 1e300] {
            o.nowMs = n
            XCTAssertEqual(PCASdJwt.verifyPcaSdJwt("a.b.c~", o).get("ok"), .bool(false))
        }
        o.nowMs = nil
        o.kbMaxAgeSec = .nan
        XCTAssertEqual(PCASdJwt.verifyPcaSdJwt("a.b.c~", o).get("reason"), .string("pca-sdjwt: kbMaxAgeSec must be finite"))
        // a cnf with private material is never a KB-JWT key
        XCTAssertThrowsError(try PCASdJwt.kbKey(["kty": .string("OKP"), "crv": .string("Ed25519"), "x": .string(Base64URLStrict.encode(try Self.pub(seed))),
                                                 "d": .string(Base64URLStrict.encode(seed))]))
        // only Ed25519 signs
        var io = PCASdJwt.IssueOptions(issuerSeed: seed)
        io.signingAlg = .string("HS256")
        XCTAssertThrowsError(try PCASdJwt.issuePcaSdJwt(.object([:]), io))
    }
}
