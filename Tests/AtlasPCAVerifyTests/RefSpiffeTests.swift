import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCASpiffe against the reference (@atlasauth/pca-spiffe). A certificate crosses as PEM text or {"$bytes"}
/// DER; the revocation modes ('false' | 'true' | 'at:N' | 'throw' | 'nonbool') become checks that record what they saw; a key option is
/// {jwk} (imported for the header's alg) or {jwks} (a local JWK Set); the cache scenarios run a scripted clock and fetch. Values a
/// typed Swift parameter cannot hold (a non-function revocation, a non-string token, a holder key that is neither text nor bytes, a
/// non-list algorithms option) are skipped.
final class RefSpiffeTests: XCTestCase {
    static let file = "ref-spiffe-svid.json.gz"
    struct Skip: Error { let why: String }
    final class Calls { var list: [JSONValue] = [] }

    static func cert(_ v: JSONValue?) throws -> PCASpiffe.CertInput {
        if let s = v?.asString { return .pem(s) }
        if let b = Base.bytes(v) { return .der(b) }
        throw Skip(why: "a certificate that is neither text nor bytes is a Swift type error")
    }

    static func certs(_ v: JSONValue?) throws -> [PCASpiffe.CertInput] {
        if let s = v?.asString { return [.pem(s)] }
        guard let a = v?.asArray else { throw Skip(why: "a chain that is neither text nor a list is a Swift type error") }
        return try a.map { try cert($0) }
    }

    static func rev(_ m: JObject, _ calls: Calls) throws -> PCASpiffe.RevocationCheck? {
        guard let raw = m["revocation"] else { return nil }
        guard let mode = raw.asString else { throw Skip(why: "a non-function revocation value is a Swift type error") }
        let at = mode.hasPrefix("at:") ? Double(mode.dropFirst(3)) ?? -1 : -1
        return { s in
            calls.list.append(.object(s))
            switch mode {
            case "throw": throw JSError("backend down")
            case "nonbool": throw JSError("revocation check did not return a boolean")
            case "true": return true
            default: return at >= 0 && IV.num(s["position"]) == at
            }
        }
    }

    static func xo(_ v: JSONValue?, _ calls: Calls) throws -> PCASpiffe.VerifyX509Options {
        let m = Ref.obj(v)
        var o = PCASpiffe.VerifyX509Options(trustDomain: m["trustDomain"]?.asString ?? "", roots: try (m["roots"]?.asArray ?? []).map { try cert($0) })
        o.nowMs = IV.num(m["nowMs"])
        o.maxChainLength = IV.num(m["maxChainLength"]).map { Int($0) }
        o.revocation = try rev(m, calls)
        return o
    }

    static func jo(_ v: JSONValue?, _ calls: Calls) throws -> PCASpiffe.VerifyJwtOptions {
        let m = Ref.obj(v)
        var aud: [String] = []
        switch m["audience"] {
        case let .string(s)?: aud = [s]
        case let .array(a)?:
            guard a.allSatisfy({ $0.asString != nil }) else { throw Skip(why: "a non-string audience member is a Swift type error") }
            aud = a.compactMap { $0.asString }
        default: break // the reference refuses these too (a TypeError)
        }
        var key: PCASpiffe.KeyResolver? = nil
        if let jwk = m["key"]?.get("jwk"), jwk.isObject {
            key = { _, alg in try PCAOidc.importJwk(jwk, alg: alg) }
        } else if let jwks = m["key"]?.get("jwks") {
            let set = try OidcLocalJwks(jwks)
            key = { h, _ in try set.select(h).key }
        }
        var o = PCASpiffe.VerifyJwtOptions(audience: aud, key: key, trustDomain: m["trustDomain"]?.asString ?? "")
        o.currentSec = IV.num(m["currentSec"])
        if let a = m["algorithms"] {
            guard let l = a.asArray, l.allSatisfy({ $0.asString != nil }) else { throw Skip(why: "a non-list algorithms option is a Swift type error") }
            o.algorithms = l.compactMap { $0.asString }
        }
        o.clockTolerance = m["clockTolerance"]
        o.revocation = try rev(m, calls)
        return o
    }

    static func token(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw Skip(why: "a non-string token is a Swift type error") }
        return s
    }

    static func holderKey(_ v: JSONValue?) throws -> PCASpiffe.HolderKey? {
        guard let v = v, v != .null else { return nil }
        if let s = v.asString { return .b64u(s) }
        if let b = Base.bytes(v) { return .raw(b) }
        throw Skip(why: "a holder key that is neither text nor bytes is a Swift type error")
    }

    static func bind(_ v: JSONValue?) -> PCASpiffe.BindOptions {
        let m = Ref.obj(v)
        return PCASpiffe.BindOptions(proof: m["proof"]?.asString, acceptUnboundJwtHolder: m["acceptUnboundJwtHolder"] == .bool(true))
    }

    static func window(_ m: JObject, _ k: String) -> Double {
        guard let v = m[JKey(k)], v.isNumber, let n = IV.num(v) else { return .nan }
        return n
    }

    final class Script {
        var t = 0.0, fetches = 0
        var cur: JSONValue? = nil
        func fetch() throws -> JSONValue? {
            fetches += 1
            if let x = cur?.get("$throw"), JS.truthy(x) { throw JSError(JS.toString(x)) }
            if let c = cur?.get("$spiffe")?.asString, !c.isEmpty { throw JSError("x", code: c) }
            return cur
        }
        func step(_ s: JSONValue) { t = IV.num(s.get("at")) ?? 0; cur = s.get("fetch"); fetches = 0 }
        func out(_ f: () throws -> JSONValue) -> JSONValue {
            do { let v = try f(); return .object(["ok": v, "fetches": .int(Int64(fetches))]) } catch {
                return .object(["code": Base.opt(Ref.code(error)), "fetches": .int(Int64(fetches))])
            }
        }
    }

    static func trustBundle(_ opts: JSONValue?, _ steps: JSONValue?) -> JSONValue {
        let m = Ref.obj(opts), sc = Script()
        let src: PCASpiffe.TrustBundleSource
        do { src = try PCASpiffe.TrustBundleSource(fetch: sc.fetch, refreshMs: window(m, "refreshMs"), maxStaleMs: window(m, "maxStaleMs"), now: { sc.t }) } catch {
            return .object(["ctor": Base.opt(Ref.code(error))])
        }
        return .object(["steps": .array((steps?.asArray ?? []).map { s in
            sc.step(s)
            if s.get("op") == .string("x509Roots") { return sc.out { .array(try src.x509Roots()) } }
            let h = s.get("header")?.asObject ?? ["alg": .string("ES256")]
            return sc.out { _ = try src.jwtKey(h); return .string("key") }
        })])
    }

    static func revocation(_ opts: JSONValue?, _ steps: JSONValue?) -> JSONValue {
        let m = Ref.obj(opts), sc = Script()
        let src: PCASpiffe.RevocationSource
        do { src = try PCASpiffe.RevocationSource(fetch: sc.fetch, refreshMs: window(m, "refreshMs"), maxStaleMs: window(m, "maxStaleMs"), now: { sc.t }) } catch {
            return .object(["ctor": Base.opt(Ref.code(error))])
        }
        return .object(["steps": .array((steps?.asArray ?? []).map { s in
            sc.step(s)
            let subject = s.get("subject")?.asObject ?? [:]
            switch s.get("op")?.asString {
            case "ensureFresh": return sc.out { try src.ensureFresh(); return .null }
            case "refresh": return sc.out { try src.refresh(); return .null }
            case "x509": return sc.out { .bool(try src.x509(subject)) }
            default: return sc.out { .bool(try src.jwt(subject)) }
            }
        })])
    }

    func testSpiffe() throws {
        try K042.requireCovers(["Spiffe", "Jose", "AttestCert"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
            var got: BaseGot
            do {
                switch c.fn {
                case "parseSpiffeId":
                    got = Ref.v { try PCASpiffe.parseSpiffeId(a0?.asString ?? "").json }
                case "parseX509Svid":
                    let ci = try Self.cert(a0)
                    got = Ref.v { let s = try PCASpiffe.parseX509Svid(ci); return .object(["spiffeId": s.spiffeId.json, "publicKeyDer": .string(s.publicKeyDer)]) }
                case "verifyX509Svid":
                    let calls = Calls(), chain = try Self.certs(a0), o = try Self.xo(a1, calls)
                    got = Ref.v {
                        let s = try PCASpiffe.verifyX509Svid(chain, o)
                        var out = s.spiffeId.json.asObject ?? [:]
                        out["publicKeyDer"] = .string(s.publicKeyDer)
                        out["calls"] = .array(calls.list)
                        return .object(out)
                    }
                case "verifyJwtSvid":
                    let calls = Calls(), t = try Self.token(a0), o = try Self.jo(a1, calls)
                    got = Ref.v {
                        let s = try PCASpiffe.verifyJwtSvid(t, o)
                        return .object(["spiffeId": s.spiffeId.json, "claims": .object(s.claims), "audience": s.audience, "expiresAt": s.expiresAt, "calls": .array(calls.list)])
                    }
                case "svidToHolderX509":
                    let chain = try Self.certs(a0), o = try Self.xo(a1, Calls()), hk = try Self.holderKey(a2)
                    got = Ref.v { try PCASpiffe.svidToHolder(.x509(try PCASpiffe.verifyX509Svid(chain, o)), hk, Self.bind(a3)).json }
                case "svidToHolderJwt":
                    let t = try Self.token(a0), o = try Self.jo(a1, Calls()), hk = try Self.holderKey(a2)
                    got = Ref.v { try PCASpiffe.svidToHolder(.jwt(try PCASpiffe.verifyJwtSvid(t, o)), hk, Self.bind(a3)).json }
                case "svidToHolderUnverified":
                    // a string, a hand-built object, null or a number are no SVID value in Swift; a parse-only SVID is
                    let kind = a0?.asString ?? ""
                    got = Ref.v {
                        let s: PCASpiffe.Svid? = kind.hasPrefix("parsed") && kind != "parsed jwt-like" ? .x509(try PCASpiffe.parseX509Svid(try Self.cert(a1))) : nil
                        return try PCASpiffe.svidToHolder(s, .b64u("NdQrWOmikoF0DqDFEK2vMLAjX2TEdbAk2yigAcMDoX8")).json
                    }
                case "spiffeIdForHolder":
                    let chain = try Self.certs(a0), o = try Self.xo(a1, Calls())
                    got = Ref.s { try PCASpiffe.spiffeIdForHolder(.x509(try PCASpiffe.verifyX509Svid(chain, o)), a2?.asString ?? "", Self.bind(a3)) }
                case "workloadDischargePin":
                    let chain = try Self.certs(a1), o = try Self.xo(a2, Calls())
                    got = Ref.v { .object(try PCASpiffe.workloadDischargePin(a0?.asString ?? "", try PCASpiffe.verifyX509Svid(chain, o))) }
                case "holderToSpiffeId":
                    got = Ref.s { try PCASpiffe.holderToSpiffeId(a0?.get("spiffeId")?.asString ?? "") }
                case "holderBindingMessage":
                    got = .value(Base.bytesValue(PCASpiffe.holderBindingMessage(a0?.asString ?? "", a1?.asString ?? "")))
                case "spiffeAdmissionEvidence":
                    let e = Ref.obj(a0)
                    let ev: PCASpiffe.Evidence = e["kind"] == .string("x509")
                        ? .x509(chain: try Self.certs(e["chain"]), verify: try Self.xo(e["verify"], Calls()), bind: Self.bind(e["bind"]))
                        : .jwt(token: try Self.token(e["token"]), verify: try Self.jo(e["verify"], Calls()), bind: Self.bind(e["bind"]))
                    got = .value(PCASpiffe.spiffeAdmissionEvidence(ev, a1?.asString ?? ""))
                case "trustBundleScenario": got = .value(Self.trustBundle(a0, a1))
                case "revocationScenario": got = .value(Self.revocation(a0, a1))
                case "constants": got = .value(.object(["jwtSvidAlgorithms": .array(PCASpiffe.JWT_SVID_ALGORITHMS.map { .string($0) })]))
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
        d.finish(1100)
    }

    func testSpiffeFailClosed() throws {
        // an unverified SVID never binds; the caches refuse before their first fetch succeeds
        XCTAssertThrowsError(try PCASpiffe.svidToHolder(nil, .b64u("NdQrWOmikoF0DqDFEK2vMLAjX2TEdbAk2yigAcMDoX8"))) { XCTAssertEqual(Ref.code($0), "unverified_svid") }
        XCTAssertThrowsError(try PCASpiffe.parseSpiffeId("spiffe://example.org/a/")) { XCTAssertEqual(Ref.code($0), "invalid_path") }
        let tb = try PCASpiffe.TrustBundleSource(fetch: { throw JSError("down") }, refreshMs: 10, maxStaleMs: 10, now: { 0 })
        XCTAssertThrowsError(try tb.x509Roots()) { XCTAssertEqual(Ref.code($0), "trust_bundle_unavailable") }
        let rv = try PCASpiffe.RevocationSource(fetch: { .object([:]) }, refreshMs: 10, maxStaleMs: 10, now: { 0 })
        XCTAssertThrowsError(try rv.x509(["spiffeId": .string("spiffe://a/b")])) { XCTAssertEqual(Ref.code($0), "revocation_unavailable") }
        XCTAssertThrowsError(try PCASpiffe.RevocationSource(fetch: { nil }, refreshMs: 0, maxStaleMs: 10))
        XCTAssertEqual(try PCASpiffe.toleranceSecs(.string("2 minutes ago")), -120)
        XCTAssertThrowsError(try PCASpiffe.toleranceSecs(.string("-2 minutes ago")))
    }
}
