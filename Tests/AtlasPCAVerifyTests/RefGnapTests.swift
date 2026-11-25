import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAGnap / PCAGnapInteraction against the reference (@atlasauth/pca-gnap). Seeds cross as base64url text and
/// a {"$bytes": ...} value as raw bytes; JS-typed options are mapped onto the typed options here. interactionScenario runs the
/// authorization-server state machine and redacts the random values, as the reference runner does. The SHA-3 interaction hashes are
/// refused natively (unsupported_hash), so cases that name one are skipped.
final class RefGnapTests: XCTestCase {
    static let file = "ref-gnap.json.gz"
    struct Skip: Error { let why: String }

    static func seed(_ v: JSONValue?) throws -> [UInt8] {
        guard let s = v?.asString, let b = Base64URLStrict.decode(s) else { throw JSError("secret is not a seed") }
        return b
    }

    static func content(_ m: JObject, _ k: String) -> PCAGnap.Content {
        guard let v = m[JKey(k)] else { return .none }
        if let b = Base.bytes(v) { return .bytes(b) }
        if let t = v.asString { return .text(t) }
        return .json(v)
    }

    static func pins(_ v: JSONValue?) -> PCAGnap.ChainPins {
        let m = Ref.obj(v)
        var p = PCAGnap.ChainPins()
        if let e = m["expectedRootIssuer"] { p.expectedRootIssuer = e.asString ?? "\u{0}null" } // null names an issuer no chain has
        if let q = m["pqPins"]?.asObject {
            var d: [String: String] = [:]
            for (k, x) in q { d[k.s] = x.asString ?? "" }
            p.pqPins = d
        }
        return p
    }

    static func grantOpts(_ v: JSONValue?) throws -> PCAGnap.GrantOptions {
        let m = Ref.obj(v)
        var o = PCAGnap.GrantOptions()
        if let sk = m["issuerSecret"] { o.issuerSeed = try seed(sk) }
        o.issuerPublic = m["issuerPublic"]?.asString
        o.parent = m["parent"]
        o.issuerChain = m["issuerChain"]?.asArray
        o.clampToIssuer = m["clampToIssuer"] != .bool(false)
        o.holder = m["holder"]
        o.interacted = m["interacted"] == .bool(true)
        o.now = m["now"].flatMap { IV.num($0) }
        o.goal = m["goal"]?.asString
        o.riskPolicy = JS.present(m["riskPolicy"])
        o.agentBinding = JS.present(m["agentBinding"])
        o.salt = m["salt"]?.asString
        return o
    }

    static func sign(_ m: JObject) throws -> JSONValue {
        let key = Ref.obj(m["key"])
        guard let htm = m["htm"]?.asString else { throw JSError("Cannot read properties of undefined (reading 'toUpperCase')") }
        var a = PCAGnap.SignArgs(body: content(m, "body"), seed: try seed(key["secretKey"]), htm: htm, uri: m["uri"] ?? .null)
        a.publicKey = key["publicKey"]?.asString.flatMap { Base64URLStrict.decode($0) }
        a.created = m["created"]
        a.kid = m["kid"]
        if let t = m["accessTokenValue"] { a.accessTokenValue = JS.toString(t) }
        return try PCAGnap.signGnapRequest(a)
    }

    static func verify(_ m: JObject) throws -> JSONValue {
        var seen: [JSONValue] = []
        var a = PCAGnap.VerifyArgs(detachedJws: m["detachedJws"], body: content(m, "body"), holder: m["holder"], htm: m["htm"], uri: m["uri"])
        a.replayUnchecked = m["replayCheck"] == .string("unchecked")
        a.now = m["now"].flatMap { IV.num($0) }
        a.maxAgeSec = m["maxAgeSec"].flatMap { IV.num($0) }
        if let t = m["accessTokenValue"] { a.accessTokenValue = JS.toString(t) }
        if let mode = m["seenProofMode"]?.asString {
            a.seenProof = { id, exp in
                seen.append(.array([.string(id), PCASdJwt.jnum(exp)]))
                switch mode {
                case "fresh": return false
                case "replayed": return true
                case "throws": throw JSError("store down")
                default: return nil
                }
            }
        }
        var r = try PCAGnap.verifyGnapRequest(a)
        if case var .object(o) = r, let reason = o["reason"]?.asString,
           let range = reason.range(of: #"(bad-json) \(.*\)$"#, options: .regularExpression) {
            o["reason"] = .string(reason.replacingCharacters(in: range, with: "bad-json"))
            r = .object(o)
        }
        return .object(["result": r, "seen": .array(seen)])
    }

    static func complete(_ m: JObject) throws -> JSONValue {
        guard let cs = m["cosignSecrets"]?.asArray else { throw JSError("Cannot read properties of undefined (reading 'map')") }
        var a = PCAGnap.ContinuationArgs(grant: m["grant"] ?? .null, chain: m["chain"]?.asArray ?? [], plan: (m["plan"]?.asArray ?? []).map { $0.asObject ?? [:] },
                                         nodeId: m["nodeId"]?.asString ?? "", counter: Int64(IV.num(m["counter"]) ?? 0), aud: m["aud"]?.asString ?? "",
                                         agentLeafSeed: try seed(m["agentLeafSecret"]), signerSet: m["signerSet"], t: m["t"],
                                         cosigns: try cs.map { (role: JS.toString($0.get("role")), seed: try seed($0.get("secret"))) })
        a.params = m["params"]
        a.now = m["now"].flatMap { IV.num($0) }.map { Int64($0) }
        a.ttlMs = m["ttlMs"].flatMap { IV.num($0) }.map { Int64($0) }
        return try PCAGnap.completeGnapContinuation(a)
    }

    // ---- the interaction-server runner (the reference's, with its manual clock and redaction) ----

    static func redact(_ v: JSONValue, _ toks: [(String, String)]) -> JSONValue {
        switch v {
        case var .string(s):
            for (k, t) in toks where !k.isEmpty { s = s.replacingOccurrences(of: k, with: t) }
            return .string(s)
        case let .array(a): return .array(a.map { redact($0, toks) })
        case let .object(o): return .object(o.mapValues { redact($0, toks) })
        default: return v
        }
    }

    static let INTERACTION_CODES: Set<String> = ["invalid_interaction", "unknown_interaction", "too_many_attempts", "invalid_request", "expired",
                                                 "wrong_state", "unsupported_hash"]

    static func scenario(_ sc: JSONValue?) -> JSONValue {
        var clock = 1000.0
        let opts = Ref.obj(sc?.get("opts"))
        let ge = opts["grantEndpoint"]?.asString ?? "https://as.example/tx"
        var so = PCAGnapInteraction.ServerOptions(grantEndpoint: ge, supports: (opts["supports"]?.asArray ?? []).compactMap { $0.asString },
                                                  redirectUri: { "https://as.example/i/\($0)" }, now: { clock })
        if JS.truthy(opts["app"]) { so.appUri = { "app://as/\($0)" } }
        if JS.truthy(opts["userCodeUri"]) { so.userCodeUri = opts["userCodeUri"]?.asString }
        if let t = opts["ttlSec"] { so.ttlSec = IV.num(t) }
        let srv = PCAGnapInteraction.Server(so)
        var v: [String: String] = [:]
        var lastReq: JSONValue? = nil
        // every started interaction's random id, user code and AS nonce is redacted, not only the latest: the latest keeps <ID> / <CODE> / <ASNONCE>, an earlier one
        // (start number n, from 0) is <ID:n> / <CODE:n> / <ASNONCE:n>
        var started: [(id: String, code: String, asnonce: String)] = []
        func sub(_ x: JSONValue?) -> String {
            guard let s = x?.asString, s.hasPrefix("$") else { return x?.asString ?? "" }
            let code = v["code"] ?? ""
            if s == "$code:lower" { return code.lowercased() }
            if s == "$code:spaced" { return String(code.prefix(4)) + " - " + String(code.dropFirst(4)) }
            return v[String(s.dropFirst())] ?? s
        }
        var trace: [JSONValue] = []
        for st in sc?.get("steps")?.asArray ?? [] {
            let op = st.get("op")?.asString ?? ""
            do {
                var value: JSONValue = .null
                switch op {
                case "start":
                    lastReq = st.get("req")
                    let r = try srv.start(st.get("req") ?? .null)
                    v["id"] = r.interaction.id
                    v["code"] = r.interaction.userCode ?? ""
                    v["asnonce"] = r.interaction.finish?["asNonce"]?.asString ?? ""
                    started.append((v["id"] ?? "", v["code"] ?? "", v["asnonce"] ?? ""))
                    value = .object(["interaction": r.interaction.json, "response": r.response])
                case "lookup": value = srv.lookupUserCode(sub(st.get("code")))?.json ?? .null
                case "approve":
                    let r = try srv.approve(sub(st.get("id")))
                    let ref = r.get("interactRef")?.asString ?? ""
                    v["ref"] = ref
                    let it = v["id"].flatMap { srv.get($0) }
                    var m: String? = nil
                    if let f = r.get("finish") {
                        if f.get("method") == .string("push") { m = f.get("body")?.get("hash")?.asString } else if let url = f.get("url")?.asString,
                            let rg = url.range(of: #"[?&]hash=[^&]+"#, options: .regularExpression) {
                            m = String(url[rg].drop { $0 != "=" }.dropFirst())
                        }
                    }
                    v["hash"] = m ?? ""
                    var expected: String? = nil
                    if let f = it?.finish {
                        expected = try PCAGnapInteraction.interactionHash(.object(["clientNonce": f["clientNonce"] ?? .null, "asNonce": f["asNonce"] ?? .null,
                                                                                    "interactRef": .string(ref), "grantEndpoint": .string(it!.grantEndpoint),
                                                                                    "hashMethod": f["hashMethod"] ?? .null]))
                    }
                    value = .object(["result": r, "hashOk": .bool(m == expected)])
                case "consume": value = try srv.consume(sub(st.get("ref"))).json
                case "finalize": srv.finalize(sub(st.get("id")))
                case "get": value = srv.get(sub(st.get("id")))?.json ?? .null
                case "advance":
                    clock += IV.num(st.get("sec")) ?? 0
                    value = PCASdJwt.jnum(clock)
                case "accept":
                    guard let fin = lastReq?.get("finish")?.asObject else { throw JSError("Cannot read properties of undefined (reading 'nonce')") }
                    var ctx: JObject = ["clientNonce": fin["nonce"] ?? .null, "grantEndpoint": .string(ge)]
                    if let n = v["asnonce"] { ctx["asNonce"] = .string(n) }
                    if JS.truthy(fin["hash_method"]) { ctx["hashMethod"] = fin["hash_method"] }
                    value = .string(try PCAGnapInteraction.acceptFinish(.object(["hash": .string(sub(st.get("hash"))), "interact_ref": .string(sub(st.get("ref")))]), ctx))
                default: break
                }
                var toks = [("ref", "<REF>"), ("hash", "<HASH>"), ("asnonce", "<ASNONCE>"), ("id", "<ID>"), ("code", "<CODE>")].map { (v[$0.0] ?? "", $0.1) }
                for (n, a) in started.dropLast().enumerated() { toks += [(a.id, "<ID:\(n)>"), (a.code, "<CODE:\(n)>"), (a.asnonce, "<ASNONCE:\(n)>")] }
                trace.append(.object(["op": .string(op), "ok": .bool(true), "value": redact(value, toks)]))
            } catch {
                let code = (error as? JSError)?.code.flatMap { Self.INTERACTION_CODES.contains($0) ? $0 : nil } ?? "other"
                trace.append(.object(["op": .string(op), "ok": .bool(false), "code": .string(code)]))
            }
        }
        return .array(trace)
    }

    func testGnap() throws {
        try K042.requireCovers(["Gnap", "JSInterop", "Jose"])
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            var got: BaseGot
            do {
                if Base.canon(.array(c.args)).contains("sha3-"), Sha3.digest("sha3-256", []) == nil { throw Skip(why: "a SHA-3 interaction hash: no SHA-3 on this platform") }
                switch c.fn {
                case "constants":
                    let mine: JSONValue = .object([
                        "GNAP_GRANT_CAVEAT": .string(PCAGnap.GNAP_GRANT_CAVEAT), "GNAP_ACCESS_CAVEAT": .string(PCAGnap.GNAP_ACCESS_CAVEAT),
                        "MAX_DETACHED_JWS_CHARS": .int(Int64(PCAGnap.MAX_DETACHED_JWS_CHARS)),
                        "START_MODES": .array(PCAGnapInteraction.START_MODES.map { .string($0) }), "FINISH_METHODS": .array(PCAGnapInteraction.FINISH_METHODS.map { .string($0) }),
                    ])
                    // HASH_METHODS is the reference's list, in the same order
                    var want = c.out.asObject ?? [:]
                    let ref = (want["HASH_METHODS"]?.asArray ?? []).compactMap { $0.asString }
                    want["HASH_METHODS"] = nil
                    d.add(c, Base.canon(.object(want)) == Base.canon(mine) && ref == PCAGnapInteraction.HASH_METHODS ? nil : "constants differ")
                    return
                case "AGENT_GNAP_PROFILE": got = .value(PCAGnap.AGENT_GNAP_PROFILE)
                case "gnapActionResource": got = .value(.string(PCAGnap.gnapActionResource(a0?.asString ?? "", a1?.asString ?? "")))
                case "normalizeAccess": got = Ref.v { .array(try PCAGnap.normalizeAccess(a0)) }
                case "accessToPredicates": got = .value(.array(PCAGnap.accessToPredicates(Ref.obj(a0))))
                case "accessContains": got = .value(.bool(PCAGnap.accessContains(Ref.obj(a0), Ref.obj(a1))))
                case "accessWithin": got = .value(.bool(PCAGnap.accessWithin(a0?.asArray ?? [], Ref.obj(a1))))
                case "clampAccess":
                    let r = PCAGnap.clampAccess(a0?.asArray ?? [], a1?.asArray ?? [])
                    got = .value(.object(["granted": .array(r.granted), "dropped": .array(r.dropped)]))
                case "resolveHolder": got = Ref.s { try PCAGnap.resolveHolder(a0, override: c.args.count > 1 ? a1 : nil) }
                case "holderJwk": got = .value(PCAGnap.holderJwk(a0?.asString ?? ""))
                case "grantRequestToCapability": got = Ref.v { try PCAGnap.grantRequestToCapability(a0, try Self.grantOpts(a1)) }
                case "grantedAccessOf": got = Ref.v { .array(try PCAGnap.grantedAccessOf(a0)) }
                case "authorizeGnapAction": got = Ref.v { try PCAGnap.authorizeGnapAction(a0, a1, Self.pins(a2)) }
                case "encodeBoundToken":
                    if c.name.hasSuffix("order") { throw Skip(why: "member order of a non-capability object (JSONValue keeps none)") }
                    got = .value(.string(PCAGnap.encodeBoundToken(a0?.asArray ?? [])))
                case "capabilityToGrantResponse": got = Ref.v { try PCAGnap.capabilityToGrantResponse(a0, Ref.obj(a1)) }
                case "verifyGnapToken": got = .value(PCAGnap.verifyGnapToken(a0, Self.pins(a1)))
                case "gnapContentDigest": got = Ref.v { Base.bytesValue(try PCAGnap.gnapContentDigest(Self.content(["b": a0 ?? .null], "b"))) }
                case "gnapContentDigestAbsent": got = Ref.v { Base.bytesValue(try PCAGnap.gnapContentDigest(.none)) }
                case "signGnapRequest": got = Ref.v { try Self.sign(Ref.obj(a0)) }
                case "verifyGnapRequest": got = Ref.v { try Self.verify(Ref.obj(a0)) }
                case "gnapRequestRequiresStepUp":
                    let m = Ref.obj(a1)
                    got = Ref.v { try PCAGnap.gnapRequestRequiresStepUp(a0, issuerChain: JS.truthy(m["issuerChain"]) ? m["issuerChain"]?.asArray : nil, tier: m["tier"]) }
                case "beginGnapContinuation": got = .value(PCAGnap.beginGnapContinuation(Ref.obj(a0)))
                case "gnapStepUpShare":
                    got = Ref.v { try PCAGnap.gnapStepUpShare(Ref.obj(a0), role: a1?.asString ?? "", seed: try Self.seed(a2), signerSet: c.arg(3), t: c.arg(4)) }
                case "completeGnapContinuation": got = Ref.v { try Self.complete(Ref.obj(a0)) }
                case "callbackUriOk": got = .value(.bool(PCAGnapInteraction.callbackUriOk(a0)))
                case "validateInteractRequest": got = .value(.array(PCAGnapInteraction.validateInteractRequest(a0).map { .string($0) }))
                case "interactionHash":
                    got = Ref.v {
                        guard let a = a0, a.isObject else { throw JSError("not an object") }
                        return .string(try PCAGnapInteraction.interactionHash(a))
                    }
                case "verifyInteractionHash": got = Ref.v { .bool(try PCAGnapInteraction.verifyInteractionHash(a0, a1 ?? .null)) }
                case "acceptFinish": got = Ref.v { .string(try PCAGnapInteraction.acceptFinish(a0, Ref.obj(a1))) }
                case "newUserCode": got = Ref.s { try PCAGnapInteraction.newUserCode(Int(IV.num(a0) ?? 0)) }
                case "accessToNeeds": got = Ref.v { .array(try PCAGnapInteraction.accessToNeeds(a0?.asArray ?? [])) }
                case "interactionScenario": got = .value(Self.scenario(a0))
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
        d.finish(1500)
    }

    func testGnapFailClosed() throws {
        // no replay store and no explicit opt-out: refused; a SHA-3 hash method is refused where the platform has no SHA-3, never computed with another hash
        let a = PCAGnap.VerifyArgs(detachedJws: .string("a..b"), body: .none, holder: .null, htm: .string("POST"), uri: .string("u"))
        XCTAssertThrowsError(try PCAGnap.verifyGnapRequest(a))
        if Sha3.digest("sha3-256", []) == nil {
            XCTAssertThrowsError(try PCAGnapInteraction.interactionHash(.object(["hashMethod": .string("sha3-256")]))) { e in
                XCTAssertEqual((e as? JSError)?.code, "unsupported_hash")
            }
        }
        // RFC 9635 4.2.3 example inputs, sha-256
        let rfc: JSONValue = .object(["clientNonce": .string("VJLO6A4CAYLBXHTR0KRO"), "asNonce": .string("MBDOFXG4Y5CVJCX821LH"),
                                      "interactRef": .string("4IFWWIKYBC2PQ6U56NL1"), "grantEndpoint": .string("https://server.example.com/tx")])
        XCTAssertEqual(try PCAGnapInteraction.interactionHash(rfc), "jdHcrti02HLCwGU3qhUZ3wZXt8IjrV_BtE3oUyOuKNk")
        XCTAssertFalse(PCAGnapInteraction.callbackUriOk(.string("http://remote.example/cb")))
        XCTAssertTrue(PCAGnapInteraction.callbackUriOk(.string("http://[::1]:3000/cb")))
    }
}
