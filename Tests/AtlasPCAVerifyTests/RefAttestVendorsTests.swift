import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The reference corpus of the vendor attestation facades (ref-attest-vendors.json.gz, 758 cases, 22 functions) replayed through the reference-named
/// functions of AttestationVendors: constants, the DCAP quote / TD report parsers, the PCK extension reader and chain, the genuine-quote and collateral
/// verifiers, CRL / signed JSON, the Azure binding, the MAA / Confidential Space token parsers, the x5c chain checks, the hardware-model mapper and both
/// JWKS fetchers over a scripted transport (every requested URL is compared). A reason or throw text that comes from a library (OpenSSL "error:" text,
/// JSON.parse messages, the P-256 library's point errors, "URI malformed") is compared by presence; a case whose certificate bytes are not DER at all
/// only requires a refusal. Every function has a handler and the totals are asserted; no case is skipped.
final class RefAttestVendorsTests: XCTestCase {
    typealias V = AttestationVendors

    private static let TOTALS: [String: Int] = [
        "constants": 1, "toHex": 8, "pemToDer": 10, "ecdsaP256PublicKey": 12, "parseDcapTdReport": 11, "parseDcapQuote": 45, "extractPckFmspcAndTcb": 25,
        "verifyIntelPckChainX509": 46, "verifyGenuineTdxQuote": 64, "verifyCrl": 34, "serialIsRevoked": 10, "verifySignedJson": 31, "decodeIssuerChainHeader": 13,
        "verifyIntelTdxCollateral": 159, "checkAzureRuntimeDataBinding": 24, "parseMaaJwt": 57, "parseGcpCsJwt": 57, "verifyX5cChain": 61,
        "verifyJwkX5cChain": 27, "teeTypeOfHwModel": 15, "fetchMaaJwks": 22, "fetchGcpConfidentialSpaceJwks": 26,
    ]
    private static let NOT_DER = ["malformed-certificate", "pem-malformed-block", "garbage"]
    private static let LIB = try! NSRegularExpression(pattern: "error:[0-9A-Fa-f]{8}:|Unexpected token|Unexpected end of JSON input|bad point:|invalid Point, expected length|URI malformed|is not valid JSON|Expecting|Extra data")

    private static func isLib(_ s: String) -> Bool { LIB.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil }

    // ---- argument decoding ----

    private static func bytes(_ v: JSONValue?) -> [UInt8] { Base.bytes(v) ?? [] }
    private static func str(_ v: JSONValue?) -> String { v?.asString ?? "" }
    private static func ms(_ v: JSONValue?) -> Int64 { Int64(IV.num(v) ?? 0) }
    private static func list(_ v: JSONValue?) -> [String]? { v?.asArray.map { $0.compactMap { $0.asString } } }
    private static func bj(_ b: [UInt8]) -> JSONValue { Base.bytesValue(b) }

    /// A collateral document member: a string, or bytes (both occur).
    private static func text(_ v: JSONValue?) -> String {
        if let s = v?.asString { return s }
        if let b = Base.bytes(v) { return String(decoding: b, as: UTF8.self) }
        return ""
    }

    private static func collateral(_ v: JSONValue?) -> IntelTdxCollateral? {
        guard let o = v, o.isObject else { return nil }
        return IntelTdxCollateral(tcbInfoJson: text(o.get("tcbInfoJson")), tcbInfoIssuerChainPem: text(o.get("tcbInfoIssuerChainPem")), qeIdentityJson: text(o.get("qeIdentityJson")),
                                  qeIdentityIssuerChainPem: text(o.get("qeIdentityIssuerChainPem")), pckCrlDer: bytes(o.get("pckCrlDer")), rootCrlDer: bytes(o.get("rootCrlDer")))
    }

    // ---- the scripted JWKS transport: the i-th call gets script[min(i, last)] ----

    private static func fetch(_ a: JSONValue?, _ run: (@escaping AttestJwksTransport) throws -> JSONValue) -> JSONValue {
        let script = a?.get("script")?.asArray ?? []
        var log: [JSONValue] = []
        var i = 0
        let transport: AttestJwksTransport = { url in
            log.append(.string(url))
            let r = script[Swift.min(i, script.count - 1)]
            i += 1
            if let t = r.get("$throws")?.asString { throw JSError(t) }
            let status = Int(IV.num(r.get("status")) ?? 200)
            let body = r.get("body") ?? .null
            if let t = body.get("$text")?.asString, body.asObject?.count == 1 { return (status, Array(t.utf8)) }
            return (status, Array(JS.stringify(body).utf8))
        }
        var out: JObject = [:]
        do {
            out["jwks"] = try run(transport)
            out["ok"] = .bool(true)
        } catch {
            out["ok"] = .bool(false)
            out["error"] = .string((error as? AttestationConfigError)?.message ?? (error as? JSError)?.message ?? "\(error)")
        }
        out["requests"] = .array(log)
        return .object(out)
    }

    // ---- one case ----

    /// The native answer, or a refusal (the text of the thrown error).
    private static func call(_ c: BaseCase) throws -> JSONValue {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
        switch c.fn {
        case "constants": return V.constants()
        case "toHex": return .string(V.toHex(bytes(a0)))
        case "pemToDer": return bj(try V.pemToDer(str(a0)))
        case "ecdsaP256PublicKey": return try V.ecdsaP256PublicKey(bytes(a0))
        case "parseDcapTdReport": return try V.parseDcapTdReport(bytes(a0))
        case "parseDcapQuote": return try V.parseDcapQuote(bytes(a0))
        case "extractPckFmspcAndTcb": return try V.extractPckFmspcAndTcb(bytes(a0))
        case "verifyIntelPckChainX509":
            return V.verifyIntelPckChainX509(pckChainPem: str(a0?.get("pckChainPem")), trustAnchorRootCaSpkiSha256: a0?.get("trustAnchorRootCaSpkiSha256")?.asString, nowMs: ms(a0?.get("nowMs")))
        case "verifyGenuineTdxQuote":
            var pol: DcapQuotePolicy?
            if let p = a0?.get("policy"), p.isObject {
                pol = DcapQuotePolicy(mrtds: list(p.get("mrtds")), fmspcs: list(p.get("fmspcs")), rtmrs: list(p.get("rtmrs")), mrSeams: list(p.get("mrSeams")),
                                      mrSignerSeams: list(p.get("mrSignerSeams")), allowDebug: p.get("allowDebug") == .bool(true))
            }
            return V.verifyGenuineTdxQuote(quote: bytes(a0?.get("quote")), trustAnchorRootCaSpkiSha256: a0?.get("trustAnchorRootCaSpkiSha256")?.asString,
                                           expected: AttestVectorTests.binding(a0?.get("expected")), policy: pol, nowMs: ms(a0?.get("nowMs")))
        case "verifyCrl": return try V.verifyCrl(bytes(a0), issuerSpkiDer: bytes(a1?.get("spkiDer")), nowMs: ms(a2))
        case "serialIsRevoked": return .bool(V.serialIsRevoked(list(a0) ?? [], str(a1)))
        case "verifySignedJson": return try V.verifySignedJson(str(a0), name: str(a1), signerSpkiDer: bytes(a2?.get("spkiDer")))
        case "decodeIssuerChainHeader": return .string(try V.decodeIssuerChainHeader(str(a0)))
        case "verifyIntelTdxCollateral":
            let pol = a0?.get("policy")
            return V.verifyIntelTdxCollateral(quote: bytes(a0?.get("quote")), collateral: collateral(a0?.get("collateral")), nowMs: ms(a0?.get("nowMs")),
                                              acceptStatuses: list(pol?.get("acceptStatuses")), minTcbEvaluationDataNumber: IV.num(pol?.get("minTcbEvaluationDataNumber")),
                                              trustAnchorRootCaSpkiSha256: a0?.get("trustAnchorRootCaSpkiSha256")?.asString, allowDebug: a0?.get("allowDebug") == .bool(true))
        case "checkAzureRuntimeDataBinding":
            guard let exp = AttestVectorTests.binding(a2) else { throw JSError("expected binding missing") }
            return V.checkAzureRuntimeDataBinding(bytes(a0), bytes(a1), exp).map { JSONValue.string($0) } ?? JSONValue.null
        case "parseMaaJwt": return try V.parseMaaJwt(str(a0))
        case "parseGcpCsJwt": return try V.parseGcpCsJwt(str(a0))
        case "verifyX5cChain":
            // a chain that is not an array has no certificate (the reference reads its length as 0)
            return V.verifyX5cChain(a0?.asArray ?? [], rootCertsPem: list(a1?.get("rootCertsPem")) ?? [], rootSpkiSha256: list(a1?.get("rootSpkiSha256")) ?? [],
                                    nowMs: ms(a2?.get("nowMs")), clockSkewMs: IV.num(a2?.get("clockSkewMs")) ?? 0)
        case "verifyJwkX5cChain":
            return V.verifyJwkX5cChain(a0?.asArray ?? [], trustedKeySpki: list(a1?.get("trustedKeySpki")) ?? [], rootCertsPem: list(a1?.get("rootCertsPem")) ?? [],
                                       nowMs: ms(a2?.get("nowMs")), skewMs: IV.num(a2?.get("skewMs")) ?? 0).map { JSONValue.string($0) } ?? JSONValue.null
        case "teeTypeOfHwModel": return V.teeTypeOfHwModel(str(a0)).map { JSONValue.string($0) } ?? JSONValue.null
        case "fetchMaaJwks":
            return fetch(a0) { try V.fetchMaaJwks(issuer: str(a0?.get("issuer")), certsPath: a0?.get("opts")?.get("certsPath")?.asString, transport: $0) }
        case "fetchGcpConfidentialSpaceJwks":
            return fetch(a0) { try V.fetchGcpConfidentialSpaceJwks(issuer: str(a0?.get("issuer")), jwksUri: a0?.get("opts")?.get("jwksUri")?.asString, transport: $0) }
        default: throw JSError("unhandled fn \(c.fn)")
        }
    }

    // ---- comparison ----

    private static func eq(_ w: JSONValue, _ g: JSONValue) -> Bool {
        switch (w, g) {
        case let (.object(a), .object(b)):
            return Set(a.keys) == Set(b.keys) && a.allSatisfy { eq($0.value, b[$0.key]!) }
        case let (.array(a), .array(b)):
            return a.count == b.count && zip(a, b).allSatisfy { eq($0, $1) }
        case let (.string(s), _) where isLib(s):
            if case let .string(t) = g { return !t.isEmpty }
            return false
        default:
            return Base.canon(w) == Base.canon(g)
        }
    }

    /// nil when the native answer matches the reference, else the divergence.
    private static func diff(_ c: BaseCase, _ got: Result<JSONValue, Error>) -> String? {
        if let t = c.out.get("$throws")?.asString {
            guard case let .failure(e) = got else { return "\(c.name): want throw \(t), got a value" }
            let m = (e as? AttestationConfigError)?.message ?? (e as? JSError)?.message ?? "\(e)"
            if Base.isEngineCrash(t) { return nil }
            if isLib(t) { return m.isEmpty ? "\(c.name): empty refusal text" : nil }
            return m == t ? nil : "\(c.name): want throw \(t) got \(m)"
        }
        guard case let .success(g) = got else { return "\(c.name): want \(Base.canon(c.out).prefix(200)) got a throw \(got)" }
        if NOT_DER.contains(where: { c.name.contains($0) }), c.out.get("ok") == .bool(false) { return g.get("ok") == .bool(false) ? nil : "\(c.name): not refused" }
        // a refusal whose reason is library text: the rest compared exactly, the reason by presence
        if let o = c.out.asObject, let r = o["reason"]?.asString, isLib(r), let go = g.asObject {
            var w = o, x = go
            w["reason"] = nil
            guard case let .string(gr)? = x["reason"], !gr.isEmpty else { return "\(c.name): missing reason" }
            x["reason"] = nil
            return eq(.object(w), .object(x)) ? nil : "\(c.name): \(Base.firstDiff(.object(w), .object(x), "@"))"
        }
        return eq(c.out, g) ? nil : "\(c.name): \(Base.firstDiff(c.out, g, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(g).prefix(300))"
    }

    func testEveryCaseOfTheVendorCorpus() throws {
        let doc = K042.parse(String(decoding: try K042.bytes("ref-attest-vendors.json.gz"), as: UTF8.self))
        let blobs = doc.get("blobs")?.asObject ?? [:]
        var seen: [String: Int] = [:]
        var bad: [String] = []
        let cases = doc.get("cases")?.asArray ?? []
        for raw in cases {
            let c = BaseCase(fn: raw.get("fn")?.asString ?? "", name: raw.get("name")?.asString ?? "?", args: (raw.get("args")?.asArray ?? []).map { AttestVectorTests.hydrate($0, blobs) },
                             out: AttestVectorTests.hydrate(raw.get("out") ?? .null, blobs), suspect: false, raw: raw)
            seen[c.fn, default: 0] += 1
            let got: Result<JSONValue, Error>
            do { got = .success(try Self.call(c)) } catch { got = .failure(error) }
            if let d = Self.diff(c, got) { bad.append(d) }
        }
        XCTAssertEqual(cases.count, 758)
        XCTAssertEqual(doc.get("count"), .int(758))
        XCTAssertEqual(seen, Self.TOTALS)
        XCTAssert(bad.isEmpty, "\(bad.count)/758 divergent:\n" + bad.prefix(40).joined(separator: "\n"))
    }
}
