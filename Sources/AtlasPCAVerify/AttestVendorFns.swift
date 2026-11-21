import Foundation
import CryptoKit

// The per-function surface of the vendor attestation modules under the reference names: the Intel TDX / DCAP quote and report parsers, the PCK
// chain, the genuine-quote and collateral verifiers, CRL and signed-JSON checks, the Azure runtime-data binding, the MAA and Confidential Space
// token parsers, the x5c chain checks and the JWKS fetchers over an injected transport. Each is a thin layer over the verifier internals; results
// are JSON values in the reference's shape, and a binary member is `{"$bytes": <base64url>}`. A refusal that the reference throws is thrown as an
// `AttestationConfigError` carrying the reference's text.

/// The collateral of one Intel TDX quote (Intel PCS documents and CRLs); an empty member is a missing one.
public struct IntelTdxCollateral: Sendable {
    public var tcbInfoJson: String
    public var tcbInfoIssuerChainPem: String
    public var qeIdentityJson: String
    public var qeIdentityIssuerChainPem: String
    public var pckCrlDer: [UInt8]
    public var rootCrlDer: [UInt8]
    public init(tcbInfoJson: String = "", tcbInfoIssuerChainPem: String = "", qeIdentityJson: String = "", qeIdentityIssuerChainPem: String = "",
                pckCrlDer: [UInt8] = [], rootCrlDer: [UInt8] = []) {
        self.tcbInfoJson = tcbInfoJson
        self.tcbInfoIssuerChainPem = tcbInfoIssuerChainPem
        self.qeIdentityJson = qeIdentityJson
        self.qeIdentityIssuerChainPem = qeIdentityIssuerChainPem
        self.pckCrlDer = pckCrlDer
        self.rootCrlDer = rootCrlDer
    }
}

/// The allowlists of a genuine-quote check. A nil list is not given; an empty `mrtds` / `fmspcs` / `rtmrs` list is not gated; an EMPTY `mrSeams` /
/// `mrSignerSeams` list refuses every quote.
public struct DcapQuotePolicy: Sendable {
    public var mrtds: [String]?
    public var fmspcs: [String]?
    public var rtmrs: [String]?
    public var mrSeams: [String]?
    public var mrSignerSeams: [String]?
    public var allowDebug: Bool
    public init(mrtds: [String]? = nil, fmspcs: [String]? = nil, rtmrs: [String]? = nil, mrSeams: [String]? = nil, mrSignerSeams: [String]? = nil, allowDebug: Bool = false) {
        self.mrtds = mrtds
        self.fmspcs = fmspcs
        self.rtmrs = rtmrs
        self.mrSeams = mrSeams
        self.mrSignerSeams = mrSignerSeams
        self.allowDebug = allowDebug
    }
}

/// The JWKS fetch transport: the URL in, the HTTP status and the body bytes out (a throw is a transport failure).
public typealias AttestJwksTransport = (String) throws -> (status: Int, body: [UInt8])

extension AttestationVendors {
    private static func b(_ x: [UInt8]) -> JSONValue { .object(["$bytes": .string(Base64URLStrict.encode(x))]) }
    private static func strs(_ l: [String]) -> JSONValue { .array(l.map { .string($0) }) }
    private static func fail(_ m: String) -> AttestationConfigError { AttestationConfigError(message: m) }
    private static func wrap<T>(_ f: () throws -> T) throws -> T {
        do { return try f() } catch let e as AttestError { throw fail(e.message) }
    }
    private static func num(_ d: Double) -> JSONValue { d == d.rounded() && abs(d) < 9e15 ? .int(Int64(d)) : .double(d) }

    /// The suite and pin constants of the vendor modules.
    public static func constants() -> JSONValue {
        .object(["INTEL_DCAP_SUITE": .string(INTEL_DCAP_SUITE), "AZURE_MAA_SUITE": .string(AZURE_MAA_SUITE), "AZURE_MAA_SUITES": strs(AZURE_MAA_SUITES),
                 "GCP_CS_SUITE": .string(GCP_CS_SUITE), "GCP_CS_SUITES": strs(GCP_CS_SUITES), "GCP_CS_DEFAULT_ISSUER": .string(GCP_CS_DEFAULT_ISSUER),
                 "INTEL_SGX_ROOT_CA_SPKI_SHA256": .string(INTEL_SGX_ROOT_CA_SPKI_SHA256), "AMD_SNP_SUITE": .string(AMD_SNP_SUITE),
                 "AMD_ARK_SPKI_SHA384": .object(AMD_ARK_SPKI_SHA384.reduce(into: JObject()) { $0[JKey($1.key)] = .string($1.value) }),
                 "DEFAULT_ACCEPTED_STATUSES": strs(DEFAULT_ACCEPTED_STATUSES)])
    }

    /// Lowercase hex.
    public static func toHex(_ bytes: [UInt8]) -> String { ACrypto.hex(bytes) }

    /// The uncompressed SEC1 point of a P-256 public key (a compressed point is expanded); throws off the curve or on a wrong length.
    public static func ecdsaP256PublicKey(_ sec1: [UInt8]) throws -> JSONValue {
        if sec1.count == 65, sec1[0] == 4 {
            guard ACrypto.ecPointValid(curve: "P-256", point: sec1) else { throw fail("bad point: not on the P-256 curve") }
            return .object(["point": b(sec1)])
        }
        if sec1.count == 33, sec1[0] == 2 || sec1[0] == 3 {
            guard let k = try? P256.Signing.PublicKey(compressedRepresentation: Data(sec1)) else { throw fail("bad point: not on the P-256 curve") }
            return .object(["point": b(Array(k.x963Representation))])
        }
        throw fail("invalid Point, expected length 33 or 65, got \(sec1.count)")
    }

    private static func tdReport(_ body: [UInt8]) -> JSONValue {
        func s(_ a: Int, _ z: Int) -> JSONValue { b(Array(body[a..<z])) }
        return .object(["teeTcbSvn": s(0, 16), "mrSeam": s(16, 64), "mrSignerSeam": s(64, 112), "tdAttributes": s(120, 128), "mrTd": s(136, 184), "mrConfigId": s(184, 232),
                        "rtmr0": s(328, 376), "rtmr1": s(376, 424), "rtmr2": s(424, 472), "rtmr3": s(472, 520), "reportData": s(520, 584), "raw": s(0, 584)])
    }

    /// The fields of a TD report body (584 bytes or more); throws under 584.
    public static func parseDcapTdReport(_ body: [UInt8]) throws -> JSONValue {
        if body.count < 584 { throw fail("parseDcapTdReport: body too short (\(body.count) < 584)") }
        return tdReport(body)
    }

    /// A DCAP v4 / ECDSA-P256 / TDX quote split into its parts; throws on every structural violation.
    public static func parseDcapQuote(_ quote: [UInt8]) throws -> JSONValue {
        let q = try wrap { try DcapVerifier.parseQuote(quote) }
        return .object(["version": .int(Int64(DcapVerifier.le(quote, 0, 2))), "attKeyType": .int(Int64(DcapVerifier.le(quote, 2, 2))), "teeType": .int(Int64(DcapVerifier.le(quote, 4, 4))),
                        "header": b(q.header), "tdReportBody": b(q.tdReportBody), "quoteSignature": b(q.quoteSignature), "akPubRaw": b(q.akPubRaw), "qeReportBody": b(q.qeReportBody),
                        "qeReportSignature": b(q.qeReportSignature), "qeAuthData": b(q.qeAuthData), "pckChainPem": .string(q.pckChainPem)])
    }

    private static func pckTcb(_ t: DcapVerifier.PckTcb) -> JSONValue {
        .object(["fmspc": b(t.fmspc), "sgxTcbComponents": b(t.sgx), "pcesvn": .int(Int64(t.pcesvn)), "cpusvn": b(t.cpusvn)])
    }

    /// The FMSPC and the issued TCB of a PCK leaf, read from its Intel SGX extension; throws on a missing or malformed extension.
    public static func extractPckFmspcAndTcb(_ leafDer: [UInt8]) throws -> JSONValue {
        pckTcb(try wrap { try DcapVerifier.extractPckFmspcAndTcb(leafDer) })
    }

    /// The embedded PCK chain to the pinned Intel SGX Root CA at `nowMs`: `{ok, reason?, leafKey?: {point}, leafDer?, depth?, failure?}`.
    public static func verifyIntelPckChainX509(pckChainPem: String, trustAnchorRootCaSpkiSha256: String? = nil, nowMs: Int64) -> JSONValue {
        let r = DcapVerifier.verifyPckChain(pckChainPem, (trustAnchorRootCaSpkiSha256 ?? INTEL_SGX_ROOT_CA_SPKI_SHA256).lowercased(), nowMs)
        guard r.ok, let leaf = r.leaf, let point = r.leafPoint else {
            var o: JObject = ["ok": .bool(false), "reason": .string(r.reason)]
            if r.validity { o["failure"] = .string("validity") }
            return .object(o)
        }
        return .object(["ok": .bool(true), "leafKey": .object(["point": b(point)]), "leafDer": b(leaf.raw), "depth": .int(Int64(r.depth))])
    }

    /// A genuine DCAP v4 TDX quote end to end, offline: `{ok, reason?, report?, fmspc?, pckTcb?, akPub?: {point}, chainDepth?, measured?}`.
    public static func verifyGenuineTdxQuote(quote: [UInt8], trustAnchorRootCaSpkiSha256: String? = nil, expected: AttestationBinding? = nil, policy: DcapQuotePolicy? = nil, nowMs: Int64) -> JSONValue {
        var qp: DcapVerifier.QuotePolicy?
        if let p = policy {
            var x = DcapVerifier.QuotePolicy()
            x.mrtds = Attest.lowerAll(p.mrtds ?? [])
            x.fmspcs = Attest.lowerAll(p.fmspcs ?? [])
            x.rtmrs = Attest.lowerAll(p.rtmrs ?? [])
            x.mrSeams = Attest.lowerAll(p.mrSeams ?? [])
            x.mrSignerSeams = Attest.lowerAll(p.mrSignerSeams ?? [])
            x.hasMrSeams = p.mrSeams != nil
            x.hasMrSigner = p.mrSignerSeams != nil
            x.allowDebug = p.allowDebug
            qp = x
        }
        let r = DcapVerifier.verifyGenuineQuote(quote, (trustAnchorRootCaSpkiSha256 ?? INTEL_SGX_ROOT_CA_SPKI_SHA256).lowercased(), nowMs, qp, false, expected: expected)
        guard r.ok, let tcb = r.pck, let parsed = try? DcapVerifier.parseQuote(quote) else { return .object(["ok": .bool(false), "reason": .string(r.reason)]) }
        return .object(["ok": .bool(true), "report": tdReport(parsed.tdReportBody), "fmspc": .string(r.fmspc), "pckTcb": pckTcb(tcb), "akPub": .object(["point": b([0x04] + r.akPubRaw)]),
                        "chainDepth": .int(Int64(r.chainDepth)), "measured": .object(Attest.newMeasured(ACrypto.hex(r.mrTd), ""))])
    }

    /// A CRL (DER) under the issuer key (a DER SubjectPublicKeyInfo) at `nowMs`: `{ok, revoked}` (sorted lowercase hex serials, no leading zeros) or `{ok: false, reason}`.
    public static func verifyCrl(_ crlDer: [UInt8], issuerSpkiDer: [UInt8], nowMs: Int64) throws -> JSONValue {
        let key = try wrap { try Cert.keyOfSPKI(issuerSpkiDer) }
        let (revoked, why) = IntelCollateral.verifyCRL(crlDer, key, nowMs)
        guard let rev = revoked else { return .object(["ok": .bool(false), "reason": .string(why)]) }
        return .object(["ok": .bool(true), "revoked": strs(rev.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) })])
    }

    /// Whether a certificate serial (case and leading zeros ignored) is in the revoked list a `verifyCrl` result carries.
    public static func serialIsRevoked(_ revoked: [String], _ serialHex: String) -> Bool {
        Set(revoked).contains(IntelCollateral.normSerial(serialHex))
    }

    /// An Intel PCS document `{"<name>": {...}, "signature": "<128 hex>"}` checked under the signer key: `{body}` or `{error}`.
    public static func verifySignedJson(_ text: String, name: String, signerSpkiDer: [UInt8]) throws -> JSONValue {
        let key = try wrap { try Cert.keyOfSPKI(signerSpkiDer) }
        let (body, why) = IntelCollateral.verifySignedJSON(text, name, key)
        guard let o = body else { return .object(["error": .string(why)]) }
        return .object(["body": .object(o)])
    }

    /// `decodeURIComponent`: a malformed %-escape or a byte sequence that is not UTF-8 is `URI malformed`.
    public static func decodeIssuerChainHeader(_ value: String) throws -> String {
        let src = Array(value.utf8)
        var out: [UInt8] = []
        var i = 0
        func hexv(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x41...0x46: return c - 0x41 + 10
            case 0x61...0x66: return c - 0x61 + 10
            default: return nil
            }
        }
        while i < src.count {
            if src[i] == 0x25 {
                guard i + 2 < src.count, let h = hexv(src[i + 1]), let l = hexv(src[i + 2]) else { throw fail("URI malformed") }
                out.append(h << 4 | l)
                i += 3
            } else {
                out.append(src[i])
                i += 1
            }
        }
        guard let s = String(bytes: out, encoding: .utf8) else { throw fail("URI malformed") }
        return s
    }

    /// The quote, then its Intel PCS collateral at `nowMs`: the evaluated TCB status and the policy decision. The evaluation fields are present whenever it completed.
    public static func verifyIntelTdxCollateral(quote: [UInt8], collateral: IntelTdxCollateral?, nowMs: Int64, acceptStatuses: [String]? = nil, minTcbEvaluationDataNumber: Double? = nil,
                                                trustAnchorRootCaSpkiSha256: String? = nil, allowDebug: Bool = false) -> JSONValue {
        var cp = CollateralPolicy()
        if let a = acceptStatuses {
            cp.acceptStatuses = a
            cp.hasAccept = true
        }
        if let m = minTcbEvaluationDataNumber {
            cp.minEval = m
            cp.hasMinEval = true
        }
        var c: IntelCollateral?
        if let x = collateral {
            c = IntelCollateral(tcbInfoJSON: x.tcbInfoJson, tcbInfoChain: x.tcbInfoIssuerChainPem, qeIdentityJSON: x.qeIdentityJson, qeIdentityChain: x.qeIdentityIssuerChainPem)
            c?.pckCrl = x.pckCrlDer
            c?.rootCrl = x.rootCrlDer
        }
        let r = IntelCollateral.verify(quote, c, nowMs, cp, (trustAnchorRootCaSpkiSha256 ?? INTEL_SGX_ROOT_CA_SPKI_SHA256).lowercased(), allowDebug)
        if !r.evaluated { return .object(["ok": .bool(false), "reason": .string(r.reason)]) }
        var o: JObject = ["ok": .bool(r.ok), "status": .string(r.status), "platformStatus": .string(r.platformStatus), "tdxModuleStatus": .string(r.tdxModuleStatus),
                          "qeStatus": .string(r.qeStatus), "advisoryIds": strs(r.advisoryIDs), "tcbEvaluationDataNumber": num(r.evaluationDataNumber), "fmspc": .string(r.fmspc)]
        if !r.ok { o["reason"] = .string(r.reason) }
        return .object(o)
    }

    /// The Azure runtime-data binding of a quote's report data: the failure reason, nil when the quote binds.
    public static func checkAzureRuntimeDataBinding(_ reportData: [UInt8], _ runtimeData: [UInt8], _ expected: AttestationBinding) -> String? {
        let why = Attest.checkAzureRuntimeDataBinding(reportData, runtimeData, expected)
        return why.isEmpty ? nil : why
    }

    private static func jwt(_ token: String, _ name: String) throws -> JSONValue {
        let t = try wrap { try JWS.parse(token, name) }
        var h: JObject = ["alg": .string(t.alg)]
        if t.hasKid { h["kid"] = .string(t.kid) }
        if t.hasJku { h["jku"] = .string(t.jku) }
        if t.hasX5c { h["x5c"] = strs(t.x5c) }
        if t.hasTyp { h["typ"] = .string(t.typ) }
        return .object(["header": .object(h), "payload": .object(t.payload), "signingInput": b(t.signingInput), "signature": b(t.signature)])
    }

    /// An Azure MAA token split into header, payload, signing input and signature (nothing is verified); throws on a structural violation.
    public static func parseMaaJwt(_ token: String) throws -> JSONValue { try jwt(token, "parseMaaJwt") }

    /// A Confidential Space token split the same way.
    public static func parseGcpCsJwt(_ token: String) throws -> JSONValue { try jwt(token, "parseGcpCsJwt") }

    /// An MAA `x5c` chain (base64 DER, leaf first) to a configured anchor: `{ok, reason?, leafDer?, leafSpkiSha256?}`.
    public static func verifyX5cChain(_ x5c: [JSONValue], rootCertsPem: [String] = [], rootSpkiSha256: [String] = [], nowMs: Int64, clockSkewMs: Double = 0) -> JSONValue {
        let (leaf, why) = MaaVerifier.verifyX5cChain(x5c, rootCertsPem: rootCertsPem, rootSpki: rootSpkiSha256, nowMs, max(0, clockSkewMs))
        guard let c = leaf else { return .object(["ok": .bool(false), "reason": .string(why)]) }
        let spki = (try? Cert.keyOf(c))?.spkiSHA256 ?? ""
        return .object(["ok": .bool(true), "leafDer": b(c.raw), "leafSpkiSha256": .string(spki)])
    }

    /// A Confidential Space JWK `x5c` chain to a trusted key pin or root: the failure reason, nil when it anchors.
    public static func verifyJwkX5cChain(_ x5c: [JSONValue], trustedKeySpki: [String] = [], rootCertsPem: [String] = [], nowMs: Int64, skewMs: Double = 0) -> String? {
        let why = GcpVerifier.verifyJwkX5cChain(x5c, spkiPins: Set(trustedKeySpki.map { $0.lowercased() }), rootCertsPem: rootCertsPem, nowMs, max(0, skewMs))
        return why.isEmpty ? nil : why
    }

    // ---- JWKS fetchers ----

    private static func get(_ transport: AttestJwksTransport, _ url: String, _ what: String) throws -> JSONValue {
        let r = try transport(url)
        guard r.status >= 200 && r.status < 300 else { throw fail("\(what) failed: HTTP \(r.status) for \(url)") }
        if let v = Attest.jsonLenient(r.body) { return v }
        let m = V8JSON.error(String(decoding: r.body, as: UTF8.self))
        throw fail(m.isEmpty ? "invalid JSON" : m)
    }

    private static func keySet(_ body: JSONValue, _ members: [String], _ what: String) throws -> JSONValue {
        guard case let .object(o) = body, case let .array(keys)? = o["keys"] else { throw fail("\(what): response has no keys array") }
        var out: [JSONValue] = []
        for k in keys {
            guard case let .object(ko) = k else { continue }
            var e = JObject()
            for m in members {
                if m == "x5c" {
                    if let l = Attest.asStrList(ko["x5c"]) { e["x5c"] = strs(l) }
                } else if let s = ko[JKey(m)]?.asString { e[JKey(m)] = .string(s) }
            }
            out.append(.object(e))
        }
        return .object(["keys": .array(out)])
    }

    private static func trimSlashes(_ s: String) -> String {
        var t = Substring(s)
        while t.hasSuffix("/") { t = t.dropLast() }
        return String(t)
    }

    /// The MAA signing keys from `<issuer><certsPath>` (default `/certs`): kid, kty, alg and x5c of each key object.
    public static func fetchMaaJwks(issuer: String, certsPath: String? = nil, transport: AttestJwksTransport) throws -> JSONValue {
        let url = trimSlashes(issuer) + ((certsPath?.isEmpty ?? true) ? "/certs" : certsPath!)
        return try keySet(try get(transport, url, "MAA JWKS fetch"), ["kid", "kty", "alg", "x5c"], "MAA JWKS fetch")
    }

    /// The Confidential Space signing keys: from `jwksUri`, else the `jwks_uri` of the issuer's OpenID configuration.
    public static func fetchGcpConfidentialSpaceJwks(issuer: String, jwksUri: String? = nil, transport: AttestJwksTransport) throws -> JSONValue {
        var uri = jwksUri ?? ""
        if uri.isEmpty {
            let conf = try get(transport, trimSlashes(issuer) + "/.well-known/openid-configuration", "Confidential Space OpenID config fetch")
            guard let u = conf.get("jwks_uri")?.asString, !u.isEmpty else { throw fail("Confidential Space OpenID config carries no jwks_uri") }
            uri = u
        }
        return try keySet(try get(transport, uri, "Confidential Space JWKS fetch"), ["kid", "kty", "alg", "use", "n", "e", "crv", "x", "y", "x5c"], "Confidential Space JWKS fetch")
    }
}
