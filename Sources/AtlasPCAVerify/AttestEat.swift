import Foundation
import CryptoKit

// Entity Attestation Token (RFC 9711) freshness, channel binding and RATS appraisal, mirroring the reference
// (@atlasauth/pca-attest-eat): EAT build / verify as a compact JWS (`eat+jwt`, EdDSA or ES256), the anti-replay freshness gate, the
// RA-TLS channel binding, the RATS appraisal (reference values + endorsements -> a trust tier) and the version-tolerant SEV-SNP
// report parse. The AMD hardware root is AttestEatAmd.swift, the post-quantum co-signature AttestEatPq.swift, the admission
// evidence and the artifact discharge AttestEatAdmission.swift.
//
// Values are `JSONValue`s with the JavaScript semantics of the reference where it reads dynamic input (a property of an absent or
// null value is a refusal, a member of a primitive is absent, `x ?? y` treats absent and null alike). Total on hostile input: every
// refusal is a thrown `JSError` or a `{ok: false, reason}` result, never a trap. Binary values inside an options object are the JSON
// form `{"$bytes": "<base64url>"}`.
//
// Deliberately stricter than the reference: a present `clockSkewMs` that is not a finite number is refused (an unbounded skew would
// disable the age window); a `dbgstat` outside the RFC 9711 values is an unknown debug status (a debug requirement fails closed);
// an admission `minTier` other than `affirming` / `affirming-hw-rooted` is refused.

/// JavaScript value semantics shared by the attest-eat files.
enum EatJS {
    static func typeError(_ m: String) -> JSError { JSError(m, code: "TypeError") }

    /// `v.k` as the reference reads it: undefined / null throw a TypeError, an object yields its member, anything else has none.
    static func prop(_ v: JSONValue?, _ k: String) throws -> JSONValue? {
        guard let x = v else { throw typeError("Cannot read properties of undefined (reading '\(k)')") }
        switch x {
        case .null: throw typeError("Cannot read properties of null (reading '\(k)')")
        case let .object(o): return o[JKey(k)]
        default: return nil
        }
    }

    /// `v?.k`: absent for undefined / null.
    static func opt(_ v: JSONValue?, _ k: String) -> JSONValue? {
        if case let .object(o)? = v { return o[JKey(k)] }
        return nil
    }

    static func isRecord(_ v: JSONValue?) -> Bool {
        if case .object? = v { return true }
        return false
    }

    static func string(_ v: JSONValue?) -> String? {
        if case let .string(s)? = v { return s }
        return nil
    }

    /// `typeof v === 'number' && Number.isFinite(v)`.
    static func finite(_ v: JSONValue?) -> Double? {
        guard let d = IV.num(v), d.isFinite else { return nil }
        return d
    }

    /// A JS number as a JSON number (integral values are ints).
    static func jn(_ d: Double) -> JSONValue {
        if d.isFinite, d == d.rounded(), abs(d) <= 9_007_199_254_740_991 { return .int(Int64(d)) }
        return .double(d)
    }

    /// Test seam: the clock every default `now` reads, in epoch ms (a replay of a corpus made under a frozen clock sets it for the cases that depend on it).
    nonisolated(unsafe) static var clockOverrideMs: Double?

    static func clockMs() -> Double { clockOverrideMs ?? (Date().timeIntervalSince1970 * 1000).rounded(.down) }

    /// Equality of two strings by their UTF-8 bytes.
    static func utf8Eq(_ a: String, _ b: String) -> Bool { Array(a.utf8) == Array(b.utf8) }

    /// SameValueZero over JSON values (objects and arrays are never the same reference).
    static func svz(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case (.null?, .null?): return true
        case let (.bool(x)?, .bool(y)?): return x == y
        case let (.string(x)?, .string(y)?): return x.unicodeScalars.elementsEqual(y.unicodeScalars)
        default:
            if let x = IV.num(a), let y = IV.num(b) { return x == y }
            return false
        }
    }

    static func strContains(_ list: [String], _ s: String) -> Bool { list.contains { $0.unicodeScalars.elementsEqual(s.unicodeScalars) } }

    /// `{"$bytes": b64url}` -> the bytes.
    static func bytesOf(_ v: JSONValue?) -> [UInt8]? {
        guard case let .object(o)? = v, o.count == 1, case let .string(s)? = o[JKey("$bytes")] else { return nil }
        return Base64URLStrict.decode(s)
    }

    /// The exact integer of a finite non-negative whole double.
    static func bigFromDouble(_ d: Double) -> BigUInt {
        if d < 18_446_744_073_709_551_616.0 { return BigUInt(UInt64(d)) }
        let m = d.significandBitPattern | (UInt64(1) << 52)
        return BigUInt(m) << (Int(d.exponent) - 52)
    }
}

public enum PCAAttestEat {
    // ---- constants ----
    public static let EAT_TYP = "eat+jwt"
    public static let DEFAULT_EAT_ALG = "EdDSA"
    public static let DEFAULT_MAX_AGE_MS: Double = 300_000
    public static let CHANNEL_BINDING_DOMAIN = "atlas-pca/eat-channel/v1"
    public static let AMD_SEV_SNP_SIGNED_REGION_END = 0x2a0
    public static let AMD_SEV_SNP_HARDWARE_ROOT_LABEL = "amd-sev-snp/ecdsa-p384 (VCEK\u{2192}ASK\u{2192}ARK; classical hardware root, not post-quantum)"
    public static let KNOWN_REPORT_VERSIONS: [Int] = [2, 3, 5]
    public static let KNOWN_AMD_ARK_SPKI_SHA384: [String: String] = AmdVerifier.ARK_SPKI_SHA384
    public static let AMD_MILAN_ARK_SPKI_SHA384: String = AmdVerifier.ARK_SPKI_SHA384["milan"] ?? ""
    static let SUPPORTED_ALGS = ["EdDSA", "ES256"]
    static let DBGSTAT_VALUES = ["enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently"]
    static let FULL_REPORT_MIN_LEN = 0x2e8 + 72

    /// Member order of the JSON the reference writes (a parsed object has none): claim names first, then the nested members.
    static let CLAIM_ORDER = ["iss", "iat", "eat_nonce", "cnf", "ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp",
                              "tls_exporter", "jkt", "type", "value",
                              "model_id", "weights_digest", "weights_measured", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest",
                              "version", "measurement", "reported_tcb", "guest_svn", "chip_id", "debug", "degraded",
                              "bootloader", "tee", "snp", "microcode"]

    // ---- nonce ----

    /// A fresh single-use challenge: random bytes (at least 16) and the issue time in base 36 (whole milliseconds).
    public static func issueNonce(now: Double? = nil, bytes: Int = 32) -> (value: String, issuedAt: Double) {
        var t = EatJS.clockMs()
        if let n = now, n.isFinite { t = n }
        let n = max(16, bytes)
        var r = [UInt8](repeating: 0, count: n)
        for i in 0..<n { r[i] = UInt8.random(in: 0...255) }
        let whole = Int64(max(0, min(t, 9_007_199_254_740_991)))
        return (Base64URLStrict.encode(r) + "." + String(whole, radix: 36), t)
    }

    // ---- channel binding ----

    /// `cnf.tls_exporter` for a channel id: base64url(sha256(domain || channelId)); `jkt` is the optional holder-key thumbprint.
    public static func deriveChannelCnf(_ channelId: JSONValue?, _ holderKeyThumbprint: JSONValue? = nil) throws -> JSONValue {
        guard let id = EatJS.string(channelId), !id.isEmpty else { throw JSError("deriveChannelCnf: channelId is required") }
        let h = Canonical.sha256(Array(CHANNEL_BINDING_DOMAIN.utf8) + Array(id.utf8))
        var o: JObject = ["tls_exporter": .string(Base64URLStrict.encode(h))]
        if let t = EatJS.string(holderKeyThumbprint), !t.isEmpty { o["jkt"] = .string(t) }
        return .object(o)
    }

    /// Evidence bound to a channel id and a per-session nonce.
    public static func bindChannel(_ evidence: JSONValue?, _ channelId: JSONValue?, _ nonce: JSONValue?) throws -> JSONValue {
        guard let n = EatJS.string(nonce), !n.isEmpty else { throw JSError("bindChannel: a per-session nonce is required for freshness") }
        let cnf = try deriveChannelCnf(channelId)
        var o: JObject = ["nonce": .string(n), "cnf": cnf]
        if let e = evidence { o["evidence"] = e }
        return .object(o)
    }

    // ---- build ----

    /// A signed EAT. `sign(alg, signingInput)` signs the JWS signing input under the attester key for `alg` (`EdDSA`: the 64-byte
    /// Ed25519 signature, `ES256`: the raw r || s); it throws when the key does not fit the algorithm. Refuses an unbound token.
    public static func buildEAT(_ args: JSONValue?, sign: (_ alg: String, _ input: [UInt8]) throws -> [UInt8]) throws -> String {
        let issuerV = try EatJS.prop(args, "issuer")
        guard let issuer = EatJS.string(issuerV), !issuer.isEmpty else { throw JSError("buildEAT: issuer is required") }
        let nonceV = try EatJS.prop(args, "nonce")
        guard let nonce = EatJS.string(nonceV), !nonce.isEmpty else { throw JSError("buildEAT: nonce (eat_nonce) is required for freshness") }
        let algV = JS.present(try EatJS.prop(args, "alg"))
        var alg = DEFAULT_EAT_ALG
        if let a = algV {
            guard let s = EatJS.string(a), SUPPORTED_ALGS.contains(s) else { throw JSError("buildEAT: unsupported alg '\(JS.toString(a))'") }
            alg = s
        }
        // resolveCnf: a channel id derives the exporter; an explicit binding overrides it member by member
        var cnf: JObject = [:]
        if let cid = try EatJS.prop(args, "channelId") {
            let d = try deriveChannelCnf(cid)
            if let te = d.get("tls_exporter") { cnf["tls_exporter"] = te }
        }
        if let cb = try EatJS.prop(args, "channelBinding") {
            if let te = EatJS.string(try EatJS.prop(cb, "tls_exporter")) { cnf["tls_exporter"] = .string(te) }
            if let jk = EatJS.string(try EatJS.prop(cb, "jkt")) { cnf["jkt"] = .string(jk) }
        }
        if cnf["tls_exporter"] == nil && cnf["jkt"] == nil {
            throw JSError("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) \u{2014} refusing to emit unbound evidence")
        }
        var iatMs = EatJS.clockMs()
        if let n = EatJS.finite(try EatJS.prop(args, "now")) { iatMs = n }
        var claims: JObject = ["iss": .string(issuer), "iat": EatJS.jn((iatMs / 1000).rounded(.down)), "eat_nonce": .string(nonce), "cnf": .object(cnf)]
        for k in ["ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp"] {
            if let v = try EatJS.prop(args, k) { claims[JKey(k)] = v }
        }
        let header: JSONValue = .object(["alg": .string(alg), "typ": .string(EAT_TYP)])
        return try Jose.sign(header: header, headerOrder: ["alg", "typ"], payload: .object(claims), payloadOrder: CLAIM_ORDER, signer: { input in try sign(alg, input) })
    }

    // ---- verify ----

    /// RFC 7515 4.1.9: media types compare case-insensitively and a `typ` without a `/` is the `application/` form.
    static func normalizeTyp(_ typ: String) -> String {
        let t = typ.lowercased()
        return t.contains("/") ? t : "application/" + t
    }

    static func parseCnf(_ v: JSONValue?) -> JSONValue? {
        guard case let .object(o)? = v else { return nil }
        var out: JObject = [:]
        if let s = o["tls_exporter"], case .string = s { out["tls_exporter"] = s }
        if let s = o["jkt"], case .string = s { out["jkt"] = s }
        return out.isEmpty ? nil : .object(out)
    }

    static func parseMeasurements(_ v: JSONValue?) -> JSONValue? {
        guard case let .array(a)? = v else { return nil }
        var out: [JSONValue] = []
        for e in a {
            if case let .object(o) = e, let t = o["type"], case .string = t, let x = o["value"], case .string = x { out.append(.object(["type": t, "value": x])) }
        }
        return out.isEmpty ? nil : .array(out)
    }

    static func parseTcbVersion(_ v: JSONValue?) -> JSONValue? {
        guard let x = v else { return nil }
        switch x {
        case .int, .string: return x
        case let .double(d): return d.isFinite ? x : nil
        case let .object(o):
            var out: JObject = [:]
            for k in ["bootloader", "tee", "snp", "microcode"] { if let n = o[JKey(k)], n.isNumber { out[JKey(k)] = n } }
            return .object(out)
        default: return nil
        }
    }

    static func parseMeasured(_ v: JSONValue?) -> JSONValue? {
        guard case let .object(o)? = v else { return nil }
        var out: JObject = [:]
        for k in ["model_id", "weights_digest", "runtime_measurement", "operator"] {
            guard let s = o[JKey(k)], case .string = s else { return nil }
            out[JKey(k)] = s
        }
        if let b = o["weights_measured"], case .bool = b { out["weights_measured"] = b }
        for k in ["system_prompt_digest", "tool_manifest_digest"] { if let s = o[JKey(k)], case .string = s { out[JKey(k)] = s } }
        return .object(out)
    }

    static func parseSevSnp(_ v: JSONValue?) -> JSONValue? {
        guard case let .object(o)? = v, let ver = o["version"], ver.isNumber, let m = o["measurement"], case .string = m else { return nil }
        var out: JObject = ["version": ver, "measurement": m]
        if let t = parseTcbVersion(o["reported_tcb"]) { out["reported_tcb"] = t }
        if let g = o["guest_svn"], g.isNumber { out["guest_svn"] = g }
        if let c = o["chip_id"], case .string = c { out["chip_id"] = c }
        if let d = o["debug"], case .bool = d { out["debug"] = d }
        if let d = o["degraded"], case .bool = d { out["degraded"] = d }
        return .object(out)
    }

    /// Verify an EAT's signature, `typ`, `alg` and `iss` and parse its claims. A claim of the wrong type is dropped so every later
    /// gate fails closed. Authenticity only: freshness, channel binding and appraisal are separate gates.
    public static func verifyEAT(_ eat: JSONValue?, key: Jose.Key, _ opts: JSONValue? = nil) throws -> JSONValue {
        guard case .string? = eat else { throw JSError("EAT invalid: token is not a string") }
        let gate: Jose.CanonicalJws
        do { gate = try Jose.assertCanonicalCompactJws(eat, maxBytes: 1 << 20) } catch let e as JSError { throw JSError("EAT invalid: \(e.message)") }
        let o: JSONValue = opts ?? .object([:])
        guard let alg = EatJS.string(gate.header["alg"]), SUPPORTED_ALGS.contains(alg) else { throw JSError("EAT invalid: missing or unsupported `alg` header") }
        if let algs = JS.present(try EatJS.prop(o, "algorithms")) {
            var allowed = false
            switch algs {
            case let .array(a): allowed = a.contains { EatJS.string($0) == alg }
            case let .string(s): allowed = s.contains(alg)
            default: throw EatJS.typeError("allowed.includes is not a function")
            }
            if !allowed { throw JSError("EAT invalid: alg \(alg) not in the allowed set") }
        }
        let requireTyp = try EatJS.prop(o, "requireTyp")
        if requireTyp != JSONValue.bool(false) {
            let typV = try EatJS.prop(o, "typ")
            let want: JSONValue = JS.present(typV) ?? JSONValue.string(EAT_TYP)
            guard let ht = EatJS.string(gate.header["typ"]) else { throw JSError("EAT invalid: typ \(JS.toString(gate.header["typ"])) is not \(JS.toString(want))") }
            guard let ws = EatJS.string(want) else { throw EatJS.typeError("typ.toLowerCase is not a function") }
            if normalizeTyp(ht) != normalizeTyp(ws) { throw JSError("EAT invalid: typ \(ht) is not \(ws)") }
        }
        let sig = try Jose.decodeCanonicalBase64url(gate.segments[2])
        let input = Array((gate.segments[0] + "." + gate.segments[1]).utf8)
        if !Jose.verifySignature(alg: alg, key: key, input: input, sig: sig) { throw JSError("EAT invalid: signature does not verify") }
        guard let payload = gate.payload else { throw JSError("EAT invalid: payload is not an object") }
        guard let iss = EatJS.string(payload["iss"]) else { throw JSError("EAT invalid: missing or non-string `iss`") }
        guard let iatV = payload["iat"], EatJS.finite(iatV) != nil else { throw JSError("EAT invalid: missing or non-numeric `iat`") }
        if let want = try EatJS.prop(o, "issuer") {
            var ok = false
            if case let .array(a) = want { ok = a.contains { EatJS.string($0).map { IV.same($0, iss) } ?? false } } else if case let .string(s) = want { ok = IV.same(s, iss) }
            if !ok { throw JSError("EAT invalid: iss \(iss) is not an accepted issuer") }
        }
        var claims: JObject = ["iss": .string(iss), "iat": iatV]
        if let n = payload["eat_nonce"], case .string = n { claims["eat_nonce"] = n }
        if let c = parseCnf(payload["cnf"]) { claims["cnf"] = c }
        if let u = payload["ueid"], case .string = u { claims["ueid"] = u }
        if let u = payload["sueid"], case .string = u { claims["sueid"] = u }
        if let m = parseMeasurements(payload["measurements"]) { claims["measurements"] = m }
        if let d = payload["dbgstat"], let s = EatJS.string(d), DBGSTAT_VALUES.contains(s) { claims["dbgstat"] = d }
        if let u = payload["oemid"], case .string = u { claims["oemid"] = u }
        if let m = parseMeasured(payload["measured"]) { claims["measured"] = m }
        if let s = parseSevSnp(payload["sevsnp"]) { claims["sevsnp"] = s }
        return .object(claims)
    }

    // ---- freshness + channel binding ----

    static func ok() -> JSONValue { .object(["ok": .bool(true)]) }
    static func no(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    /// Anti-replay freshness: the token's `eat_nonce` must equal the server-issued challenge and its `iat` must lie in
    /// `[now - maxAgeMs, now]` (widened by `clockSkewMs`). A present skew that is not a finite number is refused.
    public static func verifyFreshness(_ eat: JSONValue?, _ opts: JSONValue?) throws -> JSONValue {
        let nowV = try EatJS.prop(opts, "now")
        let now = EatJS.finite(nowV) ?? EatJS.clockMs()
        var skew = 0.0
        if let s = try EatJS.prop(opts, "clockSkewMs") {
            guard let d = EatJS.finite(s) else { return no("invalid clockSkewMs (must be a finite number)") }
            skew = max(0, d)
        }
        guard let expected = EatJS.string(try EatJS.prop(opts, "expectedNonce")), !expected.isEmpty else { return no("no expected (server-issued) nonce supplied (fail closed)") }
        guard let nonce = EatJS.string(try EatJS.prop(eat, "eat_nonce")), !nonce.isEmpty else { return no("EAT carries no eat_nonce \u{2014} cannot establish freshness (replayable)") }
        if !EatJS.utf8Eq(nonce, expected) { return no("eat_nonce does not match the server-issued challenge (replayed or relayed evidence)") }
        guard let iat = EatJS.finite(try EatJS.prop(eat, "iat")) else { return no("EAT has no valid iat (cannot establish age)") }
        guard let maxAge = EatJS.finite(try EatJS.prop(opts, "maxAgeMs")), maxAge > 0 else { return no("invalid maxAgeMs") }
        let iatMs = iat * 1000
        if !(iatMs - skew <= now) { return no("EAT iat is in the future") }
        if !(now - iatMs <= maxAge + skew) { return no("EAT is stale (iat older than maxAgeMs) \u{2014} expired/replayed attestation") }
        return ok()
    }

    /// RA-TLS channel binding: every field of the expected cnf (derived from `channelId`, and/or an explicit `expectedCnf`) must be
    /// present and equal in the token's `cnf`.
    public static func verifyChannelBinding(_ eat: JSONValue?, _ opts: JSONValue?) throws -> JSONValue {
        var expTls: String? = nil
        var expJkt: String? = nil
        if let c = EatJS.string(try EatJS.prop(opts, "channelId")), !c.isEmpty {
            expTls = EatJS.string(try deriveChannelCnf(JSONValue.string(c)).get("tls_exporter"))
        }
        if let ec = try EatJS.prop(opts, "expectedCnf") {
            if let t = EatJS.string(try EatJS.prop(ec, "tls_exporter")) { expTls = t }
            if let j = EatJS.string(try EatJS.prop(ec, "jkt")) { expJkt = j }
        }
        if expTls == nil && expJkt == nil { return no("no expected channel binding supplied (fail closed)") }
        let cnf = try EatJS.prop(eat, "cnf")
        let cTls = EatJS.opt(cnf, "tls_exporter")
        let cJkt = EatJS.opt(cnf, "jkt")
        if !JS.truthy(cnf) || (cTls == nil && cJkt == nil) {
            return no("EAT carries no channel/key binding (cnf) \u{2014} evidence is not bound to a live channel (RA-TLS)")
        }
        func same(_ got: JSONValue?, _ want: String) throws -> Bool {
            guard case let .string(g)? = got else { throw EatJS.typeError("The first argument must be of type string") }
            return EatJS.utf8Eq(g, want)
        }
        if let t = expTls {
            let mismatch = try cTls == nil || !same(cTls, t)
            if mismatch { return no("TLS-exporter channel binding mismatch (evidence lifted to another channel?)") }
        }
        if let j = expJkt {
            let mismatch = try cJkt == nil || !same(cJkt, j)
            if mismatch { return no("holder-key thumbprint (cnf.jkt) mismatch") }
        }
        return ok()
    }

    // ---- appraisal ----

    /// A TCB version packed into a comparable integer, or nil for an unknown shape (fail closed): a number (floored, non-negative),
    /// a decimal string, or the structured components (each 0..255, absent = 0).
    static func packTcb(_ v: JSONValue?) throws -> BigUInt? {
        switch v {
        case let .int(i)?: return i >= 0 ? BigUInt(UInt64(i)) : nil
        case let .double(d)?:
            guard d.isFinite, d >= 0 else { return nil }
            return EatJS.bigFromDouble(d.rounded(.down))
        case let .string(s)?:
            let t = Attest.jsTrim(s)
            if !t.isEmpty, t.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) { return BigUInt(decimal: t) }
            return nil
        default: break
        }
        // true / [] / null are not a TCB version
        guard case .object? = v else { return nil }
        func comp(_ k: String) throws -> UInt64? {
            guard let x = try EatJS.prop(v, k) else { return 0 }
            guard let d = IV.num(x), d == d.rounded(), d >= 0, !(d == 0 && d.sign == .minus), d <= 255 else { return nil }
            return UInt64(d)
        }
        guard let bl = try comp("bootloader"), let tee = try comp("tee"), let snp = try comp("snp"), let uc = try comp("microcode") else { return nil }
        return BigUInt(bl | (tee << 8) | (snp << 48) | (uc << 56))
    }

    static func lcList(_ a: [JSONValue]) throws -> [String] {
        var out: [String] = []
        for x in a {
            guard case let .string(s) = x else { throw EatJS.typeError("s.toLowerCase is not a function") }
            out.append(s.lowercased())
        }
        return out
    }

    /// `eat.measurements?.find(e => e.type === a || e.type === b)`.
    static func findMeasurement(_ eat: JSONValue?, _ types: [String]) throws -> JSONValue? {
        guard let ms = try EatJS.prop(eat, "measurements"), !ms.isNull else { return nil }
        guard case let .array(a) = ms else { throw EatJS.typeError("eat.measurements?.find is not a function") }
        for e in a {
            if let t = EatJS.string(try EatJS.prop(e, "type")), types.contains(t) { return try EatJS.prop(e, "value") }
        }
        return nil
    }

    /// The launch measurement to appraise: the measured identity, else the sevsnp block, else a `launch` / `measurement` entry.
    static func launchMeasurement(_ eat: JSONValue?) throws -> JSONValue? {
        let measured = try EatJS.prop(eat, "measured")
        if JS.truthy(measured), let rm = EatJS.string(EatJS.opt(measured, "runtime_measurement")), !rm.isEmpty { return .string(rm) }
        let sev = try EatJS.prop(eat, "sevsnp")
        if JS.truthy(sev), let m = EatJS.string(EatJS.opt(sev, "measurement")) { return .string(m) }
        return try findMeasurement(eat, ["launch", "measurement"])
    }

    static func weightsMeasurement(_ eat: JSONValue?) throws -> JSONValue? {
        let measured = try EatJS.prop(eat, "measured")
        if JS.truthy(measured), let w = EatJS.string(EatJS.opt(measured, "weights_digest")), !w.isEmpty { return .string(w) }
        return try findMeasurement(eat, ["weights"])
    }

    /// true / false when the debug status is known, else nil (the caller fails closed).
    static func isDebugDisabled(_ eat: JSONValue?) throws -> Bool? {
        if let dbg = try EatJS.prop(eat, "dbgstat") {
            if let s = EatJS.string(dbg), DBGSTAT_VALUES.contains(s) { return s != "enabled" }
            return nil
        }
        let sev = try EatJS.prop(eat, "sevsnp")
        if JS.truthy(sev), case let .bool(b)? = EatJS.opt(sev, "debug") { return !b }
        return nil
    }

    static func result(_ tier: String, _ reasons: [String]) -> JSONValue {
        let trustworthy = tier == "affirming-hw-rooted" || tier == "affirming" || tier == "warning"
        return .object(["tier": .string(tier), "trustworthy": .bool(trustworthy), "reasons": .array(reasons.map { JSONValue.string($0) })])
    }

    /// Appraise an EAT's evidence against RATS reference values and endorsements (RFC 9334). Tiers: `affirming-hw-rooted` >
    /// `affirming` > `warning` (acceptable); `contraindicated` and `rejected` fail closed. An empty policy is `rejected`.
    public static func appraise(_ evidence: JSONValue?, _ referenceValues: JSONValue? = nil, _ endorsements: JSONValue? = nil, _ extras: JSONValue? = nil) throws -> JSONValue {
        let rv: JSONValue = referenceValues ?? .object([:])
        let en: JSONValue = endorsements ?? .object([:])
        let ex: JSONValue = extras ?? .object([:])
        var reasons: [String] = []
        func nonEmpty(_ v: JSONValue?) -> [JSONValue]? {
            if case let .array(a)? = v, !a.isEmpty { return a }
            return nil
        }
        let issuers = nonEmpty(try EatJS.prop(en, "issuers"))
        let oemids = nonEmpty(try EatJS.prop(en, "oemids"))
        let operators = nonEmpty(try EatJS.prop(en, "operators"))
        let rvMeasurements = nonEmpty(try EatJS.prop(rv, "measurements"))
        let rvModels = nonEmpty(try EatJS.prop(rv, "models"))
        let rvWeights = nonEmpty(try EatJS.prop(rv, "weightsMeasurements"))
        let requireWeights = try EatJS.prop(rv, "requireMeasuredWeights") == JSONValue.bool(true)
        let minTcb = try EatJS.prop(rv, "minTcb")
        let minSvn = try EatJS.prop(rv, "minGuestSvn")
        let requireDebug = try EatJS.prop(rv, "requireDebugDisabled") == JSONValue.bool(true)
        let hasEndorsements = issuers != nil || oemids != nil || operators != nil
        let hasReferenceValues = rvMeasurements != nil || rvModels != nil || rvWeights != nil || requireWeights || minTcb != nil || IV.num(minSvn) != nil || requireDebug
        if !hasEndorsements && !hasReferenceValues {
            return result("rejected", ["empty appraisal policy: no endorsements or reference values to appraise against (fail closed)"])
        }

        // Endorsements (who): a mismatch is rejected.
        if let list = issuers {
            let iss = try EatJS.prop(evidence, "iss")
            if !list.contains(where: { EatJS.svz($0, iss) }) { return result("rejected", reasons + ["issuer \(JS.toString(iss)) is not an endorsed attester"]) }
            reasons.append("issuer endorsed")
        }
        if let list = oemids {
            guard let oem = EatJS.string(try EatJS.prop(evidence, "oemid")), list.contains(where: { EatJS.svz($0, JSONValue.string(oem)) }) else {
                return result("rejected", reasons + ["oemid absent or not endorsed (fail closed)"])
            }
            reasons.append("oemid endorsed")
        }
        if let list = operators {
            let op = EatJS.string(EatJS.opt(try EatJS.prop(evidence, "measured"), "operator"))
            guard let o = op, !o.isEmpty, list.contains(where: { EatJS.svz($0, JSONValue.string(o)) }) else {
                return result("rejected", reasons + ["hardware operator absent or not endorsed (fail closed)"])
            }
            reasons.append("operator endorsed")
        }

        // Reference values (what): a bad value is contraindicated, an absent or unknown required one is rejected.
        if let list = rvMeasurements {
            guard let m = try launchMeasurement(evidence) else { return result("rejected", reasons + ["no launch measurement in evidence to compare against reference values (fail closed)"]) }
            let lower = try lcList(list)
            guard case let .string(ms) = m else { throw EatJS.typeError("m.toLowerCase is not a function") }
            if !EatJS.strContains(lower, ms.lowercased()) { return result("contraindicated", reasons + ["launch measurement not in reference values"]) }
            reasons.append("launch measurement matches a reference value")
        }
        if let list = rvModels {
            guard let model = EatJS.string(EatJS.opt(try EatJS.prop(evidence, "measured"), "model_id")), !model.isEmpty else {
                return result("rejected", reasons + ["no model id in evidence (fail closed)"])
            }
            if !list.contains(where: { EatJS.svz($0, JSONValue.string(model)) }) { return result("contraindicated", reasons + ["model id not in reference values (model swap?)"]) }
            reasons.append("model id matches a reference value")
        }
        if requireWeights {
            if EatJS.opt(try EatJS.prop(evidence, "measured"), "weights_measured") != JSONValue.bool(true) {
                return result("contraindicated", reasons + ["weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)"])
            }
            reasons.append("weights digest is hardware-measured")
        }
        if let list = rvWeights {
            guard let w = try weightsMeasurement(evidence) else { return result("rejected", reasons + ["no measured-weights digest in evidence (fail closed)"]) }
            guard case let .string(ws) = w else { throw EatJS.typeError("w.toLowerCase is not a function") }
            if ws.isEmpty { return result("rejected", reasons + ["no measured-weights digest in evidence (fail closed)"]) }
            let lower = try lcList(list)
            if !EatJS.strContains(lower, ws.lowercased()) { return result("contraindicated", reasons + ["weights measurement not in reference values (model swap / fine-tune?)"]) }
            reasons.append("weights measurement matches a reference value")
        }
        if let mt = minTcb {
            guard let min = try packTcb(mt) else { return result("rejected", reasons + ["reference minTcb is not a comparable TCB version"]) }
            let raw = EatJS.opt(try EatJS.prop(evidence, "sevsnp"), "reported_tcb")
            var got: BigUInt? = nil
            if let r = raw { got = try packTcb(r) }
            guard let g = got else { return result("rejected", reasons + ["evidence TCB version is absent or an unknown format \u{2014} failing closed (see 2025-10-27 GCP firmware drift)"]) }
            if g < min { return result("contraindicated", reasons + ["reported TCB is below the reference minimum (downgrade / rollback)"]) }
            reasons.append("TCB at or above reference minimum")
        }
        if let want = IV.num(minSvn) {
            guard let svn = EatJS.finite(EatJS.opt(try EatJS.prop(evidence, "sevsnp"), "guest_svn")) else { return result("rejected", reasons + ["guest_svn absent (fail closed)"]) }
            if svn < want { return result("contraindicated", reasons + ["guest_svn \(JS.toString(EatJS.jn(svn))) below reference minimum \(JS.toString(minSvn))"]) }
            reasons.append("guest_svn at or above reference minimum")
        }
        if requireDebug {
            guard let disabled = try isDebugDisabled(evidence) else { return result("rejected", reasons + ["debug status unknown \u{2014} failing closed"]) }
            if !disabled { return result("contraindicated", reasons + ["debug is enabled (host can inspect the guest \u{2014} no confidentiality)"]) }
            reasons.append("debug disabled")
        }

        // Everything passed: degraded evidence is a warning; a verified silicon signature lifts the tier.
        if EatJS.opt(try EatJS.prop(evidence, "sevsnp"), "degraded") == JSONValue.bool(true) {
            return result("warning", reasons + ["evidence came from a degraded (version-tolerant) parse \u{2014} review"])
        }
        if try EatJS.prop(ex, "hardwareVerified") == JSONValue.bool(true) {
            let label = JS.present(try EatJS.prop(ex, "hardwareRootLabel")).map { JS.toString($0) } ?? AMD_SEV_SNP_HARDWARE_ROOT_LABEL
            return result("affirming-hw-rooted", reasons + ["AMD SEV-SNP report signature + VCEK\u{2192}ASK\u{2192}ARK chain verified \u{2014} \(label)"])
        }
        return result("affirming", reasons)
    }

    // ---- version-tolerant SEV-SNP report parse ----

    static func hexOf(_ b: ArraySlice<UInt8>) -> String { ACrypto.hex(Array(b)) }

    /// The EAT evidence block of a complete report (a known version): decimal-string TCB, hex measurement and chip id.
    static func fullEvidence(_ b: [UInt8]) -> JSONValue {
        let policy = AmdVerifier.u64(b, AmdVerifier.OFF_POLICY)
        return .object([
            "version": .int(Int64(AmdVerifier.u32(b, 0))),
            "measurement": .string(hexOf(b[0x90..<(0x90 + 48)])),
            "reported_tcb": .string(String(AmdVerifier.u64(b, AmdVerifier.OFF_REPORTED_TCB))),
            "guest_svn": .int(Int64(AmdVerifier.u32(b, AmdVerifier.OFF_GUEST_SVN))),
            "chip_id": .string(hexOf(b[AmdVerifier.OFF_CHIP_ID..<(AmdVerifier.OFF_CHIP_ID + 64)])),
            "debug": .bool(policy & AmdVerifier.POLICY_DEBUG_BIT != 0),
        ])
    }

    /// The default measured identity of a complete report: runtime measurement = hex(MEASUREMENT), operator = hex(CHIP_ID).
    static func measuredFromReportBytes(_ b: [UInt8]) -> JSONValue {
        .object(["model_id": .string(""), "weights_digest": .string(""), "weights_measured": .bool(false),
                 "runtime_measurement": .string(hexOf(b[0x90..<(0x90 + 48)])), "operator": .string(hexOf(b[AmdVerifier.OFF_CHIP_ID..<(AmdVerifier.OFF_CHIP_ID + 64)]))])
    }

    /// Parse an AMD SEV-SNP report across format versions, degrading instead of throwing. A known version with a complete buffer
    /// is the full parse (`hasReport`, `measured`); an unknown version or a short buffer reads the version-stable header fields
    /// and is `degraded`. Result: ok, version, known, degraded, notes, hasReport, evidence?, measured?.
    public static func parseReportTolerant(_ bytes: [UInt8]) -> JSONValue {
        func out(_ ok: Bool, _ version: Int64, _ known: Bool, _ degraded: Bool, _ notes: [String], _ evidence: JSONValue?, _ measured: JSONValue?) -> JSONValue {
            var o: JObject = ["ok": .bool(ok), "version": .int(version), "known": .bool(known), "degraded": .bool(degraded),
                              "notes": .array(notes.map { JSONValue.string($0) }), "hasReport": .bool(measured != nil)]
            if let e = evidence { o["evidence"] = e }
            if let m = measured { o["measured"] = m }
            return .object(o)
        }
        if bytes.count < 4 { return out(false, 0, false, true, ["buffer too short to read the report version"], nil, nil) }
        let version = AmdVerifier.u32(bytes, 0)
        let known = KNOWN_REPORT_VERSIONS.contains(Int(version))
        var notes: [String] = []
        if known && bytes.count >= FULL_REPORT_MIN_LEN {
            return out(true, Int64(version), true, false, notes, fullEvidence(bytes), measuredFromReportBytes(bytes))
        } else if !known {
            notes.append("unknown report version \(version) \u{2014} parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)")
        } else {
            notes.append("buffer length \(bytes.count) < full report \(FULL_REPORT_MIN_LEN) \u{2014} degraded header-only parse")
        }
        if bytes.count < 0x90 + 48 { return out(false, Int64(version), known, true, notes + ["buffer too short to read the launch measurement"], nil, nil) }
        var ev: JObject = ["version": .int(Int64(version)), "measurement": .string(hexOf(bytes[0x90..<(0x90 + 48)])), "degraded": .bool(true)]
        if bytes.count >= AmdVerifier.OFF_GUEST_SVN + 4 { ev["guest_svn"] = .int(Int64(AmdVerifier.u32(bytes, AmdVerifier.OFF_GUEST_SVN))) }
        if bytes.count >= AmdVerifier.OFF_POLICY + 8 { ev["debug"] = .bool(AmdVerifier.u64(bytes, AmdVerifier.OFF_POLICY) & AmdVerifier.POLICY_DEBUG_BIT != 0) }
        if bytes.count >= AmdVerifier.OFF_REPORTED_TCB + 8 { ev["reported_tcb"] = .string(String(AmdVerifier.u64(bytes, AmdVerifier.OFF_REPORTED_TCB))) }
        if bytes.count >= AmdVerifier.OFF_CHIP_ID + 64 { ev["chip_id"] = .string(hexOf(bytes[AmdVerifier.OFF_CHIP_ID..<(AmdVerifier.OFF_CHIP_ID + 64)])) }
        return out(true, Int64(version), known, true, notes, .object(ev), nil)
    }
}
