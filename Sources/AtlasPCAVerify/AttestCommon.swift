import Foundation
import CryptoKit

// Hardware attestation verifiers (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, Google Confidential Space, NVIDIA GPU SPDM): shared
// types and helpers. The vendor verifiers answer exactly what the reference verifiers of @atlasauth/pca answer, reason text
// included, and fail closed on anything they cannot establish.

/// What a vendor quote's bound value must equal: the server-known holder key, grant, epoch and nonce. `epoch` is a Double
/// because the wire form carries a JSON number; only a non-negative safe integer is constructible.
public struct AttestationBinding: Equatable, Sendable {
    public var holderPub: String
    public var grantRef: String
    public var epoch: Double
    public var nonce: String
    public init(holderPub: String, grantRef: String, epoch: Double, nonce: String) {
        self.holderPub = holderPub
        self.grantRef = grantRef
        self.epoch = epoch
        self.nonce = nonce
    }
}

/// A vendor verifier's answer (the reference `HardwareAttestationResult`).
public struct HardwareResult: Sendable {
    public var ok: Bool
    public var bound: Bool
    public var reason: String
    public var measured: JObject?
    public var hostAsserted: [String: String]?
    public init(ok: Bool = false, bound: Bool = false, reason: String = "", measured: JObject? = nil, hostAsserted: [String: String]? = nil) {
        self.ok = ok
        self.bound = bound
        self.reason = reason
        self.measured = measured
        self.hostAsserted = hostAsserted
    }

    static func fail(_ reason: String) -> HardwareResult { HardwareResult(reason: reason) }

    /// The language-neutral form of the result (what the conformance vectors record in `expect`).
    public var wire: JSONValue {
        if !ok { return .object(["ok": .bool(false), "reason": .string(reason)]) }
        var o: JObject = ["ok": .bool(true), "bound": .bool(bound)]
        if let m = measured { o["measured"] = .object(m) }
        if let h = hostAsserted { o["hostAsserted"] = .object(h.reduce(into: JObject()) { $0[JKey($1.key)] = .string($1.value) }) }
        return .object(o)
    }
}

/// A vendor verifier for one kind of hardware evidence. `evidence` is the vendor wire object (nil: none supplied).
public protocol HardwareAttestationVerifier {
    func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult
}

enum Attest {
    static let BIND_DOMAIN = "atlas-pca/attest-bind/v1\u{0}"

    static func lengthPrefixed(_ s: String) -> [UInt8] {
        let b = Array(s.utf8)
        let n = UInt32(truncatingIfNeeded: b.count)
        return [UInt8(n >> 24 & 0xff), UInt8(n >> 16 & 0xff), UInt8(n >> 8 & 0xff), UInt8(n & 0xff)] + b
    }

    /// SHA-512( "atlas-pca/attest-bind/v1\0" || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce) ), or the reason it
    /// cannot be constructed.
    static func bindingBytes(_ e: AttestationBinding) -> (bytes: [UInt8]?, error: String) {
        if e.holderPub.isEmpty { return (nil, "binding: holderPub required") }
        if e.grantRef.isEmpty { return (nil, "binding: grantRef required") }
        if e.nonce.isEmpty { return (nil, "binding: nonce required") }
        if e.epoch.isNaN || e.epoch != e.epoch.rounded(.towardZero) || e.epoch < 0 || e.epoch > Double(Canonical.MAX_SAFE) {
            return (nil, "binding: epoch must be a non-negative safe integer")
        }
        var buf = Array(BIND_DOMAIN.utf8) + lengthPrefixed(e.holderPub) + lengthPrefixed(e.grantRef)
        let ep = UInt64(e.epoch)
        for i in (0..<8).reversed() { buf.append(UInt8((ep >> UInt64(8 * i)) & 0xff)) }
        buf += lengthPrefixed(e.nonce)
        return (Array(SHA512.hash(data: Data(buf))), "")
    }
}

// MARK: - small helpers shared by the vendor verifiers

extension Attest {
    static func isJSSpace(_ r: Unicode.Scalar) -> Bool {
        switch r.value {
        case 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff: return true
        default: return r.value >= 0x2000 && r.value <= 0x200a
        }
    }

    /// String.prototype.trim
    static func jsTrim(_ s: String) -> String {
        var u = Array(s.unicodeScalars)
        while let f = u.first, isJSSpace(f) { u.removeFirst() }
        while let l = u.last, isJSSpace(l) { u.removeLast() }
        var out = String.UnicodeScalarView()
        out.append(contentsOf: u)
        return String(out)
    }

    static func stripJSSpace(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars where !isJSSpace(u) { out.append(u) }
        return String(out)
    }

    /// Buffer.from(s, "base64"): either alphabet, characters outside it are skipped, "=" ends the data.
    static func nodeB64(_ s: String) -> [UInt8] {
        var out: [UInt8] = []
        var acc: UInt32 = 0
        var bits = 0
        for c in s.utf8 {
            let v: UInt32
            switch c {
            case 0x41...0x5a: v = UInt32(c - 0x41)
            case 0x61...0x7a: v = UInt32(c - 0x61) + 26
            case 0x30...0x39: v = UInt32(c - 0x30) + 52
            case 0x2b, 0x2d: v = 62
            case 0x2f, 0x5f: v = 63
            case 0x3d: return out
            default: continue
            }
            acc = acc << 6 | v
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: acc >> UInt32(bits)))
                acc &= (1 << UInt32(bits)) - 1
            }
        }
        return out
    }

    /// base64.StdEncoding.DecodeString: padded, standard alphabet, no stray characters.
    static func base64Std(_ s: String) -> [UInt8]? {
        let u = Array(s.utf8)
        if u.count % 4 != 0 { return nil }
        var out: [UInt8] = []
        var i = 0
        while i < u.count {
            var vals = [UInt32](repeating: 0, count: 4)
            var pad = 0
            for j in 0..<4 {
                let c = u[i + j]
                switch c {
                case 0x41...0x5a: vals[j] = UInt32(c - 0x41)
                case 0x61...0x7a: vals[j] = UInt32(c - 0x61) + 26
                case 0x30...0x39: vals[j] = UInt32(c - 0x30) + 52
                case 0x2b: vals[j] = 62
                case 0x2f: vals[j] = 63
                case 0x3d:
                    if i + 4 != u.count || j < 2 { return nil }
                    pad += 1
                default:
                    return nil
                }
                if pad > 0 && c != 0x3d { return nil }
            }
            let n = vals[0] << 18 | vals[1] << 12 | vals[2] << 6 | vals[3]
            out.append(UInt8(n >> 16 & 0xff))
            if pad < 2 { out.append(UInt8(n >> 8 & 0xff)) }
            if pad < 1 { out.append(UInt8(n & 0xff)) }
            i += 4
        }
        return out
    }

    static func base64StdEncode(_ b: [UInt8]) -> String { Data(b).base64EncodedString() }

    static func isHexString(_ s: String) -> Bool {
        let u = Array(s.utf8)
        return !u.isEmpty && u.count % 2 == 0 && u.allSatisfy { ACrypto.nibble($0) != nil }
    }

    /// A byte-carrying claim: hex (optionally 0x-prefixed), else base64url / base64. nil when nothing decodes.
    static func decodeClaimBytes(_ value: String) -> [UInt8]? {
        let t = jsTrim(value)
        var hx = t
        if t.hasPrefix("0x") || t.hasPrefix("0X") { hx = String(t.dropFirst(2)) }
        if isHexString(hx) { return ACrypto.unhex(hx) }
        let b = nodeB64(t)
        return b.isEmpty ? nil : b
    }

    /// JSON.parse: numbers as the lenient parser reads them; trailing data is an error.
    static func jsonLenient(_ b: [UInt8]) -> JSONValue? {
        try? StrictJSON.parseLenient(String(decoding: b, as: UTF8.self))
    }

    static func asFinite(_ v: JSONValue?) -> Double? {
        guard let d = IV.num(v), d.isFinite else { return nil }
        return d
    }

    static func asStrList(_ v: JSONValue?) -> [String]? {
        guard case let .array(a)? = v else { return nil }
        var out: [String] = []
        for x in a {
            guard let s = x.asString else { return nil }
            out.append(s)
        }
        return out
    }

    /// String(n) for the integers this package reports.
    static func jsNumString(_ f: Double) -> String { Canonical.numberString(f) }

    static func lowerAll(_ l: [String]) -> [String] { l.map { $0.lowercased() } }

    static func newMeasured(_ runtimeMeasurement: String, _ operatorName: String) -> JObject {
        ["model_id": .string(""), "weights_digest": .string(""), "weights_measured": .bool(false),
         "runtime_measurement": .string(runtimeMeasurement), "operator": .string(operatorName)]
    }

    static func evBytes(_ ev: JObject?, _ key: String) -> [UInt8]? {
        guard let s = ev?[JKey(key)]?.asString else { return nil }
        return nodeB64(s)
    }

    static func evString(_ ev: JObject?, _ key: String) -> String? { ev?[JKey(key)]?.asString }

    /// The Azure runtime-data binding: the hash relation and user-data equality. The failure reason, or "" when the quote binds.
    static func checkAzureRuntimeDataBinding(_ reportData: [UInt8], _ runtimeData: [UInt8], _ expected: AttestationBinding) -> String {
        if reportData.count != 64 { return "report_data is not 64 bytes" }
        for b in reportData[32...] where b != 0 { return "report_data[32:64] is not zero (not an Azure runtime-data hash)" }
        if !ACrypto.eq(ACrypto.sha256(runtimeData), Array(reportData[0..<32])) { return "sha256(runtime data) does not equal the quote report_data" }
        guard let parsed = jsonLenient(runtimeData) else { return "runtime data is not valid JSON" }
        guard case let .object(obj) = parsed else { return "runtime data is not a JSON object" }
        guard let userData = obj["user-data"]?.asString, userData.utf8.count == 128, ACrypto.unhex(userData) != nil else {
            return "runtime data carries no 64-byte hex user-data"
        }
        let want = bindingBytes(expected)
        guard let wb = want.bytes else { return "binding not constructible: " + want.error }
        if !ACrypto.eq(ACrypto.unhex(userData) ?? [], wb) { return "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)" }
        return ""
    }
}
