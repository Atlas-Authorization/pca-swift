import Foundation
import CryptoKit
import CAda

/// A quantum random number source. `fetch` returns exactly `numBytes` bytes or throws; it never decides anything about trust.
public protocol PCAQrngSource {
    var name: String { get }
    func fetch(_ numBytes: Int) throws -> [UInt8]
}

/// QRNG entropy as an ADDITION to key generation, never a trust dependency: every seed is HKDF-SHA256(local CSPRNG || quantum), so a hostile or
/// broken quantum source cannot lower the result below the local CSPRNG. An HTTP source over an injected transport (the SDK ships no network
/// client), the SP 800-90B section 4.4 continuous health tests, the combiner, `secureSeed` and an Ed25519 key pair helper.
public enum PCAEntropy {
    public static let MAX_HKDF_OUTPUT = 8160
    public static let MIN_LOCAL_BYTES = 16
    public static let DEFAULT_SEED_BYTES = 32
    public static let DEFAULT_MAX_QRNG_BYTES = 1024
    public static let DEFAULT_TIMEOUT_MS = 5000
    static let MIX_LABEL = "atlas-pca/entropy/mix/v1"
    static let MIX_SALT = Array("atlas-pca/entropy/salt/v1".utf8)

    /// A policy refusal: `quantum_required`, `health_test_failed` or `insecure_transport`.
    public struct EntropyError: Error, CustomStringConvertible {
        public let name = "EntropyError"
        public let code: String
        public let message: String
        public init(_ code: String, _ message: String) { self.code = code; self.message = message }
        public var description: String { message }
    }

    /// Any other refusal. `kind` is the reference's error class: `Error`, `RangeError` or `TypeError`.
    public struct Refusal: Error, CustomStringConvertible {
        public let kind: String
        public let message: String
        init(_ message: String, _ kind: String = "Error") { self.kind = kind; self.message = message }
        public var description: String { message }
    }

    /// What a transport throws when its own deadline passed.
    public struct TransportTimeout: Error { public init() {} }

    /// A double that is an integer in the safe range, as an Int (the reference takes numbers; a fraction or a non-finite value is never a count).
    static func integer(_ d: Double) -> Int? { d.isFinite && d.rounded(.towardZero) == d && abs(d) <= 9_007_199_254_740_991 ? Int(d) : nil }

    private static func u32be(_ n: Int) -> [UInt8] { [UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] }

    private static func hmac(_ key: [UInt8], _ data: [UInt8]) -> [UInt8] { Array(HMAC<SHA256>.authenticationCode(for: Data(data), using: SymmetricKey(data: Data(key)))) }

    /// HKDF-SHA256 (RFC 5869) over the platform HMAC: extract, then as many expand blocks as `length` needs (at most 255).
    static func hkdfSha256(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        let prk = hmac(salt, ikm)
        var out: [UInt8] = [], t: [UInt8] = []
        var i: UInt8 = 1
        while out.count < length {
            t = hmac(prk, t + info + [i])
            out += t
            i &+= 1
        }
        return Array(out.prefix(length))
    }

    // MARK: health tests (SP 800-90B section 4.4)

    public struct HealthTestOptions: Equatable, Sendable {
        /// Assumed min-entropy per byte, in [1, 8].
        public var h: Double
        /// Adaptive proportion window, an integer of at least 2.
        public var window: Double
        public init(h: Double = 8, window: Double = 512) { self.h = h; self.window = window }
    }

    public struct HealthVerdict: Equatable, Sendable {
        public let ok: Bool
        /// The failing test: `repetition-count` or `adaptive-proportion`.
        public let test: String?
    }

    /// The repetition count cutoff for min-entropy `h` at a false positive rate of 2^-20.
    public static func repetitionCutoff(_ h: Double) -> Double { 1 + (20 / h).rounded(.up) }

    /// The adaptive proportion cutoff: 1 + the smallest k whose binomial(w, 2^-h) distribution function reaches 1 - 2^-20.
    public static func proportionCutoff(_ h: Double, _ w: Double) -> Double {
        // the reference's pow (fdlibm), not the platform's: a last-ulp difference could move a boundary cutoff
        let p = FdLibm.pow(2, -h)
        let target = 1 - FdLibm.pow(2, -20.0)
        var pmf = FdLibm.pow(1 - p, w)
        var cdf = pmf
        var k = 0.0
        while cdf < target && k < w {
            pmf *= ((w - k) / (k + 1)) * (p / (1 - p))
            k += 1
            cdf += pmf
        }
        return 1 + k
    }

    /// Both continuous health tests over `bytes`. Bad parameters and an empty buffer fail closed as `repetition-count`.
    public static func healthTestBytes(_ bytes: [UInt8], _ opts: HealthTestOptions = HealthTestOptions()) -> HealthVerdict {
        let h = opts.h
        guard h >= 1 && h <= 8, let w0 = integer(opts.window), w0 >= 2, !bytes.isEmpty else { return HealthVerdict(ok: false, test: "repetition-count") }
        let rc = repetitionCutoff(h)
        var run = 1.0
        for i in bytes.indices.dropFirst() {
            run = bytes[i] == bytes[i - 1] ? run + 1 : 1
            if run >= rc { return HealthVerdict(ok: false, test: "repetition-count") }
        }
        let w = min(w0, bytes.count)
        let ac = proportionCutoff(h, Double(w))
        var start = 0
        while start + w <= bytes.count {
            let first = bytes[start]
            var count = 0.0
            for i in start..<(start + w) where bytes[i] == first { count += 1 }
            if count >= ac { return HealthVerdict(ok: false, test: "adaptive-proportion") }
            start += w
        }
        return HealthVerdict(ok: true, test: nil)
    }

    // MARK: the combiner

    /// HKDF-SHA256 over the length-framed pair (local, quantum). `local` must be at least 16 bytes; `quantum` may be empty; `length` defaults to
    /// the local byte count and is 1...8160; a non-empty `context` separates uses.
    public static func mixEntropy(_ local: [UInt8], _ quantum: [UInt8], length: Int? = nil, context: String? = nil) throws -> [UInt8] {
        if local.count < MIN_LOCAL_BYTES { throw Refusal("mixEntropy: local CSPRNG must be >= \(MIN_LOCAL_BYTES) bytes (fail-closed)", "RangeError") }
        let n = length ?? local.count
        if n <= 0 || n > MAX_HKDF_OUTPUT { throw Refusal("mixEntropy: length must be an integer in 1..\(MAX_HKDF_OUTPUT)", "RangeError") }
        let label = (context ?? "").isEmpty ? MIX_LABEL : MIX_LABEL + "/" + (context ?? "")
        return hkdfSha256(ikm: u32be(local.count) + u32be(quantum.count) + local + quantum, salt: MIX_SALT, info: Array(label.utf8) + u32be(n), length: n)
    }

    // MARK: secureSeed

    public struct SecureSeedOptions {
        public var length: Int = PCAEntropy.DEFAULT_SEED_BYTES
        public var source: PCAQrngSource?
        /// Default max(32, length).
        public var quantumBytes: Int?
        /// Default max(32, length); at least 16.
        public var localBytes: Int?
        public var context: String?
        /// Fail closed when no health-tested quantum bytes were obtained.
        public var requireQuantum = false
        /// Nil disables the health test of the quantum bytes.
        public var healthTest: HealthTestOptions? = HealthTestOptions()
        /// Told every reason the source was not used. Whatever it throws is ignored: observability never breaks key generation.
        public var onQrngError: ((Error) throws -> Void)?
        /// The local CSPRNG (a test seam); the platform generator when nil.
        public var randomBytesImpl: ((Int) throws -> [UInt8])?
        public init() {}
    }

    public struct SecureSeedResult: Equatable, Sendable {
        public let seed: [UInt8]
        public let usedQuantum: Bool
        public let quantumByteCount: Int
        public let source: String?
    }

    private static func drawLocal(_ impl: ((Int) throws -> [UInt8])?, _ n: Int) throws -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        let bytes = try impl.map { try $0(n) } ?? (0..<n).map { _ in UInt8.random(in: .min ... .max, using: &g) }
        if bytes.count != n { throw Refusal("secureSeed: local CSPRNG did not return the requested bytes (fail-closed)") }
        return bytes
    }

    /// A seed from the local CSPRNG mixed with health-tested quantum bytes when a source answers. A failing source falls back to the local bytes
    /// alone (reported through `onQrngError`), unless `requireQuantum` is set.
    public static func secureSeed(_ opts: SecureSeedOptions = SecureSeedOptions()) throws -> SecureSeedResult {
        let length = opts.length
        if length <= 0 || length > MAX_HKDF_OUTPUT { throw Refusal("secureSeed: length must be an integer in 1..\(MAX_HKDF_OUTPUT)", "RangeError") }
        let localBytes = opts.localBytes ?? max(DEFAULT_SEED_BYTES, length)
        if localBytes < MIN_LOCAL_BYTES { throw Refusal("secureSeed: localBytes must be an integer >= \(MIN_LOCAL_BYTES)", "RangeError") }
        let quantumBytes = opts.quantumBytes ?? max(DEFAULT_SEED_BYTES, length)
        if quantumBytes <= 0 { throw Refusal("secureSeed: quantumBytes must be a positive integer", "RangeError") }
        let local = try drawLocal(opts.randomBytesImpl, localBytes)
        var quantum: [UInt8] = []
        var usedQuantum = false
        if let source = opts.source {
            do {
                let q = try source.fetch(quantumBytes)
                if q.count != quantumBytes { throw Refusal("QRNG: source returned \(q.count), expected \(quantumBytes)") }
                if let ht = opts.healthTest {
                    let v = healthTestBytes(q, ht)
                    if !v.ok { throw EntropyError("health_test_failed", "QRNG: \(v.test ?? "health") test failed; source rejected") }
                }
                quantum = q
                usedQuantum = true
            } catch {
                quantum = []
                usedQuantum = false
                try? opts.onQrngError?(error)
            }
        }
        if opts.requireQuantum && !usedQuantum { throw EntropyError("quantum_required", "secureSeed: quantum entropy is required but was not obtained (fail-closed)") }
        let seed = try mixEntropy(local, quantum, length: length, context: opts.context)
        return SecureSeedResult(seed: seed, usedQuantum: usedQuantum, quantumByteCount: usedQuantum ? quantum.count : 0, source: opts.source?.name)
    }

    public struct EntropyKeyPair {
        public let secretKey: [UInt8]
        public let publicKey: [UInt8]
        public let usedQuantum: Bool
    }

    /// An Ed25519 key pair whose 32-byte seed comes from `secureSeed` (context `ed25519-key` unless one is given; `length` is ignored).
    public static func generateKeyPairWithEntropy(_ opts: SecureSeedOptions = SecureSeedOptions()) throws -> EntropyKeyPair {
        var o = opts
        o.length = 32
        o.context = opts.context ?? "ed25519-key"
        let r = try secureSeed(o)
        return EntropyKeyPair(secretKey: r.seed, publicKey: try PCAEdKey(seed: r.seed).pub, usedQuantum: r.usedQuantum)
    }

    // MARK: sources

    /// A source that always fails: a deployment with no QRNG keeps one code path.
    public struct NullQrngSource: PCAQrngSource {
        public let name = "null-qrng"
        let reason: String
        public init(reason: String = "no QRNG source configured") { self.reason = reason }
        public func fetch(_ numBytes: Int) throws -> [UInt8] { throw Refusal("QRNG unavailable: \(reason)") }
    }

    public static func unavailableSource(_ reason: String? = nil) -> PCAQrngSource { reason.map { NullQrngSource(reason: $0) } ?? NullQrngSource() }

    // MARK: response parsers

    /// `{"success": true, "data": [0..255, ...]}` (the `success` member may be absent; when present it must be exactly true).
    public static func parseAnuUint8(_ body: JSONValue) throws -> [UInt8] {
        guard case let .object(o) = body else {
            if case .array = body { throw Refusal("QRNG: response `data` is not an array") }
            throw Refusal("QRNG: response body is not a JSON object")
        }
        if let s = o["success"], s != .bool(true) { throw Refusal("QRNG: response reports success=false") }
        guard case let .array(data)? = o["data"] else { throw Refusal("QRNG: response `data` is not an array") }
        var out: [UInt8] = []
        out.reserveCapacity(data.count)
        for (i, v) in data.enumerated() {
            guard let d = IV.safe(v), d >= 0, d <= 255 else { throw Refusal("QRNG: response data[\(i)] is not a 0..255 integer") }
            out.append(UInt8(d))
        }
        return out
    }

    public static func parseHex(_ text: String) throws -> [UInt8] {
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x41...0x46: return c - 0x41 + 10
            case 0x61...0x66: return c - 0x61 + 10
            default: return nil
            }
        }
        let b = Array(text.utf8)
        guard b.count % 2 == 0 else { throw Refusal("QRNG: malformed hex payload") }
        var out: [UInt8] = []
        out.reserveCapacity(b.count / 2)
        for i in stride(from: 0, to: b.count, by: 2) {
            guard let hi = nibble(b[i]), let lo = nibble(b[i + 1]) else { throw Refusal("QRNG: malformed hex payload") }
            out.append(hi << 4 | lo)
        }
        return out
    }

    /// Standard-alphabet base64 with at most two trailing `=`, decoded the forgiving way: padding may be missing, padding that is present must
    /// complete a group of four, and unused trailing bits are dropped.
    public static func parseBase64(_ text: String) throws -> [UInt8] {
        let bad = Refusal("QRNG: malformed base64 payload")
        func val(_ c: UInt8) -> UInt32? {
            switch c {
            case 0x41...0x5a: return UInt32(c - 0x41)
            case 0x61...0x7a: return UInt32(c - 0x61) + 26
            case 0x30...0x39: return UInt32(c - 0x30) + 52
            case 0x2b: return 62
            case 0x2f: return 63
            default: return nil
            }
        }
        var b = Array(text.utf8)
        var pad = 0
        while pad < 2, let last = b.last, last == 0x3d, b.count % 4 == 0 || pad > 0 { b.removeLast(); pad += 1 }
        // one "=" on a length that is not a multiple of four, or a third "=", is still in `b` here and is refused as a non-alphabet byte
        if b.count % 4 == 1 { throw bad }
        var out: [UInt8] = []
        var acc: UInt32 = 0
        var bits = 0
        for c in b {
            guard let v = val(c) else { throw bad }
            acc = (acc << 6) | v
            bits += 6
            if bits >= 8 { bits -= 8; out.append(UInt8((acc >> UInt32(bits)) & 0xff)) }
        }
        return out
    }

    // MARK: the HTTP source

    public struct QrngHttpResponse {
        public var ok: Bool
        public var status: Int
        public var json: () throws -> JSONValue
        public var text: () throws -> String
        public init(ok: Bool, status: Int, json: @escaping () throws -> JSONValue, text: @escaping () throws -> String) {
            self.ok = ok; self.status = status; self.json = json; self.text = text
        }
    }

    /// The injected HTTP client: one GET of `url` with `headers`. It MUST NOT follow redirects (a redirect is an error) and MUST give up after
    /// `timeoutMs` by throwing `TransportTimeout`.
    public typealias QrngTransport = (_ url: String, _ headers: [(name: String, value: String)], _ timeoutMs: Int) throws -> QrngHttpResponse

    public struct HttpQrngConfig {
        public var url: String
        public var apiKey: String?
        public var apiKeyHeader = "x-api-key"
        /// `anu-uint8` (JSON), `hex` or `base64` (text).
        public var format = "anu-uint8"
        public var timeoutMs = PCAEntropy.DEFAULT_TIMEOUT_MS
        public var maxBytes = PCAEntropy.DEFAULT_MAX_QRNG_BYTES
        public var lengthParam = "length"
        /// Further query parameters, set in this order.
        public var extraParams: [(name: String, value: String)] = []
        /// A custom URL builder (base, byte count); its result still goes through the transport security check.
        public var buildUrl: ((String, Int) -> String)?
        /// Allow plain http to localhost, 127.0.0.1 or [::1] (development only).
        public var allowInsecureLoopback = false
        public var transport: QrngTransport?
        public init(url: String) { self.url = url }
    }

    private static func ada(_ call: (UnsafeMutablePointer<UInt8>, Int, UnsafeMutablePointer<Int>) -> Int32) -> String? {
        let cap = 8192
        var out = [UInt8](repeating: 0, count: cap)
        var n = 0
        guard call(&out, cap, &n) == 1, n <= cap else { return nil }
        return String(decoding: out[0..<n], as: UTF8.self)
    }

    /// A part of the WHATWG-parsed URL: 0 protocol, 1 hostname, 2 host, 3 href. Nil when the URL does not parse (or is longer than 8192 bytes).
    static func urlPart(_ url: String, _ which: Int32) -> String? {
        let u = Array(url.utf8)
        return ada { out, cap, n in atlas_ada_url_part(u, u.count, which, out, cap, n) }
    }

    static func urlSetParam(_ url: String, _ key: String, _ value: String) -> String? {
        let u = Array(url.utf8), k = Array(key.utf8), v = Array(value.utf8)
        return ada { out, cap, n in atlas_ada_url_set_param(u, u.count, k, k.count, v, v.count, out, cap, n) }
    }

    /// https only; http solely for a loopback host when the caller allowed it.
    static func assertSecureTransport(_ url: String, _ allowLoopback: Bool) throws {
        guard let proto = urlPart(url, 0), let host = urlPart(url, 1) else { throw EntropyError("insecure_transport", "QRNG: endpoint URL is not a valid URL") }
        if proto == "https:" { return }
        if proto == "http:" && allowLoopback && (host == "localhost" || host == "127.0.0.1" || host == "[::1]") { return }
        throw EntropyError("insecure_transport", "QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)")
    }

    public final class HttpQrngSource: PCAQrngSource {
        public let name: String
        private let cfg: HttpQrngConfig

        public init(_ config: HttpQrngConfig) throws {
            if config.url.isEmpty { throw Refusal("HttpQrngSource: `url` must be a non-empty string", "TypeError") }
            if config.maxBytes <= 0 { throw Refusal("HttpQrngSource: `maxBytes` must be a positive integer", "TypeError") }
            if config.timeoutMs <= 0 { throw Refusal("HttpQrngSource: `timeoutMs` must be a positive integer", "TypeError") }
            cfg = config
            let host = PCAEntropy.urlPart(config.url, 2) ?? ""
            name = "http-qrng(\(host.isEmpty ? "unknown" : host))"
        }

        private func buildUrl(_ numBytes: Int) throws -> String {
            if let b = cfg.buildUrl { return b(cfg.url, numBytes) }
            guard var u = PCAEntropy.urlSetParam(cfg.url, cfg.lengthParam, String(numBytes)) else { throw Refusal("Invalid URL", "TypeError") }
            for (k, v) in cfg.extraParams {
                guard let next = PCAEntropy.urlSetParam(u, k, v) else { throw Refusal("Invalid URL", "TypeError") }
                u = next
            }
            return u
        }

        public func fetch(_ numBytes: Int) throws -> [UInt8] {
            if numBytes <= 0 { throw Refusal("QRNG: numBytes must be a positive integer, got \(numBytes)", "TypeError") }
            if numBytes > cfg.maxBytes { throw Refusal("QRNG: requested \(numBytes) bytes exceeds per-request cap \(cfg.maxBytes)", "RangeError") }
            guard let transport = cfg.transport else { throw Refusal("QRNG: no fetch implementation available in this runtime") }
            let url = try buildUrl(numBytes)
            try PCAEntropy.assertSecureTransport(url, cfg.allowInsecureLoopback)
            var headers: [(name: String, value: String)] = [("accept", "application/json, text/plain")]
            let key = cfg.apiKey ?? ""
            if !key.isEmpty { headers.append((cfg.apiKeyHeader, key)) }
            let res: QrngHttpResponse
            do { res = try transport(url, headers, cfg.timeoutMs) } catch {
                var detail = error is TransportTimeout ? "timeout" : ((error as? CustomStringConvertible)?.description ?? "unknown error")
                // the key never appears in an error
                if !key.isEmpty { detail = detail.components(separatedBy: key).joined(separator: "[redacted]") }
                throw Refusal("QRNG: fetch failed (\(detail))")
            }
            if !res.ok { throw Refusal("QRNG: endpoint returned HTTP \(res.status)") }
            let bytes: [UInt8]
            if cfg.format == "anu-uint8" {
                bytes = try PCAEntropy.parseAnuUint8(try res.json())
            } else {
                let text = Attest.jsTrim(try res.text())
                bytes = try (cfg.format == "hex" ? PCAEntropy.parseHex(text) : PCAEntropy.parseBase64(text))
            }
            if bytes.count != numBytes { throw Refusal("QRNG: expected \(numBytes) bytes, response decoded to \(bytes.count)") }
            return bytes
        }
    }
}
