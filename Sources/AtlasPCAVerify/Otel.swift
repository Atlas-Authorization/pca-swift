import Foundation

/// OpenTelemetry instrumentation for PCA: a guard wrapper that emits a span and two metrics per decision, and the credential
/// redaction every string leaving in telemetry goes through. Telemetry observes and never decides: every tracer / meter call is
/// isolated, so an exporter that throws cannot change what the guard returned.
///
/// shortcut: `instrumentGuard` wraps a synchronous guard; wrap an async guard by calling the same pieces from the host's own
/// async closure. A cut of the redacted text that would split a surrogate pair drops the lone half (a Swift String cannot hold one).
public enum PCAOtel {
    public static let STATUS_OK = 1
    public static let STATUS_ERROR = 2
    static let MAX_TEXT = 256

    public struct Span {
        public var setAttribute: (String, JSONValue) throws -> Void
        public var setStatus: (Int, String?) throws -> Void
        /// (error name, message): a fresh error, never the original.
        public var recordException: (String, String) throws -> Void
        public var end: () throws -> Void
        public init(setAttribute: @escaping (String, JSONValue) throws -> Void, setStatus: @escaping (Int, String?) throws -> Void,
                    recordException: @escaping (String, String) throws -> Void, end: @escaping () throws -> Void) {
            self.setAttribute = setAttribute; self.setStatus = setStatus; self.recordException = recordException; self.end = end
        }
    }
    public struct Tracer {
        public var startSpan: (String) throws -> Span
        public init(startSpan: @escaping (String) throws -> Span) { self.startSpan = startSpan }
    }
    /// `add` / `record`: (value, attributes object).
    public struct Instrument {
        public var apply: (JSONValue, JSONValue) throws -> Void
        public init(_ apply: @escaping (JSONValue, JSONValue) throws -> Void) { self.apply = apply }
    }
    public struct Meter {
        public var createCounter: (String) throws -> Instrument
        public var createHistogram: (String) throws -> Instrument
        public init(createCounter: @escaping (String) throws -> Instrument, createHistogram: @escaping (String) throws -> Instrument) {
            self.createCounter = createCounter; self.createHistogram = createHistogram
        }
    }

    // MARK: redaction

    /// JavaScript's regular-expression flavour (no `u` flag): `\w` / `\b` are ASCII, `\s` is the ECMAScript white-space set, `i` folds ASCII only.
    private static let W = "[A-Za-z0-9_]"
    private static let notAfterWord = "(?<![A-Za-z0-9_])"
    private static let spaceSet = #"\t\n\u000B\u000C\r    -     　﻿"#
    private static let S = "[" + spaceSet + "]"
    private static func ci(_ w: String) -> String {
        w.map { c in c.isASCII && c.isLetter ? "[\(c.lowercased())\(c.uppercased())]" : String(c) }.joined()
    }

    private static func re(_ p: String) -> NSRegularExpression {
        // a fixed, reviewed pattern: failing to compile is a programming error, never an input error
        try! NSRegularExpression(pattern: p)
    }

    private static let jwt = re(notAfterWord + #"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"#)
    private static let authorization = re(notAfterWord + "(" + ci("authorization") + "[\"']?" + S + "*[:=]" + S + "*)" + "[^\\n\"']*")
    private static let scheme = re(notAfterWord + "(" + ci("Bearer") + "|" + ci("Basic") + "|" + ci("Token") + ")" + S + "+[A-Za-z0-9_.~+/=-]{6,}")
    private static let userinfo = re("([A-Za-z][A-Za-z0-9+.-]*://)[^" + spaceSet + "/@]*:[^" + spaceSet + "/@]*@")
    private static let pair = re(notAfterWord + "((?:" + ["token", "secret", "password", "passwd", "pwd"].map(ci).joined(separator: "|")
        + "|" + ci("api") + "[_-]?" + ci("key") + "|" + ["key", "signature", "sig", "credential", "auth"].map(ci).joined(separator: "|")
        + ")[\"']?" + S + "*[:=]" + S + "*)(\"[^\"]*\"|'[^']*'|[^" + spaceSet + "\"'&,;]+)")
    private static let longRun = re("[A-Za-z0-9_-]{32,}")

    private static func sub(_ s: String, _ r: NSRegularExpression, _ f: (NSTextCheckingResult, NSString) -> String) -> String {
        let ns = s as NSString
        var out = "", last = 0
        for m in r.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            out += f(m, ns)
            last = m.range.location + m.range.length
        }
        return out + ns.substring(from: last)
    }

    /// Removes what looks like a credential from text bound for telemetry: JWTs, Bearer / Basic / Token credentials, URL userinfo,
    /// name=value pairs whose name is token, secret, password, key, signature, credential or authorization, and long unbroken
    /// base64url or hex runs (32+ characters). The result is cut to 256 UTF-16 units. A pattern list is a net, not a proof.
    public static func redactSecrets(_ text: String) -> String {
        var t = sub(text, jwt) { _, _ in "[redacted]" }
        t = sub(t, authorization) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]" }
        t = sub(t, scheme) { m, ns in ns.substring(with: m.range(at: 1)) + " [redacted]" }
        t = sub(t, userinfo) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]@" }
        t = sub(t, pair) { m, ns in
            let head = ns.substring(with: m.range(at: 1)), val = ns.substring(with: m.range(at: 2))
            let q = val.hasPrefix("\"") || val.hasPrefix("'") ? String(val.first!) : ""
            return head + q + "[redacted]" + q
        }
        t = sub(t, longRun) { _, _ in "[redacted]" }
        let ns = t as NSString
        guard ns.length > MAX_TEXT else { return t }
        var n = MAX_TEXT
        if UTF16.isLeadSurrogate(ns.character(at: n - 1)) { n -= 1 }
        return ns.substring(to: n) + "..."
    }

    // MARK: attributes

    static func finite(_ v: JSONValue?) -> JSONValue? {
        switch v {
        case .int?: return v
        case let .double(d)?: return d.isFinite ? v : nil
        default: return nil
        }
    }

    /// `x?.[0]` of the reference for the first deny reason: an array's first member, a string's first code unit, an object's "0" member.
    static func firstReason(_ result: JSONValue?) -> String? {
        switch result?.get("verdict")?.get("reasons") {
        case let .array(a)?: return a.first?.asString
        case let .string(s)?: return s.utf16.first.flatMap { UTF16.isLeadSurrogate($0) ? nil : String(utf16CodeUnits: [$0], count: 1) }
        case let .object(o)?: return o[JKey("0")]?.asString
        default: return nil
        }
    }

    /// The span attributes in the reference's insertion order.
    static func attributePairs(_ result: JSONValue?, _ redact: (String) -> String) -> [(String, JSONValue)] {
        let ok = result?.get("ok") == .bool(true)
        var out: [(String, JSONValue)] = [("pca.decision", .string(ok ? "allow" : "deny"))] // anything but an explicit allow is a deny
        if let s = finite(result?.get("status")) { out.append(("pca.status", s)) }
        if let t = finite(result?.get("verdict")?.get("requiredThreshold")?.get("t")) { out.append(("pca.tier", t)) }
        if let r = finite(result?.get("verdict")?.get("r")) { out.append(("pca.risk", r)) }
        let action = result?.get("pcactn")?.get("action")
        if let v = action?.get("verb")?.asString { out.append(("pca.verb", .string(redact(v)))) }
        if let r = action?.get("resource")?.asString { out.append(("pca.resource", .string(redact(r)))) }
        if !ok, let reason = firstReason(result) { out.append(("pca.reason", .string(redact(reason)))) }
        return out
    }

    /// Maps a guard result to span attributes; undefined fields are omitted and `pca.reason` is added on deny only.
    public static func pcaSpanAttributes(_ result: JSONValue?, redact: ((String) -> String)? = nil) -> JSONValue {
        var o: JObject = [:]
        for (k, v) in attributePairs(result, redact ?? redactSecrets) { o[JKey(k)] = v }
        return .object(o)
    }

    // MARK: guard

    /// Wraps a verification guard so each decision emits a span and metrics; the result is returned unchanged. Throws when the
    /// meter cannot create its instruments (as the reference does).
    public static func instrumentGuard(_ guardFn: @escaping (JSONValue) throws -> JSONValue, tracer: Tracer? = nil, meter: Meter? = nil,
                                       spanName: String? = nil, redact: ((String) -> String)? = nil) throws -> (JSONValue) throws -> JSONValue {
        let name = spanName ?? "pca.verify"
        let counter = try meter.map { try $0.createCounter("pca.verifications") }
        let histogram = try meter.map { try $0.createHistogram("pca.verify.risk") }
        let red = redact ?? redactSecrets
        // the decision is the guard's, not the exporter's
        func safe(_ f: () throws -> Void) { do { try f() } catch {} }

        return { req in
            var span: Span?
            safe { span = try tracer?.startSpan(name) }
            defer { if let sp = span { safe { try sp.end() } } }
            do {
                let result = try guardFn(req)
                let ok = result.get("ok") == .bool(true)
                if let sp = span {
                    safe {
                        for (k, v) in attributePairs(result, red) { try sp.setAttribute(k, v) }
                        if ok { try sp.setStatus(STATUS_OK, nil) } else { try sp.setStatus(STATUS_ERROR, firstReason(result).map(red)) }
                    }
                }
                let attrs = JSONValue.object(["decision": .string(ok ? "allow" : "deny")])
                safe { try counter?.apply(.int(1), attrs) }
                if let h = histogram, let risk = finite(result.get("verdict")?.get("r")) { safe { try h.apply(risk, attrs) } }
                return result
            } catch {
                if let sp = span {
                    safe {
                        // a fresh error: the original may carry credentials in its message, its cause or its stack
                        let msg = red((error as? JSError)?.message ?? "\(error)")
                        let raw = (error is JSError) ? "Error" : String(describing: type(of: error))
                        let nameOk = !raw.isEmpty && raw.utf8.count <= 64 && raw.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 95 }
                        try sp.recordException(nameOk ? raw : "Error", msg)
                        try sp.setStatus(STATUS_ERROR, msg)
                    }
                }
                throw error
            }
        }
    }
}
