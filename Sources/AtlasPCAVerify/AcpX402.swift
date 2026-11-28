import Foundation

/// x402 v2 alongside v1 (negotiated), its HTTP transport (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`: each the base64 of
/// a JSON object) and Stripe Shared Payment Granted Tokens, over the same JSON values as `Acp.swift`. Every validator returns the list
/// of problems (empty = valid); the encoders refuse an invalid object, the decoders refuse bad base64, bad JSON or an invalid object.
/// No I/O. Where the reference lists problems for the members of an object in insertion order, a parsed object has none, so the
/// members are listed index keys first, then by UTF-16 code unit.
extension PCAAcp {
    // ---- character classes (the reference's anchored regular expressions) ----

    static func shortAscii(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString else { return false }
        return JS.length(s) <= 32 && printable(s)
    }

    static func printable(_ s: String) -> Bool { s.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value <= 0x7e } }

    /// `^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$`.
    static func isCaip2(_ v: V) -> Bool {
        guard let s = v?.asString else { return false }
        let parts = s.utf8.split(separator: 0x3a, omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0].count >= 3, parts[0].count <= 8, parts[1].count >= 1, parts[1].count <= 32 else { return false }
        func low(_ c: UInt8) -> Bool { c == 0x2d || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) }
        func ref(_ c: UInt8) -> Bool { c == 0x2d || c == 0x5f || (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) }
        return parts[0].allSatisfy(low) && parts[1].allSatisfy(ref)
    }

    /// `^(0|[1-9][0-9]*)$`.
    static func isAtomic(_ v: V) -> Bool {
        guard let s = v?.asString else { return false }
        let b = Array(s.utf8)
        if b.isEmpty { return false }
        if b == [0x30] { return true }
        return b[0] >= 0x31 && b[0] <= 0x39 && b.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    /// `^[A-Za-z0-9+/]+={0,2}$`.
    static func isBase64Shape(_ s: String) -> Bool {
        var n = 0
        var pad = 0
        for c in s.utf8 {
            if c == 0x3d { pad += 1; if pad > 2 { return false } }
            else if pad > 0 { return false }
            else if (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c == 0x2b || c == 0x2f { n += 1 }
            else { return false }
        }
        return n >= 1
    }

    /// `new URL(u).protocol` is http: or https:.
    static func absoluteHttp(_ u: V) -> Bool {
        guard let s = u?.asString, let url = WhatwgURL.parse(s) else { return false }
        return url.scheme == "http" || url.scheme == "https"
    }

    /// `Object.keys` order of a parsed object: array-index keys ascending, then the rest by UTF-16 code unit.
    /// JavaScript's own-key order of an object: index keys ascending, then the others in the order the text gave them (the parser's member
    /// positions), so "the first header named like this" resolves as the reference's does.
    static func keyOrder(_ o: JObject) -> [String] { JS.keyOrder(o).map { $0.s } }

    // ---- x402 v2 ----

    /// Problems with a `ResourceInfo` (empty = valid).
    public static func resourceInfoProblems(_ r: JSONValue?) -> [String] {
        guard let o = r?.asObject else { return ["resource must be an object"] }
        var p: [String] = []
        if !absoluteHttp(o["url"]) { p.append("resource.url must be an absolute http(s) URL") }
        for k in ["description", "mimeType"] {
            if let v = o[JKey(k)], v.asString == nil { p.append("resource.\(k) must be a string") }
        }
        if let sn = o["serviceName"], !shortAscii(sn) {
            p.append("resource.serviceName must be printable ASCII up to 32 characters")
        }
        if let tags = o["tags"] {
            var ok = false
            if let l = tags.asArray { ok = l.count <= 5 && l.allSatisfy { shortAscii($0) } }
            if !ok { p.append("resource.tags must be up to 5 printable ASCII strings of up to 32 characters") }
        }
        if let icon = o["iconUrl"], !(absoluteHttp(icon) && JS.length(icon.asString ?? "") <= 2048) {
            p.append("resource.iconUrl must be an absolute http(s) URL up to 2048 characters")
        }
        return p
    }

    /// Problems with one v2 `PaymentRequirements` (empty = valid).
    public static func requirementV2Problems(_ q: JSONValue?) -> [String] {
        guard let o = q?.asObject else { return ["requirements must be an object"] }
        var p: [String] = []
        if !nonEmptyStr(o["scheme"]) { p.append("scheme is required") }
        if !isCaip2(o["network"]) { p.append("network must be a CAIP-2 identifier") }
        if !isAtomic(o["amount"]) || o["amount"] == .string("0") { p.append("amount must be a positive decimal string of atomic units") }
        if !nonEmptyStr(o["asset"]) { p.append("asset is required") }
        if !nonEmptyStr(o["payTo"]) { p.append("payTo is required") }
        let t = o["maxTimeoutSeconds"]
        if !P.safeInt(t) || (P.numOf(t) ?? 0) <= 0 { p.append("maxTimeoutSeconds must be a positive integer") }
        if let e = o["extra"], !e.isObject { p.append("extra must be an object") }
        return p
    }

    /// Problems with a v2 `PaymentRequired` (empty = valid).
    public static func paymentRequiredV2Problems(_ pr: JSONValue?) -> [String] {
        guard let o = pr?.asObject else { return ["PaymentRequired must be an object"] }
        var p: [String] = []
        if P.numOf(o["x402Version"]) != 2 { p.append("x402Version must be 2") }
        if let e = o["error"], e.asString == nil { p.append("error must be a string") }
        p.append(contentsOf: resourceInfoProblems(o["resource"]))
        if let acc = o["accepts"]?.asArray, !acc.isEmpty {
            for (i, q) in acc.enumerated() { p.append(contentsOf: requirementV2Problems(q).map { "accepts[\(i)].\($0)" }) }
        } else {
            p.append("accepts must be a non-empty array")
        }
        if let ex = o["extensions"] {
            if let eo = ex.asObject {
                for k in keyOrder(eo) {
                    let v = eo[JKey(k)]
                    if !(v?.isObject ?? false) || !(v?.get("info")?.isObject ?? false) || !(v?.get("schema")?.isObject ?? false) {
                        p.append("extensions.\(k) needs info and schema objects")
                    }
                }
            } else {
                p.append("extensions must be an object")
            }
        }
        return p
    }

    static func b64Encode(_ v: JSONValue) -> String { Data(Array(JS.stringify(v, order: ORDER).utf8)).base64EncodedString() }

    /// Decode like Node's `Buffer.from(v, 'base64')` behind the shape gate, then `JSON.parse` it.
    static func decodeHeader(_ value: V, _ name: String) throws -> JSONValue {
        guard let s = value?.asString, isBase64Shape(s) else { throw JSError("x402: \(name) is not base64") }
        guard let v = Attest.jsonLenient(Attest.nodeB64(s)) else { throw JSError("x402: \(name) is not JSON") }
        return IV.normalized(v)
    }

    static func encodeHeader(_ obj: V, _ problems: [String]) throws -> String {
        if !problems.isEmpty { throw JSError("x402: " + problems.joined(separator: "; ")) }
        return b64Encode(obj ?? .null)
    }

    static func decodeChecked(_ value: V, _ name: String, _ problems: (JSONValue?) -> [String]) throws -> JSONValue {
        let doc = try decodeHeader(value, name)
        let pr = problems(doc)
        if !pr.isEmpty { throw JSError("x402: " + pr.joined(separator: "; ")) }
        return doc
    }

    /// Encode a `PaymentRequired` for the `PAYMENT-REQUIRED` header (validates first; throws).
    public static func encodePaymentRequiredHeader(_ pr: JSONValue?) throws -> String { try encodeHeader(pr, paymentRequiredV2Problems(pr)) }

    /// Decode and validate a `PAYMENT-REQUIRED` header value.
    public static func decodePaymentRequiredHeader(_ value: JSONValue?) throws -> JSONValue {
        try decodeChecked(value, "PAYMENT-REQUIRED") { paymentRequiredV2Problems($0) }
    }

    /// The v2 402 challenge: the JSON body plus the base64 `PAYMENT-REQUIRED` header. Refuses anything the v2 spec makes invalid.
    public static func x402ChallengeV2(_ resource: JSONValue?, _ opts: JSONValue?) throws -> JSONValue {
        let amount = try P.prop(opts, "amount")
        if !isAmount(amount) { throw JSError("x402Challenge: amount must be a positive integer in atomic units") }
        let info: JSONValue = resource?.asString != nil ? .object(["url": resource ?? .null]) : .object(P.spreadObj(resource))
        var req: JObject = [:]
        req["scheme"] = JS.present(try P.prop(opts, "scheme")) ?? .string("exact")
        if let v = try P.prop(opts, "network") { req["network"] = v }
        req["amount"] = .string(P.tostr(amount))
        if let v = try P.prop(opts, "asset") { req["asset"] = v }
        if let v = try P.prop(opts, "payTo") { req["payTo"] = v }
        req["maxTimeoutSeconds"] = JS.present(try P.prop(opts, "maxTimeoutSeconds")) ?? .int(60)
        if let v = try P.prop(opts, "extra") { req["extra"] = v }
        var body: JObject = ["x402Version": .int(2), "resource": info, "accepts": .array([.object(req)])]
        body["error"] = JS.present(try P.prop(opts, "error")) ?? .string("PAYMENT-SIGNATURE header is required")
        if let v = try P.prop(opts, "extensions") { body["extensions"] = v }
        let header = try encodePaymentRequiredHeader(.object(body))
        return .object(["status": .int(402), "headers": .object(["Content-Type": .string("application/json"), "PAYMENT-REQUIRED": .string(header)]),
                        "body": .object(body)])
    }

    /// The highest x402 version both sides speak, or nil (answer 402 v1 with an error, never guess). `offered` is what the client says it
    /// speaks: omitted or empty means `[1]`; null is a TypeError, as in the reference.
    public static func x402Negotiate(_ offered: JSONValue?, supported: JSONValue? = nil) throws -> Int? {
        let sup: [JSONValue]
        switch supported {
        case nil: sup = [JSONValue.int(2), JSONValue.int(1)]
        case let .array(a)?: sup = a
        default: throw JSError("supported.filter is not a function")
        }
        var mine: [Int] = []
        for v in sup {
            if let d = P.numOf(v), d == 1 || d == 2 { mine.append(Int(d)) }
        }
        mine.sort(by: >)
        var list: [JSONValue]? = nil
        var text: String? = nil
        switch offered {
        case nil: list = [JSONValue.int(1)]
        case .null?: throw JSError("Cannot read properties of null (reading 'length')")
        case let .array(a)?: list = a.isEmpty ? [.int(1)] : a
        case let .string(s)?:
            if s.isEmpty { list = [JSONValue.int(1)] } else { text = s }
        case let .object(o)?:
            if let l = o["length"], P.numOf(l) == 0 { list = [JSONValue.int(1)] } else { throw JSError("theirs.includes is not a function") }
        default: throw JSError("theirs.includes is not a function")
        }
        for v in mine {
            if let l = list, l.contains(where: { P.numOf($0) == Double(v) }) { return v }
            if let t = text, strContains(t, String(v)) { return v }
        }
        return nil
    }

    /// `JSON.stringify` with the keys of every object sorted (the reference's `stable`).
    static func stable(_ v: JSONValue) -> String {
        switch v {
        case let .array(a): return "[" + a.map { stable($0) }.joined(separator: ",") + "]"
        case let .object(o):
            let keys = o.keys.map { $0.s }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            return "{" + keys.map { JS.stringify(.string($0)) + ":" + stable(o[JKey($0)] ?? .null) }.joined(separator: ",") + "}"
        default: return JS.stringify(v)
        }
    }

    /// True when `accepted` (echoed by the client in its v2 payload) is exactly one of the requirements the server offered.
    public static func x402AcceptedMatches(_ offered: JSONValue?, _ accepted: JSONValue?) throws -> Bool {
        if !requirementV2Problems(accepted).isEmpty { return false }
        let a = stable(accepted ?? .null)
        guard let list = offered?.asArray else { throw JSError("offered.some is not a function") }
        return list.contains { stable($0) == a }
    }

    /// Read a client payload of either version. v1: the token, merchant and amount are top-level members. v2: the token is `payload.token`
    /// and the echoed `accepted` must be a valid v2 requirement (the merchant is never read from a v2 payload and the amount only from
    /// `accepted.amount`). Anything else is `{ok: false}`.
    public static func normalizeX402Payload(_ raw: JSONValue?) -> JSONValue {
        func bad(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        guard let o = raw?.asObject else { return bad("x402 payment payload is not an object") }
        let ver = o["x402Version"]
        if P.numOf(ver) == 2 {
            guard let inner = o["payload"]?.asObject, let token = inner["token"]?.asString, !token.isEmpty else { return bad("x402 v2 payload is missing payload.token") }
            let problems = requirementV2Problems(o["accepted"])
            if !problems.isEmpty { return bad("x402 v2 payload.accepted is invalid: " + problems.joined(separator: "; ")) }
            let accepted = o["accepted"] ?? .null
            var out: JObject = ["ok": .bool(true), "version": .int(2), "token": .string(token), "accepted": accepted]
            if let d = Double(accepted.get("amount")?.asString ?? ""), P.safeF(d) { out["amount"] = .int(Int64(d)) }
            return .object(out)
        }
        if let v = ver, P.numOf(v) != 1 { return bad("unsupported x402Version \(P.tostr(v))") }
        guard let token = o["token"]?.asString else { return bad("x402 payment payload is missing a token") }
        var out: JObject = ["ok": .bool(true), "version": .int(1), "token": .string(token)]
        if let m = o["merchant"]?.asString { out["merchant"] = .string(m) }
        if let a = o["amount"], a.isNumber { out["amount"] = a }
        return .object(out)
    }

    // ---- x402 v2 HTTP transport ----

    /// Problems with a v2 `PaymentPayload` (empty = valid).
    public static func paymentPayloadV2Problems(_ p: JSONValue?) -> [String] {
        guard let o = p?.asObject else { return ["PaymentPayload must be an object"] }
        var out: [String] = []
        if P.numOf(o["x402Version"]) != 2 { out.append("x402Version must be 2") }
        if let r = o["resource"] { out.append(contentsOf: resourceInfoProblems(r)) }
        out.append(contentsOf: requirementV2Problems(o["accepted"]).map { "accepted.\($0)" })
        if !isObj(o["payload"]) { out.append("payload must be an object") }
        if let e = o["extensions"], !e.isObject { out.append("extensions must be an object") }
        return out
    }

    /// Problems with a `SettlementResponse` (empty = valid). A success must not carry an `errorReason`; a failure must.
    public static func settlementResponseProblems(_ r: JSONValue?) -> [String] {
        guard let o = r?.asObject else { return ["SettlementResponse must be an object"] }
        var out: [String] = []
        let success = o["success"], tx = o["transaction"], er = o["errorReason"]
        if !isBool(success) { out.append("success must be a boolean") }
        if let t = tx?.asString {
            if success == .bool(true) && t.isEmpty { out.append("a successful settlement needs a transaction") }
        } else {
            out.append("transaction must be a string")
        }
        if !isCaip2(o["network"]) { out.append("network must be a CAIP-2 identifier") }
        if let e = er, e.asString == nil { out.append("errorReason must be a string") }
        if success == .bool(true) && er != nil { out.append("errorReason must be omitted on success") }
        if success == .bool(false) && !nonEmptyStr(er) { out.append("errorReason is required on failure") }
        if let pa = o["payer"], pa.asString == nil { out.append("payer must be a string") }
        if let a = o["amount"], !isAtomic(a) { out.append("amount must be a decimal string of atomic units") }
        if let e = o["extensions"], !e.isObject { out.append("extensions must be an object") }
        return out
    }

    /// Encode a `PaymentPayload` for the `PAYMENT-SIGNATURE` request header (validates first; throws).
    public static func encodePaymentSignatureHeader(_ p: JSONValue?) throws -> String { try encodeHeader(p, paymentPayloadV2Problems(p)) }

    /// Decode and validate a `PAYMENT-SIGNATURE` header value.
    public static func decodePaymentSignatureHeader(_ value: JSONValue?) throws -> JSONValue {
        try decodeChecked(value, "PAYMENT-SIGNATURE") { paymentPayloadV2Problems($0) }
    }

    /// Encode a `SettlementResponse` for the `PAYMENT-RESPONSE` response header.
    public static func encodePaymentResponseHeader(_ r: JSONValue?) throws -> String { try encodeHeader(r, settlementResponseProblems(r)) }

    /// Decode and validate a `PAYMENT-RESPONSE` header value.
    public static func decodePaymentResponseHeader(_ value: JSONValue?) throws -> JSONValue {
        try decodeChecked(value, "PAYMENT-RESPONSE") { settlementResponseProblems($0) }
    }

    /// Server side: read the client's `PAYMENT-SIGNATURE` header (case-insensitive, first value of a list). A missing header is 402 (answer
    /// with a `PAYMENT-REQUIRED` challenge); a present but undecodable or invalid one is 400.
    public static func readPaymentSignature(_ headers: JSONValue?) throws -> JSONValue {
        var found: JSONValue? = nil
        switch headers {
        case nil, .null?: throw JSError("Cannot convert undefined or null to object")
        case let .object(o)?:
            let want = X402_PAYMENT_SIGNATURE_HEADER.lowercased()
            for k in keyOrder(o) where k.lowercased() == want {
                found = o[JKey(k)]
                break
            }
        default: break
        }
        if case let .array(a)? = found { found = a.first }
        if found == nil || found == .string("") {
            return .object(["ok": .bool(false), "status": .int(402), "reason": .string("PAYMENT-SIGNATURE header is required")])
        }
        do {
            return .object(["ok": .bool(true), "payload": try decodePaymentSignatureHeader(found)])
        } catch {
            return .object(["ok": .bool(false), "status": .int(400), "reason": .string((error as? JSError)?.message ?? "\(error)")])
        }
    }

    /// Server side: the status and `PAYMENT-RESPONSE` header for a settlement outcome (a success is 200 and needs the transaction; a failure
    /// is 402 with `success: false`, the reason and an empty transaction unless one was broadcast). Throws if the response would be invalid.
    public static func x402SettlementResponse(_ outcome: JSONValue?, _ network: JSONValue?) throws -> JSONValue {
        let settled = JS.truthy(try P.prop(outcome, "settled"))
        var body: JObject = [:]
        if settled {
            body["success"] = .bool(true)
            if let t = try P.prop(outcome, "transaction") { body["transaction"] = t }
            if let n = network { body["network"] = n }
            if let p = try P.prop(outcome, "payer") { body["payer"] = p }
            if let a = try P.prop(outcome, "amount") { body["amount"] = a }
        } else {
            body["success"] = .bool(false)
            if let r = try P.prop(outcome, "reason") { body["errorReason"] = r }
            body["transaction"] = JS.present(try P.prop(outcome, "transaction")) ?? .string("")
            if let n = network { body["network"] = n }
            if let p = try P.prop(outcome, "payer") { body["payer"] = p }
        }
        let header = try encodePaymentResponseHeader(.object(body))
        return .object(["status": .int(settled ? 200 : 402), "headers": .object([JKey(X402_PAYMENT_RESPONSE_HEADER): .string(header)])])
    }

    /// Client side: the request header to attach on the retry, from a payload built for an offered requirement.
    public static func x402PaymentSignatureHeaders(_ p: JSONValue?) throws -> JSONValue {
        .object([JKey(X402_PAYMENT_SIGNATURE_HEADER): .string(try encodePaymentSignatureHeader(p))])
    }

    // ---- Stripe Shared Payment Granted Tokens ----

    static func isCurrency(_ v: V) -> Bool {
        guard let b = v?.asString.map({ Array($0.utf8) }) else { return false }
        return b.count == 3 && b.allSatisfy { $0 >= 0x61 && $0 <= 0x7a }
    }

    /// `^spt_[A-Za-z0-9_]+$`.
    static func isSptId(_ v: V) -> Bool {
        guard let b = v?.asString.map({ Array($0.utf8) }), b.count > 4, Array(b[0..<4]) == Array("spt_".utf8) else { return false }
        return b[4...].allSatisfy { ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5f }
    }

    /// Problems with a Shared Payment Granted Token object (empty = well formed).
    public static func stripeSptProblems(_ t: JSONValue?) -> [String] {
        guard let o = t?.asObject else { return ["the token must be an object"] }
        var p: [String] = []
        if o["object"] != .string(STRIPE_SPT_OBJECT) { p.append("object must be \"\(STRIPE_SPT_OBJECT)\"") }
        if !isSptId(o["id"]) { p.append("id must be an spt_ identifier") }
        if !isInt(o["created"]) { p.append("created must be an integer timestamp") }
        if !isBool(o["livemode"]) { p.append("livemode must be a boolean") }
        if o["deactivated_at"] != .null && !isInt(o["deactivated_at"]) { p.append("deactivated_at must be null or an integer timestamp") }
        let dr = o["deactivated_reason"]
        if dr != .null && !(dr?.asString.map { ["consumed", "expired", "resolved", "revoked"].contains($0) } ?? false) {
            p.append("deactivated_reason must be null or one of consumed, expired, resolved, revoked")
        }
        if let u = o["usage_limits"]?.asObject {
            if !isCurrency(u["currency"]) { p.append("usage_limits.currency must be a lowercase three-letter code") }
            if !isInt(u["max_amount"]) || (P.numOf(u["max_amount"]) ?? 0) < 0 { p.append("usage_limits.max_amount must be a non-negative integer in minor units") }
            if let ea = u["expires_at"], ea != .null, !isInt(ea) { p.append("usage_limits.expires_at must be an integer timestamp") }
        } else {
            p.append("usage_limits is required")
        }
        if let ud = o["usage_details"], ud != .null {
            let c = ud.get("amount_captured")
            if !isObj(c) || !isInt(c?.get("value")) || (P.numOf(c?.get("value")) ?? 0) < 0 || !isCurrency(c?.get("currency")) {
                p.append("usage_details.amount_captured needs a non-negative integer value and a lowercase currency")
            }
        }
        for k in ["payment_method_details", "agent_details", "shared_metadata"] {
            if let v = o[JKey(k)], v != .null, !v.isObject { p.append("\(k) must be null or an object") }
        }
        if let pmd = o["payment_method_details"], pmd.isObject, pmd.get("type")?.asString == nil { p.append("payment_method_details.type must be a string") }
        return p
    }

    /// Parse a Shared Payment Granted Token; throws listing every problem.
    public static func parseStripeSpt(_ t: JSONValue?) throws -> JSONValue {
        let problems = stripeSptProblems(t)
        if !problems.isEmpty { throw JSError("stripe spt: " + problems.joined(separator: "; ")) }
        return t ?? .null
    }

    /// Can this token still be used for this capture (`use`: now in epoch seconds, amount in minor units, currency, livemode default true)?
    /// Refuses a malformed token, a deactivated or expired one, the wrong mode, a different currency, a non-integer amount and one above
    /// `max_amount` minus what was already captured.
    public static func stripeSptUsable(_ t: JSONValue?, _ use: JSONValue?) throws -> JSONValue {
        let problems = stripeSptProblems(t)
        if !problems.isEmpty { return no("malformed token: \(problems[0])") }
        let o = t?.asObject ?? [:]
        let nowV = try P.prop(use, "now"), amountV = try P.prop(use, "amount")
        guard isInt(nowV), isInt(amountV), let now = P.numOf(nowV), let amount = P.numOf(amountV), amount > 0 else {
            return no("now and amount must be integers and the amount positive")
        }
        let lm = JS.present(try P.prop(use, "livemode")) ?? .bool(true)
        if lm != o["livemode"] { return no("the token is in the wrong mode") }
        if let r = o["deactivated_reason"], r != .null { return no("the token is deactivated (\(P.tostr(r)))") }
        if let da = o["deactivated_at"], da != .null, (P.numOf(da) ?? 0) <= now { return no("the token is deactivated") }
        let lim = o["usage_limits"]?.asObject ?? [:]
        if let ea = lim["expires_at"], ea.isNumber, now >= (P.numOf(ea) ?? 0) { return no("the token has expired") }
        guard let cur = try P.prop(use, "currency")?.asString else { throw JSError("use.currency.toLowerCase is not a function") }
        if lim["currency"] != .string(cur.lowercased()) { return no("the capture currency differs from the token currency") }
        let captured = o["usage_details"]?.get("amount_captured")
        if let c = captured, c.get("currency") != lim["currency"] { return no("the captured amount is in another currency") }
        let remaining = (P.numOf(lim["max_amount"]) ?? 0) - (captured.flatMap { P.numOf($0.get("value")) } ?? 0)
        if amount > remaining { return no("the amount \(P.tostr(amountV)) exceeds the remaining \(P.tostr(P.num(remaining)))") }
        return .object(["ok": .bool(true)])
    }

    /// The `usage_limits` to request for a PCA authority: lowercase currency, integer minor units, expiry in whole seconds (rounded down).
    public static func stripeUsageLimitsFor(_ authority: JSONValue?) throws -> JSONValue {
        let ma = try P.prop(authority, "maxAmount")
        if !isInt(ma) || (P.numOf(ma) ?? 0) <= 0 { throw JSError("stripe spt: maxAmount must be a positive integer in minor units") }
        let cur = try P.prop(authority, "currency")
        guard let cs = cur?.asString, cs.utf8.count == 3, cs.utf8.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) }) else {
            throw JSError("stripe spt: currency must be a three-letter code")
        }
        let exp = try P.prop(authority, "expiresAtMs")
        if exp != nil && !(P.isFinite(exp) && (P.numOf(exp) ?? 0) > 0) { throw JSError("stripe spt: expiresAtMs must be a positive epoch-ms time") }
        var out: JObject = ["currency": .string(cs.lowercased()), "max_amount": ma ?? .null]
        if let e = P.numOf(exp) { out["expires_at"] = P.num((e / 1000).rounded(.down)) }
        return .object(out)
    }

    /// A Shared Payment Token may be no wider than the delegated payment token (and so the PCA proof) it serves: same currency,
    /// `max_amount` not above the delegated amount, and an expiry present and not after the delegated token's.
    public static func stripeSptWithinClaims(_ t: JSONValue?, _ claims: JSONValue?) throws -> JSONValue {
        let problems = stripeSptProblems(t)
        if !problems.isEmpty { return no("malformed token: \(problems[0])") }
        let lim = t?.get("usage_limits")?.asObject ?? [:]
        guard let cur = try P.prop(claims, "currency")?.asString else { throw JSError("claims.currency.toLowerCase is not a function") }
        if lim["currency"] != .string(cur.lowercased()) { return no("the token currency differs from the delegated currency") }
        let amount = try P.prop(claims, "amount"), exp = try P.prop(claims, "exp")
        if !P.isFinite(amount) || P.jsGt(lim["max_amount"], amount) { return no("max_amount \(P.tostr(lim["max_amount"])) exceeds the delegated amount \(P.tostr(amount))") }
        guard let ea = lim["expires_at"], ea.isNumber else { return no("the token has no expiry") }
        if !P.isFinite(exp) || P.jsGt(P.num((P.numOf(ea) ?? 0) * 1000), exp) { return no("the token outlives the delegated payment token") }
        return .object(["ok": .bool(true)])
    }
}
