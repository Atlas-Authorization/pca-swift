import Foundation

// UNDO WINDOWS (0.5): reversible actions execute at once and the principal gets a veto window in which they can undo them. This is
// the PURE, language-neutral layer of the TypeScript reference (`undo.ts`; vectors conformance/undo-vectors.json): the compensation
// digest, the signed one-click undo token, the signed hash-chained receipts, the record state machine and the window clamp. The
// coordinator (admission, ledger writes, compensation, notification) runs in the TypeScript coordinator or the hosted ledger;
// `PCA.authorize` reaches it through its `undo` admission hook.
//
//     open --veto (now <= window_end)--> vetoed --compensated--> compensated
//       |                                  |  \--compensation_failed--> compensation_failed --retry--> vetoed
//       |                                  |                                   \--compensated--> compensated
//       +--finalize (now > window_end)--> finalized
//       +--abort (the effect never ran)--> finalized
//
// Every function is total and never throws on its inputs (the signers throw on a missing or malformed key or record).

/// The admission `PCA.authorize`'s `undo` hook returns: the record the caller's undo coordinator has DURABLY opened for this action,
/// its window end (epoch ms) and the compensating action.
public struct UndoAdmission: Equatable, Sendable {
    /// The undo record id (the original operation id; at most 128 characters to ride in the `undo_window` obligation).
    public var id: String
    public var windowEnd: Int64
    public var compensationVerb: String
    public var compensationResource: String

    public init(id: String, windowEnd: Int64, compensationVerb: String, compensationResource: String) {
        self.id = id
        self.windowEnd = windowEnd
        self.compensationVerb = compensationVerb
        self.compensationResource = compensationResource
    }

    /// The obligation the allowed result carries: `{kind: "undo_window", params: {id, window_end}, due: window_end}`.
    public var obligation: JSONValue {
        .object(["kind": .string("undo_window"), "params": .object(["id": .string(id), "window_end": .int(windowEnd)]), "due": .int(windowEnd)])
    }
}

/// What the `undo` hook is asked about: the presented PCActn, the stored grant and the bound operation.
public struct UndoAdmitRequest {
    public let pcactn: JSONValue
    public let grant: JSONValue
    public let operation: PCA.Operation
}

/// The result of `Undo.transition`: `applied` (the next record, version bumped; the receipt to sign and append), `replayed` (the same
/// transition already happened: nothing to write) or `refused` (`code`).
public struct UndoTransition: Equatable, Sendable {
    public let outcome: String
    public let code: String?
    public let reason: String?
    /// The next record (applied) or the stored one (replayed).
    public let record: JSONValue?
    /// The receipt event and note of an applied transition.
    public let event: String?
    public let note: String?
}

public enum Undo {
    public static let TOKEN_DOMAIN = "atlas-pca/undo-token/v1\u{0}"
    public static let RECEIPT_DOMAIN = "atlas-pca/undo-receipt/v1\u{0}"
    public static let COMPENSATION_DOMAIN = "atlas-pca/undo-compensation/v1"
    public static let RECEIPT_REF_DOMAIN = "atlas-pca/undo-receipt-ref/v1"
    public static let TOKEN_REF_DOMAIN = "atlas-pca/undo-token-ref/v1"
    public static let TOKEN_KIND = "pca-undo-token"
    public static let RECEIPT_KIND = "pca-undo-receipt"
    /// The realistic floor of a veto window: a human must be able to react.
    public static let MIN_WINDOW_MS: Int64 = 30_000
    public static let DEFAULT_WINDOW_MS: Int64 = 900_000
    public static let MAX_WINDOW_MS: Int64 = 86_400_000
    public static let STATES = ["open", "vetoed", "compensated", "compensation_failed", "finalized"]
    public static let EVENTS = ["opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect"]
    public static let VETO_VIAS = ["token", "operator", "fraud_proof", "revocation"]
    static let TOKEN_MEMBERS = ["v", "kind", "record", "aud", "principal", "compensation_digest", "render_digest", "exp", "signer", "sig"]
    static let RECEIPT_BODY_MEMBERS = ["v", "kind", "record", "event", "state", "at", "compensation_digest", "prev", "note", "signer"]

    /// A record id: a string of 1..256 UTF-16 code units without control characters (U+0000..U+001F).
    static func idOk(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString else { return false }
        return IV.u16(s) >= 1 && IV.u16(s) <= 256 && !s.unicodeScalars.contains { $0.value < 0x20 }
    }

    /// Both values are strings with the same code points (a missing or non-string value is never equal).
    static func eqStr(_ a: JSONValue?, _ b: JSONValue?) -> Bool { IV.same(a?.asString, b?.asString) }

    static func body(_ o: JObject, _ members: [String]) -> JSONValue {
        var b: JObject = [:]
        for k in members { b[JKey(k)] = o[JKey(k)] }
        return .object(b)
    }

    // ---- digests ----

    /// `hashCanonical({d, verb, resource, params, undo_of, def_digest, target_param?})`; nil for a malformed compensation.
    public static func compensationDigest(_ c: JSONValue) -> String? {
        guard case let .object(o) = c, let verb = o["verb"], let resource = o["resource"], let params = o["params"], let undoOf = o["undo_of"],
              let def = o["def_digest"] else { return nil }
        var d: JObject = ["d": .string(COMPENSATION_DOMAIN), "verb": verb, "resource": resource, "params": params, "undo_of": undoOf, "def_digest": def]
        if let t = o["target_param"] { d["target_param"] = t }
        return IV.strictHash(.object(d))
    }

    // ---- the one-click undo token ----

    /// Sign the token for a record `{id, aud, principal, compensation_digest, render_digest?, window_end}` with the undo service key.
    public static func signToken(record: JSONValue, key: PCAEdKey) throws -> JSONValue {
        guard case let .object(r) = record, idOk(r["id"]), let aud = r["aud"]?.asString, let principal = r["principal"]?.asString,
              let cd = r["compensation_digest"]?.asString, let end = IV.int(r["window_end"]) else { throw PCAProducerError("signUndoToken: malformed record") }
        let body: JObject = ["v": .int(1), "kind": .string(TOKEN_KIND), "record": r["id"]!, "aud": .string(aud), "principal": .string(principal),
                             "compensation_digest": .string(cd), "render_digest": .string(r["render_digest"]?.asString ?? ""), "exp": .int(end), "signer": .string(key.id)]
        var t = body
        t["sig"] = .string(try PCAIssue.signBody(key, domain: TOKEN_DOMAIN, body: .object(body)))
        return .object(t)
    }

    /// The first check a token fails, in order: `malformed`, `signer` (not the pinned undo service key), `signature`, `record`,
    /// `binding` (aud, principal, compensation, render, window end), `expired` (`now > exp`, or `now` not a safe integer; valid THROUGH
    /// exp); `ok` when none.
    public static func tokenCheck(_ token: JSONValue?, expectedSigner: String, record: JSONValue, now: Double) -> String {
        guard case let .object(t)? = token, t.count == TOKEN_MEMBERS.count, TOKEN_MEMBERS.allSatisfy({ t[JKey($0)] != nil }) else { return "malformed" }
        guard IV.num(t["v"]) == 1, eqStr(t["kind"], .string(TOKEN_KIND)), idOk(t["record"]), t["aud"]?.asString != nil, t["principal"]?.asString != nil,
              t["compensation_digest"]?.asString != nil, t["render_digest"]?.asString != nil, let exp = IV.int(t["exp"]), t["signer"]?.asString != nil,
              let sig = t["sig"]?.asString, Base64URLStrict.isValid(sig, length: 64) else { return "malformed" }
        if !eqStr(t["signer"], .string(expectedSigner)) { return "signer" }
        guard let msg = IV.message(TOKEN_DOMAIN, body(t, Array(TOKEN_MEMBERS.dropLast()))), Ed25519Strict.verifyB64u(expectedSigner, msg, sig) else { return "signature" }
        let rec = record.asObject ?? [:]
        if !eqStr(t["record"], rec["id"]) { return "record" }
        var render: JSONValue = .string("")
        if let rd = rec["render_digest"], rd != .null { render = rd }
        guard eqStr(t["aud"], rec["aud"]), eqStr(t["principal"], rec["principal"]), eqStr(t["compensation_digest"], rec["compensation_digest"]),
              eqStr(t["render_digest"], render), let end = IV.num(rec["window_end"]), Double(exp) == end else { return "binding" }
        if !IV.isSafeDouble(now) || IV.isNegZero(now) || now > Double(exp) { return "expired" }
        return "ok"
    }

    /// The token as a URL-safe string (base64url of its strict-canonical JSON) for a one-click link; nil outside the strict profile.
    public static func encodeToken(_ t: JSONValue) -> String? { IV.strictCanon(t).map { Base64URLStrict.encode(Canonical.utf8($0)) } }

    /// Inverse of `encodeToken`: nil for anything that is not a non-empty string of at most 4096 characters holding strict base64url
    /// of UTF-8 JSON text of an object.
    public static func decodeToken(_ s: String) -> JSONValue? {
        guard !s.isEmpty, IV.u16(s) <= 4096, let bytes = Base64URLStrict.decode(s), let text = PcaGuard.utf8Text(bytes),
              let v = JSONValue.parse(text), v.isObject else { return nil }
        return v
    }

    public static func tokenDigest(_ t: JSONValue) -> String? { IV.strictHash(.object(["d": .string(TOKEN_REF_DOMAIN), "t": t])) }

    // ---- receipts ----

    /// The content address of a receipt (signature included): the next receipt's `prev`.
    public static func receiptDigest(_ r: JSONValue) -> String? { IV.strictHash(.object(["d": .string(RECEIPT_REF_DOMAIN), "r": r])) }

    /// Sign the receipt of one transition (`state` is the state AFTER `event`; `prev` the previous receipt's digest, '' for the first).
    public static func signReceipt(record: String, event: String, state: String, at: Int64, compensationDigest: String, prev: String, note: String,
                                   key: PCAEdKey) throws -> JSONValue {
        let b: JObject = ["v": .int(1), "kind": .string(RECEIPT_KIND), "record": .string(record), "event": .string(event), "state": .string(state), "at": .int(at),
                          "compensation_digest": .string(compensationDigest), "prev": .string(prev), "note": .string(note), "signer": .string(key.id)]
        var r = b
        r["sig"] = .string(try PCAIssue.signBody(key, domain: RECEIPT_DOMAIN, body: .object(b)))
        guard verifyReceipt(.object(r), expectedSigner: key.id) else { throw PCAProducerError("signUndoReceipt: malformed receipt") }
        return .object(r)
    }

    /// True iff `r` is well formed (exactly its 11 members, known event and state, a valid record id) and signed by `expectedSigner`.
    public static func verifyReceipt(_ rv: JSONValue?, expectedSigner: String) -> Bool {
        guard case let .object(r)? = rv else { return false }
        guard IV.num(r["v"]) == 1, eqStr(r["kind"], .string(RECEIPT_KIND)), idOk(r["record"]), r["event"]?.asString.map({ IV.contains(EVENTS, $0) }) == true,
              r["state"]?.asString.map({ IV.contains(STATES, $0) }) == true, IV.int(r["at"]) != nil, r["compensation_digest"]?.asString != nil,
              r["prev"]?.asString != nil, r["note"]?.asString != nil, eqStr(r["signer"], .string(expectedSigner)),
              let sig = r["sig"]?.asString, Base64URLStrict.isValid(sig, length: 64), r.count == 11 else { return false }
        guard let msg = IV.message(RECEIPT_DOMAIN, body(r, RECEIPT_BODY_MEMBERS)) else { return false }
        return Ed25519Strict.verifyB64u(expectedSigner, msg, sig)
    }

    /// A record's receipt chain `{id, compensation_digest, state, receipts}`: nil when every receipt verifies, names this record and its
    /// compensation, links `prev` to the previous receipt ('' for the first), the first is `opened`, `at` never decreases and the last
    /// state is the record's state; else the reason.
    public static func receiptChainError(_ record: JSONValue, expectedSigner: String) -> String? {
        guard case let .array(rs)? = record.get("receipts"), !rs.isEmpty else { return "no receipts" }
        var prev = ""
        var at: Int64 = .min
        for (i, r) in rs.enumerated() {
            if !verifyReceipt(r, expectedSigner: expectedSigner) { return "receipt \(i) does not verify" }
            if !eqStr(r.get("record"), record.get("id")) || !eqStr(r.get("compensation_digest"), record.get("compensation_digest")) { return "receipt \(i) is for another record" }
            if !eqStr(r.get("prev"), .string(prev)) { return "receipt \(i) does not link to the previous one" }
            if i == 0 && !eqStr(r.get("event"), .string("opened")) { return "the first receipt is not opened" }
            let t = IV.int(r.get("at")) ?? .min
            if t < at { return "receipt \(i) goes back in time" }
            guard let d = receiptDigest(r) else { return "receipt \(i) is outside the strict JSON profile" }
            prev = d
            at = t
        }
        return eqStr(rs[rs.count - 1].get("state"), record.get("state")) ? nil : "the last receipt does not state the record state"
    }

    // ---- the pure transitions ----

    /// `String(x).slice(0, n)` over UTF-16 code units (a surrogate pair is never split).
    static func jsSlice(_ s: String, _ n: Int) -> String {
        var out = String.UnicodeScalarView()
        var units = 0
        for c in s.unicodeScalars {
            units += c.utf16.count
            if units > n { break }
            out.append(c)
        }
        return String(out)
    }

    /// The state machine, pure: `record` is not modified; an applied transition returns the next record (version bumped; its receipt
    /// is NOT appended: the store signs and links it). `event` is `{kind: veto|finalize|abort|effect|compensated|compensation_failed|
    /// retry, ...}`; `now` is the trusted server clock (epoch ms; anything but a safe integer is `invalid`). Total; never throws.
    public static func transition(_ recordValue: JSONValue, _ event: JSONValue, now nowIn: Double) -> UndoTransition {
        func refused(_ code: String, _ reason: String) -> UndoTransition {
            UndoTransition(outcome: "refused", code: code, reason: reason, record: nil, event: nil, note: nil)
        }
        guard case let .object(rec) = recordValue, let state = rec["state"]?.asString, IV.contains(STATES, state), let windowEnd = IV.int(rec["window_end"]),
              let ver = IV.int(rec["ver"]) else { return refused("invalid", "malformed record") }
        guard IV.isSafeDouble(nowIn), !IV.isNegZero(nowIn) else { return refused("invalid", "now must be a safe integer") }
        let now = Int64(nowIn)
        let replayed = UndoTransition(outcome: "replayed", code: nil, reason: nil, record: recordValue, event: nil, note: nil)
        func next(_ patch: JObject, _ ev: String, _ note: String = "") -> UndoTransition {
            var r = rec
            for (k, v) in patch { r[k] = v }
            r["ver"] = .int(ver + 1)
            return UndoTransition(outcome: "applied", code: nil, reason: nil, record: .object(r), event: ev, note: note)
        }
        func outcome(_ status: String, _ extra: JObject = [:]) -> JSONValue {
            var o: JObject = ["at": .int(now), "status": .string(status)]
            for (k, v) in extra { o[k] = v }
            return .object(o)
        }
        let effectRecorded = rec["effect"] != nil
        switch event.get("kind")?.asString {
        case "veto"?:
            guard case let .object(v)? = event.get("veto"), IV.int(v["at"]) != nil, let via = v["via"]?.asString, IV.contains(VETO_VIAS, via),
                  let by = v["by"]?.asString, !by.isEmpty else { return refused("invalid", "malformed veto") }
            if ["vetoed", "compensated", "compensation_failed"].contains(state) { return replayed }
            if state == "finalized" { return refused("finalized", "the window is closed and the action is final") }
            if now > windowEnd { return refused("window_closed", "the veto window closed at \(windowEnd)") }
            return next(["state": .string("vetoed"), "veto": .object(v)], "vetoed", via)
        case "finalize"?:
            if state == "finalized" { return replayed }
            if state != "open" { return refused("vetoed", "a \(state) record is not finalized") }
            if now <= windowEnd { return refused("window_open", "the veto window is open until \(windowEnd)") }
            return next(["state": .string("finalized"), "outcome": outcome("finalized")], "finalized")
        case "abort"?:
            if state == "finalized" && IV.same(rec["outcome"]?.get("status")?.asString, "aborted") { return replayed }
            if state != "open" && state != "vetoed" { return refused("finalized", "a \(state) record cannot be aborted") }
            if effectRecorded { return refused("effect_recorded", "the effect ran: it can only be compensated or finalized") }
            let why = IntentWB.jsOpt(event.get("reason"))
            return next(["state": .string("finalized"), "outcome": outcome("aborted", ["reason": .string(jsSlice(why, 512))])], "aborted", jsSlice(why, 128))
        case "effect"?:
            if effectRecorded { return replayed }
            if state != "open" && state != "vetoed" { return refused("finalized", "a \(state) record takes no effect report") }
            var e: JObject = ["at": .int(now)]
            if let r = event.get("result") { e["result"] = r }
            return next(["effect": .object(e)], "effect")
        case "compensated"?:
            if state == "compensated" { return replayed }
            if state != "vetoed" && state != "compensation_failed" { return refused("not_vetoed", "a \(state) record is not being compensated") }
            var extra: JObject = [:]
            if let r = event.get("result") { extra["result"] = r }
            return next(["state": .string("compensated"), "outcome": outcome("compensated", extra)], "compensated")
        case "compensation_failed"?:
            if state == "compensation_failed" { return replayed }
            if state != "vetoed" { return refused("not_vetoed", "a \(state) record is not being compensated") }
            let why = IntentWB.jsOpt(event.get("reason"))
            return next(["state": .string("compensation_failed"), "outcome": outcome("compensation_failed", ["reason": .string(jsSlice(why, 512))])],
                        "compensation_failed", jsSlice(why, 128))
        case "retry"?:
            if state != "compensation_failed" { return refused("not_failed", "a \(state) record is not retried") }
            guard let attempt = IV.int(rec["attempt"]) else { return refused("invalid", "malformed record") }
            return next(["state": .string("vetoed"), "attempt": .int(attempt + 1)], "retried")
        default:
            return refused("invalid", "unknown event")
        }
    }

    /// Clamp a requested window into [max(MIN_WINDOW_MS, minMs), min(maxMs, MAX_WINDOW_MS)] (never below the lower bound); absent or
    /// non-finite -> `defaultMs` (default 15 minutes). Non-finite policy values count as absent.
    public static func resolveWindow(_ requestedMs: Double?, minMs: Double? = nil, maxMs: Double? = nil, defaultMs: Double? = nil) -> Int64 {
        func fin(_ x: Double?) -> Double? { x.flatMap { $0.isFinite ? $0 : nil } }
        let lo = Swift.max(Double(MIN_WINDOW_MS), fin(minMs) ?? Double(MIN_WINDOW_MS))
        let hi = Swift.max(lo, Swift.min(fin(maxMs) ?? Double(MAX_WINDOW_MS), Double(MAX_WINDOW_MS)))
        let want = fin(requestedMs) ?? fin(defaultMs) ?? Double(DEFAULT_WINDOW_MS)
        return Int64(Swift.min(Swift.min(hi, Swift.max(lo, want)).rounded(.down), Double(Canonical.MAX_SAFE)))
    }
}
