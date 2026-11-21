import Foundation

/// Action receipts: the principal's own tamper-evident, hash-chained log of what their agents did and how each action was verified. Each receipt commits
/// to the previous one, so a dropped or altered entry is detectable. Pure (hashing only). A receipt is
/// `{seq, at, actionDigest, verb, resource, outcome: allow|deny, checks?, prev, hash}`.
public enum PCAReceipts {
    private static func body(_ r: JSONValue) -> JSONValue {
        let get = { (k: String) -> JSONValue in r.get(k) ?? .null }
        return .object(["d": .string("atlas-pca/receipt/v1"), "seq": get("seq"), "at": get("at"), "actionDigest": get("actionDigest"), "verb": get("verb"),
                        "resource": get("resource"), "outcome": get("outcome"), "checks": get("checks"), "prev": get("prev")])
    }

    private static func digest(_ v: JSONValue) throws -> String {
        guard let h = IV.strictHash(v) else { throw JSError("hashCanonical: value outside the strict profile") }
        return h
    }

    /// The next receipt in a chain for a verified action; `checks` may be nil, `at` may be nil (the action's `iat`).
    public static func receiptFor(prevHash: String, seq: Int64, pcactn: JSONValue, allow: Bool, checks: JSONValue? = nil, at: Double? = nil) throws -> JSONValue {
        guard let action = pcactn.get("action"), action.isObject else { throw JSError("receiptFor: the PCActn has no action") }
        var b: JObject = ["seq": .int(seq), "at": at.map { PCARiskBudgets.num($0) } ?? (pcactn.get("iat") ?? .null), "actionDigest": .string(try digest(pcactn)),
                          "verb": action.get("verb") ?? .null, "resource": action.get("resource") ?? .null, "outcome": .string(allow ? "allow" : "deny"),
                          "prev": .string(prevHash)]
        if let c = checks { b["checks"] = c }
        var r = b
        r["hash"] = .string(try digest(body(.object(b))))
        return .object(r)
    }

    /// A copy of `log` with the verified action appended, chained to the last entry.
    public static func appendReceipt(_ log: [JSONValue], pcactn: JSONValue, allow: Bool, checks: JSONValue? = nil, at: Double? = nil) throws -> [JSONValue] {
        let last = log.last
        let prev = last?.get("hash")?.asString ?? ""
        let seq = (last?.get("seq")?.safeInt).map { $0 + 1 } ?? 0
        return log + [try receiptFor(prevHash: prev, seq: seq, pcactn: pcactn, allow: allow, checks: checks, at: at)]
    }

    /// Verify a receipt log is an intact hash chain: `{ok}` or `{ok:false, brokenAt, reason}` for the first broken link.
    public static func verifyReceiptChain(_ log: [JSONValue]) -> JSONValue {
        var prev = ""
        func broken(_ r: JSONValue, _ reason: String) -> JSONValue {
            var m: JObject = ["ok": .bool(false), "reason": .string(reason)]
            if let s = r.get("seq") { m["brokenAt"] = s }
            return .object(m)
        }
        for (i, r) in log.enumerated() {
            let st = JS.toString(r.get("seq"))
            if !(IV.num(r.get("seq")) == Double(i) && r.get("seq")?.isNumber == true) { return broken(r, "seq \(st) out of order (expected \(i))") }
            if r.get("prev") != .string(prev) { return broken(r, "prev link mismatch at seq \(st)") }
            guard let h = try? digest(body(r)), r.get("hash") == .string(h) else { return broken(r, "hash mismatch at seq \(st) (tampered body)") }
            prev = h
        }
        return .object(["ok": .bool(true)])
    }

    /// The head hash of a log: one value that commits to the entire history ("" for an empty log).
    public static func receiptHead(_ log: [JSONValue]) -> String { log.last?.get("hash")?.asString ?? "" }
}
