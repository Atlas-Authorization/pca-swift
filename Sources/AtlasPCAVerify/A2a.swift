import Foundation

/// The A2A binding (verification side): typed needs (`pca_need`), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption,
/// push-token binding and signed task-update receipts. Total. Per-hop PCActn verification is the ordinary verifier's job; this is what
/// surrounds it. Replays packages/pca/conformance/a2a-vectors.json.
public enum A2a {
    public static let RECEIPT_DOMAIN = "atlas-pca/a2a-receipt/v1\u{0}"
    static let NEED_MEMBERS: Set<String> = ["v", "kind", "verb", "resource", "scopes", "grant_ref", "limits", "discharges", "tier", "policy_digest"]
    static let TERMINAL: Set<String> = ["TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"]
    static let STATES: Set<String> = TERMINAL.union(["TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"])

    static func number(_ v: JSONValue?) -> Double? {
        switch v { case let .int(i)?: return Double(i); case let .double(d)?: return d.isFinite ? d : nil; default: return nil }
    }

    /// nil when valid, else the refusal code.
    public static func needError(_ v: JSONValue?) -> String? {
        guard let x = v?.asObject else { return "bad_shape" }
        if x.keys.contains(where: { !NEED_MEMBERS.contains($0.s) }) { return "unknown_member" }
        guard number(x[JKey("v")]) == 1 else { return "bad_version" }
        guard let kind = x[JKey("kind")]?.asString, ["scope", "grant", "discharge", "escalate"].contains(kind) else { return "bad_kind" }
        guard K3Sig.str(x[JKey("verb")], 128) != nil, K3Sig.str(x[JKey("resource")], 512) != nil else { return "bad_field" }
        if let sc = x[JKey("scopes")] {
            guard let a = sc.asArray, a.count <= 16, a.allSatisfy({ K3Sig.str($0, 128) != nil && !($0.asString ?? "").unicodeScalars.contains(where: { $0.properties.isWhitespace }) }) else { return "bad_field" }
        }
        for k in ["grant_ref", "policy_digest"] { if let g = x[JKey(k)], K3Sig.str(g, 128) == nil { return "bad_field" } }
        if let t = x[JKey("tier")] {
            guard let tv = number(t), tv == 2 || tv == 3, kind == "escalate" else { return "bad_field" }
        }
        if let l = x[JKey("limits")] {
            guard let o = l.asObject, o.count <= 16, o.allSatisfy({ K3Sig.str(.string($0.key.s), 64) != nil && (number($0.value) ?? -1) >= 0 }) else { return "bad_field" }
        }
        if let d = x[JKey("discharges")] {
            guard let a = d.asArray, a.count <= 16, a.allSatisfy({ e in
                guard let o = e.asObject else { return false }
                return o.keys.allSatisfy { $0.s == "issuer" || $0.s == "claim" } && K3Sig.str(o[JKey("issuer")], 512) != nil && K3Sig.str(o[JKey("claim")], 256) != nil
            }) else { return "bad_field" }
        }
        if kind == "escalate" && x[JKey("tier")] == nil { return "bad_field" }
        return nil
    }

    /// The decoded need, or the refusal code.
    public static func decodeNeed(_ value: JSONValue?) -> (need: JSONValue?, code: String?) {
        guard let s = value?.asString, !s.isEmpty else { return (nil, "bad_base64") }
        if s.utf8.count > 2048 { return (nil, "too_long") }
        guard let raw = Base64URLStrict.decode(s) else { return (nil, "bad_base64") }
        guard let text = String(validatingUTF8: raw.map { CChar(bitPattern: $0) } + [0]), text.utf8.count == raw.count else { return (nil, "bad_utf8") }
        guard let parsed = try? StrictJSON.parse(text) else { return (nil, "bad_json") }
        if let code = needError(parsed) { return (nil, code) }
        return (parsed, nil)
    }

    public static func needDigest(_ need: JSONValue) -> String {
        Canonical.hashCanonical(.object([JKey("d"): .string("atlas-pca/need/v1"), JKey("need"): need]))
    }

    /// Every hop has a chain and each extends the one before it: (failedHop, reason) or nil.
    public static func checkChainExtension(_ chains: [[String]]) -> (failedHop: Int, reason: String)? {
        for (i, ids) in chains.enumerated() {
            if ids.isEmpty { return (i, "no_chain") }
            if i > 0 {
                let prev = chains[i - 1]
                if ids.count < prev.count || Array(ids.prefix(prev.count)) != prev { return (i, "chain_does_not_extend_previous_hop") }
            }
        }
        return nil
    }

    /// nil when the full verifier may now be asked, else the refusal code.
    public static func resumeGate(state: String?, needEncoded: JSONValue?, answerDigest: String?, proofVerb: String?, proofResource: String?) -> String? {
        guard state == "TASK_STATE_AUTH_REQUIRED" || state == "auth-required" else { return "task_not_auth_required" }
        guard let ne = needEncoded, !ne.isNull, let need = decodeNeed(ne).need else { return "no_valid_need" }
        guard answerDigest == needDigest(need) else { return "answer_not_bound_to_need" }
        guard let pv = proofVerb, let pr = proofResource else { return "no_proof" }
        if pv != need.get("verb")?.asString || pr != need.get("resource")?.asString { return "action_mismatch" }
        return nil
    }

    /// nil where the reference throws (a salt shorter than 16 characters).
    public static func pushToken(taskId: String, chainIds: [String], salt: String) -> String? {
        if salt.unicodeScalars.reduce(0, { $0 + ($1.value > 0xFFFF ? 2 : 1) }) < 16 { return nil }
        return Canonical.hashCanonical(.object([JKey("d"): .string("atlas-pca/a2a-push/v1"), JKey("task_id"): .string(taskId),
                                                JKey("chain"): .string(PcaGrant.chainDigest(chainIds)), JKey("salt"): .string(salt)]))
    }

    /// nil when ok, else the reason.
    public static func checkPush(taskId: String, chainIds: [String], salt: String, token: JSONValue?, payload: JSONValue?) -> String? {
        guard let t = token?.asString, !t.isEmpty else { return "no_token" }
        guard let want = pushToken(taskId: taskId, chainIds: chainIds, salt: salt), want == t else { return "token_mismatch" }
        for (key, field) in [("task", "id"), ("statusUpdate", "taskId"), ("artifactUpdate", "taskId")] {
            if let c = payload?.get(key), let v = c.get(field), !v.isNull { return v.asString == taskId ? nil : "task_mismatch" }
        }
        return "task_mismatch"
    }

    public static func receiptDigest(_ r: JSONValue) -> String {
        Canonical.hashCanonical(.object([JKey("d"): .string("atlas-pca/a2a-receipt-ref/v1"), JKey("r"): r]))
    }

    public static func verifyReceipt(_ v: JSONValue?, signer: String) -> Bool {
        guard let r = v?.asObject, number(r[JKey("v")]) == 1, r[JKey("signer")]?.asString == signer,
              K3Sig.str(r[JKey("task_id")], 4096) != nil, let st = r[JKey("state")]?.asString, STATES.contains(st),
              let seq = K3Sig.safeInt(r[JKey("seq")]), K3Sig.safeInt(r[JKey("issued_at")]) != nil,
              let c = r[JKey("chain")]?.asString, Base64URLStrict.decode(c, length: 32) != nil else { return false }
        let prev = r[JKey("prev")]
        let prevNull = prev == nil || prev!.isNull
        if !prevNull {
            guard let p = prev?.asString, Base64URLStrict.decode(p, length: 32) != nil else { return false }
        }
        if (seq == 0) != prevNull { return false }
        var body: JObject = [:]
        for k in ["v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer"] { body[JKey(k)] = r[JKey(k)] ?? .null }
        return K3Sig.verifyBody(RECEIPT_DOMAIN, .object(body), signer: signer, sig: r[JKey("sig")])
    }

    public struct ReceiptChain: Equatable {
        public var ok: Bool
        public var code: String? = nil
        public var at: Int = -1
        public var terminal = false
        public var lastState: String? = nil
    }

    public static func checkReceiptChain(_ receipts: [JSONValue], signer: String, taskId: String, chainIds: [String]) -> ReceiptChain {
        if receipts.isEmpty { return ReceiptChain(ok: false, code: "empty") }
        let chain = PcaGrant.chainDigest(chainIds)
        var prev: JObject?
        for (i, x) in receipts.enumerated() {
            guard verifyReceipt(x, signer: signer), let r = x.asObject else { return ReceiptChain(ok: false, code: "bad_receipt", at: i) }
            if r[JKey("task_id")]?.asString != taskId { return ReceiptChain(ok: false, code: "wrong_task", at: i) }
            if r[JKey("chain")]?.asString != chain { return ReceiptChain(ok: false, code: "wrong_chain", at: i) }
            let seq = K3Sig.safeInt(r[JKey("seq")]) ?? -1
            if let p = prev {
                if TERMINAL.contains(p[JKey("state")]?.asString ?? "") { return ReceiptChain(ok: false, code: "after_terminal", at: i) }
                if seq != (K3Sig.safeInt(p[JKey("seq")]) ?? -2) + 1 || r[JKey("prev")]?.asString != receiptDigest(.object(p)) { return ReceiptChain(ok: false, code: "broken_link", at: i) }
            } else if seq != 0 {
                return ReceiptChain(ok: false, code: "bad_start", at: i)
            }
            prev = r
        }
        let last = prev?[JKey("state")]?.asString ?? ""
        return ReceiptChain(ok: true, terminal: TERMINAL.contains(last), lastState: last)
    }

    public static func mayTriggerNext(_ receipts: [JSONValue], signer: String, taskId: String, chainIds: [String]) -> Bool {
        let r = checkReceiptChain(receipts, signer: signer, taskId: taskId, chainIds: chainIds)
        return r.ok && r.lastState == "TASK_STATE_COMPLETED"
    }
}
