import Foundation

/// The policy side of detector receipts: which gateway keys the verifier pins, and the tighten-only fold of a list of receipts into a signal. The one
/// rule: `suspicious` may lower a decision, `no_finding` is exactly equivalent to no receipt at all (requiring one would let a clean scan, or a bypassed
/// detector, buy back authority the policy withheld). A receipt that fails verification is not evidence of anything: it raises `escalate`, never `ok`.
extension PCADetectorReceipt {
    public static let MAX_DETECTOR_RECEIPTS = 32

    /// nil when the policy `{detectors: [{id, keys: [{pk, pq_pk?}], on_suspicious, max_age_ms, categories?}]}` is well-formed.
    public static func detectorPolicyError(_ p: JSONValue?) -> String? {
        guard let po = p?.asObject, IntentWB.closedMembers(po, ["detectors"]) else { return "policy must be {detectors}" }
        guard let ds = po["detectors"]?.asArray, ds.count <= 16 else { return "detectors must hold at most 16 entries" }
        var ids: [String] = []
        for d in ds {
            guard let o = d.asObject, IntentWB.closedMembers(o, ["id", "keys", "on_suspicious", "max_age_ms"], ["categories"]) else { return "detector entry is malformed" }
            guard let id = o["id"]?.asString, idOk(id), !IV.same(id, "invalid"), !ids.contains(where: { IV.same($0, id) }) else { return "detector ids must be distinct ids other than \"invalid\"" }
            ids.append(id)
            guard let keys = o["keys"]?.asArray, keys.count >= 1, keys.count <= 8,
                  keys.allSatisfy({ k in k.asObject != nil && k.get("pk")?.asString != nil && (k.asObject?[JKey("pq_pk")].map { $0.asString != nil } ?? true) })
            else { return "detector '\(id)': keys must hold 1..8 pins" }
            guard let on = o["on_suspicious"]?.asString, IV.same(on, "escalate") || IV.same(on, "deny") else { return "detector '\(id)': on_suspicious must be escalate or deny" }
            if let cs = o["categories"], !(cs.asArray.map { !$0.isEmpty && $0.allSatisfy { $0.asString.map(idOk) ?? false } } ?? false) { return "detector '\(id)': categories must be 1+ ids" }
            guard let age = o["max_age_ms"]?.safeInt, age >= 1, age <= 86_400_000 else { return "detector '\(id)': max_age_ms must be 1..86400000" }
        }
        return nil
    }

    private static func rank(_ s: String) -> Int { s == "ok" ? 2 : s == "escalate" ? 1 : 0 }

    private static func receiptProblem(_ r: JSONValue, _ detectors: [JSONValue], _ digests: [JSONValue], _ session: JSONValue?, _ now: Double) -> String? {
        if let se = shapeError(r) { return "malformed: \(se)" }
        guard let rc = r.asObject else { return "malformed: receipt must be an object" }
        guard let d = detectors.first(where: { $0.get("id") == rc["detector"] }) else { return "undeclared detector '\(JS.toString(rc["detector"]))'" }
        let id = JS.toString(d.get("id"))
        let signed = (d.get("keys")?.asArray ?? []).contains { k in
            guard let pk = k.get("pk")?.asString else { return false }
            return IntentWB.verifyArtifactSig(DOMAIN, rc, pk, pqPin: k.get("pq_pk")?.asString)
        }
        if !signed { return "detector '\(id)': no pinned key signed it" }
        if !digests.contains(where: { $0 == rc["input_digest"] }) { return "detector '\(id)': the receipt is about other content" }
        if let s = rc["session"], s != session { return "detector '\(id)': bound to another session" }
        let iat = IV.num(rc["iat"]) ?? .nan
        if !(iat <= now) { return "detector '\(id)': from the future" }
        if !(now - iat <= (IV.num(d.get("max_age_ms")) ?? .nan)) { return "detector '\(id)': stale" }
        return nil
    }

    private static func rejection(_ index: Int, _ reason: String) -> JSONValue { .object(["index": .int(Int64(index)), "reason": .string(reason)]) }

    /// The tighten-only fold of detector receipts. Total. `input` is `{receipts?, policy, input_digests, session?, now}`. A malformed policy is `deny`; an
    /// invalid receipt (shape, undeclared detector, no pinned key signed it, other content, other session, from the future, stale) lowers the signal to
    /// `escalate`; a valid `suspicious` receipt with an acting category lowers it to the detector's `on_suspicious`; a valid `no_finding` changes nothing.
    /// Answers `{signal, env: {detect: {<id>: flagged, invalid: n}}, flagged, rejected}`.
    public static func detectorSignal(_ input: JSONValue?) -> JSONValue {
        var flagged: [String] = []
        var rejected: [JSONValue] = []
        var signal = "ok"
        func lower(_ s: String) { if rank(s) < rank(signal) { signal = s } }
        var env: [(String, JSONValue)] = []
        func setEnv(_ k: String, _ v: JSONValue) { if let i = env.firstIndex(where: { $0.0 == k }) { env[i].1 = v } else { env.append((k, v)) } }
        let policy = input?.get("policy")
        if let pe = detectorPolicyError(policy) {
            return PCAApprovalChannels.obj([("signal", .string("deny")), ("env", PCAApprovalChannels.obj([("detect", PCAApprovalChannels.obj([("invalid", .int(0))]))])),
                                            ("flagged", .array([])), ("rejected", .array([rejection(-1, "policy: \(pe)")]))])
        }
        let detectors = policy?.get("detectors")?.asArray ?? []
        for d in detectors { setEnv(d.get("id")?.asString ?? "", .bool(false)) }
        let receiptsV = JS.present(input?.get("receipts")) ?? .array([])
        let digests = input?.get("input_digests")?.asArray ?? []
        let nowV = input?.get("now")
        if let receipts = receiptsV.asArray, receipts.count <= MAX_DETECTOR_RECEIPTS, let now = nowV?.safeInt {
            for (index, r) in receipts.enumerated() {
                if let why = receiptProblem(r, detectors, digests, input?.get("session"), Double(now)) {
                    rejected.append(rejection(index, why))
                    lower("escalate")
                    continue
                }
                guard r.get("verdict")?.asString == "suspicious", let d = detectors.first(where: { $0.get("id") == r.get("detector") }) else { continue }
                let rcats = r.get("categories")?.asArray ?? []
                if let dc = d.get("categories")?.asArray, !rcats.isEmpty, !rcats.contains(where: { dc.contains($0) }) { continue }
                let id = d.get("id")?.asString ?? ""
                if !flagged.contains(id) { flagged.append(id) }
                setEnv(id, .bool(true))
                lower(d.get("on_suspicious")?.asString ?? "deny")
            }
        } else {
            lower("escalate")
            rejected.append(rejection(-1, "receipt list or clock malformed"))
        }
        setEnv("invalid", .int(Int64(rejected.count)))
        return PCAApprovalChannels.obj([("signal", .string(signal)), ("env", PCAApprovalChannels.obj([("detect", PCAApprovalChannels.obj(env))])),
                                        ("flagged", .array(flagged.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.map { .string($0) })), ("rejected", .array(rejected))])
    }
}
